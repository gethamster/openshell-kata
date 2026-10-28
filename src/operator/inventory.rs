//! Metadata-only validation of the complete known hosted-state layout.

use anyhow::{Context, Result, bail, ensure};
use cap_fs_ext::DirExt;
use cap_std::{ambient_authority, fs::Dir};
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::{File, Metadata, Permissions},
    io::ErrorKind,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

const MAX_SANDBOXES: usize = 128;
// Stable lock files can outlive deleted sandboxes; preserve their inodes.
const MAX_RETAINED_LOCKS: usize = 4096;
const MAX_REGISTRY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REGISTRY_RECORD_BYTES: u64 = 4 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 64 * 1024;
const MAX_KEY_BYTES: u64 = 16 * 1024;

#[derive(Clone, Copy)]
pub(super) enum Layout {
    State,
    Registry,
    Sandbox,
}

#[derive(Clone, Copy)]
enum Role {
    Private(u64),
    PublicKey,
    EmptyLock,
}

enum Kind {
    Directory(Layout),
    File(Role),
}

struct Record {
    name: OsString,
    file: File,
    metadata: Metadata,
    role: Role,
}

/// All objects stay pinned until validation and in-place repair complete.
pub(super) struct Tree {
    parent: Dir,
    name: OsString,
    directory: Dir,
    readable: File,
    metadata: Metadata,
    records: Vec<Record>,
    children: Vec<Tree>,
}

impl Tree {
    pub(super) fn inspect(path: &Path) -> Result<Option<Self>> {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let parent = Dir::open_ambient_dir(
            path.parent().context("state parent required")?,
            ambient_authority(),
        )?;
        let name = path.file_name().context("state name required")?;
        let result = Self::inspect_in(parent, name, Layout::State)?;
        result.revalidate()?;
        Ok(Some(result))
    }

    fn inspect_in(parent: Dir, name: &OsStr, layout: Layout) -> Result<Self> {
        let directory = parent.open_dir_nofollow(name)?;
        let readable = directory.open(".")?.into_std();
        let metadata = readable.metadata()?;
        validate_directory(&metadata)?;
        let mut result = Self {
            parent,
            name: name.to_owned(),
            directory,
            readable,
            metadata,
            records: Vec::new(),
            children: Vec::new(),
        };
        result.collect(layout)?;
        Ok(result)
    }

    fn collect(&mut self, layout: Layout) -> Result<()> {
        let mut total_bytes = 0_u64;
        for entry in self.directory.entries()? {
            ensure!(
                self.records.len() + self.children.len() < layout.entry_limit(),
                "known state entry limit exceeded"
            );
            let name = entry?.file_name();
            let kind = layout.kind(&name)?;
            total_bytes = total_bytes
                .checked_add(self.collect_entry(name, kind)?)
                .context("state size overflow")?;
        }
        ensure!(
            !matches!(layout, Layout::Registry) || total_bytes <= MAX_REGISTRY_BYTES,
            "registry size limit exceeded"
        );
        ensure!(
            !matches!(layout, Layout::State)
                || self
                    .children
                    .iter()
                    .filter(|child| child.name != OsStr::new("registry"))
                    .count()
                    <= MAX_SANDBOXES,
            "sandbox state count exceeded"
        );
        ensure!(
            !matches!(layout, Layout::State) || self.records.len() <= MAX_RETAINED_LOCKS + 1,
            "retained lock count exceeded"
        );
        Ok(())
    }

    fn collect_entry(&mut self, name: OsString, kind: Kind) -> Result<u64> {
        match kind {
            Kind::Directory(layout) => {
                self.children.push(Self::inspect_in(
                    self.directory.try_clone()?,
                    &name,
                    layout,
                )?);
                Ok(0)
            }
            Kind::File(role) => {
                let record = record(&self.directory, name, role)?;
                let bytes = record.metadata.len();
                self.records.push(record);
                Ok(bytes)
            }
        }
    }

    fn revalidate(&self) -> Result<()> {
        let current = self.parent.symlink_metadata(&self.name)?;
        ensure!(
            current.is_dir()
                && !current.file_type().is_symlink()
                && cap_fs_ext::MetadataExt::dev(&current) == self.metadata.dev()
                && cap_fs_ext::MetadataExt::ino(&current) == self.metadata.ino(),
            "state directory was replaced"
        );
        let root = self.readable.metadata()?;
        validate_directory(&root)?;
        ensure!(
            same_metadata(&root, &self.metadata),
            "state directory changed before repair"
        );
        let actual = self
            .directory
            .entries()?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<BTreeSet<_>>>()?;
        let expected = self
            .records
            .iter()
            .map(|record| record.name.clone())
            .chain(self.children.iter().map(|child| child.name.clone()))
            .collect::<BTreeSet<_>>();
        ensure!(actual == expected, "state inventory changed before repair");
        for record in &self.records {
            self.revalidate_record(record)?;
        }
        for child in &self.children {
            child.revalidate()?;
        }
        Ok(())
    }

    fn revalidate_record(&self, record: &Record) -> Result<()> {
        let current = record.file.metadata()?;
        validate_file(&current, record.role)?;
        ensure!(
            same_metadata(&current, &record.metadata),
            "state file changed before repair"
        );
        let named = self.directory.symlink_metadata(&record.name)?;
        ensure!(
            named.is_file()
                && !named.file_type().is_symlink()
                && cap_fs_ext::MetadataExt::dev(&named) == record.metadata.dev()
                && cap_fs_ext::MetadataExt::ino(&named) == record.metadata.ino(),
            "state file was replaced"
        );
        Ok(())
    }

    pub(super) fn restore(self) -> Result<()> {
        // Check the entire tree before the first chmod. No content is read,
        // rewritten or invented; descriptors preserve keys and lock inodes.
        self.revalidate()?;
        self.apply_modes()
    }

    fn apply_modes(&self) -> Result<()> {
        for record in &self.records {
            record.file.set_permissions(Permissions::from_mode(0o600))?;
            record.file.sync_all()?;
        }
        for child in &self.children {
            child.apply_modes()?;
        }
        self.readable
            .set_permissions(Permissions::from_mode(0o700))?;
        self.readable.sync_all()?;
        Ok(())
    }
}

impl Layout {
    fn entry_limit(self) -> usize {
        match self {
            Self::State => MAX_SANDBOXES + MAX_RETAINED_LOCKS + 2,
            Self::Registry => MAX_SANDBOXES,
            Self::Sandbox => 7,
        }
    }

    fn kind(self, name: &OsStr) -> Result<Kind> {
        let name = name
            .to_str()
            .context("known state filename must be UTF-8")?;
        match self {
            Self::State => match name {
                "registry" => Ok(Kind::Directory(Self::Registry)),
                ".lock" => Ok(Kind::File(Role::EmptyLock)),
                _ if sandbox_name(name) => Ok(Kind::Directory(Self::Sandbox)),
                _ if name.strip_suffix(".lock").is_some_and(sandbox_name) => {
                    Ok(Kind::File(Role::EmptyLock))
                }
                _ => bail!("unknown root state entry"),
            },
            Self::Registry => {
                ensure!(
                    name.strip_suffix(".json").is_some_and(|stem| hex(stem, 64)),
                    "unknown registry record filename"
                );
                Ok(Kind::File(Role::Private(MAX_REGISTRY_RECORD_BYTES)))
            }
            Self::Sandbox => match name {
                "metadata.json" | "metadata.new" => {
                    Ok(Kind::File(Role::Private(MAX_METADATA_BYTES)))
                }
                "client_key" | "host_key" | "known_hosts" => {
                    Ok(Kind::File(Role::Private(MAX_KEY_BYTES)))
                }
                "client_key.pub" | "host_key.pub" => Ok(Kind::File(Role::PublicKey)),
                _ => bail!("unknown sandbox state entry"),
            },
        }
    }
}

fn sandbox_name(name: &str) -> bool {
    name.strip_prefix("kata-")
        .is_some_and(|suffix| hex(suffix, 24))
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn record(directory: &Dir, name: OsString, role: Role) -> Result<Record> {
    let descriptor = rustix::fs::openat(
        directory,
        &name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    validate_file(&metadata, role)?;
    if matches!(role, Role::EmptyLock) {
        file.try_lock()
            .context("state lock is active; quiesce the owner before migration")?;
    }
    Ok(Record {
        name,
        file,
        metadata,
        role,
    })
}

fn validate_owner(metadata: &Metadata) -> Result<()> {
    ensure!(
        metadata.uid() == rustix::process::getuid().as_raw()
            && metadata.gid() == rustix::process::getgid().as_raw(),
        "state object ownership differs"
    );
    Ok(())
}

fn validate_directory(metadata: &Metadata) -> Result<()> {
    validate_owner(metadata)?;
    ensure!(
        metadata.is_dir() && metadata.mode() & 0o007 == 0,
        "state directory type or public permissions differ"
    );
    Ok(())
}

fn validate_file(metadata: &Metadata, role: Role) -> Result<()> {
    validate_owner(metadata)?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "state file type or link count differs"
    );
    ensure!(
        metadata.mode() & 0o003 == 0,
        "state file permits public writes or execution"
    );
    match role {
        Role::Private(limit) => ensure!(
            metadata.mode() & 0o007 == 0 && metadata.len() <= limit,
            "private state permissions or size differ"
        ),
        Role::PublicKey => ensure!(
            metadata.len() <= MAX_KEY_BYTES,
            "public key size limit exceeded"
        ),
        Role::EmptyLock => ensure!(metadata.len() == 0, "state lock must remain empty"),
    }
    Ok(())
}

fn same_metadata(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
