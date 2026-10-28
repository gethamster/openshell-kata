use anyhow::{Context, Result, ensure};
use cap_fs_ext::DirExt;
use cap_std::{ambient_authority, fs::Dir};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{File, Metadata, Permissions},
    io::ErrorKind,
    os::unix::fs::{MetadataExt as UnixMetadataExt, PermissionsExt},
    path::Path,
};

const MAX_RECORDS: usize = 128;

struct Record {
    name: OsString,
    file: File,
    metadata: Metadata,
}

/// Open handles pin every validated object; permission repair never follows names.
pub(super) struct ValidatedRegistry {
    parent: Dir,
    name: OsString,
    directory: Dir,
    readable: File,
    metadata: Metadata,
    records: Vec<Record>,
}

impl ValidatedRegistry {
    pub(super) fn inspect(path: &Path) -> Result<Option<Self>> {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let parent = Dir::open_ambient_dir(
            path.parent().context("registry parent required")?,
            ambient_authority(),
        )?;
        let name = path
            .file_name()
            .context("registry name required")?
            .to_owned();
        let directory = parent.open_dir_nofollow(&name)?;
        let readable = directory.open(".")?.into_std();
        let metadata = readable.metadata()?;
        validate_metadata(&metadata, true)?;
        let mut records = Vec::new();
        for entry in directory.entries()? {
            ensure!(
                records.len() < MAX_RECORDS,
                "registry record limit exceeded"
            );
            let name = entry?.file_name();
            let descriptor = rustix::fs::openat(
                &directory,
                &name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?;
            let file = File::from(descriptor);
            let metadata = file.metadata()?;
            validate_metadata(&metadata, false)?;
            records.push(Record {
                name,
                file,
                metadata,
            });
        }
        let result = Self {
            parent,
            name,
            directory,
            readable,
            metadata,
            records,
        };
        result.revalidate()?;
        Ok(Some(result))
    }

    fn revalidate(&self) -> Result<()> {
        let current = self.parent.symlink_metadata(&self.name)?;
        ensure!(
            current.is_dir()
                && !current.file_type().is_symlink()
                && cap_fs_ext::MetadataExt::dev(&current) == self.metadata.dev()
                && cap_fs_ext::MetadataExt::ino(&current) == self.metadata.ino(),
            "registry root was replaced"
        );
        let root = self.readable.metadata()?;
        validate_metadata(&root, true)?;
        ensure!(
            same_metadata(&root, &self.metadata),
            "registry root changed before repair"
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
            .collect::<BTreeSet<_>>();
        ensure!(
            actual == expected,
            "registry inventory changed before repair"
        );
        for record in &self.records {
            let current = record.file.metadata()?;
            validate_metadata(&current, false)?;
            ensure!(
                same_metadata(&current, &record.metadata),
                "registry record changed before repair"
            );
            let named = self.directory.symlink_metadata(&record.name)?;
            ensure!(
                named.is_file()
                    && !named.file_type().is_symlink()
                    && cap_fs_ext::MetadataExt::dev(&named) == record.metadata.dev()
                    && cap_fs_ext::MetadataExt::ino(&named) == record.metadata.ino(),
                "registry record was replaced"
            );
        }
        Ok(())
    }

    pub(super) fn restore(self) -> Result<()> {
        // Complete all validation again before the first mode change. Handles
        // remain pinned, so a later path swap cannot redirect chmod elsewhere.
        self.revalidate()?;
        for record in self.records {
            record.file.set_permissions(Permissions::from_mode(0o600))?;
            record.file.sync_all()?;
        }
        self.readable
            .set_permissions(Permissions::from_mode(0o700))?;
        self.readable.sync_all()?;
        Ok(())
    }
}

fn validate_metadata(metadata: &Metadata, directory: bool) -> Result<()> {
    ensure!(
        if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        },
        "registry object type differs"
    );
    ensure!(
        metadata.uid() == rustix::process::getuid().as_raw()
            && metadata.gid() == rustix::process::getgid().as_raw(),
        "registry object ownership differs"
    );
    ensure!(
        metadata.mode() & 0o007 == 0,
        "registry object has public permissions"
    );
    ensure!(
        directory || metadata.nlink() == 1,
        "registry record has multiple links"
    );
    Ok(())
}

fn same_metadata(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
}
