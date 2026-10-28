//! Validated file transfer without exposing host paths to a rootful guest.
//!
//! Archives are normalized into private immutable blobs. No archive is ever
//! unpacked on the host. The trusted operator owns the store and its ancestors;
//! guest VMs must never receive a mount or credentials that can reach it.
use anyhow::{Context, Result, bail};
use cap_fs_ext::{FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
    str::FromStr,
};
use uuid::Uuid;

const MAX_PATH_BYTES: usize = 255;
const MAX_PATH_DEPTH: usize = 32;
const MAX_TRANSFER_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_TRANSFER_ENTRIES: u64 = 65_536;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostMounts {
    #[default]
    Deny,
}

/// Trusted limits for each import or export. No host mount option is supported.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    pub host_mounts: HostMounts,
    pub transfer_max_bytes: u64,
    pub transfer_max_entries: u64,
}
impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            host_mounts: HostMounts::Deny,
            transfer_max_bytes: 256 * 1024 * 1024,
            transfer_max_entries: 4096,
        }
    }
}
impl FilesystemPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.transfer_max_bytes == 0
            || self.transfer_max_bytes > MAX_TRANSFER_BYTES
            || self.transfer_max_entries == 0
            || self.transfer_max_entries > MAX_TRANSFER_ENTRIES
        {
            bail!("filesystem transfer limits are outside supported bounds");
        }
        Ok(())
    }
    /// Maximum tar transport bytes including headers, padding and terminators.
    /// Call `validate` before using this value for untrusted policy input.
    pub fn wire_limit(&self) -> u64 {
        self.transfer_max_bytes
            .saturating_add(self.transfer_max_entries.saturating_mul(1024))
            .saturating_add(1024)
    }
}

/// Create a transfer directory with private permissions at creation time.
/// `tempfile::tempdir()` itself uses the process umask, which can be permissive.
pub fn private_transfer_directory() -> io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("openshell-transfer-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir()
}

/// Identifier of a sealed transfer, deliberately incapable of naming a path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportId(Uuid);
impl fmt::Display for ImportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for ImportId {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        let parsed = Uuid::parse_str(value).context("invalid transfer identifier")?;
        if parsed.to_string() != value {
            bail!("transfer identifier must be canonical");
        }
        Ok(Self(parsed))
    }
}

/// Validation outcome for the normalized archive.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArchiveSummary {
    pub entries: u64,
    pub expanded_bytes: u64,
}

/// Directory capability held solely by the host adapter. The root must already
/// exist, have private permissions, and reside under trusted ancestors.
#[derive(Debug)]
pub struct ImportStore {
    root: Dir,
}
impl ImportStore {
    pub fn open(trusted_private_root: impl AsRef<Path>) -> Result<Self> {
        let path = trusted_private_root.as_ref();
        let metadata = std::fs::symlink_metadata(path).context("inspect transfer store")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("transfer store must be a real directory");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!("transfer store must have owner-only permissions");
            }
        }
        Ok(Self {
            root: Dir::open_ambient_dir(path, ambient_authority())
                .context("open transfer store")?,
        })
    }

    /// Stage, fully validate and durably publish a canonical archive atomically.
    pub fn import_tar(&self, reader: impl Read, policy: &FilesystemPolicy) -> Result<ImportId> {
        policy.validate()?;
        let id = ImportId(Uuid::new_v4());
        let staged = format!(".{id}.partial");
        let result = (|| {
            let mut file = self.create_private(&staged)?;
            normalize_archive(reader, &mut file, policy)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o400))?;
            }
            file.sync_all().context("sync staged transfer")?;
            self.root
                .rename(&staged, &self.root, format!("{id}.tar"))
                .context("publish transfer")?;
            #[cfg(unix)]
            self.root.try_clone()?.into_std_file().sync_all()?;
            Ok(id)
        })();
        if result.is_err() {
            self.remove_if_present(&staged)?;
            self.remove_if_present(&format!("{id}.tar"))?;
        }
        result
    }

    /// Open only a regular, single-link sealed blob. Never resolves symlinks.
    pub fn open_archive(&self, id: &ImportId) -> Result<std::fs::File> {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = self
            .root
            .open_with(format!("{id}.tar"), &options)?
            .into_std();
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            bail!("transfer must be a private regular file");
        }
        Ok(file)
    }

    /// Revalidate into a private temporary snapshot before writing any output.
    /// This also validates archives produced by an untrusted guest on download.
    pub fn export_tar(
        &self,
        id: &ImportId,
        mut writer: impl Write,
        policy: &FilesystemPolicy,
    ) -> Result<ArchiveSummary> {
        let staged = format!(".{}.export", Uuid::new_v4());
        let result = (|| {
            let source = self.open_archive(id)?;
            let mut snapshot = self.create_private(&staged)?;
            let summary = normalize_archive(source, &mut snapshot, policy)?;
            snapshot.seek(SeekFrom::Start(0))?;
            io::copy(&mut snapshot, &mut writer)?;
            Ok(summary)
        })();
        self.remove_if_present(&staged)?;
        result
    }

    /// Remove a completed transfer when its consumer has finished.
    pub fn remove(&self, id: &ImportId) -> Result<()> {
        self.root
            .remove_file(format!("{id}.tar"))
            .context("remove transfer")
    }

    fn create_private(&self, name: &str) -> Result<std::fs::File> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        Ok(self.root.open_with(name, &options)?.into_std())
    }
    fn remove_if_present(&self, name: &str) -> Result<()> {
        match self.root.remove_file(name) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("clean staged transfer"),
        }
    }
}

/// Validate an archive without publishing it. Accepts only ordinary USTAR
/// files/directories; links, sparse files and extension records are rejected.
pub fn validate_archive(reader: impl Read, policy: &FilesystemPolicy) -> Result<ArchiveSummary> {
    normalize_archive(reader, io::sink(), policy)
}

fn normalize_archive(
    reader: impl Read,
    writer: impl Write,
    policy: &FilesystemPolicy,
) -> Result<ArchiveSummary> {
    policy.validate()?;
    let mut archive = tar::Archive::new(reader.take(policy.wire_limit() + 1));
    let mut builder = tar::Builder::new(writer);
    let mut paths = BTreeMap::new();
    let mut summary = ArchiveSummary::default();
    for entry in archive.entries()?.raw(true) {
        let mut entry = entry.context("invalid archive entry")?;
        summary.entries += 1;
        if summary.entries > policy.transfer_max_entries {
            bail!("archive exceeds entry quota");
        }
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_dir() {
            bail!("archive contains a forbidden entry type");
        }
        let size = entry.header().size()?;
        if kind.is_dir() && size != 0 {
            bail!("archive directory has content");
        }
        summary.expanded_bytes = summary
            .expanded_bytes
            .checked_add(size)
            .context("archive size overflow")?;
        if summary.expanded_bytes > policy.transfer_max_bytes {
            bail!("archive exceeds expanded byte quota");
        }
        let path_bytes = entry.path_bytes();
        let path = normalize_path(&path_bytes, kind.is_dir())?;
        if path.is_empty() {
            continue;
        }
        validate_tree(&paths, &path, kind.is_dir())?;
        paths.insert(path.clone(), kind.is_dir());
        let mut header = tar::Header::new_ustar();
        header
            .set_path(&path)
            .context("archive path exceeds portable USTAR limits")?;
        header.set_entry_type(kind);
        header.set_size(size);
        header.set_mode(if kind.is_dir() || entry.header().mode()? & 0o111 != 0 {
            0o700
        } else {
            0o600
        });
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append(&header, &mut entry)
            .context("read complete archive entry")?;
    }
    // The parser stops at the first zero block. Require another zero block and
    // reject appended payloads, truncated padding and overlong wire streams.
    let mut remaining = archive.into_inner();
    let consumed = policy.wire_limit() + 1 - remaining.limit();
    let mut tail_len = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let count = remaining.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if buffer[..count].iter().any(|byte| *byte != 0) {
            bail!("archive has nonzero trailing payload");
        }
        tail_len += count as u64;
    }
    if consumed + tail_len > policy.wire_limit()
        || tail_len < 512
        || !(consumed + tail_len).is_multiple_of(512)
    {
        bail!("archive is truncated or exceeds wire quota");
    }
    builder.finish()?;
    Ok(summary)
}

fn normalize_path(raw: &[u8], directory: bool) -> Result<String> {
    let path = std::str::from_utf8(raw).context("archive paths must be UTF-8")?;
    if path.len() > MAX_PATH_BYTES
        || path.contains(['\\', ':'])
        || path.chars().any(char::is_control)
        || path.starts_with('/')
    {
        bail!("archive path is not portable or safe");
    }
    let path = path.trim_start_matches("./");
    let path = if directory {
        path.trim_end_matches('/')
    } else {
        path
    };
    if directory && (path.is_empty() || path == ".") {
        return Ok(String::new());
    }
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() > MAX_PATH_DEPTH
        || parts
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        bail!("archive path contains invalid components");
    }
    Ok(path.to_owned())
}

fn validate_tree(paths: &BTreeMap<String, bool>, path: &str, directory: bool) -> Result<()> {
    if paths.contains_key(path) {
        bail!("archive contains duplicate paths");
    }
    for (index, _) in path.match_indices('/') {
        if paths.get(&path[..index]) == Some(&false) {
            bail!("archive file used as a directory");
        }
    }
    if !directory {
        let prefix = format!("{path}/");
        if paths
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(existing, _)| existing.starts_with(&prefix))
        {
            bail!("archive file conflicts with a directory");
        }
    }
    Ok(())
}
