use super::config::{absolute, bounded};
use crate::network::InfrastructureInventory;
use anyhow::{Context, Result, ensure};
use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) fn prepare(path: &Path) -> Result<()> {
    absolute(path)?;
    let parent = path
        .parent()
        .context("inventory output directory required")?;
    if !parent.exists() {
        std::fs::DirBuilder::new().mode(0o700).create(parent)?;
    }
    let meta = std::fs::symlink_metadata(parent)?;
    ensure!(
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && meta.uid() == rustix::process::geteuid().as_raw()
            && meta.mode() & 0o777 == 0o700,
        "inventory output directory must be UID-owned private 0700"
    );
    existing(path)?;
    Ok(())
}
fn existing(path: &Path) -> Result<Option<(u64, u64)>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                meta.is_file()
                    && !meta.file_type().is_symlink()
                    && meta.uid() == rustix::process::geteuid().as_raw()
                    && meta.mode() & 0o777 == 0o600
                    && meta.nlink() == 1,
                "existing inventory must be UID-owned regular 0600 without links"
            );
            Ok(Some((meta.dev(), meta.ino())))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
pub(super) fn next_generation(path: &Path) -> Result<u64> {
    prepare(path)?;
    let last = if existing(path)?.is_some() {
        let previous: InfrastructureInventory =
            serde_json::from_slice(&bounded(path, 1024 * 1024)?)?;
        previous.validate_at(previous.issued_at_unix)?;
        previous.generation
    } else {
        0
    };
    let clock = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
    Ok(clock.max(
        last.checked_add(1)
            .context("inventory generation overflow")?,
    ))
}
pub(super) fn publish(path: &Path, inventory: &InfrastructureInventory) -> Result<()> {
    prepare(path)?;
    let identity = existing(path)?;
    let parent = path.parent().context("inventory output parent")?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    temp.write_all(&serde_json::to_vec(inventory)?)?;
    temp.as_file().sync_all()?;
    ensure!(
        existing(path)? == identity,
        "inventory changed during publication"
    );
    temp.persist(path).map_err(|e| e.error)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
