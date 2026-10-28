//! One shared, fail-closed retained-generation budget for every host artifact.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
const ROOT: &str = "/run/openshell-kata/generations";
const CAPACITY: usize = 512;

/// Reserve a bounded host generation before creating any UID-specific artifact.
///
/// Reservations persist until independently verified VM and interface destruction;
/// expiry or API absence never frees a reservation or an authoritative fence.
pub fn reserve_hosted_fence_generation(uid: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(uid)?;
    ensure!(
        !parsed.is_nil() && parsed.to_string() == uid,
        "noncanonical generation identity"
    );
    let root = Path::new(ROOT);
    let parent = root.parent().context("generation parent absent")?;
    super::hosted_fence_runtime::trusted_path(parent)?;
    if !root.exists() {
        match std::fs::DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    super::hosted_fence_runtime::trusted_path(root)?;
    reserve_in(root, uid, CAPACITY, 0)
}
fn reserve_in(root: &Path, uid: &str, capacity: usize, owner: u32) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(uid)?;
    ensure!(
        !parsed.is_nil() && parsed.to_string() == uid,
        "noncanonical generation identity"
    );
    private(root, owner)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(root.join(".budget.lock"))?;
    private_file(&lock, owner)?;
    lock.lock()?;
    let marker = root.join(uid);
    if marker.exists() {
        private(&marker, owner)?;
        ensure!(marker.is_dir(), "generation marker must be a directory");
        return Ok(());
    }
    let entries = std::fs::read_dir(root)?
        .filter(|entry| match entry {
            Err(_) => true,
            Ok(entry) => entry.file_name() != ".budget.lock",
        })
        .take(capacity + 1)
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        entries.len() < capacity,
        "retained host fence generation capacity reached; verified reclamation required"
    );
    std::fs::DirBuilder::new().mode(0o700).create(&marker)?;
    File::open(root)?.sync_all()?;
    Ok(())
}
fn private(path: &Path, owner: u32) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink()
            && metadata.uid() == owner
            && metadata.permissions().mode() & 0o077 == 0,
        "generation state must be private, owned and non-symlink"
    );
    Ok(())
}
fn private_file(file: &File, owner: u32) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.uid() == owner && metadata.permissions().mode() & 0o077 == 0,
        "generation budget lock must be a private owned regular file"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> (tempfile::TempDir, u32) {
        let root = tempfile::tempdir().expect("temporary budget");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let owner = root.path().metadata().expect("root metadata").uid();
        (root, owner)
    }
    #[test]
    fn existing_generation_does_not_consume_another_slot() {
        let (root, owner) = root();
        let first = uuid::Uuid::new_v4().to_string();
        let second = uuid::Uuid::new_v4().to_string();
        reserve_in(root.path(), &first, 1, owner).expect("first reservation");
        reserve_in(root.path(), &first, 1, owner).expect("same generation");
        assert!(reserve_in(root.path(), &second, 1, owner).is_err());
        assert!(!root.path().join(second).exists());
    }
    #[test]
    fn concurrent_new_generations_obey_one_atomic_budget() {
        let (root, owner) = root();
        let path = root.path().to_owned();
        let workers = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    reserve_in(&path, &uuid::Uuid::new_v4().to_string(), 2, owner).is_ok()
                })
            })
            .collect::<Vec<_>>();
        let succeeded = workers
            .into_iter()
            .map(|thread| usize::from(thread.join().expect("worker")))
            .sum::<usize>();
        assert_eq!(succeeded, 2);
    }
    #[test]
    fn unsafe_marker_and_untrusted_owner_fail_before_reuse() {
        let (root, owner) = root();
        let uid = uuid::Uuid::new_v4().to_string();
        reserve_in(root.path(), &uid, 2, owner).expect("reservation");
        std::fs::set_permissions(
            root.path().join(&uid),
            std::fs::Permissions::from_mode(0o777),
        )
        .expect("fixture mode");
        assert!(reserve_in(root.path(), &uid, 2, owner).is_err());
        assert!(
            reserve_in(
                root.path(),
                &uuid::Uuid::new_v4().to_string(),
                2,
                owner.wrapping_add(1)
            )
            .is_err()
        );
        assert!(reserve_in(root.path(), "../escape", 2, owner).is_err());
    }
}
