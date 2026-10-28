//! Node-side VM lifetime enforcement through an already-open cgroup kill handle.

use crate::boundary::process::VmDeadline;
use anyhow::{Context, Result, bail};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MANAGED_CGROUP_ROOT: &str = "/sys/fs/cgroup/openshell-kata";
// Poll wall time at least once per second so forward jumps also expire leases promptly.
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Validate a real cgroup directory below the runtime's dedicated managed root.
///
/// # Errors
/// Rejects outside roots, the root itself, relative or noncanonical paths,
/// symlink components, nonexistent directories, and canonicalization failures.
pub fn validate_cgroup_path(path: &Path) -> Result<PathBuf> {
    validate_under(path, Path::new(MANAGED_CGROUP_ROOT))
}

/// Terminate a VM's cgroup when its wall-clock or monotonic lifetime expires.
///
/// This function must run as a node-side service independent of the adapter and
/// gateway. It opens `cgroup.kill` once and retains the descriptor, so deleting
/// and recreating the path cannot redirect a later kill to another cgroup.
/// A failed or backward wall clock expires the lease instead of extending it.
///
/// # Errors
/// Rejects unsafe cgroup paths, unavailable kill handles, and failed kill writes.
/// Runtime admission must reject the VM when this control cannot be established.
pub async fn watch_cgroup(cgroup_path: &Path, deadline: VmDeadline) -> Result<()> {
    watch_cgroup_ready(cgroup_path, deadline, None).await
}

/// As [`watch_cgroup`], recording readiness only after the kill handle is pinned.
pub async fn watch_cgroup_ready(
    cgroup_path: &Path,
    deadline: VmDeadline,
    ready: Option<&Path>,
) -> Result<()> {
    let canonical = validate_cgroup_path(cgroup_path)?;
    let mut kill_handle = open_kill_file(&canonical)?;
    if let Some(path) = ready {
        fs::write(path, std::process::id().to_string()).context("recording watchdog readiness")?;
    }
    let started = Instant::now();
    let remaining = remaining_duration(deadline, wall_now());
    let monotonic_deadline = started.checked_add(remaining).unwrap_or(started);
    loop {
        let now = Instant::now();
        if must_terminate(deadline, wall_now(), now >= monotonic_deadline) {
            return terminate(&mut kill_handle);
        }
        let delay = MAX_POLL_INTERVAL.min(monotonic_deadline.saturating_duration_since(now));
        tokio::time::sleep(delay).await;
    }
}

fn remaining_duration(deadline: VmDeadline, wall_now: Option<u64>) -> Duration {
    match wall_now {
        Some(now) if !deadline.expired_at(now) => {
            Duration::from_secs(deadline.expires_at_unix_secs().saturating_sub(now))
        }
        _ => Duration::ZERO,
    }
}

fn must_terminate(deadline: VmDeadline, wall_now: Option<u64>, monotonic_expired: bool) -> bool {
    monotonic_expired || wall_now.is_none_or(|now| deadline.expired_at(now))
}

fn wall_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

fn validate_under(path: &Path, root: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || !root.is_absolute() {
        bail!("cgroup path must be absolute");
    }
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0)
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        bail!("cgroup path must be canonical without traversal");
    }
    if !path.starts_with(root) || path == root {
        bail!("cgroup path is outside the managed runtime root");
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => current.push(component.as_os_str()),
            _ => bail!("cgroup path contains a relative component"),
        }
        let metadata = fs::symlink_metadata(&current).context("checking cgroup path component")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("cgroup path contains a symlink or nondirectory component");
        }
    }
    let canonical = fs::canonicalize(path).context("canonicalizing cgroup path")?;
    let root = fs::canonicalize(root).context("canonicalizing managed cgroup root")?;
    if !canonical.starts_with(&root) || canonical == root {
        bail!("canonical cgroup path is outside the managed runtime root");
    }
    Ok(canonical)
}

fn open_kill_file(path: &Path) -> Result<File> {
    let mut directory = Dir::open_ambient_dir("/", ambient_authority())?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = directory
                    .open_dir_nofollow(name)
                    .context("opening cgroup directory without symlinks")?
            }
            _ => bail!("cgroup path contains an invalid component"),
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).follow(FollowSymlinks::No);
    let handle = directory
        .open_with("cgroup.kill", &options)
        .context("opening cgroup kill control")?;
    if !handle.metadata()?.is_file() {
        bail!("cgroup kill control is not a regular kernel control file");
    }
    Ok(handle.into_std())
}

fn terminate(kill_handle: &mut File) -> Result<()> {
    kill_handle
        .write_all(b"1")
        .context("terminating expired VM cgroup")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn deadline(start: u64, expires: u64) -> VmDeadline {
        serde_json::from_value(
            serde_json::json!({"started_at_unix_secs":start,"expires_at_unix_secs":expires}),
        )
        .expect("deadline fixture")
    }

    #[test]
    fn initial_remaining_respects_expiry_and_clock_rollback() {
        let deadline = deadline(100, 200);
        assert_eq!(
            remaining_duration(deadline, Some(150)),
            Duration::from_secs(50)
        );
        assert_eq!(remaining_duration(deadline, Some(200)), Duration::ZERO);
        assert_eq!(remaining_duration(deadline, Some(99)), Duration::ZERO);
        assert_eq!(remaining_duration(deadline, None), Duration::ZERO);
        assert_eq!(
            remaining_duration(self::deadline(200, 100), Some(150)),
            Duration::ZERO
        );
    }

    #[test]
    fn monotonic_expiry_cannot_be_extended_by_wall_clock_changes() {
        let deadline = deadline(100, 200);
        assert!(!must_terminate(deadline, Some(150), false));
        assert!(must_terminate(deadline, Some(150), true));
        assert!(must_terminate(deadline, Some(250), false));
        assert!(must_terminate(deadline, Some(50), false));
        assert!(must_terminate(deadline, None, false));
    }

    #[test]
    fn managed_path_validation_rejects_traversal_and_outside_roots() {
        let temp = tempfile::tempdir_in("/tmp").expect("temporary root");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical root")
            .join("managed");
        fs::create_dir(&root).expect("managed root");
        fs::create_dir(root.join("one")).expect("cgroup directory");
        assert_eq!(
            validate_under(&root.join("one"), &root).expect("valid path"),
            root.join("one")
        );
        for invalid in [
            root.clone(),
            root.join("one/../one"),
            root.join("one//child"),
            root.with_file_name("managed-sibling").join("one"),
            PathBuf::from("relative/one"),
        ] {
            assert!(
                validate_under(&invalid, &root).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn managed_paths_and_kill_files_do_not_follow_symlinks() {
        let temp = tempfile::tempdir_in("/tmp").expect("temporary root");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical root")
            .join("managed");
        fs::create_dir_all(root.join("one")).expect("managed directory");
        symlink(root.join("one"), root.join("alias")).expect("alias");
        assert!(validate_under(&root.join("alias"), &root).is_err());
        fs::write(root.join("outside"), b"keep").expect("outside file");
        symlink(root.join("outside"), root.join("one/cgroup.kill")).expect("kill symlink");
        assert!(open_kill_file(&root.join("one")).is_err());
        assert_eq!(
            fs::read(root.join("outside")).expect("outside retained"),
            b"keep"
        );
    }

    #[test]
    fn held_kill_handle_does_not_retarget_a_replaced_path() {
        let temp = tempfile::tempdir_in("/tmp").expect("temporary root");
        let group = temp.path().canonicalize().expect("canonical root");
        fs::write(group.join("cgroup.kill"), b"").expect("kill file");
        let mut handle = open_kill_file(&group).expect("pin kill file");
        fs::rename(group.join("cgroup.kill"), group.join("old.kill")).expect("replace path");
        fs::write(group.join("cgroup.kill"), b"new target").expect("new kill file");
        terminate(&mut handle).expect("write pinned handle");
        assert_eq!(fs::read(group.join("old.kill")).expect("old target"), b"1");
        assert_eq!(
            fs::read(group.join("cgroup.kill")).expect("new target"),
            b"new target"
        );
    }
}
