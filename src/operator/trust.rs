use anyhow::{Context, Result, ensure};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, DirBuilder, DirBuilderExt, OpenOptions, OpenOptionsExt},
};
use std::{
    ffi::OsString,
    fs::{File, Permissions},
    io::{ErrorKind, Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};
use uuid::Uuid;

const MAX_CA_BYTES: u64 = 2 * 1024 * 1024;

pub(super) fn bundle(system: &Path, platform: &Path) -> Result<Vec<u8>> {
    let mut result = read_ca(system)?;
    result.push(b'\n');
    result.extend_from_slice(&read_ca(platform)?);
    Ok(result)
}

fn read_ca(path: &Path) -> Result<Vec<u8>> {
    // The paths are operator-owned. Projected Kubernetes CA files deliberately
    // use symlinks; validate the opened regular file and never read a FIFO.
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_CA_BYTES,
        "CA input must be a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_CA_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_CA_BYTES,
        "CA input is empty or oversized"
    );
    Ok(bytes)
}

pub(super) struct Output {
    directory: Dir,
    name: OsString,
}

fn open_private_directory(path: &Path) -> Result<Dir> {
    let parent = Dir::open_ambient_dir(
        path.parent().context("private directory parent required")?,
        ambient_authority(),
    )?;
    let name = path
        .file_name()
        .context("private directory name required")?;
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    match parent.create_dir_with(name, &builder) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let directory = parent.open_dir_nofollow(name)?;
    let metadata = directory.open(".")?.into_std().metadata()?;
    ensure!(
        metadata.uid() == rustix::process::getuid().as_raw()
            && metadata.gid() == rustix::process::getgid().as_raw()
            && metadata.mode() & 0o077 == 0,
        "control directory must be private and owned"
    );
    Ok(directory)
}

pub(super) fn private_directory(path: &Path) -> Result<Dir> {
    let directory = open_private_directory(path)?;
    directory
        .open(".")?
        .into_std()
        .set_permissions(Permissions::from_mode(0o700))?;
    Ok(directory)
}

impl Output {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let parent_path = path.parent().context("trust output parent required")?;
        let name = path
            .file_name()
            .context("trust output filename required")?
            .to_owned();
        let directory = open_private_directory(parent_path)?;
        let readable = directory.open(".")?.into_std();
        match directory.symlink_metadata(&name) {
            Ok(metadata) => {
                use cap_std::fs::{MetadataExt, PermissionsExt as CapPermissionsExt};
                ensure!(
                    metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.uid() == rustix::process::getuid().as_raw()
                        && metadata.gid() == rustix::process::getgid().as_raw()
                        && metadata.permissions().mode() & 0o077 == 0
                        && metadata.nlink() == 1,
                    "trust output must be a private owned regular file"
                );
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        // fsGroup can inherit setgid onto the new private directory. Strip it
        // through its pinned descriptor after complete registry validation.
        readable.set_permissions(Permissions::from_mode(0o700))?;
        Ok(Self { directory, name })
    }

    pub(super) fn publish(self, bundle: &[u8]) -> Result<()> {
        let temporary = format!(".trust-{}", Uuid::new_v4());
        let result = (|| {
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .mode(0o600)
                .follow(FollowSymlinks::No);
            let mut file = self.directory.open_with(&temporary, &options)?;
            file.write_all(bundle)?;
            file.sync_all()?;
            self.directory
                .rename(&temporary, &self.directory, &self.name)?;
            self.directory.open(".")?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            match self.directory.remove_file(&temporary) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("remove incomplete trust bundle"),
            }
        }
        result
    }
}
