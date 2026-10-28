//! Private retained intent, SSH material, and per-sandbox lifecycle locking.

use super::{model::State, policy};
use crate::runtime::state::StateDirectory;
use anyhow::{Context, Result, ensure};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, MetadataExt, OpenOptions, OpenOptionsExt},
};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

pub(super) struct Store {
    state: StateDirectory,
    root: Dir,
}

impl Store {
    pub(super) fn new(path: &Path) -> Result<Self> {
        let state = StateDirectory::new(path)?;
        let root = Dir::open_ambient_dir(state.root(), ambient_authority())?;
        Ok(Self { state, root })
    }

    pub(super) fn lock(&self, sandbox: &str) -> Result<File> {
        let name = format!("{}.lock", policy::resource_id(sandbox)?);
        let mut options = OpenOptions::new();
        options
            .create(true)
            .append(true)
            .mode(0o600)
            .follow(FollowSymlinks::No);
        let file = self.root.open_with(name, &options)?.into_std();
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0
                && metadata.uid() == self.root.dir_metadata()?.uid(),
            "unsafe lifecycle lock"
        );
        file.lock().context("locking sandbox lifecycle")?;
        Ok(file)
    }

    pub(super) fn folder(&self, sandbox: &str) -> Result<PathBuf> {
        let name = policy::resource_id(sandbox)?;
        match self.state.create(&name) {
            Ok(path) => Ok(path),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                self.directory(&name)?;
                self.state.path(&name)
            }
            Err(error) => Err(error),
        }
    }

    fn directory(&self, name: &str) -> Result<Dir> {
        let dir = self.root.open_dir_nofollow(name)?;
        let metadata = dir.dir_metadata()?;
        ensure!(
            metadata.mode() & 0o077 == 0 && metadata.uid() == self.root.dir_metadata()?.uid(),
            "unsafe sandbox state directory"
        );
        Ok(dir)
    }

    pub(super) fn read(&self, sandbox: &str) -> Result<Option<State>> {
        let name = policy::resource_id(sandbox)?;
        let dir = self.directory(&name)?;
        match dir.symlink_metadata("metadata.json") {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
            Ok(metadata) => {
                ensure!(
                    metadata.len() <= 1024 * 1024,
                    "retained runtime metadata too large"
                );
                let state: State = self.state.read(&name)?;
                state.validate(sandbox, &self.state.path(&name)?)?;
                Ok(Some(state))
            }
        }
    }

    pub(super) fn save(&self, state: &State) -> Result<()> {
        let name = policy::resource_id(&state.sandbox_id)?;
        state.validate(&state.sandbox_id, &self.state.path(&name)?)?;
        self.state.write(&name, state)
    }

    pub(super) fn key(&self, sandbox: &str, name: &str) -> Result<String> {
        ensure!(
            matches!(name, "client_key.pub" | "host_key.pub" | "host_key"),
            "unknown SSH material"
        );
        let dir = self.directory(&policy::resource_id(sandbox)?)?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = dir.open_with(name, &options)?;
        ensure!(
            file.metadata()?.is_file() && file.metadata()?.len() <= 16 * 1024,
            "invalid SSH material"
        );
        let mut value = String::new();
        file.take(16 * 1024 + 1).read_to_string(&mut value)?;
        Ok(value)
    }

    pub(super) fn remove_key(&self, sandbox: &str, name: &str) -> Result<()> {
        ensure!(
            matches!(
                name,
                "client_key"
                    | "client_key.pub"
                    | "host_key"
                    | "host_key.pub"
                    | "known_hosts"
                    | "metadata.new"
            ),
            "unknown SSH material"
        );
        let dir = self.directory(&policy::resource_id(sandbox)?)?;
        match dir.remove_file(name) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub(super) fn known_hosts(&self, sandbox: &str, host: &str, public_key: &str) -> Result<()> {
        let fields: Vec<_> = public_key.split_whitespace().collect();
        ensure!(
            fields.len() >= 2 && fields[0] == "ssh-ed25519",
            "invalid guest SSH host key"
        );
        self.remove_key(sandbox, "known_hosts")?;
        let dir = self.directory(&policy::resource_id(sandbox)?)?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .follow(FollowSymlinks::No);
        let mut file = dir.open_with("known_hosts", &options)?;
        writeln!(file, "{host} {} {}", fields[0], fields[1])?;
        file.sync_all()?;
        Ok(())
    }

    pub(super) fn erase(&self, sandbox: &str) -> Result<()> {
        self.state.remove(&policy::resource_id(sandbox)?)
    }
}
