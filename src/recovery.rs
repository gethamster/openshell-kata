//! Credential-free durable intent for stopped sandbox recovery.

use crate::{
    config::{Config, SandboxId},
    proto::openshell::compute::v1 as c,
};
use anyhow::{Context, Result, ensure};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};

const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
const MAX_STORE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 128;

/// Validated sandbox intent, separate from live supervisor authentication.
#[derive(Clone)]
pub struct Retained {
    pub sandbox: c::DriverSandbox,
    pub runtime_identity: String,
    pub generation: String,
}

impl Retained {
    pub fn new(
        mut sandbox: c::DriverSandbox,
        runtime_identity: String,
        generation: String,
    ) -> Self {
        sandbox.status = None;
        if let Some(spec) = &mut sandbox.spec {
            spec.launch_authentication.clear();
        }
        Self {
            sandbox,
            runtime_identity,
            generation,
        }
    }

    pub fn observation(&self) -> c::DriverSandbox {
        let mut sandbox = self.sandbox.clone();
        sandbox.status = Some(c::DriverSandboxStatus {
            name: sandbox.name.clone(),
            instance_id: self.runtime_identity.clone(),
            conditions: vec![
                c::DriverCondition {
                    r#type: "Ready".into(),
                    status: "False".into(),
                    reason: "FreshStartRequired".into(),
                    ..Default::default()
                },
                c::DriverCondition {
                    r#type: "Suspended".into(),
                    status: "True".into(),
                    reason: "Stopped".into(),
                    message: "Recovered intent; fresh gateway Start authentication required".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        sandbox
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    sandbox: Vec<u8>,
    runtime_identity: String,
    generation: String,
}

/// Private atomic snapshots of operator-validated intent, never bearer tokens.
#[derive(Clone)]
pub struct Store {
    root: PathBuf,
    mutation: Arc<Mutex<()>>,
}

impl Store {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            mutation: Arc::default(),
        }
    }

    fn directory(&self) -> Result<()> {
        ensure!(
            self.root.is_absolute(),
            "recovery directory must be absolute"
        );
        if self.root.exists() {
            ensure!(
                fs::symlink_metadata(&self.root)?.is_dir()
                    && !fs::symlink_metadata(&self.root)?.file_type().is_symlink(),
                "recovery directory must not be a symlink"
            );
        }
        fs::create_dir_all(&self.root)?;
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn path(&self, id: &str) -> Result<PathBuf> {
        SandboxId::parse(id)?;
        Ok(self
            .root
            .join(format!("{:x}.json", Sha256::digest(id.as_bytes()))))
    }

    fn inventory(&self) -> Result<Vec<(PathBuf, u64)>> {
        let mut entries = Vec::new();
        let mut total = 0;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "json")
            {
                continue;
            }
            ensure!(
                entry.file_type()?.is_file(),
                "recovery snapshot must be a regular file"
            );
            let metadata = entry.metadata()?;
            ensure!(
                metadata.len() <= MAX_RECORD_BYTES && metadata.permissions().mode() & 0o077 == 0,
                "recovery snapshot size or permissions differ"
            );
            total += metadata.len();
            entries.push((entry.path(), metadata.len()));
            ensure!(
                entries.len() <= MAX_RECORDS && total <= MAX_STORE_BYTES,
                "recovery inventory exceeds bounds"
            );
        }
        Ok(entries)
    }

    pub fn save(&self, retained: &Retained) -> Result<()> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("recovery store lock unavailable"))?;
        let target = self.path(&retained.sandbox.id)?;
        self.directory()?;
        let sanitized = Retained::new(
            retained.sandbox.clone(),
            retained.runtime_identity.clone(),
            retained.generation.clone(),
        );
        let snapshot = Snapshot {
            version: 1,
            sandbox: sanitized.sandbox.encode_to_vec(),
            runtime_identity: sanitized.runtime_identity,
            generation: sanitized.generation,
        };
        let encoded = serde_json::to_vec(&snapshot)?;
        ensure!(
            encoded.len() as u64 <= MAX_RECORD_BYTES,
            "recovery snapshot exceeds size limit"
        );
        let inventory = self.inventory()?;
        let mut workspace_records = 0;
        let mut existing = false;
        for (path, _) in &inventory {
            let stored: Snapshot = serde_json::from_slice(&fs::read(path)?)?;
            ensure!(stored.version == 1, "unsupported recovery snapshot version");
            let sandbox = c::DriverSandbox::decode(stored.sandbox.as_slice())?;
            ensure!(
                self.path(&sandbox.id)? == *path,
                "recovery snapshot identity differs from filename"
            );
            if path == &target {
                existing = true;
                ensure!(
                    sandbox.workspace == sanitized.sandbox.workspace,
                    "retained workspace differs"
                );
            }
            if sandbox.workspace == sanitized.sandbox.workspace {
                workspace_records += 1;
            }
        }
        ensure!(
            existing || workspace_records < 2,
            "pilot workspace already has two retained sandboxes"
        );
        let replaced = inventory
            .iter()
            .find(|(path, _)| path == &target)
            .map_or(0, |(_, size)| *size);
        let total: u64 = inventory.iter().map(|(_, size)| size).sum();
        ensure!(
            total - replaced + encoded.len() as u64 <= MAX_STORE_BYTES,
            "recovery inventory exceeds size limit"
        );
        ensure!(
            replaced != 0 || inventory.len() < MAX_RECORDS,
            "recovery inventory exceeds record limit"
        );
        let mut temporary = tempfile::NamedTempFile::new_in(&self.root)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        temporary.write_all(&encoded)?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(target)
            .map_err(|e| e.error)
            .context("persisting sandbox recovery intent")?;
        fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    pub fn load(&self, config: &Config) -> Result<Vec<Retained>> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("recovery store lock unavailable"))?;
        self.directory()?;
        let mut retained = Vec::new();
        for (path, _) in self.inventory()? {
            let snapshot: Snapshot = serde_json::from_slice(&fs::read(&path)?)
                .context("decoding sandbox recovery intent")?;
            ensure!(
                snapshot.version == 1,
                "unsupported recovery snapshot version"
            );
            let sandbox = c::DriverSandbox::decode(snapshot.sandbox.as_slice())?;
            ensure!(
                sandbox
                    .spec
                    .as_ref()
                    .is_some_and(|spec| spec.launch_authentication.is_empty()),
                "recovery snapshot contains forbidden launch authentication"
            );
            ensure!(
                self.path(&sandbox.id)? == path,
                "recovery snapshot identity differs from filename"
            );
            config.validate_request(&sandbox)?;
            ensure!(
                snapshot.runtime_identity.is_empty()
                    || uuid::Uuid::parse_str(&snapshot.runtime_identity).is_ok(),
                "invalid retained runtime identity"
            );
            retained.push(Retained::new(
                sandbox,
                snapshot.runtime_identity,
                snapshot.generation,
            ));
        }
        Ok(retained)
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("recovery store lock unavailable"))?;
        match fs::remove_file(self.path(id)?) {
            Ok(()) => {
                fs::File::open(&self.root)?.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}
