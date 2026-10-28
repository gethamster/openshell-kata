//! Bounded explicit TLS identity without ambient credential discovery.
use super::validate_endpoint;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

/// Gateway credentials for the dedicated read-only guard proof service.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuardClientConfig {
    pub version: u32,
    pub server_ca_file: PathBuf,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
}
impl GuardClientConfig {
    /// Read trusted explicit credentials; no system CA or agent fallback is used.
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self = serde_json::from_slice(&read_file(path, FileKind::Public)?)?;
        config.validate()?;
        read_file(&config.server_ca_file, FileKind::Public)?;
        read_file(&config.certificate_file, FileKind::Public)?;
        read_file(&config.private_key_file, FileKind::PrivateKey)?;
        Ok(config)
    }
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported guard client version");
        for path in [
            &self.server_ca_file,
            &self.certificate_file,
            &self.private_key_file,
        ] {
            absolute(path)?;
        }
        Ok(())
    }
}

/// Node-owned server identity and exact gateway certificate authorization.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuardServerConfig {
    pub version: u32,
    pub bind: Option<std::net::SocketAddr>,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub client_ca_file: PathBuf,
    pub allowed_client_certificate_sha256: Vec<String>,
}
impl GuardServerConfig {
    pub(super) fn bind_address(
        &self,
        override_address: Option<std::net::SocketAddr>,
    ) -> Result<std::net::SocketAddr> {
        let bind = override_address
            .or(self.bind)
            .context("guard proof bind address required")?;
        validate_endpoint(bind)?;
        Ok(bind)
    }
    /// Load a bounded operator configuration and its private server key.
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self = serde_json::from_slice(&read_file(path, FileKind::Public)?)?;
        config.validate()?;
        read_file(&config.certificate_file, FileKind::Public)?;
        read_file(&config.private_key_file, FileKind::PrivateKey)?;
        read_file(&config.client_ca_file, FileKind::Public)?;
        Ok(config)
    }
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported guard server version");
        if let Some(bind) = self.bind {
            validate_endpoint(bind)?;
        }
        ensure!(
            (1..=16).contains(&self.allowed_client_certificate_sha256.len()),
            "bounded client certificate inventory required"
        );
        let mut unique = BTreeSet::new();
        for digest in &self.allowed_client_certificate_sha256 {
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && unique.insert(digest),
                "invalid or duplicate client certificate fingerprint"
            );
        }
        for path in [
            &self.certificate_file,
            &self.private_key_file,
            &self.client_ca_file,
        ] {
            absolute(path)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) enum FileKind {
    Public,
    PrivateKey,
}
fn absolute(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|part| !matches!(part, Component::CurDir | Component::ParentDir)),
        "TLS paths must be absolute without traversal"
    );
    Ok(())
}
pub(super) fn read_file(path: &Path, kind: FileKind) -> Result<Vec<u8>> {
    absolute(path)?;
    let metadata = std::fs::symlink_metadata(path).context("reading guard TLS file metadata")?;
    let uid = rustix::process::geteuid().as_raw();
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && (metadata.uid() == 0 || metadata.uid() == uid)
            && metadata.mode() & 0o022 == 0,
        "guard TLS file is not a trusted regular file"
    );
    if matches!(kind, FileKind::PrivateKey) {
        ensure!(
            metadata.mode() & 0o077 == 0,
            "guard TLS private key must be private"
        );
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    ensure!(
        opened.dev() == metadata.dev()
            && opened.ino() == metadata.ino()
            && opened.uid() == metadata.uid()
            && opened.mode() == metadata.mode()
            && opened.nlink() == metadata.nlink(),
        "guard TLS file changed while opening"
    );
    let mut bytes = Vec::new();
    (&mut file).take(65537).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= 65536,
        "guard TLS file is empty or oversized"
    );
    Ok(bytes)
}
