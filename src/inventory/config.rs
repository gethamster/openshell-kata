use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    net::IpAddr,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryConfig {
    pub version: u32,
    pub kubectl_path: PathBuf,
    pub kubectl_sha256: String,
    pub kubeconfig_path: PathBuf,
    pub protected_hostnames: Vec<String>,
    pub resolver_ip: IpAddr,
    #[serde(default = "dns_port")]
    pub resolver_port: u16,
    pub baseline_denied_cidrs: Vec<String>,
    #[serde(default = "yes")]
    pub include_external_names: bool,
    pub refresh_secs: u64,
    pub freshness_secs: u64,
    pub query_timeout_secs: u64,
    pub api_timeout_secs: u64,
    pub output_path: PathBuf,
}
fn dns_port() -> u16 {
    53
}
fn yes() -> bool {
    true
}
impl InventoryConfig {
    pub fn load(path: &Path) -> Result<Self> {
        trusted_file(path, 1024 * 1024)?;
        let config: Self = serde_json::from_slice(&bounded(path, 1024 * 1024)?)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported inventory configuration version"
        );
        ensure!(
            (1..=10).contains(&self.refresh_secs)
                && (1..=60).contains(&self.freshness_secs)
                && (1..=5).contains(&self.query_timeout_secs)
                && (1..=10).contains(&self.api_timeout_secs),
            "inventory timing outside operator bounds"
        );
        ensure!(
            self.resolver_port > 0
                && !self.resolver_ip.is_unspecified()
                && !self.resolver_ip.is_multicast(),
            "invalid trusted resolver endpoint"
        );
        for path in [&self.kubectl_path, &self.kubeconfig_path, &self.output_path] {
            absolute(path)?;
        }
        ensure!(
            self.output_path != self.kubectl_path && self.output_path != self.kubeconfig_path,
            "inventory output aliases trusted input"
        );
        validate_auth(
            &self.kubectl_path,
            &self.kubectl_sha256,
            &self.kubeconfig_path,
        )?;
        ensure!(
            self.protected_hostnames.len() <= 256 && self.baseline_denied_cidrs.len() <= 4096,
            "excessive inventory inputs"
        );
        let mut names = std::collections::BTreeSet::new();
        for hostname in &self.protected_hostnames {
            let host = crate::network::normalize_host(hostname)?;
            ensure!(
                host.parse::<IpAddr>().is_err(),
                "protected hostname must be DNS name"
            );
            ensure!(names.insert(host), "duplicate protected hostname");
        }
        for cidr in &self.baseline_denied_cidrs {
            let _: ipnet::IpNet = cidr.parse()?;
        }
        Ok(())
    }
}
pub(super) fn validate_auth(kubectl: &Path, expected: &str, kubeconfig: &Path) -> Result<()> {
    ensure!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "kubectl SHA256 must be lowercase hexadecimal"
    );
    trusted_file(kubectl, 256 * 1024 * 1024)?;
    trusted_file(kubeconfig, 1024 * 1024)?;
    let value: serde_json::Value = serde_json::from_slice(&bounded(kubeconfig, 1024 * 1024)?)?;
    crate::node_intent::validate_kubeconfig(&value)?;
    for path in [
        value["clusters"][0]["cluster"]["certificate-authority"].as_str(),
        value["users"][0]["user"]["tokenFile"].as_str(),
    ]
    .into_iter()
    .flatten()
    {
        trusted_file(&std::fs::canonicalize(path)?, 1024 * 1024)?;
    }
    let actual = format!("{:x}", Sha256::digest(bounded(kubectl, 256 * 1024 * 1024)?));
    ensure!(actual == expected, "kubectl executable digest differs");
    Ok(())
}
pub(super) fn absolute(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|p| !matches!(p, Component::ParentDir | Component::CurDir)),
        "inventory paths must be absolute without traversal"
    );
    Ok(())
}
pub(super) fn trusted_file(path: &Path, max: u64) -> Result<()> {
    absolute(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    let uid = rustix::process::geteuid().as_raw();
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && (metadata.uid() == 0 || metadata.uid() == uid)
            && metadata.mode() & 0o022 == 0
            && metadata.len() <= max,
        "operator file must be bounded, regular, trusted-owner and not writable by others"
    );
    Ok(())
}
pub(super) fn bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= max, "inventory file exceeds limit");
    Ok(bytes)
}
