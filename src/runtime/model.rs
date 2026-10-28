//! Persisted lifecycle identity and validation for one isolated guest.
use crate::{
    boundary::process::VmDeadline,
    guest::Guest,
    network::FenceSpec,
    profile::{EnforcementEvidence, VmPolicy},
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{net::Ipv4Addr, path::PathBuf, str::FromStr};

/// Existing lifecycle verbs plus explicit policy verification and replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Create,
    Start,
    Stop,
    Delete,
    Verify,
    Update,
    Abort,
}
impl FromStr for Action {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        Ok(match value {
            "create" => Self::Create,
            "start" => Self::Start,
            "stop" => Self::Stop,
            "delete" => Self::Delete,
            "verify" => Self::Verify,
            "update" => Self::Update,
            "abort" => Self::Abort,
            _ => bail!("unsupported lifecycle action"),
        })
    }
}

/// Serializable SSH route; the private key itself never enters the guest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub sandbox_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub private_key_path: PathBuf,
    pub known_hosts_path: PathBuf,
}
impl Route {
    /// Return the adapter's transport contract with fresh enforcement evidence.
    pub fn guest(&self, enforcement: Option<EnforcementEvidence>) -> Guest {
        Guest {
            sandbox_id: self.sandbox_id.clone(),
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            private_key_path: self.private_key_path.clone(),
            known_hosts_path: self.known_hosts_path.clone(),
            enforcement,
        }
    }
    /// Produce JSON without requiring the adapter's internal transport type to serialize.
    pub fn output(&self, enforcement: EnforcementEvidence) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        value["enforcement"] = serde_json::to_value(enforcement)?;
        Ok(value)
    }
}

/// Host-only records required to reverify and destroy one guest generation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub creation_nonce: String,
    pub attachment: super::network::Attachment,
    pub route: Route,
    pub policy: VmPolicy,
    pub deadline: VmDeadline,
    pub network: Option<FenceSpec>,
    pub storage_id: String,
    pub hypervisor_pid: u32,
    pub watchdog_pid: u32,
    pub cgroup_path: String,
}

/// Require an unpredictable, printable per-request proof challenge.
pub fn validate_nonce(value: &str) -> Result<()> {
    if !(16..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        bail!("invalid runtime proof nonce");
    }
    Ok(())
}

/// This local profile has one fixed, independently verified hardware/disk size.
pub fn validate_supported_profile(policy: &VmPolicy) -> Result<()> {
    policy.validate()?;
    if policy.resources.vcpus != 1
        || policy.resources.memory_mib != 2048
        || policy.resources.disk_mib != 2048
    {
        bail!("local runtime supports exactly one vCPU, 2048 MiB RAM and 2048 MiB disk");
    }
    Ok(())
}

/// Select the actual IPv4 NIC, ignoring Kata's addressless tap helper.
pub fn guest_address(inspection: &Value) -> Result<Ipv4Addr> {
    let networks = inspection
        .pointer("/NetworkSettings/Networks")
        .and_then(Value::as_object)
        .context("missing guest network observation")?;
    let mut addresses = networks
        .values()
        .filter_map(|v| v.get("IPAddress").and_then(Value::as_str))
        .filter(|v| !v.is_empty());
    let address = addresses
        .next()
        .context("guest has no IPv4 address")?
        .parse()?;
    if addresses.next().is_some() {
        bail!("guest has ambiguous network addresses");
    }
    Ok(address)
}

/// Recognize only the pinned nerdctl response for the requested missing object.
pub fn confirmed_absent(code: i32, stdout: &[u8], stderr: &[u8], id: &str) -> bool {
    let message = String::from_utf8_lossy(stderr);
    let message = message.trim();
    let expected = format!("level=fatal msg=\"1 errors: [no such object {id}]\"");
    let prefix = message.strip_suffix(&expected);
    code == 1
        && (stdout.is_empty() || stdout == b"[]\n" || stdout == b"[]")
        && prefix.is_some_and(|p| {
            p.is_empty() || (p.starts_with("time=\"") && p.ends_with("\" ") && !p.contains('\n'))
        })
}
