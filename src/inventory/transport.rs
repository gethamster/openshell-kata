//! Generation-bound ConfigMap transport without extending source authority.
mod api;
mod run;
#[cfg(test)]
mod tests;

use super::{InventoryConfig, config, publication};
use crate::network::InfrastructureInventory;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

pub(super) use run::{run_courier, run_publisher};
const LIMIT: u64 = 1024 * 1024;
const KEY: &str = "inventory.json";
const RUN: &str = "openshell-kata.io/inventory-run";

/// Fresh observations are generated using the separately pinned inventory file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherConfig {
    pub version: u32,
    pub inventory_config_file: PathBuf,
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub run_uuid: String,
}

/// An exact API object is copied into a private local authority file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CourierConfig {
    pub version: u32,
    pub kubectl_path: PathBuf,
    pub kubectl_sha256: String,
    pub kubeconfig_path: PathBuf,
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub run_uuid: String,
    pub output_path: PathBuf,
    pub poll_millis: u64,
    pub api_timeout_secs: u64,
}

#[derive(Clone, Debug)]
struct Target {
    namespace: String,
    name: String,
    uid: String,
    run_uuid: String,
}

fn uuid(value: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(value)?;
    ensure!(
        !parsed.is_nil() && parsed.to_string() == value,
        "noncanonical inventory transport identity"
    );
    Ok(())
}
fn dns(value: &str, namespaced: bool) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= if namespaced { 63 } else { 253 },
        "invalid inventory resource name"
    );
    ensure!(
        !namespaced || !value.contains('.'),
        "namespace cannot contain dots"
    );
    for label in value.split('.') {
        ensure!(
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "invalid inventory DNS label"
        );
    }
    Ok(())
}
fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    config::trusted_file(path, LIMIT)?;
    Ok(serde_json::from_slice(&config::bounded(path, LIMIT)?)?)
}
impl PublisherConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let result: Self = load(path)?;
        ensure!(
            result.version == 1,
            "unsupported inventory publisher version"
        );
        result.target().validate()?;
        config::absolute(&result.inventory_config_file)?;
        Ok(result)
    }
    fn target(&self) -> Target {
        Target {
            namespace: self.namespace.clone(),
            name: self.name.clone(),
            uid: self.uid.clone(),
            run_uuid: self.run_uuid.clone(),
        }
    }
}
impl CourierConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let result: Self = load(path)?;
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && (1..=1000).contains(&self.poll_millis)
                && (1..=5).contains(&self.api_timeout_secs),
            "invalid courier version or timing"
        );
        self.target().validate()?;
        config::absolute(&self.output_path)?;
        ensure!(
            self.output_path != self.kubectl_path && self.output_path != self.kubeconfig_path,
            "courier output aliases trusted input"
        );
        config::validate_auth(
            &self.kubectl_path,
            &self.kubectl_sha256,
            &self.kubeconfig_path,
        )
    }
    fn target(&self) -> Target {
        Target {
            namespace: self.namespace.clone(),
            name: self.name.clone(),
            uid: self.uid.clone(),
            run_uuid: self.run_uuid.clone(),
        }
    }
}
impl Target {
    fn validate(&self) -> Result<()> {
        dns(&self.namespace, true)?;
        dns(&self.name, false)?;
        uuid(&self.uid)?;
        uuid(&self.run_uuid)
    }
    fn path(&self) -> String {
        format!(
            "/api/v1/namespaces/{}/configmaps/{}",
            self.namespace, self.name
        )
    }
    fn observe(&self, value: &Value) -> Result<(String, String)> {
        ensure!(
            value["apiVersion"] == "v1"
                && value["kind"] == "ConfigMap"
                && value["metadata"]["namespace"] == self.namespace
                && value["metadata"]["name"] == self.name
                && value["metadata"]["uid"] == self.uid
                && value["metadata"]["annotations"][RUN] == self.run_uuid,
            "inventory ConfigMap identity or run differs"
        );
        ensure!(
            value["metadata"]
                .get("deletionTimestamp")
                .is_none_or(Value::is_null)
                && value.get("immutable").is_none_or(|v| v == false)
                && value
                    .get("binaryData")
                    .is_none_or(|v| v.as_object().is_some_and(serde_json::Map::is_empty)),
            "inventory ConfigMap is terminating, immutable or mixed"
        );
        let rv = value["metadata"]["resourceVersion"]
            .as_str()
            .context("inventory resource version missing")?;
        ensure!(
            !rv.is_empty() && rv.len() <= 128 && rv.bytes().all(|b| b.is_ascii_graphic()),
            "invalid inventory resource version"
        );
        let data = value["data"]
            .as_object()
            .context("inventory ConfigMap data missing")?;
        ensure!(data.len() == 1, "unexpected inventory ConfigMap data keys");
        let bytes = data
            .get(KEY)
            .and_then(Value::as_str)
            .context("inventory data key missing")?;
        ensure!(
            bytes.len() as u64 <= LIMIT,
            "inventory ConfigMap data exceeds limit"
        );
        Ok((rv.into(), bytes.into()))
    }
}

fn inventory(bytes: &str, now: u64) -> Result<InfrastructureInventory> {
    ensure!(
        bytes.len() as u64 <= LIMIT,
        "inventory exceeds transport bound"
    );
    let value: InfrastructureInventory = serde_json::from_str(bytes)?;
    value.validate_at(now)?;
    ensure!(
        !value.denied_cidrs.is_empty(),
        "empty transported infrastructure inventory"
    );
    Ok(value)
}
fn unix_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

struct Cursor {
    value: InfrastructureInventory,
    digest: String,
    deadline: tokio::time::Instant,
}
impl Cursor {
    fn from_value(value: InfrastructureInventory, now: u64) -> Result<Self> {
        value.validate_at(value.issued_at_unix)?;
        Ok(Self {
            digest: value.digest()?,
            deadline: tokio::time::Instant::now()
                + Duration::from_secs(value.expires_at_unix.saturating_sub(now)),
            value,
        })
    }
    fn admit(&self, next: &InfrastructureInventory) -> Result<bool> {
        ensure!(
            next.generation >= self.value.generation,
            "inventory generation regressed"
        );
        if next.generation == self.value.generation {
            ensure!(
                next.digest()? == self.digest,
                "inventory changed within generation"
            );
            ensure!(
                tokio::time::Instant::now() < self.deadline,
                "cached inventory monotonic deadline expired"
            );
            return Ok(false);
        }
        ensure!(
            next.issued_at_unix >= self.value.issued_at_unix,
            "inventory observation time regressed"
        );
        Ok(true)
    }
}
fn retained(path: &Path) -> Result<Option<Cursor>> {
    publication::prepare(path)?;
    if !path.exists() {
        return Ok(None);
    }
    let value: InfrastructureInventory = serde_json::from_slice(&config::bounded(path, LIMIT)?)?;
    Ok(Some(Cursor::from_value(value, unix_now()?)?))
}

fn replacement(
    target: &Target,
    old: &Value,
    new: &InfrastructureInventory,
) -> Result<(Value, String)> {
    let (rv, bytes) = target.observe(old)?;
    if !bytes.is_empty() {
        let previous: InfrastructureInventory = serde_json::from_str(&bytes)?;
        previous.validate_at(previous.issued_at_unix)?;
        ensure!(
            new.generation > previous.generation,
            "publisher generation did not advance"
        );
    }
    new.validate_at(unix_now()?)?;
    let mut value = old.clone();
    value["data"][KEY] = Value::String(serde_json::to_string(new)?);
    Ok((value, rv))
}
fn committed(
    target: &Target,
    value: &Value,
    expected: &InfrastructureInventory,
    old_rv: &str,
) -> Result<()> {
    let (rv, bytes) = target.observe(value)?;
    ensure!(
        rv != old_rv,
        "inventory replacement did not advance resource version"
    );
    let found = inventory(&bytes, unix_now()?)?;
    ensure!(
        found.generation == expected.generation && found.digest()? == expected.digest()?,
        "inventory write outcome differs"
    );
    Ok(())
}
