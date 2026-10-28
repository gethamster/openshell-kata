use super::InventoryConfig;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{collections::BTreeSet, net::IpAddr, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command};

#[derive(Default)]
pub(super) struct Footprint {
    pub cidrs: BTreeSet<String>,
    pub names: BTreeSet<String>,
    count: usize,
}
fn strings(value: Option<&Value>) -> Result<Vec<&str>> {
    match value {
        None => Ok(vec![]),
        Some(Value::Array(values)) => values
            .iter()
            .map(|v| v.as_str().context("inventory address must be string"))
            .collect(),
        _ => anyhow::bail!("inventory address collection must be array"),
    }
}
fn ip(value: &str, output: &mut Footprint) -> Result<()> {
    let address: IpAddr = value
        .parse()
        .context("invalid Kubernetes infrastructure IP")?;
    output.cidrs.insert(match address {
        IpAddr::V4(_) => format!("{address}/32"),
        IpAddr::V6(_) => format!("{address}/128"),
    });
    ensure!(
        output.cidrs.len() <= 4096,
        "excessive Kubernetes IP inventory"
    );
    Ok(())
}
fn name(value: &str, output: &mut Footprint) -> Result<()> {
    let normalized = crate::network::normalize_host(value)?;
    ensure!(
        normalized.parse::<IpAddr>().is_err(),
        "expected DNS infrastructure name"
    );
    output.names.insert(normalized);
    ensure!(
        output.names.len() <= 256,
        "excessive Kubernetes DNS inventory"
    );
    Ok(())
}
pub(super) fn observe_page(
    value: &Value,
    kind: &str,
    external: bool,
    output: &mut Footprint,
) -> Result<()> {
    ensure!(
        value["kind"] == kind,
        "unexpected Kubernetes inventory kind"
    );
    let items = value["items"]
        .as_array()
        .context("missing Kubernetes inventory items")?;
    output.count = output
        .count
        .checked_add(items.len())
        .context("resource count overflow")?;
    ensure!(
        items.len() <= 200 && output.count <= 4096,
        "excessive Kubernetes resources"
    );
    for item in items {
        if kind == "NodeList" {
            let addresses = item["status"]["addresses"]
                .as_array()
                .context("node has no observed addresses")?;
            ensure!(
                !addresses.is_empty() && addresses.len() <= 32,
                "invalid node address count"
            );
            for address in addresses {
                let v = address["address"]
                    .as_str()
                    .context("node address missing")?;
                match address["type"].as_str() {
                    Some("InternalIP" | "ExternalIP") => ip(v, output)?,
                    Some("Hostname" | "InternalDNS" | "ExternalDNS") => {
                        if v.contains('.') {
                            name(v, output)?;
                        }
                    }
                    _ => anyhow::bail!("unsupported node address type"),
                }
            }
        } else {
            let spec = item["spec"]
                .as_object()
                .context("service specification missing")?;
            ensure!(
                spec.contains_key("clusterIP")
                    || spec.contains_key("clusterIPs")
                    || spec.contains_key("externalName"),
                "service has no observed cluster address or ExternalName"
            );
            for field in ["clusterIPs", "externalIPs"] {
                for v in strings(spec.get(field))? {
                    if v != "None" {
                        ip(v, output)?;
                    }
                }
            }
            if let Some(v) = spec.get("clusterIP") {
                let v = v.as_str().context("invalid clusterIP")?;
                if v != "None" {
                    ip(v, output)?;
                }
            }
            if external && let Some(v) = spec.get("externalName") {
                name(v.as_str().context("invalid ExternalName")?, output)?;
            }
            if let Some(ingress) = item.pointer("/status/loadBalancer/ingress") {
                let entries = ingress
                    .as_array()
                    .context("invalid load-balancer ingress")?;
                ensure!(entries.len() <= 256, "excessive load-balancer ingress");
                for entry in entries {
                    let mut present = false;
                    if let Some(v) = entry.get("ip") {
                        ip(v.as_str().context("invalid LB IP")?, output)?;
                        present = true;
                    }
                    if let Some(v) = entry.get("hostname") {
                        name(v.as_str().context("invalid LB hostname")?, output)?;
                        present = true;
                    }
                    ensure!(present, "empty load-balancer ingress");
                }
            }
        }
    }
    Ok(())
}
async fn page(config: &InventoryConfig, path: &str) -> Result<Value> {
    let mut child = Command::new(&config.kubectl_path)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args([
            "--kubeconfig",
            config
                .kubeconfig_path
                .to_str()
                .context("UTF8 kubeconfig path")?,
            "--request-timeout",
            &format!("{}s", config.api_timeout_secs),
            "get",
            "--raw",
            path,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = child.stdout.take().context("kubectl stdout unavailable")?;
    let mut bytes = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(config.api_timeout_secs), async {
        (&mut stdout)
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= 4 * 1024 * 1024,
            "Kubernetes inventory page too large"
        );
        ensure!(
            child.wait().await?.success(),
            "Kubernetes inventory request failed"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await;
    result.context("Kubernetes inventory request timed out")??;
    Ok(serde_json::from_slice(&bytes)?)
}
fn encode(token: &str) -> String {
    token
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
pub(super) async fn observe(config: &InventoryConfig) -> Result<Footprint> {
    let mut output = Footprint::default();
    for (resource, kind) in [("nodes", "NodeList"), ("services", "ServiceList")] {
        let mut next = String::new();
        let mut seen = BTreeSet::new();
        let mut revision = None;
        for index in 0..=32 {
            ensure!(index < 32, "excessive Kubernetes inventory pagination");
            let path = format!(
                "/api/v1/{resource}?limit=200{}",
                if next.is_empty() {
                    String::new()
                } else {
                    format!("&continue={}", encode(&next))
                }
            );
            let value = page(config, &path).await?;
            let current = value["metadata"]["resourceVersion"]
                .as_str()
                .context("inventory list lacks consistent resource version")?;
            ensure!(
                !current.is_empty() && current.len() <= 1024,
                "invalid Kubernetes inventory resource version"
            );
            if let Some(previous) = &revision {
                ensure!(
                    previous == current,
                    "Kubernetes resource revision changed during pagination"
                );
            } else {
                revision = Some(current.to_string());
            }
            observe_page(&value, kind, config.include_external_names, &mut output)?;
            next = match value["metadata"].get("continue") {
                None => String::new(),
                Some(v) => v.as_str().context("invalid pagination token")?.to_string(),
            };
            if next.is_empty() {
                break;
            }
            ensure!(
                next.len() <= 8192 && seen.insert(next.clone()),
                "invalid/repeated pagination token"
            );
        }
    }
    Ok(output)
}
