use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{net::Ipv4Addr, process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command};

/// Host-owned identity of a dedicated point-to-point guest network attachment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceSpec {
    pub sandbox_id: String,
    pub host_veth: String,
    pub ifindex: u32,
    pub guest_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub guest_mac: String,
    pub gateway_mac: String,
    pub broker_port: u16,
    pub proof_nonce: String,
}
impl FenceSpec {
    pub fn validate(&self) -> Result<()> {
        crate::config::SandboxId::parse(&self.sandbox_id)?;
        if self.host_veth.is_empty()
            || self.host_veth.len() > 15
            || !self
                .host_veth
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || self.ifindex == 0
        {
            bail!("invalid host interface identity");
        }
        if !self.guest_ip.is_private()
            || !self.gateway_ip.is_private()
            || self.guest_ip == self.gateway_ip
        {
            bail!("guest and gateway require distinct private IPv4 addresses");
        }
        for mac in [&self.guest_mac, &self.gateway_mac] {
            let octets = mac
                .split(':')
                .map(|part| {
                    if part.len() == 2 {
                        u8::from_str_radix(part, 16).ok()
                    } else {
                        None
                    }
                })
                .collect::<Option<Vec<_>>>()
                .context("invalid network MAC")?;
            if octets.len() != 6 || octets[0] & 1 != 0 || octets.iter().all(|x| *x == 0) {
                bail!("network MAC must be unicast");
            }
        }
        if self.broker_port == 0 || self.broker_port == 22 {
            bail!("invalid dedicated broker port");
        }
        if !(16..=128).contains(&self.proof_nonce.len())
            || !self
                .proof_nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            bail!("invalid network proof nonce");
        }
        Ok(())
    }
    pub fn table_name(&self) -> String {
        format!("osk_net_{}", self.ifindex)
    }
    /// Complete atomic nft batch. No guest-selected expression is interpolated.
    pub fn rules(&self) -> Result<String> {
        self.validate()?;
        let name = self.table_name();
        let dev = &self.host_veth;
        let source = self.guest_ip;
        let gateway = self.gateway_ip;
        let port = self.broker_port;
        let mac = self.guest_mac.to_ascii_lowercase();
        let hostmac = self.gateway_mac.to_ascii_lowercase();
        Ok(format!(
            r#"add table netdev {name} {{ comment "openshell-kata:{}:{}"; }}
add chain netdev {name} ingress {{ type filter hook ingress device "{dev}" priority -500; policy drop; }}
add rule netdev {name} ingress ether saddr != {mac} drop
add rule netdev {name} ingress ether type arp arp htype 1 arp ptype ip arp hlen 6 arp plen 4 arp saddr ether {mac} arp saddr ip {source} arp daddr ip {gateway} arp operation {{ request, reply }} accept
add rule netdev {name} ingress ether type ip ip hdrlength != 5 drop
add rule netdev {name} ingress ether type ip ip frag-off & 0x3fff != 0 drop
add rule netdev {name} ingress ether type ip ether daddr {hostmac} ip saddr {source} ip daddr {gateway} tcp dport {port} accept
add rule netdev {name} ingress ether type ip ether daddr {hostmac} ip saddr {source} ip daddr {gateway} tcp sport 22 accept
add table inet {name} {{ comment "openshell-kata:{}:{}"; }}
add chain inet {name} input {{ type filter hook input priority -250; policy accept; }}
add rule inet {name} input iifname "{dev}" ip saddr {source} ip daddr {gateway} tcp dport {port} accept
add rule inet {name} input iifname "{dev}" ip saddr {source} ip daddr {gateway} tcp sport 22 ct state established ct direction reply accept
add rule inet {name} input iifname "{dev}" drop
add rule inet {name} input iifname != "lo" ip daddr {gateway} tcp dport {port} drop
add chain inet {name} forward {{ type filter hook forward priority -250; policy accept; }}
add rule inet {name} forward iifname "{dev}" drop
add rule inet {name} forward oifname "{dev}" drop
"#,
            self.sandbox_id, self.proof_nonce, self.sandbox_id, self.proof_nonce
        ))
    }
}

/// A read-back of installed host rules, bound to a specific interface generation.
/// Store it in host-owned state; it is not a guest-provided authorization token.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceProof {
    pub spec: FenceSpec,
    pub netdev: Value,
    pub inet: Value,
}

async fn nft(args: &[&str], input: Option<&str>) -> Result<Vec<u8>> {
    let mut command = Command::new("nft");
    command
        .args(args)
        .kill_on_drop(true)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context("starting host nft tool")?;
    if let Some(input) = input {
        let mut stdin = child.stdin.take().context("nft stdin unavailable")?;
        stdin.write_all(input.as_bytes()).await?;
        stdin.shutdown().await?;
    }
    let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .context("host nft command timed out")??;
    if !output.status.success() {
        bail!(
            "host nft command rejected: {}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(2048)
                .collect::<String>()
        );
    }
    Ok(output.stdout)
}
async fn check_interface(spec: &FenceSpec) -> Result<()> {
    spec.validate()?;
    if !cfg!(target_os = "linux") {
        bail!("host network fencing requires Linux");
    }
    let path = format!("/sys/class/net/{}/ifindex", spec.host_veth);
    let actual = tokio::fs::read_to_string(path)
        .await?
        .trim()
        .parse::<u32>()?;
    if actual != spec.ifindex {
        bail!("host network interface generation changed");
    }
    let mac =
        tokio::fs::read_to_string(format!("/sys/class/net/{}/address", spec.host_veth)).await?;
    if !mac.trim().eq_ignore_ascii_case(&spec.gateway_mac) {
        bail!("host network interface MAC changed");
    }
    if !if_addrs::get_if_addrs()?.iter().any(|interface| {
        interface.name == spec.host_veth && interface.ip() == std::net::IpAddr::V4(spec.gateway_ip)
    }) {
        bail!("host network gateway address is not attached to the fenced interface");
    }
    Ok(())
}
fn normalized(mut value: Value) -> Value {
    fn strip(value: &mut Value) {
        match value {
            Value::Object(object) => {
                object.remove("handle");
                object.remove("index");
                for value in object.values_mut() {
                    strip(value);
                }
            }
            Value::Array(array) => {
                array.retain(|item| item.get("metainfo").is_none());
                for value in array {
                    strip(value);
                }
            }
            _ => {}
        }
    }
    strip(&mut value);
    value
}
async fn read_tables(spec: &FenceSpec) -> Result<(Value, Value)> {
    let table = spec.table_name();
    let netdev = normalized(serde_json::from_slice(
        &nft(&["-j", "list", "table", "netdev", &table], None).await?,
    )?);
    let inet = normalized(serde_json::from_slice(
        &nft(&["-j", "list", "table", "inet", &table], None).await?,
    )?);
    Ok((netdev, inet))
}

/// Install rules before enabling the guest link, then return their exact read-back.
pub async fn install_fence(spec: FenceSpec) -> Result<FenceProof> {
    check_interface(&spec).await?;
    let rules = spec.rules()?;
    nft(&["-f", "-"], Some(&rules)).await?;
    check_interface(&spec).await?;
    let (netdev, inet) = read_tables(&spec).await?;
    Ok(FenceProof { spec, netdev, inet })
}
/// Verify both interface identity and installed rules against host-owned proof.
pub async fn verify_fence(proof: &FenceProof) -> Result<()> {
    check_interface(&proof.spec).await?;
    let (netdev, inet) = read_tables(&proof.spec).await?;
    if netdev != proof.netdev || inet != proof.inet {
        bail!("host network fence no longer matches installed proof");
    }
    Ok(())
}
/// Remove only this verified attachment's tables, before deleting its interface.
pub async fn remove_fence(proof: &FenceProof) -> Result<()> {
    verify_fence(proof).await?;
    let table = proof.spec.table_name();
    nft(
        &["-f", "-"],
        Some(&format!(
            "delete table netdev {table}\ndelete table inet {table}\n"
        )),
    )
    .await?;
    Ok(())
}
