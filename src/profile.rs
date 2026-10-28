//! Immutable operator ceilings compiled with native OpenShell policy intent.
use crate::{
    boundary::{
        filesystem::FilesystemPolicy,
        process::{OperatorCeilings, VmLimits},
    },
    network::{Endpoint, NetworkPolicy},
    proto::openshell::sandbox::v1::{NetworkEndpoint, SandboxPolicy},
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::{collections::BTreeSet, path::Path};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VmPolicy {
    pub version: u32,
    pub profile: String,
    pub resources: VmLimits,
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
}
impl VmPolicy {
    pub fn load(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .context("reading operator VM policy")?
            .take(128 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 128 * 1024 {
            bail!("operator policy exceeds size limit");
        }
        let policy: Self = serde_json::from_slice(&bytes).context("decoding operator VM policy")?;
        policy.validate()?;
        Ok(Self {
            network: policy.network.validate()?.normalized(),
            ..policy
        })
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.profile != "docker-vm" {
            bail!("unsupported VM policy version or profile");
        }
        self.resources.validate(&OperatorCeilings::default())?;
        self.filesystem.validate()?;
        self.network.validate()?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let canonical = Self {
            network: self.network.validate()?.normalized(),
            ..self.clone()
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&canonical)?)
        ))
    }
    /// Native network intent can only reduce the trusted operator ceiling.
    /// Guest-root Docker cannot enforce executable identity or native FS rules.
    pub fn compile(&self, native: &SandboxPolicy) -> Result<Self> {
        self.validate()?;
        let without_network = SandboxPolicy {
            network_policies: Default::default(),
            ..native.clone()
        };
        let _intent = crate::policy::validate_policy(&without_network)?;
        let ceiling = self.network.validate()?;
        let mut allowed = BTreeSet::new();
        for rule in native.network_policies.values() {
            if rule.binaries.is_empty() || rule.endpoints.is_empty() {
                bail!("network rule requires endpoints and all-binary selector");
            }
            for binary in &rule.binaries {
                let all_binaries =
                    crate::proto::openshell::sandbox::v1::NetworkBinary { path: "/**".into() };
                if binary.path != "/**" || binary != &all_binaries {
                    bail!("guest executable identity enforcement is unsupported");
                }
            }
            for endpoint in &rule.endpoints {
                validate_endpoint(endpoint)?;
                let ports = if endpoint.ports.is_empty() {
                    vec![endpoint.port]
                } else {
                    endpoint.ports.clone()
                };
                for port in ports {
                    let port = u16::try_from(port).context("invalid TCP port")?;
                    let requested = NetworkPolicy {
                        tcp_allow: vec![Endpoint {
                            host: endpoint.host.clone(),
                            port,
                        }],
                    };
                    requested.validate()?;
                    if !ceiling.allows(&endpoint.host, port) {
                        bail!("native destination exceeds operator network ceiling");
                    }
                    // Policy validation canonicalizes DNS case and terminal dot.
                    let host = endpoint.host.trim_end_matches('.').to_ascii_lowercase();
                    let host = host
                        .parse::<std::net::IpAddr>()
                        .map_or(host, |ip| ip.to_string());
                    allowed.insert(Endpoint { host, port });
                }
            }
        }
        Ok(Self {
            network: NetworkPolicy {
                tcp_allow: allowed.into_iter().collect(),
            },
            ..self.clone()
        })
    }
}
fn validate_endpoint(endpoint: &NetworkEndpoint) -> Result<()> {
    let supported = NetworkEndpoint {
        host: endpoint.host.clone(),
        port: endpoint.port,
        ports: endpoint.ports.clone(),
        protocol: endpoint.protocol.clone(),
        tls: endpoint.tls,
        enforcement: endpoint.enforcement,
        // The gateway stamps this opaque authority even on uncredentialed
        // global TCP policies. It conveys no credentials to this runtime.
        token_grant_owner: endpoint.token_grant_owner.clone(),
        ..Default::default()
    };
    if endpoint != &supported
        || !matches!(endpoint.protocol.as_str(), "" | "tcp")
        || endpoint.tls != 1
        || !matches!(endpoint.enforcement, 0 | 1)
        || !valid_owner(&endpoint.token_grant_owner)
    {
        bail!(
            "endpoint requires unsupported fields [{}], protocol or TLS behavior (tcp={}, tls_mode={}, enforcement_mode={}); use explicit tls skip and TCP",
            unsupported_fields(endpoint),
            matches!(endpoint.protocol.as_str(), "" | "tcp"),
            endpoint.tls,
            endpoint.enforcement
        );
    }
    if endpoint.port != 0 && !endpoint.ports.is_empty() && endpoint.ports != [endpoint.port] {
        bail!("ambiguous endpoint ports");
    }
    Ok(())
}

fn valid_owner(owner: &str) -> bool {
    owner.is_empty()
        || owner
            .strip_prefix("grant-owner:v1:")
            .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn unsupported_fields(e: &NetworkEndpoint) -> String {
    [
        ("access", e.access != 0),
        ("rules", !e.rules.is_empty()),
        ("allowed_ips", !e.allowed_ips.is_empty()),
        ("deny_rules", !e.deny_rules.is_empty()),
        ("allow_encoded_slash", e.allow_encoded_slash),
        ("persisted_queries", !e.persisted_queries.is_empty()),
        (
            "graphql_persisted_queries",
            !e.graphql_persisted_queries.is_empty(),
        ),
        ("graphql_max_body_bytes", e.graphql_max_body_bytes != 0),
        ("path", !e.path.is_empty()),
        (
            "websocket_credential_rewrite",
            e.websocket_credential_rewrite,
        ),
        (
            "request_body_credential_rewrite",
            e.request_body_credential_rewrite,
        ),
        ("advisor_proposed", e.advisor_proposed),
        ("credential_signing", !e.credential_signing.is_empty()),
        ("signing_service", !e.signing_service.is_empty()),
        ("signing_region", !e.signing_region.is_empty()),
        ("json_rpc_max_body_bytes", e.json_rpc_max_body_bytes != 0),
        ("mcp", e.mcp.is_some()),
        ("credential_binding", e.credential_binding.is_some()),
        (
            "allow_uninspected_credentials",
            e.allow_uninspected_credentials,
        ),
        ("provider_credentialed", e.provider_credentialed),
        ("token_grant_owner", !e.token_grant_owner.is_empty()),
    ]
    .into_iter()
    .filter_map(|(name, present)| present.then_some(name))
    .collect::<Vec<_>>()
    .join(",")
}

/// Fresh host-runtime observation, never supplied by a sandbox or gateway user.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnforcementEvidence {
    pub sandbox_id: String,
    pub policy_sha256: String,
    pub nonce: String,
    pub runtime: String,
    pub hypervisor_pid: u32,
    pub resources: VmLimits,
    pub storage_id: String,
    pub network_fence: String,
    pub watchdog_pid: u32,
    pub expires_at_unix_secs: u64,
}
impl EnforcementEvidence {
    pub fn validate(&self, id: &str, nonce: &str, policy: &VmPolicy) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        if self.sandbox_id != id
            || self.nonce != nonce
            || self.policy_sha256 != policy.digest()?
            || self.resources != policy.resources
            || self.runtime != "kata-runtime-rs"
            || self.hypervisor_pid == 0
            || self.watchdog_pid == 0
            || self.storage_id.is_empty()
            || self.network_fence.is_empty()
            || self.expires_at_unix_secs <= now
            || self.expires_at_unix_secs > now.saturating_add(policy.resources.lifetime_secs)
        {
            bail!("runtime enforcement evidence does not match this launch");
        }
        Ok(())
    }
}
