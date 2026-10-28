//! Native TCP intent compiled beneath an immutable operator ceiling.
use super::{Endpoint, NetworkPolicy};
use crate::proto::openshell::sandbox::v1::{NetworkEndpoint, SandboxPolicy};
use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;

/// Compile supported native intent; omitted network rules grant no access.
///
/// # Errors
/// Rejects unsupported native guarantees and destinations outside the ceiling.
pub fn compile_native(native: &SandboxPolicy, ceiling: &NetworkPolicy) -> Result<NetworkPolicy> {
    let without_network = SandboxPolicy {
        network_policies: Default::default(),
        ..native.clone()
    };
    let _intent = crate::policy::validate_policy(&without_network)?;
    let ceiling = ceiling.validate()?;
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

    Ok(NetworkPolicy {
        tcp_allow: allowed.into_iter().collect(),
    })
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
