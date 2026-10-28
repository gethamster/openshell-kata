//! Explicit VM-scoped admission and live Kubernetes runtime evidence.

use crate::proto::openshell::compute::v1::DriverSandbox;
use anyhow::{Result, bail, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Validate the operator-owned private network used for guest endpoints.
pub fn validate_network(cidr: &str) -> Result<ipnet::IpNet> {
    let network: ipnet::IpNet = cidr.parse()?;
    let private = match network {
        ipnet::IpNet::V4(net) => {
            net.network().is_private() && net.broadcast().is_private() && net.prefix_len() >= 8
        }
        ipnet::IpNet::V6(net) => net.network().is_unique_local() && net.prefix_len() >= 7,
    };
    ensure!(private, "guest network must be a bounded private CIDR");
    Ok(network)
}

/// Evidence produced by the trusted launcher after observing live Kubernetes resources.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProof {
    pub version: u32,
    pub sandbox_id: String,
    pub workspace: String,
    pub namespace: String,
    pub runtime_identity: String,
    pub runtime_class: String,
    pub image: String,
    pub network: String,
    pub cpu: String,
    pub memory: String,
    pub policy_sha256: String,
    pub expires_at_unix: u64,
    pub deadline_enforcement: String,
}

/// Derive the only permitted namespace for a platform-owned workspace.
pub fn namespace(workspace: &str) -> Result<String> {
    ensure!(
        !workspace.is_empty()
            && workspace.len() <= 63
            && workspace
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && workspace.as_bytes()[0].is_ascii_alphanumeric()
            && workspace.as_bytes()[workspace.len() - 1].is_ascii_alphanumeric()
            && !matches!(
                workspace,
                "default"
                    | "kube-system"
                    | "network"
                    | "master"
                    | "foundry"
                    | "dashboard"
                    | "platform"
            ),
        "unsupported hosted workspace"
    );
    let suffix = if workspace.len() <= 55 {
        workspace.to_owned()
    } else {
        format!("{:x}", Sha256::digest(workspace.as_bytes()))[..24].to_owned()
    };
    Ok(format!("sandbox-{suffix}"))
}

/// Require an immutable image in the configured operator profile.
pub fn validate_image(image: &str) -> Result<()> {
    let Some((repository, digest)) = image.split_once("@sha256:") else {
        bail!("hosted guest image must use a SHA-256 digest")
    };
    ensure!(
        !repository.is_empty()
            && !repository.chars().any(char::is_whitespace)
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid immutable guest image"
    );
    Ok(())
}

/// Admit only VM-wide isolation without native guest filesystem/process claims.
pub fn validate_request(sandbox: &DriverSandbox, image: &str) -> Result<()> {
    namespace(&sandbox.workspace)?;
    validate_image(image)?;
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("sandbox spec required"))?;
    let template = spec
        .template
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("sandbox template required"))?;
    ensure!(
        template.image == image,
        "guest image differs from qualified operator profile"
    );
    ensure!(
        spec.environment.is_empty() && template.environment.is_empty(),
        "guest environment overrides are unsupported"
    );
    ensure!(
        spec.isolation_backend.is_none(),
        "external isolation backend override unsupported"
    );
    ensure!(
        template
            .platform_config
            .as_ref()
            .is_none_or(|value| value.fields.is_empty())
            && template
                .driver_config
                .as_ref()
                .is_none_or(|value| value.fields.is_empty()),
        "platform overrides are unsupported"
    );
    ensure!(
        spec.resource_requirements
            .as_ref()
            .is_none_or(|value| value.gpu.is_none()),
        "GPU resources unsupported"
    );
    if let Some(resources) = &template.resources {
        ensure!(
            (resources.cpu_request.is_empty() || resources.cpu_request == "2")
                && (resources.cpu_limit.is_empty() || resources.cpu_limit == "2")
                && (resources.memory_request.is_empty() || resources.memory_request == "4Gi")
                && (resources.memory_limit.is_empty() || resources.memory_limit == "4Gi"),
            "resource override differs from qualified limits"
        );
    }
    let policy = spec
        .policy
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("explicit VM policy required"))?;
    let _validated_intent = crate::policy::validate_policy(policy)?;
    ensure!(
        template.user_namespaces.is_none(),
        "user namespace override unsupported"
    );
    ensure!(
        spec.workload_identity
            .as_ref()
            .is_none_or(|identity| identity.user.is_empty() && identity.group.is_empty()),
        "guest identity selectors unsupported"
    );
    Ok(())
}

impl RuntimeProof {
    /// Bind observed fences to this exact sandbox, workspace, image, and Pod generation.
    pub fn validate(
        &self,
        sandbox: &DriverSandbox,
        image: &str,
        runtime_identity: &str,
    ) -> Result<()> {
        validate_request(sandbox, image)?;
        ensure!(
            self.version == 1
                && self.sandbox_id == sandbox.id
                && self.workspace == sandbox.workspace
                && self.namespace == namespace(&sandbox.workspace)?
                && self.runtime_identity == runtime_identity
                && uuid::Uuid::parse_str(runtime_identity).is_ok(),
            "runtime proof identity differs from sandbox generation"
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        ensure!(
            self.expires_at_unix > now
                && self.expires_at_unix <= now.saturating_add(86400)
                && self.deadline_enforcement == "kubelet-active-deadline",
            "runtime proof has no bounded independent lifetime"
        );
        ensure!(
            self.runtime_class == "kata-qemu-runtime-rs"
                && self.image == image
                && self.network == "deny-all-egress"
                && self.cpu == "2"
                && self.memory == "4Gi"
                && self.policy_sha256.len() == 64
                && self.policy_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "runtime proof is missing qualified fences"
        );
        Ok(())
    }
}
