use crate::proto::openshell::{compute::v1::DriverSandbox, sandbox::v1::GetSandboxConfigResponse};
use anyhow::{Result, bail};

pub fn compile_request(
    sandbox: &DriverSandbox,
    operator: &crate::profile::VmPolicy,
) -> Result<crate::profile::VmPolicy> {
    let native = sandbox
        .spec
        .as_ref()
        .and_then(|s| s.policy.as_ref())
        .ok_or_else(|| anyhow::anyhow!("hardened mode requires explicit native policy"))?;
    // Reuse the exact image/environment/resource boundary, then separately
    // compile native network intent without discarding its requirements.
    let mut shape = sandbox.clone();
    shape.spec.as_mut().expect("spec checked").policy = None;
    validate_request(&shape, true)?;
    operator.compile(native)
}

pub fn validate_request(sandbox: &DriverSandbox, prototype: bool) -> Result<()> {
    if !prototype {
        let policy = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.policy.as_ref())
            .ok_or_else(|| anyhow::anyhow!("strict mode requires an explicit policy"))?;
        let _validated = crate::policy::validate_policy(policy)?;
        bail!(
            "runtime enforcement is not qualified: verified VM, storage and external network fences are required"
        );
    }
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("sandbox spec required"))?;
    let template = spec
        .template
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("sandbox template required"))?;
    if !matches!(
        template.image.as_str(),
        "docker:29-dind" | "docker.io/library/docker:29-dind"
    ) {
        bail!("prototype supports only docker:29-dind");
    }
    if !spec.environment.is_empty()
        || !template.environment.is_empty()
        || template
            .driver_config
            .as_ref()
            .is_some_and(|v| !v.fields.is_empty())
        || spec.isolation_backend.is_some()
    {
        bail!("unsupported runtime configuration");
    }
    if template.resources.as_ref().is_some_and(|v| {
        !v.cpu_request.is_empty()
            || !v.cpu_limit.is_empty()
            || !v.memory_request.is_empty()
            || !v.memory_limit.is_empty()
    }) || spec
        .resource_requirements
        .as_ref()
        .is_some_and(|v| v.gpu.is_some())
    {
        bail!("prototype rejects resource overrides");
    }
    if spec
        .policy
        .as_ref()
        .is_some_and(|p| !p.network_policies.is_empty())
    {
        bail!("prototype cannot enforce network policies");
    }
    Ok(())
}
pub fn validate_snapshot(config: &GetSandboxConfigResponse) -> Result<()> {
    if !config.configuration_admitted {
        bail!("gateway has not admitted the configuration");
    }
    if config
        .policy
        .as_ref()
        .is_some_and(|p| !p.network_policies.is_empty())
        || !config.supervisor_middleware_services.is_empty()
    {
        bail!("prototype cannot enforce effective network policy or middleware");
    }
    Ok(())
}
