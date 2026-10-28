use openshell_kata::{
    profile::VmPolicy,
    proto::openshell::sandbox::v1::{
        NetworkBinary, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy,
    },
};

fn profile() -> VmPolicy {
    serde_json::from_str(r#"{"version":1,"profile":"docker-vm","resources":{"vcpus":1,"memory_mib":2048,"disk_mib":2048,"lifetime_secs":3600},"filesystem":{"host_mounts":"deny","transfer_max_bytes":268435456,"transfer_max_entries":4096},"network":{"tcp_allow":[{"host":"example.com","port":443}]}}"#).expect("valid profile fixture")
}
fn native(host: &str) -> SandboxPolicy {
    SandboxPolicy {
        version: 1,
        network_policies: [(
            "web".into(),
            NetworkPolicyRule {
                binaries: vec![NetworkBinary { path: "/**".into() }],
                endpoints: vec![NetworkEndpoint {
                    host: host.into(),
                    port: 443,
                    protocol: "tcp".into(),
                    tls: 1,
                    enforcement: 1,
                    ..Default::default()
                }],
                ..Default::default()
            },
        )]
        .into(),
        ..Default::default()
    }
}
#[test]
fn empty_native_policy_never_grants_operator_network_ceiling() {
    let effective = profile()
        .compile(&SandboxPolicy {
            version: 1,
            ..Default::default()
        })
        .expect("valid profile fixture");
    assert!(effective.network.tcp_allow.is_empty());
}
#[test]
fn native_network_is_intersected_with_operator_ceiling() {
    assert_eq!(
        profile()
            .compile(&native("EXAMPLE.COM"))
            .expect("valid profile fixture")
            .network
            .tcp_allow[0]
            .host,
        "example.com"
    );
    assert!(profile().compile(&native("evil.example")).is_err());
}
#[test]
fn unimplemented_native_endpoint_fields_fail_closed() {
    let mut policy = native("example.com");
    policy
        .network_policies
        .get_mut("web")
        .expect("valid profile fixture")
        .endpoints[0]
        .path = "/secret".into();
    assert!(profile().compile(&policy).is_err());
}
#[test]
fn policy_digest_is_stable_and_sensitive_to_limits() {
    let first = profile();
    let mut second = profile();
    assert_eq!(
        first.digest().expect("valid profile fixture"),
        second.digest().expect("valid profile fixture")
    );
    second.resources.lifetime_secs -= 1;
    assert_ne!(
        first.digest().expect("valid profile fixture"),
        second.digest().expect("valid profile fixture")
    );
}

#[test]
fn digest_canonicalizes_duplicate_and_reordered_destinations() {
    use openshell_kata::network::Endpoint;
    let first = profile();
    let mut same = profile();
    same.network.tcp_allow.push(Endpoint {
        host: "EXAMPLE.COM.".into(),
        port: 443,
    });
    assert_eq!(
        first.digest().expect("digest"),
        same.digest().expect("digest")
    );
}

#[test]
fn gateway_owner_metadata_never_enables_provider_credentials() {
    let mut policy = native("example.com");
    let endpoint = &mut policy
        .network_policies
        .get_mut("web")
        .expect("rule")
        .endpoints[0];
    endpoint.token_grant_owner = format!("grant-owner:v1:{}", "a".repeat(64));
    assert!(profile().compile(&policy).is_ok());
    policy
        .network_policies
        .get_mut("web")
        .expect("rule")
        .endpoints[0]
        .provider_credentialed = true;
    assert!(profile().compile(&policy).is_err());
}
#[test]
fn unknown_fields_and_unsupported_profiles_are_rejected() {
    assert!(
        serde_json::from_str::<VmPolicy>(r#"{"version":1,"profile":"docker-vm","extra":1}"#)
            .is_err()
    );
    let mut policy = profile();
    policy.profile = "native".into();
    assert!(policy.validate().is_err());
}

#[test]
fn rejects_each_native_feature_that_cannot_be_enforced_outside_guest() {
    let mut binary = native("example.com");
    binary
        .network_policies
        .get_mut("web")
        .expect("rule")
        .binaries[0]
        .path = "/usr/bin/curl".into();
    assert!(profile().compile(&binary).is_err());
    let mut filesystem = native("example.com");
    filesystem.filesystem = Some(
        openshell_kata::proto::openshell::sandbox::v1::FilesystemPolicy {
            include_workdir: true,
            ..Default::default()
        },
    );
    assert!(profile().compile(&filesystem).is_err());
    let mut audit = native("example.com");
    audit
        .network_policies
        .get_mut("web")
        .expect("rule")
        .endpoints[0]
        .enforcement = 2;
    assert!(profile().compile(&audit).is_err());
    let mut missing = native("example.com");
    missing
        .network_policies
        .get_mut("web")
        .expect("rule")
        .binaries
        .clear();
    assert!(profile().compile(&missing).is_err());
}

#[test]
fn profile_loading_is_bounded_and_validates_resource_limits() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("policy.json");
    std::fs::write(&path, serde_json::to_vec(&profile())?)?;
    assert_eq!(VmPolicy::load(&path)?, profile());
    std::fs::write(&path, vec![b' '; 128 * 1024 + 1])?;
    assert!(VmPolicy::load(&path).is_err());
    let mut zero = profile();
    zero.resources.vcpus = 0;
    assert!(zero.validate().is_err());
    Ok(())
}

#[test]
fn evidence_is_bound_to_request_policy_resources_and_live_lease() -> anyhow::Result<()> {
    use openshell_kata::profile::EnforcementEvidence;
    let policy = profile();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let evidence = EnforcementEvidence {
        sandbox_id: "sandbox-one".into(),
        policy_sha256: policy.digest()?,
        nonce: "fresh-challenge".into(),
        runtime: "kata-runtime-rs".into(),
        hypervisor_pid: 4,
        resources: policy.resources,
        storage_id: "private-block".into(),
        network_fence: "checked-rules".into(),
        watchdog_pid: 5,
        expires_at_unix_secs: now + 1800,
    };
    evidence.validate("sandbox-one", "fresh-challenge", &policy)?;
    assert!(
        evidence
            .validate("sandbox-two", "fresh-challenge", &policy)
            .is_err()
    );
    assert!(
        evidence
            .validate("sandbox-one", "new-challenge", &policy)
            .is_err()
    );
    let mut expired = evidence.clone();
    expired.expires_at_unix_secs = now;
    assert!(
        expired
            .validate("sandbox-one", "fresh-challenge", &policy)
            .is_err()
    );
    let mut extended = evidence.clone();
    extended.expires_at_unix_secs = now + policy.resources.lifetime_secs + 60;
    assert!(
        extended
            .validate("sandbox-one", "fresh-challenge", &policy)
            .is_err()
    );
    let mut missing = evidence.clone();
    missing.network_fence.clear();
    assert!(
        missing
            .validate("sandbox-one", "fresh-challenge", &policy)
            .is_err()
    );
    let mut wrong = evidence.clone();
    wrong.resources.vcpus += 1;
    assert!(
        wrong
            .validate("sandbox-one", "fresh-challenge", &policy)
            .is_err()
    );
    Ok(())
}

#[test]
fn local_operator_image_and_resources_are_ceilings_not_request_overrides() -> anyhow::Result<()> {
    use openshell_kata::{admission, proto::openshell::compute::v1 as c};
    let image = format!("registry.example/system@sha256:{}", "a".repeat(64));
    let mut sandbox = c::DriverSandbox {
        id: "fixture".into(),
        spec: Some(c::DriverSandboxSpec {
            policy: Some(SandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            template: Some(c::DriverSandboxTemplate {
                image: image.clone(),
                resources: Some(c::DriverResourceRequirements {
                    cpu_request: "1".into(),
                    cpu_limit: "1".into(),
                    memory_request: "2Gi".into(),
                    memory_limit: "2048Mi".into(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    admission::compile_request_for_image(&sandbox, &profile(), Some(&image))?;
    assert!(
        admission::compile_request_for_image(&sandbox, &profile(), None).is_err(),
        "caller cannot select an unconfigured image"
    );
    let template = sandbox
        .spec
        .as_mut()
        .expect("spec")
        .template
        .as_mut()
        .expect("template");
    template.image = format!("registry.example/system@sha256:{}", "b".repeat(64));
    assert!(
        admission::compile_request_for_image(&sandbox, &profile(), Some(&image)).is_err(),
        "operator digest must match"
    );
    let template = sandbox
        .spec
        .as_mut()
        .expect("spec")
        .template
        .as_mut()
        .expect("template");
    template.image = image.clone();
    template.resources.as_mut().expect("limits").cpu_limit = "2".into();
    assert!(
        admission::compile_request_for_image(&sandbox, &profile(), Some(&image)).is_err(),
        "requested CPU cannot exceed actual VM profile"
    );
    Ok(())
}
