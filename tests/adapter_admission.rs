use openshell_kata::{
    admission,
    proto::openshell::{compute::v1 as c, sandbox::v1 as s},
};

fn sandbox() -> c::DriverSandbox {
    c::DriverSandbox {
        id: "sandbox-123".into(),
        spec: Some(c::DriverSandboxSpec {
            template: Some(c::DriverSandboxTemplate {
                image: "docker:29-dind".into(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn unqualified_policy_mode_fails_closed_before_provisioning() {
    assert!(admission::validate_request(&sandbox(), false).is_err());
    assert!(admission::validate_request(&sandbox(), true).is_ok());
}

#[test]
fn unsupported_image_environment_resources_and_network_are_rejected() {
    let mut image = sandbox();
    image
        .spec
        .as_mut()
        .expect("spec")
        .template
        .as_mut()
        .expect("template")
        .image = "ubuntu:latest".into();
    let mut environment = sandbox();
    environment
        .spec
        .as_mut()
        .expect("spec")
        .environment
        .insert("SECRET".into(), "test-placeholder".into());
    let mut resource = sandbox();
    resource
        .spec
        .as_mut()
        .expect("spec")
        .template
        .as_mut()
        .expect("template")
        .resources = Some(c::DriverResourceRequirements {
        memory_limit: "2Gi".into(),
        ..Default::default()
    });
    let mut network = sandbox();
    network.spec.as_mut().expect("spec").policy = Some(s::SandboxPolicy {
        network_policies: std::collections::HashMap::from([(
            "external".into(),
            s::NetworkPolicyRule::default(),
        )]),
        ..Default::default()
    });
    for input in [image, environment, resource, network] {
        assert!(admission::validate_request(&input, true).is_err());
    }
}

#[test]
fn gateway_snapshot_must_be_admitted_before_activation() {
    assert!(admission::validate_snapshot(&s::GetSandboxConfigResponse::default()).is_err());
    assert!(
        admission::validate_snapshot(&s::GetSandboxConfigResponse {
            configuration_admitted: true,
            ..Default::default()
        })
        .is_ok()
    );
}

#[test]
fn strict_mode_validates_intent_but_never_admits_without_runtime_fences() {
    let mut input = sandbox();
    input.spec.as_mut().expect("spec").policy = Some(s::SandboxPolicy {
        version: 2,
        ..Default::default()
    });
    let error = admission::validate_request(&input, false).expect_err("unknown policy rejected");
    assert!(error.to_string().contains("unsupported policy version"));
    input
        .spec
        .as_mut()
        .expect("spec")
        .policy
        .as_mut()
        .expect("policy")
        .version = 1;
    let error =
        admission::validate_request(&input, false).expect_err("intent is not enforcement evidence");
    assert!(
        error
            .to_string()
            .contains("runtime enforcement is not qualified")
    );
}
