use openshell_kata::{
    network::{
        BrokerBinding, HostedBrokerConfig, InfrastructureInventory, NetworkPolicy, compile_native,
    },
    proto::openshell::sandbox::v1::SandboxPolicy,
};
use serde_json::json;

fn config(now: u64) -> HostedBrokerConfig {
    serde_json::from_value(json!({"version":1,"operator_ceiling":{"tcp_allow":[{"host":"example.com","port":443}]},"initial_ceiling":{"tcp_allow":[{"host":"example.com","port":443}]},"binding":{"workspace":"tenant","namespace_uid":uuid::Uuid::new_v4().to_string(),"sandbox_id":uuid::Uuid::new_v4().to_string(),"launch_nonce":uuid::Uuid::new_v4().to_string(),"expires_at_unix":now+3600},"protected_hostname_suffixes":["internal.example.com"],"baseline_denied_cidrs":["10.0.0.0/8"],"authorization_lease_secs":30})).expect("bounded operator profile")
}

#[test]
fn shared_compiler_preserves_empty_native_deny_all() {
    let profile = config(1000);
    let result = compile_native(
        &SandboxPolicy {
            version: 1,
            ..Default::default()
        },
        &profile.operator_ceiling,
    )
    .expect("explicit minimal policy");
    assert_eq!(result, NetworkPolicy::default());
}

#[test]
fn hosted_profile_is_bounded_and_canonical() {
    let profile = config(1000);
    profile.validate().expect("qualified config");
    let mut invalid = profile.clone();
    invalid.authorization_lease_secs = 31;
    assert!(invalid.validate().is_err());
    invalid = profile.clone();
    invalid.initial_ceiling.tcp_allow[0].host = "foreign.example.com".into();
    assert!(invalid.validate().is_err());
    let mut canonical = profile.clone();
    canonical.baseline_denied_cidrs.push("10.1.2.3/8".into());
    assert_eq!(
        profile.digest().expect("digest"),
        canonical.digest().expect("canonical digest")
    );
}

#[test]
fn inventory_freshness_and_revision_are_explicit() {
    let current = InfrastructureInventory {
        version: 1,
        generation: 1,
        issued_at_unix: 1000,
        expires_at_unix: 1060,
        denied_cidrs: vec!["8.8.8.8/32".into()],
    };
    current.validate_at(1000).expect("fresh inventory");
    assert!(current.validate_at(1060).is_err());
    let mut future = current.clone();
    future.issued_at_unix = 1001;
    assert!(future.validate_at(1000).is_err());
    let mut long = current.clone();
    long.expires_at_unix = 1061;
    assert!(long.validate_at(1000).is_err());
}

#[test]
fn immutable_binding_rejects_unknown_fields() {
    let mut value = serde_json::to_value(config(1000).binding).expect("binding");
    value["extra"] = true.into();
    assert!(serde_json::from_value::<BrokerBinding>(value).is_err());
}

#[test]
fn invalid_operator_inputs_fail_before_broker_start() {
    let profile = config(1000);
    let value = serde_json::to_value(&profile).expect("configuration");
    for (field, bad) in [
        ("version", json!(2)),
        ("authorization_lease_secs", json!(0)),
        ("baseline_denied_cidrs", json!(["10.0.0.1"])),
        ("protected_hostname_suffixes", json!(["8.8.8.8."])),
        ("protected_hostname_suffixes", json!(["*.internal"])),
        ("protected_hostname_suffixes", json!(["EXAMPLE.COM."])),
    ] {
        let mut invalid = value.clone();
        invalid[field] = bad;
        assert!(
            serde_json::from_value::<HostedBrokerConfig>(invalid)
                .expect("typed config")
                .validate()
                .is_err(),
            "invalid field {field}"
        );
    }
    for (field, bad) in [
        ("workspace", json!("Tenant")),
        ("workspace", json!("-tenant")),
        ("namespace_uid", json!("not-a-uuid")),
        ("sandbox_id", json!("../../other")),
        ("launch_nonce", json!("not-a-uuid")),
        ("expires_at_unix", json!(0)),
    ] {
        let mut invalid = profile.binding.clone();
        let mut binding = serde_json::to_value(&invalid).expect("binding");
        binding[field] = bad;
        invalid = serde_json::from_value(binding).expect("typed binding");
        assert!(invalid.validate().is_err(), "invalid binding {field}");
    }
}

#[test]
fn trusted_config_load_is_bounded_and_empty_operator_defaults_to_deny() {
    let root = tempfile::tempdir().expect("temporary config");
    let path = root.path().join("config.json");
    let mut profile = config(1000);
    profile.operator_ceiling = NetworkPolicy::default();
    profile.initial_ceiling = NetworkPolicy::default();
    std::fs::write(&path, serde_json::to_vec(&profile).expect("serialize")).expect("write");
    let loaded = HostedBrokerConfig::load(&path).expect("deny-all profile");
    assert_eq!(
        loaded
            .compile(&SandboxPolicy {
                version: 1,
                ..Default::default()
            })
            .expect("empty native intent"),
        NetworkPolicy::default()
    );
    std::fs::write(&path, vec![b' '; 1024 * 1024 + 1]).expect("oversized file");
    assert!(HostedBrokerConfig::load(&path).is_err());
}
