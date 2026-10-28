use openshell_kata::network::FenceSpec;

fn spec() -> FenceSpec {
    FenceSpec {
        sandbox_id: "sandbox-123".into(),
        host_veth: "okata12".into(),
        ifindex: 12,
        guest_ip: "10.240.0.2".parse().expect("IP"),
        gateway_ip: "10.240.0.1".parse().expect("IP"),
        guest_mac: "02:00:00:00:00:02".into(),
        gateway_mac: "02:00:00:00:00:01".into(),
        broker_port: 18080,
        proof_nonce: "0123456789abcdef".into(),
    }
}

#[test]
fn fence_is_bound_to_host_interface_and_denies_unbrokered_traffic() {
    let rules = spec().rules().expect("valid rules");
    assert!(rules.contains("hook ingress device \"okata12\""));
    assert!(rules.contains("policy drop"));
    assert!(rules.contains("ether saddr != 02:00:00:00:00:02 drop"));
    assert!(rules.contains("ip frag-off & 0x3fff != 0 drop"));
    assert!(rules.contains("ip hdrlength != 5 drop"));
    assert!(rules.contains("ip daddr 10.240.0.1 tcp dport 18080 accept"));
    assert!(rules.contains("tcp sport 22 ct state established ct direction reply accept"));
    assert!(rules.contains("forward iifname \"okata12\" drop"));
    assert!(rules.contains("forward oifname \"okata12\" drop"));
    assert!(rules.contains("input iifname != \"lo\" ip daddr 10.240.0.1 tcp dport 18080 drop"));
    assert!(
        !rules.contains("ip6") && !rules.contains("udp"),
        "no IPv6/UDP allow rule exists"
    );
}

#[test]
fn untrusted_identity_cannot_inject_nft_expressions() {
    for name in [
        "veth; accept",
        "veth\nflush ruleset",
        "../../net",
        "0123456789abcdef",
    ] {
        let mut invalid = spec();
        invalid.host_veth = name.into();
        assert!(invalid.rules().is_err());
    }
    let mut invalid = spec();
    invalid.guest_mac = "ff:ff:ff:ff:ff:ff".into();
    assert!(invalid.rules().is_err());
    invalid = spec();
    invalid.ifindex = 0;
    assert!(invalid.rules().is_err());
    invalid = spec();
    invalid.proof_nonce = "bad\";flush".into();
    assert!(invalid.rules().is_err());
}
