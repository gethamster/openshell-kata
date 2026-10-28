use super::*;
fn intent() -> HostedFenceIntent {
    HostedFenceIntent {
        version: 1,
        workspace: "tenant-a".into(),
        namespace_uid: "c60050d6-39a8-4cf2-85bf-0b79d8aa822b".into(),
        sandbox_id: "sandbox-a".into(),
        pod_uid: "d60050d6-39a8-4cf2-85bf-0b79d8aa822b".into(),
        launch_nonce: "e60050d6-39a8-4cf2-85bf-0b79d8aa822b".into(),
        expires_at_unix: 2000,
        broker_pod_uid: "f60050d6-39a8-4cf2-85bf-0b79d8aa822b".into(),
        broker_ip: "10.176.2.3".parse().expect("valid fence fixture"),
        broker_port: 3128,
        broker_config_sha256: "a".repeat(64),
        controller_cidrs: vec!["10.128.0.2/32".into()],
        guest_ip: "10.176.1.2".parse().expect("valid fence fixture"),
        guest_mac: "02:00:00:00:00:01".into(),
        gateway_ip: "169.254.1.1".parse().expect("valid fence fixture"),
        gateway_mac: "02:00:00:00:00:02".into(),
        interface: "eth0".into(),
        node_uid: "a60050d6-39a8-4cf2-85bf-0b79d8aa822b".into(),
        boot_id: "b60050d6-39a8-4cf2-85bf-0b79d8aa822b".into(),
    }
}
#[test]
fn intent_validates_and_canonical_digest_binds_everything() {
    let i = intent();
    i.validate(1000).expect("valid fence fixture");
    let digest = i.sha256().expect("valid fence fixture");
    let mut changed = i.clone();
    changed.broker_pod_uid = uuid::Uuid::new_v4().to_string();
    assert_ne!(digest, changed.sha256().expect("valid fence fixture"));
    let config = i
        .packet_config(1000, 5_000_000_000)
        .expect("valid fence fixture");
    assert_eq!(config.guest_ip, i.guest_ip.octets());
    assert_eq!(config.expires_at_boottime_ns, 1_004_000_000_000);
}
#[test]
fn intent_rejects_fence_bypasses() {
    let good = intent();
    for change in [
        |i: &mut HostedFenceIntent| i.version = 2,
        |i: &mut HostedFenceIntent| i.interface = "eth0;foo".into(),
        |i: &mut HostedFenceIntent| i.pod_uid = "../other".into(),
        |i: &mut HostedFenceIntent| i.broker_port = 22,
        |i: &mut HostedFenceIntent| i.guest_ip = "127.0.0.1".parse().expect("valid fence fixture"),
        |i: &mut HostedFenceIntent| i.broker_ip = i.guest_ip,
        |i: &mut HostedFenceIntent| i.guest_mac = "ff:ff:ff:ff:ff:ff".into(),
        |i: &mut HostedFenceIntent| i.controller_cidrs = vec!["0.0.0.0/0".into()],
        |i: &mut HostedFenceIntent| i.controller_cidrs = vec!["8.8.8.0/24".into()],
        |i: &mut HostedFenceIntent| i.controller_cidrs = vec!["fd00::/8".into()],
        |i: &mut HostedFenceIntent| i.controller_cidrs.clear(),
        |i: &mut HostedFenceIntent| i.broker_config_sha256 = "A".repeat(64),
    ] {
        let mut bad = good.clone();
        change(&mut bad);
        assert!(bad.validate(1000).is_err(), "bad intent {bad:?}");
    }
    assert!(good.validate(2000).is_err());
    let mut excessive = good.clone();
    excessive.expires_at_unix = 90000;
    assert!(excessive.validate(1000).is_err());
}
#[test]
fn proof_requires_nonzero_distinct_link_and_program_identity() {
    let i = intent();
    let proof = HostedFenceProof {
        version: 1,
        intent_sha256: i.sha256().expect("valid fence fixture"),
        binding: i,
        netns_device: 4,
        netns_inode: 5,
        ifindex: 2,
        ingress_link_id: 1,
        egress_link_id: 2,
        ingress_program_id: 3,
        egress_program_id: 4,
        object_sha256: "b".repeat(64),
        installed_at_unix: 1000,
    };
    proof.validate(1001).expect("valid fence fixture");
    let mut bad = proof.clone();
    bad.egress_link_id = bad.ingress_link_id;
    assert!(bad.validate(1001).is_err());
    let mut bad = proof.clone();
    bad.binding.guest_mac = "02:00:00:00:00:03".into();
    assert!(bad.validate(1001).is_err());
    let mut bad = proof;
    bad.installed_at_unix = 1002;
    assert!(bad.validate(1001).is_err());
}
#[test]
fn packet_mac_parser_rejects_multicast_and_ambiguous_spellings() {
    assert_eq!(
        parse_mac("02:00:00:00:00:01").expect("valid fence fixture"),
        [2, 0, 0, 0, 0, 1]
    );
    for value in [
        "0:0:0:0:0:1",
        "01:00:00:00:00:01",
        "00:00:00:00:00:00",
        "02:00:00:00:00:GG",
    ] {
        assert!(parse_mac(value).is_err());
    }
}

#[test]
fn boottime_deadline_expires_after_suspend_even_when_monotonic_does_not_advance() {
    let i = intent();
    // The node already suspended for 900 seconds before launch. /proc/uptime
    // and bpf_ktime_get_boot_ns agree at 1,000s; CLOCK_MONOTONIC is only 100s.
    let boot_before = 1_000_000_000_000;
    let mono_before = 100_000_000_000;
    let config = i.packet_config(1000, boot_before).expect("valid fixture");
    assert_eq!(config.expires_at_boottime_ns, boot_before + 999_000_000_000);
    let mut frame = [0u8; 54];
    frame[..6].copy_from_slice(&config.gateway_mac);
    frame[6..12].copy_from_slice(&config.guest_mac);
    frame[12..14].copy_from_slice(&[8, 0]);
    frame[14] = 0x45;
    frame[17] = 40;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&config.guest_ip);
    frame[30..34].copy_from_slice(&config.broker_ip);
    frame[34..36].copy_from_slice(&50000u16.to_be_bytes());
    frame[36..38].copy_from_slice(&3128u16.to_be_bytes());
    frame[46] = 0x50;
    frame[47] = 2;
    assert_eq!(
        packet::classify(&config, packet::Direction::Egress, &frame, 54, boot_before),
        packet::Decision::Next
    );
    // A later 1,100-second suspend passes the absolute launch expiry. The
    // suspend-aware clock revokes immediately on resume; monotonic time would
    // incorrectly preserve access, illustrating the old mismatch regression.
    let boot_after = boot_before + 1_100_000_000_000;
    assert_eq!(
        packet::classify(&config, packet::Direction::Egress, &frame, 54, boot_after),
        packet::Decision::Drop
    );
    assert!(mono_before < config.expires_at_boottime_ns);
}
