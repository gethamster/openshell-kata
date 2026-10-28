use super::*;
fn config() -> PacketConfig {
    let mut controllers = [([0; 4], 0); MAX_CONTROLLERS];
    controllers[0] = ([10, 128, 0, 0], 20);
    PacketConfig {
        guest_ip: [10, 176, 1, 2],
        broker_ip: [10, 176, 2, 3],
        gateway_ip: [169, 254, 1, 1],
        guest_mac: [2, 0, 0, 0, 0, 1],
        gateway_mac: [2, 0, 0, 0, 0, 2],
        broker_port: 3128,
        controllers,
        controller_count: 1,
        expires_at_boottime_ns: 1000,
    }
}
fn tcp(direction: Direction, remote: [u8; 4], sport: u16, dport: u16, flags: u8) -> [u8; 54] {
    let c = config();
    let mut b = [0; 54];
    let (src, dst, smac, dmac) = match direction {
        Direction::Egress => (c.guest_ip, remote, c.guest_mac, c.gateway_mac),
        Direction::Ingress => (remote, c.guest_ip, c.gateway_mac, c.guest_mac),
    };
    b[..6].copy_from_slice(&dmac);
    b[6..12].copy_from_slice(&smac);
    b[12..14].copy_from_slice(&0x800u16.to_be_bytes());
    b[14] = 0x45;
    b[16..18].copy_from_slice(&40u16.to_be_bytes());
    b[23] = 6;
    b[26..30].copy_from_slice(&src);
    b[30..34].copy_from_slice(&dst);
    b[34..36].copy_from_slice(&sport.to_be_bytes());
    b[36..38].copy_from_slice(&dport.to_be_bytes());
    b[46] = 0x50;
    b[47] = flags;
    b
}
#[test]
fn codec_roundtrip() {
    assert_eq!(PacketConfig::decode(&config().encode()), config());
}
#[test]
fn broker_only_allows_exact_tcp_route() {
    let c = config();
    assert_eq!(
        classify(
            &c,
            Direction::Egress,
            &tcp(Direction::Egress, c.broker_ip, 50000, 3128, 2),
            54,
            1
        ),
        Decision::Next
    );
    assert_eq!(
        classify(
            &c,
            Direction::Ingress,
            &tcp(Direction::Ingress, c.broker_ip, 3128, 50000, 0x12),
            54,
            1
        ),
        Decision::Next
    );
    for (ip, port) in [
        ([169, 254, 169, 254], 80),
        ([10, 144, 0, 4], 10250),
        ([8, 8, 8, 8], 443),
        (c.broker_ip, 3129),
    ] {
        assert_eq!(
            classify(
                &c,
                Direction::Egress,
                &tcp(Direction::Egress, ip, 50000, port, 2),
                54,
                1
            ),
            Decision::Drop
        );
    }
}
#[test]
fn ssh_needs_separate_state_decision() {
    let c = config();
    let syn = tcp(Direction::Ingress, [10, 128, 0, 2], 50000, 22, 2);
    let Decision::SshSyn(key) = classify(&c, Direction::Ingress, &syn, 54, 1) else {
        panic!("expected controller SYN");
    };
    assert_eq!(
        classify(
            &c,
            Direction::Egress,
            &tcp(Direction::Egress, [10, 128, 0, 2], 22, 50000, 0x12),
            54,
            1
        ),
        Decision::SshReply(key)
    );
    assert_eq!(
        classify(
            &c,
            Direction::Ingress,
            &tcp(Direction::Ingress, [10, 128, 0, 2], 50000, 22, 0x10),
            54,
            1
        ),
        Decision::SshIngress(key)
    );
    for (dir, ip, sport, dport, flags) in [
        (Direction::Ingress, [10, 129, 0, 2], 50000, 22, 2),
        (Direction::Egress, [10, 128, 0, 2], 22, 50000, 2),
        (Direction::Egress, [10, 128, 0, 2], 50000, 22, 2),
    ] {
        assert_eq!(
            classify(&c, dir, &tcp(dir, ip, sport, dport, flags), 54, 1),
            Decision::Drop
        );
    }
}
#[test]
fn malformed_encapsulation_and_source_spoofing_denied() {
    let c = config();
    let b = tcp(Direction::Egress, c.broker_ip, 50000, 3128, 2);
    for (index, value) in [
        (6, 3),
        (0, 3),
        (12, 0x86),
        (13, 0xdd),
        (14, 0x46),
        (20, 0x20),
        (20, 0x80),
        (21, 1),
        (23, 17),
        (26, 127),
        (46, 0x40),
        (34, 0),
        (35, 0),
    ] {
        let mut bad = b;
        bad[index] = value;
        if index == 34 || index == 35 {
            bad[34] = 0;
            bad[35] = 0;
        }
        assert_eq!(
            classify(&c, Direction::Egress, &bad, 54, 1),
            Decision::Drop,
            "index {index}"
        );
    }
    assert_eq!(
        classify(&c, Direction::Egress, &b[..13], 54, 1),
        Decision::Drop
    );
    assert_eq!(
        classify(&c, Direction::Egress, &b[..40], 54, 1),
        Decision::Drop
    );
    assert_eq!(classify(&c, Direction::Egress, &b, 53, 1), Decision::Drop);
    assert_eq!(
        classify(&c, Direction::Egress, &b, 54, 1000),
        Decision::Drop
    );
    let mut bad = c;
    bad.controller_count = 17;
    assert_eq!(classify(&bad, Direction::Egress, &b, 54, 1), Decision::Drop);
}
#[test]
fn arp_only_exact_gateway_and_guest() {
    let c = config();
    for direction in [Direction::Ingress, Direction::Egress] {
        let mut b = [0; 42];
        let (smac, source, target) = match direction {
            Direction::Ingress => (c.gateway_mac, c.gateway_ip, c.guest_ip),
            Direction::Egress => (c.guest_mac, c.guest_ip, c.gateway_ip),
        };
        b[..6].copy_from_slice(&[255; 6]);
        b[6..12].copy_from_slice(&smac);
        b[12..14].copy_from_slice(&0x806u16.to_be_bytes());
        b[14..20].copy_from_slice(&[0, 1, 8, 0, 6, 4]);
        b[21] = 1;
        b[22..28].copy_from_slice(&smac);
        b[28..32].copy_from_slice(&source);
        b[38..42].copy_from_slice(&target);
        assert_eq!(classify(&c, direction, &b, 42, 1), Decision::Next);
        for (i, v) in [(14, 1), (21, 3), (22, 3), (28, 127), (38, 127), (0, 3)] {
            let mut bad = b;
            bad[i] = v;
            assert_eq!(
                classify(&c, direction, &bad, 42, 1),
                Decision::Drop,
                "index {i}"
            );
        }
        assert_eq!(classify(&c, direction, &b[..41], 42, 1), Decision::Drop);
    }
}
