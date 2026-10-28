//! Raw Ethernet fixtures for kernel BPF_PROG_TEST_RUN, separate from socket tests.
use std::{fs, path::Path};
fn tcp(
    source: [u8; 4],
    destination: [u8; 4],
    sport: u16,
    dport: u16,
    flags: u8,
    ingress: bool,
) -> [u8; 54] {
    let mut p = [0u8; 54];
    let (src, dst) = if ingress {
        ([2, 0, 0, 0, 0, 2], [2, 0, 0, 0, 0, 1])
    } else {
        ([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
    };
    p[..6].copy_from_slice(&dst);
    p[6..12].copy_from_slice(&src);
    p[12..14].copy_from_slice(&[8, 0]);
    p[14] = 0x45;
    p[16..18].copy_from_slice(&40u16.to_be_bytes());
    p[23] = 6;
    p[26..30].copy_from_slice(&source);
    p[30..34].copy_from_slice(&destination);
    p[34..36].copy_from_slice(&sport.to_be_bytes());
    p[36..38].copy_from_slice(&dport.to_be_bytes());
    p[46] = 0x50;
    p[47] = flags;
    p
}
fn main() -> std::io::Result<()> {
    let root = std::env::args().nth(1).expect("packet output folder");
    fs::create_dir_all(&root)?;
    let root = Path::new(&root);
    let good = tcp([10, 50, 0, 2], [10, 50, 0, 3], 50000, 3128, 2, false);
    let mut fixtures = vec![
        ("broker-allow", good, u32::MAX),
        (
            "metadata",
            tcp([10, 50, 0, 2], [169, 254, 169, 254], 50000, 80, 2, false),
            2,
        ),
        (
            "direct-public",
            tcp([10, 50, 0, 2], [8, 8, 8, 8], 50000, 443, 2, false),
            2,
        ),
        (
            "own-node",
            tcp([10, 50, 0, 2], [10, 50, 0, 1], 50000, 8080, 2, false),
            2,
        ),
        (
            "untracked-ssh-reply",
            tcp([10, 50, 0, 2], [10, 50, 0, 4], 22, 8080, 0x10, false),
            2,
        ),
    ];
    for (name, index, value) in [
        ("spoof-source-ip", 26, 127),
        ("spoof-source-mac", 6, 4),
        ("ipv6", 12, 0x86),
        ("udp", 23, 17),
        ("fragment", 20, 0x20),
        ("reserved-fragment", 20, 0x80),
        ("ipv4-options", 14, 0x46),
    ] {
        let mut bad = good;
        bad[index] = value;
        fixtures.push((name, bad, 2));
    }
    for (name, packet, expected) in fixtures {
        fs::write(root.join(format!("{name}.bin")), packet)?;
        println!("{name} {expected}");
    }
    fs::write(
        root.join("ssh-syn.bin"),
        tcp([10, 50, 0, 4], [10, 50, 0, 2], 60572, 22, 2, true),
    )?;
    fs::write(
        root.join("ssh-admitted-reply.bin"),
        tcp([10, 50, 0, 2], [10, 50, 0, 4], 22, 60572, 0x12, false),
    )?;
    fs::write(
        root.join("ssh-unadmitted-port.bin"),
        tcp([10, 50, 0, 2], [10, 50, 0, 4], 22, 60573, 0x10, false),
    )?;
    Ok(())
}
