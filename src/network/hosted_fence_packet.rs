//! Packet policy shared by host tests and the TCX eBPF program.

/// Fixed map representation, avoiding userspace/eBPF ABI padding.
pub const CONFIG_LEN: usize = 192;
/// Maximum separately admitted controller network prefixes.
pub const MAX_CONTROLLERS: usize = 16;
/// A packet must continue through the platform CNI after passing this fence.
pub const NEXT: i32 = -1;
/// A denied packet terminates processing before later CNI programs.
pub const DROP: i32 = 2;

/// Validated immutable packet selectors, encoded into one read-only BPF map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketConfig {
    pub guest_ip: [u8; 4],
    pub broker_ip: [u8; 4],
    pub gateway_ip: [u8; 4],
    pub guest_mac: [u8; 6],
    pub gateway_mac: [u8; 6],
    pub broker_port: u16,
    pub controllers: [([u8; 4], u8); MAX_CONTROLLERS],
    pub controller_count: u8,
    /// Absolute CLOCK_BOOTTIME expiry; no userspace heartbeat keeps it alive.
    pub expires_at_boottime_ns: u64,
}
impl PacketConfig {
    #[cfg(not(target_arch = "bpf"))]
    pub fn encode(&self) -> [u8; CONFIG_LEN] {
        let mut bytes = [0; CONFIG_LEN];
        bytes[..4].copy_from_slice(&self.guest_ip);
        bytes[4..8].copy_from_slice(&self.broker_ip);
        bytes[8..12].copy_from_slice(&self.gateway_ip);
        bytes[12..18].copy_from_slice(&self.guest_mac);
        bytes[18..24].copy_from_slice(&self.gateway_mac);
        bytes[24..26].copy_from_slice(&self.broker_port.to_be_bytes());
        bytes[26] = self.controller_count;
        let mut index = 0;
        while index < MAX_CONTROLLERS {
            let offset = 32 + index * 8;
            bytes[offset..offset + 4].copy_from_slice(&self.controllers[index].0);
            bytes[offset + 4] = self.controllers[index].1;
            index += 1;
        }
        bytes[184..192].copy_from_slice(&self.expires_at_boottime_ns.to_be_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8; CONFIG_LEN]) -> Self {
        let mut controllers = [([0; 4], 0); MAX_CONTROLLERS];
        let mut index = 0;
        while index < MAX_CONTROLLERS {
            let offset = 32 + index * 8;
            controllers[index] = (four(bytes, offset), bytes[offset + 4]);
            index += 1;
        }
        Self {
            guest_ip: four(bytes, 0),
            broker_ip: four(bytes, 4),
            gateway_ip: four(bytes, 8),
            guest_mac: six(bytes, 12),
            gateway_mac: six(bytes, 18),
            broker_port: u16::from_be_bytes([bytes[24], bytes[25]]),
            controllers,
            controller_count: bytes[26],
            expires_at_boottime_ns: u64::from_be_bytes([
                bytes[184], bytes[185], bytes[186], bytes[187], bytes[188], bytes[189], bytes[190],
                bytes[191],
            ]),
        }
    }
    fn controller(&self, ip: [u8; 4]) -> bool {
        let mut index = 0;
        while index < MAX_CONTROLLERS {
            if index < usize::from(self.controller_count) {
                let (network, prefix) = self.controllers[index];
                if prefix > 0 && prefix <= 32 {
                    let mask = u32::MAX << (32 - prefix);
                    if u32::from_be_bytes(ip) & mask == u32::from_be_bytes(network) & mask {
                        return true;
                    }
                }
            }
            index += 1;
        }
        false
    }
}
#[inline(always)]
fn four(bytes: &[u8], offset: usize) -> [u8; 4] {
    [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]
}
#[inline(always)]
fn six(bytes: &[u8], offset: usize) -> [u8; 6] {
    [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
    ]
}
/// Exact controller/guest TCP four-tuple; no packet padding enters the BPF key.
pub type FlowKey = [u8; 12];
/// Network directions are relative to the outer Kata Pod interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Ingress,
    Egress,
}
/// Stateful SSH decisions require a separately admitted ingress SYN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Drop,
    Next,
    SshSyn(FlowKey),
    SshIngress(FlowKey),
    SshReply(FlowKey),
}

/// Classify a bounded Ethernet prefix, rejecting all unsupported protocols.
#[inline(always)]
pub fn classify(
    config: &PacketConfig,
    direction: Direction,
    bytes: &[u8],
    wire_len: usize,
    now_ns: u64,
) -> Decision {
    let mut decision = [0u8; 16];
    classify_frame(
        config,
        direction,
        &Frame {
            bytes,
            wire_len,
            now_ns,
        },
        &mut decision,
    );
    let key = [
        decision[1],
        decision[2],
        decision[3],
        decision[4],
        decision[5],
        decision[6],
        decision[7],
        decision[8],
        decision[9],
        decision[10],
        decision[11],
        decision[12],
    ];
    match decision[0] {
        1 => Decision::Next,
        2 => Decision::SshSyn(key),
        3 => Decision::SshIngress(key),
        4 => Decision::SshReply(key),
        _ => Decision::Drop,
    }
}
struct Frame<'a> {
    bytes: &'a [u8],
    wire_len: usize,
    now_ns: u64,
}
// Keep the BPF call ABI within five register arguments using an explicit byte
// output. A slice plus separate time/length and an aggregate return exceeded it.
#[inline(never)]
fn classify_frame(
    config: &PacketConfig,
    direction: Direction,
    frame: &Frame<'_>,
    output: &mut [u8; 16],
) {
    // BPF subprograms may return only R0. Small Rust aggregates otherwise use
    // multiple return registers, which the kernel verifier correctly rejects.
    *output = [0; 16];
    let decision = classify_frame_inline(config, direction, frame);
    let (tag, key) = match decision {
        Decision::Drop => (0, [0; 12]),
        Decision::Next => (1, [0; 12]),
        Decision::SshSyn(key) => (2, key),
        Decision::SshIngress(key) => (3, key),
        Decision::SshReply(key) => (4, key),
    };
    output[0] = tag;
    output[1..13].copy_from_slice(&key);
}
#[inline(always)]
fn classify_frame_inline(
    config: &PacketConfig,
    direction: Direction,
    frame: &Frame<'_>,
) -> Decision {
    let bytes = frame.bytes;
    let wire_len = frame.wire_len;
    let now_ns = frame.now_ns;
    if now_ns >= config.expires_at_boottime_ns
        || config.controller_count as usize > MAX_CONTROLLERS
        || bytes.len() < 14
    {
        return Decision::Drop;
    }
    let (source_mac, destination_mac) = match direction {
        Direction::Ingress => (config.gateway_mac, config.guest_mac),
        Direction::Egress => (config.guest_mac, config.gateway_mac),
    };
    if six(bytes, 6) != source_mac {
        return Decision::Drop;
    }
    let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
    if ethertype == 0x0806 {
        return arp(config, direction, bytes);
    }
    if ethertype != 0x0800 || six(bytes, 0) != destination_mac || bytes.len() < 54 {
        return Decision::Drop;
    }
    // Options, fragments, UDP, IPv6 and transition encapsulation are never admitted.
    let length = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
    if bytes[14] != 0x45
        || bytes[23] != 6
        || bytes[20] & 0xbf != 0
        || bytes[21] != 0
        || length < 40
        || length + 14 > wire_len
        || bytes[46] >> 4 < 5
        || usize::from(bytes[46] >> 4) * 4 + 20 > length
    {
        return Decision::Drop;
    }
    let source = four(bytes, 26);
    let destination = four(bytes, 30);
    let source_port = u16::from_be_bytes([bytes[34], bytes[35]]);
    let destination_port = u16::from_be_bytes([bytes[36], bytes[37]]);
    if source_port == 0 || destination_port == 0 {
        return Decision::Drop;
    }
    let (remote, remote_port) = match direction {
        Direction::Egress if source == config.guest_ip => {
            if destination == config.broker_ip && destination_port == config.broker_port {
                return Decision::Next;
            }
            if source_port != 22 || !config.controller(destination) || bytes[47] & 0x10 == 0 {
                return Decision::Drop;
            }
            (destination, destination_port)
        }
        Direction::Ingress if destination == config.guest_ip => {
            if source == config.broker_ip && source_port == config.broker_port {
                return Decision::Next;
            }
            if destination_port != 22 || !config.controller(source) {
                return Decision::Drop;
            }
            (source, source_port)
        }
        _ => return Decision::Drop,
    };
    let mut flow = [0; 12];
    flow[..4].copy_from_slice(&remote);
    flow[4..8].copy_from_slice(&config.guest_ip);
    flow[8..10].copy_from_slice(&remote_port.to_be_bytes());
    flow[10..12].copy_from_slice(&22u16.to_be_bytes());
    match direction {
        Direction::Egress => Decision::SshReply(flow),
        Direction::Ingress if bytes[47] & 0x17 == 0x02 => Decision::SshSyn(flow),
        Direction::Ingress => Decision::SshIngress(flow),
    }
}
#[inline(always)]
fn arp(config: &PacketConfig, direction: Direction, bytes: &[u8]) -> Decision {
    if bytes.len() < 42
        || bytes[14..20] != [0, 1, 8, 0, 6, 4]
        || !matches!([bytes[20], bytes[21]], [0, 1] | [0, 2])
    {
        return Decision::Drop;
    }
    let (source_ip, target_ip, source_mac) = match direction {
        Direction::Ingress => (config.gateway_ip, config.guest_ip, config.gateway_mac),
        Direction::Egress => (config.guest_ip, config.gateway_ip, config.guest_mac),
    };
    if four(bytes, 28) != source_ip || four(bytes, 38) != target_ip || six(bytes, 22) != source_mac
    {
        return Decision::Drop;
    }
    // ARP may use Ethernet broadcast; its protocol addresses remain exact.
    if six(bytes, 0) != [255; 6]
        && six(bytes, 0)
            != match direction {
                Direction::Ingress => config.guest_mac,
                Direction::Egress => config.gateway_mac,
            }
    {
        return Decision::Drop;
    }
    Decision::Next
}

#[cfg(test)]
#[path = "hosted_fence_packet_tests.rs"]
mod tests;
