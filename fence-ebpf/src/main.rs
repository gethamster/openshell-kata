//! TCX classifiers enforcing the immutable outer Kata network boundary.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_ktime_get_boot_ns,
    macros::{classifier, map},
    maps::{Array, LruHashMap},
    programs::TcContext,
};
#[path = "../../src/network/hosted_fence_packet.rs"]
mod packet;
use packet::{CONFIG_LEN, DROP, Decision, Direction, FlowKey, NEXT, PacketConfig};

// Only userspace may write the single configuration. It is initialized before
// either classifier is attached and never exposed inside the guest namespace.
#[map]
static CONFIG: Array<[u8; CONFIG_LEN]> = Array::with_max_entries(1, 128);
#[map]
static SSH: LruHashMap<FlowKey, u64> = LruHashMap::with_max_entries(1024, 0);
const SSH_IDLE_NS: u64 = 120_000_000_000;

#[classifier]
pub fn kata_ingress(ctx: TcContext) -> i32 {
    classify(ctx, Direction::Ingress)
}
#[classifier]
pub fn kata_egress(ctx: TcContext) -> i32 {
    classify(ctx, Direction::Egress)
}

#[inline(always)]
fn classify(ctx: TcContext, direction: Direction) -> i32 {
    let Some(raw) = CONFIG.get(0) else {
        return DROP;
    };
    let config = PacketConfig::decode(raw);
    let mut bytes = [0u8; 54];
    let Ok(ethernet) = ctx.load::<[u8; 14]>(0) else {
        return DROP;
    };
    bytes[..14].copy_from_slice(&ethernet);
    let size = if ethernet[12..14] == [8, 6] { 42 } else { 54 };
    if size == 42 {
        let Ok(arp) = ctx.load::<[u8; 28]>(14) else {
            return DROP;
        };
        bytes[14..42].copy_from_slice(&arp);
    } else {
        let Ok(headers) = ctx.load::<[u8; 40]>(14) else {
            return DROP;
        };
        bytes[14..].copy_from_slice(&headers);
    }
    // SAFETY: the TCX context supports the parameterless suspend-aware boot-clock helper.
    let now = unsafe { bpf_ktime_get_boot_ns() };
    match packet::classify(&config, direction, &bytes[..size], ctx.len() as usize, now) {
        Decision::Drop => DROP,
        Decision::Next => NEXT,
        Decision::SshSyn(key) => {
            if SSH.insert(&key, &now, 0).is_ok() {
                NEXT
            } else {
                DROP
            }
        }
        Decision::SshIngress(key) => {
            if !active(&key, now) {
                return DROP;
            }
            if bytes[47] & 0x04 != 0 {
                let _ = SSH.remove(&key);
            } else if SSH.insert(&key, &now, 0).is_err() {
                return DROP;
            }
            NEXT
        }
        Decision::SshReply(key) => {
            if active(&key, now) {
                NEXT
            } else {
                DROP
            }
        }
    }
}
#[inline(always)]
fn active(key: &FlowKey, now: u64) -> bool {
    // SAFETY: the value is copied immediately from the kernel-managed, aligned
    // map slot; no reference survives another map operation or packet callback.
    let Some(last) = (unsafe { SSH.get(key) }).copied() else {
        return false;
    };
    last <= now && now - last < SSH_IDLE_NS
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
