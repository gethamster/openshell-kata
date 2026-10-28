# Kata host fence eBPF object

The Rust TCX classifiers run on the outer Kata Pod interface before the platform CNI. Allowed packets return `TCX_NEXT` so later CNI policy still applies. All other packets terminate with `TCX_DROP`.

Build on Linux from the repository root with the standalone Rust builder:

```
rustc --edition=2024 scripts/build_hosted_fence.rs -o /tmp/build-hosted-fence
/tmp/build-hosted-fence --output-dir .local/fence-artifacts
```

The builder installs `nightly-2026-10-27` with `rust-src`, verifies the official `bpf-linker` 0.12.0 archive against a pinned SHA-256 for Linux x86_64 or aarch64, and builds with the committed Cargo lockfile. It requires `curl`, `tar`, `zstd`, `sha256sum`, `rustup`, and network access to the pinned tool sources. It writes `openshell-kata-fence.o`, its checksum, and `build-inputs.txt`. Regular adapter builds continue to use stable Rust. Set `OPENSHELL_KATA_FENCE_BUILD_DIR` to reuse a bounded build cache.

The operator pins the resulting `openshell-kata-fence` ELF by SHA-256 in the trusted runtime-guard configuration. This object requires Linux TCX support (6.6 or newer), verified on the deployed kernel and CNI. No fallback to legacy TC or nftables is accepted. Hardware and CNI qualification remain deployment gates.

The shared parser in `src/network/hosted_fence_packet.rs` is ordinary safe Rust and runs in host unit tests. Unsafe operations are limited to the parameterless suspend-aware boot-clock helper and an immediate copy from a kernel map value; no map reference is retained. Maps and links remain outside the Kata guest.


The root-owned node runtime configuration lives at `/etc/openshell-kata/runtime-guard.json`:

```json
{
  "version": 1,
  "node_uid": "<Kubernetes node UUID>",
  "shim_path": "/opt/kata/bin/containerd-shim-kata-v2",
  "shim_sha256": "<qualified official shim SHA-256>",
  "object_path": "/opt/openshell-kata/openshell-kata-fence.o",
  "object_sha256": "<built object SHA-256>",
  "nsenter_path": "/usr/bin/nsenter",
  "ip_path": "/usr/bin/ip",
  "guard_path": "/opt/openshell-kata/kata-runtime-guard"
}
```

Paths must be canonical, root-owned and non-symlink, with no group or other write permission on any ancestor. The operator creates root-owned private `/run/openshell-kata/intents`, `/run/openshell-kata/fences` and `/sys/fs/bpf/openshell-kata` directories. The bpffs mount must also prohibit group or other writes. The trusted node intent controller publishes one immutable intent per Pod UID after independently verifying the source namespace, launch, broker and controller identities. The wrapper waits at most 30 seconds for that intent before refusing to start the official shim. The CNI must have populated an exact gateway neighbor before the barrier; missing or mismatched neighbors fail closed. Controller selectors are exact private IPv4 `/32` addresses, up to 16.

`kata-runtime-guard verify --pod-uid UUID --nonce UUID` checks the immutable intent, node boot, pinned namespace generation, interface MAC/ifindex, map selectors, unexpired suspend-aware boot-clock deadline, exact pinned TCX link/program IDs, and first position in both TCX chains. After Kata moves the IP into its guest, verification retains the immutable Pod IP binding without requiring that address on outer `eth0`.

Never unpin a fence merely because its deadline passed, its Pod disappeared from the API, or its namespace path disappeared. An expired guest might remain alive. The kernel fence must continue to drop packets until the exact CRI sandbox and its outer interface/network namespace have actually been destroyed. Reclamation requires independent generation-specific destruction evidence; this wrapper does not weaken the boundary for cleanup. A single shared, root-owned `/run/openshell-kata/generations` budget atomically reserves at most 512 distinct Pod UIDs before any per-generation intent, lock, proof, or pin creation. Existing generations can verify or finish, while new generations fail closed at capacity until verified reclamation occurs. This also bounds failed-start artifacts; expiry never frees capacity.

Packet fixtures under `tests/fixtures` are standalone Rust tools for an isolated privileged Linux test. `packets.rs` writes raw Ethernet cases; `run.rs` checks them with `bpftool prog run` against already attached task-owned ingress and egress program IDs. `tcp.rs` supplies socket fixtures. The deployment qualification must additionally exercise the actual Kata/CNI packet path; unit tests and BPF test-run verdicts alone do not establish that path.
