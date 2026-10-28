# Rust Kata runtime

`setup-local.sh` provisions the dedicated `openshell-kata-enforcement` Lima VM
on Apple Silicon macOS with nested virtualization. It requires Lima, OpenSSH,
GitHub CLI and Rust 1.98. No Python helper or Go Kata fallback is used.
Docker, containerd, nerdctl and Lima remain upstream dependencies.

The node has four CPUs, 8 GiB RAM, a 30 GiB disk, no host directory mounts and
no forwarded SSH agent. Tenant workloads always use the official Kata 4.3.1
Rust shim with Dragonball and `virtio-blk-mmio`. Trusted image assembly alone
uses runc. The source Docker image and Kata release archive are pinned by hash.

## Enforcement

Each guest has one vCPU, a 2048 MiB memory ceiling, a private 2048 MiB devmapper
block root and a persistent expiration deadline. Host cgroups constrain the
Rust VMM process and its threads. A separate systemd watchdog pins the cgroup
kill handle before readiness; it survives adapter exit and enforces expiration.
Restart does not renew the deadline.

Shared filesystems are disabled. The minimal OCI specification contains no
host bind mounts or host device entries. The guest agent image is read-only at
the block-device level. Thin-pool block zeroing is mandatory; an unsafe existing
pool is rejected. See `evidence/runtime-rust-summary.md` for the resource tests.

A generation-owned network namespace and veth are created before boot. Host nft
rules bind to their identity and permit only the guest's dedicated TCP broker
and replies to host-initiated SSH. The broker runs without root or capabilities,
uses a private control socket, and validates public destination addresses.
Direct guest DNS, UDP, IPv6, metadata, sibling traffic and forwarded inbound
traffic are denied. Restart boots behind deny-all egress until the adapter
applies the current gateway policy.

The guest owns a Docker daemon listening only on its own Unix socket. Docker
root and privileged nested containers remain inside the VM boundary. Proxy
settings are installed for noninteractive SSH commands, Docker image pulls,
build arguments and application containers; removing those settings cannot
remove the host packet fence.

## Lifecycle contract

Build the Rust binaries from the repository root. The adapter invokes
`kata-runtime ACTION ID` with trusted operator arguments:

- `create`, `start`, `verify`, and `update` require `--policy-file /absolute/path`
  and a fresh `--proof-nonce`. They emit the pinned loopback SSH route plus
  matching host-observed enforcement evidence.
- `stop` and `delete` operate on retained private state and verify cleanup.
- `abort` takes the failed launch nonce and can remove only resources owned by
  that launch. A different generation remains intact.

`OPENSHELL_KATA_STATE_DIR` or `--state-dir` selects an absolute private state
root. `--vm` selects the dedicated Lima node. Keep state until guests, watchdogs,
brokers and tunnels are removed. The private SSH client key and gateway
credentials never enter the guest. Guest SSH keys are generated and installed
before its first boot; untrusted guest filesystems are never mounted for that
operation after execution begins.

The operator profile is documented in `docs/ENFORCEMENT_CONTRACT.md`. Native
OpenShell guest filesystem/process restrictions remain unsupported with guest
root and are rejected. The current launcher has not been qualified on Windows,
native Linux hosts or cloud node types; those backends must preserve this same
contract and pass the adversarial suite before deployment.

## Validation and cleanup

`cargo test --locked` covers lifecycle identity, state privacy, command bounds,
resource/deadline validation, archive transfers and broker controls. The official
CLI suite is `kata-dev e2e`; the node-side adversarial network harness is
`test-network-enforcement.sh`. Run it only on this dedicated test node with an
explicit fixture and control socket.

Delete sandboxes through the official CLI, then stop local services and delete
the dedicated Lima VM as described in the repository README. Release archives,
node build outputs and VM disks are disposable after validation; preserve the
nonsecret qualification evidence in the repository.

Restart clears only the pinned Kata profile's stale tap/filter state inside its
verified namespace. Failed-start shims are matched by full ID, namespace,
executable and creation ownership, then signaled through Linux pidfds. Socket
cleanup follows [Kata 4.3.1's socket derivation](https://github.com/kata-containers/kata-containers/blob/4.3.1/src/runtime-rs/crates/shim/src/shim.rs#L64)
and refuses a live endpoint or an unexpected file type. Guest `/run` is tmpfs,
so Docker's runtime handles do not survive a reboot. Normal stop attempts a
bounded guest filesystem flush; the independent expiry watchdog always retains
its hard deadline.
