# Local Kata runtime

`setup-local.sh` creates only the named `openshell-kata-rust` Lima VM on an Apple Silicon Mac with nested virtualization support. It does not change Docker contexts or existing containers. The VM has four CPUs, 8 GiB memory, a 30 GiB disk, and no host directory mounts. Kata guests use one CPU and 2 GiB memory each.

```sh
runtime/setup-local.sh
runtime/lifecycle.py create example-sandbox
runtime/lifecycle.py stop example-sandbox
runtime/lifecycle.py start example-sandbox
runtime/lifecycle.py delete example-sandbox
```

The helper requires Lima, Python 3, OpenSSH, and `gh` for downloading the pinned Kata release. `OPENSHELL_KATA_VM` overrides the dedicated VM name. Private runtime state defaults to `.local/runtime`; `OPENSHELL_KATA_STATE_DIR` overrides that directory. Use a short absolute path because OpenSSH control sockets have a platform path-length limit. Per-sandbox control socket filenames are hashes, so UUID sandbox IDs fit on macOS.

## Adapter contract

The executable accepts two arguments: `create|start|stop|delete` and a sandbox ID. Create/start print one JSON object on stdout containing `sandbox_id`, `host`, `port`, `username`, `private_key_path`, and `known_hosts_path`. Stop/delete print `{}`. A repeated delete with no metadata succeeds only when native container inspection confirms that exact container is absent; existing containers and transport failures are rejected. Start refreshes the guest IP after a restart and replaces any stale SSH tunnel while retaining the loopback port and pinned host identity. Diagnostics use stderr. A nonzero exit means the operation failed. The Rust adapter owns the OpenShell protocol and passes commands, SFTP streams, and approved loopback preview connections through this SSH endpoint.

Each guest has a persistent SSH daemon, its own host key, and a unique client public key. The client private key stays outside the Linux VM. The SSH host identity is pinned before the first connection. User data never uses `nerdctl exec`; containerd handles only lifecycle and trusted image preparation. This avoids the earlier concurrent exec/stream stall. The control socket is separate from guest SSH and only tunnels a loopback port through the dedicated Lima host.

The SSH user is `sandbox` (UID 1000), with `/sandbox` as its home and initial working directory. GNU coreutils supplies `realpath -e --`, which the OpenShell download probe requires. Its private Docker daemon listens only on `/var/run/docker.sock`. Root access through Docker is intentionally confined to the Kata guest. The container gets guest capabilities, not node block devices or a node Docker socket. SSH permits forwarding only to guest loopback destinations. Each sandbox has its own CNI bridge; a rule inserted ahead of CNI forwarding rules rejects traffic between sandbox subnets. New connections from these subnets to the Linux node are rejected.

Docker data is a 2 GiB tmpfs so overlay2 never uses virtiofs as its upper filesystem. Images and Docker volumes disappear on stop/start. Guest startup removes stale Docker PID files and sockets before launching the new daemon. The sandbox filesystem persists in the container snapshot, but this is not a durable production storage design.

## Runtime qualification

Kata 4.3.1 and the Docker source image are pinned by digest. The local profile explicitly uses the official Kata Go compatibility runtime. On this nested arm64 host, runtime-rs/QEMU failed network hotplug, and runtime-rs/Dragonball failed to boot the supplied guest kernel because of virtio-mmio/root-device errors. This is a local compatibility profile, not a decision to depend permanently on the deprecated Go runtime. A supported runtime-rs configuration must be qualified on each production node type before hosted rollout. The SSH transport does not depend on which Kata implementation supplies the guest. Trusted image assembly runs in an ordinary unprivileged build container inside the dedicated VM; tenant sandboxes always use Kata.

The Linux/cloud backend can implement the same lifecycle JSON contract without Lima; Windows and other cloud node types have not been tested by this local profile.

## Validation and cleanup

```sh
python3 -m unittest discover -s runtime -p 'test_*.py'
python3 runtime/test_transport.py .local/runtime/SANDBOX_ID/metadata.json
python3 runtime/test_workspace.py .local/runtime/SANDBOX_ID/metadata.json
python3 runtime/test_restart.py .local/runtime/SANDBOX_ID/metadata.json
```

The transport test keeps a command with open stdin alive while four concurrent SFTP sessions upload and download 16 MiB each, checks every SHA-256, then verifies another exec and the Docker daemon. The integration evidence is under `evidence/runtime-*`. OpenShell-level authorization, policy, Docker Compose, and preview tests are maintained by the parent integration suite.

After all integration work finishes, delete each sandbox through its lifecycle helper, then run `limactl stop openshell-kata-rust` and `limactl delete --force openshell-kata-rust`. Keep private state until guests and tunnels have been removed; remove it afterward. Release archives under `runtime/.cache` are disposable and excluded from Git.
