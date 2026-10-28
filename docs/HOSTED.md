# Kubernetes runtime profile

The same Rust adapter supports local Kata guests and an explicitly selected
Kubernetes profile. The operator installs the Kata runtime and admission/network
controls separately. No cloud provider API is required by this launcher.

Select the hosted profile with `--runtime-profile kubernetes`, an immutable
`--guest-image repository@sha256:...`, a private `--guest-network-cidr`, an
absolute `--recovery-dir`, and `--lifecycle /usr/local/bin/kata-kubernetes`.
The adapter passes the exact guest range to the launcher as
`OPENSHELL_KATA_GUEST_NETWORK_CIDR`; absent or public ranges fail closed.
The operator may select `OPENSHELL_KATA_KUBE_CONTEXT`,
`OPENSHELL_KATA_STATE_DIR`, and reviewed `OPENSHELL_KATA_STORAGE_CLASS`
(`standard-rwo` or `kata-regional-rwo`). Tenants cannot choose these settings.

The launcher derives `sandbox-<workspace>` from gateway-owned metadata and
checks existing namespace labels. It never creates namespaces. Each sandbox
has a Kata Pod, a private 19 GiB RWO PVC, an SSH Secret and selecting network
policy. The profile is two vCPU, 4 GiB memory and 1 GiB ephemeral storage.
Ephemeral storage uses Kubernetes accounting and eviction, not an instantaneous
block quota. The local block-backed profile separately supports one vCPU and
2 GiB memory/disk. Operator-owned templates must match the selected profile.

## Guarantees and limits

The Kubernetes profile accepts version-1 policy with all fine-grained sections
absent. It enforces deny-all guest egress and permits SSH only from the trusted
control role. Before launch and during revalidation, it rejects additive
selecting policies that broaden that boundary and verifies the actual Pod UID,
nonce, runtime class, node qualification, image, storage and resource settings.
It never falls back to an ordinary container runtime.

Guest root and Docker do not imply selective native path, executable or process
identity enforcement. Unsupported policy is rejected. The local host broker's
public-destination allowlists are not yet a Kubernetes capability. Hosted
internet-dependent builds require that additional implementation and testing;
offline Docker tests do not prove internet access.

`OPENSHELL_KATA_LIFETIME_SECS` defaults to 3600 and accepts 60–86400 seconds.
The original expiry persists across stop/start. The Pod receives a remaining
`activeDeadlineSeconds`; the launcher binds any tightening patch to UID,
resource version and creation nonce, and verifies the observed start-time
relative deadline. Missing legacy deadlines and expired leases fail launch and
verification; explicit stop/delete remain available. This is kubelet-enforced
termination with Kubernetes reconciliation timing. It is distinct from the local
profile's independent node watchdog and does not promise exact deadline timing
when the node agent is unavailable.

Stop removes the Pod while retaining storage and private metadata. Start makes
new keys and a new Pod identity without extending the lease. Delete removes the
Pod, PVC, Secret, network policy and retained key files. Nonce-bound abort never
removes a preexisting generation and preserves a preexisting PVC on failed start.
Cleanup verifies ownership and absence; it never deletes shared namespaces.

## Control and recovery

Lifecycle serialization is per sandbox, so a slow create cannot hold another
sandbox's cancellation behind a global lock. Access is withdrawn before bounded
cleanup. Gateway-session identity and compute-runtime identity are tracked
separately. Supervisor credentials remain in memory and refresh before expiry;
public observations and retained recovery records never contain them.

The private recovery registry retains bounded credential-free intent. Adapter
restart validates all records before mutation, stops retained guests and exposes
Stopped with Ready false. A fresh authenticated Start must repeat admission and
runtime verification. Corrupt records or unconfirmed cleanup prevent serving;
this is not a transparent session-resume mechanism.

## Integration and qualification

The `kata-workspace` Rust helper is baked into both guest recipes at
`/usr/local/bin/kata-workspace`. `protocol` prints
`openshell-kata-workspace/1`; System checks that compatibility identifier before
use. File operations retain the bounded, digest-checked streaming contract.
The helper is an untrusted guest convenience, not the external security boundary.

Trusted startup can use `kata-operator socket-ready --socket
/run/openshell-kata/private/driver.sock`. Keep the adapter and gateway configured
for that same private child; do not weaken the socket parent's permissions to
accommodate a group-writable Kubernetes mount root.

After quiescing the existing owner and retaining its encrypted backup, restore
the known retained-state permissions in place with:

```sh
kata-operator prepare \
  --state-dir /var/openshell/kata \
  --registry-dir /var/openshell/kata/registry \
  --driver-dir /run/openshell-kata/private \
  --system-ca /etc/ssl/certs/ca-certificates.crt \
  --platform-ca /etc/internal-ca/ca.crt \
  --output /var/run/trust/private/ca-bundle.pem
```

This validates the complete bounded known inventory before changing state
permissions, including retained lock ownership and quiescence checks. It
preserves contents, names and inodes, restores directories to 0700/files to
0600, and invents no metadata or lease deadlines. Unknown entries, links,
foreign ownership and unsafe private-file permissions fail closed. Only known
public-key files and empty locks may carry legacy other-read permission.
Root-owned mount directories remain unchanged; driver/trust use private owned
children. The gateway's `SSL_CERT_FILE` must select the resulting private bundle.

The SRE deployment owner retains cluster installation, trusted identity/access,
namespace admission, image promotion and live tenant qualification. The original
hosted sibling `e2d897e` and its image receipts are separate baseline evidence.
The reconciled Rust candidate must repeat the complete System/CLI flow, two-tenant
denials, token renewal, lease expiry, restart/recovery and observation period on
its exact artifacts before promotion. See `DELIVERY_PLAN.md` for current gates.
