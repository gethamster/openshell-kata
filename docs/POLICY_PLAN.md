# Policy enforcement for Docker-capable Kata sandboxes

## Status and execution gate

This document is an implementation plan, not a claim that the adapter enforces
OpenShell policy. The local upload, execution, Docker/Compose, preview, and
lifecycle gate in [DELIVERY_PLAN.md](DELIVERY_PLAN.md) comes first. No hosted
deployment is authorized by a passing parser or an acknowledged configuration.

The current explicit prototype mode is for local qualification. It must remain
disabled by default and must not report native filesystem, process, or network
policy as enforced. Hardened admission remains closed until the required runtime
controls and negative tests pass.

The first policy implementation now validates and rejects unsupported requests
in `src/policy.rs`, with request-admission integration and negative tests. It
does not make the prototype a hardened runtime by accepting configuration.
The local upload regression passed before this implementation started; hosted
deployment and the runtime enforcement milestones below remain gated.

## Security contract

Treat the entire Docker-capable guest as hostile, including its kernel, Docker
daemon, containers, build steps, agent, and guest management helper. Access to
the guest Docker socket gives the caller effective guest administration even
when the initial agent runs as a non-root user. An immutable image is useful at
boot; it does not keep a running guest trustworthy after guest-root compromise.

Keep the gateway identity, supervisor credentials, SSH host identity, policy
authority, and final network authorization outside that guest. Bind every
control and relay operation to the tenant, workspace, sandbox, immutable runtime
identity, and current generation. Host root and cluster administrators remain
trusted; the adapter does not protect tenants from a compromised cluster
control plane or a hypervisor escape.

| Property | Native OpenShell contract | Docker-capable adapter contract |
| --- | --- | --- |
| Gateway authentication and tenant/workspace authorization | Owned by the unmodified gateway | Retain gateway checks and independently check the sandbox/generation on every adapter operation. |
| Guest filesystem paths | The native backend enforces admitted path restrictions | Guest-root Docker can bypass restrictions inside its guest. Do not claim selective guest-path enforcement. |
| Process UID, capabilities, and syscalls | The native backend qualifies a non-root, capability-free workload | Record the actual entrypoint identity; do not claim that it restricts Docker-created workloads or a compromised guest kernel. |
| Network executable identity | Native mediation can authorize measured workload executables | Authorize the entire sandbox at the external boundary. Reject narrower guest-executable requirements. |
| Resource limits | Depend on the selected runtime | Enforce CPU, memory, lifetime, and storage at the VM/host boundary. Do not advertise a guest process-count guarantee based on host process counts. |
| Provider credentials | Native supervisors keep provider material outside workloads | Keep real credentials outside the guest; implement and test any supported injection path before accepting that provider configuration. |
| Preview ingress | Gateway routes authorized services | Expose only explicit gateway previews; never create direct application ingress to workload Pods. |

## Policy representation is an unresolved admission constraint

The unmodified OpenShell 0.1.6 gateway rejects an unrestricted guest
`read_write: ["/"]` policy as unsafe. Its accepted selective paths, such as
`/sandbox` and `/tmp`, must not be reinterpreted as permission to write the whole
guest. The prototype previously accepted those paths without enforcing them;
that is not a hardened compatibility result.

The adapter must reject a native filesystem policy that it cannot honor. A
useful VM-scoped policy needs an explicit, validated representation that the
gateway and adapter agree on. Establish that representation before admitting a
hardened full-Docker sandbox. Do not manufacture a policy principal, silently
discard native fields, or claim that a VM boundary implements guest-path rules.
This can block hardened full-Docker admission while implementation proceeds.

For network rules, the upstream policy supports executable globs. An explicitly
all-executables rule may be a candidate for sandbox-wide authorization, but it
must be verified against the pinned gateway and effective policy. A rule for a
specific guest executable must be rejected. Do not submit invented binary
identity evidence to make the stock supervisor accept it.

## Admission and capability checks

Implement `validate_policy(&SandboxPolicy) -> Result<ValidatedPolicy, PolicyError>`
as a pure validation step over the vendored OpenShell type. `ValidatedPolicy`
means that the adapter understands the requested intent; it does not mean the
runtime has installed or proved enforcement.

The implemented first slice recognizes a version-1 policy with no requested
guest filesystem, process, Landlock, middleware, or network-access features.
Even that result remains blocked by strict admission because the required
runtime fences are unqualified. The validator rejects valid selective guest
paths as unsupported and rejects ambiguous paths before reporting capability
limitations. It never substitutes a broader policy or returns an enforcement
flag. Its typed errors omit supplied paths, identities, and secret values.

Call validation before resource creation and again for the effective
`GetSandboxConfig` snapshot. Require gateway admission, pinned protocol support,
and an exact sandbox/generation match. Reject missing policy, unsupported
versions, selective guest filesystem guarantees, unimplemented process
selectors, guest-binary rules, middleware, credential mechanisms, and endpoint
features. Diagnostics should identify the unsupported field without echoing
secrets. Keep the prototype bypass explicit and separate from hardened mode.

Before a hardened sandbox becomes Ready, verify independently that the runtime
has installed its outer fences and that its effective policy revision matches
the admitted snapshot. A missing fence, expired identity, failed policy update,
or unsupported feature must prevent launch or stop external access. Never treat
the gateway's configuration-admitted bit as runtime enforcement evidence.

## Filesystem and credentials outside the guest

Use sandbox-private disks and workspace storage. A guest may corrupt its own
disk; it must not gain access to another sandbox's disk or host directories.
Audit the actual Kata storage path, including any virtiofs daemon and its host
permissions. Prefer bounded block-backed guest storage where practical. Do not
claim that a shared host directory is safe merely because it is mounted through
a VM. Host filesystem paths and arbitrary host sockets are not caller inputs.

Provide explicit import/export operations for host files. Pin the permitted
directory with a directory descriptor, resolve paths beneath it without
following symlinks or magic links, and defend against concurrent rename/symlink
races. Reject traversal, device files, FIFOs, unexpected hard links, excessive
expansion, and unauthorized permission bits. Apply byte/count/time quotas and
stage imports before atomic publication. Preserve executable files only within
the allowed mode policy. On platforms without equivalent safe path-resolution
primitives, fail the operation instead of falling back to a string-prefix check.

Keep gateway tokens, SSH private keys, provider material, and cloud credentials
out of guest mounts, environment, logs, images, and upload archives. Any
guest-facing authentication capability must be scoped to that sandbox and
generation and must not authorize a different sandbox. Provider support starts
disabled. Add it only after an external broker can authorize the destination and
operation before credential injection and can revoke that access reliably.

## Network enforcement outside the guest

Install an independently enforced deny-all egress and ingress fence before any
untrusted guest instruction. The only external path is a sandbox-bound relay to
the trusted control/egress adapter. Guest iptables, proxy environment variables,
and guest process identity are not security boundaries.

The external adapter captures and validates the destination, resolves names,
checks policy, and opens approved upstream connections. Check resolved addresses
at connection time and on every redirect/re-resolution; deny metadata,
loopback, link-local, multicast, and unspecified destinations. Private services
require explicit operator-authorized destinations. Prevent DNS rebinding and
cross-sandbox relay reuse. DNS itself is an egress channel and must not offer
unrestricted external recursion from the guest.

Start with no provider credentials, no middleware, no wildcard destinations,
and no external UDP except supported DNS mediation. Add an exact-host/port TCP
allowlist only when its semantics are fully implemented. TLS inspection, HTTP
method/path restrictions, credential rewriting, and generic UDP are separate
features; reject requests for them until they have real enforcement.

Apply policy revisions atomically. Revoke or terminate existing connections
when a new policy removes their authorization. Losing policy/control service
must never open a direct route. Preview ports remain reachable only through the
authenticated gateway, with per-sandbox authorization and explicit port grants.

## Process and resource enforcement

Apply CPU, memory, storage, and lifetime limits at the host VM boundary. Validate
requested resources against operator ceilings before allocating them. Host
process limits constrain the VMM and relay, not the number of guest processes.
Test fork bombs and memory/CPU/disk exhaustion at the guest boundary.

Implement stop/delete as authoritative destruction or termination of the VM
and its external relay. Guest cooperation can improve shutdown but cannot be
required for containment. Define command cancellation separately from stopping
the whole VM; a Docker-created detached process may survive a command's exit.
Do not expose arbitrary host devices, KVM handles, or runtime sockets to callers.

## Implementation sequence

1. **Pass the local upload gate.** Check repeated and concurrent binary transfers,
   hashes, executable permissions, failure cleanup, and command progress with the
   official unmodified CLI. Preserve reproducible evidence.
2. **Implement fail-closed policy validation.** The first slice and its request
   admission hook are implemented. Complete effective-snapshot integration as
   runtime capabilities are added. Keep hardened Ready blocked while VM-scope
   representation or runtime controls are unavailable.
3. **Prove isolation of secrets and host storage.** Remove guest-visible control
   secrets and arbitrary host mounts; test cross-sandbox and path attacks.
4. **Install and prove the external deny-all fence.** Test it from the agent,
   rootful Docker daemon, build step, and Compose service, including after guest
   firewall changes and control-service failure.
5. **Add bounded external TCP/DNS authorization.** Implement exact destinations,
   sandbox binding, policy revisions, revocation, and explicit previews. Validate
   every accepted effective-policy field before enabling hardened admission.
6. **Add optional features independently.** Credential injection, L7 controls,
   middleware, resource extensions, and platform launchers each need positive and
   adversarial tests. Unimplemented features remain rejected.

The smallest first implementation after upload passes is step 2. Its security
effect is rejecting misleading requests before execution. The first added
runtime network guarantee is deny-all in step 4, not a configuration flag.

## Required adversarial tests

- Reject accepted-by-gateway guest-path policies that the adapter cannot enforce,
  unsupported policy versions, narrow executable rules, and unimplemented
  provider/middleware settings before creating a VM.
- Try raw IPv4/IPv6, alternate DNS, metadata access, DNS rebinding, HTTP redirects,
  proxy-variable removal, guest firewall replacement, host networking in an
  inner container, and guest-root network changes. Verify external denial.
- Exercise approved and denied destinations from agent code, `docker pull`, a
  BuildKit build step, and a detached Compose service. Record external evidence.
- Attempt another sandbox's socket, relay, generation, preview, data disk, and
  imported files. Test stale credentials after stop/restart and deletion.
- Exercise upload/export traversal, symlink swaps, hard links, oversized archives,
  special files, partial transfer, concurrent transfer, and sandbox teardown.
- Rotate/revoke policy while a connection is active, disconnect the supervisor,
  restart the adapter, and replace the workload Pod. No case may gain access.
- Exhaust guest CPU, memory, disk, processes, and connections while checking that
  other sandboxes and trusted control services remain responsive.

## Upstream evidence and portability

Pin OpenShell 0.1.6 and qualify its private supervisor protocol on upgrades.
The external driver contract expressly permits policy enforcement outside the
stock supervisor. Native backend audit checks are not a universal guarantee for
external backends:

- [External driver policy contract](https://github.com/NVIDIA/OpenShell/blob/v0.1.6/proto/compute_driver.proto#L191)
- [Native-only audit validation](https://github.com/NVIDIA/OpenShell/blob/v0.1.6/crates/openshell-sandbox-backend/src/runtime.rs#L739)
- [Executable identity semantics](https://github.com/NVIDIA/OpenShell/blob/v0.1.6/crates/openshell-isolation-interface/src/contract.rs#L418)
- [Kubernetes driver configuration limits](https://github.com/NVIDIA/OpenShell/blob/v0.1.6/crates/openshell-driver-kubernetes/src/driver.rs#L508)

Share the policy/control contract and guest image profile across deployments;
qualify the launcher and external fences separately on each platform. Kata needs
bare metal or nested virtualization. A Linux VM on macOS or Windows does not
automatically expose nested virtualization. Local native OpenShell defaults stay
unchanged; this adapter must advertise only the launchers it has tested.
