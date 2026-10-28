# OpenShell Kata delivery and System integration

## Current end-to-end objective

Use one maintained Rust adapter with unmodified OpenShell for our System agent
as well as stock CLI users. The observable product path is tenant authorization
through the access service, gateway admission, a Kata VM, System command/file
operations, Docker build/Compose, an authorized preview, cancellation, recovery,
and deletion. Local CLI success alone does not establish this path.

The public repository is `gethamster/openshell-kata`. Initial public main
was `1c6aa11`. The shared candidate fixes its Linux directory-handle durability
and early extractor-exit failures and incorporates the hosted branch's lifecycle,
credential refresh and recovery behavior while preserving local external-policy
controls. The guest workspace and operator startup helpers are Rust.

The real System backend now passes all eight local checks through the production
access router, stock OpenShell 0.1.6 and an actual Kata VM. The access authority is
a scoped local fixture, so this does not qualify Google sign-in. The stock CLI
also passes after the SSH compatibility changes. See
`evidence/integration-qualification.json` for exact source and validation scope.

## Integration gates

1. **Portable foundation:** reproduce and fix actual Linux failures; run the
   full Rust suite, formatting, lint, docs and audit on the combined source.
   Preserve capability-relative storage and fail-closed admission.
2. **One Rust implementation:** reconcile hosted/local adapter core; port the
   Kubernetes lifecycle helper to Rust. Preserve generation identity, bounded
   per-sandbox operations, credential refresh, credential-free recovery and
   explicit backend capability differences. No ordinary-container fallback.
3. **System guest contract:** replace embedded Python command/file helpers with
   a Rust workspace helper and exercise its actual System consumer. Pin the
   same helper/image contract in both guest recipes. Keep process/file helpers
   separate from the trusted external enforcement boundary.
4. **Local dogfood:** run the real System sandbox backend against the actual
   gateway and Kata guest: seed/read/write/remove, stdout/stderr/stdin, process
   cancellation, Docker build/Compose, preview, stop/start, persistence, delete.
   Admit the operator-owned template/resource/image contract explicitly; do not
   accept caller overrides merely to satisfy a fixture.
5. **Hosted candidate:** coordinate with the active tenant-platform delivery
   owner before shared cluster or template mutation. Build immutable artifacts
   from the reconciled source and test the same System flow from a team namespace
   before changing routes. An earlier sibling-branch image is separate evidence.
6. **Tenant and recovery checks:** two concurrent tenants, cross-tenant denial,
   authorization and policy revocation, token renewal beyond fifteen minutes,
   gateway restart, storage recovery, and thirty-minute observation on the exact
   candidate. Record missing cases rather than inheriting a green component test.
7. **Ship and consume:** reviewed PR and passing CI; pin the qualified adapter,
   System and SRE artifacts; verify real agent work through the consuming product.
   Preserve other owners' active work, runtime data, routes and credentials.

Current hosted capability is deny-all guest egress. Local exact-destination TCP
brokering is a distinct capability until hosted enforces and qualifies it too.
Do not claim internet-dependent hosted builds or all-platform equivalence from
an offline Docker test. Selective native guest filesystem/process identity
restrictions remain unsupported with guest root.

Before hosted dependency downloads or internet-dependent builds, deliver the
broker as a separate capability: a trusted broker outside the Kata Pod, external
per-generation network fences, an explicit narrowing native policy and operator
ceiling, and System authorization for that capability. Preserve `deny-all`
semantics. Qualify actual registry/dependency traffic, denied/private destinations,
cross-tenant routes, revocation, broker failure and recovery on the exact deployed
artifact; API objects or offline builds do not establish these guarantees.

The active migration chat owns the shared hosted deployment. Its worktree and
running qualification Pods must not be overwritten or removed by this delivery.
Use separate task evidence and build outputs, coordinate shared build slots,
and bound temporary adapter verification caches to 12 GiB while Linux/Mac builds
coexist. Preserve the Linux helper artifact and reports, then retire its normal
target before instrumented coverage. Retain at most 3 GiB after delivery; shared
System caches have their own owner and must not be treated as disposable.

## Previous milestones

The first gate is a Rust adapter that works with unmodified OpenShell 0.1.6 and
fixes the previous Kata upload failure. Hosted infrastructure work remains
blocked until the local gate passes.

## Local gate

1. Preserve the original prototype as evidence; implement the adapter in Rust.
2. Replace repeated containerd exec streams with authenticated guest transport.
   Keep gateway authentication and OpenShell SSH identity outside the guest.
3. Exercise the official OpenShell CLI: create, execute, upload/download, build,
   Docker Compose, gateway preview, stop/start, delete, and repeated transfers.
4. Verify file hashes, concurrent command progress, per-sandbox authorization,
   cleanup, and absence of host mounts or host Docker sockets.
5. Run formatting, lint, tests, and coverage; review the complete candidate.

## Policy gate

After local upload works, implement the first slice of `POLICY_PLAN.md`:
fail-closed capability/admission checks with accurate VM-scope semantics.
Unknown or unsupported guarantees must be rejected before a sandbox is Ready.
Then establish real external network and filesystem fences with negative tests.
No fixture policy or configuration acknowledgement is evidence of enforcement.

## Hosted gate

Only a locally verified adapter and a reviewed policy contract may proceed to
hosted deployment planning. No cloud infrastructure changes are part of this
local implementation step. Linux, macOS, Windows, and cloud launchers share a
control contract; platform support must be demonstrated individually.

## Delivery and recovery

The original local milestone had no supplied remote or established release target.
Keep source, tests, nonsecret evidence, and reproducible commands together.
Keep generated credentials, binaries, VM disks, and caches out of Git. Use one
shared build directory and remove task-owned runtime resources after validation.
During coverage qualification, the combined normal and instrumented build cache
is bounded at 8 GiB while the runtime and instrumented adapter are tested together.
Remove superseded incremental outputs after validation and
retain the evidence separately from build caches.

## Delivered local milestone

The Rust adapter, upload repair, official-CLI end-to-end suite, and first
fail-closed policy-admission slice pass. `evidence/qualification.json` records
the source fingerprint and results. The temporary VM and service processes are
removed after qualification. The retained normal build cache is bounded at
3 GiB; coverage build outputs and downloaded Kata archives are disposable.

## Delivered enforcement milestone

The Rust Kata `docker-vm` profile passed a fresh official-CLI run including four
16 MiB uploads, five matching downloads, concurrent execution, Docker build,
Compose, preview, stop/start, fresh-file persistence, and deletion. Guest-root
network attacks, storage caps/zeroing, host cgroup bounds, and an independent
watchdog were exercised separately. The suite has 139 passing tests and 84.85%
implementation line coverage. See `evidence/enforcement-qualification.json` for
the source fingerprint, evidence, and exact limitations.

The adapter, lifecycle, network broker, and development tools are Rust. Python
helpers and the former Go Kata fallback were removed. The final security review
found no critical/high issues in the reviewed lifecycle and boundary delta.

The task-owned services and VM are removed after qualification. Reports are
retained; the isolated instrumented cache is disposable. An unrelated checkout
was found writing to the default `target/`, so final verification used the
task-owned `.local/policy-build` directory and did not clean the shared cache.

Hosted rollout remains gated on production and additional-platform
qualification described in `POLICY_PLAN.md`. The original publication blocker
was resolved by creating the public repository and pushing main; the integration
gates above now define the remaining delivery work.
