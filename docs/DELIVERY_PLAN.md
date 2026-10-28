# Local adapter and policy delivery

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

This new local repository has no supplied remote or established release target.
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
qualification described in `POLICY_PLAN.md`. There is no Git remote or release
target configured for this repository, so publication is blocked on that input.
