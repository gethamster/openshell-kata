# Pipeline updates

Inspect the running pipeline’s owners and input contracts before changing its
configuration. Preserve the repository’s protections and established publishing
mechanism rather than adding a parallel path to obtain a faster result.

## Deploy consumers before new inputs

A manifest in the checkout may be read by a dispatcher or controller running an
older image. Establish the current canonical contract and the deployed version.
Update and verify the real reader on that contract before publishing dependent
manifests. Do not infer runtime support from a merged source change.

Keep rollout ordering explicit when tooling and configuration live in different
repositories. Use the existing forward migration and versioning mechanisms.
Remove superseded readers and formats within the authorized scope; do not
retain rollback support or add dual protocols to accommodate old controllers.
If the required owner or deployed version cannot be established, identify that
specific missing evidence before changing the dependent input.

## Preserve useful build outputs

Track the source, build inputs, artifact digest or checksum, and qualification
that belong together. Reuse a completed artifact only when it still matches the
requested target and its relevant evidence remains valid.

A deployment can be cancelled while its build output remains usable. Preserve
that output and its evidence through the repository’s existing retention process;
do not rebuild merely because a later deployment was superseded. Reconcile an
uncertain publication or deployment before replaying its side effects.

When staging and production consume the same artifact format, promote the
verified artifact rather than recompiling for the next stage. When the repository
requires a different build, qualify its actual output and report that distinction.
Keep required signing, security checks, and immutable artifact identities intact.

## Coordinate shared resources

Assign one owner to a shared staging environment, publication lock, or other
mutated resource. Other work can proceed independently, but it must not restart
or replace the resource while another verification relies on it. Verify the
revision and configuration actually serving each test.

Parallelize work only when its inputs and writes are independent and there is
sufficient permitted capacity. Respect required review-before-publish ordering;
running a build alongside review does not authorize promotion before approval.

## Retain proof while improving time

Use the test scope and evidence rules in
[Verified Delivery](../../verified-delivery/references/verification.md).
An unrelated provider outage should remain scoped to its own operation, but a
mandatory relevant check still has to pass. Keep skipped, reused, newly passed,
and unavailable checks distinct.

For documentation not consumed by a runtime, use applicable content, reference,
and generated-output checks rather than an unrelated application build. For
configuration or executable tooling, verify the affected behavior and rollout
ordering and current user flow. Faster completion must still mean the requested
outcome works.
