# Rust adapter port

The Rust executable implements the external compute and internal supervisor wire
contracts from unmodified NVIDIA OpenShell v0.1.6. `proto/SHA256SUMS` records the
exact vendored source files; no OpenShell source changes are required.

| Python prototype behavior | Rust implementation |
| --- | --- |
| Driver RPCs and runtime observations | `driver.rs` |
| Identifier, loopback and operator configuration validation | `config.rs`, `guest.rs` |
| Supervisor JWT, configuration admission and relay streams | `supervisor.rs` |
| Private SSH listener, exec, SFTP and main-process output | `ssh.rs` |
| Upload plan and cumulative consumption acknowledgments | `upload.rs` |
| Explicit prototype-only admission | `admission.rs` |

The runtime executable receives `create`, `start`, `stop`, or `delete` followed
by the sandbox ID. Create/start return JSON describing a loopback SSH route,
username, private client-key path and pinned known-hosts path. Workload commands
run through system OpenSSH with agent forwarding disabled and strict host-key
checking. The gateway JWT and gateway-facing SSH private key remain in the Rust
process; they are never passed to workload commands.

The guest SSH server replaces repeated `nerdctl exec -i` calls. The latter
stalled during the Python prototype's concurrent command/upload tests. File
transfer now uses bounded streaming buffers and reports progress only after
writing bytes to the guest transport. Extraction stderr drains concurrently.
SSH error paths explicitly return an exit status and close the channel, including
an invalid plan or an extractor which exits while the client keeps stdin open.

Deliberate corrections to the prototype include gateway configuration lookup by
sandbox **name**, fresh launch credentials on restart, an early `Bootstrapping`
condition during restart, idempotent control cleanup, retryable failed deletion,
and URI-based validation of the local-only prototype exception.
Successful deletion atomically removes the active record and records a tombstone
for compute watchers. Each watcher receives it once, and a reconnect replays it.
An unknown in-memory record is deleted only after the launcher confirms cleanup
or exact resource absence; a transport failure never counts as absence.

The default mode fails closed because full policy enforcement is not yet
qualified. `--prototype-policy-mode` is restricted to a TLS loopback gateway and
permits the local integration fixture; it does not implement filesystem,
process or selective-egress enforcement. Only the fixed `docker:29-dind` runtime
is supported. Caller environment, resource overrides, custom runtime selections,
network policies and provider credential installation are rejected.

The adapter currently keeps its registry in memory. Process restart requires
explicit guest cleanup/recreation. The canonical main command is noninteractive;
PTY emulation, `--no-login-shell`, main-process exit reconciliation and memory
suspension are not implemented. The supervisor contract is internal to
OpenShell, so version compatibility is pinned rather than assumed. Launch-token
refresh and control-session reconnection are not implemented; live experiments
must finish within the configured token lifetime or recreate the sandbox.

## Test mapping

`adapter_boundaries.rs` covers the original identifier, preview-route, upload
destination and explicit-runner trust boundaries. `adapter_admission.rs` covers
fail-closed policy admission and unsupported inputs. `adapter_upload.rs` tests a
16 MiB stream through small buffers, cumulative credit, and extractor failure.
`adapter_ssh.rs` uses the actual private SSH listener and a controlled guest
transport fixture to verify separate stdout/stderr, exit status, binary upload
acknowledgments, invalid-plan termination, early extractor failure, and
cancellation before the upload plan is complete. The real gateway/Kata workflow
is maintained by the integration scripts and recorded evidence.

Validation commands: `cargo fmt --check`, `cargo clippy --all-targets
--all-features -- -D warnings`, and `cargo test --all-targets`. Coverage of the
generated protobuf modules is excluded; an instrumented integration run is
required to exercise real gateway session and lifecycle branches.
