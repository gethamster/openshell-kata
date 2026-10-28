# Rust adapter port

The Rust executable implements the external compute and internal supervisor wire
contracts from unmodified NVIDIA OpenShell v0.1.6. `proto/SHA256SUMS` records the
exact vendored source files; no OpenShell source changes are required.

| Python prototype behavior | Rust implementation |
| --- | --- |
| Driver RPCs and runtime observations | `driver.rs` |
| Identifier, loopback and operator configuration validation | `config.rs`, `guest.rs` |
| Supervisor JWT, configuration admission and relay streams | `supervisor.rs` |
| Private SSH listener, exec and main-process output | `ssh.rs` |
| Upload plan and cumulative consumption acknowledgments | `upload.rs` |
| Native policy admission and VM profile compilation | `admission.rs`, `profile.rs` |

The runtime executable receives `create`, `start`, `stop`, or `delete` followed
by the sandbox ID. The adapter supplies the compiled policy file and a fresh
proof nonce for enforced launches. Create/start return JSON describing a
loopback SSH route, username, private client-key path, pinned known-hosts path,
and host enforcement evidence bound to that launch. Workload commands
run through system OpenSSH with agent forwarding disabled and strict host-key
checking. The gateway JWT and gateway-facing SSH private key remain in the Rust
process; they are never passed to workload commands.

The guest SSH server replaces repeated `nerdctl exec -i` calls. The latter
stalled during the Python prototype's concurrent command/upload tests. Enforced
uploads consume bounded input into a private host spool, validate archive paths,
entry types, and quotas, and seal the archive before replaying it to the guest.
Intermediate acknowledgments report consumed input; the final acknowledgment
requires successful guest extraction. Host-side staging never unpacks the
archive. Extraction stderr drains concurrently, and SSH errors return an exit
status and close the channel. Enforced mode rejects raw SFTP, which would bypass
the validated transfer path.

Deliberate corrections to the prototype include gateway configuration lookup by
sandbox **name**, fresh launch credentials on restart, an early `Bootstrapping`
condition during restart, idempotent control cleanup, retryable failed deletion,
and URI-based validation of the local-only prototype exception.
Successful deletion atomically removes the active record and records a tombstone
for compute watchers. Each watcher receives it once, and a reconnect replays it.
An unknown in-memory record is deleted only after the launcher confirms cleanup
or exact resource absence; a transport failure never counts as absence.

Without an explicit `--vm-policy`, the default mode rejects launch. The VM
profile fixes resource limits, denies host mounts, bounds transfers, and limits
native network policy to an exact public TCP endpoint subset of the operator
ceiling. Empty native network policy remains deny-all. Guest filesystem,
Landlock, process-identity and executable-specific policies are rejected because
guest-root Docker can defeat those controls. Readiness requires launch-bound
host enforcement evidence; passing admission alone does not establish isolation.
The older `--prototype-policy-mode` remains restricted to a TLS loopback gateway
and makes no enforcement guarantee. Only the fixed `docker:29-dind` runtime is
supported; caller environment, resource overrides, custom runtime selections,
provider credentials and unsupported inspection requests remain rejected.

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
is maintained by the Rust qualification command and recorded evidence.

Validation commands: `cargo fmt --check`, `cargo clippy --all-targets
--all-features -- -D warnings`, and `cargo test --all-targets`. Coverage of the
generated protobuf modules is excluded; an instrumented integration run is
required to exercise real gateway session and lifecycle branches.

## Local tooling port

The local control and qualification commands now run in the `kata-dev` Rust
binary. They invoke the pinned official OpenShell binaries and system tools;
no Python interpreter is needed to install, start, stop, or exercise the local
adapter. Existing `.local` credentials remain in place.

| Previous Python entry point | Rust command / implementation |
| --- | --- |
| `scripts/cli.py` | `kata-dev cli -- ...`; replaces itself with the official CLI and preserves the terminal |
| `scripts/local.py` | `devtools/local.rs`; isolated environment, bounded command lifetime, evidence records |
| `scripts/setup_gateway.py` | `kata-dev setup-gateway`; preserves existing PKI and registers only isolated local state |
| `scripts/services.py start` | `kata-dev services start --vm-policy /absolute/profile.json`; uses the Rust `kata-runtime` binary |
| `scripts/services.py stop` | `kata-dev services stop`; checks executable, process group, and recorded start time before signaling |
| `scripts/fetch_openshell.py` | `kata-dev fetch-openshell`; verifies pinned archive SHA-256 before extracting only the expected regular binary |
| `scripts/verify_upstream.py` | `kata-dev verify-upstream`; verifies the vendored source manifest |
| `scripts/e2e.py` | `kata-dev e2e --policy /absolute/native-policy.yaml`; official CLI transfer, Docker build, Compose, preview, restart, and delete checks |

The three original `test_tools.py` behaviors map to Rust tests named
`credential_environment_is_not_inherited`, `failure_is_recorded_before_returning`,
and `timeout_closes_descendant_output_pipes`. Additional tests cover archive
member types and duplication, checksum path traversal, existing PKI preservation,
private process records, stale sockets, and reused PIDs.

The new service command requires an explicit VM policy and does not enable the
prototype policy bypass. The end-to-end command similarly requires an explicit
native OpenShell policy. Its large fixture remains 16 MiB, but deterministic
SHA-256 blocks replace Python's SHAKE-256 fixture generator; transfer equality
is checked against the generated bytes rather than a baked-in hash. The Docker
fixture now executes a `RUN` instruction as well as `COPY` and Compose startup.
Official tool download still requires `curl`; archive decoding and verified
member extraction run in Rust. These are development dependencies, separate
from the Rust adapter and lifecycle executable.

Local tooling verification: `CARGO_INCREMENTAL=0 cargo test --bin kata-dev`
passed 12 tests. The actual end-to-end environment remains a separate required
qualification and is not implied by those unit and component tests.

By default each invocation that records evidence uses a fresh
`evidence/local-runs/<timestamp>-<pid>` directory. Pass global
`--evidence-dir /absolute/path` to select a shared qualification directory. This
preserves earlier baseline evidence rather than overwriting its JSON and logs.

The Docker Hub qualification fixture is `scripts/e2e-native-policy.yaml`.
It lists exact public destinations with `tls: skip` and the all-binary selector
needed for rootful Docker. The trusted VM profile must list the same endpoints;
new registry redirect hosts remain denied until explicitly reviewed. The
separate `scripts/protocol-fixture.yaml` is deny-all and is suitable for tests
that do not download images.

Run `kata-dev` from the checkout root, or pass global `--root /absolute/checkout`.
The tool resolves that directory at runtime, so distributed binaries do not depend
on a build machine's source path.
