# OpenShell Kata adapter

A Rust external compute driver and control adapter for running Docker-capable
Kata sandboxes with an unmodified OpenShell gateway.

The adapter owns the gateway protocol, sandbox lifecycle, SSH relay, file
transfer, and preview forwarding. A small Python launcher provisions the local
Lima/Kata environment; it is not part of the adapter's protocol implementation.

Development is gated on local upload, execution, Docker/Compose, preview, and
lifecycle tests before any hosted rollout. See [the delivery plan](docs/DELIVERY_PLAN.md),
[the policy plan](docs/POLICY_PLAN.md), and [porting notes](docs/PORTING.md).

## Local development

The local launcher requires an Apple Silicon Mac with nested virtualization,
Lima 2.2 or newer, OpenSSH, Python 3, and GitHub CLI for pinned release downloads.
The Rust build uses Rust 1.98. The tested hardware is an Apple M5 Max. This
launcher has not been qualified on Windows or other cloud node types.

```sh
python3 scripts/fetch_openshell.py
runtime/setup-local.sh
cargo build --locked
python3 scripts/setup_gateway.py
python3 scripts/services.py start --prototype-policy-mode
python3 scripts/e2e.py
```

`scripts/cli.py` runs the official CLI with this checkout's configuration.
Credentials and generated state stay under the ignored `.local/` directory;
the user's existing OpenShell and Docker configuration is not changed.

The local test gateway listens on `127.0.0.1:29670` with TLS and client
authentication. The adapter connects to each guest over a private, pinned SSH
route. Uploaded files and command input do not use containerd exec streams.

The explicit `--prototype-policy-mode` flag is only for local qualification.
It does not make the fixture's filesystem, process, or egress policy enforced.
The default mode rejects launches whose required guarantees cannot be proved.

## Validation

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo doc --locked --no-deps
cargo audit
python3 -m unittest discover -s runtime -p 'test_*.py'
python3 scripts/verify_upstream.py
```

The end-to-end suite uses the official CLI to create a sandbox, upload/download
a 16 MiB binary fixture, compare hashes, run concurrent commands and transfers,
build an image, run Docker Compose, fetch a gateway preview, restart the
sandbox, verify retained files, and delete it. Evidence is written to `evidence/`.

### Verified locally

The final run passed against unmodified OpenShell 0.1.6 and a Kata 4.3.1 guest:

| Check | Result |
| --- | --- |
| Four 16 MiB uploads and five downloads, including after restart | Matching SHA-256 hashes |
| Concurrent commands during repeated uploads after preview | Passed |
| Docker image build and two Compose services | Passed |
| Gateway preview | HTTP 200 |
| Automatic stop/start and retained workspace | Passed |
| Runtime deletion and gateway deletion event | Passed |
| Strict policy rejection before allocation | Passed |

There are 33 passing Rust tests, 27 passing runtime tests, and three passing
local harness tests. Rust line coverage is 85.7% from unit and live integration
tests, excluding generated protocol code. Formatting, Clippy, documentation,
dependency audit, and vendored protocol checksum checks pass.

See [the qualification record](evidence/qualification.json) and
[coverage summary](evidence/coverage-summary.txt). The local runtime uses the
documented Go compatibility profile; a supported hosted runtime and actual
filesystem/process/network policy enforcement remain separate qualification
gates. No hosted deployment was performed.

## Cleanup

Delete active sandboxes through `scripts/cli.py`, then stop the local services:

```sh
python3 scripts/services.py stop
limactl stop openshell-kata-rust
limactl delete --force openshell-kata-rust
```

Do not remove `.local/runtime` while its guests or SSH tunnels are running.
The local VM is dedicated to this checkout. Its Docker data is temporary;
production workspace storage and backup are not implemented by this launcher.

OpenShell's external compute-driver interface is versioned. Its supervisor
control protocol is internal, so this adapter pins OpenShell 0.1.6 and must be
qualified again when that dependency changes.

The policy implementation and supported guarantees are under development.
Configuration acknowledgement alone must never be presented as proof of
filesystem, process, or network enforcement.

The first policy slice is implemented in `src/policy.rs`: typed validation and
explicit rejection of unsupported filesystem, process, executable, network,
and middleware requirements. Strict creation checks it before provisioning and
then refuses execution until the required runtime fences are qualified. Passing
this validator never grants permission to run a sandbox.
