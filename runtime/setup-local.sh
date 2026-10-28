#!/usr/bin/env bash
# Provision only a task-owned Linux VM; user workloads always use the Rust Kata runtime.
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(dirname -- "$here")
vm=${OPENSHELL_KATA_VM:-openshell-kata-enforcement}
[[ "$vm" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || exit 2
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || { echo 'This local profile requires Apple Silicon with nested virtualization support.' >&2; exit 2; }
command -v limactl >/dev/null
command -v gh >/dev/null
cache="$here/.cache"
mkdir -p "$cache"
asset=kata-static-4.3.1-arm64.tar.zst
if [[ ! -f "$cache/$asset" ]]; then gh release download 4.3.1 --repo kata-containers/kata-containers --pattern "$asset" --dir "$cache"; fi
(cd "$cache" && printf '%s  %s\n' 2c5bf7cde334ad5307d482f45cceda496f91c9b6b96f5278c47f4f4eac1bbae6 "$asset" | shasum -a 256 -c -)
if limactl list --format '{{.Name}}' | grep -Fxq "$vm"; then limactl start --yes "$vm"; else limactl start --name "$vm" --yes --timeout 8m "$here/lima.yaml"; fi
limactl cp "$cache/$asset" "$vm:/tmp/$asset"
for script in bootstrap.sh node-prepare.sh setup-devmapper.sh; do
  limactl cp "$here/$script" "$vm:/tmp/openshell-$script"
  limactl shell "$vm" bash "/tmp/openshell-$script"
done
(cd "$root" && tar --exclude='./target' --exclude='./.git' --exclude='./.local' --exclude='./evidence' --exclude='./runtime/.cache' -czf "$cache/node-source.tar.gz" .)
limactl cp "$cache/node-source.tar.gz" "$vm:/tmp/openshell-kata-source.tar.gz"
limactl shell "$vm" sh -c 'mkdir -p "$HOME/openshell-kata-build"; tar -xzf /tmp/openshell-kata-source.tar.gz -C "$HOME/openshell-kata-build"; cd "$HOME/openshell-kata-build"; CARGO_INCREMENTAL=0 "$HOME/.cargo/bin/cargo" build --release --bin kata-runtime --bin kata-network -j 2; sudo install -D -m 0755 target/release/kata-runtime /opt/openshell-kata/kata-runtime; sudo install -D -m 0755 target/release/kata-network /opt/openshell-kata/kata-network'
limactl shell "$vm" sh -c 'cd "$HOME/openshell-kata-build"; "$HOME/.cargo/bin/rustup" target add aarch64-unknown-linux-musl; CC_aarch64_unknown_linux_musl=musl-gcc CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc CARGO_INCREMENTAL=0 "$HOME/.cargo/bin/cargo" build --release --locked --target aarch64-unknown-linux-musl --bin kata-workspace -j 2; sudo install -D -m 0755 target/aarch64-unknown-linux-musl/release/kata-workspace /opt/openshell-kata/kata-workspace'
OPENSHELL_KATA_VM="$vm" "$here/prepare-enforcement-image.sh"
