#!/usr/bin/env bash
# This provisions only the named disposable Lima VM; it never touches Docker contexts.
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
vm=${OPENSHELL_KATA_VM:-openshell-kata-rust}
[[ "$vm" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || exit 2
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || { echo 'This local profile requires Apple Silicon macOS with nested virtualization support.' >&2; exit 2; }
command -v limactl >/dev/null
command -v gh >/dev/null
cache="$here/.cache"
mkdir -p "$cache"
for asset in kata-static-4.3.1-arm64.tar.zst kata-go-static-4.3.1-arm64.tar.zst; do
  if [[ ! -f "$cache/$asset" ]]; then gh release download 4.3.1 --repo kata-containers/kata-containers --pattern "$asset" --dir "$cache"; fi
done
(cd "$cache" && printf '%s  %s\n' 2c5bf7cde334ad5307d482f45cceda496f91c9b6b96f5278c47f4f4eac1bbae6 kata-static-4.3.1-arm64.tar.zst 2ff9b77869a902405c5d5b65fb38a5e93a18ae29e5e8891181e3a097f110741a kata-go-static-4.3.1-arm64.tar.zst | shasum -a 256 -c -)
if limactl list --format '{{.Name}}' | grep -Fxq "$vm"; then
  limactl start --yes "$vm"
else
  limactl start --name "$vm" --yes --timeout 8m "$here/lima.yaml"
fi
for asset in kata-static-4.3.1-arm64.tar.zst kata-go-static-4.3.1-arm64.tar.zst; do limactl cp "$cache/$asset" "$vm:/tmp/$asset"; done
limactl cp "$here/bootstrap.sh" "$vm:/tmp/openshell-kata-bootstrap.sh"
# Explicit compatibility profile: runtime-rs must be qualified on this host before replacing it.
limactl shell "$vm" bash /tmp/openshell-kata-bootstrap.sh go
"$here/prepare-image.sh"
