#!/usr/bin/env bash
set -euo pipefail
vm=${OPENSHELL_KATA_VM:-openshell-kata-rust}
here=$(cd -- "$(dirname -- "$0")" && pwd)
image=docker@sha256:9e79b879b177fbd72c34376a3dd3d91747da5db49e1f560f76aea59561471977
run() { limactl shell "$vm" sudo nerdctl "$@"; }
run pull "$image"
# Trusted image assembly uses an ordinary build container inside the dedicated VM.
# Tenant sandboxes always use Kata in lifecycle.py.
run run --runtime io.containerd.runc.v2 --name openshell-kata-seed --label openshell-kata.managed=true "$image" sh -ec 'apk add --no-cache openssh-server openssh-sftp-server python3 bash coreutils; addgroup -g 1000 sandbox; adduser -D -h /sandbox -u 1000 -G sandbox sandbox; passwd -d sandbox; mkdir -p /sandbox; chown 1000:1000 /sandbox'
limactl cp "$here/guest-init.sh" "$vm:/tmp/openshell-kata-init"
limactl cp "$here/sshd_config" "$vm:/tmp/openshell-kata.conf"
limactl shell "$vm" chmod +x /tmp/openshell-kata-init
run cp /tmp/openshell-kata-init openshell-kata-seed:/usr/local/sbin/openshell-kata-init
run cp /tmp/openshell-kata.conf openshell-kata-seed:/etc/ssh/openshell-kata.conf
run commit openshell-kata-seed openshell-kata-guest:local
run rm openshell-kata-seed
