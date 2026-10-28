#!/usr/bin/env bash
# Install the official Rust Kata runtime on the dedicated disposable Linux node.
set -euo pipefail
archive=/tmp/kata-static-4.3.1-arm64.tar.zst
printf '%s  %s\n' 2c5bf7cde334ad5307d482f45cceda496f91c9b6b96f5278c47f4f4eac1bbae6 "$archive" | sha256sum -c -
command -v zstd >/dev/null || { sudo apt-get update -qq; sudo apt-get install -y -qq zstd; }
sudo tar --zstd -xf "$archive" -C /
config=/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml
sudo sed -i -E \
 -e 's/virtio-blk-pci/virtio-blk-mmio/g' \
 -e 's/^shared_fs = .*/shared_fs = "none"/' \
 -e 's/^default_vcpus = .*/default_vcpus = 1/' \
 -e 's/^default_maxvcpus = .*/default_maxvcpus = 1/' \
 -e 's/^default_memory = .*/default_memory = 2048/' \
 -e 's/^default_maxmemory = .*/default_maxmemory = 2048/' \
 -e 's/^overhead_vcpus = .*/overhead_vcpus = 0/' \
 -e 's/^overhead_memory = .*/overhead_memory = 0/' "$config"
sudo ln -sfn configuration-dragonball.toml /opt/kata/share/defaults/kata-containers/runtime-rs/configuration.toml
sudo ln -sfn /opt/kata/runtime-rs/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-v2
sudo modprobe vhost_vsock
sudo modprobe vhost_net
