#!/usr/bin/env bash
# Execute inside the task VM after copying the pinned release archives into /tmp.
set -euo pipefail
mode=${1:-go}
printf '%s  %s\n' 2c5bf7cde334ad5307d482f45cceda496f91c9b6b96f5278c47f4f4eac1bbae6 /tmp/kata-static-4.3.1-arm64.tar.zst | sha256sum -c -
printf '%s  %s\n' 2ff9b77869a902405c5d5b65fb38a5e93a18ae29e5e8891181e3a097f110741a /tmp/kata-go-static-4.3.1-arm64.tar.zst | sha256sum -c -
command -v zstd >/dev/null || { sudo apt-get update -qq; sudo apt-get install -y -qq zstd; }
sudo tar --zstd -xf /tmp/kata-static-4.3.1-arm64.tar.zst -C /
sudo mkdir -p /etc/kata-containers
case "$mode" in
  go)
    sudo tar --zstd -xf /tmp/kata-go-static-4.3.1-arm64.tar.zst -C / ./opt/kata/bin/containerd-shim-kata-v2 ./opt/kata/bin/kata-runtime ./opt/kata/share/defaults/kata-containers/configuration-qemu.toml
    sudo cp /opt/kata/share/defaults/kata-containers/configuration-qemu.toml /etc/kata-containers/configuration.toml
    sudo sed -i 's/pmu=off//g' /etc/kata-containers/configuration.toml
    sudo ln -sf /opt/kata/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-v2
    ;;
  dragonball)
    sudo cp /opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml /opt/kata/share/defaults/kata-containers/runtime-rs/configuration.toml
    sudo ln -sf /opt/kata/runtime-rs/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-v2
    ;;
  *) echo 'Unsupported runtime mode' >&2; exit 2 ;;
esac
sudo modprobe vhost_vsock
sudo modprobe vhost_net
sudo iptables -C FORWARD -s 10.202.0.0/16 -d 10.202.0.0/16 -j DROP 2>/dev/null || sudo iptables -I FORWARD 1 -s 10.202.0.0/16 -d 10.202.0.0/16 -j DROP
sudo iptables -C INPUT -s 10.202.0.0/16 -m conntrack --ctstate NEW -j DROP 2>/dev/null || sudo iptables -I INPUT 1 -s 10.202.0.0/16 -m conntrack --ctstate NEW -j DROP
