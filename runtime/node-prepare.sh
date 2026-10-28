#!/usr/bin/env bash
# Dedicated Linux node bootstrap. Never run against an unrelated/shared node.
set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential musl-tools curl pkg-config nftables lvm2 thin-provisioning-tools zstd
if ! test -x "$HOME/.cargo/bin/cargo"; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/openshell-rustup-init.sh
  sh /tmp/openshell-rustup-init.sh -y --profile minimal --default-toolchain 1.98.0 --no-modify-path
fi
