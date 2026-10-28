#!/usr/bin/env bash
# Fixed 2GiB per-snapshot cap in a task-owned thin pool on the disposable node.
set -euo pipefail
root=/var/lib/openshell-kata-devmapper
sudo mkdir -p "$root" /etc/containerd/conf.d
sudo modprobe dm_thin_pool
if ! sudo dmsetup info openshell-kata-pool >/dev/null 2>&1; then
  sudo truncate -s 12G "$root/data"
  sudo truncate -s 256M "$root/metadata"
  data=$(sudo losetup --find --show "$root/data")
  metadata=$(sudo losetup --find --show "$root/metadata")
  sectors=$(sudo blockdev --getsz "$data")
  printf '0 %s thin-pool %s %s 128 32768 1 error_if_no_space\n' "$sectors" "$metadata" "$data" | sudo dmsetup create openshell-kata-pool
fi
# Raw guest block access must never expose data from recycled thin-pool blocks.
if sudo dmsetup table openshell-kata-pool | grep -q skip_block_zeroing; then
  echo 'Unsafe existing thin pool: quiesce and reload it with block zeroing enabled before admission.' >&2
  exit 1
fi
sudo tee /etc/containerd/conf.d/openshell-kata-devmapper.toml >/dev/null <<'TOML'
version = 2
[plugins."io.containerd.snapshotter.v1.devmapper"]
  root_path = "/var/lib/openshell-kata-devmapper/snapshots"
  pool_name = "openshell-kata-pool"
  base_image_size = "2048MB"
  async_remove = false
[[plugins."io.containerd.transfer.v1.local".unpack_config]]
  platform = "linux/arm64"
  snapshotter = "overlayfs"
[[plugins."io.containerd.transfer.v1.local".unpack_config]]
  platform = "linux/arm64"
  snapshotter = "devmapper"
TOML
sudo systemctl restart containerd
sudo ctr plugins ls | grep devmapper
