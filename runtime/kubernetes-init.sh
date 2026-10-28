#!/bin/sh
set -eu
# These mounts and credentials are inside the Kata VM, never node resources.
if grep -q ' /proc/sys ' /proc/mounts; then mount -o remount,rw /proc/sys; fi
if grep -q ' /sys/fs/cgroup ' /proc/mounts; then mount -o remount,rw /sys/fs/cgroup; fi
cp /run/guest-ssh/authorized_keys /etc/ssh/authorized_keys
cp /run/guest-ssh/host_key /etc/ssh/ssh_host_ed25519_key
chmod 644 /etc/ssh/authorized_keys
chmod 600 /etc/ssh/ssh_host_ed25519_key
mkdir -p /run/sshd /sandbox /var/log
: > /etc/ssh/openshell-kata-env.conf
chown sandbox:sandbox /sandbox
rm -f /var/run/docker.pid /var/run/docker.sock \
  /var/run/docker/containerd/containerd.pid /var/run/docker/containerd/containerd.sock
# The PVC transport requires VFS; local block-backed guests use overlay2.
dockerd --host=unix:///var/run/docker.sock --group=sandbox --storage-driver=vfs > /var/log/docker.log 2>&1 &
exec /usr/sbin/sshd -D -e -f /etc/ssh/openshell-kata.conf
