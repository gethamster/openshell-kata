#!/bin/sh
set -eu
# These mounts are inside the Kata guest. Never pass node block devices or sockets.
mount -o remount,rw /proc/sys
mount -o remount,rw /sys/fs/cgroup
chown root:root /etc/ssh/authorized_keys /etc/ssh/ssh_host_ed25519_key
chmod 644 /etc/ssh/authorized_keys
chmod 600 /etc/ssh/ssh_host_ed25519_key
mkdir -p /run/sshd /sandbox /var/log
chown sandbox:sandbox /sandbox
# PID files survive in the container snapshot even though all guest processes died.
# At this fresh boot no Docker daemon exists; discard only its transient runtime handles.
rm -f /var/run/docker.pid /var/run/docker.sock \
  /var/run/docker/containerd/containerd.pid /var/run/docker/containerd/containerd.sock
# The only Docker API listener is a Unix socket inside this guest.
dockerd --host=unix:///var/run/docker.sock --group=sandbox --storage-driver=overlay2 > /var/log/docker.log 2>&1 &
exec /usr/sbin/sshd -D -e -f /etc/ssh/openshell-kata.conf
