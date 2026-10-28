#!/bin/sh
set -eu
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DOCKER_HOST=unix:///var/run/docker.sock
export DOCKER_TLS_CERTDIR=
echo RUST_KATA_KERNEL
uname -a
cat /proc/mounts
if grep -Eq ' (virtiofs|9p) ' /proc/mounts; then echo UNEXPECTED_SHARED_FILESYSTEM; exit 1; fi
for dev in /sys/class/block/vd*; do
  name=${dev##*/}
  case "$name" in *[0-9]) continue;; esac
  pair=$(cat "$dev/dev")
  mknod "/tmp/$name" b "${pair%:*}" "${pair#*:}"
  printf 'BLOCK %s sectors=%s readonly=%s\n' "$name" "$(cat "$dev/size")" "$(cat "$dev/ro")"
  if [ "$(cat "$dev/ro")" = 1 ]; then
    dd if="/tmp/$name" of=/tmp/original-byte bs=1 count=1 2>/dev/null
    if command -v blockdev >/dev/null; then blockdev --setrw "/tmp/$name" || true; fi
    if dd if=/tmp/original-byte of="/tmp/$name" bs=1 count=1 conv=notrunc 2>/tmp/block-write-error; then
      echo READ_ONLY_DISK_WRITE_UNEXPECTEDLY_SUCCEEDED
      exit 1
    fi
    printf 'READ_ONLY_WRITE_BLOCKED %s: ' "$name"
    cat /tmp/block-write-error
  fi
done
if grep -qs " /proc/sys " /proc/mounts; then mount -o remount,rw /proc/sys; fi
if grep -qs " /sys/fs/cgroup " /proc/mounts; then
  mount -o remount,rw /sys/fs/cgroup
else
  mkdir -p /sys/fs/cgroup
  mount -t cgroup2 cgroup /sys/fs/cgroup
fi
rm -f /var/run/docker.pid /var/run/docker.sock
dockerd --host=unix:///var/run/docker.sock --storage-driver=overlay2 >/tmp/dockerd-proof.log 2>&1 &
for count in $(seq 1 90); do
  if curl -fs --max-time 2 --unix-socket /var/run/docker.sock http://localhost/_ping >/dev/null; then break; fi
  sleep 1
done
docker version --format 'DOCKER_CLIENT={{.Client.Version}} DOCKER_SERVER={{.Server.Version}}'
mkdir -p /sandbox/proof
cp /bin/busybox /sandbox/proof/busybox
cp /lib/ld-musl-aarch64.so.1 /sandbox/proof/ld-musl-aarch64.so.1
cat > /sandbox/proof/Dockerfile <<'EOF'
FROM scratch
COPY busybox /busybox
COPY ld-musl-aarch64.so.1 /lib/ld-musl-aarch64.so.1
ENTRYPOINT ["/busybox"]
EOF
docker build --network none -t runtime-proof:local /sandbox/proof
docker run --rm --network none runtime-proof:local echo RUST_KATA_DOCKER_RUN_OK
cat > /sandbox/proof/compose.yaml <<'EOF'
services:
  check:
    image: runtime-proof:local
    command: ["echo", "RUST_KATA_COMPOSE_OK"]
    network_mode: none
EOF
docker compose -f /sandbox/proof/compose.yaml up --abort-on-container-exit --exit-code-from check
docker compose -f /sandbox/proof/compose.yaml down
printf 'RUST_KATA_PROOF_COMPLETE\n'
exec sleep 900
