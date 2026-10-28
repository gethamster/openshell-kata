#!/usr/bin/env bash
set -euo pipefail
name=openshell-kata-cap-canary
thin_id=16700000
pool=openshell-kata-pool
if dmsetup info "$name" >/dev/null 2>&1; then
  echo 'Refusing to replace an existing canary device' >&2
  exit 1
fi
dmsetup message "$pool" 0 "create_thin $thin_id"
created=true
cleanup() {
  dmsetup remove "$name" 2>/dev/null || true
  if [[ "$created" = true ]]; then dmsetup message "$pool" 0 "delete $thin_id"; fi
}
trap cleanup EXIT
printf '0 4194304 thin /dev/mapper/%s %s\n' "$pool" "$thin_id" | dmsetup create "$name"
size=$(blockdev --getsize64 "/dev/mapper/$name")
[[ "$size" = 2147483648 ]]
printf X | dd of="/dev/mapper/$name" bs=1 count=1 conv=notrunc status=none
cmp -i 1:0 -n 65535 "/dev/mapper/$name" /dev/zero
printf 'ZERO_TAIL_OK bytes=65535\n'
set +e
message=$(dd if=/dev/zero of="/dev/mapper/$name" bs=512 seek=4194304 count=1 conv=notrunc 2>&1)
code=$?
set -e
[[ "$code" != 0 && "$message" = *'No space left on device'* ]]
printf 'HARD_CAP_OK size=%s exit=%s\n%s\n' "$size" "$code" "$message"
dmsetup table "$pool"
