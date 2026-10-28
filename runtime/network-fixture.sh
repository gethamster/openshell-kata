#!/usr/bin/env bash
set -euo pipefail
ns=oke-probe
host=okehost0
peer=okeguest0
ip netns add "$ns"
ip link add "$host" type veth peer name "$peer"
ip link set "$peer" netns "$ns"
ip addr add 10.203.0.1/30 dev "$host"
ip link set "$host" up
ip -n "$ns" link set lo up
ip -n "$ns" link set "$peer" name eth0
ip -n "$ns" addr add 10.203.0.2/30 dev eth0
ip -n "$ns" link set eth0 up
ip -n "$ns" route add default via 10.203.0.1
printf '{"sandbox_id":"network-fixture","netns":"/run/netns/%s","host_veth":"%s","ifindex":%s,"guest_ip":"10.203.0.2","gateway_ip":"10.203.0.1","guest_mac":"%s","gateway_mac":"%s","broker_port":38080,"proof_nonce":"fixture-nonce"}\n' "$ns" "$host" "$(cat /sys/class/net/$host/ifindex)" "$(ip netns exec "$ns" cat /sys/class/net/eth0/address)" "$(cat /sys/class/net/$host/address)"
