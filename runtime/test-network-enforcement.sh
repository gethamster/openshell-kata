#!/usr/bin/env bash
# Run as root on the dedicated Linux test node. Never on an unrelated host.
set -euo pipefail

NETWORK_BIN=${NETWORK_BIN:-/opt/openshell-kata/kata-network}
NAMESPACE=${NAMESPACE:-oke-probe}
HOST_VETH=${HOST_VETH:-okehost0}
GUEST_IP=${GUEST_IP:-10.203.0.2}
GATEWAY_IP=${GATEWAY_IP:-10.203.0.1}
GUEST_MAC=${GUEST_MAC:-b6:93:d0:ea:f8:e7}
GATEWAY_MAC=${GATEWAY_MAC:-86:08:cd:14:80:d2}
BROKER_PORT=${BROKER_PORT:-38080}
CONTROL=${CONTROL:?set CONTROL to the private broker control socket}
GUEST_ID=${GUEST_ID:-}
GUEST_EXECUTOR=${GUEST_EXECUTOR:-nerdctl}
TEST_UNIT=${TEST_UNIT:-}
[[ $(id -u) == 0 ]] || { echo 'run inside the dedicated test VM as root' >&2; exit 1; }
[[ $NAMESPACE =~ ^[A-Za-z0-9_-]+$ && $HOST_VETH =~ ^[A-Za-z0-9_-]+$ ]] || exit 64
WORK=$(mktemp -d /tmp/openshell-network-test.XXXXXX)
PIDS=()
METADATA_ADDED=0
PEER_CREATED=0
HOST_MARKER="openshell-network-test-$$"
guest() {
  if [[ -n $GUEST_ID ]]; then
    if [[ $GUEST_EXECUTOR == ctr ]]; then ctr tasks exec --exec-id "netprobe-$BASHPID-$RANDOM" "$GUEST_ID" "$@";
    else nerdctl exec --user 0 "$GUEST_ID" "$@"; fi
  else ip netns exec "$NAMESPACE" "$@"; fi
}
cleanup() {
  set +e
  printf '{"tcp_allow":[]}' > "$WORK/deny.json"
  "$NETWORK_BIN" update --control "$CONTROL" --policy "$WORK/deny.json" --nonce cleanup-deny-policy-0001 > /dev/null 2>&1
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null; done
  guest ip addr del 10.203.0.99/32 dev eth0 2>/dev/null
  guest ip -6 addr del fd00:203::2/64 dev eth0 2>/dev/null
  guest iptables -D INPUT -s 10.204.0.2 -p tcp --dport 22 -m comment --comment okata-inbound-probe -j ACCEPT 2>/dev/null
  ip route del 10.203.0.99/32 dev "$HOST_VETH" 2>/dev/null
  ip neigh del 10.203.0.99 dev "$HOST_VETH" 2>/dev/null
  ip -6 addr del fd00:203::1/64 dev "$HOST_VETH" 2>/dev/null
  if [[ $METADATA_ADDED == 1 ]]; then ip addr del 169.254.169.254/32 dev lo; fi
  if [[ $PEER_CREATED == 1 ]]; then ip netns del okata-peer-probe; ip link del okpeerhost 2>/dev/null; fi
  sed "/# $HOST_MARKER$/d" /etc/hosts > "$WORK/hosts.cleaned"
  cat "$WORK/hosts.cleaned" > /etc/hosts
  rm -rf "$WORK"
}
trap cleanup EXIT
passed() { printf '{"test":"%s","passed":true}\n' "$1"; }
blocked() {
  local label=$1; shift
  if "$@" > "$WORK/blocked.stdout" 2> "$WORK/blocked.stderr"; then
    printf '{"test":"%s","passed":false}\n' "$label"; exit 1
  fi
  passed "$label"
}
curl_guest() { guest curl --noproxy '*' --connect-timeout 2 --max-time 3 -sS "$@"; }

cat > "$WORK/http" <<'EOF'
#!/bin/bash
IFS= read -r line || exit
while IFS= read -r line; do [[ $line == $'\r' || -z $line ]] && break; done
printf 'HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nsentinel'
EOF
chmod 700 "$WORK/http"
socat "TCP4-LISTEN:38081,bind=$GATEWAY_IP,reuseaddr,fork" "EXEC:$WORK/http" > /dev/null 2> "$WORK/tcp.log" & PIDS+=("$!")
socat "UDP4-RECVFROM:53535,bind=$GATEWAY_IP,reuseaddr,fork" EXEC:/bin/cat > /dev/null 2> "$WORK/udp.log" & PIDS+=("$!")
dnsmasq --keep-in-foreground --bind-interfaces --interface="$HOST_VETH" --listen-address="$GATEWAY_IP" --port=53 --no-resolv --no-hosts --address=/blocked.example/93.184.216.34 --pid-file= > /dev/null 2> "$WORK/dns.log" & PIDS+=("$!")
if ! ip -4 addr show dev lo | grep -q '169.254.169.254/32'; then ip addr add 169.254.169.254/32 dev lo; METADATA_ADDED=1; fi
socat TCP4-LISTEN:80,bind=169.254.169.254,reuseaddr,fork "EXEC:$WORK/http" > /dev/null 2> "$WORK/metadata.log" & PIDS+=("$!")
ip -6 addr add fd00:203::1/64 dev "$HOST_VETH" nodad
guest ip -6 addr add fd00:203::2/64 dev eth0 nodad
guest ip -6 neigh replace fd00:203::1 lladdr "$GATEWAY_MAC" dev eth0 nud permanent
ip -6 neigh replace fd00:203::2 lladdr "$GUEST_MAC" dev "$HOST_VETH" nud permanent
socat 'TCP6-LISTEN:38083,bind=[fd00:203::1],reuseaddr,fork' "EXEC:$WORK/http" > /dev/null 2> "$WORK/ipv6.log" & PIDS+=("$!")

ip netns add okata-peer-probe; PEER_CREATED=1
ip link add okpeerhost type veth peer name eth0 netns okata-peer-probe
ip addr add 10.204.0.1/30 dev okpeerhost; ip link set okpeerhost up
ip -n okata-peer-probe addr add 10.204.0.2/30 dev eth0
ip -n okata-peer-probe link set eth0 up; ip -n okata-peer-probe link set lo up
ip -n okata-peer-probe route add default via 10.204.0.1
[[ $(sysctl -n net.ipv4.ip_forward) == 1 ]] || { echo 'fixture requires host IPv4 forwarding for a meaningful sibling test' >&2; exit 1; }
ip netns exec okata-peer-probe socat TCP4-LISTEN:38084,reuseaddr,fork "EXEC:$WORK/http" > /dev/null 2> "$WORK/peer.log" & PIDS+=("$!")
if [[ -z $GUEST_ID ]]; then
  guest socat TCP4-LISTEN:22,reuseaddr,fork "EXEC:$WORK/http" > /dev/null 2> "$WORK/guest-control.log" & PIDS+=("$!")
fi

sleep 0.2
[[ $(curl --noproxy '*' -sS --max-time 2 "http://$GATEWAY_IP:38081") == sentinel ]]
[[ $(curl --noproxy '*' -sS --max-time 2 http://169.254.169.254/) == sentinel ]]
[[ $(curl --noproxy '*' -g -sS --max-time 2 'http://[fd00:203::1]:38083/') == sentinel ]]
[[ $(curl --noproxy '*' -sS --max-time 2 http://10.204.0.2:38084/) == sentinel ]]
[[ $(printf udp-baseline | nc -u -w 1 "$GATEWAY_IP" 53535) == udp-baseline ]]
[[ $(dig +short +tries=1 +time=1 @"$GATEWAY_IP" blocked.example) == 93.184.216.34 ]]
passed positive_host_service_baselines

[[ $(guest id -u) == 0 ]]
guest sh -c 'iptables -F; iptables -t nat -F; iptables -P OUTPUT ACCEPT; ip6tables -F; ip6tables -P OUTPUT ACCEPT'
passed guest_root_can_flush_guest_firewall
nc -z -w 2 "$GUEST_IP" 22
passed host_local_control_path_allowed
guest iptables -I INPUT 1 -s 10.204.0.2 -p tcp --dport 22 -m comment --comment okata-inbound-probe -j ACCEPT
blocked forwarded_sibling_inbound ip netns exec okata-peer-probe nc -z -w 2 "$GUEST_IP" 22
[[ $(guest iptables -L INPUT -n -v -x | awk '/okata-inbound-probe/{print $1}') == 0 ]]
passed forwarded_packets_do_not_reach_guest
blocked sibling_cannot_use_tenant_broker ip netns exec okata-peer-probe nc -z -w 2 "$GATEWAY_IP" "$BROKER_PORT"
blocked raw_tcp_to_host curl_guest "http://$GATEWAY_IP:38081/"
blocked metadata_endpoint curl_guest http://169.254.169.254/
blocked sibling_network curl_guest http://10.204.0.2:38084/
blocked ipv6_to_host curl_guest -g 'http://[fd00:203::1]:38083/'
[[ -z $(printf udp-denied | guest nc -u -w 1 "$GATEWAY_IP" 53535) ]]
passed raw_udp_to_host
blocked direct_dns guest dig +short +tries=1 +time=1 @"$GATEWAY_IP" blocked.example

cat > "$WORK/allow.json" <<'EOF'
{"tcp_allow":[{"host":"example.com","port":80},{"host":"example.com","port":443},{"host":"osk-rebind.invalid","port":443}]}
EOF
"$NETWORK_BIN" update --control "$CONTROL" --policy "$WORK/allow.json" --nonce network-allow-request-0001 > "$WORK/update.json"
guest curl --noproxy '' -x "http://$GATEWAY_IP:$BROKER_PORT" --connect-timeout 10 --max-time 20 -sS -o /dev/null https://example.com/
passed allowed_https_connect
guest curl --noproxy '' -x "http://$GATEWAY_IP:$BROKER_PORT" --connect-timeout 10 --max-time 20 -sS -o /dev/null http://example.com/
passed allowed_http_forward
[[ $(printf 'CONNECT example.net:443 HTTP/1.1\r\n\r\n' | guest nc -w 2 "$GATEWAY_IP" "$BROKER_PORT" | head -1) == *'403 Forbidden'* ]]
passed unlisted_host_denied
[[ $(printf 'CONNECT 127.0.0.1:22 HTTP/1.1\r\n\r\n' | guest nc -w 2 "$GATEWAY_IP" "$BROKER_PORT" | head -1) == *'403 Forbidden'* ]]
passed private_host_denied
[[ $(printf 'CONNECT user@example.com:443 HTTP/1.1\r\n\r\n' | guest nc -w 2 "$GATEWAY_IP" "$BROKER_PORT" | head -1) == *'400 Bad Request'* ]]
passed malformed_host_denied

printf '127.0.0.1 osk-rebind.invalid # %s\n' "$HOST_MARKER" >> /etc/hosts
getent ahostsv4 osk-rebind.invalid | grep -q '^127\.0\.0\.1'
DNS_RESPONSE=$(printf 'CONNECT osk-rebind.invalid:443 HTTP/1.1\r\n\r\n' | guest nc -w 2 "$GATEWAY_IP" "$BROKER_PORT" | head -1)
[[ $DNS_RESPONSE == *'403 Forbidden'* || $DNS_RESPONSE == *'502 Bad Gateway'* ]]
passed allowed_name_resolving_private_denied

guest ip addr add 10.203.0.99/32 dev eth0
ip route add 10.203.0.99/32 dev "$HOST_VETH"
ip neigh replace 10.203.0.99 lladdr "$GUEST_MAC" dev "$HOST_VETH" nud permanent
blocked spoofed_source_ip guest nc -z -w 2 -s 10.203.0.99 "$GATEWAY_IP" "$BROKER_PORT"
if [[ -z $GUEST_ID ]]; then
  guest hping3 -S -a 10.203.0.99 -p "$BROKER_PORT" -c 2 -i u100000 "$GATEWAY_IP" > "$WORK/spoof.log" 2>&1 || true
  grep -q '100% packet loss' "$WORK/spoof.log"; passed raw_source_ip_spoof
fi

if [[ -n $TEST_UNIT ]]; then
  [[ $(systemctl show "$TEST_UNIT" --property=NoNewPrivileges --value) == yes ]]
  [[ -z $(systemctl show "$TEST_UNIT" --property=CapabilityBoundingSet --value) ]]
  [[ $(systemctl show "$TEST_UNIT" --property=User --value) != root ]]
  BROKER_PID=$(systemctl show "$TEST_UNIT" --property=MainPID --value)
  [[ $BROKER_PID =~ ^[1-9][0-9]*$ ]]
  [[ $(awk '/^Uid:/{print $2}' "/proc/$BROKER_PID/status") != 0 ]]
  [[ $(awk '/^CapEff:/{print $2}' "/proc/$BROKER_PID/status") =~ ^0+$ ]]
  [[ $(awk '/^CapBnd:/{print $2}' "/proc/$BROKER_PID/status") =~ ^0+$ ]]
  [[ $(awk '/^NoNewPrivs:/{print $2}' "/proc/$BROKER_PID/status") == 1 ]]
  passed unprivileged_broker_no_capabilities
fi

guest bash -c '
  exec 3<>/dev/tcp/$1/$2
  printf "CONNECT example.com:443 HTTP/1.1\r\n\r\n" >&3
  while IFS= read -r -t 10 line <&3; do [[ $line == $'"'"'\r'"'"' ]] && break; done
  printf "READY\n"
  if IFS= read -r -t 10 value <&3; then exit 4; else code=$?; [[ $code == 1 ]] || exit 5; fi
  printf "REVOKED\n"
' probe "$GATEWAY_IP" "$BROKER_PORT" > "$WORK/revocation.log" 2>&1 &
REVOKE_PID=$!; PIDS+=("$REVOKE_PID")
for _ in $(seq 1 40); do grep -q READY "$WORK/revocation.log" && break; sleep 0.25; done
grep -q READY "$WORK/revocation.log"
printf '{"tcp_allow":[]}' > "$WORK/deny.json"
"$NETWORK_BIN" update --control "$CONTROL" --policy "$WORK/deny.json" --nonce revoke-policy-request-0001 > "$WORK/revoke.json"
wait "$REVOKE_PID"
grep -q REVOKED "$WORK/revocation.log"
passed active_connection_revoked
MODE=namespace; [[ -n $GUEST_ID ]] && MODE=kata
printf '{"complete":true,"mode":"%s"}\n' "$MODE"
