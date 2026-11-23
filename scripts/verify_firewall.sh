#!/bin/sh
# Real-kernel check for the generated worker firewall plan.
#
# Run as root inside a disposable Linux container with NET_ADMIN, NET_RAW and
# SYS_ADMIN, nftables + iproute2 installed:
#
#   docker run --rm --user 0 --network bridge \
#     --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=SYS_ADMIN \
#     -v "$PWD/egress.nft:/egress.nft:ro" \
#     -v "$PWD/scripts/verify_firewall.sh:/lab.sh:ro" <image> sh /lab.sh
#
# Topology (all private, nothing leaves the machine):
#
#   worker ns 172.30.0.1 --veth-- 172.30.0.2  router  10.99.0.1 --veth-- 10.99.0.2 target ns
#
# Namespaces are held by sleeping PIDs (``unshare -n`` + ``ip link set ... netns
# PID``), which avoids the /run/netns mount that fails in restricted runtimes.
#
# The plan under test allows exactly 172.30.0.0/24 -> 10.99.0.2:8080 and drops
# every other forwarded packet from the worker. Baseline probes run first, so a
# later BLOCK is the rules blocking traffic, not a missing route or dead port.
set -eu

PLAN_FILE="${1:-/egress.nft}"
GATEWAY_IP="10.99.0.2"
GATEWAY_PORT="8080"
BLOCKED_PORT="8081"
OTHER_HOST="10.99.0.3"

PIDS=""
W_PID=""
T_PID=""
cleanup() {
    for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
    [ -n "$W_PID" ] && kill "$W_PID" 2>/dev/null || true
    [ -n "$T_PID" ] && kill "$T_PID" 2>/dev/null || true
    nft delete table inet ishastra_egress 2>/dev/null || true
    ip link del wh 2>/dev/null || true
    ip link del th 2>/dev/null || true
}
trap cleanup EXIT

unshare -n -- sh -c 'ip link set lo up; while :; do sleep 60; done' &
W_PID=$!
unshare -n -- sh -c 'ip link set lo up; while :; do sleep 60; done' &
T_PID=$!
sleep 1

ip link add wh type veth peer name ww
ip link set ww netns "$W_PID"
ip addr add 172.30.0.2/24 dev wh
ip link set wh up

ip link add th type veth peer name tt
ip link set tt netns "$T_PID"
ip addr add 10.99.0.1/24 dev th
ip link set th up

nsenter -t "$W_PID" -n ip addr add 172.30.0.1/24 dev ww
nsenter -t "$W_PID" -n ip link set ww up
nsenter -t "$W_PID" -n ip route add default via 172.30.0.2

nsenter -t "$T_PID" -n ip addr add "$GATEWAY_IP/24" dev tt
nsenter -t "$T_PID" -n ip addr add "$OTHER_HOST/24" dev tt
nsenter -t "$T_PID" -n ip link set tt up
nsenter -t "$T_PID" -n ip route add 172.30.0.0/24 via 10.99.0.1

# procfs may be read-only in a container; --sysctl sets these instead.
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true

nsenter -t "$T_PID" -n python3 -m http.server "$GATEWAY_PORT" --bind "$GATEWAY_IP" >/dev/null 2>&1 &
PIDS="$PIDS $!"
nsenter -t "$T_PID" -n python3 -m http.server "$BLOCKED_PORT" --bind "$GATEWAY_IP" >/dev/null 2>&1 &
PIDS="$PIDS $!"
nsenter -t "$T_PID" -n python3 -m http.server "$GATEWAY_PORT" --bind "$OTHER_HOST" >/dev/null 2>&1 &
PIDS="$PIDS $!"

# UDP responder on 53 (DNS) and 5353 (baseline port). The baseline uses 5353 so
# no conntrack entry exists for 53 when the rules are applied; otherwise the
# established flow would be accepted and hide the drop.
nsenter -t "$T_PID" -n python3 -u - <<'PY' >/dev/null 2>&1 &
import select
import socket

socks = []
for port in (53, 5353):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("10.99.0.2", port))
    socks.append(s)
while True:
    ready, _, _ = select.select(socks, [], [])
    for s in ready:
        data, addr = s.recvfrom(2048)
        s.sendto(b"pong", addr)
PY
PIDS="$PIDS $!"
sleep 1

# Prints ALLOW when the TCP handshake completes, BLOCK otherwise.
probe() {
    nsenter -t "$W_PID" -n python3 - "$1" "$2" <<'PY'
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
sock = socket.socket()
sock.settimeout(2)
try:
    sock.connect((host, port))
except OSError:
    print("BLOCK")
else:
    print("ALLOW")
finally:
    sock.close()
PY
}

FAILED=0
# UDP counterpart: a reply means the datagram crossed the router.
udp_probe() {
    nsenter -t "$W_PID" -n python3 - "$1" "$2" <<'PY'
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2)
try:
    sock.sendto(b"ping", (host, port))
    data, _ = sock.recvfrom(2048)
except OSError:
    print("BLOCK")
else:
    print("ALLOW" if data else "BLOCK")
finally:
    sock.close()
PY
}

expect() {  # label expected actual
    if [ "$2" = "$3" ]; then
        echo "PASS $1: $3"
    else
        echo "FAIL $1: expected $2, got $3"
        FAILED=1
    fi
}

echo "--- baseline (rules not applied yet) ---"
expect "baseline gateway:port" ALLOW "$(probe "$GATEWAY_IP" "$GATEWAY_PORT")"
expect "baseline gateway:other-port" ALLOW "$(probe "$GATEWAY_IP" "$BLOCKED_PORT")"
expect "baseline other-host:port" ALLOW "$(probe "$OTHER_HOST" "$GATEWAY_PORT")"
expect "baseline udp:5353" ALLOW "$(udp_probe "$GATEWAY_IP" 5353)"

echo "--- applying the generated plan ---"
nft -f "$PLAN_FILE"
nft list table inet ishastra_egress

echo "--- after rules ---"
expect "allowed gateway:port" ALLOW "$(probe "$GATEWAY_IP" "$GATEWAY_PORT")"
expect "blocked gateway:other-port" BLOCK "$(probe "$GATEWAY_IP" "$BLOCKED_PORT")"
expect "blocked other-host:port" BLOCK "$(probe "$OTHER_HOST" "$GATEWAY_PORT")"
expect "blocked metadata ip" BLOCK "$(probe 169.254.169.254 80)"
expect "blocked udp dns:53" BLOCK "$(udp_probe "$GATEWAY_IP" 53)"

if [ "$FAILED" -ne 0 ]; then
    echo "RESULT: FAILED"
    exit 1
fi
echo "RESULT: ALL RULES ENFORCED BY THE KERNEL"
