#!/usr/bin/env bash
# VM-side half of scripts/servicelb/smoke.sh. Copied into the Lima VM and
# run there as root by smoke.sh -- not meant to be invoked directly by a
# human. Builds a self-contained veth-pair + netns fixture so the whole
# client->VIP->backend round trip happens on ONE VM (the original
# hand-verification in PR #1557 used a second physical Lima VM as the
# client; a reproducible harness can't depend on a peer machine being
# available). Owns geneve0 and the smoke-veth0/smoke-client fixture
# exclusively for its duration -- do not run this alongside a real
# servicelb deployment on the same VM.
set -euo pipefail

# RFC 5737 documentation ranges: deliberately disjoint from any real subnet
# a given VM's CNI/pod network happens to be using.
VIP_IP="203.0.113.1"
CLIENT_IP="203.0.113.2"
VIP_PORT="19100"
POD_IP="198.51.100.53"
TARGET_PORT="18080"
PIN_DIR="/sys/fs/bpf/servicelb-smoke"
BIN="/tmp/u7s-servicelb-smoke"
LOADER_LOG="/tmp/servicelb-smoke-loader.log"
BACKEND_LOG="/tmp/servicelb-smoke-backend.log"
RESPONSE_FILE="/tmp/servicelb-smoke-response.http"
RPFILTER_SAVE_FILE="/tmp/servicelb-smoke-rpfilter-all.saved"

cmd="${1:-}"

cleanup() {
  pkill -f "$BIN" 2>/dev/null || true
  pkill -f "nc -l -N ${POD_IP} ${TARGET_PORT}" 2>/dev/null || true
  rm -rf "$PIN_DIR"
  # Delete the veth (destroys both ends, wherever each lives) BEFORE the
  # netns: deleting the netns first can orphan smoke-veth1's namespace --
  # the veth peer keeps it alive with its bind-mount name already gone,
  # leaving an unreachable, unnamed namespace behind (seen empirically).
  ip link del smoke-veth0 2>/dev/null || true
  ip netns del smoke-client 2>/dev/null || true
  ip link del geneve0 2>/dev/null || true
  ip addr del "${POD_IP}/32" dev lo 2>/dev/null || true
  if [ -f "$RPFILTER_SAVE_FILE" ]; then
    sysctl -w net.ipv4.conf.all.rp_filter="$(cat "$RPFILTER_SAVE_FILE")" >/dev/null 2>&1 || true
    rm -f "$RPFILTER_SAVE_FILE"
  fi
}

case "$cmd" in
  cleanup)
    cleanup
    exit 0
    ;;
  run)
    ;;
  *)
    echo "usage: $0 {run|cleanup}" >&2
    exit 1
    ;;
esac

command -v bpftool >/dev/null || {
  echo "FAIL: bpftool not found in the VM (install linux-tools-\$(uname -r))" >&2
  exit 1
}

# Idempotent: clear any leftover fixture from a prior interrupted run before
# creating a fresh one.
cleanup >/dev/null 2>&1 || true

echo "==> creating geneve0 external (collect-metadata) device"
ip link add geneve0 type geneve external
ip link set geneve0 up

echo "==> creating smoke-veth0/smoke-veth1 + smoke-client netns (stands in for a real client machine)"
ip link add smoke-veth0 type veth peer name smoke-veth1
ip netns add smoke-client
ip link set smoke-veth1 netns smoke-client
ip addr add "${VIP_IP}/24" dev smoke-veth0
ip link set smoke-veth0 up
ip netns exec smoke-client ip addr add "${CLIENT_IP}/24" dev smoke-veth1
ip netns exec smoke-client ip link set smoke-veth1 up
ip netns exec smoke-client ip link set lo up
ip addr add "${POD_IP}/32" dev lo

# Empirically required for this fixture (kfree_skb tracepoint pinpointed
# `ip_rcv_finish_core`, reason IP_RPFILTER): the forward-decap program
# re-delivers the DNAT'd packet locally via `lo` (the pod_ip alias above)
# while it physically arrived on geneve0 -- Linux's loose (2) reverse-path
# filter still drops that mismatch for a source reachable only via a
# different device (smoke-veth0). A real deployment routes the decap'd
# packet to an actual Pod veth instead of a loopback alias and does not
# appear to need this (PR #1557's real 2-node run never touched rp_filter);
# saved/restored so this harness never leaves the VM's global rp_filter
# permanently weakened.
if [ ! -f "$RPFILTER_SAVE_FILE" ]; then
  sysctl -n net.ipv4.conf.all.rp_filter > "$RPFILTER_SAVE_FILE"
fi
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.geneve0.rp_filter=0 >/dev/null

echo "==> loading servicelb-ebpf -- this is the verifier-accept gate"
nohup "$BIN" \
  --uplink-iface smoke-veth0 --geneve-iface geneve0 --pin-dir "$PIN_DIR" \
  --vip-ip "$VIP_IP" --vip-port "$VIP_PORT" --proto tcp \
  --backend-node-ip "$VIP_IP" --pod-ip "$POD_IP" --target-port "$TARGET_PORT" \
  >"$LOADER_LOG" 2>&1 &
disown

for _ in $(seq 1 20); do
  grep -q "all 3 hooks attached" "$LOADER_LOG" 2>/dev/null && break
  if ! pgrep -f "$BIN" >/dev/null; then
    echo "FAIL: loader exited before attaching (verifier rejection or load error):" >&2
    cat "$LOADER_LOG" >&2
    exit 1
  fi
  sleep 0.5
done
grep -q "all 3 hooks attached" "$LOADER_LOG" || {
  echo "FAIL: loader never reported all 3 hooks attached within 10s:" >&2
  cat "$LOADER_LOG" >&2
  exit 1
}
echo "VERIFIER-ACCEPT: PASS"
cat "$LOADER_LOG"

# Independent, kernel-truth confirmation (not just the loader's own log):
# a verifier rejection never reaches this state at all, since program.load()
# above would have returned Err and aborted the loader before this point.
loaded=$(bpftool prog list | grep -cE 'name (uplink_ingress|geneve_ingress|uplink_egress_return)')
[ "$loaded" -eq 3 ] || {
  echo "FAIL: expected 3 sched_cls programs loaded, bpftool sees $loaded" >&2
  exit 1
}

echo "==> starting backend responder on ${POD_IP}:${TARGET_PORT}"
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK' > "$RESPONSE_FILE"
nohup nc -l -N "$POD_IP" "$TARGET_PORT" < "$RESPONSE_FILE" >"$BACKEND_LOG" 2>&1 &
disown
sleep 0.5

echo "==> driving one client -> VIP -> backend round trip"
body=$(ip netns exec smoke-client curl -sS -m 5 "http://${VIP_IP}:${VIP_PORT}/")
[ "$body" = "OK" ] || {
  echo "FAIL: expected response body 'OK', got: $body" >&2
  exit 1
}
echo "ROUND-TRIP: PASS (client ${CLIENT_IP} -> VIP ${VIP_IP}:${VIP_PORT} -> backend ${POD_IP}:${TARGET_PORT} -> response 'OK')"
