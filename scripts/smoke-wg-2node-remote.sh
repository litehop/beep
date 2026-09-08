#!/usr/bin/env bash
# VM-side half of scripts/servicelb/smoke-wg-2node.sh. Copied into each Lima
# VM and run there as root by the host driver -- not meant to be invoked
# directly by a human. One copy of this script runs on BOTH nodes; which
# steps actually apply to a given node is decided by which subcommand the
# host driver calls, not by a baked-in role.
#
# Requires wireguard-tools (`apt-get install wireguard-tools`) and bpftool
# (already present on the assigned Lima images from prior servicelb work).
set -euo pipefail

WG_IFACE="wg0"
GENEVE_IFACE="geneve0"
PIN_DIR="/sys/fs/bpf/servicelb-wg2node"
BIN="/tmp/u7s-servicelb-wg2node"
LOADER_LOG="/tmp/servicelb-wg2node-loader.log"
RPFILTER_SAVE_FILE="/tmp/servicelb-wg2node-rpfilter-all.saved"
# Canonical's wg AppArmor profile (`/etc/apparmor.d/wg`, confirmed present on
# the Ubuntu Lima image this rig targets) grants `/usr/bin/wg` file rw ONLY
# under `/etc/wireguard/**` -- no `dac_override`/`dac_read_search`
# capability, so `wg set <iface> private-key <path>` on a key anywhere else
# fails with `fopen: Permission denied` even as root (confirmed via
# `dmesg`'s `apparmor="DENIED" ... capname="dac_read_search"` /
# `"dac_override"` entries). This is NOT the Lima guest kernel (the 2026-09-04
# spike wrongly suspected 7.0.0-30-generic; the operator's own physical fleet
# runs that exact kernel over Tailscale/WireGuard) -- it is Ubuntu's own
# wireguard-tools package hardening, and the fix is simply keeping every key
# under this exact directory.
WG_KEY_DIR="/etc/wireguard"

cmd="${1:-}"
shift || true

# `wg set <iface> listen-port N` alone, on a still-administratively-DOWN
# interface, reports success (`wg show` even echoes the configured port
# back) but the kernel does NOT bind the UDP socket until the device
# transitions up -- confirmed empirically: `ss -ulnp`/`/proc/net/udp` show
# nothing for the port until immediately after `ip link set <iface> up`,
# at which point the listener appears with no further config change. This
# -- not a Lima networking quirk -- is the second half of the 2026-09-04
# spike's "wg set/show OK, no UDP listen socket" mystery: wg-quick always
# does key/peer config BEFORE bringing the link up for this exact reason,
# and this rig follows the same order.
# Idempotent: generates this node's key pair under the AppArmor-allowed
# directory if one doesn't already exist. Split out from setup_wg so the
# host driver can fetch both nodes' pubkeys (via the `pubkey` subcommand)
# BEFORE either side's peer config is known, instead of the two nodes'
# WireGuard configs depending on each other in a chicken-and-egg order.
genkey() {
  mkdir -p "$WG_KEY_DIR"
  if [ ! -s "$WG_KEY_DIR/privatekey" ]; then
    umask 077
    wg genkey > "$WG_KEY_DIR/privatekey"
  fi
}

setup_wg() {
  local self_ip="" peer_ip="" peer_pubkey="" peer_endpoint="" listen_port="51820"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --self-ip) self_ip="$2"; shift 2 ;;
      --peer-ip) peer_ip="$2"; shift 2 ;;
      --peer-pubkey) peer_pubkey="$2"; shift 2 ;;
      --peer-endpoint) peer_endpoint="$2"; shift 2 ;;
      --listen-port) listen_port="$2"; shift 2 ;;
      *) echo "setup-wg: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  [[ -n "$self_ip" && -n "$peer_ip" && -n "$peer_pubkey" && -n "$peer_endpoint" ]] || {
    echo "setup-wg: --self-ip, --peer-ip, --peer-pubkey, --peer-endpoint all required" >&2
    exit 1
  }

  genkey
  ip link show "$WG_IFACE" >/dev/null 2>&1 || ip link add "$WG_IFACE" type wireguard
  wg set "$WG_IFACE" private-key "$WG_KEY_DIR/privatekey" listen-port "$listen_port"
  wg set "$WG_IFACE" peer "$peer_pubkey" allowed-ips "${peer_ip}/32" endpoint "$peer_endpoint"
  ip addr replace "${self_ip}/24" dev "$WG_IFACE"
  ip link set "$WG_IFACE" up

  for _ in $(seq 1 20); do
    ss -uln 2>/dev/null | grep -q ":${listen_port} " && break
    sleep 0.2
  done
  ss -uln 2>/dev/null | grep -q ":${listen_port} " || {
    echo "FAIL: no UDP listen socket on port ${listen_port} after bringing ${WG_IFACE} up" >&2
    exit 1
  }
  echo "WG-UP: PASS (${WG_IFACE} ${self_ip}, listening on :${listen_port}, peer ${peer_ip} via ${peer_endpoint})"
}

pubkey() {
  genkey
  wg pubkey < "$WG_KEY_DIR/privatekey"
}

setup_geneve() {
  ip link show "$GENEVE_IFACE" >/dev/null 2>&1 || ip link add "$GENEVE_IFACE" type geneve external
  ip link set "$GENEVE_IFACE" up
}

# Same empirically-required workaround smoke-remote.sh documents: the
# forward-decap program re-delivers the DNAT'd packet locally via `lo`
# while it physically arrived on geneve0, and Linux's reverse-path filter
# drops that mismatch. Saved/restored so this rig never leaves the VM's
# global rp_filter permanently weakened.
setup_backend() {
  local pod_ip=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pod-ip) pod_ip="$2"; shift 2 ;;
      *) echo "setup-backend: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  [ -n "$pod_ip" ] || { echo "setup-backend: --pod-ip required" >&2; exit 1; }

  ip addr replace "${pod_ip}/32" dev lo
  if [ ! -f "$RPFILTER_SAVE_FILE" ]; then
    sysctl -n net.ipv4.conf.all.rp_filter > "$RPFILTER_SAVE_FILE"
  fi
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  sysctl -w "net.ipv4.conf.${GENEVE_IFACE}.rp_filter=0" >/dev/null
}

start_loader() {
  local uplink_iface="$WG_IFACE" fixture=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --fixture) fixture="$2"; shift 2 ;;
      *) echo "start-loader: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  [ -n "$fixture" ] || { echo "start-loader: --fixture required" >&2; exit 1; }
  mkdir -p "$PIN_DIR"

  nohup "$BIN" \
    --uplink-iface "$uplink_iface" --geneve-iface "$GENEVE_IFACE" --pin-dir "$PIN_DIR" \
    --fixture "$fixture" \
    >"$LOADER_LOG" 2>&1 &
  loader_pid=$!
  disown

  for _ in $(seq 1 20); do
    grep -q "all 3 hooks attached" "$LOADER_LOG" 2>/dev/null && break
    if ! kill -0 "$loader_pid" 2>/dev/null; then
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
  loaded=$(bpftool prog list | grep -cE 'name (uplink_ingress|geneve_ingress|uplink_egress_return)')
  [ "$loaded" -eq 3 ] || {
    echo "FAIL: expected 3 sched_cls programs loaded, bpftool sees $loaded" >&2
    exit 1
  }
  echo "VERIFIER-ACCEPT: PASS"
  cat "$LOADER_LOG"
}

start_backend_responder() {
  local pod_ip="" port=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pod-ip) pod_ip="$2"; shift 2 ;;
      --port) port="$2"; shift 2 ;;
      *) echo "start-backend-responder: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK' > /tmp/wg2node-response.http
  nohup nc -l -N "$pod_ip" "$port" < /tmp/wg2node-response.http > /tmp/wg2node-backend.log 2>&1 &
  disown
  sleep 0.5
}

# Drives the client request and reports the OUTCOME either way -- a
# currently-known dataplane blocker (see this script's header) is expected
# to time out here, and this must FAIL LOUD with the map/counter evidence
# rather than hang or claim a false pass.
run_client() {
  local vip_ip="" vip_port="" pin_dir_ingress=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --vip-ip) vip_ip="$2"; shift 2 ;;
      --vip-port) vip_port="$2"; shift 2 ;;
      *) echo "run-client: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  set +e
  body=$(curl -sS -m 5 "http://${vip_ip}:${vip_port}/" 2>&1)
  rc=$?
  set -e
  if [ "$rc" -eq 0 ] && [ "$body" = "OK" ]; then
    echo "ROUND-TRIP: PASS (client -> VIP ${vip_ip}:${vip_port} -> cross-node backend -> response 'OK')"
    return 0
  fi
  echo "ROUND-TRIP: FAIL (curl rc=$rc, body='$body') -- run 'dump-evidence' on both nodes" >&2
  return 1
}

# bpftool + geneve0 counters -- the evidence this rig captured for the
# bpf_redirect(wg0 -> geneve0) finding: FWD_PENDING dumps prove
# uplink_ingress correctly parsed a real L3 WireGuard packet (aie31.5's
# fix), while geneve0's TX `dropped` counter incrementing on every attempt,
# with zero corresponding RX on the peer, is the redirect failing before
# the encapsulated packet ever leaves this node.
dump_evidence() {
  echo "== bpftool map dump: VIP_MAP =="
  bpftool map dump pinned "$PIN_DIR/VIP_MAP" 2>&1 || true
  echo "== bpftool map dump: FWD_PENDING =="
  bpftool map dump pinned "$PIN_DIR/FWD_PENDING" 2>&1 || true
  echo "== bpftool map dump: FWD_MAIN =="
  bpftool map dump pinned "$PIN_DIR/FWD_MAIN" 2>&1 || true
  echo "== geneve0 counters =="
  ip -s link show "$GENEVE_IFACE" 2>&1 || true
  echo "== wg0 counters =="
  ip -s link show "$WG_IFACE" 2>&1 || true
}

cleanup() {
  pkill -f "$BIN" 2>/dev/null || true
  pkill -f "nc -l -N .* 18090" 2>/dev/null || true
  rm -rf "$PIN_DIR"
  rm -f /tmp/wg2node-response.http /tmp/wg2node-backend.log "$LOADER_LOG"
  ip link del "$GENEVE_IFACE" 2>/dev/null || true
  ip link del "$WG_IFACE" 2>/dev/null || true
  if [ -f "$RPFILTER_SAVE_FILE" ]; then
    sysctl -w net.ipv4.conf.all.rp_filter="$(cat "$RPFILTER_SAVE_FILE")" >/dev/null 2>&1 || true
    rm -f "$RPFILTER_SAVE_FILE"
  fi
  rm -f "$WG_KEY_DIR/privatekey"
}

case "$cmd" in
  setup-wg) setup_wg "$@" ;;
  pubkey) pubkey ;;
  setup-geneve) setup_geneve ;;
  setup-backend) setup_backend "$@" ;;
  start-loader) start_loader "$@" ;;
  start-backend-responder) start_backend_responder "$@" ;;
  run-client) run_client "$@" ;;
  dump-evidence) dump_evidence ;;
  cleanup) cleanup ;;
  *)
    echo "usage: $0 {setup-wg|pubkey|setup-geneve|setup-backend|start-loader|start-backend-responder|run-client|dump-evidence|cleanup} [args...]" >&2
    exit 1
    ;;
esac
