#!/usr/bin/env bash
# VM-side half of scripts/smoke-eth-ingress-2node.sh. Copied into node-a
# and node-b (NOT the client VM, which has no MCP server and is driven
# directly via `limactl shell` from the host script) and run there as root
# by the host driver -- not meant to be invoked directly by a human. One
# copy of this script runs on both nodes; which steps actually apply to a
# given node is decided by which subcommand the host driver calls, not by
# a baked-in role. Adapted from smoke-wg-2node-remote.sh: same wg0 tunnel
# + geneve0 setup, but node-a's beep instance binds its uplink hooks to
# eth0 (the real user-v2 NIC) instead of wg0.
#
# Requires wireguard-tools (`apt-get install wireguard-tools`) and bpftool
# (already present on the assigned Lima images from prior beep work).
set -euo pipefail

WG_IFACE="wg0"
GENEVE_IFACE="geneve0"
PIN_DIR="/sys/fs/bpf/beep-ethingress2node"
BIN="/tmp/beep-ethingress2node"
LOADER_LOG="/tmp/beep-ethingress2node-loader.log"
RPFILTER_SAVE_FILE="/tmp/beep-ethingress2node-rpfilter-all.saved"
ACCEPT_LOCAL_SAVE_FILE="/tmp/beep-ethingress2node-acceptlocal-all.saved"
TARGET_PORT="18090"
# See smoke-wg-2node-remote.sh's own header comment for the AppArmor/
# UDP-listen-timing rationale behind this exact directory and the
# key-then-up ordering below -- identical constraints, reused verbatim.
WG_KEY_DIR="/etc/wireguard"

cmd="${1:-}"
shift || true

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

# Node-a only. Confirms eth0 is up before the loader binds its uplink hooks
# to it -- a silent no-op attach to a down/missing device would otherwise
# surface only much later as an inexplicable client timeout.
check_uplink() {
  local iface="$1"
  ip link show "$iface" 2>/dev/null | grep -q "state UP\|UNKNOWN" || {
    echo "FAIL: uplink iface $iface is not up on this node" >&2
    ip -brief link show >&2
    exit 1
  }
  echo "UPLINK-CHECK: PASS ($iface is up)"
}

# Same rp_filter workaround smoke-wg-2node-remote.sh documents: the
# forward-decap program re-delivers the DNAT'd packet locally via `lo`
# while it physically arrived on geneve0, and Linux's reverse-path filter
# drops that mismatch. accept_local is set for the same reason as a
# defensive belt-and-suspenders measure, even though the client is now a
# genuinely foreign 3rd VM (beep-client) rather than one of node-b's own
# addresses. Saved/restored so this rig never leaves the VM's global
# rp_filter/accept_local permanently changed.
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
  if [ ! -f "$ACCEPT_LOCAL_SAVE_FILE" ]; then
    sysctl -n net.ipv4.conf.all.accept_local > "$ACCEPT_LOCAL_SAVE_FILE"
  fi
  sysctl -w net.ipv4.conf.all.accept_local=1 >/dev/null
  sysctl -w "net.ipv4.conf.${GENEVE_IFACE}.accept_local=1" >/dev/null
  sysctl -w net.ipv4.conf.lo.accept_local=1 >/dev/null
}

start_loader() {
  local uplink_iface="$WG_IFACE" fixture="" pod_cidr="" node_ip=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --uplink-iface) uplink_iface="$2"; shift 2 ;;
      --fixture) fixture="$2"; shift 2 ;;
      --pod-cidr) pod_cidr="$2"; shift 2 ;;
      --node-ip) node_ip="$2"; shift 2 ;;
      *) echo "start-loader: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  [ -n "$fixture" ] || { echo "start-loader: --fixture required" >&2; exit 1; }
  [ -n "$pod_cidr" ] || { echo "start-loader: --pod-cidr required" >&2; exit 1; }
  [ -n "$node_ip" ] || { echo "start-loader: --node-ip required" >&2; exit 1; }
  mkdir -p "$PIN_DIR"

  nohup "$BIN" \
    --uplink-iface "$uplink_iface" --geneve-iface "$GENEVE_IFACE" --pin-dir "$PIN_DIR" \
    --pod-cidr "$pod_cidr" --node-ip "$node_ip" \
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
  echo "VERIFIER-ACCEPT: PASS (uplink-iface=$uplink_iface)"
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
  printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK' > /tmp/ethingress2node-response.http
  nohup nc -l -N "$pod_ip" "$port" < /tmp/ethingress2node-response.http > /tmp/ethingress2node-backend.log 2>&1 &
  disown
  sleep 0.5
}

# bpftool + geneve0/wg0/eth0 counters + routes -- eth0 is the NEW evidence
# this rig needs beyond smoke-wg-2node-remote.sh's set, since the ingress
# leg under test here is eth0, not wg0.
dump_evidence() {
  echo "== bpftool map dump: VIP_MAP =="
  bpftool map dump pinned "$PIN_DIR/VIP_MAP" 2>&1 || true
  echo "== bpftool map dump: FWD_PENDING =="
  bpftool map dump pinned "$PIN_DIR/FWD_PENDING" 2>&1 || true
  echo "== bpftool map dump: FLOW_TABLE =="
  bpftool map dump pinned "$PIN_DIR/FLOW_TABLE" 2>&1 || true
  echo "== eth0 counters =="
  ip -s link show eth0 2>&1 || true
  echo "== geneve0 counters =="
  ip -s link show "$GENEVE_IFACE" 2>&1 || true
  echo "== wg0 counters =="
  ip -s link show "$WG_IFACE" 2>&1 || true
  echo "== route table =="
  ip route show 2>&1 || true
}

cleanup() {
  # Matches "--uplink-iface", not just "$BIN", so this can never match its
  # OWN invocation (`bash .../beep-ethingress2node-remote.sh cleanup`) --
  # $BIN's basename is a literal prefix of this script's own filename, so a
  # bare `pkill -f "$BIN"` self-SIGTERMs the running cleanup script before
  # it reaches the rest of these teardown steps (ip link del, sysctl
  # restore), silently leaving wg0/geneve0/the pin dir behind.
  pkill -f "$BIN --uplink-iface" 2>/dev/null || true
  pkill -f "nc -l -N .* ${TARGET_PORT}" 2>/dev/null || true
  rm -rf "$PIN_DIR"
  rm -f /tmp/ethingress2node-response.http /tmp/ethingress2node-backend.log "$LOADER_LOG"
  ip link del "$GENEVE_IFACE" 2>/dev/null || true
  ip link del "$WG_IFACE" 2>/dev/null || true
  if [ -f "$RPFILTER_SAVE_FILE" ]; then
    sysctl -w net.ipv4.conf.all.rp_filter="$(cat "$RPFILTER_SAVE_FILE")" >/dev/null 2>&1 || true
    rm -f "$RPFILTER_SAVE_FILE"
  fi
  if [ -f "$ACCEPT_LOCAL_SAVE_FILE" ]; then
    sysctl -w net.ipv4.conf.all.accept_local="$(cat "$ACCEPT_LOCAL_SAVE_FILE")" >/dev/null 2>&1 || true
    rm -f "$ACCEPT_LOCAL_SAVE_FILE"
  fi
  rm -f "$WG_KEY_DIR/privatekey"
}

case "$cmd" in
  setup-wg) setup_wg "$@" ;;
  pubkey) pubkey ;;
  setup-geneve) setup_geneve ;;
  check-uplink) check_uplink "$@" ;;
  setup-backend) setup_backend "$@" ;;
  start-loader) start_loader "$@" ;;
  start-backend-responder) start_backend_responder "$@" ;;
  dump-evidence) dump_evidence ;;
  cleanup) cleanup ;;
  *)
    echo "usage: $0 {setup-wg|pubkey|setup-geneve|check-uplink|setup-backend|start-loader|start-backend-responder|dump-evidence|cleanup} [args...]" >&2
    exit 1
    ;;
esac
