#!/usr/bin/env bash
# VM-side half of scripts/smoke-wg-2node.sh. Copied into each Lima
# VM and run there as root by the host driver -- not meant to be invoked
# directly by a human. One copy of this script runs on BOTH nodes; which
# steps actually apply to a given node is decided by which subcommand the
# host driver calls, not by a baked-in role.
#
# Requires wireguard-tools (`apt-get install wireguard-tools`) and bpftool
# (already present on the assigned Lima images from prior beep work).
set -euo pipefail

WG_IFACE="wg0"
GENEVE_IFACE="geneve0"
PIN_DIR="/sys/fs/bpf/beep-wg2node"
BIN="/tmp/beep-wg2node"
LOADER_LOG="/tmp/beep-wg2node-loader.log"
RPFILTER_SAVE_FILE="/tmp/beep-wg2node-rpfilter-all.saved"
IPFORWARD_SAVE_FILE="/tmp/beep-wg2node-ipforward.saved"
IP6FORWARD_SAVE_FILE="/tmp/beep-wg2node-ip6forward.saved"
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
# Dual-stack client fixture: a veth pair whose peer end lives in its own
# netns, standing in for a genuinely foreign v4 AND v6 client on the same
# 2-node rig -- same isolation technique smoke-remote.sh's smoke-client
# netns already uses, chosen here (over a 3rd VM) so this node's own address
# is never also the packet's source, which is what martian-source-drops a
# co-located client. Both families share one veth pair since one device can
# hold a v4 and a v6 address simultaneously.
CLIENT_VETH="wg2ds-veth0"
CLIENT_VETH_PEER="wg2ds-veth1"
CLIENT_NETNS="smoke-wg2node-client"

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
  local self_ip="" peer_ip="" peer_pubkey="" peer_endpoint="" listen_port="51820" extra_allowed="" family="4"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --self-ip) self_ip="$2"; shift 2 ;;
      --peer-ip) peer_ip="$2"; shift 2 ;;
      --peer-pubkey) peer_pubkey="$2"; shift 2 ;;
      --peer-endpoint) peer_endpoint="$2"; shift 2 ;;
      --listen-port) listen_port="$2"; shift 2 ;;
      --extra-allowed) extra_allowed="$2"; shift 2 ;;
      --family) family="$2"; shift 2 ;;
      *) echo "setup-wg: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  [[ -n "$self_ip" && -n "$peer_ip" && -n "$peer_pubkey" && -n "$peer_endpoint" ]] || {
    echo "setup-wg: --self-ip, --peer-ip, --peer-pubkey, --peer-endpoint all required" >&2
    exit 1
  }
  [[ "$family" == "4" || "$family" == "6" ]] || {
    echo "setup-wg: --family must be 4 or 6, got '$family'" >&2
    exit 1
  }
  # WireGuard tunnels arbitrary IP payloads over a v4 or v6 endpoint alike,
  # but the tunnel's OWN self/peer addressing (assigned inside this
  # function, distinct from --peer-endpoint's outer transport address) has
  # a family-specific mask: a v6 ULA needs a /64 self-address and /128
  # peer allowed-ips, where v4's /24 and /32 do not apply.
  local self_mask="24" peer_mask="32"
  [ "$family" = "6" ] && { self_mask="64"; peer_mask="128"; }

  genkey
  ip link show "$WG_IFACE" >/dev/null 2>&1 || ip link add "$WG_IFACE" type wireguard
  wg set "$WG_IFACE" private-key "$WG_KEY_DIR/privatekey" listen-port "$listen_port"
  # --extra-allowed: node-a's peer entry for node-b, widened past node-b's
  # own /32 to also admit the foreign beep-client's real address. WireGuard
  # validates a decrypted packet's SOURCE against the sending peer's
  # allowed-ips, so node-b relaying (ip_forward) beep-client's plain SYN
  # into the tunnel would otherwise be silently dropped on decrypt -- the
  # client can never be a WG peer itself (see lima/beep-client.yaml).
  local allowed="${peer_ip}/${peer_mask}"
  [ -n "$extra_allowed" ] && allowed="${allowed},${extra_allowed}"
  wg set "$WG_IFACE" peer "$peer_pubkey" allowed-ips "$allowed" endpoint "$peer_endpoint"
  ip addr replace "${self_ip}/${self_mask}" dev "$WG_IFACE"
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
  local pod_ip="" pod_ip_v6=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pod-ip) pod_ip="$2"; shift 2 ;;
      --pod-ip-v6) pod_ip_v6="$2"; shift 2 ;;
      *) echo "setup-backend: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  [ -n "$pod_ip" ] || { echo "setup-backend: --pod-ip required" >&2; exit 1; }

  ip addr replace "${pod_ip}/32" dev lo
  [ -n "$pod_ip_v6" ] && ip -6 addr replace "${pod_ip_v6}/128" dev lo
  if [ ! -f "$RPFILTER_SAVE_FILE" ]; then
    sysctl -n net.ipv4.conf.all.rp_filter > "$RPFILTER_SAVE_FILE"
  fi
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  sysctl -w "net.ipv4.conf.${GENEVE_IFACE}.rp_filter=0" >/dev/null

  # This node is also the client's WireGuard relay (see setup_wg's
  # --extra-allowed comment): the client's SYN arrives on eth0 destined for
  # the VIP on node-a's wg0 subnet, which is a genuine inter-device forward,
  # not local delivery -- the kernel drops it unless ip_forward is on.
  if [ ! -f "$IPFORWARD_SAVE_FILE" ]; then
    sysctl -n net.ipv4.ip_forward > "$IPFORWARD_SAVE_FILE"
  fi
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  # v6 forwarding is its own separate sysctl (net.ipv4.ip_forward doesn't
  # cover it) -- only needed/toggled when a v6 pod_ip is actually in play.
  if [ -n "$pod_ip_v6" ]; then
    if [ ! -f "$IP6FORWARD_SAVE_FILE" ]; then
      sysctl -n net.ipv6.conf.all.forwarding > "$IP6FORWARD_SAVE_FILE"
    fi
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
  fi
}

# Dual-stack client fixture: idempotent create of
# $CLIENT_VETH/$CLIENT_VETH_PEER + $CLIENT_NETNS, with a v4 and/or v6 address
# on each end. The root end stays in this node's default netns (so ordinary
# kernel routing -- ip_forward, enabled by setup_backend above -- carries the
# client's packet from here toward wg0/geneve0 exactly like a real foreign
# client's would); the peer end, isolated in $CLIENT_NETNS, is where the
# actual curl client runs. A default route per family inside the netns is
# enough: it has no other interface to prefer.
setup_client_netns() {
  local v4_root="" v4_client="" v4_prefix="" v6_root="" v6_client="" v6_prefix=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --v4-root) v4_root="$2"; shift 2 ;;
      --v4-client) v4_client="$2"; shift 2 ;;
      --v4-prefix) v4_prefix="$2"; shift 2 ;;
      --v6-root) v6_root="$2"; shift 2 ;;
      --v6-client) v6_client="$2"; shift 2 ;;
      --v6-prefix) v6_prefix="$2"; shift 2 ;;
      *) echo "setup-client-netns: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  [ -n "$v4_root" ] && [ -n "$v4_client" ] && [ -n "$v4_prefix" ] || {
    echo "setup-client-netns: --v4-root, --v4-client, --v4-prefix all required" >&2
    exit 1
  }
  [ -n "$v6_root" ] && [ -n "$v6_client" ] && [ -n "$v6_prefix" ] || {
    echo "setup-client-netns: --v6-root, --v6-client, --v6-prefix all required" >&2
    exit 1
  }

  ip link show "$CLIENT_VETH" >/dev/null 2>&1 || \
    ip link add "$CLIENT_VETH" type veth peer name "$CLIENT_VETH_PEER"
  ip netns add "$CLIENT_NETNS" 2>/dev/null || true
  ip link show "$CLIENT_VETH_PEER" >/dev/null 2>&1 && \
    ip link set "$CLIENT_VETH_PEER" netns "$CLIENT_NETNS"

  ip addr replace "${v4_root}/${v4_prefix}" dev "$CLIENT_VETH"
  ip -6 addr replace "${v6_root}/${v6_prefix}" dev "$CLIENT_VETH"
  ip link set "$CLIENT_VETH" up

  ip netns exec "$CLIENT_NETNS" ip addr replace "${v4_client}/${v4_prefix}" dev "$CLIENT_VETH_PEER"
  ip netns exec "$CLIENT_NETNS" ip -6 addr replace "${v6_client}/${v6_prefix}" dev "$CLIENT_VETH_PEER"
  ip netns exec "$CLIENT_NETNS" ip link set "$CLIENT_VETH_PEER" up
  ip netns exec "$CLIENT_NETNS" ip link set lo up
  ip netns exec "$CLIENT_NETNS" ip route replace default via "$v4_root"
  ip netns exec "$CLIENT_NETNS" ip -6 route replace default via "$v6_root"
  echo "CLIENT-NETNS-UP: PASS (${CLIENT_NETNS}: v4 ${v4_client} via ${v4_root}, v6 ${v6_client} via ${v6_root})"
}

start_loader() {
  local uplink_iface="$WG_IFACE" pod_cidr="" node_ip=""
  # `--fixture` is repeatable (`beep`'s own CLI, `src/main.rs`'s `Vec<Fixture>`):
  # collected into an array here too, not a scalar, or a 2nd `--fixture`
  # would silently overwrite the 1st instead of adding a 2nd front
  # (confirmed empirically: a dual-stack fixture set's v4 entry vanished
  # from LB_FRONT_MAP with a scalar `fixture=`, since only the last
  # `--fixture` given ever survived).
  local fixtures=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --uplink-iface) uplink_iface="$2"; shift 2 ;;
      --fixture) fixtures+=("$2"); shift 2 ;;
      --pod-cidr) pod_cidr="$2"; shift 2 ;;
      --node-ip) node_ip="$2"; shift 2 ;;
      *) echo "start-loader: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  [ "${#fixtures[@]}" -gt 0 ] || { echo "start-loader: at least one --fixture required" >&2; exit 1; }
  [ -n "$pod_cidr" ] || { echo "start-loader: --pod-cidr required" >&2; exit 1; }
  [ -n "$node_ip" ] || { echo "start-loader: --node-ip required" >&2; exit 1; }
  mkdir -p "$PIN_DIR"

  local fixture_args=()
  for f in "${fixtures[@]}"; do
    fixture_args+=(--fixture "$f")
  done
  nohup "$BIN" \
    --uplink-iface "$uplink_iface" --geneve-iface "$GENEVE_IFACE" --pin-dir "$PIN_DIR" \
    --pod-cidr "$pod_cidr" --node-ip "$node_ip" \
    "${fixture_args[@]}" \
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
  local pod_ip="" port="" family="4" nc_flag="-4" body="OK"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pod-ip) pod_ip="$2"; shift 2 ;;
      --port) port="$2"; shift 2 ;;
      --family) family="$2"; shift 2 ;;
      --body) body="$2"; shift 2 ;;
      *) echo "start-backend-responder: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  [ "$family" = "6" ] && nc_flag="-6"
  local response_file="/tmp/wg2node-response-${port}.http"
  local backend_log="/tmp/wg2node-backend-${port}.log"
  printf 'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' \
    "${#body}" "$body" > "$response_file"
  nohup nc "$nc_flag" -l -N "$pod_ip" "$port" < "$response_file" > "$backend_log" 2>&1 &
  disown
  sleep 0.5
}

# bpftool + geneve0/wg0/eth0/client-veth counters + routes -- eth0 and the
# route table are the relay-specific evidence this rig needs beyond the
# original geneve0/wg0 set, since the client's SYN now transits this node's
# eth0 (as a genuine IP forward into wg0) rather than being self-originated
# here. The client-veth/netns block is this rig's dual-stack addition.
dump_evidence() {
  echo "== bpftool map dump: LB_FRONT_MAP =="
  bpftool map dump pinned "$PIN_DIR/LB_FRONT_MAP" 2>&1 || true
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
  echo "== $CLIENT_VETH counters =="
  ip -s link show "$CLIENT_VETH" 2>&1 || true
  echo "== $CLIENT_NETNS addrs/routes =="
  ip netns exec "$CLIENT_NETNS" ip addr show 2>&1 || true
  ip netns exec "$CLIENT_NETNS" ip route show 2>&1 || true
  ip netns exec "$CLIENT_NETNS" ip -6 route show 2>&1 || true
  echo "== route table =="
  ip route show 2>&1 || true
}

cleanup() {
  # Matches "$BIN --uplink-iface", not just "$BIN": $BIN's basename
  # ("beep-wg2node") is a literal prefix of this script's own filename
  # ("beep-wg2node-remote.sh"), so a bare `pkill -f "$BIN"` self-SIGTERMs
  # the running cleanup script (invoked as `bash /tmp/beep-wg2node-remote.sh
  # cleanup`) before it reaches the rest of these teardown steps -- same
  # fix as smoke-eth-ingress-2node-remote.sh's cleanup().
  pkill -f "$BIN --uplink-iface" 2>/dev/null || true
  pkill -f "nc -[46] -l -N" 2>/dev/null || true
  rm -rf "$PIN_DIR"
  rm -f /tmp/wg2node-response*.http /tmp/wg2node-backend*.log "$LOADER_LOG"
  ip link del "$GENEVE_IFACE" 2>/dev/null || true
  ip link del "$WG_IFACE" 2>/dev/null || true
  ip link del "$CLIENT_VETH" 2>/dev/null || true
  ip netns del "$CLIENT_NETNS" 2>/dev/null || true
  if [ -f "$RPFILTER_SAVE_FILE" ]; then
    sysctl -w net.ipv4.conf.all.rp_filter="$(cat "$RPFILTER_SAVE_FILE")" >/dev/null 2>&1 || true
    rm -f "$RPFILTER_SAVE_FILE"
  fi
  if [ -f "$IPFORWARD_SAVE_FILE" ]; then
    sysctl -w net.ipv4.ip_forward="$(cat "$IPFORWARD_SAVE_FILE")" >/dev/null 2>&1 || true
    rm -f "$IPFORWARD_SAVE_FILE"
  fi
  if [ -f "$IP6FORWARD_SAVE_FILE" ]; then
    sysctl -w net.ipv6.conf.all.forwarding="$(cat "$IP6FORWARD_SAVE_FILE")" >/dev/null 2>&1 || true
    rm -f "$IP6FORWARD_SAVE_FILE"
  fi
  rm -f "$WG_KEY_DIR/privatekey"
}

case "$cmd" in
  setup-wg) setup_wg "$@" ;;
  pubkey) pubkey ;;
  setup-geneve) setup_geneve ;;
  setup-backend) setup_backend "$@" ;;
  setup-client-netns) setup_client_netns "$@" ;;
  start-loader) start_loader "$@" ;;
  start-backend-responder) start_backend_responder "$@" ;;
  dump-evidence) dump_evidence ;;
  cleanup) cleanup ;;
  *)
    echo "usage: $0 {setup-wg|pubkey|setup-geneve|setup-backend|setup-client-netns|start-loader|start-backend-responder|dump-evidence|cleanup} [args...]" >&2
    exit 1
    ;;
esac
