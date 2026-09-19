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
# netns, standing in for a genuinely foreign v4 AND v6 client -- same
# isolation technique smoke-remote.sh's smoke-client netns already uses, so
# this node's own address is never also the packet's source, which is what
# martian-source-drops a co-located client. Both families share one veth
# pair since one device can hold a v4 and a v6 address simultaneously.
CLIENT_VETH="wg2ds-veth0"
CLIENT_VETH_PEER="wg2ds-veth1"
CLIENT_NETNS="smoke-wg2node-client"
# Layered on top of the veth pair above (as pure transport) for a genuine
# cross-node round trip: `try_geneve_decap_return`'s final client-bound
# `bpf_redirect` blindly carries over whatever L2 header arrived on
# `geneve0`'s decap, which is an all-zero synthetic one whenever the
# re-encapsulating peer's own uplink is L3-only (`wg0`, unavoidable for a
# 2-node WireGuard-mesh rig's return leg) -- redirecting that zero-dst-mac
# frame straight at a real Ethernet device like $CLIENT_VETH gets it
# `eth_type_trans`-classified `PACKET_OTHERHOST` and dropped by `ip_rcv`,
# confirmed via a live kernel capture (dst mac `00:00:00:00:00:00`, tcpdump
# sees it since it runs promiscuous, but the IP stack never does). An
# `ipip`/`ip6tnl` tunnel device is ARPHRD_TUNNEL, not Ethernet -- no
# `eth_type_trans` dst-mac check applies at all, so layering one on top of
# the veth (which still only ever carries genuinely address-matched traffic
# of its own) sidesteps the whole class of failure with zero dataplane
# changes. `IP{,6}TNL_ROOT`/`_CLIENT` name the tunnel's OWN inner endpoints;
# `CLIENT_VETH`'s own addresses (set by setup_client_netns) become the
# tunnel's local/remote transport addresses instead of being dialed
# directly.
IPTNL_IFACE="wg2ds-ipc0"
IPTNL_IFACE_PEER="wg2ds-ipc1"
IP6TNL_IFACE="wg2ds-ip6c0"
IP6TNL_IFACE_PEER="wg2ds-ip6c1"

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
  local return_routes=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pod-ip) pod_ip="$2"; shift 2 ;;
      --pod-ip-v6) pod_ip_v6="$2"; shift 2 ;;
      # `uplink_egress_return`'s TC-egress hook only ever fires for a
      # destination the kernel's OWN routing table already resolves to
      # $WG_IFACE -- a genuinely cross-node client's tunnel-inner subnet
      # (see $IPTNL_IFACE's comment) has no such route by default, since it
      # never physically touches this node's LAN. Repeatable: one v4 + one
      # v6 CIDR for a dual-stack round trip.
      --return-route) return_routes+=("$2"); shift 2 ;;
      *) echo "setup-backend: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  [ -n "$pod_ip" ] || { echo "setup-backend: --pod-ip required" >&2; exit 1; }

  ip addr replace "${pod_ip}/32" dev lo
  [ -n "$pod_ip_v6" ] && ip -6 addr replace "${pod_ip_v6}/128" dev lo
  for cidr in "${return_routes[@]}"; do
    case "$cidr" in
      *:*) ip -6 route replace "$cidr" dev "$WG_IFACE" ;;
      *) ip route replace "$cidr" dev "$WG_IFACE" ;;
    esac
  done
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
# on each end. The root end stays in this node's default netns; the peer
# end, isolated in $CLIENT_NETNS, is where the actual curl client runs. On
# the genuinely-cross-node ingress node, this veth pair is pure transport
# for setup_client_tunnels' ipip/ip6tnl overlay below, not the client's own
# dialed address -- its default route gets replaced by that step.
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

# $CLIENT_VETH's own comment above explains WHY: this node's ingress uplink
# is an ipip/ip6tnl tunnel, not $CLIENT_VETH directly, so the client's own
# packets are genuinely sourced from --v4-inner-client/--v6-inner-client,
# not $CLIENT_VETH's address. Idempotent, mirrors setup_client_netns's
# create-both-ends-then-address-each shape; must run AFTER
# setup_client_netns (its --v4-root/--v6-root become this tunnel's local
# endpoint, --v4-client/--v6-client its remote one).
setup_client_tunnels() {
  local v4_root="" v4_peer="" v4_inner_root="" v4_inner_client="" v4_inner_prefix=""
  local v6_root="" v6_peer="" v6_inner_root="" v6_inner_client="" v6_inner_prefix=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --v4-transport-root) v4_root="$2"; shift 2 ;;
      --v4-transport-client) v4_peer="$2"; shift 2 ;;
      --v4-inner-root) v4_inner_root="$2"; shift 2 ;;
      --v4-inner-client) v4_inner_client="$2"; shift 2 ;;
      --v4-inner-prefix) v4_inner_prefix="$2"; shift 2 ;;
      --v6-transport-root) v6_root="$2"; shift 2 ;;
      --v6-transport-client) v6_peer="$2"; shift 2 ;;
      --v6-inner-root) v6_inner_root="$2"; shift 2 ;;
      --v6-inner-client) v6_inner_client="$2"; shift 2 ;;
      --v6-inner-prefix) v6_inner_prefix="$2"; shift 2 ;;
      *) echo "setup-client-tunnels: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  [ -n "$v4_root" ] && [ -n "$v4_peer" ] && [ -n "$v4_inner_root" ] && [ -n "$v4_inner_client" ] && [ -n "$v4_inner_prefix" ] || {
    echo "setup-client-tunnels: --v4-transport-root, --v4-transport-client, --v4-inner-root, --v4-inner-client, --v4-inner-prefix all required" >&2
    exit 1
  }
  [ -n "$v6_root" ] && [ -n "$v6_peer" ] && [ -n "$v6_inner_root" ] && [ -n "$v6_inner_client" ] && [ -n "$v6_inner_prefix" ] || {
    echo "setup-client-tunnels: --v6-transport-root, --v6-transport-client, --v6-inner-root, --v6-inner-client, --v6-inner-prefix all required" >&2
    exit 1
  }

  ip link show "$IPTNL_IFACE" >/dev/null 2>&1 || \
    ip link add "$IPTNL_IFACE" type ipip local "$v4_root" remote "$v4_peer"
  ip addr replace "${v4_inner_root}/${v4_inner_prefix}" dev "$IPTNL_IFACE"
  ip link set "$IPTNL_IFACE" up

  ip -6 link show "$IP6TNL_IFACE" >/dev/null 2>&1 || \
    ip -6 link add "$IP6TNL_IFACE" type ip6tnl mode ip6ip6 local "$v6_root" remote "$v6_peer"
  ip -6 addr replace "${v6_inner_root}/${v6_inner_prefix}" dev "$IP6TNL_IFACE"
  ip link set "$IP6TNL_IFACE" up

  ip netns exec "$CLIENT_NETNS" ip link show "$IPTNL_IFACE_PEER" >/dev/null 2>&1 || \
    ip netns exec "$CLIENT_NETNS" ip link add "$IPTNL_IFACE_PEER" type ipip local "$v4_peer" remote "$v4_root"
  ip netns exec "$CLIENT_NETNS" ip addr replace "${v4_inner_client}/${v4_inner_prefix}" dev "$IPTNL_IFACE_PEER"
  ip netns exec "$CLIENT_NETNS" ip link set "$IPTNL_IFACE_PEER" up
  # ipip needs an explicit next-hop (its own remote endpoint resolves the
  # rest); ip6tnl below is happy with a bare `dev` default, confirmed
  # empirically -- `via <addr> dev ip6c1` on a /127-narrow point-to-point
  # tunnel address instead answers "No route to host".
  ip netns exec "$CLIENT_NETNS" ip route replace default via "$v4_inner_root" dev "$IPTNL_IFACE_PEER"

  ip netns exec "$CLIENT_NETNS" ip -6 link show "$IP6TNL_IFACE_PEER" >/dev/null 2>&1 || \
    ip netns exec "$CLIENT_NETNS" ip -6 link add "$IP6TNL_IFACE_PEER" type ip6tnl mode ip6ip6 local "$v6_peer" remote "$v6_root"
  ip netns exec "$CLIENT_NETNS" ip -6 addr replace "${v6_inner_client}/${v6_inner_prefix}" dev "$IP6TNL_IFACE_PEER"
  ip netns exec "$CLIENT_NETNS" ip link set "$IP6TNL_IFACE_PEER" up
  ip netns exec "$CLIENT_NETNS" ip -6 route replace default dev "$IP6TNL_IFACE_PEER"
  echo "CLIENT-TUNNELS-UP: PASS (v4 ${v4_inner_client} over ${IPTNL_IFACE}/${v4_root}<->${v4_peer}, v6 ${v6_inner_client} over ${IP6TNL_IFACE}/${v6_root}<->${v6_peer})"
}

start_loader() {
  local pod_cidr="" node_ip=""
  # `--fixture`/`--uplink-iface` are both repeatable (`beep`'s own CLI,
  # `src/main.rs`'s `Vec<Fixture>`/`Vec<String>`): collected into arrays
  # here too, not scalars, or a 2nd occurrence would silently overwrite the
  # 1st instead of adding a 2nd front/uplink (confirmed empirically: a
  # dual-stack fixture set's v4 entry vanished from LB_FRONT_MAP with a
  # scalar `fixture=`, since only the last `--fixture` given ever
  # survived -- the same failure mode bit a dual-stack (v4+v6 tunnel)
  # `--uplink-iface` pair here, silently dropping the v4 uplink's own
  # tc attachment).
  local fixtures=()
  local uplink_ifaces=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --uplink-iface) uplink_ifaces+=("$2"); shift 2 ;;
      --fixture) fixtures+=("$2"); shift 2 ;;
      --pod-cidr) pod_cidr="$2"; shift 2 ;;
      --node-ip) node_ip="$2"; shift 2 ;;
      *) echo "start-loader: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  [ "${#uplink_ifaces[@]}" -gt 0 ] || uplink_ifaces=("$WG_IFACE")
  [ "${#fixtures[@]}" -gt 0 ] || { echo "start-loader: at least one --fixture required" >&2; exit 1; }
  [ -n "$pod_cidr" ] || { echo "start-loader: --pod-cidr required" >&2; exit 1; }
  [ -n "$node_ip" ] || { echo "start-loader: --node-ip required" >&2; exit 1; }
  mkdir -p "$PIN_DIR"

  local fixture_args=()
  for f in "${fixtures[@]}"; do
    fixture_args+=(--fixture "$f")
  done
  local uplink_args=()
  for u in "${uplink_ifaces[@]}"; do
    uplink_args+=(--uplink-iface "$u")
  done
  nohup "$BIN" \
    "${uplink_args[@]}" --geneve-iface "$GENEVE_IFACE" --pin-dir "$PIN_DIR" \
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
  echo "VERIFIER-ACCEPT: PASS (uplink-iface=${uplink_ifaces[*]})"
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
  # `-v`: nc logs "Connection received on <peer-ip> <peer-port>" to
  # $backend_log on accept -- the host driver's client-IP-preservation
  # assertion (the whole point of a genuine cross-node round trip, not just
  # a passing curl) greps this for the client's OWN tunnel-inner address,
  # not this node's or any NAT'd address.
  nohup nc "$nc_flag" -v -l -N "$pod_ip" "$port" < "$response_file" > "$backend_log" 2>&1 &
  disown
  sleep 0.5
}

# `beep_common::peer_node_admission`'s doc comment: fixture/smoke mode has
# no controller-driven Node watch, so a bare loader's `NODE_ALLOW` only ever
# contains ITS OWN `--node-ip` (`populate_fixtures` in `src/main.rs` prunes
# every other entry on each start). A genuine two-node round trip needs each
# side to also admit the OTHER's outer Geneve source, which nothing but a
# controller (not run here) or this test-side fixture ever writes. Printing
# this node's own key -- rather than recomputing the peer's from its
# `--node-ip` string here in bash -- sidesteps re-deriving
# `tunnel_remote_v6`'s host-native/wire-token v4 byte-reversal convention: the
# loader already computed it correctly when it wrote its own entry, so the
# host driver just copies those exact bytes into the peer's NODE_ALLOW.
dump_node_allow_key() {
  bpftool map dump pinned "$PIN_DIR/NODE_ALLOW" -j | jq -r '.[0].key | join(" ")'
}

# See dump_node_allow_key's comment above for why this takes raw key bytes
# rather than an IP string. Adds, not replaces: this node's OWN self-entry
# (written by its own loader at start-loader time) must survive alongside
# the peer's.
seed_node_allow() {
  local key_hex=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key-hex) key_hex="$2"; shift 2 ;;
      *) echo "seed-node-allow: unknown argument: $1" >&2; exit 1 ;;
    esac
  done
  [ -n "$key_hex" ] || { echo "seed-node-allow: --key-hex required" >&2; exit 1; }
  # shellcheck disable=SC2086 # $key_hex is a bpftool-supplied space-separated byte list, meant to split.
  bpftool map update pinned "$PIN_DIR/NODE_ALLOW" key $key_hex value 0x01
  echo "NODE-ALLOW-SEED: PASS (added peer key ${key_hex// /:})"
}

# RX+TX packet count on $WG_IFACE as one number -- the host driver diffs
# this before/after a round trip as its wg0-traversal evidence: a genuine
# cross-node encap/decap must move this counter, unlike the same-node
# self-loop this rig replaces.
wg_packet_count() {
  local rx tx
  rx=$(cat "/sys/class/net/${WG_IFACE}/statistics/rx_packets")
  tx=$(cat "/sys/class/net/${WG_IFACE}/statistics/tx_packets")
  echo "$((rx + tx))"
}

# bpftool + geneve0/wg0/eth0/client-veth counters + routes -- eth0 and the
# route table are the relay-specific evidence this rig needs beyond the
# original geneve0/wg0 set, since the client's SYN now transits this node's
# eth0 (as a genuine IP forward into wg0) rather than being self-originated
# here. The client-veth/netns/tunnel block is this rig's dual-stack
# addition -- gated on $CLIENT_NETNS actually existing, since
# smoke-wg-2node.sh's single-fixture v4 path (this function's other caller)
# never creates it: unconditionally `ip netns exec`-ing a netns that was
# never set up on THIS node just adds "Cannot open network namespace"
# noise to that script's own failure dumps.
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
  if ip netns list 2>/dev/null | grep -q "^${CLIENT_NETNS}"; then
    echo "== $CLIENT_VETH counters =="
    ip -s link show "$CLIENT_VETH" 2>&1 || true
    echo "== $IPTNL_IFACE/$IP6TNL_IFACE counters =="
    ip -s link show "$IPTNL_IFACE" 2>&1 || true
    ip -s link show "$IP6TNL_IFACE" 2>&1 || true
    echo "== $CLIENT_NETNS addrs/routes =="
    ip netns exec "$CLIENT_NETNS" ip addr show 2>&1 || true
    ip netns exec "$CLIENT_NETNS" ip route show 2>&1 || true
    ip netns exec "$CLIENT_NETNS" ip -6 route show 2>&1 || true
  fi
  echo "== route table =="
  ip route show 2>&1 || true
  ip -6 route show 2>&1 || true
}

cleanup() {
  # Matches "$BIN --uplink-iface", not just "$BIN": $BIN's basename
  # ("beep-wg2node") is a literal prefix of this script's own filename
  # ("beep-wg2node-remote.sh"), so a bare `pkill -f "$BIN"` self-SIGTERMs
  # the running cleanup script (invoked as `bash /tmp/beep-wg2node-remote.sh
  # cleanup`) before it reaches the rest of these teardown steps -- same
  # fix as smoke-eth-ingress-2node-remote.sh's cleanup().
  pkill -f "$BIN --uplink-iface" 2>/dev/null || true
  pkill -f "nc -[46] -v -l -N" 2>/dev/null || true
  rm -rf "$PIN_DIR"
  rm -f /tmp/wg2node-response*.http /tmp/wg2node-backend*.log "$LOADER_LOG"
  ip link del "$GENEVE_IFACE" 2>/dev/null || true
  ip link del "$WG_IFACE" 2>/dev/null || true
  ip link del "$IPTNL_IFACE" 2>/dev/null || true
  ip link del "$IP6TNL_IFACE" 2>/dev/null || true
  ip link del "$CLIENT_VETH" 2>/dev/null || true
  # The netns's own tunnel/veth-peer devices ($IPTNL_IFACE_PEER,
  # $IP6TNL_IFACE_PEER, $CLIENT_VETH_PEER) all die with the netns itself --
  # no separate delete needed.
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
  setup-client-tunnels) setup_client_tunnels "$@" ;;
  start-loader) start_loader "$@" ;;
  start-backend-responder) start_backend_responder "$@" ;;
  dump-node-allow-key) dump_node_allow_key ;;
  seed-node-allow) seed_node_allow "$@" ;;
  wg-packet-count) wg_packet_count ;;
  dump-evidence) dump_evidence ;;
  cleanup) cleanup ;;
  *)
    echo "usage: $0 {setup-wg|pubkey|setup-geneve|setup-backend|setup-client-netns|setup-client-tunnels|start-loader|start-backend-responder|dump-node-allow-key|seed-node-allow|wg-packet-count|dump-evidence|cleanup} [args...]" >&2
    exit 1
    ;;
esac
