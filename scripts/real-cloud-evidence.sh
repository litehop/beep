#!/usr/bin/env bash
# Collects the beep (B) evidence from docs/verification/real-cloud.md on ONE node.
# Run as root on each node (e.g. over ssh) around the request under test:
#
#   real-cloud-evidence.sh before <dir>      snapshot into <dir>/before/
#   real-cloud-evidence.sh pcap-start <dir>  background tcpdump -> <dir>/geneve.pcap
#   ... drive the request ...
#   real-cloud-evidence.sh pcap-stop <dir>
#   real-cloud-evidence.sh after <dir>       snapshot into <dir>/after/, write
#                                            <dir>/geneve0-delta.json, exit 1 unless
#                                            geneve0 rx and tx packets both grew
#
# Layout per <dir> (one per checklist item and node): before/ and after/ each hold
# geneve0.json (ip -s -j link show), flow_table.json (bpftool dump), rp_filter.txt,
# kernel.txt; plus geneve0-delta.json and geneve.pcap.
#
# Env: BEEP_PIN_DIR (default /sys/fs/bpf/beep), BEEP_EVIDENCE_PCAP_SECS (pcap
# time bound, default 300). Requires ip, jq, bpftool, sysctl, tcpdump, timeout.
set -euo pipefail

PIN_DIR="${BEEP_PIN_DIR:-/sys/fs/bpf/beep}"
PCAP_SECS="${BEEP_EVIDENCE_PCAP_SECS:-300}"

die() { echo "real-cloud-evidence: $*" >&2; exit 1; }
need() { for t in "$@"; do command -v "$t" >/dev/null 2>&1 || die "required tool missing: $t"; done; }

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ "$#" -eq 2 ] || die "usage: $0 before|after|pcap-start|pcap-stop <dir>"
cmd="$1"
dir="$2"

snapshot() { # snapshot <subdir>
  local out="$dir/$1" iface
  need ip jq bpftool sysctl uname
  ip link show geneve0 >/dev/null 2>&1 || die "geneve0 does not exist (beep not running on this node?)"
  [ -e "$PIN_DIR/FLOW_TABLE" ] || die "$PIN_DIR/FLOW_TABLE is not pinned"
  iface="$(ip -j route show default | jq -er '.[0].dev')" || die "no default-route interface"
  mkdir -p "$out"
  ip -s -j link show geneve0 >"$out/geneve0.json"
  bpftool map dump pinned "$PIN_DIR/FLOW_TABLE" --json >"$out/flow_table.json"
  jq -e . "$out/flow_table.json" >/dev/null || die "FLOW_TABLE dump is not valid JSON"
  sysctl "net.ipv4.conf.all.rp_filter" "net.ipv4.conf.default.rp_filter" \
    "net.ipv4.conf.$iface.rp_filter" >"$out/rp_filter.txt"
  uname -r >"$out/kernel.txt"
}

case "$cmd" in
  before) snapshot before ;;
  after)
    snapshot after
    jq -n --slurpfile b "$dir/before/geneve0.json" --slurpfile a "$dir/after/geneve0.json" '
      ($b[0][0].stats64) as $x | ($a[0][0].stats64) as $y
      | {rx_packets: {before: $x.rx.packets, after: $y.rx.packets, delta: ($y.rx.packets - $x.rx.packets)},
         tx_packets: {before: $x.tx.packets, after: $y.tx.packets, delta: ($y.tx.packets - $x.tx.packets)}}
    ' >"$dir/geneve0-delta.json"
    cat "$dir/geneve0-delta.json"
    jq -e '.rx_packets.delta > 0 and .tx_packets.delta > 0' "$dir/geneve0-delta.json" >/dev/null ||
      die "geneve0 rx and tx packets did not both grow; the request did not traverse Geneve on this node"
    ;;
  pcap-start)
    need tcpdump timeout
    mkdir -p "$dir"
    [ ! -e "$dir/tcpdump.pid" ] || die "$dir/tcpdump.pid exists; pcap already started"
    setsid timeout "$PCAP_SECS" tcpdump -nn -U -i any -w "$dir/geneve.pcap" 'udp port 6081' \
      >"$dir/tcpdump.log" 2>&1 </dev/null &
    echo $! >"$dir/tcpdump.pid"
    sleep 1
    kill -0 "$(cat "$dir/tcpdump.pid")" 2>/dev/null || die "tcpdump exited at start: $(cat "$dir/tcpdump.log")"
    ;;
  pcap-stop)
    [ -f "$dir/tcpdump.pid" ] || die "$dir/tcpdump.pid missing; pcap-start was not run"
    pid="$(cat "$dir/tcpdump.pid")"
    kill -INT "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5; do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    rm -f "$dir/tcpdump.pid"
    [ -s "$dir/geneve.pcap" ] || die "$dir/geneve.pcap is missing or empty"
    ;;
  *) die "unknown subcommand: $cmd" ;;
esac
