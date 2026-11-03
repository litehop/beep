#!/usr/bin/env bash
# Collects the beep (B) evidence from docs/verification/real-cloud.md on ONE node.
# Run as root on each node (e.g. over ssh) around the request under test:
#
#   real-cloud-evidence.sh before <dir>      snapshot into <dir>/before/
#   real-cloud-evidence.sh pcap-start <dir>  background tcpdumps, one pcap per iface:
#                                            geneve.pcap (-i any, udp port 6081) and,
#                                            when WireGuard is present, <wg>.pcap
#                                            (udp port 6081 on the wg iface) and
#                                            <nic>.pcap (ALL udp on the underlay NIC,
#                                            to show only WireGuard crosses it)
#   ... drive the request ...
#   real-cloud-evidence.sh pcap-stop <dir>
#   real-cloud-evidence.sh after <dir>       snapshot into <dir>/after/, write
#                                            <dir>/geneve0-delta.json, exit 1 unless
#                                            geneve0 rx and tx packets both grew
#                                            (only meaningful on nodes the plan names
#                                            as carrying the flow; others legitimately
#                                            exit 1)
#
# Layout per <dir> (one per checklist item and node): before/ and after/ each hold
# geneve0.json (ip -s -j link show), flow_table.json (bpftool dump), rp_filter.txt,
# kernel.txt, and with WireGuard wg-<iface>.txt (wg show, no keys) plus
# wg-<iface>-handshakes.txt and wg-<iface>-transfer.txt; plus geneve0-delta.json
# and the pcaps above.
#
# Env: BEEP_PIN_DIR (default /sys/fs/bpf/beep), BEEP_EVIDENCE_PCAP_SECS (pcap
# time bound, default 300), BEEP_EVIDENCE_WG_IFACE (wg iface; default: first of
# `wg show interfaces`, none if wg is not installed). Requires ip, jq, bpftool,
# sysctl, tcpdump, timeout (and wg for WireGuard evidence).
set -euo pipefail

PIN_DIR="${BEEP_PIN_DIR:-/sys/fs/bpf/beep}"
PCAP_SECS="${BEEP_EVIDENCE_PCAP_SECS:-300}"

die() { echo "real-cloud-evidence: $*" >&2; exit 1; }
need() { for t in "$@"; do command -v "$t" >/dev/null 2>&1 || die "required tool missing: $t"; done; }

default_iface() {
  ip -j route show default | jq -er '.[0].dev // empty' 2>/dev/null ||
    ip -6 -j route show default | jq -er '.[0].dev // empty' 2>/dev/null
}

wg_iface() {
  if [ -n "${BEEP_EVIDENCE_WG_IFACE:-}" ]; then echo "$BEEP_EVIDENCE_WG_IFACE"; return; fi
  command -v wg >/dev/null 2>&1 || return 0
  wg show interfaces | awk '{print $1}'
}

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ "$#" -eq 2 ] || die "usage: $0 before|after|pcap-start|pcap-stop <dir>"
cmd="$1"
dir="$2"

snapshot() { # snapshot <subdir>
  local out="$dir/$1" iface wg
  need ip jq bpftool sysctl uname
  ip link show geneve0 >/dev/null 2>&1 || die "geneve0 does not exist (beep not running on this node?)"
  [ -e "$PIN_DIR/FLOW_TABLE" ] || die "$PIN_DIR/FLOW_TABLE is not pinned"
  iface="$(default_iface)" || die "no default-route interface (v4 or v6)"
  mkdir -p "$out"
  wg="$(wg_iface)"
  if [ -n "$wg" ]; then
    wg show "$wg" >"$out/wg-$wg.txt"
    wg show "$wg" latest-handshakes >"$out/wg-$wg-handshakes.txt"
    wg show "$wg" transfer >"$out/wg-$wg-transfer.txt"
  fi
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
    if [ -e "$dir/tcpdump.pid" ]; then
      while read -r p; do
        ! kill -0 "$p" 2>/dev/null || die "$dir/tcpdump.pid lists live pid $p; pcap already started"
      done <"$dir/tcpdump.pid"
      rm -f "$dir/tcpdump.pid"
    fi
    capture() { # capture <iface> <pcap> <filter>
      setsid timeout "$PCAP_SECS" tcpdump -nn -U -i "$1" -w "$dir/$2" "$3" \
        >"$dir/tcpdump-$2.log" 2>&1 </dev/null &
      echo $! >>"$dir/tcpdump.pid"
      echo "$2" >>"$dir/pcaps.txt"
    }
    : >"$dir/pcaps.txt"
    capture any geneve.pcap 'udp port 6081'
    wg="$(wg_iface)"
    if [ -n "$wg" ]; then
      nic="$(default_iface)" || die "no default-route interface (v4 or v6)"
      capture "$wg" "$wg.pcap" 'udp port 6081'
      capture "$nic" "$nic.pcap" 'udp'
    fi
    sleep 1
    while read -r p; do
      kill -0 "$p" 2>/dev/null || die "tcpdump exited at start: $(cat "$dir"/tcpdump-*.log)"
    done <"$dir/tcpdump.pid"
    ;;
  pcap-stop)
    [ -f "$dir/tcpdump.pid" ] || die "$dir/tcpdump.pid missing; pcap-start was not run"
    while read -r pid; do kill -INT "$pid" 2>/dev/null || true; done <"$dir/tcpdump.pid"
    for _ in 1 2 3 4 5; do
      alive=0
      while read -r pid; do ! kill -0 "$pid" 2>/dev/null || alive=1; done <"$dir/tcpdump.pid"
      [ "$alive" -eq 1 ] || break
      sleep 1
    done
    rm -f "$dir/tcpdump.pid"
    while read -r f; do
      [ -e "$dir/$f" ] || die "$dir/$f is missing"
    done <"$dir/pcaps.txt"
    [ -s "$dir/geneve.pcap" ] || die "$dir/geneve.pcap is missing or empty"
    ;;
  *) die "unknown subcommand: $cmd" ;;
esac
