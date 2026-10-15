#!/usr/bin/env bash
# Unit test for count0_wire_replies in scripts/smoke-remote.sh: the count-0
# silent-drop wire check must stay strict (RST, SYN-ACK, unreachable from a
# count-0 port fail) without flaking on traffic that cannot answer the probe.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# smoke-remote.sh runs the fixture on source; lift just the function.
eval "$(sed -n '/^count0_wire_replies() {/,/^}/p' "$SCRIPT_DIR/smoke-remote.sh")"
declare -F count0_wire_replies >/dev/null || { echo "FAIL: count0_wire_replies not found in smoke-remote.sh" >&2; exit 1; }

fail=0
expect() { # <name> <want: empty|nonempty> <capture-text>
  printf '%s\n' "$3" >"$TMP/cap"
  local got
  got=$(count0_wire_replies "$TMP/cap")
  if { [ "$2" = empty ] && [ -z "$got" ]; } || { [ "$2" = nonempty ] && [ -n "$got" ]; }; then
    echo "PASS: $1"
  else
    echo "FAIL: $1 (want $2, got '$got')" >&2
    fail=1
  fi
}

SYN='    203.0.113.2.35100 > 203.0.113.1.19300: Flags [S], cksum 0x7833, seq 616866696, win 64240, length 0'

expect "router solicitation on interface bring-up is not an answer" empty \
  "06:11:49 IP6 (hlim 255, next-header ICMPv6 (58) payload length: 16) fe80::dc04:eaff:feff:f29 > ff02::2: ICMP6, router solicitation, length 16
${SYN}"

expect "neighbor solicitation, router advertisement and MLD are not answers" empty \
  "IP6 fe80::1 > ff02::1:ff00:2: ICMP6, neighbor solicitation, who has 2001:db8:5::2, length 32
IP6 fe80::1 > ff02::1: ICMP6, router advertisement, length 56
IP6 fe80::1 > ff02::16: HBH ICMP6, multicast listener report v2, 1 group record(s), length 28"

expect "control-port SYN-ACK whose timestamp digits contain 19301 is not a count-0 answer" empty \
  "    203.0.113.1.19304 > 203.0.113.2.48264: Flags [S.], cksum 0x7833, seq 3696135785, ack 611876875, options [TS val 279619301 ecr 1806778904], length 0"

expect "a RST from a count-0 port is an answer" nonempty \
  "    203.0.113.1.19300 > 203.0.113.2.35100: Flags [R.], cksum 0x1, seq 0, ack 616866697, win 0, length 0"

expect "a SYN-ACK from a count-0 port is an answer" nonempty \
  "    2001:db8:5::1.19302 > 2001:db8:5::2.47302: Flags [S.], cksum 0x1, seq 1, ack 176404568, win 65160, length 0"

expect "an ICMP port unreachable is an answer" nonempty \
  "IP 203.0.113.1 > 203.0.113.2: ICMP 203.0.113.1 udp port 19301 unreachable, length 41"

expect "an ICMPv6 unreachable is an answer" nonempty \
  "IP6 2001:db8:5::1 > 2001:db8:5::2: ICMP6, destination unreachable, unreachable port, 2001:db8:5::1 udp port 19303, length 69"

exit "$fail"
