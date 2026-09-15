# WG-free cross-node round trip: not actually demonstrated by this rig

Bead: beep-7no

**Answer: the cross-node round trip is live-confirmed GREEN, but it is NOT
WireGuard-free.** `scripts/smoke-eth-ingress-2node.sh`'s own header and its
own final line (`GATE 1 TIER-1 MECHANISM: PASS (eth0-ingress, wg0-transport,
...)`) say this plainly: the rig removes WireGuard only from the
**client-facing ingress** hop, not from the path. WireGuard remains the real
inter-node Geneve transport — the fixture routes the backend leg to
`10.99.0.4`/`10.99.0.2`, the WireGuard tunnel addresses, and node-b's
`start-loader --node-ip` is the WG address, not its real eth0 address. Live
counters below confirm `wg0` actually carried the encapsulated traffic during
the run. The bead's premise ("a WG-free rig already exists... no WireGuard")
is incorrect for this script; no genuinely WG-free 2-node cross-node smoke
rig exists in this repo today (the only other multi-VM rig,
`smoke-wg-2node.sh`, uses WireGuard as ingress, which is strictly more
WireGuard, not less).

## What was run

`bash scripts/smoke-eth-ingress-2node.sh --vm-a beep-node-a --vm-b
beep-node-b --vm-client beep-client`, 2026-09-15 ~06:56Z. Full run went
green end to end:

```
UPLINK-IFACE-NAME: PASS (beep-node-a's user-v2 NIC is eth0)
WIREGUARD TUNNEL: PASS (beep-node-a 10.99.0.2 <-> beep-node-b 10.99.0.4, over real underlay 192.168.104.12/192.168.104.13)
VERIFIER-ACCEPT: PASS (uplink-iface=eth0)   [x2, node-a and node-b]
ROUND-TRIP: PASS (client beep-client -> VIP 192.168.104.12:19100 -> cross-node backend -> response 'OK')
GATE 1 TIER-1 MECHANISM: PASS (eth0-ingress, wg0-transport, symmetric return proven from a genuinely foreign client)
```

The script's own `EXIT` trap tears down `wg0`/`geneve0`/pinned maps
immediately on completion, so to capture the WG-presence evidence the task
asked for, the same rig steps were re-driven manually (same binaries, same
fixture, same `/tmp/beep-ethingress2node-remote.sh` subcommands the host
script uses) and torn down again with the rig's own `cleanup` subcommand
afterward. No repo file was modified to do this.

## WireGuard-in-path evidence (the crux)

`beep-node-a` interfaces during the run — `wg0` present and up, not just
`eth0`:

```
eth0             UP             192.168.104.12/24 ...
wg0              UNKNOWN        10.99.0.2/24
geneve0          UNKNOWN        ...
```

Client round trip (driven from the genuinely separate `beep-client` VM,
which has no `wg0` at all — only `lo`/`eth0`):

```
$ curl -sS -m 20 -w '\nHTTP_CODE:%{http_code}\n' http://192.168.104.12:19100/
OK
HTTP_CODE:200
```

Interface counters immediately after that single request, on both nodes —
`wg0` RX/TX packet counts are non-zero, proving the Geneve-encapsulated
inter-node leg actually transited the WireGuard tunnel, not a bare eth0 path:

```
node-a wg0:      RX 7 packets / 1100 bytes   TX 16 packets / 2804 bytes
node-a geneve0:  RX 6 packets / 387 bytes    TX 15 packets / 1203 bytes
node-b wg0:      RX 4 packets / 692 bytes    TX 7 packets / 1100 bytes
```

`FLOW_TABLE` grew from 0 to 1 element on both node-a and node-b across the
request (conntrack state minted for the client<->VIP and VIP<->backend
tuples), and `bpftool net show` confirms beep's three tc programs
(`uplink_ingress`, `geneve_ingress`, `uplink_egress_return`) attached on
`eth0`/`geneve0` on both nodes — no program is attached to `wg0` itself, but
`wg0` is still the kernel-level route/carrier for the Geneve packets between
the two nodes' `eth0`-attached hooks.

```
node-a: eth0(2) tcx/ingress uplink_ingress ... eth0(2) tcx/egress uplink_egress_return ... geneve0(11) tcx/ingress geneve_ingress ...
node-b: eth0(2) tcx/ingress uplink_ingress ... eth0(2) tcx/egress uplink_egress_return ... geneve0(12) tcx/ingress geneve_ingress ...
```

## Verdict

**PASS** on the mechanism the script actually tests (Ethernet-as-client-ingress,
WireGuard-as-Geneve-transport, symmetric return, from a genuinely foreign
3rd-VM client) — this reconfirms `smoke-eth-ingress-2node.sh` is green today.

**NOT CONFIRMED** on the bead's actual question (a full cross-node round trip
with *zero* WireGuard anywhere in the path). This script cannot answer that
question because it deliberately keeps `wg0` as the inter-node transport
substrate (see its own header, lines 2-35). A true WG-free cross-node smoke
test would need the fixture and both nodes' `--node-ip`/`start-loader`
arguments to use their real `eth0` addresses end to end instead of the
`10.99.0.x` WireGuard subnet — that variant does not exist as a script in
this repo and was out of scope to author here (the bead asked to run the
existing rig, not build a new one). Static analysis remains correct that
beep's *loader* has no WireGuard dependency (`--uplink-iface` is
configurable, defaults `eth0`); what's unconfirmed is a *live* rig that
proves it end to end across two real nodes.

## VM state left behind

`beep-node-a`, `beep-node-b`, `beep-client`: all `Running`, clean (no
`wg0`/`geneve0`, no pinned maps, no loader process) — verified with `ip -br
link` post-cleanup on node-a/node-b. Left running per the shared-VM
assignment; not stopped.
