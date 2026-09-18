# beep does not assume the Geneve underlay L2 is trustworthy

**Status:** Accepted
**Date:** 2026-09-18

## Context

`geneve0` is address-less, which forces `net.ipv4.conf.all.rp_filter=0`
node-wide (`docs/decisions/geneve-rp-filter-disable.md`), and UDP 6081 is
open on the physical NIC: any host reaching `<node>:6081` can inject a
forged Geneve packet. `rp_filter` is a routing-consistency check, not an
identity check, and never stopped same-L2 source spoofing — `rp_filter=0`
removed no protection that would have caught this.

`NODE_ALLOW` (beep-bwh, PR #98) drops (`TC_ACT_SHOT`) any packet whose
outer Geneve tunnel source is not a known peer node, ANDed before the
existing pod-admission checks. Key property: a pure drop-on-miss
tightening that only shrinks the accepted packet set, never expands it —
it opens no new hole. It fully blocks non-peer, off-L2, or routed
attackers, who cannot easily spoof a peer's IP across a routed boundary.
Against a same-L2 adversary that can spoof a peer's IP, it is only a
speed bump: the forged outer source passes the IP check, but tunnel
responses return to the real peer (blind injection). The residual
exposure is forged-inner-client-IP injection to backends (log poisoning,
IP-ACL bypass, segmentation bypass).

beep cannot close this alone: `rp_filter`, an IP/MAC host firewall, and
IP-based `NODE_ALLOW` are all IP-based, and same-L2 IP spoofing defeats
all of them equally. The only real closers are switch-enforced L2
anti-spoof (IP Source Guard, Dynamic ARP Inspection, port security —
network infrastructure, not beep) or a cryptographic underlay that
authenticates the peer by key (WireGuard/IPsec). Under a cryptographic
underlay, `NODE_ALLOW` becomes pure defense-in-depth.

## Decision

beep does not assume the Geneve underlay L2 is trustworthy, and retains
`NODE_ALLOW` as a partial compensating control, not a complete fix. When
the local L2 is not known trustworthy, operators SHOULD run beep's
Geneve transport over a WireGuard (or equivalent cryptographic) underlay;
beep already demonstrates the WireGuard cross-node path.

## Rationale

Fixing this at beep's layer means re-implementing L2 port security or a
peer-authenticated transport inside eBPF — out of scope, and worse than
the tools already built for it. Recording the assumption, instead of
silently relying on it, lets an operator choose.

## Consequences

- Deployments on an untrusted or unknown L2 without WireGuard carry a real,
  accepted residual: forged-inner-client-IP injection from a same-L2 host.
- Otherwise, operators must document that the deployment relies on L2
  trust (VLAN isolation, switch anti-spoof).
- Related, not decided here: the `NODE_ALLOW` startup blackout tradeoff
  (`docs/decisions/node-allow-startup-blackout.md`, beep-joe) and
  multi-IP-per-node `NODE_ALLOW` (beep-eix).
