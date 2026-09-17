# Node-wide rp_filter=0 is required for beep's Geneve-redirect dataplane

**Status:** Accepted
**Date:** 2026-09-17

## Context

beep preserves the client's real source IP across the Geneve tunnel — the
entire point of an eBPF-redirect LB (`docs/design/ebpf-lb-dataplane.md`).
The controller creates `geneve0` as an address-less, external-mode Geneve
device and self-preps the host at startup (PR #75, beep-o1b). An
address-less device can never satisfy the kernel's reverse-path filter for
a decapped packet whose source is the external client: strict mode (1)
checks the *best* return route, loose mode (2) checks *any* route, and
neither exists back out an unaddressed interface. Without disabling
`rp_filter`, every decapped forward packet is dropped by construction —
the root cause of beep-o1b (`ip_route_input_noref` returning `-EXDEV`).

## Decision

The controller sets `net.ipv4.conf.{all,geneve0}.rp_filter=0` on both
`all` and `geneve0`, node-wide, at startup — not just on `geneve0`.

## Rationale

A per-interface-only setting was considered (beep-o1b option B): give
`geneve0` an address/route so it earns rp_filter's loose-mode exception
without touching `all`. Not pursued, for a kernel-documented reason: the
effective rp_filter for an interface is `max(conf.all.rp_filter,
conf.<if>.rp_filter)`, so `all` must already be non-strict regardless of
what `geneve0` is set to; and an address-less external-mode Geneve device
makes the loose-mode route-existence check adversarial to satisfy
reliably in the first place. Setting both is the same tradeoff Cilium and
Katran ship, for the identical reason — they redirect/decap the same way.
Calico avoids it only because it is a routing-based LB with symmetric BGP
returns, not an eBPF-redirect one: a different architecture, not evidence
that beep's setting is wrong for beep's architecture.

## Consequences

- Anti-spoof protection via reverse-path filtering is weakened node-wide
  (`all`), not just on `geneve0` — a real cost, accepted deliberately.
- No manual sysctl step for operators: the shipped DaemonSet delivers LB
  traffic out-of-the-box (PR #75, beep-o1b).
- **Revisit trigger**: if this weakened anti-spoof posture matters for a
  given threat model, the escape hatch is a routing-based/policy-routing
  decap alternative that preserves symmetric RPF at a real datapath
  cost — not a smaller `rp_filter` change.
