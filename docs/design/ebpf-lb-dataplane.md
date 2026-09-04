---
as_of: 2026-09-03
kind: initiative-state
---

# u7s eBPF LB dataplane — mechanism

Phase-1 datapath mechanism for the ServiceLB dataplane (`bd show
mayor-2et9d`, supersedes `mayor-fhfro`/`mayor-mma08`); implements
`docs/decisions/servicelb-ebpf-geneve-dataplane.md` (this dataplane IS the
ServiceLB), `servicelb-symmetric-geneve-return.md` (symmetric, not DSR),
and `ebpf-toolchain-aya.md` (`aya`). Service-level semantics from `bd show
mayor-0gpqp` (VIP model, `externalTrafficPolicy`, IPv6/dual-stack,
node-selector scoping) carry over unchanged.

Must work across four underlay scenarios, none assumed: WireGuard/
Tailscale mesh; disjoint subnets; a node behind NAT; all colocated, no
encapsulation. The operator's fleet exercises the first three at once —
sizing below, one instance, not the assumed layout.

## Hooks

Four attachment points, all tc-bpf (clsact), none XDP:

| Hook | Where |
|---|---|
| Ingress classifier | Physical uplink, every node (forward leg) |
| Ingress classifier on `geneve0` | Backend node (forward leg, decap) |
| Egress classifier | Physical uplink, backend node (return leg) |
| Ingress classifier on `geneve0` | Ingress node (return leg, decap) |

**Why tc-bpf, not XDP.** The ingress classifier needs skb context for
`bpf_skb_set_tunnel_key` (no XDP equivalent), and XDP has no egress hook
for the backend capture. XDP over WireGuard is also unreliable — no
guaranteed tunnel-device driver support, and generic-XDP (SKB mode) gives
up XDP's only edge over tc-bpf, which attaches identically on any device.

**Hook topology** (design note, not a commitment to build L7 TPROXY; `bd
show mayor-bguco`): node-local traffic (e.g. a same-node proxy dialing the
node's own IP/VIP) never crosses the physical-uplink tc ingress qdisc
above, so a future TPROXY return leg needs its own hook. One hook for both
roles vs. separate ones is a kernel memory/processing tradeoff, decided
when that leg exists.

## Packet flow

**Forward:** (1) Client → `NODE_IP:SVC_PORT` — an address the receiving
node owns (its primary IP, or a prefix statically routed to it), dialed
directly; no floating VIP, no ARP/BGP announcement (servicelb ADR). DNS
publishes each node's own address and every node accepts the service
port, so the packet lands on whichever node the client dialed — that node
is the "ingress node," not a fixed VIP owner. `NODE_IP:SVC_PORT` plays the
role written `VIP:PORT` below (kept for continuity; it's node-owned, not
a virtual IP). (2) Ingress hashes to a ready backend, writes a
flow-affinity entry keyed on the forward tuple `(CLIENT_IP, SRC_PORT,
VIP_IP, VIP_PORT, proto)`, and (3) stamps Geneve metadata (remote =
backend node, fixed VNI, a pod-identifier option), redirects to
`geneve0`; inner packet untouched. (4) Backend decaps, reads
`VIP_IP:VIP_PORT` off the still-untouched inner dst *before* rewriting
anything, writes a reverse-flow entry storing that VIP plus the ingress
node's address, rewrites dst to `PodIP:TargetPort` (`src` unchanged),
forwards via flannel's routing to the veth. **Pod sees the real client
IP at L3.**

**Return:** (5) Pod replies ordinarily. (6) Backend's egress classifier
looks up the reverse-flow entry (same pair, read in reverse — nothing
rewrote either side here), stamps Geneve metadata back to the ingress
node **echoing the stored `VIP_IP:VIP_PORT`**, redirects to `geneve0`. (7)
Ingress decaps, reads `CLIENT_IP:SRC_PORT` off the inner dst and
`VIP_IP:VIP_PORT` off the echo, looks up its step-2 entry, rewrites `src`
to the recovered VIP, routes.

## Conntrack & affinity

**The key must include the VIP, not just the client.** A client-only
`(CLIENT_IP, SRC_PORT, proto)` key collides: a client can hold two
concurrent connections from the same local port to different VIPs, and if
both resolve to the same ingress node, their entries collide. The forward
tuple `(CLIENT_IP, SRC_PORT, VIP_IP, VIP_PORT, proto)` fixes this —
trivial at step 2, but step 7 only sees `PodIP:TargetPort` (the backend's
DNAT overwrote the VIP). Fix: the backend captures `VIP_IP:VIP_PORT`
before DNATing and echoes it on return, so the ingress rebuilds the same
key. **Still one map, just a wider key.**

The backend's reverse-flow key, `(CLIENT_IP, SRC_PORT, PodIP, TargetPort,
proto)`, is rewrite-stable — neither side changes between write (step 4)
and read (step 6) — but says nothing about cross-flow uniqueness (see
Open questions). Both keys share one shape, so **one map per protocol**
covers both roles: VIP-space and flannel's pod-CIDR are disjoint by
construction, so the two kinds never collide.

`BPF_MAP_TYPE_LRU_PERCPU_HASH`, custom (`nf_conntrack` is heavier). Per-CPU
cost is bounded by vCPU count, nearly free at 1 vCPU/1GB.

- **TCP**: key = `(CLIENT_IP, SRC_PORT, OTHER_IP, OTHER_PORT, proto)`
  (`OTHER`=VIP or PodIP, by role). IPv6-primary: **37 bytes** (16+16+2+2+1)
  — not 13 (IPv4-only) nor 19 (the client-only key that collided above).
  Value ~34 bytes. 8192-entry ceiling.
- **QUIC**: key = a fixed-length Destination Connection ID prefix, minted
  by the LB (RFC 9000 §17.2's self-describing Initial-packet DCID) — no
  TCP-style collision risk, since it's not derived from the client's
  address. Fixed-length, not variable: the 1-RTT short header (§17.3.1)
  has no length field, so matching needs one externally-agreed CID
  length. CID-based vs. 4-tuple/pass-through is a design decision
  informed by how L7 proxies (Traefik, nginx, Envoy, HAProxy) handle QUIC
  CIDs — learn-from candidates, not gates (`bd show mayor-g3lag`);
  4-tuple/pass-through is an acceptable fallback (degraded migration
  affinity) if none cooperates. `draft-ietf-quic-load-balancers-21`'s
  richer per-hop scheme is worth adopting only past a single ingress
  point (chained LBs); this fixed-length prefix suffices for one hop.
  4096-entry ceiling.

| Component | Estimate (1 vCPU) | Basis |
|---|---|---|
| Userspace control-plane process | 3–5 MiB RSS | Rust async binary; idle after reconcile. |
| eBPF programs, all tc-bpf (4 points) | ~0 MiB (kernel-resident) | JIT'd, 5–50 KiB each. |
| VIP map (<100 Services × ≤2 protocols) | ~25 KiB | <200 entries. |
| Endpoint map (<1000 endpoints) | ~128 KiB | Full map on every node. |
| TCP flow-affinity, per-CPU | ~0.5–1 MiB | 8192 × ~90 B (37 B key, ~34 B value, ~20 B overhead). |
| QUIC CID map, per-CPU | ~0.25–0.5 MiB | 4096 entries, same model. |
| `vni_to_pod` (backend, local) | <5 KiB | <20 entries. |
| **Total** | **~4–7 MiB** | Scales linearly with vCPU count. |

All maps pre-allocate their full ceiling — loxilb's "cannot start on 1GB
node" failure mode (gate 2) — sized small for u7s's envelope (<10
nodes/<100 Services/<1000 endpoints).

## Userspace control plane

Runs per node, not centrally (eBPF maps are local kernel memory). One
DaemonSet per node, `hostNetwork`/`CAP_BPF`/`CAP_NET_ADMIN`, no CRI
socket: load tc-bpf programs once, watch `Service`/`EndpointSlice`, write
maps on change, idle. Pinned under `/sys/fs/bpf` so restarts keep flow
state.

## Prototype gates — go/no-go before Phase 3

1. **Return path works cross-node on real disjoint subnets** — Lima alone
   can't validate a Geneve round trip; needs a real multi-provider
   topology.
2. **Measured RSS on a real 1GB/1vCPU node**, not the ~4–7 MiB estimate
   (pre-allocation can hide a floor until run, per loxilb).
3. **Userspace RSS and kernel eBPF-map memory independently and
   continuously monitorable** (`ebpf-toolchain-aya.md`), not assumed
   stable.

## Settled wire-format decisions (mayor-gjbov, 2026-09-03)

- **Geneve option encoding**: raw pod IP for the pod identifier; raw
  `VIP_IP:VIP_PORT` for the VIP echo. Compact alternatives save little at
  the cost of a map-ordering or id-collision surface — the echo is
  load-bearing (see Conntrack), not cosmetic.
- **VIP↔PodIP NAT placement**: DNAT on the backend (step 4), un-DNAT on
  the ingress (step 7), reusing the step-2 write. Gates Phase 2
  (mayor-g7jh2).
- **Backend reverse-flow key uniqueness**: keep the full 5-tuple key; on a
  cross-Service collision (shared backend Pod:targetPort, reused client
  source port) remap the backend's source port for that flow, un-remapping
  on return — closes UDP, where TCP's own uniqueness gives partial cover.
  QUIC is exempt: it already keys on a minted DCID (see Conntrack).

## Open questions before the Phase-3 prototype

- **QUIC conntrack keying method**: CID-based vs 4-tuple/pass-through —
  pending the L7-proxy QUIC-CID survey (`bd show mayor-g3lag`); see
  Conntrack & affinity above.

## References

`bd show mayor-0gpqp`/`mayor-fhfro`/`mayor-mma08`; `cni-svclb-landscape.md`;
`docs/decisions/flannel-for-cni.md`; `kubernetes-retired/blixt`; RFC 9000;
`draft-ietf-quic-load-balancers-21`; `crates/scheduler`/`kubeconfig`.
