---
as_of: 2026-09-03
kind: initiative-state
---

# u7s eBPF LB dataplane — mechanism

Phase-1 datapath mechanism for the ServiceLB dataplane (`bd show
mayor-2et9d`, supersedes `mayor-fhfro`/`mayor-mma08`); implements
`docs/decisions/servicelb-ebpf-geneve-dataplane.md` (this dataplane IS the
ServiceLB), `servicelb-symmetric-geneve-return.md` (symmetric, not DSR),
and `ebpf-toolchain-aya.md` (`aya`), not re-argued here. Service-level
semantics from `bd show mayor-0gpqp` (VIP model, `externalTrafficPolicy`,
IPv6/dual-stack, node-selector scoping) carry over unchanged.

Must work across four underlay scenarios, none assumed: a WireGuard/
Tailscale mesh; disjoint subnets; a node behind NAT; all nodes colocated
with no encapsulation. The operator's fleet exercises the first three at
once, used below for sizing — one instance, not the assumed layout.

## Hooks

Four attachment points, all tc-bpf (clsact), none XDP — mechanism in
Packet flow below:

| Hook | Where |
|---|---|
| Ingress classifier | Physical uplink, every node (forward leg) |
| Ingress classifier on `geneve0` | Backend node (forward leg, decap) |
| Egress classifier | Physical uplink, backend node (return leg) |
| Ingress classifier on `geneve0` | Ingress node (return leg, decap) |

**Why tc-bpf, not XDP.** The ingress classifier needs skb context for
`bpf_skb_set_tunnel_key` (no XDP equivalent); XDP also has no egress hook
for the backend capture. **Does XDP work over WireGuard?** Not reliably —
no guaranteed driver support for a tunnel device over a WireGuard
interface, and generic-XDP (SKB mode) gives up XDP's only edge over
tc-bpf. tc-bpf's clsact qdisc attaches identically on any device.

## Packet flow

**Forward:** (1) Client → `NODE_IP:SVC_PORT` — an address the receiving
node owns (its primary IP, or a prefix statically routed to it), dialed
directly. There is no floating VIP and no ARP/BGP announcement (servicelb
ADR): DNS publishes the nodes' own addresses and every node accepts the
service port, so the packet lands on whichever node the client dialed, and
that node is the "ingress node" — not a fixed VIP owner. The dialed
`NODE_IP:SVC_PORT` is the flow's "front address," and plays the role
written `VIP:PORT` in the rest of this doc (kept for continuity, though in
this model it is a node-owned address, not a virtual IP). (2) Ingress hashes to a ready backend,
writes a flow-affinity entry keyed on the forward tuple `(CLIENT_IP,
SRC_PORT, VIP_IP, VIP_PORT, proto)`, and (3) stamps Geneve metadata
(remote = backend node, fixed VNI, a pod-identifier option), redirects to
`geneve0`; inner packet untouched. (4) Backend decaps, reads
`VIP_IP:VIP_PORT` off the still-untouched inner dst *before* rewriting
anything, writes a reverse-flow entry storing that VIP plus the ingress
node's address, rewrites dst to `PodIP:TargetPort` (`src` unchanged),
forwards via flannel's routing to the veth. **The Pod sees the real
client IP at L3.**

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
concurrent connections from the same local port to two different VIPs
(demux uses the full remote address, not just the port), and if both
resolve to the same ingress node, their entries collide. The key must be
the forward tuple `(CLIENT_IP, SRC_PORT, VIP_IP, VIP_PORT, proto)` —
trivial at step 2, but step 7 can't read it back the same way: the
returning packet only carries `PodIP:TargetPort`, the backend's DNAT
having overwritten the VIP. Fix: the backend captures `VIP_IP:VIP_PORT`
before DNATing, echoes it back on the return leg, and the ingress rebuilds
the key it wrote. **Still one map, just a wider key.**

The backend's reverse-flow key, `(CLIENT_IP, SRC_PORT, PodIP, TargetPort,
proto)`, is rewrite-stable — nothing rewrites either side between write
(step 4) and read (step 6) — but that says nothing about cross-flow
uniqueness (see Open questions). Both keys share one shape and fit in
**one map per protocol** for both roles: VIP-space and flannel's pod-CIDR
are disjoint by construction, so the two entry kinds never collide.

`BPF_MAP_TYPE_LRU_PERCPU_HASH`, custom (`nf_conntrack` is heavier). Per-CPU
cost is bounded by vCPU count — target hardware is 1 vCPU/1GB, nearly free.

- **TCP**: key = `(CLIENT_IP, SRC_PORT, OTHER_IP, OTHER_PORT, proto)`
  (`OTHER`=VIP or PodIP, by role). IPv6-primary: **37 bytes** (16+16+2+2+1)
  — not 13 (IPv4-only) nor 19 (the client-only key that collided above).
  Value ~34 bytes. 8192-entry ceiling.
- **QUIC**: key = a fixed-length Destination Connection ID prefix, minted
  by the LB (RFC 9000 §17.2's self-describing Initial-packet DCID) — not
  derived from the client's address, so no TCP-style collision risk. The
  1-RTT short header (§17.3.1) has no length field, so matching needs one
  fixed CID length (Traefik support — open question); simpler than the
  IETF draft's scheme, worth adopting only past a single ingress point.
  4096-entry ceiling.

| Component | Estimate | Basis |
|---|---|---|
| Userspace control-plane process | 3–5 MiB RSS | Rust async binary, `u7s_kubeconfig` watch machinery; idle after reconcile. |
| eBPF programs, all tc-bpf (4 points) | ~0 MiB (kernel-resident) | JIT'd, 5–50 KiB each. |
| VIP map (<100 Services × ≤2 protocols) | ~25 KiB | <200 entries. |
| Endpoint map (<1000 endpoints) | ~128 KiB | Every node carries the full map. |
| TCP flow-affinity, per-CPU | ~0.5–1 MiB at 1 vCPU | 8192 × ~90 B (37 B key + ~34 B value + ~20 B overhead). |
| QUIC CID map, per-CPU | ~0.25–0.5 MiB at 1 vCPU | 4096 entries, same model. |
| `vni_to_pod` (backend, local) | <5 KiB | <20 entries. |
| **Total** | **~4–7 MiB at 1 vCPU** | Close to the pre-narrowing estimate; scales linearly with vCPU count. |

All maps pre-allocate their full ceiling at creation — loxilb's "cannot
start on 1GB node" failure mode (gate 2). Ceilings are sized small for
u7s's envelope (<10 nodes/<100 Services/<1000 endpoints).

## Userspace control plane

Runs per node, not centrally (eBPF maps are local kernel memory, no
remote-write API). One DaemonSet per node, `hostNetwork` +
`CAP_BPF`/`CAP_NET_ADMIN`, no CRI socket: load tc-bpf programs once, watch
`Service`/`EndpointSlice` via existing watch code, write maps on change,
idle. Pinned under `/sys/fs/bpf` so a restart keeps flow state.

## Prototype gates — go/no-go before Phase 3

1. **Return path works cross-node on real disjoint subnets** — a pure
   Geneve round trip; Lima alone can't validate it, needs a real
   multi-provider topology.
2. **Measured RSS footprint on a real 1GB/1vCPU node**, not the ~4–7 MiB
   estimate (pre-allocation can hide a floor until run, per loxilb).
3. **Userspace RSS and kernel eBPF-map memory independently and
   continuously monitorable** (`ebpf-toolchain-aya.md`), not assumed
   stable.

## Settled wire-format decisions (mayor-gjbov, 2026-09-03)

- **Geneve option encoding**: raw pod IP for the pod identifier; raw
  `VIP_IP:VIP_PORT` for the VIP echo. Compact alternatives save
  noise-level bytes at the cost of a map-ordering or id-collision surface.
  The echo is load-bearing (see Conntrack), not cosmetic.
- **VIP↔PodIP NAT placement**: DNAT on the backend (step 4), un-DNAT on
  the ingress (step 7), reusing the step-2 write. Gates Phase 2
  (mayor-g7jh2).
- **Backend reverse-flow key uniqueness**: keep the full 5-tuple key; on a
  cross-Service collision (shared backend Pod:targetPort, reused client
  source port) remap the backend's own source port for that flow only,
  un-remapping on return — protocol-agnostic, closing UDP where TCP's
  kernel-enforced uniqueness gives partial cover. QUIC is exempt: it
  already keys on a minted DCID (see Conntrack).

## Open questions before the Phase-3 prototype

- **Traefik fixed-length QUIC CID support**: hard precondition for the
  CID design above, not yet verified (`bd show mayor-g3lag`).

## References

`bd show mayor-0gpqp`/`mayor-fhfro`/`mayor-mma08`; `cni-svclb-landscape.md`;
`docs/decisions/flannel-for-cni.md`; `kubernetes-retired/blixt`; RFC 9000;
`draft-ietf-quic-load-balancers-21`; `crates/scheduler`/`kubeconfig`.
