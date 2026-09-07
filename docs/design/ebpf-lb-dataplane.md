---
as_of: 2026-09-07
kind: initiative-state
---

# u7s eBPF LB dataplane — mechanism

Phase-1 datapath mechanism for the ServiceLB dataplane (`bd show
mayor-2et9d`, supersedes `mayor-fhfro`/`mayor-mma08`); implements
`docs/decisions/servicelb-ebpf-geneve-dataplane.md` (this dataplane IS the
ServiceLB), `servicelb-symmetric-geneve-return.md` (symmetric, not DSR),
and `ebpf-toolchain-aya.md` (`aya`). Service-level semantics from `bd show
mayor-0gpqp` (front-IP model, `externalTrafficPolicy`, IPv6/dual-stack,
node-selector scoping) carry over unchanged.

Must work across four underlay scenarios, none assumed: WireGuard/
Tailscale mesh; disjoint subnets; a node behind NAT; all colocated, no
encapsulation. The operator's fleet exercises the first three at once;
sizing below is one instance.

## Hooks

Four attachment points, all tc-bpf (clsact), none XDP:

| Hook | Where |
|---|---|
| Ingress classifier | Physical uplink, every node (forward leg) |
| Ingress classifier on `geneve0` | Backend node (forward leg, decap) |
| Egress classifier | Physical uplink, backend node (return leg) |
| Ingress classifier on `geneve0` | Ingress node (return leg, decap) |

**Why tc-bpf, not XDP.** The ingress classifier needs skb context for
`bpf_skb_set_tunnel_key` (no XDP equivalent); XDP also has no egress
hook for backend capture, and is unreliable over WireGuard (no
guaranteed tunnel-device driver support; generic-XDP loses tc-bpf's
only edge).

**Hook topology (settled, `bd show mayor-bguco`):** a future L7 TPROXY
return leg gets its own hook, sharing existing programs and maps, not a
merged one. Node-local traffic (a same-node proxy dialing the node's own
front IP) never crosses the uplink qdisc; it needs its own, kernel-forced
`lo` attach point. Separate hooks are also cheaper — each tc program
runs only on its own device's traffic, and maps stay shared by name
regardless of hook count. Deferred until the L7 tier is scoped
(`mayor-s82zr`).

## Packet flow

**Forward:** (1) Client → `NODE_IP:SVC_PORT` — an address the receiving
node owns (its primary IP, or a prefix statically routed to it), dialed
directly; no floating IP, no ARP/BGP announcement (servicelb ADR). DNS
publishes each node's own address and every node accepts the service
port, so the packet lands on whichever node the client dialed — the
"ingress node." `NODE_IP:SVC_PORT` **is the LB front IP**: node-owned,
not necessarily virtual, never assumed to sit behind a cloud LB. (2)
Ingress hashes to a ready backend, writes a flow-affinity entry keyed on
the forward tuple `(CLIENT_IP, SRC_PORT, FRONT_IP, FRONT_PORT, proto)`,
and (3) stamps Geneve metadata (remote = backend node, fixed VNI, a
pod-identifier option), redirects to `geneve0`; inner packet untouched.
(4) Backend decaps, reads `FRONT_IP:FRONT_PORT` off the still-untouched
inner dst *before* rewriting anything, writes a reverse-flow entry
storing that front IP plus the ingress node's address, rewrites dst to
`PodIP:TargetPort` (`src` unchanged), forwards via flannel's routing to
the veth. **Pod sees the real client IP at L3.**

**Return:** (5) Pod replies ordinarily. (6) Backend's egress classifier
looks up the reverse-flow entry (same pair, read in reverse — nothing
rewrote either side here), stamps Geneve metadata back to the ingress
node **echoing the stored `FRONT_IP:FRONT_PORT`**, redirects to
`geneve0`. (7) Ingress decaps, reads `CLIENT_IP:SRC_PORT` off the inner
dst and `FRONT_IP:FRONT_PORT` off the echo, looks up its step-2 entry,
rewrites `src` to the recovered front IP, routes.

## Conntrack & affinity

**The key must include the front IP, not just the client.** A
client-only `(CLIENT_IP, SRC_PORT, proto)` key collides when a client
holds two connections to different front IPs from the same local port.
The forward tuple `(CLIENT_IP, SRC_PORT, FRONT_IP, FRONT_PORT, proto)`
fixes this — trivial at step 2, but step 7 only sees `PodIP:TargetPort`
(DNAT overwrote the front IP), so the backend captures
`FRONT_IP:FRONT_PORT` before DNATing and echoes it on return, letting
the ingress rebuild the same key. **Still one map, just a wider key.**

The backend's reverse-flow key, `(CLIENT_IP, SRC_PORT, PodIP, TargetPort,
proto)`, is rewrite-stable but says nothing about cross-flow uniqueness
(see Settled wire-format decisions). Both keys share one shape, so **one
map per protocol** covers both roles: front-IP space and pod-CIDR are
disjoint by construction, so the two kinds never collide.

`BPF_MAP_TYPE_LRU_PERCPU_HASH`, custom (`nf_conntrack` is heavier).
Per-CPU cost is bounded by vCPU count, nearly free at 1 vCPU/1GB.

- **TCP/UDP/QUIC share one key shape**: `(CLIENT_IP, SRC_PORT, OTHER_IP,
  OTHER_PORT, proto)` (`OTHER`=front IP or PodIP). IPv6-primary: **37
  bytes**. QUIC keys the same way — **4-tuple pass-through for the MVP,
  not a minted CID** (`bd show mayor-g3lag`, closed): the CID is
  server/backend-chosen (RFC 9000 §7.2), unmintable/unobservable by a
  non-terminating dataplane; CID-based keying is deferred, needing
  u7s-owned server_id distribution (`bd show mayor-xjy5o`). No longer
  exempt from the remap remedy below.
- **Admission + affinity** (`docs/decisions/servicelb-flow-admission-affinity.md`,
  `bd show mayor-aie31.11`/`mayor-aie31.21`): the forward map splits into
  `FWD_PENDING` (new) and `FWD_MAIN` (promoted on the observed return
  leg); sizes DaemonSet-configurable at load, never hard-coded.
  `FWD_FLOW`'s value pins the full backend identity
  (`backend_node_ip`+`pod_ip`); eviction fires only on endpoint removal
  (`FWD_FLOW` mandatory for UDP, `REV_FLOW` both protocols).
- **Cross-node drift invariant** (`bd show mayor-tavxy`): per-node
  controllers can lag on the same EndpointSlice event, so state diverges
  for seconds. The **delivery node**, not ingress, must be authoritative:
  inbound Geneve-decap validates the stamped `pod_ip` against its local
  serving-set before delivering — bounding drift to a drop, never a
  misdelivery.

| Component | Estimate (1 vCPU) | Basis |
|---|---|---|
| Userspace control-plane process | 3–5 MiB RSS | Rust async binary; idle after reconcile. |
| eBPF programs, all tc-bpf (4 points) | ~0 MiB (kernel-resident) | JIT'd, 5–50 KiB each. |
| Front-IP map (<100 Services × ≤2 protocols) | ~25 KiB | <200 entries. |
| Endpoint map (<1000 endpoints) | ~128 KiB | Full map on every node. |
| Flow-affinity maps, per-CPU (two-tier, TCP/UDP + QUIC) | ~1–2 MiB | Ceilings/sizing: `servicelb-flow-admission-affinity.md`. |
| `vni_to_pod` (backend, local) | <5 KiB | <20 entries. |
| **Total** | **~4–7 MiB** | Scales linearly with vCPU count. |

All maps pre-allocate their full ceiling — loxilb's "cannot start on 1GB
node" failure mode (gate 2) — sized for u7s's envelope (<10 nodes/<100
Services/<1000 endpoints).

## Userspace control plane

Runs per node, not centrally (eBPF maps are local kernel memory). One
DaemonSet per node, `hostNetwork`/`CAP_BPF`/`CAP_NET_ADMIN`, no CRI
socket: loads tc-bpf programs once, watches `Service`/`EndpointSlice`,
writes maps on change, idle. Pinned under `/sys/fs/bpf` so restarts keep
flow state.

## Prototype gates — go/no-go before Phase 3

1. **Return path works cross-node on real disjoint subnets** — Lima
   alone can't validate a Geneve round trip.
2. **Measured RSS on a real 1GB/1vCPU node**, not the ~4–7 MiB estimate
   (pre-allocation can hide a floor until run, per loxilb).
3. **Userspace RSS and kernel eBPF-map memory independently and
   continuously monitorable** (`ebpf-toolchain-aya.md`), not assumed
   stable.

## Settled wire-format decisions (mayor-gjbov, 2026-09-03)

- **Geneve option encoding**: raw pod IP for the pod identifier; raw
  `FRONT_IP:FRONT_PORT` for the front-IP echo. Compact alternatives cost
  a map-ordering/id-collision surface for little savings — the echo is
  load-bearing (see Conntrack), not cosmetic.
- **Front-IP↔PodIP NAT placement**: DNAT on the backend (step 4),
  un-DNAT on the ingress (step 7), reusing the step-2 write. Gates
  Phase 2 (mayor-g7jh2).
- **Backend reverse-flow key uniqueness**: keep the full 5-tuple key; on
  a cross-Service collision (shared Pod:targetPort, reused client source
  port), remap the backend's source port, un-remapping on return —
  closes UDP. QUIC is **not** exempt (see Conntrack).

## References

`bd show mayor-0gpqp`/`mayor-fhfro`/`mayor-mma08`; `cni-svclb-landscape.md`;
`docs/decisions/flannel-for-cni.md`; `kubernetes-retired/blixt`; RFC 9000;
`draft-ietf-quic-load-balancers-21`; `crates/scheduler`/`kubeconfig`.
