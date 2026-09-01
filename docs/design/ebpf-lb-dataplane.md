---
as_of: 2026-09-01
kind: initiative-state
---

# u7s eBPF LB dataplane — mechanism

Phase-1 datapath mechanism for the ServiceLB dataplane (`bd show
mayor-2et9d`, supersedes `mayor-fhfro`/`mayor-mma08`); implements, without
re-arguing, `servicelb-ebpf-geneve-dataplane.md` (this dataplane IS the
ServiceLB), `servicelb-symmetric-geneve-return.md` (symmetric, not DSR),
and `ebpf-toolchain-aya.md` (`aya`) — all under `docs/decisions/`.
Service-level semantics from `bd show mayor-0gpqp` (VIP model,
`externalTrafficPolicy`, IPv6/dual-stack, node-selector scoping) carry
over unchanged.

Must work across four underlay scenarios, none assumed: a WireGuard/
Tailscale mesh; disjoint subnets; a node behind NAT; all nodes colocated
with no encapsulation. The operator's multi-cloud fleet exercises the
first three at once, used below for sizing — one instance of the scenario
space, not the assumed layout.

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
`bpf_skb_set_tunnel_key` (no XDP equivalent), and XDP has no egress hook
for the backend capture. **Does XDP work over WireGuard?** Not reliably:
native XDP has no guaranteed driver support on a tunnel device over a
WireGuard/Tailscale interface, and generic-XDP (SKB mode) gives up XDP's
only edge over tc-bpf. tc-bpf's clsact qdisc attaches identically on any
device — what all four scenarios need.

## Packet flow

**Forward:** (1) Client → `VIP:PORT`; routing lands it on the node holding
the VIP (the "ingress node"). (2) Ingress hashes to a ready backend,
writes a flow-affinity entry keyed on the forward tuple `(CLIENT_IP,
SRC_PORT, VIP_IP, VIP_PORT, proto)`. (3) Stamps Geneve metadata (remote =
backend node, fixed VNI, a pod-identifier option) and redirects to
`geneve0`; inner packet untouched. (4) Backend
decaps, reads `VIP_IP:VIP_PORT` off the still-untouched inner dst *before*
rewriting anything, writes a reverse-flow entry storing that VIP plus the
ingress node's tunnel address, rewrites dst to `PodIP:TargetPort` (`src`
unchanged), forwards via flannel's pod-CIDR routing to the veth. **The Pod
sees the real client IP at L3.**

**Return:** (5) Pod replies ordinarily. (6) Backend's egress classifier
looks up the reverse-flow entry (same pair, read `dst`/`src` — valid,
nothing rewrote either side here), stamps Geneve metadata back to the
ingress node **echoing the stored `VIP_IP:VIP_PORT`**, redirects to
`geneve0`. (7) Ingress decaps, reads `CLIENT_IP:SRC_PORT` off the inner
dst and `VIP_IP:VIP_PORT` off the echo, looks up its step-2 entry,
rewrites `src` to the recovered VIP, routes.

## Conntrack & affinity

**The key must include the VIP, not just the client.** A client-only
`(CLIENT_IP, SRC_PORT, proto)` key collides: a client can hold two
concurrent connections from the same local port to two different VIPs
(demux uses the full remote address, not just the local port), and if
both resolve to the same ingress node, their entries collide. The key
must be the forward tuple `(CLIENT_IP, SRC_PORT, VIP_IP, VIP_PORT, proto)`
— trivial at step 2, but step 7 can't read it back the same way: the
returning packet only carries `PodIP:TargetPort`, the backend's DNAT
having overwritten the VIP. Fix: the backend captures `VIP_IP:VIP_PORT`
before DNATing and echoes it back on the return leg, so the ingress can
rebuild the key it wrote. **Still one map, just a wider key.**

The backend's reverse-flow key, `(CLIENT_IP, SRC_PORT, PodIP, TargetPort,
proto)`, has no equivalent problem — nothing rewrites either side between
write (step 4) and read (step 6), a genuine swap-match. Both keys share
one shape and fit in **one map per protocol** for both roles: VIP-space
and flannel's pod-CIDR are disjoint by construction, so the two entry
kinds never collide.

`BPF_MAP_TYPE_LRU_PERCPU_HASH`, custom (not `nf_conntrack` — heavier than
needed). Per-CPU cost is bounded by vCPU count — target hardware is 1
vCPU/1GB, nearly free.

- **TCP**: key = `(CLIENT_IP, SRC_PORT, OTHER_IP, OTHER_PORT, proto)`
  (`OTHER` = VIP or Pod IP, by role). IPv6-primary addressing: **37 bytes**
  (16+16+2+2+1) — not 13 (IPv4-only) nor 19 (the client-only key that
  collided above). Value ~34 bytes. 8192-entry ceiling.
- **QUIC**: key = a fixed-length Destination Connection ID prefix, minted
  by the LB itself (RFC 9000 §17.2's self-describing Initial-packet DCID)
  — not derived from the client's address, so no TCP-style collision risk.
  The 1-RTT short header (§17.3.1) has no length field, so post-handshake
  matching needs one fixed CID length cluster-wide (Traefik support —
  open question); simpler than the IETF draft's self-encoding scheme,
  which is only worth adopting past a single ingress point. 4096-entry
  ceiling.

| Component | Estimate | Basis |
|---|---|---|
| Userspace control-plane process | 3–5 MiB RSS | Rust async binary reusing `u7s_kubeconfig`'s watch machinery; idle after initial reconcile. |
| eBPF programs, all tc-bpf (4 points) | ~0 MiB (kernel-resident) | JIT'd, 5–50 KiB each. |
| VIP map (<100 Services × ≤2 protocols) | ~25 KiB | <200 entries. |
| Endpoint map (<1000 endpoints) | ~128 KiB | Every node carries the full map. |
| TCP flow-affinity, per-CPU | ~0.5–1 MiB at 1 vCPU | 8192 × ~90 B (37 B key + ~34 B value + ~20 B overhead). |
| QUIC CID map, per-CPU | ~0.25–0.5 MiB at 1 vCPU | 4096 entries, same model. |
| `vni_to_pod` (backend, local) | <5 KiB | <20 entries. |
| **Total** | **~4–7 MiB at 1 vCPU** | Close to the pre-narrowing estimate; scales linearly with vCPU count for the two per-CPU rows. |

All maps pre-allocate their full ceiling at creation — loxilb's "cannot
start on 1GB node" failure mode (gate 2). Ceilings are sized small for
u7s's envelope (<10 nodes/<100 Services/<1000 endpoints); not to grow
casually.

## Userspace control plane

Runs per node, not centrally (eBPF maps are local kernel memory, no
remote-write API). One DaemonSet per node, `hostNetwork` +
`CAP_BPF`/`CAP_NET_ADMIN`, no CRI socket: load tc-bpf programs once, watch
`Service`/`EndpointSlice` via existing watch machinery, write maps on
change, idle. Pinned under `/sys/fs/bpf` so a restart keeps flow state; a
reboot cold-starts.

## Prototype gates — go/no-go before Phase 3

1. **Return path works cross-node on real disjoint subnets** — a pure
   Geneve round trip. Lima alone can't validate this; needs a real
   multi-provider topology.
2. **Measured RSS footprint on a real 1GB/1vCPU node**, not the ~4–7 MiB
   estimate — pre-allocation can hide a floor invisible until actually
   run, per loxilb above.
3. **Userspace RSS and kernel eBPF-map memory both independently and
   continuously monitorable** (`ebpf-toolchain-aya.md`), not assumed
   stable.

## Open questions before the Phase-3 prototype

- **Traefik fixed-length QUIC CID support**: hard precondition for the CID
  design above, not yet verified.
- **Geneve option wire encoding, forward and return**: pod identifier —
  raw pod IP (simplest) vs. compact backend-index (smaller, couples to
  map-ordering across nodes). VIP echo — raw `VIP_IP:VIP_PORT` vs. a
  compact flow-id the ingress mints and the backend echoes verbatim
  (smaller, format-agnostic). Pick one of each before implementation.
- **VIP↔PodIP NAT placement**: proposed — DNAT on the backend (step 4),
  un-DNAT on the ingress (step 7), reusing the ingress's step-2 write. The
  alternative (both on the backend) needs the backend to learn the
  ingress's VIP. Not yet settled.

## References

`bd show mayor-0gpqp`/`mayor-fhfro`/`mayor-mma08`;
`ai/extended-context/cni-svclb-landscape.md`;
`docs/decisions/flannel-for-cni.md`; `kubernetes-retired/blixt`; RFC 9000;
`draft-ietf-quic-load-balancers-21`; `crates/scheduler`/`kubeconfig`.
