---
as_of: 2026-09-07
kind: initiative-state
---

# u7s eBPF LB dataplane — mechanism

Phase-1 datapath mechanism for the ServiceLB dataplane (`bd show
mayor-2et9d`, supersedes `mayor-fhfro`); implements
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
regardless of hook count. Deferred until the L7 tier is scoped.

## Packet flow

**Forward:** (1) Client → `NODE_IP:SVC_PORT` — an address the receiving
node owns (its primary IP, or a prefix statically routed to it), dialed
directly; no floating IP, no ARP/BGP announcement (servicelb ADR). DNS
publishes each node's own address and every node accepts the service
port, so the packet lands on whichever node the client dialed — the
"ingress node." `NODE_IP:SVC_PORT` **is the LB front IP**: node-owned,
not necessarily virtual, never assumed to sit behind a cloud LB. The
controller derives two separate address sets per node from Node
`status.addresses`, each rule applied per address family: the front address
is the ExternalIP when configured, else the InternalIP; the underlay
address (Geneve remote, `NODE_ALLOW`) is the InternalIP when configured,
else the ExternalIP. (2)
Ingress picks a backend (see Backend selection), writes a flow-affinity
entry keyed on the forward tuple `(CLIENT_IP, SRC_PORT, FRONT_IP,
FRONT_PORT, proto)`, and (3) stamps Geneve metadata (remote = backend
node, fixed VNI, a 24-byte pod-identifier option carrying pod IP and
target port), redirects to `geneve0`; inner packet untouched.
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

## Backend selection

The controller writes each front's endpoints as dense slots `0..count-1`
in `FRONT_ENDPOINTS` plus one `FRONT_META` row (`generation`, `count`,
`local_count`); committing the `FRONT_META` replace swaps generations
atomically. Ingress, per packet, in this order:

1. **No `FRONT_META` row**: not a front; pass to the host.
2. **Existing pin** (`FLOW_TABLE` forward entry, else `FWD_PENDING`): the
   pinned backend and its target port win over everything below, including
   count 0. Re-slotting after an endpoint change therefore never moves a
   live flow.
3. **Count 0**: silent drop (no RST/ICMP; nothing for a scanner to learn),
   counted in `FRONT_MISSES`. Applies to every owned front with no usable
   endpoint, including `externalTrafficPolicy: Local` on a node without a
   local pod, matching kube-proxy.
4. **Hash**: `slot = flow_hash(seed, client_ip, client_port, front) × N >>
   32`, where N is `local_count` if non-zero (local pods occupy slots
   `0..local_count`), else `count`. Deterministic, unweighted.

What the controller emits, from `spec.externalTrafficPolicy` and
`spec.trafficDistribution` (never EndpointSlice hints):

| Service | Slots (per front family) | `local_count` | Published node addresses (`status.loadBalancer.ingress`) |
|---|---|---|---|
| default (eTP=Cluster) | all ready, non-terminating, sorted by pod IP | 0: uniform | every node with a ready beep |
| `trafficDistribution: PreferSameNode` (`PreferClose`/`PreferSameZone` map to it: no zone model) | same, local pods first | local pod count: local preferred while any exist, else uniform | every node with a ready beep |
| eTP=Local (wins over `trafficDistribution`) | local ready pods only; if none, local serving-terminating pods; else none | = `count` | only nodes with a usable local pod |

Uniform slot order depends on pod IP alone, so one flow hashes to the
same pod from any ingress node. Terminating pods get no new flows;
pinned flows drain. Switching eTP between Cluster and Local does not
evict pinned flows. `healthCheckNodePort` is not served by beep.

## Decap trust model

Decap admits a packet if its outer source is in `NODE_ALLOW` and the
option's pod IP is in the node's local `POD_TARGETS`; it takes
`target_port` from the option with no per-front bound, so any
`NODE_ALLOW` peer can name any port on a local pod. Accepted
(operator decision 2026-10-13): the underlay is not assumed trusted but
is assumed to prevent IP spoofing (cloud VPC/VPS network, or a LAN behind
a router), so `NODE_ALLOW` source-IP admission is the trust boundary.
Reopen, adding a per-pod published-target-port check at decap, if
spoofing becomes an observable risk.

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
disjoint **only by configuration, not by construction** — a `hostNetwork`
Pod's IP equals its node's IP; they can collide.

`BPF_MAP_TYPE_LRU_HASH`, custom (`nf_conntrack` is heavier), shared not
per-CPU — `LRU_PERCPU_HASH` broke conntrack (cross-CPU misses between
forward-write and return-read).

- **TCP/UDP/QUIC share one key shape**: `(CLIENT_IP, SRC_PORT, OTHER_IP,
  OTHER_PORT, proto)` (`OTHER`=front IP or PodIP). IPv6-primary: **37
  bytes**. QUIC keys the same way — **4-tuple pass-through for the MVP,
  not a minted CID** (`bd show mayor-g3lag`, closed): the CID is
  server/backend-chosen (RFC 9000 §7.2), unmintable/unobservable by a
  non-terminating dataplane; CID-based keying is deferred, needing
  u7s-owned server_id distribution (`bd show mayor-xjy5o`). No longer
  exempt from the remap remedy below. The merged forward+reverse table
  below widens this to **38 bytes** (one added direction-tag byte) for its
  own key; the admission-only `FWD_PENDING` tier keeps the plain 37.
- **Admission + affinity** (`docs/decisions/servicelb-flow-admission-affinity.md`,
  `bd show mayor-aie31.11`/`mayor-aie31.21`): the forward map splits into
  `FWD_PENDING` (new, flood-exposed) and a promoted, established-affinity
  role (promoted on the observed return leg); sizes DaemonSet-configurable
  at load, never hard-coded. The promoted value pins the full backend
  identity (`backend_node_ip`+`pod_ip`); eviction fires only on endpoint
  removal. The promoted-forward and reverse (backend-side un-DNAT
  conntrack) roles share one physical `FLOW_TABLE`, discriminated by an
  explicit direction-tag byte rather than address-space disjointness (see
  the Cross-node drift invariant below).
- **Cross-node drift invariant** (`bd show mayor-tavxy`): per-node
  controllers can lag on the same EndpointSlice event, so state diverges
  for seconds. The **delivery node**, not ingress, must be authoritative:
  inbound Geneve-decap validates the stamped `pod_ip` against its local
  serving-set before delivering — bounding drift to a drop, never a
  misdelivery.

| Component | Estimate (1 vCPU) | Basis |
|---|---|---|
| Userspace control-plane process | ~6.9 MiB RSS | Rust async binary; idle after reconcile. Measured, not estimated — gated by CI's `memory-smoke` job (`scripts/memory-smoke-controller.sh`). |
| eBPF programs, all tc-bpf (4 points) | ~0 MiB (kernel-resident) | JIT'd, 5–50 KiB each. |
| `FRONT_META` (front tuple -> live generation, count, flags) | ~17 KiB bucket floor + ~96 B/front used | `BPF_F_NO_PREALLOC`, so only used entries cost memory. `max_entries` = `--max-fronts` (1024 by default): nodes × Service ports. |
| `FRONT_ENDPOINTS` ((front, generation, slot) -> backend node, pod, target port) | ~129 KiB bucket floor + ~128 B/row used | `BPF_F_NO_PREALLOC`. `max_entries` = `--max-fronts` × `--endpoints-per-front` (4) × 2 = 8192 by default; the 2 is swap headroom (a front's next generation is written next to the live one; the previous one is deleted ~2 s after the commit). Full map on every node. |
| `FRONT_MISSES` | <1 KiB | Per-CPU counter of ingress lookups where `FRONT_META` hit but no endpoint could be chosen (count 0 with no pin, or an unreadable row): silently dropped. |
| Other maps, shared (`FLOW_TABLE` ~2.25 MiB, `FWD_PENDING`, `POD_TARGETS`, `NODE_ALLOW`, `UPLINK_CONFIG`, `CONFIG`) | ~2.55 MiB | Preallocated at full `max_entries`; ceilings/sizing: `servicelb-flow-admission-affinity.md`. Figure is `EXPECTED_PREALLOCATED_BYTES` in `scripts/assert-ebpf-map-memory.sh` (highest across `memory-smoke` runs). |
| **Total** | **~9.6 MiB** | ~6.9 MiB control-plane RSS (above) + ~2.7 MiB kernel map memory (`bytes_memlock` 2827720 B) at defaults. The 6 MiB gross ceiling in `scripts/assert-ebpf-map-memory.sh` bounds the kernel-map part only, not this total; that script also asserts per map and in total (1.15× tripwire on expected usage). Independent of vCPU count except `FRONT_MISSES` (per-CPU, <1 KiB per CPU). |

Every map except the two front maps preallocates its full ceiling —
loxilb's "cannot start on 1GB node" failure mode (gate 2) — sized for
u7s's envelope (<10 nodes/<100 Services/<1000 endpoints). The front maps
cost their bucket floor plus used rows only; the defaults (1024 fronts × 4
endpoints) are far above the envelope.

## Userspace control plane

Runs per node, not centrally (eBPF maps are local kernel memory). One
DaemonSet per node, `hostNetwork`/`CAP_BPF`/`CAP_NET_ADMIN`, no CRI
socket: loads tc-bpf programs once, watches `Service`/`EndpointSlice`,
writes maps on change, idle. Pinned under `/sys/fs/bpf` so restarts keep
flow state.

At load time the loader compares each pinned map's type, key size, value
size and `max_entries` against the embedded object's map definitions (parsed
from the ELF, plus the `--*-max-entries` overrides; no kernel objects are
created). A mismatched pin is unlinked and recreated empty, with a log line;
matching pins are reused. Conntrack maps lose their flows when recreated.
Unlinking does not touch the old map: tc programs attached by the previous
loader keep referencing it until the new loader re-attaches, so a restart
briefly serves from the old map before the new shape takes effect.

A pin that differs only in `map_flags`/`max_entries` is parked as
`<name>_migrating` and its entries are restored into the new map before any
program attaches; the parked pin is removed only after the restore. Restore
writes use `BPF_NOEXIST`, so repeating it after a crash never overwrites a
newer entry. Entries dropped by a cap shrink are logged and do not block the
unpark; any other write failure (`ENOMEM`, `EINVAL`, ...) fails the start with
the parked pin kept, and the next start retries from it. Dev/test hook:
`BEEP_FAULT_ABORT_BEFORE_RESTORE=1` makes the loader exit after creating the
new maps and before restoring them, to exercise that recovery
(`scripts/smoke-remote.sh`, "crash-safe migration").

First upgrade to the `FRONT_META` + `FRONT_ENDPOINTS` layout starts with an
empty `FRONT_META`: until the controller's first reconcile fills it, new
flows pass to the host unbalanced (an absent front is not a front).

## Prototype gates — go/no-go before Phase 3

1. **Return path works cross-node on real disjoint subnets** — Lima
   alone can't validate a Geneve round trip.
2. **Measured RSS on a real 1GB/1vCPU node**, not the ~4–7 MiB estimate
   (pre-allocation can hide a floor until run, per loxilb).
3. **Userspace RSS and kernel eBPF-map memory independently and
   continuously monitorable** (`ebpf-toolchain-aya.md`), not assumed
   stable.

## Settled wire-format decisions (2026-09-03)

- **Geneve option encoding**: raw pod IP plus the wire-order target port
  for the pod identifier (24 bytes, the same length as the return option, so
  the forward leg needs no more underlay headroom: inner L3 ≤ underlay MTU −
  74 on a v4 underlay, − 94 on v6); raw `FRONT_IP:FRONT_PORT` for the
  front-IP echo. Compact alternatives cost a map-ordering/id-collision
  surface for little savings — the echo is load-bearing (see Conntrack), not
  cosmetic. The backend's decap reads the target port from the option and
  never looks the front up.
- **Front-IP↔PodIP NAT placement**: DNAT on the backend (step 4),
  un-DNAT on the ingress (step 7), reusing the step-2 write. Gates
  Phase 2 (mayor-g7jh2).
- **Backend reverse-flow key uniqueness**: keep the full 5-tuple key; on
  a cross-Service collision (shared Pod:targetPort, reused client source
  port), remap the backend's source port, un-remapping on return —
  closes UDP. QUIC is **not** exempt (see Conntrack).

## References

`bd show mayor-0gpqp`/`mayor-fhfro`; `cni-svclb-landscape.md`;
`kubernetes-retired/blixt`; RFC 9000; `draft-ietf-quic-load-balancers-21`.
