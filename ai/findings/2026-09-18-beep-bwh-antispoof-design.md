---
Bead: beep-bwh
Date: 2026-09-18
Scope: read-only design audit of a compensating control for rp_filter=0 (beep-o1b) — validating the outer Geneve tunnel source against known peer nodes. No code changes; decision input for the operator.
---

# Anti-spoof hardening for Geneve decap: validate outer tunnel source against known peer nodes

## Answer first

Add a `NODE_ALLOW: HashMap<u32, u8>` map — same shape as the existing
`POD_TARGETS` membership map — populated by the controller from the Node
watch it already runs (`node_ips` in `controller/src/watch.rs`, already
collected for `VIP_MAP`'s front-IP set), and check `tkey.remote_ipv4`
against it in `geneve_ingress` immediately after `bpf_skb_get_tunnel_key`,
on **both** the `VNI_FWD` and `VNI_RET` branches, dropping (`TC_ACT_SHOT`)
on a miss. This needs no new Kubernetes watch and no new eBPF map pattern —
it is the same `MAP.get(key).is_some()` admission-gate idiom `POD_TARGETS`
already uses twice in this file (main.rs:635, :1022).

## The crux: can the program see the outer IP header directly?

No — and there is no alternative to check. `geneve0` is created
`external`/collect-metadata mode (`src/lib.rs:223`, confirmed in every
smoke/e2e script). For a metadata-mode tunnel device, the kernel's tunnel
receive path strips the outer Ethernet/IP/UDP/Geneve headers **before**
handing the skb to any BPF program attached on that netdevice, and stashes
the outer key (src/dst IP, VNI, TTL, Geneve options) in the skb's tunnel
metadata (`ip_tunnel_info`). The only way to read that metadata from BPF is
the kernel helper `bpf_skb_get_tunnel_key`/`bpf_skb_get_tunnel_opt` (helper
IDs 20/21, wrapped verbatim in
`aya-ebpf-bindings-0.2.0/src/*/helpers.rs:171` — rust-analyzer can't index
`ebpf/src/main.rs` on this macOS host, `bpfel-unknown-none` isn't a
buildable target here, so this cite is the vendored source directly rather
than an LSP hover). `geneve_ingress` itself is the proof: it calls
`bpf_skb_get_tunnel_key` into `tkey` first (main.rs:576-586), and every
`ctx.load()` after that point in `try_geneve_decap_forward`/`_return` reads
the **inner** packet — `client_ip = ctx.load(IP_SRC)` at main.rs:640 is the
inner client address, not an outer one. There is no second, independent
"raw outer header in skb data" to cross-check against. `tkey.remote_ipv4`
**is** the outer source, as the kernel decapsulated it — not a
lower-fidelity proxy for it. Design question (b) from the bead therefore
collapses: there is nothing to validate the outer header "directly"
against; `tkey.remote_ipv4` is already the only and authoritative view.

## Threat model

With `rp_filter=0` node-wide (`docs/decisions/geneve-rp-filter-disable.md`),
any host that can reach a node's Geneve UDP listener can send a UDP/Geneve
packet with a **spoofed outer IP source**, `tunnel_id = VNI_FWD` (100, a
fixed constant), and a Geneve option TLV naming a real `VIP:PORT` plus a
`pod_ip` this node actually hosts (learnable by watching any real client
flow, since it's carried in plaintext on the wire). `try_geneve_decap_forward`
DNATs it straight to the real backend pod and writes the attacker's chosen
outer source into `RevFlowValue.ingress_node_ip` unconditionally
(main.rs:783). Two distinct payoffs: (1) the backend pod receives an
attacker-controlled "client IP" at L3, bypassing any client-IP-keyed trust
(allowlists, per-source rate limiting) the pod or app layer relies on; (2)
because `ingress_node_ip` is trusted verbatim, the backend's real response
gets Geneve-encapsulated (`VNI_RET`) and `bpf_redirect`'d toward *whatever
IP the attacker named* — a single-packet reflection/amplification primitive
against any third-party IP, using this node's backend as the amplifier,
with no traffic ever needing to reach the attacker. `try_geneve_decap_return`
is the more exposed of the two paths today: it takes `_tkey` (unused) and
performs **no** outer-source check of any kind, relying entirely on the
`FLOW_TABLE` reverse-key match — any fix must cover both branches, not just
forward.

## Design questions

**(a) Where does the peer-node set live?** `controller/src/watch.rs` already
maintains `node_ips: HashMap<String, Ipv4Addr>` from the cluster's Node
LIST/watch, and already flattens it to `node_ips.values()` for `VIP_MAP`'s
front-IP set (watch.rs:369). The same set is the natural source for
`NODE_ALLOW` — no new watch, just one more `apply()` map write in
`controller/src/apply.rs`, identical in shape to `pod_targets`'s upsert/delete
loop. Sizing: cluster node count, not Service count — an order of magnitude
smaller than `POD_TARGETS`'s already-tiny 32-entry default; negligible
against the documented ~8-9 MiB total map budget
(`docs/design/ebpf-lb-dataplane.md`'s sizing table).

**(c) NAT'd/multi-homed node networking:** unresolved by evidence in this
codebase; needs the operator's deployment-topology answer. `watch.rs`'s Node
parser takes only the *first* `InternalIP` (main.rs:193-200 in watch.rs). A
node with multiple NICs, or a Geneve underlay that transits a NAT hop
between peers, could present an outer source that doesn't match that single
recorded address even though the traffic is legitimate — this would need
`NODE_ALLOW` to admit every address a Node object reports (`InternalIP` +
`ExternalIP`, all entries), not just the one `front_ips` uses today.

## Options

| Option | Map shape / cost | Controller plumbing | Failure mode |
|---|---|---|---|
| **A — new `NODE_ALLOW`, POD_TARGETS-shaped (recommended)** | `HashMap<u32,u8>`, 4-byte key, one hash lookup — same verifier cost class as the existing `POD_TARGETS` check | Reuses `node_ips`; one more `apply()` write | A peer node whose Node object hasn't landed in this node's watch yet is dropped until the watch catches up (same race `watch.rs` already documents for `front_ips`) — drop, not misdeliver, consistent with the file's own cross-node-drift ethic |
| **B — fold into `POD_TARGETS` itself** | No new map | None | Rejected: `POD_TARGETS`'s own doc comment (main.rs:139-158) states it deliberately has "exactly one membership notion" so both decap directions agree; merging a peer-node set in reintroduces the ambiguity that invariant exists to prevent, and lets a pod IP be misread as a peer node or vice versa |
| **C — host firewall (iptables/ipset) instead of an eBPF map** | No eBPF map, no verifier cost | Controller must sync an ipset on every Node add/remove — same plumbing cost as A, different write target | Moves enforcement into a second converged system beep must also keep in sync, outside the same map-based failure-mode class as the rest of the dataplane; doesn't distinguish `VNI_FWD` vs `VNI_RET` at the UDP-port level the way a per-VNI eBPF check can |

## Open questions for the operator

1. Should `NODE_ALLOW` admit every address a Node object reports, or is a
   single InternalIP-per-node model (matching today's `front_ips`) actually
   sufficient for beep's target bare-metal topology? Needs a topology answer,
   not more code-reading.
2. Is the startup/rejoin drop window (new peer's Geneve traffic rejected
   until this node's own Node watch delivers that peer) acceptable as-is, or
   does this specific gate need different treatment than the FLOW_TABLE
   drift cases the cross-node-drift invariant was written for — a fail-open
   here has a spoofing consequence, not just a delayed-delivery one?
3. Is the Geneve underlay's L2/L3 segment already isolated (dedicated VLAN,
   no untrusted host reachability) in the intended bare-metal deployment,
   making this defense-in-depth rather than load-bearing — or is an
   adversarial host on that segment part of beep's actual threat model?
