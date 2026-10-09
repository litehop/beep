# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-10-09

### Upgrade notes / operator action required

- **Controller RBAC.** The controller now creates and reads a cluster-wide
  flow-hash seed Secret, `servicelb-flow-hash-seed`, in `--seed-namespace`
  (default `kube-system`). `deploy/` ships a namespaced `Role`/`RoleBinding`
  (`create` on secrets, `get` on that one Secret) for the ServiceAccount. The
  default deployment runs the controller as the CSR-minted `beep-controller`
  user, which needs its own binding (`deploy/README.md`):

  ```sh
  kubectl create rolebinding beep-controller-csr-flow-hash-seed -n kube-system \
    --role=servicelb-controller-flow-hash-seed --user=beep-controller
  ```

  Without it the controller exits at startup (fail closed). Treat the Secret
  as sensitive: anyone who can read it can precompute backend placement
  (#190).
- **Loader `--pin-dir` is now required.** There is no default. Fixture mode
  (`--fixture`) now prunes fronts and `UPLINK_CONFIG` rows absent from the
  new invocation, and refuses the controller's pin directory (#198, #204).
- **Pinned maps are recreated on upgrade, flushing conntrack.** Pinned maps
  whose type, key size, value size or `max_entries` differ from the new
  definition are deleted and recreated at load time (one log line per map).
  This release changes: `CONFIG` 4 to 16 bytes (#190); `NODE_ALLOW` 16 to 32
  and `POD_TARGETS` 32 to 128 default entries (#158); the front maps are
  consolidated into `FRONT_META` and a generation-tagged `FRONT_ENDPOINTS`
  (#167); `TARGET_PORTS`, `LB_FRONT_MAP` and `EGRESS_DROPS` are removed (#156,
  #167); `REJECT_BUCKET` is added (#206). In-flight connections are reset
  once; plan the rollout accordingly.
- **CLI changes.**
  - `--uplink-iface`/`--geneve-iface` reject names that are empty, contain
    whitespace or `:`, or are otherwise invalid for an interface (#192, #197).
  - More `--uplink-iface` values than `UPLINK_CONFIG` holds (8) are rejected
    at startup instead of failing at map insert (#192).
  - New `--flow-hash-seed <u64>` on the bare loader (random if omitted;
    single-node rigs only) and `--seed-namespace` on the controller (#190).
  - New `--node-allow-max-entries` and `--pod-targets-max-entries`; the
    loader fails loud when one of those maps is full (#158).
  - The hidden test-only `evict-pod` one-shot takes several pod IPs (#179).
- **Behaviour change:** an uplink whose ARPHRD type is neither Ethernet (1)
  nor a known L3-only tunnel type (PPP, RAWIP, IPIP/IP6IP6, SIT, GRE/IP6GRE,
  NONE) is refused. Previously every non-Ethernet type silently got an L2
  header length of 0 (#171).
- **Behaviour change:** traffic to a front this node owns that has no ready
  backends is now answered with a TCP RST or ICMP/ICMPv6 port-unreachable
  instead of being passed to the host (#202). Replies are rate-limited
  (#206) and the front stays in place at count 0 so pinned flows drain
  (#208).

### Added

- Reject path for owned fronts with no ready backends: TCP RST, or ICMP type
  3/code 3 (v4) / ICMPv6 type 1/code 4 (UDP), so clients fail fast. Traffic
  to fronts this node does not own is unchanged (#202).
- Reject replies are rate-limited by a per-CPU token bucket (`REJECT_BUCKET`):
  100 replies/s with a burst of 25 per CPU, so the node-wide budget scales
  with CPU count. Over budget the packet is dropped, never passed to the
  host, so a spoofed-source flood is not reflected at the victim (#206).
- Ingress pin-steering and seeded flow-hash backend selection in the
  dataplane; selection is keyed by a cluster-wide seed so a client cannot
  precompute source ports that pile onto one backend (#178, #190, #195).
- Selective conntrack eviction: when a backend pod is removed, only its flows
  are swept, in one pass per map (#134, #135, #179).
- Controller dual-stack: honours `spec.ipFamilies`, publishes dual-stack LB
  ingress, parses dual-stack Nodes/EndpointSlices, picks underlay vs front
  node addresses by role, and programs each front with a same-family backend
  (#139, #141, #144, #154, #163). The dataplane's Geneve tunnel-key read is
  family-aware for a v6 underlay (#140).
- Configurable `NODE_ALLOW`/`POD_TARGETS` capacities (#158).
- Interim 6 MiB eBPF map-memory CI tripwire (#199).
- Smoke rigs: WireGuard-free 2-node cross-node, controller-driven dual-stack
  and IPv6-only-node round trips, cold-neighbour-cache, forward-underlay-
  follows-FIB, and deterministic restart-flow-continuity (#146, #166, #168,
  #177, #180, #186).

### Changed

- Front state is consolidated into `FRONT_META` plus a generation-tagged
  `FRONT_ENDPOINTS` table; legacy `vip_*` identifiers are renamed to "front"
  (#167, #169). One backend is still selected per front (see Known
  Limitations).
- The controller identifies the local node by Node identity rather than
  `--node-ip` equality, and admits hostNetwork pod IPs against the endpoint
  node's own addresses in every family (#157).
- Non-reply uplink egress that misses `FLOW_TABLE` now passes instead of
  being dropped; the `EGRESS_DROPS` counter is removed (#156).
- Loader derives requested map shapes from the embedded ELF and no longer
  does a probe load (#171).
- eBPF object trimmed to fit the shared stack and size budgets; the
  embedded-object gross-size ceiling is 160 KB (#195, #202).
- Dependency and CI-action bumps (Renovate).

### Fixed

- **P1:** an ingress node now drops its flows to a remote backend pod that
  departs or whose IP is reused by a different pod, cluster-wide rather than
  only for local pods. A failed sweep withholds only the affected IPs'
  installs. Terminating-but-serving and probe-flapping pods keep their pinned
  flows until they leave the slice (graceful drain); new flows select ready
  endpoints only (#200). Draining backends are not swept early, and
  cluster-wide departures wait for a complete slice set.
- An owned front whose Service has no ready backends is kept at count 0
  instead of being deleted, so new connections are refused while pinned flows
  to draining pods keep working; the front is removed only when its Service
  goes away. Repeated count-0 reconciles do not bump the generation (#208).
- An EndpointSlice update that omits `endpoints` (sent once the last pod is
  gone) now empties the slice instead of being ignored, so the departed
  endpoint and its pins are removed (#208).
- Relists replace the watched set, so EndpointSlices deleted while the watch
  was disconnected are removed. Implausible relists (empty Services or
  slices, a Node list without this node, a paginated list) are refused and
  retried, and an unresolved peer Node is not treated as a mass departure
  (#203).
- After a controller restart, no front, endpoint or pod-target rewrites occur
  until Services, EndpointSlices and Nodes have all been listed, so live
  fronts no longer drop to count 0 on a DaemonSet rollout. Once listed, a
  one-time sweep removes pins to backends that left while the controller was
  down (#209).
- Departed pods stay pending until their flows are swept (#179).
- A failed reconcile is retried with backoff, and an armed retry is not
  postponed by later events (#183).
- The flow-hash seed converges on the stored Secret value after the Secret
  changes (#193).
- Pins are honoured before a count-0 front is rejected, and decap resolves a
  drained front's target port from the prior generation (#202).
- `CONFIG` layout and per-link-type uplink L2 header length are guarded; a
  pinned map whose shape differs is recreated rather than silently kept
  (#171, see upgrade notes).
- The embedded eBPF object is rebuilt when `common/` changes.
- Stale `UPLINK_CONFIG` rows and fixture fronts are pruned on loader restart
  (#198).

### Security

- `FLOW_TABLE` values no longer carry uninitialised kernel stack bytes;
  every field is fully initialised before insert (#185).
- Backend selection is seeded with a cluster-wide secret, so external clients
  cannot steer flows onto a chosen backend by choosing source ports (#190,
  #193, #195).

### Known Limitations

- One backend per front: the selection plumbing (hash, seed, pin-steering,
  generation-tagged endpoints) is in, but multi-endpoint selection is not
  enabled yet.
- Decap resolves a drained front's target port from the prior generation as
  an interim measure until the final design lands. It is reachable only on
  count-0 fronts and survives one generation swap.
- The reject rate limit is a compile-time constant (not a flag) and is per
  CPU; the node-wide reply budget grows with CPU count.
- The post-restart orphaned-pin sweep waits for a non-empty backend set, so
  pins to departed backends persist while the cluster has no backends at
  all.

## [0.3.0] - 2026-09-21

### Added

- Dual-stack (IPv4 + IPv6) inner services: Service VIPs, backends, and
  clients can now be IPv6 alongside existing IPv4 ones, with the real
  client source address preserved across a genuine cross-node hop (#116,
  #118, #119). This is **inner** dual-stack only — v4/v6 service, client,
  and backend addresses — carried over an **IPv4 Geneve outer/transport**.
  The IPv6 underlay is not yet supported; see Known Limitations.

### Fixed

- The Geneve return leg's client-bound redirect carried the L3 underlay's
  all-zero L2 header. Redirecting that packet onto a real Ethernet egress
  interface got it classified `PACKET_OTHERHOST` and dropped by the kernel.
  `try_geneve_decap_return` now synthesizes a valid L2 header when the
  return leg's uplink is Ethernet, fixing round trips where a bare-metal/
  Ethernet client-ingress node forwards to a WireGuard backend uplink
  (#121).

### Verified on Lima VMs

| Rig | Nodes | Client | Transport | Client-egress L2 | Family | Proves |
| --- | --- | --- | --- | --- | --- | --- |
| `smoke.sh` (+ CI memory-smoke) | 1 | co-located netns | local veth | Ethernet | v4 | verifier-accept, encap/decap round trip, multi-port Service, flow preservation across restart, anti-flush, in-kernel NODE_ALLOW drop |
| `smoke-wg-2node.sh --family 4` | 2 + foreign client VM | foreign | WireGuard `wg0` | tunnel (ipip) | v4 | cross-node round trip, `wg0` traversal |
| `smoke-wg-2node-dualstack.sh` (#119) | 2 | co-located netns | WireGuard `wg0` | tunnel (ipip/ip6tnl) | v4+v6 inner | concurrent v4+v6 round trips, client-IP preservation, genuine cross-node |
| `smoke-eth-ingress-2node.sh` | 2 + foreign client VM | foreign | WireGuard `wg0` | Ethernet (`eth0`) | v4 | Ethernet ingress + wg transport, symmetric return |
| `smoke-wg-2node-ethclient.sh` (#121) | 2 | co-located netns | WireGuard `wg0` | Ethernet (veth) | v4 | return-leg L2 synthesis on real Ethernet egress |

Every cross-node rig above tunnels Geneve over a real `wg0` WireGuard link;
none of them exercise a WireGuard-free cross-node path. The
`smoke-wg-2node-ethclient.sh` rig proving the #121 fix runs v4 only by
design — the bug it targets is family-agnostic, so one family is sufficient
to prove the redirect path.

### Known Limitations / Not Yet Verified

- IPv6 Geneve outer/underlay is incomplete: `geneve_ingress`'s NODE_ALLOW
  peer attestation reads `bpf_tunnel_key`'s `remote_ipv4` only, so the
  dual-stack support above is inner-only, over an IPv4 transport.
- No WireGuard-free cross-node transport has been verified; every
  cross-node rig above tunnels Geneve over `wg0`.
- All verification runs on Lima VMs, not real cloud or bare-metal hardware.
- Only a single backend Pod per node has been exercised; multi-Pod load
  balancing is not yet load-tested.
- Only a single uplink interface is exercised per node in any given rig.

## [0.2.0]

### Added

- Multi-symmetric-uplink: `--uplink-iface` is now repeatable. Each
  configured uplink gets its own L2 header and ingress-ifindex admission,
  and the reverse leg replies out the same physical uplink the client's
  packet arrived on. N=1 (single-uplink deployments) is unchanged.
- `NODE_ALLOW`: outer-Geneve peer-node attestation gate for decap.
  Populated additively (upsert-only) until the controller's own Node LIST
  is known complete (`fronts_known`), so a cold-started controller never
  wipes an already-pinned peer set on a partial view. Two ADRs formalize
  the trust model this assumes: the Geneve underlay L2 is not trustworthy
  (`NODE_ALLOW` is defense-in-depth, not a substitute for a cryptographic
  underlay like WireGuard), and the startup-blackout window is a
  deliberate security-vs-availability tradeoff, not an oversight.
- The embedded eBPF object is DWARF-stripped, and CI asserts it stays
  stripped, keeping the loader binary's embedded payload lean.

### Changed

- `deploy/`'s rp_filter node-prep now runs in a privileged initContainer
  instead of requiring the main container to hold node-wide privileges for
  its whole lifetime.
- The k3s e2e rig now deploys and verifies the commit-under-test's image
  `:sha`, not the DaemonSet's `:latest`, so cross-node tests catch
  regressions in the actual candidate build.

### Known Limitations

- Asymmetric relay/egress-interface selection is deferred: replying out a
  different uplink than the one a packet ingressed on is explicitly out of
  scope for this release.
- IPv6 dual-stack is in progress, not shipped. v0.2.0 is IPv4-only, same as
  v0.1.0.
- Single backend per Service, carried over from v0.1.0: multi-endpoint
  load balancing across several ready pods is still not implemented.
- Real-fleet fidelity remains unproven beyond the k3s-on-Lima VM rig,
  carried over from v0.1.0.

## [0.1.0]

### Added

- North-south `type=LoadBalancer` Service delivery via a
  Geneve-encapsulated, eBPF (aya, tc-bpf) dataplane with full-tuple
  conntrack.
- Single-node and cross-node delivery, proven on the k3s-on-Lima VM rig.
- Real client-IP preservation: the forward leg's DNAT rewrites only the
  destination IP/port, never the client's source IP.
- Controller memory footprint CI-gated (idle/loaded RSS tracked in the
  memory-smoke job).
- Docker Hub image `docker.io/valerauko/beep-lb`, natively pullable over
  IPv6.

### Known Limitations

- Single backend per Service. Multi-endpoint load balancing across several
  pods is not implemented; a Service with more than one ready endpoint
  gets only one of them selected. Real N-endpoint selection is deferred to
  a fast-follow release.
- Real-fleet fidelity unproven. Client-IP preservation is verified against
  the k3s-on-Lima VM rig, not against a real cloud provider's
  uRPF/NAT/IPv6 edge cases. Deferred, off the v0.1.0 path.
- Lives in the u7s monorepo's `beep/` subtree; an independent repo split
  for its own release cadence is not yet done.
