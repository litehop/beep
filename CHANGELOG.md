# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The controller publishes no `status.loadBalancer.ingress` until its first
  Service, EndpointSlice and Node LISTs have all completed (previously it
  published `--node-ip`'s family alone from the first Service event), and the
  DaemonSet now has an exec `readinessProbe` on `--ready-file`
  (`/tmp/beep-ready`), created at that point. Pods report NotReady during
  startup; custom manifests need the probe added. See deploy/README.md,
  "Startup readiness".
- Controller `--pod-cidr` is repeatable, at most one per family, so a
  dual-stack cluster admits non-hostNetwork pod backends of both families.
  Two CIDRs of the same family fail startup; a single flag behaves as before.

## [0.6.0] - 2026-10-19

### Upgrade notes / operator action required

- **Manifests moved to `deploy/base`.** Install with
  `kubectl apply -k deploy/base`; the client-cert opt-in is
  `kubectl apply -k deploy/overlays/client-cert`. `kubectl apply -f deploy/`
  no longer works.

- **The stock DaemonSet authenticates with its in-cluster ServiceAccount.** It
  no longer mounts the `beep-controller-kubeconfig` Secret or passes
  `--kubeconfig`. Operators who rely on a client-cert kubeconfig must apply the
  `deploy/overlays/client-cert` overlay.

- **The ServiceAccount token is mounted into the controller container only.**
  `deploy/base/daemonset.yaml` sets `automountServiceAccountToken: false` and
  mounts a projected `serviceaccount` volume into the controller container, not
  the privileged node-prep initContainer. Re-check any custom DaemonSet patches.

- **Supported platforms: systemd-based Linux only** (kernel 6.6+, little-endian
  x86-64/AArch64, latest two Kubernetes minors).

- **Nodes need `/etc/sysctl.d`.** node-prep writes `/etc/sysctl.d/60-beep.conf`
  to persist `geneve0` `rp_filter=0`.

- **Lost-node prune bounds.** A removed node leaves Service
  `status.loadBalancer.ingress` within 30 s of a graceful stop once the
  surviving controllers have run for 40 s, and up to 70 s right after a
  restart; a silently lost node within 85 s of the later of its last renewal
  and the survivor's start.

- **Published ingress for existing `externalTrafficPolicy: Local` Services
  changes.** While no node has a usable endpoint (per address family), every
  node is listed in `status.loadBalancer.ingress` (fail-open), so a Service
  created before its pods gets an ingress; new connections are dropped until a
  pod is usable. Once one is, only nodes with a usable local pod stay listed.

### Added

- Service `sessionAffinity: ClientIP` is honoured: a client stays pinned to one
  endpoint while the endpoint set is stable (`timeoutSeconds` is not honoured).

### Changed

- Loader `--fixture` repeated for one front now adds endpoints instead of
  keeping the last; an optional `:affinity` suffix requests ClientIP affinity.
- `FRONT_META.flags` bit 0 now means ClientIP affinity (no byte-layout change).
- **`externalTrafficPolicy: Local` now deviates from upstream semantics.** A
  node with no usable local pod forwards to the ready, non-terminating
  endpoints cluster-wide (client IP preserved) instead of dropping. The front
  is count 0 (drop) only when no pod is ready anywhere; a remote
  serving-but-terminating pod keeps the Service published but is not a
  fallback target.
- Dependency and CI-action bumps (Renovate).

### Fixed

- `geneve0` `rp_filter` no longer reverts to the distro default after the
  device is re-created on systemd hosts.
- The loader re-attaches pinned links severed by deleting the geneve device
  instead of crash-looping until `/sys/fs/bpf/beep` is cleaned by hand.
- The controller no longer logs WARN for idle watch timeouts or the startup
  initial-LIST wait; its watches request bookmarks.
- A removed node's address leaves Service `status.loadBalancer.ingress`
  promptly, and the controller handles SIGTERM by withdrawing its Lease
  addresses.

## [0.5.0] - 2026-10-15

### Upgrade notes / operator action required

- **beep must be the cluster's only L4 load balancer.** Disable k3s `servicelb`
  and do not run MetalLB, kube-vip or a cloud LB controller alongside; two
  controllers would write `status.loadBalancer.ingress` on the same Services.
  kube-proxy must run in iptables or nftables mode. See `deploy/README.md`
  ("Required per-cluster configuration & gotchas").

- **The loader refuses to start on kernels older than 6.6** (TCX attach).
  Upgrade nodes to Linux 6.6 or newer before rolling out 0.5.0.

- **New `beep-config` ConfigMap (`deploy/configmap.yaml`) holds the sizing
  caps.** Apply it before `deploy/daemonset.yaml`, which now loads it with
  `envFrom` (a missing ConfigMap fails the pod). `BEEP_MAX_FRONTS` (1024) and
  `BEEP_ENDPOINTS_PER_FRONT` (4) take effect on `kubectl rollout restart
  ds/servicelb-controller`; the front maps are recreated with their entries
  carried over and established flows survive. Every option, its default and
  memory cost is in `deploy/README.md` ("Configuration").

- **Controllers now keep a per-node Lease and prune dead nodes from Service
  ingress.** Apply the updated `deploy/rbac.yaml` (new `beep-leases`
  Namespace holding the Role for `coordination.k8s.io` leases, kept out of
  `kube-system` so beep cannot touch control-plane leader election; with a
  CSR kubeconfig also bind it in `beep-leases`, see `deploy/README.md`) and `deploy/daemonset.yaml` (`NODE_NAME`
  env). The controller requires `--node-name` (env `NODE_NAME`). A node whose
  beep pod stops renewing (40 s duration, 10 s renew) is removed from every
  Service's `status.loadBalancer.ingress` within about a minute.

- **Pinned maps are recreated on upgrade, flushing conntrack.** The loader
  deletes and recreates any pinned map whose type, key size, value size or
  `max_entries` differ from the new definition (one log line per map). This
  release changes `FLOW_TABLE` values from 36 to 40 bytes and `FRONT_META`
  from 8 to 12 bytes. Established flows are reset once.
- **`FRONT_META` and `FRONT_ENDPOINTS` are recreated on upgrade.** The loader
  now also compares a pinned map's `BPF_F_NO_PREALLOC` flag, and both front
  maps change from preallocated to no-prealloc (and `FRONT_META` from 4096 to
  1024 default entries). A pin whose type, key size and value size are
  unchanged (flag or `max_entries` change only, e.g. this upgrade or a changed
  `--max-fronts`/`--endpoints-per-front`) has its entries copied into the new
  map before any program is attached, so established flows see no gap; if a
  cap shrink does not fit, whole fronts are kept in key order, the loss is
  logged with counts, and the controller reconciles the rest. A layout change
  (key/value size) recreates the map empty, and established flows through
  fronts reset until the controller's first reconcile. Entries the previous
  loader's programs write after the snapshot (new flows) are not carried over.
- **Breaking flag change.** `--front-meta-max-entries` and
  `--front-endpoints-max-entries` are removed from `beep` and
  `beep-controller`. Use `--max-fronts` (default 1024, env `BEEP_MAX_FRONTS`)
  and `--endpoints-per-front` (default 4, env `BEEP_ENDPOINTS_PER_FRONT`):
  `FRONT_META` holds `max-fronts` rows and `FRONT_ENDPOINTS`
  `max-fronts x endpoints-per-front x 2` (the 2 is swap headroom).

### Fixed

- A Service that leaves `type: LoadBalancer` (e.g. patched to `ClusterIP`) now
  has beep's entries removed from `status.loadBalancer.ingress` and its fronts
  removed from the dataplane; previously the stale ingress stayed.
- The controller's `MapRestoreFailed` Warning Event (a failed map restore at
  upgrade) is verified live on k3s, and posting has an overall deadline so a
  slow apiserver cannot stall the controller. `BEEP_FAULT_FAIL_RESTORE_WRITE=1`
  makes the first restore write fail with `ENOMEM` to exercise it; test hook,
  never set it in production.
- New connections were refused (dropped at the backend node) once 16 closed
  connections had left stale remap state behind: two Services sharing a pod
  and a client reusing one source port across both remap the second flow's
  backend-facing source port, and the reverse/memo rows of finished flows were
  only ever freed by LRU eviction. A TCP flow's rows are now marked closed on
  RST, or once a FIN was seen in both directions (a half-closed connection
  stays live). A closed row keeps forwarding, so a retransmitted FIN or final
  ACK still finds it, and a new connection may reuse its remap slot; the short
  (UDP-interval) idle sweep then reclaims it with its port-remap memo, and the
  sweeps reclaim the rest.

### Added

- Idle `FLOW_TABLE` GC, swept by the controller: flow rows carry a parity bit
  that the dataplane copies from a global parity (`CONFIG`) when a packet
  matches; every sweep interval the controller deletes the rows whose bit
  differs (with their port-remap memos), then flips the parity. Idle UDP flows
  go after 1-2 `--udp-idle-sweep-secs` (env `BEEP_UDP_IDLE_SWEEP_SECS`, default
  120); TCP flows that vanish without a close go after 1-2
  `--tcp-idle-sweep-secs` (env `BEEP_TCP_IDLE_SWEEP_SECS`, default 43200 = 12 h).
  Both are in the `beep-config` ConfigMap, as is `BEEP_FLOW_TABLE_MAX_ENTRIES`
  (`--flow-table-max-entries`, default 16384); see `deploy/README.md`
  ("Configuration"). The sweep runs on wall-clock interval boundaries and the
  parity survives a controller restart.

- Front-map write failures are reported by cause: `E2BIG` (capacity), `ENOMEM`
  (kernel out of memory allocating a map element, transient) and other, each
  with its errno text. A front update that would not fit under the pinned
  map's `max_entries` is refused whole before any row is written, with a
  capacity error naming the map; fronts are applied shrinking first, then in
  key order, so the front that starves under pressure is deterministic. The
  front is left on its previous endpoints in every case.

- Node-local endpoint preference: `FRONT_META` carries a `local_count`, and
  selection prefers local endpoints when it is non-zero. Inert until the
  controller sets `local_count`.

- The controller emits every ready, non-terminating, same-family endpoint of a
  Service (previously one), with its target port and an `IS_LOCAL` flag, and
  honours Service policy:
  - `externalTrafficPolicy: Cluster` with no `spec.trafficDistribution`
    spreads uniformly over all ready endpoints.
  - `spec.trafficDistribution: PreferSameNode` prefers local endpoints and
    falls back to all; `PreferClose` and `PreferSameZone` are treated the same
    (beep has no zone model); an unknown value is logged and spreads uniformly.
  - `externalTrafficPolicy: Local` uses only endpoints on the ingress node
    (ignoring `trafficDistribution`); with no ready local pod it uses
    serving-but-terminating local pods, and with none at all the front is
    owned at count 0.
  - Each node's controller writes only its own address to
    `status.loadBalancer.ingress`; under `externalTrafficPolicy: Local` it
    removes it while the node has no usable local pod. Switching policy does
    not evict pinned flows; they drain naturally.

### Changed

- Owned fronts with no ready endpoints (count 0: eTP=Local with no usable
  local pod, 0-backend Services) now silently drop new flows instead of
  answering with a TCP RST / ICMP(v6) port unreachable, matching kube-proxy's
  hardened edge posture. Established and pending pinned flows still forward.
  A front with no `FRONT_META` row still passes to the host. The reject path
  (`beep_common::reject`) and its `REJECT_BUCKET` rate limiter are removed;
  the loader deletes a leftover `REJECT_BUCKET` pin on start.
- The forward Geneve option is now 24 bytes and carries the target port.
  Decap reads the port from the option and no longer consults the front maps.
- `FRONT_META` and `FRONT_ENDPOINTS` are `BPF_F_NO_PREALLOC`: memory is a
  bucket array (~16 B per slot of `max_entries`) plus ~96 B per front and
  ~128 B per endpoint row in use, instead of the full cap. At the 11-front
  smoke scale the two maps drop from 1.54 MB to ~0.15 MB.
- The previous endpoint generation is deleted about 2 s after a swap commits
  (it was kept until the next swap). Only a packet that loaded the old
  `FRONT_META` microseconds before the commit can still want it; established
  flows read their conntrack pin. Steady state holds one generation per front.
- The memory-smoke tripwire is 1.15x of the expected usage (bucket floors +
  entries x per-entry + the preallocated maps) instead of a flat 6 MiB, which
  stays as the gross ceiling.
- The controller reads its kubeconfig through the `politeia` crate (git
  dependency pinned to v0.1.1); the in-tree `beep-kubeconfig` crate is gone.
  It parses only an X.509 client-cert kubeconfig file; see `deploy/README.md`
  ("Kubeconfig").

### Known limitations

- kube-proxy IPVS mode is unsupported: kube-proxy binds the published ingress
  addresses (including node addresses) to `kube-ipvs0`, which breaks node
  connectivity. Use iptables or nftables mode.
- Minimum kernel is Linux 6.6; the loader fails fast on older kernels.
- Supported Kubernetes: the latest two minor versions (currently 1.36 and
  1.37), rolling forward with upstream. Older versions are unsupported.

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
  embedded-object gross-size ceiling is 128 KiB (#195, #202).
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
