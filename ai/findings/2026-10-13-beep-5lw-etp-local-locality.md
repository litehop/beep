# kube-proxy eTP=Local behaviour and beep's locality LB design

Bead: beep-5lw
Date: 2026-10-13
Status: research only, no product code changed; operator decisions listed at the end.

**Q1 answer.** With `externalTrafficPolicy: Local`, kube-proxy (iptables and
nftables alike) silently DROPs new connections that arrive on a node with no
ready local endpoint (client sees SYN retransmits and a timeout, no RST, no
ICMP), and REJECTs (ICMP port-unreachable) only when the Service has no usable
endpoint anywhere; the cloud/LB-facing signal is `healthCheckNodePort`, which
returns HTTP 503 on that node.

**Q2 answer.** Everything eTP=Local needs is expressible by the controller
alone through today's `select_endpoint_slot` semantics (emit only local rows
with `count == local_count`; emit count 0 when none are local), plus publishing
`status.loadBalancer.ingress` only from nodes that have a local ready endpoint;
the one optional dataplane change is a silent-drop verdict for count-0 fronts
if the operator wants kube-proxy's DROP instead of beep's settled REJECT.

Label key: **[src]** verified from kubernetes v1.36.5 source, **[live]**
verified on the k3s rig, **[repo]** verified in this repo at the cited
ref, **[mem]** from memory or inference, not verified.

## 1. Versions and mode

- [live] k3s `v1.36.5+k3s1 (3dd98cc5)`, go1.26.8; nodes `lima-beep-node-a`
  (server, 192.168.104.13), `lima-beep-node-b` (agent, 192.168.104.14);
  `beep-client` 192.168.104.15. Kernel 6.8.0-146-generic arm64.
- [live] kube-proxy mode is **iptables** (`curl 127.0.0.1:10249/proxyMode` on
  node-a returned `iptables`; `iptables v1.8.10 (nf_tables)` backend, so rules
  are iptables-nft). The nftables proxier is read from source only.
- [live] No beep DaemonSet was deployed. Rig left as `k3s-up.sh` leaves it
  (kube-system: coredns, local-path-provisioner, metrics-server only; zero
  `etp-research` rules remain in `iptables -t nat` or `KUBE-EXTERNAL-SERVICES`).
  Only residue: `traefik/whoami` and `busybox:1.36` images cached on node-b.
- Source tag: `kubernetes/kubernetes@v1.36.5` (k3s tracks upstream `pkg/proxy`).
  Citations are `path:line` at that tag.

## 2. Upstream behaviour (kube-proxy)

### 2.1 eTP=Local, no local endpoint: DROP, not reject

- [src] `pkg/proxy/iptables/proxier.go:902-932`: `if !hasEndpoints` (no usable
  endpoint anywhere) the external filter verdict is `REJECT`; else if
  `!hasExternalEndpoints` (eTP=Local and `len(localEndpoints)==0`, set at
  `:879-883`) the verdict is `DROP`, comment `"<svc> has no local endpoints"`,
  and the `SyncProxyRulesNoLocalEndpointsTotal{external}` metric increments
  (`:1422-1423`).
- [src] The DROP/REJECT rule is written to `KUBE-EXTERNAL-SERVICES` for
  externalIPs (`:972-984`), LB ingress IPs (`:1009-1023`) and NodePorts
  (`:1048-1060`, with `-m addrtype --dst-type LOCAL`). That chain is hooked
  from filter INPUT and FORWARD on `conntrack --ctstate NEW`
  (`:377-379`). No `KUBE-MARK-DROP` is involved.
- [src] nftables: identical decision at
  `pkg/proxy/nftables/proxier.go:1299-1324` (`goto reject-chain` vs `drop`),
  `rejectChain` defined `:86`, `:568-576`.
- [live] node-a (no local pod) rule: `-A KUBE-EXTERNAL-SERVICES -p tcp -m
  comment --comment "etp-research/whoami-local has no local endpoints" -m
  addrtype --dst-type LOCAL -m tcp --dport 30080 -j DROP`. node-b (has pod):
  chain empty.
- [live] Client to node-a:30080 (pod only on node-b): `curl` exit 28,
  `Connection timed out after 6006 ms`. `tcpdump -i eth0` on node-a saw six
  SYNs (one per second backoff, same seq) and **no RST, no ICMP, no
  SYN-ACK**. Silent drop confirmed.
- [live] Client to node-b:30080: HTTP 200 in 0.9 ms; the pod saw
  `RemoteAddr: 192.168.104.15` (client IP preserved).
- [live] With the Service having NO endpoints anywhere (pod force-deleted):
  client to either node gets `curl: (7) Failed to connect ... Couldn't
  connect`, rule `-j REJECT --reject-with icmp-port-unreachable` with comment
  `has no endpoints`. Confirms the DROP/REJECT split.

### 2.2 eTP=Local with local endpoints: local only, source IP preserved

- [src] `pkg/proxy/topology.go:114-117`: `localEndpoints` = endpoints that are
  `IsLocal() && IsReady()`; external traffic jumps to the Local policy chain
  (`iptables/proxier.go:877-884`, `:1162-1167`). No `KUBE-MARK-MASQ` on the
  Local path (`:1127-1160`), versus `:1120-1126` which masquerades every
  eTP=Cluster external packet.
- [live] eTP=Cluster NodePort on node-a (pod on node-b): HTTP 200 but the pod
  saw `RemoteAddr: 10.42.0.0` (the flannel gateway: SNAT'd, client IP lost);
  eTP=Local on node-b saw the real `192.168.104.15`. beep never source-NATs,
  so beep's eTP=Cluster already behaves like kube-proxy's eTP=Local in this
  respect.

### 2.3 Terminating endpoints

- [src] `topology.go:99-123`: if no local READY endpoint but some local
  `serving && terminating` endpoint exists, `localEndpoints` = the
  serving-terminating local ones (`useServingTerminatingEndpoints`). Same
  fallback independently for Cluster endpoints at `:70-82`. There is no
  feature-gate check on this path in v1.36.
- [src] `hasAnyEndpoints` counts serving-terminating endpoints too
  (`:100-112`), so a node that only has a terminating pod does NOT take the
  DROP branch.
- [live] Pod deleted with a 90 s grace period and `trap '' TERM` (EndpointSlice
  showed `ready:false, serving:true, terminating:true`): client to node-b:30080
  (eTP=Local) returned 200 from the terminating pod; eTP=Cluster via node-a
  also returned 200 (no ready endpoint anywhere, falls back to terminating).

### 2.4 healthCheckNodePort

- [src] `pkg/proxy/healthcheck/service_health.go:241-272`: per-Service HTTP
  listener; `X-Load-Balancing-Endpoint-Weight` = local endpoint count; status
  **200 iff count != 0 and kube-proxy healthy, else 503**; body
  `{"service":{...},"localEndpoints":N,"serviceProxyHealthy":bool}`.
- [src] Count source: `pkg/proxy/endpointschangetracker.go:274-291`
  `LocalReadyEndpoints()`: local **ready** endpoints only, deduped by pod IP.
  Terminating-serving pods are NOT counted, so the health check goes 503 (LB
  drains the node) while kube-proxy still serves in-flight traffic to the
  terminating pod. Wired at `iptables/proxier.go:1435`.
- [src] The port is allocated by the apiserver only for `type=LoadBalancer`
  with eTP=Local; iptables ACCEPTs it in `KUBE-NODEPORTS` regardless of
  endpoints (`iptables/proxier.go:1063-1074`).
- [live] Service `whoami-local` got `spec.healthCheckNodePort: 32031`.
  `curl :32031` on node-a: `HTTP/1.1 503`, `X-Load-Balancing-Endpoint-Weight:
  0`, `localEndpoints: 0`. On node-b: `HTTP/1.1 200`, weight `1`,
  `localEndpoints: 1`. During the terminating-pod test node-b flipped to 503 /
  weight 0 while still forwarding (200) to the terminating pod.
- [mem] Cloud LBs (AWS NLB/CLB, GCP, Azure) probe each node's
  healthCheckNodePort and keep only 200 nodes in rotation.

### 2.5 In-cluster and node-originated traffic under eTP=Local

- [src] `iptables/proxier.go:1127-1160`: for eTP=Local the EXT chain first
  short-circuits pod-originated traffic (`-s <cluster CIDR>`) to the
  **Cluster** policy chain ("simulates going up-and-out to an external load
  balancer and coming back in"), and sends `--src-type LOCAL` (host) traffic
  to the Cluster chain after masquerading. nftables mirror:
  `nftables/proxier.go:1507-1545`.
- [live] `curl node-a:30080` run ON node-a (no local pod) returned HTTP 200:
  host-originated traffic bypasses eTP=Local and hits the remote pod
  (masqueraded). Observed in the iptables dump:
  `route LOCAL traffic ... -j KUBE-SVC-...` and `pod traffic ... -s
  10.42.0.0/16 -j KUBE-SVC-...`. Pod-originated test not run.

### 2.6 internalTrafficPolicy

- [src] `iptables/proxier.go:859-866`: with `internalTrafficPolicy: Local` and
  no local endpoint the ClusterIP rule is `DROP` (`:915-922`) while external
  traffic is unaffected; no endpoints anywhere is `REJECT`. `UsesLocalEndpoints`
  / `UsesClusterEndpoints` in `pkg/proxy/serviceport.go:168-178`.
  Irrelevant to beep (beep handles no ClusterIP traffic).

### 2.7 trafficDistribution

- [src] `staging/src/k8s.io/api/core/v1/types.go:5851-5866`: values
  `PreferSameZone`, `PreferSameNode`, and `PreferClose` (documented as the
  original name of `PreferSameZone`). Feature gate
  `PreferSameTrafficDistribution`: alpha 1.33, beta 1.34, **GA 1.35, locked
  on** (`pkg/features/kube_features.go:1832-1836`), so PreferSameNode exists
  and is on in 1.36.
- [src] kube-proxy does NOT read `spec.trafficDistribution`. The EndpointSlice
  controller turns it into per-endpoint hints
  (`staging/src/k8s.io/endpointslice/trafficdist/trafficdist.go:26-41,112+`:
  `PreferSameNode` additionally sets node hints) and kube-proxy consumes the
  hints in `topology.go:164-218` `topologyModeFromHints`: PreferSameNode only
  if EVERY ready endpoint has a node hint AND one is hinted for this node,
  else PreferSameZone under the same all-hinted/one-local test, else no
  topology. `availableForTopology` (`:223-234`) then restricts
  `clusterEndpoints` to hinted ones. So upstream preference is **prefer with
  fallback to all** per node, evaluated at the ingress node: exactly beep's
  `select_endpoint_slot` shape.
- [src] It applies only to the Cluster-policy endpoint list
  (`topology.go:57-68`); eTP=Local ignores it (`:114-123`).

### 2.8 eTP=Cluster default distribution

- [src] iptables: a chain of `-m statistic --mode random --probability
  1/(n-i)` rules per endpoint, last rule unconditional
  (`iptables/proxier.go:1469-1489`): **uniform random across all ready
  endpoints, no weights, no locality** (with no trafficDistribution). nftables:
  `numgen random mod N map {...}` (`nftables/proxier.go:1788-1796`). Per
  connection (conntrack), not per packet. Not exercised live with N>1.
- [src] Session affinity ClientIP uses an `xt_recent` pre-check
  (`iptables/proxier.go:1447-1467`); beep uses a deterministic seeded
  flow hash instead.

## 3. What beep does today

- [repo] Selection (`origin/main` `common/src/lib.rs:1141-1158`):
  `select_endpoint_slot(hash, ready_count, local_count)` returns `None` if
  `local_count > ready_count`; reduces over `local_count` if `> 0`, else over
  `ready_count`. `ingress_steer` (`:1189-1224`): an existing pin wins over
  everything, including count 0; no pin + `count == 0` -> `Reject`
  (`ebpf/src/main.rs:491`, TCP RST / ICMP unreachable); a row picked from the
  local prefix that lacks `ENDPOINT_FLAG_IS_LOCAL` -> `Drop` (`:1216`).
  `FrontMeta.local_count` at `:296-304`, flag at `:337`.
- [repo] Controller (W-AE's unpushed `6ff3995` on
  `worker/agent-a064e544c0d482cdd`, `controller/src/reconcile.rs:~455-520`):
  every ready, non-terminating, same-family endpoint with the port gets a slot,
  `sort_by_key(!is_local, pod_ip)`, `IS_LOCAL` set per `is_local(ep, node)`,
  `local_count` derived from the flagged prefix. A front with no candidate
  keeps `FRONT_META` at count 0. Fronts are per-node programmed: the same
  Service yields different `local_count` on different nodes.
- [repo] The controller does not read `spec.externalTrafficPolicy`,
  `spec.internalTrafficPolicy`, `spec.trafficDistribution`, or
  `spec.healthCheckNodePort` (grep over `controller/src` at `6ff3995`: only
  `status.*` hits).
- [repo] Status publishing is per-node (`controller/src/status.rs`
  `ensure_node_ingress` / `merged_ingress`): each node's controller adds and
  prunes only its own address(es) in `status.loadBalancer.ingress`, driven by
  `WatchState::ips_to_publish` (`watch.rs:494-515`). Publishing is already
  structured to be conditional per node.
- [repo] Departed-backend eviction input `cluster_backends`
  (`reconcile.rs:407`) is built from ALL endpoints including unready, and does
  not depend on any traffic policy.
- Settled operator decisions (bead notes, 2026-10-09): node-local preference in
  v1 (prefer local if any, else hash over all); terminating-but-serving
  excluded from NEW selections, pinned flows continue; owned front with 0 ready
  backends REJECTs; a front-meta miss passes to host.

## 4. Design brief

### 4.1 What is controller vs dataplane vs status

| Knob | Controller emission | Dataplane (`select_endpoint_slot`/`ingress_steer`) | Status |
|---|---|---|---|
| eTP=Cluster, no trafficDistribution | all ready + IS_LOCAL flags + `local_count` (as `6ff3995`), or `local_count = 0` to force uniform | unchanged | publish every node |
| eTP=Local | only local ready rows; every row IS_LOCAL; `count == local_count == n_local` | unchanged: hashes over `local_count`; no fallback possible because remote rows are absent | publish only nodes with `n_local > 0` |
| eTP=Local, none local | `FRONT_META` count 0 (or no front) | `Reject` today; optional new Drop verdict for kube-proxy parity | node not in ingress |
| trafficDistribution PreferClose/SameZone/SameNode | see 4.4 | unchanged | publish every node |

### 4.2 eTP=Cluster default: uniform (spec-faithful) vs prefer-local (current)

- Upstream is uniform random over all ready endpoints [src 2.8]; only an explicit
  `trafficDistribution` (hint-driven) opts into locality [src 2.7].
- beep today prefers local whenever any exists (operator 2026-10-09).
- Trade-off: prefer-local saves the Geneve hop and keeps the cross-node reply
  path off the wire, but when replicas are unevenly spread the per-pod load
  skews: with the external LB spreading evenly over nodes, a node holding 1 of
  4 pods sends 100% of its share to that one pod. (This is MetalLB's own
  documented eTP=Local caveat: `metallb.io/usage` "treats each cluster node
  as one unit ... may result in traffic imbalances" [src: fetched
  2026-10-13].) Uniform is predictable and matches what a user reading the
  Service spec expects; locality is then an explicit user choice via
  `trafficDistribution`.
- Cost to switch to uniform-by-default: controller-only. Emit `local_count = 0`
  unless the Service asks for preference (4.4). No dataplane change. The
  `IS_LOCAL` flag on rows is then merely informational.
- Recommendation: make uniform the default for eTP=Cluster and map
  `trafficDistribution: PreferClose|PreferSameZone|PreferSameNode` to the
  current prefer-local behaviour. This reverses the 2026-10-09 default (an
  operator call, see section 6) but keeps the shipped mechanism and makes
  beep spec-faithful. The conservative alternative is to keep prefer-local as
  default and document the divergence.

### 4.3 eTP=Local

Emit only local rows. Dataplane needs nothing:

- `count = local_count = n_local > 0`: `select_endpoint_slot` reduces over
  `local_count` (`common/src/lib.rs:1152-1157`); every chosen row has IS_LOCAL
  so the `:1216` check passes. A node-local flow can never leave the node
  because there are no remote rows to hash to.
- Pinned (established/pending) flows keep winning over a changed table
  (`:1197-1202`), the same property that makes endpoint churn safe today.

No local endpoint: three options.

| Option | beep mechanics | Client sees | Upstream parity | Notes |
|---|---|---|---|---|
| A. count-0 front (REJECT) | controller emits `FRONT_META count 0` | RST / ICMP unreachable, fast failure | differs (kube-proxy DROPs) | zero code beyond emission; consistent with settled decision #3; an LB health-check or a client hitting a stale node fails fast instead of hanging |
| B. silent drop | new `IngressSteer::Drop` path for a count-0 front, e.g. a front flag | timeout | matches kube-proxy [src 2.1] | needs a `FrontMeta` flag in `beep-common` (layout-safe: `FrontMeta` has explicit padding for new fields, see tests at `common/src/lib.rs:1553-1561`) plus dataplane branch; client hangs until timeout |
| C. no front (pass to host) | controller emits no `FRONT_META` for that node | whatever the host does: with kube-proxy running and beep's node IPs in `status.loadBalancer.ingress`, kube-proxy has rules for those LB IPs [src `:988-1008`] and would DROP (eTP=Local, no local) or serve; without kube-proxy, kernel RST | indirect | contradicts the settled "owned front with 0 ready -> reject, NOT pass-to-host (host stack could answer misleadingly)" ; also makes beep's behaviour depend on kube-proxy being present. Not recommended |

Recommendation: **A** (count-0 REJECT) with no dataplane change. Rationale:
a client only reaches such a node if it ignores the published ingress (stale
cache, or a LB not health-checking), and a fast RST is strictly more useful
than kube-proxy's hang; correctness is the same (the packet is never
delivered to a non-local pod, source IP never lost). Option B is a small
follow-up if parity with kube-proxy (e.g. stealth, or conformance expecting a
timeout) is demanded. [mem] I did not check whether the upstream
conformance specs assert a timeout rather than a refusal; the rig's four
eTP=Local specs pass today, since they only exercise nodes with endpoints and
the healthCheckNodePort served by kube-proxy.

### 4.4 trafficDistribution

Upstream: PreferClose = PreferSameZone (zone hints); PreferSameNode (node
hints) exists and is GA-locked-on in 1.36 [src 2.7]. beep has no zone concept;
the only locality beep can express is node-local (`local_count`). Mapping:

- `PreferSameNode` -> exactly beep's prefer-local-with-fallback
  (`local_count = n_local`, remote rows kept as fallback). Spec-faithful.
- `PreferClose` / `PreferSameZone` -> beep cannot honour zones; the closest
  safe approximation is the same node-local preference (a node's pods are in
  the node's zone), or uniform if the operator wants strictness. Either is a
  documented deviation. Zone hints could later be read from EndpointSlice
  `endpoints[].hints.forZones` and `Node` `topology.kubernetes.io/zone`, but
  this adds controller state for modest value. [mem] not verified that
  `hints.forNodes` is populated in practice on a given cluster.
- Hints vs spec: kube-proxy trusts the EndpointSlice controller's hints
  [src 2.7]. beep can read `spec.trafficDistribution` directly (simpler, no
  dependence on hint propagation) with identical outcome for the node case,
  or read `hints.forNodes` for strictest parity. Reading the spec field is the
  smaller change.
- Interaction with eTP: upstream applies trafficDistribution only to Cluster
  policy [src 2.7]. beep: eTP=Local wins, trafficDistribution ignored.

### 4.5 Terminating-endpoint fallback for eTP=Local

Upstream serves new flows to local serving-terminating endpoints when there is
no ready local one [src 2.3, live-confirmed], and its health check goes 503 at
the same time so external LBs drain the node (the pod is a graceful-drain
target, not a steady-state one).

beep's settled decision (2026-10-09) is the opposite: terminating excluded
from NEW selections, pinned flows drain. Effect for eTP=Local: the instant a
node's last local pod turns terminating, new flows get REJECT (4.3-A) while
already-pinned flows continue. This is a deliberate deviation. Cheap
parity if wanted later: controller-only, when `n_local_ready == 0` and some
local pod is serving-terminating, emit those as local rows (`conditions.serving`
and `conditions.terminating` are already parsed:
`reconcile.rs:217-219`; `serving` is not yet a field of `Endpoint`). Recommend
NOT doing this in v1; it contradicts the settled decision and has a
mid-handshake-reset risk.

Status side: a node is published iff it has a local READY, non-terminating
endpoint (same predicate as kube-proxy's health count [src 2.4]), so
terminating drains the node from the published ingress at the same moment new
flows start being refused: correct ordering.

### 4.6 status.loadBalancer.ingress as the healthCheckNodePort analogue

- Cloud LBs consume `healthCheckNodePort` rather than ingress (the LB IP is
  the cloud LB's own address) [mem]. For beep the node IPs ARE the LB, so the
  published ingress list is the only discovery surface, and listing only nodes
  with local ready endpoints is the faithful analogue.
- Upstream LB-controller practice: MetalLB BGP mode with `Local` policy only
  announces from nodes that run a pod ("nodes will only attract traffic if they
  are running one or more of the service's pods locally",
  `metallb.io/usage` [src: fetched 2026-10-13]); layer2 mode elects one node
  (also restricted to nodes with endpoints, [mem]). Cloud providers: all
  healthy-node discovery via the health check, [mem]. So per-node conditional
  publication is established practice, and beep's per-node publisher
  (`ensure_node_ingress`/`merged_ingress`) already prunes its own entries
  when `ips_to_publish` shrinks.
- Required change: `ips_to_publish` (or its caller) must return empty for an
  eTP=Local Service on a node with no local ready endpoint; endpoint-slice
  events must trigger republication (today republish is driven by Node and
  Service events; `publish_ingress_for` is called from the Service/slice
  paths, `main.rs:452,465`, so verify it fires on slice events when
  implementing). Staleness: ingress write latency (one PATCH) is the window in
  which a node with no endpoint still receives traffic; kube-proxy has the
  same window with LB health-check intervals.
- Because kube-proxy (when present) also serves `healthCheckNodePort` from
  the same EndpointSlices, an external LB doing health checks keeps working
  without beep implementing a health server; the rig's passing eTP=Local specs
  rely on that. A kube-proxy-less cluster would need beep to serve it: out of
  scope for v1, flag only.
- Dual-stack/IPv6-only (firm constraint 2026-09-10): publication is per family;
  the "has local endpoint" test must be per family (a v4-only local pod must
  not publish the v6 address; the `6ff3995` candidate filter is already
  same-family).

### 4.7 Is any dataplane change required?

No, for the recommended v1: all of Cluster-uniform, Cluster-prefer-local,
Local, and Local-none-local(REJECT) are expressible by what the controller
emits against unchanged `select_endpoint_slot` / `ingress_steer`
(`common/src/lib.rs:1148, 1189`). Optional: kube-proxy-parity DROP for count-0
on a Local front (4.3-B). Positive-identification principle is respected: all
paths are an owned front (a `FRONT_META` hit); unowned traffic still passes.

One caution: `local_count = 0` (uniform) is already the encoding used on a node
with no local pod; `ingress_steer` allows IS_LOCAL-less rows exactly then
(`:1216`). A controller change that forces `local_count = 0` for uniform while
still flagging rows IS_LOCAL is harmless (flag unchecked when `local_count ==
0`).

### 4.8 Pin-steering, eviction, capacity

- Pin-steering: established/pending pins override the table (`:1197-1202`), so
  switching a Service Cluster->Local (or editing trafficDistribution) never
  moves live flows; only new flows follow the new table. Matches kube-proxy's
  conntrack behaviour [mem].
- Eviction (`bd memories eviction-churn`): eviction is driven by departed pod
  IPs (`cluster_backends` is policy-independent, `reconcile.rs:407`;
  `evict_pod_flows` in `src/lib.rs:349`). A policy flip to Local does NOT
  evict existing pins to remote pods (they are not "departed"): they live
  until FIN/timeout/LRU. Not a correctness bug (kube-proxy conntrack also
  persists), but the operator should know eTP=Local is not an instant cutoff.
  A remote pod that departs still gets its pins evicted as today.
  An eTP=Local node must still pin and evict LOCAL pods identically.
- Capacity: eTP=Local shrinks `FRONT_ENDPOINTS` rows per node (only local
  pods), strictly fewer than today's all-ready emission; sizing flags derived
  from endpoint counts only get easier. Uniform default emits the same rows as
  prefer-local, so no change. The count-0 front still consumes one
  `FRONT_META` row.
- Generation swap: a locality or policy change alters `local_count`/rows at
  constant endpoint set; `6ff3995`'s `a_locality_change_alone_republishes_the_front`
  test shows the planner already republishes on that; eTP/trafficDistribution
  changes need the same trigger (the desired `FrontMeta` differs, so it
  should fall out of the existing diff).

## 5. Recommended v1 behaviour matrix

Rows: policy x distribution x whether THIS ingress node has a local ready
endpoint. "Fallback" means remote rows are emitted after the local prefix.

| eTP | trafficDistribution | Local ready endpoint on ingress node | beep emission / selection | Ingress node in status |
|---|---|---|---|---|
| Cluster | unset | yes | all ready, `local_count = 0`: uniform over all (recommended; today: prefer local) | yes |
| Cluster | unset | no | all ready, uniform | yes |
| Cluster | PreferSameNode | yes | all ready, `local_count = n_local`: hash over local only | yes |
| Cluster | PreferSameNode | no | all ready, `local_count = 0`: uniform over all (fallback) | yes |
| Cluster | PreferClose / PreferSameZone | yes | as PreferSameNode (documented deviation: no zone concept) | yes |
| Cluster | PreferClose / PreferSameZone | no | uniform over all | yes |
| Local | any (ignored) | yes | only local rows, `count = local_count`; hash over local | yes |
| Local | any (ignored) | no | `FRONT_META count 0`: new flows REJECTED (RST/ICMP); pinned flows continue | **no** |
| Local, last local pod terminating | any | no ready, 1+ terminating-serving | same as "no": new flows REJECTED (deviates from kube-proxy [src 2.3]); pinned flows drain | no |
| any | any | zero ready anywhere | count 0 front: REJECT (settled) | Cluster: yes (stateless node IP); Local: no |

Status caveat for the last row: Cluster-policy nodes stay published even when
the Service has zero endpoints (upstream also still publishes the LB IP and
REJECTs).

## 6. Operator decisions needed

1. **eTP=Cluster default**: switch to uniform (spec-faithful; reverses the
   2026-10-09 "node-local preference in v1" for the unset case, with
   `PreferSameNode`/`PreferClose` opting into it), or keep prefer-local as the
   default and document the divergence? (4.2)
2. **eTP=Local with no local endpoint**: REJECT via count-0 front (recommended;
   no dataplane change), silent DROP for kube-proxy parity (small
   `FrontMeta`-flag + dataplane branch), or no front/pass-to-host? (4.3)
3. **trafficDistribution mapping**: read `spec.trafficDistribution` directly
   in the controller (smaller) or consume EndpointSlice hints (parity)? Map
   `PreferClose`/`PreferSameZone` to node-local approximation, or ignore
   (uniform) until zones are implemented? (4.4)
4. **Terminating-serving local endpoints under eTP=Local**: keep the settled
   exclusion (recommended) or adopt kube-proxy's serving-terminating fallback
   for local-only? (4.5)
5. **Status publication**: publish only nodes with a local ready endpoint for
   eTP=Local (recommended). Confirm this lands in the same change as the
   emission filter, since emission alone leaves clients hitting REJECT nodes. (4.6)
6. **Policy-flip eviction**: accept that Cluster->Local does not evict
   existing remote pins (matches kube-proxy conntrack), or add a policy-aware
   sweep? (4.8)
7. **Health check server**: confirm beep relies on kube-proxy for
   `healthCheckNodePort` in v1 (kube-proxy-less clusters unsupported for
   eTP=Local discovery). (4.6)

## 7. Live test log (condensed)

All on 2026-10-13 ~13:44-13:47Z (rig clocks JST 22:44-22:47). Namespace
`etp-research`, deleted afterwards. Service `whoami-local` (LoadBalancer,
eTP=Local, `nodePort 30080`, `healthCheckNodePort 32031`, pending since
servicelb is disabled) and `whoami-cluster` (NodePort, 30081), pod pinned to
node-b via nodeSelector; later `busybox httpd` with `trap '' TERM` for the
terminating window, because `traefik/whoami` is a scratch image with no
`sleep` for a preStop hook.

| Test | Result |
|---|---|
| client -> node-a:30080 (eTP=Local, no local pod) | exit 28 timeout; tcpdump on node-a: 6 SYNs, no RST/ICMP |
| client -> node-b:30080 | 200, 0.9 ms, pod saw real client IP 192.168.104.15 |
| client -> node-a:32031 / node-b:32031 | 503 weight 0 / 200 weight 1 |
| client -> node-a:30081 (eTP=Cluster) | 200, pod saw 10.42.0.0 (SNAT) |
| on node-a -> node-a:30080 | 200 (host traffic short-circuits to Cluster chain) |
| Terminating serving pod: node-b:30080 / node-b:32031 / node-a:30081 | 200 / 503 weight 0 / 200 |
| No endpoints anywhere: node-a:30080, node-b:30081 | `connect` refused (ICMP port-unreachable), iptables `REJECT` rules with `has no endpoints` |
