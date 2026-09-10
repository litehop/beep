# sonobuoy/e2e spec selection for north-south LB + real-client-IP

Bead: beep-x64

**Verdict:** run five upstream sig-network specs (below) via a plain
compiled `e2e.test --ginkgo.focus=...` binary, not sonobuoy. No
`--provider`/skip-regex un-skip mechanic is needed — the "cloud-provider-
gated `[Skipped:...]`" premise describes a pre-~1.24 kubernetes/kubernetes
convention that no longer exists in the current in-tree suite. But none
of the specs can pass on this project's stack today: `beep-controller`
never writes `Service.status.loadBalancer.ingress`, which every one of
these specs polls before doing anything else. That gap — not spec
selection — is the actual blocker, and is filed as a follow-on bead
below.

Evidence below is grounded in `test/e2e/network/{loadbalancer,service}.go`
and `test/e2e/framework/{test_context,provider,service/jig}.go` fetched
live from `kubernetes/kubernetes@master` (2026-09-10), plus this repo's
`controller/src/{main,watch,reconcile,apply}.rs`, `docs/design/
ebpf-lb-dataplane.md`, and `scripts/k3s-up.sh`.

## 1. Recommended focus-list

Primary (minimal set that genuinely proves north-south delivery + real
client IP for beep's node-owned-VIP model):

- **`LoadBalancers ExternalTrafficPolicy: Local should work for
  type=LoadBalancer`** (`loadbalancer.go:1016`). Creates an ETP=Local LB
  Service, waits for `status.loadBalancer.ingress`, does an HTTP GET
  against `ingressIP:svcPort` from outside the cluster, reads the
  backend's observed client IP from the response body, and fails if that
  IP falls inside the node's own `/16` (i.e. was masqueraded). This is
  the single spec that checks both halves of the bead's goal in one run.
  beep's design preserves client IP unconditionally (symmetric Geneve
  return, `docs/design/ebpf-lb-dataplane.md` step 4: "Pod sees the real
  client IP at L3"), not just under ETP=Local, so this spec exercises
  exactly the property beep claims regardless of its "ETP=Local" label.
- **`... should work from pods`** (`loadbalancer.go:1221`). Same
  delivery/source-IP check, but the client is an in-cluster pod dialing
  the external VIP rather than a true off-cluster client. Worth keeping
  because Lima's "external" client is itself just another VM on the same
  L2/VPN — this spec's assumptions are closer to what the Tier-2 rig can
  actually exercise than a genuine off-cluster client would be.
- **`... should only target nodes with endpoints`** (`loadbalancer.go:1081`)
  and **`... should target all nodes with endpoints`**
  (`loadbalancer.go:1174`). Together these prove beep's "any node can be
  ingress" design claim (`controller/src/main.rs:173`'s comment) actually
  holds for multi-node delivery — that a client dialing a node with no
  local backend still gets routed to a backend elsewhere via Geneve.

Secondary / regression-tier, not required to prove the goal but useful
once the primary four are green:

- **`LoadBalancers should be able to change the type and ports of a TCP
  service`** (`loadbalancer.go:132`). Proves basic external reachability
  as one assertion among many (ClusterIP→NodePort→LoadBalancer→teardown,
  port/NodePort mutation) — broader regression coverage, not a targeted
  client-IP proof, and `[Slow]`.
- **UDP flow-affinity-under-pod-cycling specs** (`loadbalancer.go:707`,
  `loadbalancer.go:841`). Prove beep's own conntrack/flow-affinity design
  goals for LB-fronted UDP survive backend churn — relevant to beep's
  dataplane correctness generally, not specifically to the client-IP
  question this bead scopes.

Explicitly excluded, with reason:

- **`should only allow access from service loadbalancer source ranges`**
  (`loadbalancer.go:422`) — exercises `spec.loadBalancerSourceRanges`,
  which beep's controller does not implement (no ACL/allow-list code path
  in `controller/src/reconcile.rs`). Would correctly fail; add only if/
  when that feature ships.
- **Session-affinity-for-LoadBalancer specs** (`loadbalancer.go:565-609`)
  — test `sessionAffinity=ClientIP` hashing consistency, orthogonal to
  north-south delivery/client-IP preservation.
- **Rolling-update disruption specs** (`loadbalancer.go:975-993`) —
  availability/disruption-focused, `[Slow]`, not a delivery or
  client-IP proof.
- **`should implement NodePort and HealthCheckNodePort correctly when
  ExternalTrafficPolicy changes`** (`service.go:3836`) — exercises
  `type=NodePort`, which is kube-proxy's existing, unmodified path per
  beep's design (beep fronts `type=LoadBalancer` VIP:PORT traffic only).
  Not a beep-dataplane proof; it's exactly the "east-west untouched"
  boundary mayor-waqhd verifies.
- **`should complete a service status lifecycle`** (`service.go:3272`,
  `[Conformance]`) — manually PATCHes `.status.loadBalancer` itself to
  test the apiserver's status subresource API; no real LB traffic
  involved. Informative about the apiserver, not about beep.

## 2. Un-skip mechanics

**None needed.** Checked directly against `kubernetes/kubernetes@master`
(2026-09-10):

- `grep -n "SkipUnlessProviderIs\|Skipped:" test/e2e/network/{loadbalancer,service}.go`
  returns nothing for either the general LoadBalancer family or the ESIPP
  family. Neither carries a `[Skipped:<provider>]` tag or a
  `SkipUnlessProviderIs`/`SkipIfProviderIs` call. That convention (inline
  `[Skipped:gce]`-style tags baked into spec names) is from older
  (pre-~1.24) kubernetes releases and is gone from the current in-tree
  suite — the bead's premise that these are still gated that way does
  not hold against current upstream source.
- `--provider` unset defaults `framework.TestContext.Provider` to
  `"skeleton"` (`test_context.go:525-529`), which resolves to
  `NullProvider{}` (`provider.go:61-65`) — a genuine no-op implementation
  of the handful of cloud-specific calls these tests make
  (`EnsureLoadBalancerResourcesDeleted`, `CleanupServiceResources`). So
  `--provider=local` (or leaving it unset) is already correct for a
  self-hosted cluster; there is no special flag value to discover.
- The one real upstream gate is sonobuoy/e2e.test's own conformance-focus
  convention: neither family carries `[Conformance]`, so a
  `--ginkgo.focus='\[Conformance\]'` run (sonobuoy's default
  `non-disruptive-conformance`/`certified-conformance` modes) excludes
  them by construction. This is trivially bypassed by naming the specs
  directly in `--ginkgo.focus`/`E2E_FOCUS`, not a wiring problem.
- **The actual, load-bearing blocker is not a skip mechanic at all**: see
  §4.

## 3. sonobuoy vs plain `e2e.test`

**Recommend plain `e2e.test`/`ginkgo run` invocation, not sonobuoy.**
Sonobuoy's value (`E2E_FOCUS`/`E2E_SKIP` env vars, `sonobuoy run`/
`sonobuoy e2e --mode=tags` dry-run tooling, an in-cluster aggregator pod
plus results-tarball collection — confirmed against sonobuoy's own
`e2eplugin.md`) targets running the *same* suite reproducibly across many
unrelated clusters/vendors for CNCF conformance certification submission.
beep is hand-picking five specs against its own single Lima rig / CI
runner — a compiled `e2e.test --kubeconfig=<...> --provider=local
--ginkgo.focus='<regex>'` binary does that directly, with no aggregator
pod, RBAC, or plugin sandbox to deploy and debug, matching this project's
existing pattern of running binaries/scripts directly (`scripts/
smoke.sh`) rather than standing up cluster-side test infrastructure.
Revisit sonobuoy only if beep later pursues an actual CNCF Certified
Kubernetes Conformance submission — a different goal than this bead's.

## 4. Per-spec Lima-runnable verdict

All five recommended specs share one blocking prerequisite before any of
them can even reach their first assertion:

**`beep-controller` never populates `Service.status.loadBalancer.ingress`.**
`grep -rn "status\|ingress\|Ingress" controller/src/*.rs` finds no status-
patch code path in any of the four controller source files
(`main.rs`, `watch.rs`, `reconcile.rs`, `apply.rs`, 1908 lines total).
Every recommended spec's entry point —
`jig.WaitForLoadBalancer`/`jig.CreateOnlyLocalLoadBalancerService`
(`test/e2e/framework/service/jig.go:589-604`) — polls exactly that field
and nothing else before doing any traffic assertions. Nor does the Lima
Tier-2 rig substitute a status-writer: `scripts/k3s-up.sh:40` starts k3s
with `--disable=servicelb,traefik`, so k3s's own klipper-lb never runs
either. **On the current stack, every one of these specs will time out
at its first `WaitForLoadBalancer` call regardless of whether the
dataplane forwards packets correctly or preserves client IP.** This is
independent of the spec-selection question this bead was scoped to
answer, but it's the fact that actually determines "Lima-runnable" today,
so it is called out here rather than silently assumed away.

Once that gap is closed (see follow-on bead below), the per-spec verdict
against the 2-node k3s-on-Lima Tier-2 rig (flannel VXLAN, kube-proxy,
node-a + node-b) is:

| Spec | Node count needed | Lima-runnable once status lands? |
|---|---|---|
| `should work for type=LoadBalancer` | 1 | Yes — single endpoint, single node. |
| `should work from pods` | 1 | Yes — same shape, in-cluster client. |
| `should only target nodes with endpoints` | ≥2 | Yes, but exactly at Lima's ceiling (2 nodes) — zero headroom versus upstream's `MaxNodesForEndpointsTests`/anti-affinity assumptions; not a substitute for a larger fleet if flakiness shows up at scale. |
| `should target all nodes with endpoints` | ≥2 | Same as above. |
| `should be able to change the type and ports of a TCP service` | 1 | Yes, mechanically — `[Slow]`, multi-minute; fine for nightly/manual, not a fast PR gate. |
| UDP pod-cycling specs (`:707`, `:841`) | 1–2 | Yes, mechanically — also `[Slow]`. |

**None of the recommended specs need a real multi-node cloud fleet.**
That is the entire point of the `skeleton`/self-hosted provider path
(§2): a real fleet only becomes necessary for questions this bead was
not asked to answer — larger endpoint fan-out, genuine WAN latency, or
coexistence with an actual cloud LB controller.

## 5. Open questions / follow-on work

1. **Populate `Service.status.loadBalancer.ingress` in beep-controller.**
   The single blocking prerequisite (§4) for every recommended spec, and
   for any future upstream LoadBalancer e2e coverage generally — not
   specific to sonobuoy/conformance. Filed as a follow-on bead (see
   below); it blocks `mayor-g9l0f`'s eventual CI/gate wiring, since there
   is nothing to gate on until this lands.
2. **kube-proxy/status-IP overlap.** Once beep-controller patches
   `status.loadBalancer.ingress` with the node's own address, kube-proxy
   independently watches that same field and will program its own
   `KUBE-FW`/`KUBE-XLB` iptables chains for it — a second dataplane
   claiming the same address beep's tc-bpf classifier already owns. This
   is squarely `mayor-waqhd`'s "no double-processing between kube-proxy
   and this dataplane" coexistence check; not resolved here, just
   flagged so the status-population follow-on doesn't get built in
   ignorance of it.
3. **`LoadBalancerIngress.IPMode`.** `loadbalancer.go:1054-1056` skips the
   primary spec entirely if `ingress.IPMode == Proxy` (tracking
   `https://issues.k8s.io/123714`, still unresolved upstream as of this
   writing). Whoever implements the status-population follow-on should
   leave `IPMode` unset (defaults to VIP semantics) to avoid the new code
   accidentally self-skipping the spec it exists to unblock.
4. **e2e.test/ginkgo version pinning.** `scripts/k3s-up.sh` installs
   whatever k3s release `get.k3s.io` currently resolves to (no
   `INSTALL_K3S_VERSION` pin) — whoever wires the focus-list into CI
   (`mayor-g9l0f`) needs to pick a `kubernetes-test-linux-amd64.tar.gz`
   (or build-from-source) version tracking that k3s minor, or accept
   version skew. Not resolved here; it's a CI-wiring decision.
5. **Features this focus-list deliberately excludes** —
   `loadBalancerSourceRanges` enforcement and LB session affinity — are
   real Service-API surface beep doesn't implement yet (§1's exclusions).
   Not urgent; noted so a future "focus-list v2" isn't a surprise once/if
   those features ship.

## Cross-references

- `mayor-g9l0f` owns turning this focus-list into actual CI/gate wiring
  once the status-population follow-on lands and `mayor-waqhd` (Phase 6
  coexistence) is green. This bead does not touch CI.
- `mayor-waqhd` owns the kube-proxy coexistence verification that open
  question 2 above feeds into.
- `mayor-elmno` (podIP-allowlist/node-ipam conformance-harness fidelity)
  was reviewed for context per the dispatch brief; it concerns a
  different control-plane admission gap (KCM node-ipam-controller being
  disabled on the conformance harness) unrelated to the ServiceLB
  north-south path this bead investigates. No overlap found.
