# e2e LoadBalancer test-harness proposal (primary + secondary specs) on k3s-on-Lima

Bead: beep-5xm

**Verdict:** a new `scripts/e2e-lb-k3s.sh` reuses `scripts/k3s-up.sh`'s
2-node cluster and the `beep-client` VM (already the martian-source-safe
external-client role in `smoke-k3s-controller.sh`) to run a
version-matched, dynamically-downloaded `e2e.test` binary with one
`--ginkgo.focus` regex covering all 6 specs, as a manual/nightly
Lima-tier gate — **not** a PR gate, and it will not go green until
`beep-v2c` (cross-node return-path bug) is fixed. It doubles as a
`beep-v2c` repro in the meantime.

Grounded in: `git show f1bf5ff:ai/findings/2026-09-10-beep-x64-sonobuoy-spec-selection.md`
(spec selection, `--provider` verdict), `scripts/k3s-up.sh`,
`scripts/smoke-k3s-controller.sh`, `controller/src/status.rs`,
`.github/workflows/ci.yaml`, `bd show beep-v2c`, and the upstream
`test/e2e/network/loadbalancer.go` source cached locally at
`/private/tmp/loadbalancer.go` from beep-x64's 2026-09-10 fetch of
`kubernetes/kubernetes@master` (read directly for this proposal to pull
exact spec text and decorator calls — see §2 for a correction this
turned up against the task brief's Slow-tag assumption).

## 1. `e2e.test` acquisition + version pin

`scripts/k3s-up.sh` installs whatever `get.k3s.io` currently resolves to
— no `INSTALL_K3S_VERSION` pin. Hardcoding a version string into the new
script would drift the day k3s's "latest" moves. Instead, resolve at
run time: k3s's version string `vX.Y.Z+k3sN` is built directly on
upstream Kubernetes `vX.Y.Z` (a documented, exact mapping, not an
approximation) — confirmed live and current on this rig via `bd show
beep-v2c`'s 2026-09-11 repro: `k3s v1.36.4+k3s1`.

Proposed script step:
```bash
K3S_VER=$(limactl shell "$VM_A" -- sudo k3s --version | awk '/^k3s version/{print $3}')
K8S_VER="${K3S_VER%%+*}"                      # v1.36.4+k3s1 -> v1.36.4
curl -sfL -o e2e-tests.tar.gz \
  "https://dl.k8s.io/${K8S_VER}/kubernetes-test-linux-arm64.tar.gz"
```
**arm64, not amd64**: the Lima VMs (`beep-node-a`/`-b`/`-client`) are
aarch64 — beep-x64's findings named the amd64 tarball generically; this
is the correction for this rig. Cache the extracted
`kubernetes/test/bin/{e2e.test,ginkgo}` by `$K8S_VER` under e.g.
`~/.cache/beep-e2e/$K8S_VER/` so a re-run with an unchanged k3s version
skips the ~400 MB download. `e2e.test` bundles ginkgo v2 and accepts
`--ginkgo.*` flags directly (confirmed in beep-x64's findings) — no
separate `ginkgo run` wrapper needed. Build-from-source is a fallback
only if `dl.k8s.io` ever lacks an arm64 tarball for the resolved minor
(unlikely for any currently-supported k3s release).

## 2. Invocation

Run `e2e.test` from the `beep-client` VM (already on the same Lima
network, already the sanctioned non-node external client per
`smoke-k3s-controller.sh`'s header — co-locating the test process with
a node causes martian-source drops for the very reason that script
documents), with the kubeconfig rewritten the same way
`smoke-k3s-controller.sh` already rewrites it (`server:` from
`127.0.0.1` to node-a's real address):

```bash
limactl shell beep-client -- ./e2e.test \
  --kubeconfig=/tmp/beep-e2e-kubeconfig \
  --provider=local \
  --ginkgo.focus='LoadBalancers ExternalTrafficPolicy: Local (should work for type=LoadBalancer|should work from pods|should only target nodes with endpoints|should target all nodes with endpoints)|LoadBalancers (should be able to change the type and ports of a TCP service|should be able to preserve UDP traffic when server pod cycles for a LoadBalancer service on (different|the same) nodes)'
```
`--provider=local` and the unset default (`skeleton`) are byte-identical
(`test/e2e/framework/provider.go:60-65`: both register a bare
`NullProvider{}`) — `local` is chosen only because it reads as intent
in a script another engineer will maintain, not because it changes
behavior.

**Correction to the task brief's Slow-tag framing**, found by reading
the actual `It`/`SIGDescribe` call sites in the cached source rather
than trusting the summary: the primary 4 and the secondary 2 have the
Slow label **backwards** from what was assumed. The primary 4 are all
declared inside `SIGDescribe("LoadBalancers ExternalTrafficPolicy:
Local", feature.LoadBalancer, framework.WithSlow(), func() {...})`
(`loadbalancer.go:994`) — a container-level `framework.WithSlow()`
decorator that every spec inside inherits, so `:1016`, `:1081`, `:1174`,
and `:1221` are **all** Slow. Of the secondary 3, only `:132` carries
its own `f.WithSlow()` (`loadbalancer.go:132`); the two UDP
flow-affinity specs (`:707`, `:841`) carry **no** Slow decorator at all
(verified: their `ginkgo.It(...)` calls have no `f.WithSlow()`/
`framework.WithSlow()` argument, unlike every sibling spec in that same
file). Net effect: **5 of the 6 chosen specs are Slow**, not "the
primary 4 fast, secondary 2 slow" — this doesn't change the gate
recommendation (§4 already puts the whole focus-list off the fast path)
but the wiring bead should not assume the two UDP specs are cheap;
they still run multi-minute pod-cycling scenarios by their own logic,
just without the formal Slow label. `framework.WithSlow()` is a
structured Ginkgo `Label`, not a bracket string baked into the spec
name, so it does not appear in `--ginkgo.focus` text matching — no
`--ginkgo.skip`/`--ginkgo.label-filter` is needed to include or exclude
it here, since every spec in the focus list is meant to run regardless.
Recommend the wiring bead confirm spec resolution with
`--ginkgo.dry-run --ginkgo.focus='<regex>'` before the first real run,
standard practice for any new hand-built focus regex.

## 3. Rig integration

New script `scripts/e2e-lb-k3s.sh`, parallel to (not a merge into)
`scripts/smoke-k3s-controller.sh`:
- calls `scripts/k3s-up.sh --vm-a --vm-b` exactly like
  `smoke-k3s-controller.sh` does, so both gates share one idempotent
  cluster-bringup path;
- deploys `deploy/rbac.yaml` + `deploy/daemonset.yaml` the same way
  (this harness is meaningless without the controller live — the specs
  poll `status.loadBalancer.ingress`, which only the controller writes);
- downloads/caches `e2e.test` per §1, copies it + the rewritten
  kubeconfig into `beep-client`, runs the focus list, and captures
  ginkgo's JUnit XML output back to the host for inspection;
- teardown: same `trap cleanup EXIT` pattern — delete the Namespaces the
  e2e run creates (ginkgo's own per-spec framework does this on success;
  the trap is the safety net for a Ctrl-C or the CONTROLLER-DEPLOY-style
  early exit), then delegate to `k3s-up.sh`'s idempotent VMs (no VM
  teardown — same convention `smoke-k3s-controller.sh` follows).

Not extending `smoke-k3s-controller.sh` itself: that gate's job is
proving the controller's *own* watch-to-map-programming pipeline with a
hand-rolled `whoami` fixture in ~9 numbered steps; bolting a multi-
minute, Slow-heavy upstream conformance run onto it would conflate two
different failure classes (controller wiring vs. upstream spec
semantics) behind one pass/fail line and roughly double that gate's
runtime for every future change to either concern.

## 4. Gate placement

**Manual/Lima-tier (nightly or on-demand), not a PR gate.** Confirmed
by inspection of `.github/workflows/ci.yaml`: every CI job runs on
GitHub-hosted `ubuntu-latest` runners, and `smoke-k3s-controller.sh` —
the closest existing analog, also a multi-VM Lima rig — is not
referenced anywhere in `ci.yaml` either. GitHub-hosted runners cannot
host 3 nested Lima VMs (2 k3s nodes + 1 client) and don't have the
project's Lima profile; this harness inherits that same constraint, one
tier further out given 5 of 6 specs are Slow (§2) and the multi-node
specs alone can run several minutes each. Follows the existing pattern
exactly — no new precedent.

## 5. Caveats carried forward

- **(a) beep-v2c blocks all 6 specs from passing today.** With
  `status.loadBalancer.ingress` now written (`beep-nxn` closed) every
  spec gets past its `WaitForLoadBalancer` gate, but `beep-v2c`'s
  cross-node return-path bug means the actual HTTP/UDP round trip
  currently times out with no SYN-ACK and no `FLOW_TABLE` entry. This
  harness lands as infrastructure now and turns green once `beep-v2c`
  is fixed; until then, running it IS a `beep-v2c` repro (arguably a
  better one than `smoke-k3s-controller.sh` alone, since some of these
  specs add pod-cycling/multi-node conditions that fixture never
  exercises).
- **(b) `LoadBalancerIngress.IPMode` must stay unset.**
  `loadbalancer.go:1054-1056` (`:1240-1242` for the `:1221` spec)
  self-skips via `e2eskipper.Skipf` if `ingress.IPMode == Proxy`.
  `controller/src/status.rs` already only ever sets `{"ip": ip}` with no
  `ipMode` key (confirmed reading the file directly, plus its own unit
  test `appended_entry_never_sets_ip_mode`) — no controller change is
  needed for this caveat, it is already satisfied; carried forward here
  only so a future controller change doesn't regress it silently.
- **(c) kube-proxy/status-IP double-processing overlap** — deferred to
  `mayor-waqhd` (Phase 6 coexistence), not this bead's or this harness's
  concern. If `mayor-waqhd` is still open when this harness first runs,
  a spec failure could be this overlap rather than `beep-v2c`; the
  wiring bead should sequence after `mayor-waqhd` closes, or at minimum
  cross-check its failure mode before attributing a red run to
  `beep-v2c`.
- **(d) 2-node Lima ceiling, zero headroom.** `:1081`/`:1174`
  (`e2enode.GetBoundedReadySchedulableNodes(ctx, cs, e2eservice.MaxNodesForEndpointsTests)`
  and `..., 2)`) need ≥2 schedulable nodes; the rig has exactly 2
  (`beep-node-a`, `beep-node-b`). Mechanically sufficient, but any
  future flakiness in these two specs can't be triaged as "needs more
  nodes" without first standing up a third — there is no slack today.
- **(e) 5 of 6 specs are Slow (§2 correction)** — multi-minute per spec;
  reinforces §4's gate placement rather than changing it. The task
  brief's original framing ("Slow on the secondary specs") undersold
  which specs are actually expensive — file this correction so whoever
  picks up the wiring bead sizes the nightly run's timeout budget off
  the real 5-of-6 figure, not 2-of-6.

## Cross-references

- `beep-v2c` — blocks all 6 specs from passing; this harness becomes its
  validation gate once fixed (§5a).
- `mayor-waqhd` — Phase 6 coexistence; a failure here before that
  closes may be its overlap, not `beep-v2c` (§5c).
- `mayor-g9l0f` — refreshed (see bd notes) to point at this proposal and
  drop its stale "cloud-provider-gated" framing, which beep-x64 already
  refuted.
- Follow-on wiring bead(s) — IDs appended to `beep-5xm`'s bd notes as
  filed.
