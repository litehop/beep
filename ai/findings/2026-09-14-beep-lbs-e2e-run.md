# beep-lbs: 7-spec upstream LoadBalancer e2e run against k3s-on-Lima

Bead: beep-lbs

**Verdict: 4/7 PASS.** All 7 specs ran to a terminal verdict (`Ran 7 of 7579
Specs in 819.105 seconds`, `FAIL! -- 4 Passed | 3 Failed`). Zero specs were
skipped or left blocked. All 3 failures are non-beep: one is a Lima
network-topology artifact (class b), two share one harness gap — `kubectl`
missing from `beep-client` (class c, filed as **beep-bol**). **Zero class-a
(genuine beep dataplane/controller) bugs found.** The core MVP signal —
spec 1, the external-client HTTP GET + real-client-IP check — technically
FAILED the spec's assertion, but the spec's own log shows beep correctly
delivered the client's true, unmasqueraded IP; the assertion only fires
because Lima's flat subnet defeats the spec's cloud-provider-specific
heuristic (detail below). Functionally, external LB delivery + client-IP
preservation both worked.

## Per-spec result

| # | Spec | Result | Reason / class |
|---|---|---|---|
| 1 | `ExternalTrafficPolicy: Local ... should work for type=LoadBalancer` | FAIL | `Source IP was NOT preserved` (loadbalancer.go:1077), class (b) — rig subnet/16 collision, beep preserved the real IP |
| 2 | `ExternalTrafficPolicy: Local ... should work from pods` | FAIL | `kubectl` missing on `beep-client` (609.9s timeout), class (c) — beep-bol |
| 3 | `ExternalTrafficPolicy: Local ... should only target nodes with endpoints` | PASS | 33.533s |
| 4 | `ExternalTrafficPolicy: Local ... should target all nodes with endpoints` | PASS | 7.024s, all endpoint pokes succeeded |
| 5 | `should be able to change the type and ports of a TCP service` | FAIL | `kubectl` missing on `beep-client` (124.7s timeout), class (c) — same root cause, beep-bol |
| 6 | `should be able to preserve UDP traffic ... different nodes` | PASS | 8.425s |
| 7 | `should be able to preserve UDP traffic ... the same nodes` | PASS | 10.958s |

## Pre-run state

- Worktree HEAD == `origin/main` (`191f3ff`, includes beep-j79 POD_TARGETS
  fix, PR #56) — 0 commits behind at run start.
- k3s cluster on `beep-node-a`/`beep-node-b` already up (4d5h uptime,
  both `Ready`, v1.36.4+k3s1) from a prior session; `k3s-up.sh` is
  idempotent so this is safe to re-run.
- No stale `servicelb-controller` DaemonSet, no `geneve0` interface, no
  `/sys/fs/bpf/beep` pin dir, no `beep-controller-kubeconfig` Secret, no
  client kubeconfig file on `beep-client` — clean slate for the harness's
  own deploy steps.
- `scripts/e2e-lb-k3s.sh` deploys beep itself (steps 3-4: kubeconfig Secret
  + `deploy/rbac.yaml` + `deploy/daemonset.yaml`, with a rollout-status +
  10s-settle + zero-restarts check) before the ginkgo run — no manual
  `smoke-k3s-controller.sh`-style replication was needed.

## Invocation

```
scripts/e2e-lb-k3s.sh
```
(all defaults: `--vm-a beep-node-a --vm-b beep-node-b --vm-client beep-client`,
default `FOCUS`, `--ginkgo-timeout 2h --wall-timeout 150m`)

Wall clock: 2026-09-14T10:28Z start (`limactl` invocation) to the script's
own exit ~19:43 local (VM clock, JST) / ~10:43Z — the ginkgo suite itself
(`Ran 7 ... Specs in 819.105 seconds`) took 13m39s; the rest of the ~15
elapsed minutes was cluster-up (already-warm, idempotent) + controller
deploy + JUnit collection + the script's own `trap cleanup EXIT`.

## Quality gate (host subset)

```
cargo fmt --check        # clean, no output
cargo test -p beep-common
```
`test result: ok. 32 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out`
(doc-tests: `0 passed; 0 failed`). No Rust touched by this bead.

## FAIL details

### Spec 1: `should work for type=LoadBalancer` — class (b), rig limitation

`[FAILED] Source IP was NOT preserved` at `loadbalancer.go:1077`. The spec's
own log shows the backend pod correctly observed `192.168.104.15:53624` —
`beep-client`'s genuine address — as the client IP (`loadbalancer.go:1064`),
i.e. beep did NOT masquerade the source. The spec fails it anyway because
its heuristic (`getSubnetPrefix`, `loadbalancer.go:75-96`) derives a `/16`
from the k3s **worker node's own internal IP** (`192.168.104.14` →
`192.168.0.0/16`) and calls any observed client IP inside that `/16` "not
preserved" — a proxy for "this must be the node's own address, i.e.
masqueraded", which holds on a real cloud VPC (node-internal `/16` is
disjoint from public/external client space) but not on Lima: `k3s-up.sh`
puts `beep-node-a`, `beep-node-b`, and `beep-client` all on the same flat
`192.168.104.0/24` VPN subnet, which nests inside that same `/16`. Confirmed
against `test/e2e/network/loadbalancer.go` fetched live at `v1.36.4` (the
exact k3s minor running on `beep-node-a`, resolved by the harness at
step 5/7). This is a topology mismatch between the spec's cloud-provider
assumption and Lima's single-subnet network, not evidence of a beep
masquerade bug — no follow-on bead filed.

### Spec 2 and Spec 5 — class (c), one shared harness gap: `beep-bol`

Both specs shell out to a literal `kubectl` binary (spec 2 via
`e2eoutput.RunHostCmd`, spec 5 via `jig.go:885`'s `CheckServiceReachability`)
to `exec` a curl/nc inside a pod. Both retry every ~1-2s with `exec:
"kubectl": executable file not found in $PATH` until their own internal
timeout: spec 2's `GetServiceLoadBalancerPropagationTimeout` (10m default on
a 2-node cluster, observed 609.9s), spec 5's 2m `ServiceReachabilityTimeout`
(observed 124.7s). Spec 2's terminal error, `Source IP not preserved from
pause-pod-deployment-... expected '10.42.1.21' got ''`, has an empty-string
"got" value — the signature of `kubectl exec` never once succeeding, not a
real client-IP mismatch. Confirmed root cause: `limactl shell beep-client --
which kubectl` exits 1 — `scripts/e2e-lb-k3s.sh` step 5/7 only downloads
`e2e.test`+`ginkgo` into `beep-client`'s cache dir, never a standalone
`kubectl`. Harness caching gap, not a beep dataplane bug. Filed as
**beep-bol** (harness scripts are hot; not edited by this bead).

## Post-run cleanup verification

The script's own `trap cleanup EXIT` ran to completion on both the FAIL
path and normal exit. Independently verified after the script exited:
- `servicelb-controller` DaemonSet: not found (deleted) on `beep-node-a`.
- `beep-controller-kubeconfig` Secret: not found (deleted).
- `geneve0`: does not exist on either `beep-node-a` or `beep-node-b`.
- `/sys/fs/bpf/beep` pin dir: absent on both nodes.
- `beep-client`: no leftover `/tmp/e2e-lb-k3s-kubeconfig` or
  `/tmp/e2e-lb-k3s-junit.xml`.
- Cluster namespaces: only the stock `default`/`kube-node-lease`/
  `kube-public`/`kube-system`, no leftover `loadbalancers-*`/`esipp-*`.
- `kube-system` pods: only stock `coredns`/`local-path-provisioner`/
  `metrics-server` — no `servicelb-controller` pods remain.

All three assigned VMs (`beep-node-a`, `beep-node-b`, `beep-client`) are
released back to their pre-run baseline state.

## Follow-on beads filed

- **beep-bol** — `e2e-lb-k3s.sh` step 5/7's cache step needs a standalone
  `kubectl` binary on `beep-client` (class c, harness gap). Blocks specs 2
  and 5 of this focus-list. No class-a beep bugs were found in this run,
  so no beep-dataplane/controller follow-on bead was needed.
