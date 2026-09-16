# k3s-controller e2e Rig

Answer: `scripts/k3s-up.sh` stands up a real 2-node k3s cluster on the Lima
pool, `scripts/e2e-lb-k3s.sh` runs the actual upstream Kubernetes
LoadBalancer conformance specs against beep's own controller + dataplane on
that cluster (the LB e2e proof bead beep-lbs closed on), and
`scripts/smoke-k3s-controller.sh` is a faster single-Service sanity check of
the same rig.

This is the Tier-2 k8s integration rig -- distinct from
`ai/extended-context/vm-operations.md`'s single-node dataplane smoke
(`scripts/smoke.sh`), which never boots k3s and drives raw netns/veth
fixtures instead of a real Service/EndpointSlice/Node reconcile loop.

## VM roles (fixed Lima pool)

Three named VMs:

- **`beep-node-a`** -- k3s server. Owns the local apiserver and is the e2e
  rig's ingress node: the VIP the client hits is node-a's own address.
- **`beep-node-b`** -- k3s agent. Hosts the backend Pod. The cross-node round
  trip depends on beep's `uplink_egress_return` hook firing on node-b's own
  client-facing NIC (`eth0`), not a tunnel device, to un-DNAT the reply
  straight back to the client.
- **`beep-client`** -- the external client, run from a VM never co-located
  with node-a or node-b. A 2-VM rig's client would be local to the backend
  node, so the return leg never leaves `lo`/veth and the tunnel-return hook
  is never exercised (see `vm-operations.md`'s cross-node section) -- a real
  third VM avoids that gap entirely.

These are the same VM *names* `vm-operations.md` documents for the
WireGuard 2-node smoke pool, but the k3s rig reprovisions them from a
different Lima profile -- `lima/beep-k3s.yaml` (4 GiB, k3s + flannel +
kube-proxy headroom) instead of `lima/beep.yaml`'s 2 GiB smoke profile.
`limactl start` never reprovisions an existing VM, so whichever profile last
*created* the VM is what's actually running; check `limactl list` before
assuming which rig a live `beep-node-a`/`beep-node-b` currently serves, and
never tear down and reprovision a VM another worker may be mid-task on.

## Standing up the cluster

```bash
scripts/k3s-up.sh --vm-a beep-node-a --vm-b beep-node-b
```

Idempotent: starts each VM if it already exists under that name, or
provisions fresh from `lima/beep-k3s.yaml` on first run. It then installs a
k3s **server** on `--vm-a` (`--disable=servicelb,traefik
--node-ip=<eth0 addr>` -- servicelb and traefik are disabled so k3s's own
klipper-lb can't race beep for `type=LoadBalancer` Services), reads the join
token, installs a k3s **agent** on `--vm-b`, and blocks until both nodes
report `Ready`. `flannel` (the default VXLAN CNI) and `kube-proxy` are left
stock. Both flags default to `beep-node-a`/`beep-node-b`, so a bare
`scripts/k3s-up.sh` is equivalent to the invocation above.

## Running the LoadBalancer e2e focus-list

```bash
scripts/e2e-lb-k3s.sh [--vm-a beep-node-a] [--vm-b beep-node-b] \
  [--vm-client beep-client] [--dry-run]
```

Runs the actual upstream `test/e2e/network/loadbalancer.go` conformance
suite (via a downloaded, cached `e2e.test`/`ginkgo`/`kubectl` matched to the
live k3s minor) against beep's own controller and dataplane -- not a
hand-rolled fixture. It calls `k3s-up.sh` itself (steps 1-2), starts
`beep-client` if it isn't already running, creates the `geneve0` tunnel
device on both nodes, ships a controller kubeconfig Secret, deploys
`deploy/{rbac,daemonset}.yaml`, and only then runs the 7-spec
`--ginkgo.focus` list from `beep-client`: the 4 `ExternalTrafficPolicy:
Local` specs, 1 TCP type/port-mutability spec, and 2 UDP flow-affinity
specs. A `trap cleanup EXIT` tears down the DaemonSet, RBAC, kubeconfig
Secret, `geneve0`, and any leftover e2e Namespaces regardless of outcome.
It's a manual/nightly Lima-tier gate, not wired into `ci.yaml` --
GitHub-hosted runners can't host this 3-VM rig.

**What PASS looks like.** The last full run (bead beep-lbs) recorded 4/7
PASS: 2 specs failed on a since-fixed harness gap (`beep-client` had no
standalone `kubectl` on `PATH`, blocking the two specs that `exec` into a
pod -- fixed by beep-bol, now on `main`), so a current run is expected to
land **6/7**. The remaining, expected failure is spec 1 (`... should work
for type=LoadBalancer`): its own log shows beep correctly delivered the
client's real, unmasqueraded IP, but the spec's cloud-provider heuristic
derives a `/16` from the node's internal address and calls any client IP
inside that `/16` "not preserved" -- which only holds when the node's
internal subnet is disjoint from the client's, true on a real cloud VPC but
false on Lima, where `k3s-up.sh` puts node-a, node-b, and `beep-client` on
the same flat `192.168.104.0/24` subnet nested inside that `/16`. Treat a
spec-1 FAIL alone as this known Lima-topology artifact, not a beep
regression; a FAIL on any other spec is a real signal -- both scripts print
`dump_evidence()`'s bpftool/`ip -s link`/controller-log dump automatically
on failure.

`--dry-run` validates the focus-list without running anything live (`Will
run 7 of 7579 specs`); use it after touching `FOCUS` before spending the
live run's ~15-90 minute wall-clock.

## Single-node controller smoke

```bash
scripts/smoke-k3s-controller.sh [--vm-a beep-node-a] [--vm-b beep-node-b] \
  [--vm-client beep-client]
```

A faster, hand-rolled sanity check of the same 3-VM rig: one `whoami`
Deployment + Service instead of the full upstream conformance suite. It
asserts every step of the controller-driven path end to end -- cluster up,
`geneve0`, kubeconfig Secret, DaemonSet/RBAC apply with zero controller
restarts, `status.loadBalancer.ingress` populated with both node IPs,
`VIP_MAP`/`POD_TARGETS` map entries actually programmed, beep-controller's
RSS growth bounded (`scripts/controller-rss.sh`), a real client -> VIP ->
cross-node backend round trip with the client IP preserved at the pod, and
a `FLOW_TABLE` conntrack entry for the flow. Use this to check the rig
itself (or a controller change) is healthy before spending the e2e suite's
much longer wall-clock.

`scripts/memory-smoke-controller.sh` is a different, lighter thing worth
not confusing with the above: it's the per-PR CI gate (`ci.yaml`'s
`memory-smoke` job) that measures the same RSS ceilings
(`scripts/controller-rss.sh`, shared with `smoke-k3s-controller.sh`) on a
single-node k3s cluster with no Lima VM at all -- it runs directly on the
GitHub-hosted runner, exercising the reconcile path without a dataplane
round trip.

## Bidirectional cross-node coverage

```bash
scripts/e2e-lb-bidirectional-k3s.sh [--vm-a beep-node-a] [--vm-b beep-node-b] \
  [--vm-client beep-client]
```

`smoke-k3s-controller.sh` and `e2e-lb-k3s.sh`'s specs only ever pin the
backend Pod to `beep-node-b` (the k3s agent) and dial in via `beep-node-a`
(the k3s server) -- one direction. This script proves the reverse
orientation too, in one cluster bring-up: two Services on distinct VIP
ports, one backend pinned to node-a dialed via node-b's address, the other
pinned to node-b dialed via node-a's address. Both assert the round trip
succeeds and the backend's own `RemoteAddr` still shows the real client
IP (beep never source-NATs the forward leg) -- catching a Geneve
encap/decap or return-path bug that only manifests in one ingress/backend
orientation.

## Driving the rig as an agent

`limactl` is the only tool that mutates VM/cluster state --
`k3s-up.sh`/`e2e-lb-k3s.sh`/`smoke-k3s-controller.sh` all drive it directly
(`limactl start`, `limactl shell <vm> -- sudo ...`), so run them exactly as
shown above rather than reimplementing their steps by hand.

For read-only inspection once a run is underway or has failed, use the
`mcp__beep-node-a`/`mcp__beep-node-b` MCP tools (`limactl mcp serve <vm>`,
wired in `.mcp.json`) instead of an ad hoc shell: `bpftool map dump pinned
/sys/fs/bpf/beep/<VIP_MAP|TARGET_PORTS|POD_TARGETS|FLOW_TABLE>` for
dataplane map contents, `ip -s link show eth0`/`geneve0` for interface
counters, and `dmesg` for verifier/kernel log output. There is no
`mcp__beep-client` server (only `beep-smoke`/`beep-node-a`/`beep-node-b`
are registered in `.mcp.json`); inspecting `beep-client` -- e.g. its cached
`e2e.test`/`kubectl` binaries or JUnit output at `/tmp/e2e-lb-k3s-*` --
needs a direct `limactl shell beep-client`. Controller pod logs and events
are only reachable through `k3s kubectl` on `beep-node-a` (the only node
with a local apiserver), e.g. `limactl shell beep-node-a -- sudo k3s
kubectl -n kube-system logs -l app.kubernetes.io/name=servicelb-controller
--previous` for a pre-crash log after a `CONTROLLER-DEPLOY: FAIL`.

Never `limactl stop` `beep-node-a`/`beep-node-b`/`beep-client` on task
completion -- the same "leave VMs running" rule `vm-operations.md` states
for the smoke pool applies here: another session may find the cluster
already `Ready` and skip re-provisioning via `k3s-up.sh`'s idempotent start
path.

## Related

- `scripts/k3s-up.sh`, `scripts/e2e-lb-k3s.sh`,
  `scripts/smoke-k3s-controller.sh`, `scripts/e2e-lb-bidirectional-k3s.sh`,
  `scripts/memory-smoke-controller.sh`, `scripts/controller-rss.sh` -- the
  scripts this doc describes.
- `lima/beep-k3s.yaml` -- the VM profile `k3s-up.sh` provisions from.
- `deploy/rbac.yaml`, `deploy/daemonset.yaml` -- the controller manifests
  both e2e scripts deploy.
- `ai/extended-context/vm-operations.md` -- the Lima pool + single-node
  dataplane smoke this rig sits alongside.
- bead beep-lbs -- the LB e2e proof this rig runs; bead beep-bol -- the
  kubectl-caching fix referenced above.
