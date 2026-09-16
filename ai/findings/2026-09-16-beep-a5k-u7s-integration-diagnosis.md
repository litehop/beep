---
Bead: beep-a5k
Date: 2026-09-16
Scope: diagnosis + repro recipe only (Phase 1). No code changes.
---

# beep<->u7s LoadBalancer integration: root cause + Phase-2 recipe

## Answer first

The most likely root cause is a **missing operational prerequisite in beep's
own deploy packaging**: beep's dataplane requires `net.ipv4.conf.geneve0.rp_filter=0`
(alongside `net.ipv4.conf.all.rp_filter=0`, since the kernel takes
`max(all, interface)`) on every node, or the kernel's reverse-path filter
silently drops every decapsulated forward packet before it reaches the
backend pod's veth/cni0 -- even though beep's own eBPF encap/decap logic runs
correctly and updates `FLOW_TABLE`. This exact fix is baked into **every one
of beep's own smoke/e2e harnesses**
(`scripts/smoke-k3s-controller.sh:159-186`, `scripts/e2e-lb-k3s.sh:133-144`,
`scripts/smoke-remote.sh:136-165`) but is **absent from `deploy/daemonset.yaml`
and `deploy/README.md`** -- the only artifacts a real cluster operator (u7s)
would actually use. u7s's own diagnostic session (`mayor-re973` round 5, u7s
checkout) independently measured `rp_filter=2` (loose) on `all`/`cni0`/`geneve0`
on the affected node and dismissed it as "not a policy block" -- but beep's
own code comments, backed by a live `kprobe:ip_route_input_noref` trace,
document that loose mode (2) does **not** grant its usual exception to an
address-less device like `geneve0`, and only `0` avoids the drop. This is a
tight, mechanism-level match for the exact symptom u7s observed (decap
succeeds, `FLOW_TABLE` populates, packet never reaches `cni0`/veth).

A second, independently real but non-explanatory gap: `deploy/daemonset.yaml`
also never creates the `geneve0` device itself (the controller crashes at
startup without it -- u7s's own round-5 notes hit this and worked around it
by hand) and pins `--pod-cidr=10.42.0.0/16` (k3s's default) while u7s ships
`10.244.0.0/16` (flannel's default, confirmed in `scripts/install.sh:902`).
u7s's tester corrected both by hand in every round, so neither explains the
observed failure -- but both are real out-of-the-box breakage for anyone who
deploys the manifest as-is, and belong in the same fix.

## (a) Exact observed u7s-side failure

Symptom, verbatim from `mayor-re973` round 5 (the only round run against
u7s's actually-shipped substrate, flannel VXLAN, on 2026-09-16): a foreign
client's `curl` to the LoadBalancer VIP times out 3/3 with zero HTTP response.
tcpdump shows the forward leg working end-to-end -- client SYN leaves the
front node as a real Geneve/UDP:6081 packet, arrives on the backend node's
`eth0`, and `geneve0`'s promiscuous capture shows a **correctly decapsulated**
inner SYN with the real client IP and VIP-addressed destination intact.
`FLOW_TABLE` on the backend node gets the expected reverse-flow entry (proving
`try_geneve_decap_forward` ran to completion and returned `TC_ACT_OK`). But
the backend pod's own `cni0`/veth capture shows **zero packets** for the same
window -- the step between "kernel accepted the DNAT'd, PACKET_HOST-reclassified
skb" and "packet lands on the pod's veth" is where it dies. A same-node
`curl` straight to the pod IP (bypassing beep) returns clean `200 OK`
immediately, so the backend itself is healthy. This exact failure signature
reproduced byte-for-byte across round 4 (cri-o bridge CNI, non-shipped) and
round 5 (flannel VXLAN, shipped) -- ruling out the CNI substrate as the
variable.

## (b) Hypotheses, ranked by evidence

### 1. Backend-node `rp_filter` reverse-path drop on the address-less `geneve0` device -- CONFIRMED (top suspect)

Evidence:
- `scripts/smoke-k3s-controller.sh:164-186`: "geneve0 carries no IP address,
  so `fib_validate_source` in the kernel never grants its loose-mode (2)
  exception for it -- an address-less input device falls through to the same
  reverse-path drop as strict mode regardless of the configured value,
  silently blackholing every decapped forward packet before it ever reaches
  cni0 (confirmed live: `kprobe:ip_route_input_noref` returns `-EXDEV` for
  the decapped packet, even with rp_filter=2 on both all and geneve0). Only
  rp_filter=0 bypasses this check. The kernel takes max(all, interface)..."
- `scripts/e2e-lb-k3s.sh:138-143` applies the identical fix on **the exact
  rig** (`beep-lbs`, k3s + real flannel) that backs beep's own "cross-node LB
  delivery is PROVEN" claim in `ai/extended-context/roadmap.md:19-21` --
  i.e. beep's own proven-green result depends on this sysctl, applied
  outside Kubernetes by the harness script, never expressed in the shippable
  manifest.
- `deploy/daemonset.yaml` and `deploy/README.md`: zero mentions of
  `rp_filter` anywhere (`grep -n rp_filter deploy/daemonset.yaml
  deploy/README.md` -> no matches).
- u7s `mayor-re973` round 5 notes (u7s checkout, `bd show mayor-re973`):
  "checked `net.ipv4.ip_forward` (=1) and
  `net.ipv4.conf.{all,cni0,geneve0}.rp_filter` (=2, loose, not strict) on the
  backend node -- neither looks like an OS-level policy block" -- this is
  **exactly** the broken condition beep's own comment describes
  ("even with rp_filter=2 on both all and geneve0"), misread as benign.
- Confirm-step: on beep-smoke, reproduce the decap path with `rp_filter=2`
  (default) and assert the pod-delivery drop via
  `bpftrace -e 'kprobe:ip_route_input_noref { @drops[args->flags] = count(); }'`
  or the same `kfree_skb` tracepoint beep's own comments cite; then set
  `net.ipv4.conf.all.rp_filter=0` + `net.ipv4.conf.geneve0.rp_filter=0` and
  assert delivery succeeds with no other change.

### 2. Pod-CIDR mismatch (`10.42.0.0/16` manifest default vs u7s's `10.244.0.0/16`) -- CONFIRMED as a real gap, KILLED as the explanation for the observed failure

Evidence:
- `deploy/daemonset.yaml:82-84`: `--pod-cidr=10.42.0.0/16` (k3s default),
  comment says "override for a cluster provisioned with a different pod
  CIDR" -- but `deploy/README.md` never tells an operator to actually do
  this; there's no kustomize overlay shipped for it.
- u7s `scripts/install.sh:899-902`: `POD_CLUSTER_CIDR="10.244.0.0/16"`
  (flannel's own default), used unconditionally by the real bring-up path.
- **Kill**: `mayor-re973` round 5 explicitly deployed beep with
  `--pod-cidr=10.244.0.0/16` (u7s's real, correct CIDR, "verified against
  the turnkey diff in mayor-0v60z") and the identical decap->veth failure
  still reproduced. A misclassified pod-CIDR would show up as `VIP_MAP`
  resolving wrong or `try_geneve_decap_forward`'s `POD_TARGETS` membership
  check dropping the packet outright (`TC_ACT_SHOT`) -- not as a
  correctly-decapped packet with a correct `FLOW_TABLE` entry that
  disappears one hop later. This hypothesis does not fit the observed
  symptom once the CIDR is corrected, which it was.
- Disposition: real bug, ship a fix (kustomize overlay or make
  `--pod-cidr` operator-required with no baked-in default), but not the
  cause of round 4/5's failure.
- Confirm-step: deploy the unmodified manifest (no override) against a
  10.244.0.0/16 cluster and assert `VIP_MAP`/`TARGET_PORTS` misprogram
  (distinguish from hypothesis 1 by checking whether the packet is dropped
  at decap, `TC_ACT_SHOT`, vs. silently vanishing after a successful decap).

### 3. Rootless/caps (u7s's runtime privileges block eBPF attach) -- KILLED

Evidence (30-second confirm, per operator redirect): every `mayor-re973`
round (4 and 5) shows the beep DaemonSet pod reaching `1/1 Running`, zero
restarts, with logs `attached uplink_ingress on eth0`, `attached
geneve_ingress on geneve0`, `attached uplink_egress_return on eth0`, "all 3
hooks attached" -- on real Lima VMs (real kernel netns, cri-o with
`CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON` + AppArmor-unconfined, matching
`deploy/daemonset.yaml`'s own `securityContext`). `FLOW_TABLE` and `VIP_MAP`
get populated, and Geneve packets are genuinely observed on the wire --
none of that is possible without a real attach and a real netns. u7s is not
rootless/userspace-networked for this test path; this hypothesis is refuted
by the same evidence that shows the actual failure point.

### 4. Image/version drift -- KILLED for the observed failure, live risk for a naive deploy

Evidence: `mayor-re973` rounds 4-5 built beep **from source at the `v0.1.0`
git tag** on the test VM (not `docker.io/valerauko/beep-lb:latest`) each
time, specifically to control for this. In this repo,
`git log --oneline v0.1.0..HEAD -- ebpf/src/main.rs` returns **zero commits**
-- the decap/redirect logic tested is byte-identical to current `HEAD`. Not
the cause of the observed failure. Separately real: `deploy/daemonset.yaml`
pulls `:latest`, which per `docs/decisions/versioning.md` (post-`beep-pk1`)
now tracks "the newest release tag" with no pin -- an operator who doesn't
override it gets whatever beep last released, unpinned, at deploy time.

### 5. Kubeconfig/RBAC gap -- UNVERIFIED, not implicated

Evidence: `mayor-re973` rounds 4-5 both used the test session's own
already-trusted **admin** client cert instead of the documented
least-privilege `deploy/rbac.yaml` ClusterRole, because the harness's
permission classifier correctly blocked minting a new CA-signed cert. Since
`VIP_MAP`/`TARGET_PORTS`/`FLOW_TABLE` all got populated correctly (proving
the controller's Service/EndpointSlice/Node watches worked), RBAC was not
the failure point in these rounds -- but the documented least-privilege
`ClusterRole` (`deploy/rbac.yaml`) has **never actually been exercised**
end-to-end. Real gap for production trust, not implicated in this bug.
Confirm-step: Phase-2 should use the real `beep-controller-kubeconfig` +
`rbac.yaml` path (no admin fallback) precisely to close this gap while
confirming hypothesis 1.

### 6. Genuine beep dataplane logic bug (decap/redirect code itself) -- effectively subsumed by #1

u7s's round 5 notes concluded "confirmed as a real beep-side bug,
independent of CNI substrate" -- true in the narrow sense that it isn't a
CNI-substrate artifact, but the evidence above indicates the "bug" is a
missing deploy-time sysctl, not defective eBPF logic: the decap/DNAT/
`bpf_skb_change_type(PACKET_HOST)` sequence (`ebpf/src/main.rs:780-828`)
completes and returns `TC_ACT_OK`; what happens after that hand-off to the
kernel's normal receive path is exactly where `rp_filter` intervenes. This
is a packaging bug in beep's shipped manifest, not a logic bug in the
eBPF program -- but it is beep's responsibility to fix either way (own the
sysctl via an init step, or document it as a hard prerequisite).

## (c) Phase-2 live-repro recipe

**Target VM: `beep-smoke`** (single-node, aarch64, currently Stopped, free
per dispatch -- do not touch `beep-node-a`/`beep-node-b`, held by the
in-flight `beep-hmj` worker). Note: u7s's `v0.3.0-snapshot.1` release assets
are `x86_64-unknown-linux-gnu` only (`gh release view v0.3.0-snapshot.1 -R
litehop/u7s`); `beep-smoke` is aarch64, so build u7s from source at the tag
rather than installing the prebuilt tarball (mirrors how u7s's own mayor
rounds built beep from source on Lima VMs rather than pulling images).

1. `limactl start beep-smoke` (idempotent per `scripts/lima-up.sh`).
2. On `beep-smoke`: clone/checkout `litehop/u7s` at tag `v0.3.0-snapshot.1`;
   `cargo build --release` the workspace natively for aarch64 (no cross
   compile needed, unlike the x86_64-pinned release tarball); run
   `scripts/install.sh --tarball <locally-assembled bin dir>` (or invoke the
   underlying systemd-unit steps directly) for a **single-node** stack --
   confirms `POD_CLUSTER_CIDR=10.244.0.0/16` (`scripts/install.sh:902`) and
   that KCM disables `-service-lb-controller` (u7s expects an external LB).
3. Build beep from this worktree's current `HEAD` (or the latest tagged
   release once cut) on `beep-smoke` (aarch64, native).
4. Deploy beep with the **documented-but-currently-missing** fixes applied
   by hand (this is what Phase-2 needs to confirm actually closes the gap):
   - `ip link add geneve0 type geneve external && ip link set geneve0 up`
     before the controller starts.
   - `sysctl -w net.ipv4.conf.all.rp_filter=0` and
     `sysctl -w net.ipv4.conf.geneve0.rp_filter=0` (both -- kernel takes
     `max`).
   - `deploy/daemonset.yaml` via kustomize patch: `--pod-cidr=10.244.0.0/16`.
   - Real `deploy/rbac.yaml` ClusterRole + a genuinely least-privilege
     X.509 client-cert kubeconfig Secret (not an admin cert) -- closes
     hypothesis 5 in the same pass.
5. Apply a backend `Deployment` (nginx or similar) + a `type=LoadBalancer`
   `Service` selecting it, scheduled by u7s.
6. Assert: `curl` to the assigned `status.loadBalancer.ingress` address from
   outside the pod netns returns `200 OK`; inspect the backend's own request
   log (or an `httpbin`-style echo) to assert the **real client IP** was
   delivered, not a NAT'd/node address -- matching the bar
   `ai/extended-context/roadmap.md:52-54` already sets for beep's own
   k3s/flannel e2e.
7. Negative control (optional, strengthens the confirm): repeat step 5-6
   once with `rp_filter` left at its default (2) and no other change, and
   assert the exact same zero-response failure u7s observed -- directly
   proving hypothesis 1 is sufficient and necessary, not just correlated.

Cross-node is not exercised on single-node `beep-smoke` (front == backend
node), but per `ai/extended-context/roadmap.md`'s own "single-node AND
cross-node" bar and beep's decap path being identical regardless of
same-node vs cross-node front/backend placement, the single-node run still
exercises the exact `geneve0` decap -> `cni0`/veth hop that failed on u7s. A
cross-node assertion is a stretch goal once a second free VM exists (not
`beep-node-a`/`-b`).
