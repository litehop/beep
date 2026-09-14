# kube-proxy/flannel coexistence: proven live on the k3s-on-Lima rig

Bead: mayor-waqhd

**Verdict: COEXISTENCE PROVEN.** All four checks pass with live evidence on
a controller-driven k3s cluster (`beep-node-a`/`beep-node-b`) running real
`Service` objects of both kinds concurrently. kube-proxy's iptables rules
and flannel's VXLAN device are untouched by beep's dataplane; beep's tc-bpf
hooks only ever fire for the physical-node-IP:port pairs the controller
programs into `VIP_MAP`, never for `ClusterIP`/`NodePort` traffic on the
same node and interface. No follow-on bead filed.

Setup: `scripts/k3s-up.sh` cluster already up (4d5h,
`lima-beep-node-a`/`lima-beep-node-b`, flannel + kube-proxy stock,
servicelb/traefik disabled). Deployed the controller
(`deploy/rbac.yaml`+`deploy/daemonset.yaml`) and a `whoami` Deployment
pinned to node-b behind three real Services in one namespace
(`beep-waqhd-e2e`): `whoami-lb` (`type=LoadBalancer`), `whoami-clusterip`
(`type=ClusterIP`), `whoami-nodeport` (`type=NodePort`, `nodePort=30080`).
Did this by hand (not via `scripts/smoke-k3s-controller.sh`, whose
`trap cleanup EXIT` tears everything down before any of these checks could
run) but reused that script's exact commands (kubeconfig Secret rewrite,
`geneve0 type geneve external` + `rp_filter=0`, RBAC/DaemonSet apply). No
harness script was edited. Cluster returned to its pre-test baseline
(namespace/DaemonSet/RBAC/Secret/`geneve0` deleted) after evidence
collection.

## 1. `uplink_ingress` never matches ClusterIP/NodePort traffic

Live: dumped `VIP_MAP` on both nodes after the controller reconciled the
real `Service` objects above:

```
key: c0 a8 68 0d 00 50 06 00  value: 0e 68 a8 c0 0a 2a 01 0f
key: c0 a8 68 0e 00 50 06 00  value: 0e 68 a8 c0 0a 2a 01 0f
Found 2 elements
```

Decoded: `{vip=192.168.104.13,port=80,tcp}` and
`{vip=192.168.104.14,port=80,tcp}` -- the two node **physical** addresses
at the LB Service's port, both resolving to
`backend_node_ip=192.168.104.14, pod_ip=10.42.1.15` (node-b, the whoami
pod). No entry for `whoami-clusterip`'s ClusterIP (`10.43.88.151`),
`whoami-nodeport`'s ClusterIP (`10.43.183.34`), or either service's
allocated NodePort (`30080`, `31067`) -- confirming the controller only
ever programs `VIP_MAP` with LoadBalancer front IP:port tuples, per
`ebpf/src/main.rs`'s `try_uplink_ingress_headers` (`VipKey{vip_ip, vip_port,
proto}` lookup, miss -> `TC_ACT_OK`, i.e. pass through to the normal
receive path untouched).

Targeted-packet proof, same node, same physical interface, before/after
each request (`FLOW_TABLE`/`FWD_PENDING` empty at baseline, 0 elements
each):

- `curl` from node-a itself to the ClusterIP (`10.43.88.151:80`) and to the
  NodePort on node-a's own address (`192.168.104.13:30080`): both succeed,
  `RemoteAddr: 10.42.0.0:*` (kube-proxy's standard masquerade for
  locally-originated traffic) -- `FLOW_TABLE`/`FWD_PENDING` still 0
  elements after both.
- `curl` from the **external** `beep-client` VM to the NodePort on node-a's
  real address (`192.168.104.13:30080`, a genuine ingress packet on
  `eth0`): succeeds, `RemoteAddr: 10.42.0.0:*` (kube-proxy DNAT path, not
  beep's) -- `FLOW_TABLE`/`FWD_PENDING` still 0 elements.
- `curl` from `beep-client` to the LB VIP (`192.168.104.13:80`): succeeds,
  `RemoteAddr: 192.168.104.15:*` (the client's real IP, un-SNAT'd) --
  `FLOW_TABLE` now has exactly 1 entry for that flow.

Same physical node, same physical NIC, three different destination
ports on the identical address (`192.168.104.13`) -- only the one present
in `VIP_MAP` (port 80) is ever touched by beep's dataplane.

## 2. VIP range outside flannel's CIDRs; geneve0 never touches flannel's vxlan device

Live cluster CIDRs (`ip route show` on node-b): pod CIDR `10.42.0.0/24`
(node-a) / `10.42.1.0/24` (node-b) under the cluster-wide `10.42.0.0/16`;
Service CIDR `10.43.0.0/16` (`kubernetes`/`kube-dns`/`metrics-server`
ClusterIPs all `10.43.x.x`). The front IP is the node's own **physical**
address (`192.168.104.13`/`.14`, the Lima bridged-network range) --
disjoint from both by construction, confirmed live via `ip route show` and
`kubectl get svc -A`.

`ip -d link show` on node-b: `flannel.1` is a VXLAN device,
`vxlan id 1 local 192.168.104.14 dev eth0 ... dstport 8472` (flannel's
default VXLAN port). `geneve0` is a separate device,
`geneve external id 0 ttl auto dstport 6081` (Geneve's IANA port). Two
different encapsulations on two different UDP ports, no shared
configuration. `ip route show` has zero routes through `geneve0` -- routes
only reference `flannel.1` (remote pod subnet) and `cni0` (local pod
subnet); `geneve0` is driven purely by beep's own `bpf_redirect` calls
(`ebpf/src/main.rs`), never by the kernel routing table. `bpftool net show`
on both nodes confirms beep's 3 tcx programs attach only to `eth0`
(ingress+egress) and `geneve0` (ingress) -- nothing on `flannel.1` or
`cni0`.

## 3. Concurrent east-west + north-south on the same node

Fired 10 concurrent ClusterIP requests from node-a itself and 10 concurrent
LB-VIP requests from `beep-client` at the same time:

```
ClusterIP 200 (x10)
VIP 200 (x10)
```

All 20 succeeded. `FLOW_TABLE` after the burst: 11 entries total (1 from
the earlier single-request check + 10 from this burst), all keyed on the
real client (`beep-client`, `192.168.104.15`) against the VIP -- zero
entries attributable to the ClusterIP traffic. `dmesg` on both nodes shows
no drops/errors from beep (only routine `cni0` veth up/down noise from
unrelated pod churn). Controller pods: 0 restarts throughout
(`kubectl get pods ... -o jsonpath='{...restartCount}'`). The one
legitimate contact point (`try_geneve_decap_forward`'s doc comment: DNAT
the decapped packet to `PodIP:TargetPort`, then `TC_ACT_OK` to hand off to
"the kernel's own routing, which is flannel's job from here, not ours")
worked correctly under this concurrent load -- the pod's `RemoteAddr`
matched the real client IP on every LB request, and the ClusterIP
requests were served by the same pod over its normal `cni0`-bridged path
without interference.

## 4. kube-proxy and beep's tc-bpf hooks don't fight

`bpftool net show` (node-a): beep's 3 programs are all `tcx/...` (the
kernel's multi-program tc attach API, not classic `tc filter` singleton
slots):

```
eth0(2) tcx/ingress uplink_ingress prog_id 1661 link_id 42
eth0(2) tcx/egress uplink_egress_return prog_id 1663 link_id 44
geneve0(32) tcx/ingress geneve_ingress prog_id 1662 link_id 43
```

`iptables-save -t nat` (node-a) shows kube-proxy operating entirely in
`KUBE-SERVICES`/`KUBE-NODEPORTS` (netfilter NAT hook chains) for all four
real Services present (`whoami-lb`'s auto-allocated ClusterIP+NodePort,
`whoami-clusterip`, `whoami-nodeport`, plus `kube-dns`/`kubernetes`/
`metrics-server`) -- a different kernel subsystem than beep's tc-clsact
hooks, and one that runs strictly *after* tc ingress in the RX pipeline.
That ordering is exactly what section 1's targeted packets prove
empirically: a `VIP_MAP` hit (port 80 on the node's own address) is fully
handled by beep before kube-proxy's chains are ever consulted (real client
IP preserved, no masquerade); a miss (port 30080/31067, or the ClusterIP
address) falls through untouched to kube-proxy's DNAT (masqueraded
`RemoteAddr`), which continues to work exactly as it would with beep
absent. k3s here runs kube-proxy in iptables mode, not IPVS (confirmed by
the `KUBE-SVC-*`/`KUBE-SEP-*` chain names); no IPVS coexistence question
arises on this rig.

## Notes for the operator

The header comments in `scripts/smoke-k3s-controller.sh` (lines 10-23) and
`scripts/e2e-lb-k3s.sh` (line 27-30) still describe the cross-node
return-path bug and this coexistence gap as open. Both are stale: beep-v2c
(the return-path bug) closed 2026-09-11 via PR #51, and this bead now
closes the coexistence gap. Not fixed here (Rule 3 -- neither script's
path was in this bead's scope, and `scripts/e2e-lb-k3s.sh` is currently
owned by an in-flight worker); worth a small stale-comment cleanup pass
whenever that script is next touched.
