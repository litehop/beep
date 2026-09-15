# IPVS-mode kube-proxy coexistence: FAIL, but not the hypothesized failure mode

Bead: beep-03m

**Verdict: FAIL.** The hypothesized failure (`kube-ipvs0` locally binding a
node's own VIP and REJECTing beep's forward traffic) does **not** happen —
confirmed empirically that `kube-ipvs0` skips a VIP address that already
matches the node's own real interface address, so beep's tc-ingress hook
still fronts it exactly as in iptables mode. The actual failure is one layer
below and more severe: because beep's controller publishes **every**
DaemonSet node's own physical IP into the same LoadBalancer Service's
`status.loadBalancer.ingress[]`, kube-proxy's IPVS reconciler binds each
*other* node's real address onto its own `kube-ipvs0` as a local, `NOARP`
dummy-device address. On this rig's flat Lima L2 network that is a genuine
duplicate-IP conflict: it broke plain TCP reachability between the two
nodes (confirmed root cause 5 times independently, including one full VM
crash) badly enough that the k3s agent could not even stay joined to the
cluster -- so the actual VIP-forwarding round trip could not be exercised
end-to-end under live IPVS mode. This is DaemonSet-topology-specific to
beep, not a generic single-VIP IPVS problem.

## Setup

Rig: `scripts/k3s-up.sh` on `beep-node-a` (k3s server, ingress) +
`beep-node-b` (k3s agent, backend), `beep-client` as the external client, all
three fresh Lima VMs (2026-09-15, JST). Added a `--proxy-mode <iptables|ipvs>`
passthrough to `scripts/k3s-up.sh` (`--kube-proxy-arg=proxy-mode=ipvs` on both
`server`/`agent` installs) so the mode switch is reusable, not a one-off hack.
`ip_vs`/`ip_vs_rr`/`nf_conntrack` modprobe cleanly on both nodes (no missing-
module blocker); `ipvsadm` isn't preinstalled by `lima/beep-k3s.yaml` --
installed via `apt-get install -y ipvsadm` for evidence collection only.

## 1. iptables baseline: PASS (reproduced before touching anything)

`scripts/smoke-k3s-controller.sh` end to end:

```
CLUSTER-UP: PASS
CONTROLLER-DEPLOY: PASS (servicelb-controller Running on both nodes, zero restarts)
SERVICE STATUS: PASS (status.loadBalancer.ingress = 192.168.104.13 192.168.104.12)
MAP-PROGRAMMING: PASS (VIP_MAP: beep-node-a=2 beep-node-b=2 entries)
ROUND-TRIP: PASS (symmetric return; whoami's RemoteAddr confirms the real client IP 192.168.104.14 reached the pod un-SNAT'd)
CONNTRACK: PASS (beep-node-a FLOW_TABLE=1 entries)
GATE CONTROLLER-DRIVEN ROUND-TRIP: PASS
```

Manually reproduced the same setup (controller kubeconfig Secret,
RBAC/DaemonSet, a `whoami` Deployment pinned to node-b behind both a
`LoadBalancer` and a `ClusterIP` Service, outside the script's own
`trap cleanup EXIT` so state stays up for inspection) and additionally
confirmed:

```
$ limactl shell beep-client -- curl -sS -o /dev/null -w "HTTP_CODE=%{http_code}\n" http://192.168.104.12:80/
HTTP_CODE=200
$ limactl shell beep-node-a -- curl -sS -o /dev/null -w "HTTP_CODE=%{http_code}\n" http://10.43.221.162:80/
HTTP_CODE=200
$ limactl shell beep-node-a -- sudo bpftool net show
tc:
eth0(2) tcx/ingress uplink_ingress prog_id 492 link_id 6
eth0(2) tcx/egress uplink_egress_return prog_id 494 link_id 8
geneve0(13) tcx/ingress geneve_ingress prog_id 493 link_id 7
$ limactl shell beep-node-a -- sudo bpftool map dump pinned /sys/fs/bpf/beep/FLOW_TABLE
... Found 1 element
```

LB-VIP forward round trip 200, ClusterIP east-west 200, beep's 3 tcx programs
on `eth0`/`geneve0` only, `FLOW_TABLE` grew for the VIP flow only. This
matches mayor-waqhd's iptables-mode result exactly and confirms the rig
itself is healthy before any IPVS change.

## 2. Switching to IPVS: `kube-ipvs0` skips the node's OWN VIP (hypothesis refuted)

After `scripts/k3s-up.sh --proxy-mode ipvs`, on `beep-node-a` (owns
`192.168.104.12`, hosts the same LB Service whose ingress is
`192.168.104.12, 192.168.104.13`):

```
$ limactl shell beep-node-a -- ip addr show kube-ipvs0
14: kube-ipvs0: <BROADCAST,NOARP> mtu 1500 qdisc noop state DOWN group default
    inet 10.43.0.1/32 ...        (kubernetes ClusterIP)
    inet 10.43.0.10/32 ...       (kube-dns ClusterIP)
    inet 10.43.83.116/32 ...     (metrics-server ClusterIP)
    inet 10.43.67.83/32 ...      (whoami LB's auto ClusterIP)
    inet 192.168.104.13/32 ...   (beep-node-b's OWN address -- foreign VIP)
    inet 10.43.221.162/32 ...    (whoami-clusterip ClusterIP)
```

`192.168.104.12` -- node-a's own eth0 address, and one of the two VIPs this
exact LoadBalancer Service is published under -- is **absent**. kube-proxy's
IPVS proxier recognizes it as already a local (`NodeIP`) address and does not
duplicate it onto the dummy device. `ipvsadm -Ln` on node-a still shows a
virtual server for it (`TCP 192.168.104.12:80 rr`), but with no local-address
conflict, that virtual server sits behind the normal netfilter/IPVS hooks
which -- like iptables' `KUBE-SERVICES` chain -- run strictly after tc
ingress. So on the node that **owns** the VIP, beep's `uplink_ingress`
hook still fronts it first regardless of proxy mode: **the originally
hypothesized local-REJECT-of-VIP-traffic does not occur.**

## 3. The actual failure: foreign-node VIP binding is a real duplicate-IP conflict

`beep-node-b`'s own `kube-ipvs0` mirrors the pattern in reverse -- it binds
`192.168.104.12` (node-a's real address), not its own `192.168.104.13`:

```
$ limactl shell beep-node-b -- ip addr show kube-ipvs0
...
    inet 192.168.104.12/32 scope global kube-ipvs0   (node-a's OWN address)
...
```

Both nodes now each hold a `NOARP` dummy-device claim on the *other* node's
real physical address, because beep publishes both addresses into the same
Service's ingress list and IPVS mirrors every ingress IP onto every node
that doesn't already own it. On this rig's flat Lima L2 network that is a
genuine duplicate-IP condition, and it broke real connectivity, not just a
theoretical corner case:

```
$ limactl shell beep-node-b -- ping -c 3 192.168.104.12
From 192.168.104.13 icmp_seq=1 Destination Host Unreachable
From 192.168.104.13 icmp_seq=2 Destination Host Unreachable
From 192.168.104.13 icmp_seq=3 Destination Host Unreachable
$ limactl shell beep-node-b -- curl -sk -m5 https://192.168.104.12:6443/version
curl: (7) Failed to connect ...
$ limactl shell beep-node-b -- sudo journalctl -u k3s-agent.service | tail -1
... level=error msg="Failed to validate connection to cluster at https://192.168.104.12:6443: failed to get CA certs: ... connection reset by peer"
```

The k3s agent's own control-plane tunnel to the server -- ordinary node-to-
node TCP, nothing to do with beep's dataplane -- looped on this error
indefinitely. **Direct causal test, reproduced independently 5 times across
this session:** deleting the conflicting address restores connectivity
immediately; kube-proxy's own periodic `syncProxyRules` reconcile re-adds it
within roughly 15-30s, breaking it again. This is steady-state IPVS-proxier
behavior, not a one-off race:

```
$ limactl shell beep-node-a -- sudo ip addr del 192.168.104.13/32 dev kube-ipvs0
$ limactl shell beep-node-b -- ping -c 3 192.168.104.12
64 bytes from 192.168.104.12: icmp_seq=1 ttl=64 time=211 ms   # <- immediate recovery
...
# ~15s later, unprompted:
$ limactl shell beep-node-a -- ip addr show kube-ipvs0 | grep 192.168.104.13
    inet 192.168.104.13/32 scope global kube-ipvs0            # <- re-added by kube-proxy
```

One of these cycles (agent stuck retrying while the conflict was live) ended
with `beep-node-b`'s entire Lima VM stopping outright (`limactl list` showed
`Stopped`, not just the k3s-agent unit down) -- almost certainly resource
exhaustion from the tight retry loop on a 4GiB VM, not a direct IPVS effect,
but a concrete symptom of how disruptive the steady-state conflict is.
Because the conflict is reciprocal (each node's `kube-ipvs0` corrupts
reachability *to* the other), it could not be worked around by fixing only
one side -- both nodes needed the offending address cleared simultaneously
before the cluster's own control plane would stabilize. With both node-to-
node k3s connectivity and the backend Pod's scheduling repeatedly disrupted
by this, the actual client-to-VIP-to-backend curl and the ClusterIP
east-west curl could not be safely re-run to completion under live IPVS
mode -- the cluster's own control plane broke first, before the dataplane
question could be exercised.

## 4. DaemonSet-on-every-node implication

Confirmed directly (not merely inferred): with 2 nodes, both nodes' own
`kube-ipvs0` devices independently exhibited the same asymmetric pattern (own
address skipped, foreign address bound). This scales with the DaemonSet: on
an N-node cluster, kube-proxy on every node would bind the other N-1 nodes'
addresses as local dummy-device entries for the same Service, so the
duplicate-IP hazard is present on every node pair simultaneously, not just a
2-node edge case.

## Cleanup

Deleted the test namespace/Deployment/Services, the controller
DaemonSet/RBAC/kubeconfig-Secret, `geneve0`, and restored
`net.ipv4.conf.all.rp_filter` on both nodes (node-b's own value was lost to
its VM crash/reboot, which reset it to the image default -- nothing to
restore there). Reverted both nodes to `--proxy-mode iptables` via
`scripts/k3s-up.sh` (no flag); this required manually `ip addr flush dev
kube-ipvs0` on both nodes first, since switching a running node's kube-proxy
mode does not itself clean up the previous mode's dummy-device state (a
kube-proxy limitation, not a beep-specific rediscovery), and `ipvsadm -C` to
clear now-orphaned virtual-server entries left in the kernel's IPVS table.
Re-ran `scripts/smoke-k3s-controller.sh` afterward: full green
`GATE CONTROLLER-DRIVEN ROUND-TRIP: PASS`, confirming the rig is back to its
iptables-mode baseline, not left dirty. `beep-node-a`/`beep-node-b`/
`beep-client` left Running (matching every other smoke script's convention of
not stopping VMs on exit).
