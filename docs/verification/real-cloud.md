# Real-cloud verification plan

Passing items (a)-(e) on real cloud nodes lets beep claim Tier-2 real-fleet
fidelity, which the operator requires (2026-10-31) before calling beep
production ready (v1.0). Items (f)-(g) are optional.

Written for a u7s session to follow cold on GCP. Lima-rig equivalents are the
scripts named below; this plan covers what they cannot prove.

## Prerequisites

- **beep v0.7.0 (or later).** Every u7s release through v0.4.2-snapshot.2 pins
  beep v0.6.0 (`beep-lb@sha256:076a8474...`, via the image digest in u7s
  `manifests/beep.yaml`), which predates it. Bump that digest to v0.7.0 or
  later, and record the digest used.
- Kernel 6.6 or newer, systemd Linux, x86-64 or AArch64 nodes (support scope).
- GCP VPC with at least two subnets in different CIDRs (different regions are
  fine); `IPV4_IPV6` subnets for item (d).
- A client VM outside the VPC (another project/VPC or a non-GCP host).

## Already verified (do not redo)

u7s run 2026-10-19 (u7s `temp/e2e-install/20261019T133006Z/`), beep v0.6.0,
GCP e2-micro control plane + worker + client, all in one subnet 10.80.0.0/24:

- LB round trip passed.
- Client IP preserved for an intra-VPC client.
- An internet client via GCP 1:1 NAT reached beep then Traefik; its public IP
  was seen in `X-Forwarded-For` only (L7), no capture kept.

Not covered: disjoint subnets/uRPF, L4 external client IP, WireGuard
underlay, dual-stack, MTU, IPv6-only.

## Checklist

Record `net.ipv4.conf.{all,default,<iface>}.rp_filter` on every node before
each item.

**Beep evidence (B).** A plain-routed 200 proves nothing, so PASS for (a)-(d)
and (g) also requires: `ip -s -j link show geneve0` rx+tx packet counts on
both nodes grow across the request, and the ingress node's FLOW_TABLE holds
the flow (`sudo bpftool map dump pinned /sys/fs/bpf/beep/FLOW_TABLE --json`,
as `scripts/smoke-k3s-controller-v6only.sh` steps 9 and 12 do).

**(a) Disjoint subnets (required).**
Topology: two or more nodes in different subnets; ingress on node A, backend
pod on node B, client elsewhere.
Run: TCP/HTTP round trip through a LoadBalancer front; `tcpdump -ni any
'udp port 6081'` on both nodes.
PASS: response received; Geneve leaves A and arrives at B; return packets
reach the client with the front address as source; no provider anti-spoof
drops (VPC flow logs); (B).
Evidence: pcaps, rp_filter values, flow-log excerpt, beep logs.

**(b) External client, L4 client IP (required).**
Topology: client outside the VPC targeting the front/public address, with
`externalTrafficPolicy` `Cluster` and `Local`.
Run: backend that echoes the TCP peer address (not XFF), e.g. a raw TCP echo.
PASS: backend sees the client's real public IP as peer, not a node IP; (B).
Evidence: backend log, client's public IP, pcap on the backend node.

**(c) Node-to-node over WireGuard (required; stands in for Tailscale).**
Topology: nodes joined by a real `wg0` over the VPC/public path (not
loopback), with the wg address as the k3s `--node-ip` (underlay IP).
Run: as (a), Geneve carried inside wg0. Mirror `scripts/smoke-wg-2node.sh`
and `scripts/smoke-wg-2node-dualstack.sh`. Those use a bare loader with seeded
NODE_ALLOW; on the real fleet the controller's Node watch populates NODE_ALLOW,
so the k3s + controller deployment, not the bare loader, is under test.
PASS: round trip works; `wg show` handshake and transfer counters grow; Geneve
(UDP 6081) is visible on `wg0`; a pcap on the physical NIC shows only
WireGuard UDP, no cleartext Geneve; (B).
Evidence: `wg show`, pcaps on NIC and wg0, round-trip output.

**(d) Dual-stack with a pod backend (required).**
Topology: dual-stack subnets and k3s; PreferDualStack Service backed by a
regular (non-hostNetwork) pod on a non-ingress node.
Run: controller with both `--pod-cidr` values; v4 and v6 round trips from the
external client. Mirror `scripts/smoke-k3s-controller-dualstack.sh` step 13
(negative control with only the v4 `--pod-cidr`, then both).
PASS: for both v4 and v6 the response body is `Hostname: <pod name>` of the
non-hostNetwork pod and the client's real IP is preserved (step 13's check);
the v6 pod address is rejected with v4-only `--pod-cidr` and accepted with
both; (B).
Evidence: DaemonSet args, `kubectl get svc,endpointslices -o wide`, curl output
for both families, controller logs.

**(e) MTU (required).**
Run: `ping -M do -s <n>` (and `ping -6`) stepwise across the plain and wg0
node-to-node paths to find path MTU; fetch at least 100 MB through the front
and a response larger than the path MTU minus Geneve overhead.
PASS: transfer completes with matching checksum, no stalls or retransmit
storms; Geneve (+WireGuard) overhead recorded against the interface MTUs.
Evidence: MTU table, `ip -d link` for geneve0/wg0/NIC, payload sha256,
`ss -ti` retransmit counts.

**(f) IPv6-only node (optional, not blocking).**
On GCP if feasible: IPv6-only primary node, no NAT64/DNS64, registry pull over
native v6. PASS: (d) round trips over the node's v6 and image pull succeeds.
Mirror `scripts/smoke-k3s-controller-v6only.sh`.

**(g) Mixed fleet (optional, needs a v6-only node).**
Topology: a dual-stack node (DaemonSet `--node-ip` = v4 from status.hostIP)
and a v6-only node. The controller falls back to the peer's v6 underlay
(`pick_underlay_ip`) and the kernel picks the outer v6 source; only hardware
shows whether that source is one the v6-only peer's NODE_ALLOW holds (every
node's full underlay).
PASS: v6 round trip in both directions; `tcpdump` on the underlay shows outer
v6 src among the dual-stack node's Node InternalIPs; (B). The dual-stack node
logs a spurious "no shared address family" WARN (known); not a failure.

**(h) Not required.** Cross-provider latency, home NAT.

## Evidence and reporting

Archive each run under u7s `temp/<run-name>/<UTC-timestamp>/` with
`result.txt` and `run.log` (the 2026-10-19 convention) plus one subdirectory
per item (a)-(g).

Paste into `beep-903`: beep image digest and commit under test; u7s commit;
per-item PASS/FAIL with the criterion quoted; rp_filter values; the archive
path; deviations from this plan. The beep mayor signs off from that note.
