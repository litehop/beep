# deploy/

Manifest skeleton for the beep servicelb controller.

- `daemonset.yaml` points at `docker.io/valerauko/beep-lb:latest`, a
  dual-arch (linux/amd64 + linux/arm64) image built by the root
  `Dockerfile` and published by `.github/workflows/delivery.yaml`'s
  `image` job. `:latest` tracks the newest `v*` release tag (see
  `docs/decisions/versioning.md`); a push to `main` alone only publishes
  a `:<sha>` image. To run a specific version or commit, override the
  image with a local `kustomize` patch rather than editing this manifest,
  e.g. to pin `v0.1.0`:
  ```yaml
  # kustomization.yaml
  resources:
    - github.com/<org>/beep/deploy?ref=v0.1.0
  images:
    - name: docker.io/valerauko/beep-lb
      newTag: v0.1.0
  ```
- **RBAC is scoped to exactly what the design calls for:** list/watch/get on
  `Service`, `discovery.k8s.io/EndpointSlice`, and `Node` (the last needed to
  resolve an `EndpointSlice` endpoint's hosting-node IP), plus, in
  `kube-system` only, `create` on Secrets and `get` on the single Secret
  `servicelb-flow-hash-seed` (the cluster-wide backend-selection seed: the first
  controller to start creates it, the rest read it; every node must share it
  or ingress-node changes re-steer flows). Treat that Secret as sensitive:
  anyone who can read it can precompute which source ports hit which backend.
  Running controllers re-read the Secret every 30s and converge on it: a
  changed value is adopted (logged as a WARN, never the value) and a deleted
  Secret is recreated with the controller's current seed, first creator wins.
  To rotate, edit the Secret; every node switches within one poll interval.
  Flows already steered by a conntrack pin keep their backend; only new flows
  are placed with the new seed, and may land on different backends.

## Required per-cluster configuration & gotchas

Read this before deploying to any cluster other than the k3s-on-Lima dev rig
this manifest's defaults target. One of these is silent — get them right
the first time, then confirm with "Verify your deployment" below.

1. **`--pod-cidr` MUST match your cluster's real pod CIDR — this is the
   day-one gotcha.** `daemonset.yaml` defaults to k3s's own flannel CIDR,
   `10.42.0.0/16` (`deploy/daemonset.yaml:96`). If your cluster's actual pod
   network differs (e.g. Calico's `10.244.0.0/16`), every backend Pod is
   rejected by the controller's admission gate: an `EndpointSlice` endpoint
   is only admitted if its `pod_ip` falls inside `--pod-cidr`, or equals its
   hosting node's own IP, the hostNetwork case
   (`controller/src/reconcile.rs:211-243`). The result: `POD_TARGETS` ends
   up empty on every node, so the dataplane has no backend to deliver to.
   The controller logs a `controller: WARN N endpoint(s) rejected from
   POD_TARGETS: ...` on every reconcile while this is wrong — watch
   `kubectl logs` for it, since a `Running` Pod status alone proves
   nothing. Fix by overriding `--pod-cidr` via a local kustomize patch
   (never edit this manifest directly) to your cluster's real pod CIDR
   (`kubectl cluster-info dump | grep -i cluster-cidr`, or your CNI's own
   config), then confirm with "Verify your deployment" below.

2. **The front-IP range MUST be disjoint from the pod CIDR — LOUD if
   wrong, but hard to hit in a real cluster.** Under beep's
   node-owned-address model every node's own address doubles as a front
   IP, and a front IP inside the pod CIDR can byte-collide a forward and
   reverse flow key. The standalone `beep` loader (driven by `--fixture`
   for manual/smoke runs — not the shipped `beep-controller` DaemonSet
   binary; it requires an explicit `--pin-dir` and must never share one with
   the controller, since it prunes every front not in its `--fixture` set)
   rejects such a front at startup: `front_outside_pod_cidr`
   (`src/main.rs:195`). The DaemonSet binary itself never feeds this path a
   user-supplied front — its front IP is always a `Node` object's own
   address — so on a normally-addressed cluster (node IPs and pod IPs are
   always disjoint ranges) this can't come up in practice. Full rationale
   and the separate Service-CIDR caveat:
   `docs/design/kube-proxy-coexistence.md`.

3. **kube-proxy mode must be iptables or nftables — IPVS is unsupported.**
   Reproduced live: under IPVS mode, kube-proxy on every node ends up
   binding every *other* node's real IP as a local address, breaking
   node-to-node connectivity. Check before deploying:
   ```bash
   kubectl -n kube-system get configmap kube-proxy -o yaml | grep mode
   ```
   Full mechanism and the k3s verification recipe:
   `docs/design/kube-proxy-coexistence.md`.

4. **Node self-prep (`geneve0`, `rp_filter=0`) is automatic — nothing to do
   here.** See "Node self-prep" under "Deployment model" below; it is part
   of controller startup, not a manual step this manifest or its operator
   needs to provide.

5. **Only one uplink, `eth0`, is configured by default — add a second
   `--uplink-iface` per additional client-facing interface a node admits
   traffic on.** `daemonset.yaml` ships `--uplink-iface=eth0`
   (`deploy/daemonset.yaml:119`); the flag is repeatable and required —
   the loader refuses to start with none — so a node that also takes
   client traffic over e.g. a WireGuard mesh interface needs a second
   `--uplink-iface=wg0` entry alongside it, added via a local kustomize
   patch. A flow's reply always egresses the same uplink it arrived on
   (symmetric return) — there's no separate egress interface to configure.
   Design rationale: `docs/decisions/servicelb-multi-symmetric-uplink.md`.

## Files

- `daemonset.yaml` — one controller pod per node (`hostNetwork: true`),
  tolerates all taints so it runs on every node including control-plane
  nodes, and mounts the host's bpffs (`/sys/fs/bpf`) so pinned programs/maps
  survive pod restarts. The main container runs `CAP_BPF` + `CAP_NET_ADMIN`
  only (no `privileged: true`, no CRI socket mount) and requires
  `appArmorProfile: Unconfined` to pin to bpffs under containerd's default
  AppArmor profile — see
  `docs/decisions/servicelb-controller-apparmor-unconfined.md`. A separate,
  privileged `node-prep` initContainer runs first for the one step that
  needs it (disabling `rp_filter`) — see
  `docs/decisions/servicelb-rp-filter-init-container.md`.
- `configmap.yaml` — `beep-config`, the sizing caps (see "Configuration").
- `rbac.yaml` — `ServiceAccount` + `ClusterRole` + `ClusterRoleBinding` (plus
  a `Role`/`RoleBinding` for the flow-hash seed Secret and one for the
  per-node Leases) for the above.

## Configuration

`configmap.yaml` (`beep-config`, `kube-system`) holds the sizing caps. The
DaemonSet loads it with `envFrom`, so each key is an environment variable of
the controller container. The ConfigMap is required: a pod whose
`beep-config` is missing stays in `CreateContainerConfigError`. A CLI flag
(e.g. from a kustomize patch) overrides the env var.

| Option | Env var (ConfigMap key) | Default | Meaning |
| --- | --- | --- | --- |
| `--max-fronts` | `BEEP_MAX_FRONTS` | 1024 | Most fronts (front address x Service port x protocol) a node holds. Under the every-node-is-a-front model that is nodes x Service ports. Sets `FRONT_META` `max_entries`. |
| `--endpoints-per-front` | `BEEP_ENDPOINTS_PER_FRONT` | 4 | Endpoints each front is sized for. Sets `FRONT_ENDPOINTS` `max_entries` = `max-fronts` x `endpoints-per-front` x 2 (8192 by default; the 2 is swap headroom for a front's next generation). |

Both maps are `BPF_F_NO_PREALLOC`, so the caps are ceilings: a node pays
about 16 B per slot up front (the bucket array) and entries cost memory only
as they are used.

| Map | Up front | Per used entry | Defaults, all slots used |
| --- | --- | --- | --- |
| `FRONT_META` | ~16 B x `max-fronts` | ~96 B per front | ~16 KiB + ~96 KiB |
| `FRONT_ENDPOINTS` | ~16 B x `max-fronts` x `endpoints-per-front` x 2 | ~128 B per endpoint row | ~128 KiB + ~1 MiB |

Prefer a value at or just below a power of two: the kernel rounds the bucket
array up, so a cap just above one doubles the up-front cost. A front update
that would not fit under a map's cap is refused whole with a capacity error
naming the map, and the front keeps its previous endpoints.

The flags in `daemonset.yaml`'s `args` (`--pod-cidr`, `--node-ip`,
`--uplink-iface`, ...) are per-cluster or per-node values, not part of the
ConfigMap (gotchas above). The remaining map caps (`--flow-table-max-entries`
and similar) are CLI-only flags with defaults; see `beep-controller --help`.

### Changing a cap

Edit the ConfigMap, then restart the DaemonSet. Pods do not reread env vars,
so nothing happens until you do:

```bash
kubectl -n kube-system edit configmap beep-config
kubectl -n kube-system rollout restart daemonset/servicelb-controller
```

The restarted controller sees a pinned map whose `max_entries` differs from
its new definition and recreates it (a `MapShape` mismatch), copying the
old entries into the new map before any program is attached; the
controller's first reconcile then writes back whatever did not fit. Only
the front maps change (`FLOW_TABLE` is untouched), so established flows keep
their conntrack entries. If a cap shrinks below the entries in use, whole
fronts are kept in key order, the loss is logged with counts, and the
controller repopulates the rest.

Observed on the k3s rig (2 nodes; `BEEP_MAX_FRONTS` 1024 to 1000;
`scripts/smoke-k3s-controller.sh`, leg H): the restarted controllers
showed `BEEP_MAX_FRONTS=1000` in their process environment and the pinned maps
reported `max_entries` 1000 (`FRONT_META`) and 8000 (`FRONT_ENDPOINTS`). A
TCP connection established through a front before the change was still the
same connection (same client port, same backend pod) when its 100 s request
finished after the rollout (62 s for both nodes). Fresh connections, probed
about every 0.1 s through each node's front for the whole rollout, saw 0
failures in 653 probes per node, so no new-connection window longer than one
probe interval was observed. Expect a gap only if a cap shrinks below the
fronts in use: the dropped fronts answer nothing until the controller
repopulates them.

## Node liveness Leases

Each controller renews a `coordination.k8s.io/v1` Lease `beep-node-<node>`
in `--lease-namespace` (default `beep-leases`, created by `rbac.yaml` so the
Lease Role is not bound in `kube-system`, where write access to Leases could
let a compromised beep pod hijack control-plane leader election; `NODE_NAME`
supplies the node name) every 10 s, with a 40 s duration -- the same timing Kubernetes
uses for node leases. The Lease carries the node's addresses in the
`beep.litehop.io/node-ips` annotation. Every controller lists these Leases
every ~10-15 s (10 s plus up to 5 s of jitter) and removes any
`status.loadBalancer.ingress` entry whose address has no live Lease, so a
node whose beep pod stopped is dropped from every Service within about
40 s + one prune interval. When that node's controller returns it renews
its Lease and re-adds its own entry.

Liveness is judged by observation: a Lease is live while its `renewTime`
keeps changing as seen by the pruning controller's own monotonic clock, so
wall-clock skew between nodes is irrelevant. A freshly started controller
does not prune for its first 40 s and never prunes until it sees its own
Lease renewing, so a missing Lease permission cannot empty every Service's
ingress. Timings are constants (`controller/src/lease.rs`), not flags.

## Upgrading from 0.4

Apply the new objects before the DaemonSet rolls:

1. `deploy/rbac.yaml` creates the `beep-leases` Namespace and the Lease Role
   (with a CSR-minted kubeconfig, also bind it in `beep-leases`; see
   "Kubeconfig").
2. `deploy/configmap.yaml` creates `beep-config`. The DaemonSet's `envFrom`
   is required, so pods stay in `CreateContainerConfigError` without it.
3. `deploy/daemonset.yaml` last. It sets `NODE_NAME`; the controller requires
   `--node-name` (env `NODE_NAME`) and exits without it.

Two different things reset or keep flows, so do not confuse them:

- **The 0.4 to 0.5 upgrade flushes conntrack once.** `FLOW_TABLE` and
  `FRONT_META` change layout, so the loader recreates those pinned maps and
  established flows reset. Schedule the rollout accordingly.
- **A later 0.5 ConfigMap change plus `rollout restart` does not drop
  established flows.** Only the front maps are recreated, with their entries
  copied over; `FLOW_TABLE` is untouched (see "Changing a cap").

Behaviour changes to expect:

- A front with no usable endpoint (count 0: `externalTrafficPolicy: Local`
  with no usable local pod, or a Service with no ready endpoints) now
  silently drops new connections. 0.4 answered with a TCP RST or ICMP
  port-unreachable. Established flows keep forwarding.
- Services may now spread over every ready endpoint and honour
  `externalTrafficPolicy` and `spec.trafficDistribution`; see "Service
  policy".
- `--front-meta-max-entries` and `--front-endpoints-max-entries` are gone;
  use `--max-fronts` and `--endpoints-per-front` (see "Configuration").

Full list: `CHANGELOG.md`.

## Service policy

Each node's controller derives a front's endpoints from the Service spec
(`controller/src/reconcile.rs`):

- `externalTrafficPolicy: Local` uses only endpoints on the ingress node:
  ready ones, else serving-but-terminating ones, else none (count 0, silent
  drop). It ignores `spec.trafficDistribution`. A node with no usable local
  pod removes its own address from `status.loadBalancer.ingress`, so clients
  are only sent to nodes that can serve them.
- Otherwise `spec.trafficDistribution` of `PreferSameNode`, `PreferClose` or
  `PreferSameZone` prefers local endpoints and falls back to all ready ones.
  beep has no zone model, so the latter two behave as `PreferSameNode`.
- No `trafficDistribution`, or an unknown value (logged as a WARN), spreads
  uniformly over all ready endpoints, and every node is listed in `ingress`.

Switching policy does not evict pinned flows; they drain naturally.

## Security & underlay assumptions

**The Geneve underlay MUST prevent IP spoofing.** UDP 6081 is open on every
node, and `rp_filter` is disabled (see "Node self-prep"). The only
admission check on tunnelled packets is `NODE_ALLOW`: the outer source IP
must be a known peer node, otherwise the packet is dropped. That makes the
outer source IP the trust boundary, and it holds only if hosts on the
underlay cannot forge a peer's address.

Without anti-spoofing a host on the same L2 can forge a peer's address and
inject Geneve packets carrying a forged inner client IP into backends (log
poisoning, IP-ACL and segmentation bypass). Non-peer, off-L2 and routed
senders are blocked. Close the gap with switch-enforced anti-spoofing (IP
Source Guard, Dynamic ARP Inspection, port security) or run the underlay
over WireGuard or IPsec, which makes `NODE_ALLOW` defense in depth.
Rationale: `docs/decisions/geneve-underlay-trust-model.md`.

## Deployment model

Per `docs/design/ebpf-lb-dataplane.md`'s "Userspace control plane" section:
the controller runs per node (eBPF maps are local kernel memory, so a
central controller can't program them), loads and pins the tc-bpf programs
once, watches `Service`/`EndpointSlice`, writes maps on change, then idles —
the kernel does the packet forwarding.

Node self-prep is part of that same startup, not a separate step this
manifest or its operator needs to provide: `geneve0` (an address-less,
external-mode Geneve device) is created if it doesn't already exist, and the
reverse-path filter is disabled on `all` and `geneve0`
(`net.ipv4.conf.{all,geneve0}.rp_filter=0`). The `rp_filter` write runs in
the privileged `node-prep` initContainer, not the main container — see
`docs/decisions/servicelb-rp-filter-init-container.md` for why.

This is a deliberate, operator-decided tradeoff, not an oversight — see
`docs/decisions/geneve-rp-filter-disable.md` for the rationale and the
revisit trigger.

## Kubeconfig

`beep-kubeconfig` only parses an X.509 client-cert kubeconfig file (no
in-cluster ServiceAccount token support yet), so `--kubeconfig` points at a
Secret-mounted kubeconfig, not the ServiceAccount's own projected token.
Provisioning that Secret (`beep-controller-kubeconfig` in `kube-system`) is
left to the cluster operator/deploy tooling -- not this manifest. The
parser only reads four fields -- `server:`, `certificate-authority-data:`,
`client-certificate-data:`, `client-key-data:` -- so any kubeconfig
containing those four works, however it was minted.

**Minting one via the Kubernetes CSR API**, scoped to exactly the RBAC
`deploy/rbac.yaml` grants (run as a cluster admin who can approve CSRs):

```bash
# 1. Keypair + CSR for CN=beep-controller (the identity the cert authenticates as)
openssl req -new -newkey rsa:2048 -nodes \
  -keyout beep-controller.key -out beep-controller.csr \
  -subj "/CN=beep-controller"

# 2. Submit + approve a client-auth CertificateSigningRequest
kubectl apply -f - <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: beep-controller
spec:
  request: $(base64 < beep-controller.csr | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  usages: ["client auth"]
EOF
kubectl certificate approve beep-controller
kubectl get csr beep-controller -o jsonpath='{.status.certificate}' \
  | base64 -d > beep-controller.crt

# 3. Bind that identity to the SAME ClusterRole deploy/rbac.yaml defines --
#    a User, not the ServiceAccount rbac.yaml's own binding targets: X.509
#    client-cert auth authenticates as a distinct Kubernetes User (the
#    cert's CN), never as the DaemonSet's own ServiceAccount.
kubectl create clusterrolebinding beep-controller-csr \
  --clusterrole=servicelb-controller --user=beep-controller
kubectl create rolebinding beep-controller-csr-flow-hash-seed -n kube-system \
  --role=servicelb-controller-flow-hash-seed --user=beep-controller
kubectl create rolebinding beep-controller-csr-node-lease -n beep-leases \
  --role=servicelb-controller-node-lease --user=beep-controller

# 4. Assemble a kubeconfig with exactly the 4 fields beep-kubeconfig reads
kubectl config set-cluster beep --server=https://<api-server>:6443 \
  --certificate-authority=<cluster-ca.crt> --embed-certs \
  --kubeconfig=beep-controller.kubeconfig
kubectl config set-credentials beep-controller \
  --client-certificate=beep-controller.crt --client-key=beep-controller.key \
  --embed-certs --kubeconfig=beep-controller.kubeconfig
kubectl config set-context beep-controller \
  --cluster=beep --user=beep-controller --kubeconfig=beep-controller.kubeconfig
kubectl config use-context beep-controller --kubeconfig=beep-controller.kubeconfig

# 5. Ship it as the Secret the DaemonSet mounts -- the key name must be
#    `kubeconfig` to land at /etc/beep-controller/kubeconfig
kubectl create secret generic beep-controller-kubeconfig -n kube-system \
  --from-file=kubeconfig=beep-controller.kubeconfig
```

## Verify your deployment

Applying `deploy/rbac.yaml`, `deploy/configmap.yaml` and `deploy/daemonset.yaml` (with your own
`--pod-cidr` override) leaves every controller Pod `Running` even when
gotcha #1 above is misconfigured -- a healthy Pod status proves nothing
about actual delivery, and the WARN log is easy to miss across a fleet of
`Running` pods. Confirm the real thing:

1. Apply a `type=LoadBalancer` Service plus a backend that echoes the
   client's address, e.g. `traefik/whoami`:
   ```bash
   kubectl create deployment whoami --image=docker.io/traefik/whoami:latest --port=80
   kubectl expose deployment whoami --type=LoadBalancer --port=80
   ```
2. Wait for `status.loadBalancer.ingress` to list your nodes' addresses,
   then curl one:
   ```bash
   kubectl get svc whoami -o jsonpath='{.status.loadBalancer.ingress[*].ip}'
   curl http://<node-ip>:80/
   ```
   Expect **HTTP 200**, with the response body's `RemoteAddr:` reporting
   your **real curl client IP** -- not a node or Pod address. Preserving
   that source IP across the Geneve tunnel is the entire point of this LB.
3. If it doesn't work, `bpftool map dump` (pin dir defaults to
   `/sys/fs/bpf/beep`) tells you which gotcha above you hit:
   ```bash
   bpftool map dump pinned /sys/fs/bpf/beep/POD_TARGETS --json | jq length
   bpftool map dump pinned /sys/fs/bpf/beep/FLOW_TABLE --json | jq length
   ```
   - `POD_TARGETS` empty and `FLOW_TABLE` stays `0` after a request -> the
     pod-CIDR admission gate rejected the backend (gotcha #1) -- the
     forward packet is dropped before it ever reaches `FLOW_TABLE`.
   - `FLOW_TABLE` is non-zero but the client still gets no response -> the
     packet was admitted; look at node-prep/routing instead (e.g.
     `rp_filter`, a missing Geneve route) rather than the pod-CIDR gate.
