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
  resolve an `EndpointSlice` endpoint's hosting-node IP). Nothing broader.

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

2. **The VIP/front-IP range MUST be disjoint from the pod CIDR — LOUD if
   wrong, but hard to hit in a real cluster.** Under beep's
   node-owned-address model every node's own address doubles as a front
   IP, and a front IP inside the pod CIDR can byte-collide a forward and
   reverse flow key. The standalone `beep` loader (driven by `--fixture`
   for manual/smoke runs — not the shipped `beep-controller` DaemonSet
   binary) rejects such a VIP at startup: `vip_outside_pod_cidr`
   (`src/main.rs:195`). The DaemonSet binary itself never feeds this path a
   user-supplied VIP — its front IP is always a `Node` object's own
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
- `rbac.yaml` — `ServiceAccount` + `ClusterRole` + `ClusterRoleBinding` for
  the above.

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

Applying `deploy/rbac.yaml` and `deploy/daemonset.yaml` (with your own
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
