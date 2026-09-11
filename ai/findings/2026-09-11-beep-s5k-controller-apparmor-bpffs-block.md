# controller-driven k3s round trip: DaemonSet crashloops before loading any eBPF program

Bead: beep-s5k

**Verdict:** the round trip never starts. `deploy/daemonset.yaml`'s
`servicelb-controller` pods CrashLoopBackOff on both nodes with
`Error: creating pin dir /sys/fs/bpf/beep: Permission denied (os error 13)`
before loading a single eBPF program. Root cause: containerd's default
`cri-containerd.apparmor.d` AppArmor profile, applied automatically to
every non-privileged pod on this (AppArmor-enabled, Ubuntu 24.04) cluster,
denies ALL writes under the bpffs mount (`/sys/fs/bpf`) -- both directory
creation and `BPF_OBJ_PIN` -- even as UID 0 with `CAP_BPF`/`CAP_NET_ADMIN`
added. Linux capabilities and AppArmor are separate confinement layers;
the capabilities this DaemonSet already requests don't reach AppArmor's
mediation. Not fixed here: loosening this DaemonSet's AppArmor confinement
is a security-posture decision needing explicit operator sign-off, filed
as beep-26s.

Evidence gathered on the real k3s-on-Lima cluster (`beep-node-a` server +
`beep-node-b` agent, `scripts/k3s-up.sh`'s `lima/beep-k3s.yaml` profile),
deploying the actual published `docker.io/valerauko/beep-lb:latest` image
(delivery.yaml run `34543538486`, headSha `ef2677e`, confirmed pullable on
both nodes via `k3s ctr images pull`) via `scripts/smoke-k3s-controller.sh`.

## 1. The gate reaches the controller deploy step cleanly

`scripts/smoke-k3s-controller.sh` PASSes cluster bring-up
(`CLUSTER-UP: PASS`), creates `geneve0` on both nodes, provisions the
controller's kubeconfig Secret from node-a's own admin kubeconfig
(`server:` rewritten from `127.0.0.1` to node-a's real address, since
node-b -- a k3s agent -- has no local apiserver at `127.0.0.1:6443`), and
applies `deploy/rbac.yaml` + `deploy/daemonset.yaml` without error.

## 2. Both controller pods CrashLoopBackOff immediately

```
servicelb-controller-588pz   0/1   CrashLoopBackOff   1 (9s ago)   12s   192.168.104.13   lima-beep-node-a
servicelb-controller-mq6k5   0/1   CrashLoopBackOff   1 (9s ago)   12s   192.168.104.14   lima-beep-node-b
```

Container logs (identical on both nodes):

```
warning: setrlimit(RLIMIT_MEMLOCK) failed (harmless on memcg-accounted kernels)
Error: creating pin dir /sys/fs/bpf/beep

Caused by:
    Permission denied (os error 13)
```

An earlier run (before this doc's final evidence capture) also logged the
BPF_OBJ_PIN variant of the same failure, once `/sys/fs/bpf/beep` happened
to already exist from a prior attempt:

```
Error: loading beep-ebpf

Caused by:
    0: loading the beep-ebpf object
    1: map error: map `Some("TARGET_PORTS")` requested pinning. pinning failed
    2: map `Some("TARGET_PORTS")` requested pinning. pinning failed
    3: `BPF_OBJ_PIN` failed
    4: Permission denied (os error 13)
```

This confirms the denial is not specific to `mkdir` -- every bpffs write
this process attempts (directory creation, object pinning) is blocked.

## 3. Root cause isolated: AppArmor, not capabilities or DAC

A debug pod (`kube-system/bpf-debug`, `nodeName: lima-beep-node-b`,
`hostNetwork: true`, identical `securityContext` to the DaemonSet: `drop:
["ALL"], add: ["BPF", "NET_ADMIN"]`, same `bpffs` hostPath mount) running
the same `valerauko/beep-lb:latest` image with `sleep 3600` as its command
reproduced the failure directly:

```
$ kubectl -n kube-system exec bpf-debug -- id
uid=0(root) gid=0(root) groups=0(root)
$ kubectl -n kube-system exec bpf-debug -- ls -la /sys/fs/bpf
drwx-----T 2 root root 0 ... .
$ kubectl -n kube-system exec bpf-debug -- mkdir -p /sys/fs/bpf/test123
mkdir: cannot create directory '/sys/fs/bpf/test123': Permission denied
```

UID 0, matching owner (`root:root`, mode `0700`) -- a plain DAC check would
pass. Pre-creating the pin directory from the HOST side (outside the
container, as real root) and re-testing a plain file write from inside the
(still-confined) pod also failed:

```
$ kubectl -n kube-system exec bpf-debug -- touch /sys/fs/bpf/beep/testfile
touch: cannot touch '/sys/fs/bpf/beep/testfile': Permission denied
```

Adding the (deprecated but still honored) AppArmor-unconfined annotation
to the SAME debug pod spec immediately fixed both:

```
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/debug: unconfined
```

```
$ kubectl -n kube-system exec bpf-debug -- mkdir -p /sys/fs/bpf/test123
$ kubectl -n kube-system exec bpf-debug -- ls -la /sys/fs/bpf
drwxr-xr-x 2 root root 0 ... test123
```

`dmesg` confirms the profile in question is loaded and active on both
nodes: `apparmor="STATUS" operation="profile_load" profile="unconfined"
name="cri-containerd.apparmor.d"` (containerd auto-generates and loads
this profile at startup; it applies to every pod that doesn't request
`privileged: true` or an explicit override).

## 4. Why this isn't fixed in this bead

Fixing it means loosening a privileged, `hostNetwork: true` DaemonSet's
AppArmor confinement (`securityContext.appArmorProfile.type: Unconfined`,
or authoring and distributing a custom profile). That is a security-
posture decision the operator should make explicitly, not something an
agent session should bake into `deploy/daemonset.yaml` unreviewed --
confirmed by Claude Code's own auto-mode classifier declining to apply
that exact manifest change against the live cluster, flagging it as a
security weakening. Filed as beep-26s with three concrete options
(Unconfined, a scoped custom Localhost profile, or a containerd/k3s config
exemption) for the operator to choose from.

## 5. What this means for beep-s5k / mayor-9gr0n

This is a genuine, previously-unknown deployment-time blocker specific to
running the controller under a real (AppArmor-enabled) containerd cluster
-- Tier-1's fixture rigs (`smoke.sh`/`smoke-wg-2node.sh`/
`smoke-eth-ingress-2node.sh`) run the `beep` loader as a bare host process,
never inside a confined container, so they could never surface it. Once
beep-26s is resolved, `scripts/smoke-k3s-controller.sh` should get past
`CONTROLLER-DEPLOY` and continue on to the actual Service/EndpointSlice/
round-trip assertions it already implements.
