# servicelb controller DaemonSet requires AppArmor-unconfined

**Status:** Accepted
**Date:** 2026-09-11

## Context

`deploy/daemonset.yaml`'s controller pods crashlooped on every
AppArmor-enabled containerd node with `Error: creating pin dir
/sys/fs/bpf/beep: Permission denied (os error 13)`, before loading a
single eBPF program (`bd show beep-26s`). Root cause, confirmed with a
debug pod carrying the same `securityContext`: containerd's default
`cri-containerd.apparmor.d` profile denies all writes under bpffs
(`deny /sys/fs/[^c]*//** wklx` — everything under `/sys/fs/` except
`cgroup`), including `mkdir` and `BPF_OBJ_PIN`, even as UID 0 with
`CAP_BPF`/`CAP_NET_ADMIN` added. Linux capabilities and AppArmor are
separate confinement layers; capabilities don't grant AppArmor-mediated
file access. This affects any containerd-managed cluster with AppArmor
enabled, not just Lima/k3s.

## Decision

Set `securityContext.appArmorProfile.type: Unconfined` on the controller
container. Keep `privileged: false` and the existing `CAP_BPF`+
`CAP_NET_ADMIN` grant — this is Cilium's own posture for the identical
problem (its agent DaemonSet ships non-privileged + AppArmor-unconfined),
not a blanket `privileged: true`. Kubernetes 1.30+ honors the native
`securityContext.appArmorProfile` field directly; older clusters need the
deprecated `container.apparmor.security.beta.kubernetes.io/<container>:
unconfined` pod annotation instead.

`CAP_BPF`+`CAP_NET_ADMIN` alone gets past the AppArmor fix above but then
fails `BPF_PROG_LOAD` itself: the verifier's pointer-arithmetic relaxations
for a non-root load additionally gate on `perfmon_capable()` (CAP_PERFMON
or CAP_SYS_ADMIN), which neither of those two capabilities grants. Add
`CAP_PERFMON` to `add:` — still short of CAP_SYS_ADMIN or `privileged`.

## Rationale

Authoring a custom Localhost AppArmor profile scoped to exactly the
bpf()/mount surface this controller needs is narrower but requires
distributing and loading that profile out-of-band on every node before
the DaemonSet can schedule — a bootstrapping dependency this project
isn't ready to own. A containerd/k3s config change exempting CAP_BPF pods
cluster-wide isn't portable across CRI implementations. Unconfined is the
smallest change that matches a project this project already imitates
(Cilium) for the same eBPF-pinning requirement.

## Consequences

- The controller container runs without AppArmor mediation on any node.
  Its actual attack surface is unchanged: `hostNetwork: true` and
  `CAP_BPF`/`CAP_NET_ADMIN` already grant kernel-level device access that
  AppArmor's default profile only partially constrained.
- A future scoped Localhost profile (option (b) in beep-26s) remains open
  if node provisioning grows the ability to ship one.
