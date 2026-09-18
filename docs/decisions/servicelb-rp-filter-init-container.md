# servicelb controller runs rp_filter node-prep in a privileged initContainer

**Status:** Accepted
**Date:** 2026-09-18

## Context

`deploy/daemonset.yaml`'s controller crash-looped on every real
containerd-CRI node: `disable_rp_filter()` (`src/lib.rs`) failed writing
`/proc/sys/net/ipv4/conf/*/rp_filter` with `EROFS` (`bd show beep-1vf`).
Containerd's default OCI spec marks `/proc/sys` read-only
(`readonlyPaths`) for a non-privileged container; the main container's
`CAP_NET_ADMIN` and `appArmorProfile: Unconfined`
(`servicelb-controller-apparmor-unconfined.md`) do not unmask it —
mount-level readonly is a third, independent confinement layer from
capabilities and AppArmor, the same lesson that ADR already drew for
bpffs writes. Invisible until the k3s rig started deploying the
commit-under-test's real `:sha` image instead of a release predating
this self-prep step.

## Decision

Move the `rp_filter` write into a new, privileged `node-prep`
initContainer that runs `beep-controller --node-prep` and exits. The main
container is unchanged: `privileged: false`, the same minimal
`CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON` set, the same
`appArmorProfile: Unconfined`. `--node-prep` reuses the existing
`ensure_geneve_iface`/`disable_rp_filter` functions rather than
duplicating their writes in initContainer shell, so the sysctl set stays
exactly what `geneve-rp-filter-disable.md` decided:
`conf.all.rp_filter=0` plus `conf.<geneve_iface>.rp_filter=0` — no uplink
or other-interface writes (that is a separate, deferred, per-interface
hardening question, not this fix).

Sequencing: `conf.<geneve_iface>.rp_filter` cannot be written before
`geneve0` exists, so `--node-prep` runs `ensure_geneve_iface` immediately
before `disable_rp_filter`, in the same order the main container used to.
The main container still calls `ensure_geneve_iface` itself afterward — an
idempotent no-op once the initContainer has already created it, and a
clear failure instead of a silent skip if it somehow hasn't.

## Rationale

A privileged main container (option (a) in beep-1vf) was rejected: it
would broaden the attack surface for the container's entire running
lifetime, not just the few hundred milliseconds node-prep needs, and
would abandon the non-privileged posture the AppArmor ADR already
established for the identical CAP_BPF/bpffs problem. A containerd/CRI
config change to unmask `/proc/sys/net` cluster-wide (option (c)) was
rejected for the same portability reason that ADR rejected a custom
Localhost AppArmor profile: it isn't portable across the CRI
implementations this project targets. A privileged initContainer bounds
the elevated-privilege window to one node-prep run per pod (re)start,
after which it exits and never runs again.

## Consequences

- `ensure_geneve_iface` now runs twice on a fresh pod (once in
  `--node-prep`, once idempotently in the main container) — accepted
  redundancy, not code duplication.
- Per-interface (uplink) `rp_filter` hardening remains deferred (beep-hl6);
  this ADR does not change the sysctl set.
