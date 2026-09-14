# Extended Context

Longer reference docs, loaded on demand rather than kept in the main
CLAUDE.md. Pulled in when a task needs the detail; skip otherwise.

| Doc | Covers |
| --- | --- |
| [`vm-operations.md`](./vm-operations.md) | Lima VM lifecycle, the `beep-smoke`/`beep-node-a`/`beep-node-b` pool, the host-build-and-copy model `scripts/smoke.sh` uses, and in-VM inspection via `mcp__beep-*`. |
| [`roadmap.md`](./roadmap.md) | Settled ServiceLB dataplane state, the testable-by-u7s bar, near-term work, and open versioning decisions -- read first for a fresh session. |
| [`k3s-e2e-rig.md`](./k3s-e2e-rig.md) | The k3s-controller e2e VM rig (`k3s-up.sh`/`e2e-lb-k3s.sh`/`smoke-k3s-controller.sh`): VM roles, standing up + running the LoadBalancer e2e proof, and driving it via `mcp__beep-node-a`/`-b` + `limactl`. |
