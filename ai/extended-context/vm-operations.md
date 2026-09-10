# VM Operations

Answer: use `scripts/lima-up.sh` to bring up a VM, build on the host with
`scripts/smoke.sh`, and inspect running state through the `mcp__beep-*`
tools — never `limactl stop` when a session ends.

## Lima lifecycle

`scripts/lima-up.sh [vm-name]` (default `beep-smoke`) is idempotent: it
starts the named VM if it already exists (`limactl start "$VM_NAME"`), or
provisions it fresh from `lima/beep.yaml` on first run. Run it at the start
of any session that needs a VM; re-running it against an already-running
VM is a no-op start, safe to call repeatedly.

**Never `limactl stop` a VM on task completion.** Workers leave VMs running
across sessions — the next session (yours or another worker's) expects to
find its assigned VM already up and reuses it via `lima-up.sh`. Stopping a
VM you didn't provision breaks whoever is mid-task on it.

## The VM pool

Four named VMs, fixed roles:

- **`beep-smoke`** — single-node smoke gate. `scripts/smoke.sh` targets this
  by default: loads the tc-bpf classifiers into a real kernel verifier and
  drives packets through the Geneve encap/decap dataplane on one node.
- **`beep-node-a`** + **`beep-node-b`** — cross-node WireGuard pair, used by
  `scripts/smoke-wg-2node.sh`. This is the known-blocker path (bead
  beep-n24; the original mayor-f3ru5 redirect-drop blocker is fixed by
  PR #9): cross-node conntrack/WireGuard behavior that single-node smoke
  can't exercise.
- **`beep-client`** (`lima/beep-client.yaml`, started via
  `limactl start --tty=false --name=beep-client lima/beep-client.yaml`) — the
  3rd-VM client for the cross-node rigs (bead beep-vuh). A 2-VM rig's client
  is necessarily co-located with `beep-node-b`, so its address is LOCAL to
  that node and the return leg never leaves `lo`/veth to exercise beep's
  tunnel-return hook. `beep-client` joins the same `user-v2` switch as
  `beep-node-a`/`beep-node-b`, which is verified to give it a peer address
  reachable from `beep-node-a` while remaining non-local to `beep-node-b`
  (`ip route get <beep-client-addr>` on `beep-node-b` resolves via `eth0`,
  not `local … dev lo`). Not yet wired into the smoke scripts — provisioning
  and topology verification only so far.

Assign one VM per concurrent dataplane worker — two workers must not share
a VM, since each smoke run loads/unloads real bpf programs and mutates live
netns/veth fixtures. A worker touching `beep-ebpf` or conntrack logic claims
one of the pool VMs for the duration of its task; a worker doing host-only
or `beep-common` work needs none.

## Host build + copy model

`beep-ebpf` and `beep` cannot compile natively on macOS (the loader links
Linux-only syscalls; the eBPF crate needs `bpfel-unknown-none`). `smoke.sh`
cross-builds on the host instead of building inside the VM:

1. Host toolchain (nightly + `rust-src` + `bpf-linker` + `cargo-zigbuild`)
   cross-compiles `beep` and its embedded `beep-ebpf` object to
   `aarch64-unknown-linux-gnu`.
2. `smoke.sh` copies the resulting loader binary, plus
   `scripts/smoke-remote.sh`, into the VM with `limactl copy`.
3. `smoke-remote.sh` runs *inside* the VM as root: it builds a self-contained
   veth-pair + netns fixture, loads the three tc-bpf classifiers, asserts
   the verifier accepted them, and drives client → VIP → backend TCP round
   trips through the real dataplane.

Nightly and `bpf-linker` stay host-side only — never installed or invoked
inside the VM. The VM only needs `bpftool` for independent load
confirmation (already present on `beep-smoke`; otherwise
`apt-get install linux-tools-$(uname -r)`).

## In-VM inspection via MCP

Each pool VM is also exposed as an MCP server (`beep-smoke`, `beep-node-a`,
`beep-node-b` in `.mcp.json`, invoked as `limactl mcp serve <vm>`), reachable
as `mcp__beep-<vm>__*` tools. Use these for read-only inspection of live VM
state without opening a shell:

- `bpftool map dump` — read conntrack / VIP→backend map contents while the
  dataplane is loaded.
- `ip -s link` — check veth/interface counters on the smoke fixture.
- `dmesg` — check kernel/verifier log output after a load.

Prefer these tools over ad hoc `limactl shell` commands when the task is
inspection rather than mutation — they keep the VM's state legible to other
sessions watching the same pool.

**The MCP server needs its VM already started.** `limactl mcp` attaches to a
running VM; against a stopped or not-yet-provisioned VM it errors, so
`mcp__beep-<vm>__*` shows `CONNECTION_CLOSED` at session start until
`lima-up.sh` has brought the VM up. Read that as "VMs not started yet," not a
misconfiguration — the servers connect once each VM is running. The smoke
scripts drive Lima via `limactl` directly, so the dataplane gate still holds
while MCP is down.

## Host prerequisites

Required on the macOS host before any of the above works:

```bash
rustup toolchain install nightly --component rust-src
rustup target add aarch64-unknown-linux-gnu --toolchain nightly
cargo install bpf-linker cargo-zigbuild
```

Plus `limactl` itself (Lima), for VM lifecycle and the `mcp__beep-*`
bridge. See `scripts/smoke.sh`'s header comment for the exact tool checks
it runs before starting.

## Related

- `scripts/lima-up.sh`, `scripts/smoke.sh`, `scripts/smoke-remote.sh`,
  `scripts/smoke-wg-2node.sh` — the scripts this doc describes.
- `lima/beep.yaml` — the VM image definition `lima-up.sh` provisions from.
- `docs/design/ebpf-lb-dataplane.md` — why the dataplane needs a live
  verifier smoke test at all (verifier rejection under churn/scale).
- bead beep-n24 — the cross-node WireGuard blocker `beep-node-a` /
  `beep-node-b` exist to reproduce (mayor-f3ru5's original redirect-drop
  blocker is fixed by PR #9).
