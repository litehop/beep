# u7s-servicelb (Phase 1: aya eBPF skeleton)

Loader for the ServiceLB eBPF dataplane
(`ai/extended-context/ebpf-lb-dataplane.md`,
`docs/decisions/ebpf-toolchain-aya.md`). Phase 1 attaches four no-op tc-bpf
classifiers and pins them under a bpffs directory; no packet mutation yet
(Phase 2).

This crate is a nested workspace (`servicelb-ebpf` is its no_std program
sibling) and is excluded from the outer u7s workspace: it links Linux-only
syscalls (`bpf(2)`, netlink) and cannot compile on the outer workspace's
host platforms. It only builds and runs on Linux.

## Building

Requires a `nightly` toolchain with the `rust-src` component, and
`bpf-linker` on `PATH` (`cargo install bpf-linker` or a prebuilt release
from https://github.com/aya-rs/bpf-linker/releases).

```console
$ rustup toolchain install nightly --component rust-src
$ cargo install bpf-linker
$ cargo build --release   # from this directory; builds servicelb-ebpf too
```

`build.rs` cross-builds `servicelb-ebpf` for `bpfel-unknown-none`/
`bpfeb-unknown-none` (endianness matched to the host) via `aya-build`, using
`.cargo/config.toml`'s `linker = "bpf-linker"` for that target, and embeds
the resulting object into the loader binary.

## Running

```console
$ sudo ./target/release/u7s-servicelb \
    --uplink-iface eth0 --geneve-iface geneve0 --pin-dir /sys/fs/bpf/servicelb
```

Requires `CAP_BPF`/`CAP_NET_ADMIN` (root, or the DaemonSet's intended
capability set in later phases). Attaches all four hooks and pins each
link under `--pin-dir`; killing the process leaves the attachment (and
pins) in place, since state lives in the pinned kernel objects, not the
process. Re-running the binary re-adopts existing pins in place rather
than double-attaching.

## Memory observability

Per `docs/decisions/ebpf-toolchain-aya.md`, both sides of memory use must
stay independently monitorable, not just estimated at prototype time:

**Userspace RSS** — normal OS tooling, no special build:

```console
$ ps -o rss= -p "$(pgrep u7s-servicelb)"                    # KiB
$ cat /proc/"$(pgrep u7s-servicelb)"/status | grep VmRSS
```

**eBPF map memory (actual, not the pre-allocated ceiling)** — `bpftool`,
against the maps this loader's programs reference:

```console
$ sudo bpftool prog show pinned /sys/fs/bpf/servicelb/uplink_ingress.prog
$ sudo bpftool map show                     # lists every loaded map with id, type, key/value size, max_entries
$ sudo bpftool map dump id <id>             # actual live entries, not the ceiling
```

Phase 1 has no maps yet (no-op programs); this is the command path Phase 2's
conntrack/VIP maps will be read through, not new tooling to build later.
