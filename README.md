# u7s-servicelb (Phase 2+3: Geneve encap/decap, conntrack full-tuple keying)

Loader for the ServiceLB eBPF dataplane
(`ai/extended-context/ebpf-lb-dataplane.md`,
`docs/decisions/ebpf-toolchain-aya.md`). Attaches three tc-bpf classifiers
(Phase 1's separate `geneve_ingress_decap`/`geneve_ingress_return` merged
into one `geneve_ingress`, dispatched by VNI -- see that program's doc
comment for why), pins them under a bpffs directory, and populates one or
more static VIP:PORT -> backend-node/PodIP:TargetPort mappings this phase
proves the mechanism against (repeat `--fixture` for one Pod behind more
than one Service port). Real Service/EndpointSlice watching is Phase 5.

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
    --uplink-iface eth0 --geneve-iface geneve0 --pin-dir /sys/fs/bpf/servicelb \
    --fixture 10.0.0.5:8080:tcp:10.0.0.6:10.244.1.7:80
```

`--fixture` is `vip_ip:vip_port:proto:backend_node_ip:pod_ip:target_port`,
repeatable -- one Pod behind two Service ports (e.g. 80->8080 alongside
443->8443) needs two `--fixture` entries sharing the same `pod_ip`:

```console
$ sudo ./target/release/u7s-servicelb \
    --uplink-iface eth0 --geneve-iface geneve0 --pin-dir /sys/fs/bpf/servicelb \
    --fixture 10.0.0.5:80:tcp:10.0.0.6:10.244.1.7:8080 \
    --fixture 10.0.0.5:443:tcp:10.0.0.6:10.244.1.7:8443
```

`geneve0` must already exist as a "collect metadata" external Geneve device
(`ip link add geneve0 type geneve external && ip link set geneve0 up`) --
this loader only attaches classifiers to it, it does not create it.

Requires `CAP_BPF`/`CAP_NET_ADMIN` (root, or the DaemonSet's intended
capability set in later phases). Attaches all three hooks, populates the
fixture maps, and pins each link under `--pin-dir`; killing the process
leaves the attachment (and pins) in place, since state lives in the pinned
kernel objects, not the process. Re-running the binary re-adopts existing
pins in place rather than double-attaching, and overwrites the fixture
map entries with whatever `--fixture` values are passed that run.

## Local eBPF verifier gate

`ebpf-build` CI only proves the `bpfel-unknown-none` object *compiles* --
not that the kernel verifier *accepts* it at load, or that a packet
actually completes the encap/decap round trip. Run
`scripts/servicelb/smoke.sh [--vm <lima-vm-name>]` (default
`lima-node-5`) locally before merging any servicelb-ebpf PR: it
cross-builds this crate, loads the 3 tc-bpf classifiers into a real
kernel on an already-provisioned Lima VM, asserts the verifier accepted
them, and drives two client -> VIP -> backend TCP round trips (two
Service ports on one backend Pod) through a self-contained veth/netns
fixture. See the script's own header comment for prerequisites and what
each step does.

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
$ sudo bpftool prog show pinned /sys/fs/bpf/servicelb/uplink_ingress-prog
$ sudo bpftool map show                     # lists every loaded map with id, type, key/value size, max_entries
$ sudo bpftool map dump id <id>             # actual live entries, not the ceiling
```

This is the command path to inspect Phase 3's conntrack maps through:
`FWD_FLOW`/`REV_FLOW` are `LRU_HASH`, 8192-entry ceiling, full-tuple
(`u7s_servicelb_common::TcpFlowKey`) keyed. `VIP_MAP`/`TARGET_PORTS` remain
Phase 2's naive small-scale fixture maps, both keyed on the same VIP:PORT:proto
front tuple -- real Service/EndpointSlice sizing is Phase 5.
