# Beep

beep is a resource-conscious [eBPF](https://ebpf.io) service load balancer for Kubernetes. It runs the load-balancing dataplane entirely in the Linux kernel — tc-bpf classifiers plus Geneve encapsulation, with no userspace proxy in the packet path — so it stays light enough for small, memory-constrained nodes where a conventional proxy-based load balancer would not fit.

> ⚠️ **Pre-alpha — not for production.** beep is under active early development: APIs, map layouts, and behavior change without notice, core pieces (Service/EndpointSlice watching, cross-node WireGuard) are still unfinished, and known dataplane blockers remain. Don't run it against real traffic yet.

## What this loader does

This crate is beep's userspace loader. See `docs/design/ebpf-lb-dataplane.md` and `docs/decisions/ebpf-toolchain-aya.md` for the design behind it.

The loader attaches three tc-bpf classifiers and pins them under a bpffs directory.

For now, you supply the loader with static VIP:PORT -> backend-node/PodIP:TargetPort mappings via `--fixture`, to prove the mechanism works. Repeat `--fixture` if one Pod sits behind more than one Service port.

`beep-ebpf` is this crate's no_std sibling — the actual dataplane program. This loader links Linux-only syscalls (`bpf(2)`, netlink), so it only builds and runs on Linux.

## Building

You need a `nightly` toolchain with the `rust-src` component, and `bpf-linker` on your `PATH`. Install `bpf-linker` with `cargo install bpf-linker`, or grab a prebuilt release from https://github.com/aya-rs/bpf-linker/releases.

```console
$ rustup toolchain install nightly --component rust-src
$ cargo install bpf-linker
$ cargo build --release   # from this directory; builds beep-ebpf too
```

`build.rs` cross-builds `beep-ebpf` for `bpfel-unknown-none` or `bpfeb-unknown-none`, matching your host's endianness. It uses `aya-build`, with `.cargo/config.toml` setting `linker = "bpf-linker"` for that target, and it embeds the resulting object into the loader binary.

## Running

Run the loader as root, pointing it at your interfaces and at least one fixture:

```console
$ sudo ./target/release/beep \
    --uplink-iface eth0 --geneve-iface geneve0 --pin-dir /sys/fs/bpf/beep \
    --pod-cidr 10.244.0.0/16 \
    --fixture 10.0.0.5:8080:tcp:10.0.0.6:10.244.1.7:80
```

`--fixture` takes `vip_ip:vip_port:proto:backend_node_ip:pod_ip:target_port`, and you can repeat the flag. For example, one Pod behind two Service ports (80->8080 and 443->8443) needs two `--fixture` entries that share the same `pod_ip`:

```console
$ sudo ./target/release/beep \
    --uplink-iface eth0 --geneve-iface geneve0 --pin-dir /sys/fs/bpf/beep \
    --pod-cidr 10.244.0.0/16 \
    --fixture 10.0.0.5:80:tcp:10.0.0.6:10.244.1.7:8080 \
    --fixture 10.0.0.5:443:tcp:10.0.0.6:10.244.1.7:8443
```

`--pod-cidr` guards against a real collision: a hostNetwork Pod's IP equals its node's IP, so that IP lives in front-IP (VIP) space, not pod-IP space. If a `--fixture`'s vip_ip falls inside `--pod-cidr`, the two spaces overlap, and a forward flow key can byte-collide with a reverse one. The loader checks this at startup and refuses to run if it happens.

`geneve0` must exist before you run the loader, as a "collect metadata" external Geneve device:

```console
$ ip link add geneve0 type geneve external
$ ip link set geneve0 up
```

The loader only attaches classifiers to `geneve0` — it doesn't create the device for you.

You need `CAP_BPF` and `CAP_NET_ADMIN` (root today, or the DaemonSet's intended capability set in later phases). On a successful run, the loader attaches all three classifiers, populates the fixture maps, and pins each link under `--pin-dir`.

Killing the process doesn't tear anything down: the attachment and its pins live in the pinned kernel objects, not in the process. Re-running the binary re-adopts the existing pins instead of double-attaching, and it overwrites the fixture map entries with whatever `--fixture` values you pass on that run.

To detach the programs, remove their pins: each classifier is attached as a TCX link (`bpf_link`, not a classic tc filter or clsact qdisc), and its pin under `--pin-dir` is the only thing keeping it alive once the loader process exits. Delete that directory and the kernel drops the attachment:

```console
$ sudo rm -rf /sys/fs/bpf/beep
```

`scripts/smoke-remote.sh cleanup` does exactly this between runs.

## Local eBPF verifier gate

Before merging any beep-ebpf PR, run the smoke test locally to check that the kernel verifier accepts the compiled program and that a packet completes the encap/decap round trip:

```console
$ scripts/smoke.sh                    # uses the default VM: beep-smoke
$ scripts/smoke.sh --vm beep-node-a   # or target another Lima VM
```

It cross-builds this crate, loads the three tc-bpf classifiers into a real kernel on an already-provisioned Lima VM, and confirms the verifier accepts them. Then it drives two client -> VIP -> backend TCP round trips (two Service ports on one backend Pod) through a self-contained veth/netns fixture. See the script's own header comment for prerequisites and what each step does.

## Memory observability

Per `docs/decisions/ebpf-toolchain-aya.md`, you need to monitor both sides of memory use independently — estimating them at prototype time isn't enough.

### Userspace RSS

Normal OS tooling works, with no special build:

```console
$ ps -o rss= -p "$(pgrep beep)"                    # KiB
$ cat /proc/"$(pgrep beep)"/status | grep VmRSS
```

### eBPF map memory

Use `bpftool` against the maps this loader's programs reference. This shows actual usage, not the pre-allocated ceiling:

```console
$ sudo bpftool prog show pinned /sys/fs/bpf/beep/uplink_ingress-prog
$ sudo bpftool map show                     # lists every loaded map with id, type, key/value size, max_entries
$ sudo bpftool map dump id <id>             # actual live entries, not the ceiling
```

### Conntrack maps

Use this same command path to inspect Phase 3's conntrack maps. `FWD_PENDING` (2048 entries by default), `FWD_MAIN` (8192 entries by default), and `REV_FLOW` (8192 entries) are all `LRU_HASH` maps, keyed on the full tuple (`beep_common::TcpFlowKey`).

A new flow mints into `FWD_PENDING` only, then promotes to `FWD_MAIN` once its return leg is observed. This way, a flood of new flows can never evict an established one. You configure both ceilings at load time, with `--fwd-pending-max-entries` and `--fwd-main-max-entries` — they aren't baked into the object.

`VIP_MAP` and `TARGET_PORTS` are still Phase 2's simple, small-scale fixture maps, both keyed on the same VIP:PORT:proto front tuple. Real Service/EndpointSlice sizing is Phase 5.
