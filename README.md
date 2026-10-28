# Beep

beep is a resource-conscious [eBPF](https://ebpf.io) service load balancer for Kubernetes. It runs the load-balancing dataplane entirely in the Linux kernel — tc-bpf classifiers plus Geneve encapsulation, with no userspace proxy in the packet path — so it stays light enough for small, memory-constrained nodes where a conventional proxy-based load balancer would not fit.

> ⚠️ **Pre-alpha — not for production.** beep is under active early development: APIs, map layouts, and behavior change without notice, core pieces (Service/EndpointSlice watching, cross-node WireGuard) are still unfinished, and known dataplane blockers remain. Don't run it against real traffic yet.

## What this loader does

This crate is beep's userspace loader. See `docs/design/ebpf-lb-dataplane.md` and `docs/decisions/ebpf-toolchain-aya.md` for the design behind it.

The loader attaches three tc-bpf classifiers and pins them under a bpffs directory.

For now, you supply the loader with static FRONT_IP:PORT -> backend-node/PodIP:TargetPort mappings via `--fixture`, to prove the mechanism works. Repeat `--fixture` if one Pod sits behind more than one Service port.

`beep-ebpf` is this crate's no_std sibling — the actual dataplane program. This loader links Linux-only syscalls (`bpf(2)`, netlink), so it only builds and runs on Linux.

## Deploying to Kubernetes

To run beep on a real Kubernetes cluster as a DaemonSet, rather than standalone with `--fixture`, see the setup guide in `deploy/README.md`. Read its "Required per-cluster configuration & gotchas" section before deploying to any cluster other than the dev rig, and use "Verify your deployment" to confirm the install worked. To remove beep, including per-node residue (pins, `geneve0`, `/etc/sysctl.d/60-beep.conf`), follow "Uninstall" in `deploy/README.md`. beep must be the cluster's only L4 load balancer (on k3s, install with `--disable=servicelb`).
## Supported platforms

Until 1.0, beep supports:

- systemd-based Linux distros (for example Debian, Ubuntu, the Fedora/RHEL family, Flatcar)
- Linux kernel 6.6 or newer
- little-endian x86-64 and AArch64 only
- the latest two Kubernetes minor versions (currently 1.36 and 1.37)

Non-systemd distros and immutable OSes (Talos, Bottlerocket) are unsupported for now. The node must have `/etc/sysctl.d`, where the `node-prep` initContainer persists the `geneve0` `rp_filter` setting.

## Building

You need a `nightly` toolchain with the `rust-src` component, and `bpf-linker` on your `PATH`. Install `bpf-linker` with `cargo install bpf-linker`, or grab a prebuilt release from https://github.com/aya-rs/bpf-linker/releases.

```console
$ rustup toolchain install nightly --component rust-src
$ cargo install bpf-linker
$ cargo build --release   # from this directory; builds beep-ebpf too
```

`build.rs` cross-builds `beep-ebpf` for `bpfel-unknown-none`; beep builds and verifies little-endian only. It uses `aya-build`, with `.cargo/config.toml` setting `linker = "bpf-linker"` for that target, and it embeds the resulting object into the loader binary.

Release builds strip `.BTF.ext` line info from the embedded object to stay under the 128 KiB size ceiling, so verifier rejection logs and `bpftool prog dump` carry no source lines. To debug a rejection, rebuild without `--release` (`cargo build`): dev builds keep line info.

## Running

Requires Linux >= 6.6 (TCX attach; the loader no longer raises `RLIMIT_MEMLOCK`).

Run the loader as root, pointing it at your interfaces and at least one fixture:

```console
$ sudo ./target/release/beep \
    --uplink-iface eth0 --geneve-iface geneve0 --pin-dir /sys/fs/bpf/beep \
    --pod-cidr 10.244.0.0/16 \
    --fixture 10.0.0.5:8080:tcp:10.0.0.6:10.244.1.7:80
```

`--uplink-iface` is required and repeatable — there's no default, so name at
least one physical interface admitting client traffic. Repeat it to admit
traffic on more than one uplink at once, e.g. a public NIC plus a WireGuard
mesh interface:

```console
$ sudo ./target/release/beep \
    --uplink-iface eth0 --uplink-iface wg0 --geneve-iface geneve0 --pin-dir /sys/fs/bpf/beep \
    --pod-cidr 10.244.0.0/16 \
    --fixture 10.0.0.5:8080:tcp:10.0.0.6:10.244.1.7:80
```

A flow's reply always egresses the same uplink it arrived on (symmetric
return), and each uplink's L2 header handling — Ethernet's 14-byte header vs.
a WireGuard/tun interface's L3-only framing — is auto-detected from the
interface's hardware type, not something you configure. A single
`--uplink-iface`, as in the first example above, remains the common N=1
case. Design rationale: `docs/decisions/servicelb-multi-symmetric-uplink.md`.

`--fixture` takes `front_ip:front_port:proto:backend_node_ip:pod_ip:target_port`, and you can repeat the flag. For example, one Pod behind two Service ports (80->8080 and 443->8443) needs two `--fixture` entries that share the same `pod_ip`:

```console
$ sudo ./target/release/beep \
    --uplink-iface eth0 --geneve-iface geneve0 --pin-dir /sys/fs/bpf/beep \
    --pod-cidr 10.244.0.0/16 \
    --fixture 10.0.0.5:80:tcp:10.0.0.6:10.244.1.7:8080 \
    --fixture 10.0.0.5:443:tcp:10.0.0.6:10.244.1.7:8443
```

`--pod-cidr` guards against a real collision: a hostNetwork Pod's IP equals its node's IP, so that IP lives in front-IP space, not pod-IP space. If a `--fixture`'s front_ip falls inside `--pod-cidr`, the two spaces overlap, and a forward flow key can byte-collide with a reverse one. The loader checks this at startup and refuses to run if it happens.

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

It cross-builds this crate, loads the three tc-bpf classifiers into a real kernel on an already-provisioned Lima VM, and confirms the verifier accepts them. Then it drives two client -> front -> backend TCP round trips (two Service ports on one backend Pod) through a self-contained veth/netns fixture. See the script's own header comment for prerequisites and what each step does.

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

Use this same command path to inspect Phase 3's conntrack maps. `FWD_PENDING` (2048 entries by default, keyed on `beep_common::TcpFlowKey`) and `FLOW_TABLE` (16384 entries by default, keyed on `beep_common::FlowKey` — `TcpFlowKey` plus an explicit forward/reverse tag byte) are both `LRU_HASH` maps. `FLOW_TABLE` is the merged forward-established and reverse conntrack table: a forward-tagged entry pins the same state `FWD_MAIN` used to hold, a reverse-tagged entry the same state `REV_FLOW` used to hold, sharing one physical map instead of two.

A new flow mints into `FWD_PENDING` only, then promotes to a forward-tagged `FLOW_TABLE` entry once its return leg is observed. This way, a flood of new flows can never evict an established one. You configure both ceilings at load time, with `--fwd-pending-max-entries` and `--flow-table-max-entries` — they aren't baked into the object.

`FRONT_META` (keyed on the front address:port:proto tuple; value: live endpoint generation, count, flags) and `FRONT_ENDPOINTS` (keyed on front + generation + slot; value: backend node, pod, target port) are `HASH` maps created with `BPF_F_NO_PREALLOC`, so only used entries cost memory. They are sized by `--max-fronts` (1024 by default; `FRONT_META` rows) and `--endpoints-per-front` (4 by default); `FRONT_ENDPOINTS` gets `max-fronts × endpoints-per-front × 2` rows (8192 by default), the 2 being swap headroom. Both flags also read `BEEP_MAX_FRONTS` / `BEEP_ENDPOINTS_PER_FRONT`, which the DaemonSet sets from the `beep-config` ConfigMap (`deploy/README.md`, "Configuration"). The controller replaces a front's endpoints by writing a new generation and then updating `FRONT_META` once, so a packet sees either the old endpoints or the new ones; the old generation is deleted about 2 s later. `FRONT_MISSES` counts lookups where a front had no readable endpoint (dropped from the load balancer's path).
