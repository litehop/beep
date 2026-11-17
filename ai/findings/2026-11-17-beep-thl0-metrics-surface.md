# Metrics surface design note

Bead: beep-thl0 (related: beep-844k, mayor-aie31.22). Phase 1 of audit, operator decides, apply. Date: 2026-11-17.

**Answer:** serve Prometheus text `/metrics` from the controller only (it alone holds the pinned maps and decides reconcile outcomes), v1 shipping the userspace-only signals and deferring dataplane counters to aie31.22. Prefix, default-on, port, bind, auth and crate are operator calls (below).

## 1. Current state

- **No metrics, no listener.** Logs via `eprintln!` only. Readiness is an exec probe, `test -f /tmp/beep-ready` (`deploy/base/daemonset.yaml:165`, `controller/src/main.rs:149`); `deploy/README.md:270-290` says it "opens no port". `controller/Cargo.toml` has `hyper = "1"` (client side, via politeia) and tokio `rt, macros, time, signal`, no `net`.
- **Who can read maps.** The DaemonSet runs only the controller (`beep-controller`), which owns `PinnedMaps` (`controller/src/apply.rs`). The `beep` loader (`src/main.rs`) is the standalone phase-2 fixture loader and is not in the DaemonSet args (verified from the manifest and file header only; exit behaviour not traced).
- **eBPF maps** (`ebpf/src/main.rs`, `beep::MAP_NAMES` `src/lib.rs:45`): CONFIG, UPLINK_CONFIG, FRONT_META (1024), FRONT_ENDPOINTS (8192, both `NO_PREALLOC`), POD_TARGETS (128), NODE_ALLOW (32), FWD_PENDING (LRU 2048), FLOW_TABLE (LRU 16384), and the only counter, `FRONT_MISSES` (`PerCpuArray<u64>`, one slot, line 192). **Nothing in userspace reads `FRONT_MISSES`** (the only hit is its pin name). **`REJECT_BUCKET` no longer exists** (legacy pin deleted at startup, `LEGACY_MAP_PINS`, `src/lib.rs:62`); the bead text is stale there.
- **Uncounted drops** (`TC_ACT_SHOT`, `ebpf/src/main.rs`): NODE_ALLOW (~1189), remap `Exhausted` (1371, 1519), parse/validation (809-842, 1211-1224, 1566-1643).
- **Front write failures.** `FailureKind::{Capacity=E2BIG, OutOfMemory=ENOMEM, Other}` at `src/front_swap.rs:211-235`; pre-write refusal `capacity_shortfall` (`front_swap.rs:335`). `report_front_failures` / `front_failure_line` (`controller/src/apply.rs:265, 286`) log them and `bail!`.
- **Reconcile outcome** is decided in `reconcile_once` (`controller/src/main.rs:305`): `apply()` (`apply.rs:145`) errs when fronts, NODE_ALLOW, POD_TARGETS or sweep failed, feeding `RetryBackoff.record`.
- **Already computed per reconcile:** `FrontUsage` (`apply_fronts`, `front_swap.rs:410`), `FrontCapacity` (`front_swap.rs:292`), and `RecentSwaps` (`front_swap.rs:452`, grace-held generations, `PREVIOUS_GENERATION_GRACE` 2 s, `apply.rs:263`).
- **FLOW_TABLE sweep** (`run_idle_sweep_loop`, `main.rs:413`; `beep::sweep_idle_flows`, `src/lib.rs:496`) iterates the full map and returns `(rows.len(), deleted)` (`src/lib.rs:520`), logged only. `rows` is the whole table regardless of protocol; only deletion is per class. UDP runs every 120 s and TCP every 12 h (`main.rs:216-217`), so either run yields a whole-table count at most about 120 s old by default.

## 2. Ecosystem (u7s, `/Users/balint.erdos/litehop/u7s`)

- **Format and crate:** Prometheus text exposition, `prometheus = 0.14` (`crates/apiserver/Cargo.toml:63`, `crates/store/Cargo.toml:17`, default-features off). Served by axum at `GET /metrics` (`crates/apiserver/src/handlers/metrics.rs`).
- **Prefix:** `u7s_<noun>_<unit>`, with `_total` on counters (`crates/store/src/metrics.rs`). Small closed label domains are pre-primed at zero (`prime_watch_closed_total`).
- **Auth:** apiserver gates `/metrics` by RBAC; KCM binds 127.0.0.1:10257 with delegated authn (`scripts/install.sh:2469, 2504`). **No kube-rbac-proxy anywhere.**
- **Scrape config:** none (no ServiceMonitor, PodMonitor or `prometheus.io/*` annotation). `manifests/coredns.yaml:13` deliberately omits them ("pod-direct-scrape correlation signal, not a ServiceMonitor target"); the port is only a named `containerPort` (`:134`, 9153).
- **Beep deploy:** `manifests/beep.yaml:207` `hostNetwork: true`, no `ports:`, exec readiness probe (`:281`); `deploy/base/daemonset.yaml:25` is the same (`privileged: false`, drop ALL, add `BPF, NET_ADMIN, PERFMON`).
- **Ports in use on hostNetwork nodes:** kubelet 10250/10248, kube-proxy 10249/10256 (upstream defaults), KCM 10257, scheduler 10259, apiserver 6443, CoreDNS 9153 (pod network). The u7s scheduler has an unimplemented `--health/metrics` flag (`crates/scheduler/src/main.rs:22`).

## 3. Options

| Axis | Options and trade-offs |
|---|---|
| **Endpoint** | **Controller only (recommended):** the only holder of map FDs and reconcile state. Loader: nothing persistent to scrape. Both: duplicate listener, no extra signal. |
| **Bind/port** | Node IP:port is scrapeable but exposes counters to the node network; `0.0.0.0` is widest; 127.0.0.1 plus a scraping sidecar is the smallest exposure but adds a component nobody ships. Port: a flag defaulting in the free 9xxx range (e.g. 9477), clear of the 102xx kubelet/kube-proxy/KCM/scheduler ports. hostNetwork collisions fail at bind, so the flag must be overridable and bind failure loud. |
| **Auth/TLS** | **Security decision.** (a) None (u7s CoreDNS precedent; safe only on loopback, since a Node-IP bind exposes it to the LAN). (b) kube-rbac-proxy: new image and sidecar, no u7s precedent. (c) In-process TokenReview + SubjectAccessReview, matching u7s RBAC-gated `/metrics`: new RBAC (`tokenreviews`, `subjectaccessreviews` create), TLS certs, non-trivial code. Cheapest defensible v1: no auth on loopback or node IP, exposure stated. |
| **Crate** | Hand-rolled text: about 100 lines for ~20 series, zero deps; needs tokio `net` plus a tiny HTTP/1 responder (or hyper `server`+`http1`, already in the tree). `prometheus` 0.14: u7s parity, brings a registry and parking_lot/thiserror, a modest cost against a 96 Mi limit / ~7 MiB RSS. `prometheus-client`: lighter, typed, new idiom. Cardinality is small and fixed, so atomics suffice; a consistency call. |
| **Reading maps** | `FRONT_*` usage and caps need no extra syscall. PERCPU `FRONT_MISSES`: one lookup, one u64 per possible CPU, summed in userspace (negligible). Sample at scrape time (lock `PinnedMaps` briefly; no timer, but contends the `maps` Mutex with reconcile) or on a 15-30 s tick. FLOW_TABLE iteration is O(16k) and should not run per scrape. |

## 4. Proposed metric set

Prefix `beep_` is provisional (decision 1). No client-IP or Service labels in v1 (per-Service reasons are already in logs/Events; fronts churn).

**Userspace-only (no eBPF change):**
- `beep_reconcile_total{result="ok|error"}` counter; `beep_reconcile_duration_seconds` histogram or sum/count; `beep_reconcile_last_success_timestamp_seconds` gauge.
- `beep_front_write_failures_total{kind="capacity|oom|other"}` counter (from `FailureKind`), plus `beep_front_capacity_refusals_total` (from `capacity_shortfall`).
- `beep_front_map_entries{map="FRONT_META|FRONT_ENDPOINTS"}` and `beep_front_map_max_entries{map}` gauges.
- `beep_front_previous_generations_held` gauge and `beep_front_previous_generations_deleted_total` counter (`RecentSwaps`).
- `beep_flow_table_entries` (**not live**: BPF maps have no count; take it from the UDP sweep's whole-table row count, about 120 s stale by default, and record the last-sweep timestamp so staleness is visible) and `beep_flow_table_max_entries`. `beep_flow_idle_sweep_deleted_total{class="udp|tcp"}`. A timed full iteration (about 16k rows) is only worth adding if sub-120 s freshness is needed.
- `beep_flow_pod_evicted_total` (evict_pod_flows, `src/lib.rs:354`), `beep_flow_orphan_pins_removed_total` (`:313`).
- `beep_ready` gauge.

**Need new dataplane counters (overlap aie31.22):** one `PERCPU_ARRAY<u64>` of drop reasons (`node_allow_miss`, `remap_exhausted`, `front_miss` as the existing slot, `parse`), new-flow inserts, churn (re-insert after eviction; hot-path compare, aie31.13 conflict), LRU eviction/insert failure (silent today; the only real eviction signal, needed by the 2026-10-14 sizing goal), TCP-close reclaim and stray-reverse-row frees. Label: `reason` (~6 values). **Object size: unmeasured** (CI logs do not print it). aie31.22 records 129,456 of 131,072 B after #216, leaving ~1.6 KB: about 3-5 incremented counters, **before** any hot-path logic. Reclaim space first or pick the highest-value counters. `FRONT_MISSES` can be exported with no eBPF change.

## 5. Relation to aie31.22 and 844k

**thl0** is the transport and userspace signals; **aie31.22** adds dataplane counters, which thl0 exports by sampling the new array (its "loader-sampler" means the controller here); **844k** turns discrete reconcile conditions (capacity E2BIG, recovery) into Events. Metrics answer trend and alerting, Events answer "what happened to this Service". Order: thl0, then aie31.22 (size budget decided), with 844k independent and parallelizable.

## 6. Operator decisions needed

1. Metric name prefix: `beep_` (matches the binary and the `u7s_<noun>` pattern) or a `servicelb_`-style name (describes the function, survives a rename, but longer and no u7s precedent).
2. On by default or opt-in: default-on gives alerting out of the box but opens a listener on every node; opt-in keeps the "opens no port" stance of `deploy/README.md`.
3. Endpoint location: controller only (recommended).
4. Bind address (loopback vs node IP vs 0.0.0.0) and default port (flag, default in 9xxx).
5. Auth/TLS: none, kube-rbac-proxy, or in-process TokenReview (security decision).
6. Crate: hand-rolled vs `prometheus` 0.14 (u7s parity) vs `prometheus-client`.
7. v1 metric scope: userspace-only set, with two sub-choices. (a) FLOW_TABLE occupancy from the sweep (about 120 s stale, free) or a timed full iteration, worth it only if sub-120 s freshness is needed. (b) `FRONT_MISSES` sampled at scrape time (no timer, contends the `maps` Mutex) or on a 15-30 s tick.
8. Sequencing and size budget: thl0 before aie31.22, and which dataplane counters get the ~1.6 KB.
9. Add a ServiceMonitor/annotations to `deploy/`, or leave scrape config to the user (u7s precedent: leave it).
