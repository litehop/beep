# Metrics surface design note

Bead: beep-thl0 (related: beep-844k, mayor-aie31.22). Phase 1 of audit, operator decides, apply. Date: 2026-11-17.

**Answer:** serve Prometheus text `/metrics` from the controller only (it alone holds the pinned maps and decides reconcile outcomes), hand-rolled or `prometheus` 0.14 as the operator prefers, v1 shipping the userspace-only signals now and deferring dataplane counters to aie31.22. Port, bind and auth are operator calls (below).

## 1. Current state

- **No metrics, no listener.** Logs via `eprintln!` only. Readiness is an exec probe, `test -f /tmp/beep-ready` (`deploy/base/daemonset.yaml:165`, `controller/src/main.rs:149`); `deploy/README.md:270-290` says it "opens no port". `controller/Cargo.toml` has `hyper = "1"` (client side, via politeia) and tokio features `rt, macros, time, signal`, with no `net`.
- **Who can read maps.** The DaemonSet runs only the controller (`beep-controller`), which owns `PinnedMaps` (`controller/src/apply.rs`). The `beep` loader (`src/main.rs`) is the standalone phase-2 fixture loader and is not in the DaemonSet args. Verified only from the manifest and the file header, so I did not trace whether it exits. Any endpoint belongs on the controller; a second endpoint on the loader has no consumer.
- **eBPF maps** (`ebpf/src/main.rs`, `beep::MAP_NAMES` `src/lib.rs:45`): CONFIG, UPLINK_CONFIG, FRONT_META (1024), FRONT_ENDPOINTS (8192, both `NO_PREALLOC`), POD_TARGETS (128), NODE_ALLOW (32), FWD_PENDING (LRU 2048), FLOW_TABLE (LRU 16384), and the only counter, `FRONT_MISSES` (`PerCpuArray<u64>`, one slot, line 192). **Nothing in userspace reads `FRONT_MISSES`** (the only hit is its pin name). **`REJECT_BUCKET` no longer exists**: it is a legacy pin deleted at startup (`LEGACY_MAP_PINS`, `src/lib.rs:62`). The bead text is stale on that point.
- **Uncounted drops** (`TC_ACT_SHOT`, `ebpf/src/main.rs`): NODE_ALLOW admission (~1189), remap `BackendPortDecision::Exhausted` (1371, 1519), parse/validation drops (809-842, 1211-1224, 1566-1643).
- **Front write failures.** `FailureKind::{Capacity=E2BIG, OutOfMemory=ENOMEM, Other}` classifies at `src/front_swap.rs:211-235`. The pre-write refusal is `capacity_shortfall` (`front_swap.rs:335`). `run_front_plan` collects `FrontFailure`s, and `report_front_failures` / `front_failure_line` (`controller/src/apply.rs:265, 286`) log them and `bail!`.
- **Reconcile success/failure** is decided in `reconcile_once` (`controller/src/main.rs:305`): `apply()` (`apply.rs:145`) returns Err when any of fronts, NODE_ALLOW, POD_TARGETS or sweep failed. The result feeds `RetryBackoff.record`.
- **Free data already computed per reconcile:** `FrontUsage` (`apply_fronts`, `front_swap.rs:410`) and `FrontCapacity` (`front_swap.rs:292`). `RecentSwaps` (`front_swap.rs:452`) tracks the grace-held generations (`PREVIOUS_GENERATION_GRACE`, 2 s, `apply.rs:263`).
- **FLOW_TABLE sweep** (`run_idle_sweep_loop`, `main.rs:413`; `beep::sweep_idle_flows`, `src/lib.rs:496`) already iterates the full map and returns `(scanned, deleted)` per class, logged only. UDP runs every 120 s and TCP every 12 h (`main.rs:216-217`).

## 2. Ecosystem (u7s, `/Users/balint.erdos/litehop/u7s`)

- **Format and crate:** Prometheus text exposition, `prometheus = 0.14` (`crates/apiserver/Cargo.toml:63`, `crates/store/Cargo.toml:17`, default-features off). Served by axum at `GET /metrics` (`crates/apiserver/src/handlers/metrics.rs`).
- **Prefix:** `u7s_<noun>_<unit>`, with `_total` on counters (`crates/store/src/metrics.rs`). beep's analogue is `beep_`. Small closed label domains are pre-primed at zero (`prime_watch_closed_total`).
- **Auth:** the apiserver gates `/metrics` by RBAC like any route, and KCM binds 127.0.0.1:10257 with delegated authn (`scripts/install.sh:2469, 2504`). **No kube-rbac-proxy anywhere.**
- **Scrape config:** none. There is no ServiceMonitor, PodMonitor or `prometheus.io/*` annotation. `manifests/coredns.yaml:13` deliberately omits the annotations ("pod-direct-scrape correlation signal, not a ServiceMonitor target"); the metrics port is only a named `containerPort` (`:134`, 9153).
- **Beep deploy:** `manifests/beep.yaml:207` `hostNetwork: true`, no `ports:`, exec readiness probe (`:281`). beep's own `deploy/base/daemonset.yaml:25` is the same, with `privileged: false`, drop ALL, add `BPF, NET_ADMIN, PERFMON`.
- **Ports in use on hostNetwork nodes:** kubelet 10250/10248, kube-proxy 10249/10256 (upstream defaults, not set in u7s), KCM 10257, scheduler 10259, apiserver 6443, CoreDNS 9153 (pod network). The u7s scheduler has an unimplemented `--health/metrics` flag (`crates/scheduler/src/main.rs:22`).

## 3. Options

| Axis | Options and trade-offs |
|---|---|
| **Endpoint** | **Controller only (recommended):** the only holder of map FDs and reconcile state. Loader: nothing persistent to scrape. Both: duplicates the listener for no signal. |
| **Bind/port** | (a) Node IP:port, scrapeable but exposes counters to the node network. (b) `0.0.0.0`, widest. (c) 127.0.0.1 plus a scraping sidecar or node-local agent: smallest exposure but adds a component nobody ships. Port: pick a configurable flag with a default in the free 9xxx range (e.g. 9477) to avoid 102xx kubelet/kube-proxy/KCM/scheduler. hostNetwork means collisions fail at bind, so the flag must be overridable and bind failure must be loud. A port-0 / off switch should be possible. |
| **Auth/TLS** | **Security decision for the operator.** (a) None (u7s CoreDNS precedent, but on hostNetwork a Node-IP bind exposes it to the LAN; loopback-only makes this safe). (b) kube-rbac-proxy: new image and a sidecar, with no precedent in u7s. (c) In-process TokenReview + SubjectAccessReview, matching u7s apiserver/KCM RBAC-gated `/metrics`. This needs new RBAC (`tokenreviews`, `subjectaccessreviews` create), TLS cert handling, and non-trivial code. Cheapest defensible v1: bind loopback or node IP with no auth, and state the exposure. |
| **Crate** | Hand-rolled text: about 100 lines for ~20 series, zero deps, best binary size (the release profile is already size-tuned: `lto`, `strip`, `panic=abort`). Needs the tokio `net` feature plus a tiny HTTP/1 responder (or hyper `server`+`http1`, already in the tree). `prometheus` 0.14: matches u7s, brings a registry, protobuf-off, parking_lot/thiserror; a modest cost against a 96 Mi limit / ~7 MiB RSS. `prometheus-client`: lighter and typed, but a new idiom vs u7s. Cardinality here is small and fixed; hand-rolled over a plain struct of atomics is enough. This is a style/consistency call. |
| **Reading maps** | `FRONT_*` usage and caps need no extra syscall (already read each reconcile). PERCPU `FRONT_MISSES`: one `bpf_map_lookup` returning one u64 per possible CPU, summed in userspace (cost O(CPUs), negligible). Sample at scrape time (lock `PinnedMaps` briefly) or on a 15-30 s tick. Scrape-time avoids a timer but takes the `maps` Mutex contended with reconcile. FLOW_TABLE iteration is O(16k) and should not run per scrape (see below). |

## 4. Proposed metric set

Prefix `beep_`. No client-IP labels. Service labels are avoided in v1 (per-Service reasons are already in logs/Events, and the front count is bounded by `--max-fronts` 1024 but would still be churn-prone).

**Userspace-only (no eBPF change):**
- `beep_reconcile_total{result="ok|error"}` counter; `beep_reconcile_duration_seconds` histogram or sum/count; `beep_reconcile_last_success_timestamp_seconds` gauge.
- `beep_front_write_failures_total{kind="capacity|oom|other"}` counter (from `FailureKind`), plus `beep_front_capacity_refusals_total` (from `capacity_shortfall`).
- `beep_front_map_entries{map="FRONT_META|FRONT_ENDPOINTS"}` and `beep_front_map_max_entries{map}` gauges.
- `beep_front_previous_generations_held` gauge and `beep_front_previous_generations_deleted_total` counter (`RecentSwaps`).
- `beep_flow_table_entries` (**not live**: BPF maps have no count; derive it from the idle sweep's `scanned`, so it is stale up to the class interval, 12 h for TCP) and `beep_flow_table_max_entries`. `beep_flow_idle_sweep_deleted_total{class="udp|tcp"}`, `beep_flow_idle_sweep_scanned` and last-run timestamp. A fresher count means a full iteration on a timer (about 16k rows, a few ms but holds no lock in kernel; acceptable at 60 s, operator's call).
- `beep_flow_pod_evicted_total` (evict_pod_flows, `src/lib.rs:354`), `beep_flow_orphan_pins_removed_total` (`:313`).
- `beep_ready` gauge.

**Need new dataplane counters (overlap aie31.22):** one `PERCPU_ARRAY<u64>` of drop reasons (`node_allow_miss`, `remap_exhausted`, `front_miss` as the existing slot, `parse`), new-flow inserts, churn (re-insert after eviction; hot-path compare, aie31.13 conflict), LRU eviction/insert failure (invisible today, since LRU eviction is silent; this is the only real eviction signal and the one the 2026-10-14 sizing goal needs), TCP-close reclaim and stray-reverse-row frees. Labels: `reason` (bounded, ~6). One array of ~8 u64 slots costs a few hundred bytes of object text; per-counter instrumentation costs instructions. **Object size: unmeasured** (CI logs do not print it). aie31.22 records 129,456 of 131,072 B after #216, which leaves ~1.6 KB, so only about 3-5 incremented counters fit, **before** any hot-path logic. Plan to reclaim space first or choose the counters with the most operator value. `FRONT_MISSES` can be exported with no eBPF change.

## 5. Relation to aie31.22 and 844k

One story, three layers: **thl0** is the transport and the userspace signals; **aie31.22** adds the dataplane counters, which thl0 then exports by sampling the new array (the loader-sampler framing in 22 means the controller here); **844k** turns discrete reconcile conditions (capacity E2BIG, recovery) into Events for `kubectl describe`. Metrics answer trend and alerting, Events answer "what happened to this Service". Suggested order: thl0 (endpoint plus userspace set, includes `FRONT_MISSES`), then aie31.22 (counters, size budget decided), then 844k, which is independent and could run in parallel.

## 6. Recommendation

Ship `/metrics` on the controller, loopback or node IP behind a flag with no auth in v1 (documenting the exposure), hand-rolled text format, userspace-only set plus `FRONT_MISSES`; defer eviction/drop-reason counters to aie31.22 with its own size budget.

## Operator decisions needed

1. Endpoint location: controller only (recommended)?
2. Bind address (loopback vs node IP vs 0.0.0.0) and default port (suggest a flag, default in 9xxx, off-switch).
3. Auth/TLS: none, kube-rbac-proxy, or in-process TokenReview (security decision).
4. Crate: hand-rolled vs `prometheus` 0.14 (u7s parity) vs `prometheus-client`.
5. v1 metric scope: userspace-only set, and whether FLOW_TABLE occupancy via sweep (stale, free) or a timed iteration (fresher).
6. Sequencing and size budget: thl0 before aie31.22, and which dataplane counters get the ~1.6 KB.
7. Add a ServiceMonitor/annotations to `deploy/`, or leave scrape config to the user (u7s precedent: leave it)?
