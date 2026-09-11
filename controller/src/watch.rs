//! Watches `Service` (type=LoadBalancer) + `EndpointSlice` (+ `Node`, to
//! resolve a backend's hosting-node IP) via `beep_kubeconfig::HyperApiClient`
//! and folds the parsed events into `reconcile::reconcile_service`'s inputs.
//!
//! Split into two layers on purpose (Rule 14): the JSON-parsing and
//! state-folding below (`WatchState` and friends) is pure and unit-tested
//! without a network; `run_list_watch`, the list-then-watch loop around
//! `HyperApiClient::watch_stream`, is not meaningfully testable without a
//! live apiserver, so its actual decisions (backoff, relist-on-410) are
//! pulled out into standalone pure functions (`next_backoff`,
//! `is_resource_expired`, `list_resource_version`) and tested directly --
//! the loop itself is a thin, deliberately un-tested wrapper around them.

use std::{collections::HashMap, net::Ipv4Addr, time::Duration};

use anyhow::Context;
use beep_kubeconfig::HyperApiClient;
use hyper::Method;
use serde_json::Value;

use crate::reconcile::{
    self, DesiredEntries, Endpoint, EndpointSliceView, NodeContext, Protocol, ServicePort,
    ServiceView,
};

/// Namespace+name identity for a Service and the EndpointSlices that back
/// it. An `EndpointSlice` references its owning Service by name only (the
/// `kubernetes.io/service-name` label), always in the Service's own
/// namespace, so this key doubles as both objects' lookup key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ServiceKey {
    pub namespace: String,
    pub name: String,
}

#[derive(Clone, Debug)]
struct RawServicePort {
    name: Option<String>,
    port: u16,
    protocol: Protocol,
}

#[derive(Clone, Debug, Default)]
struct RawService {
    ports: Vec<RawServicePort>,
}

#[derive(Clone, Debug)]
struct RawSlicePort {
    name: Option<String>,
    port: u16,
}

#[derive(Clone, Debug)]
struct RawEndpoint {
    pod_ip: Ipv4Addr,
    node_name: Option<String>,
    ready: bool,
}

#[derive(Clone, Debug, Default)]
struct RawEndpointSlice {
    ports: Vec<RawSlicePort>,
    endpoints: Vec<RawEndpoint>,
}

/// Accumulated view of every known LoadBalancer Service, its EndpointSlices,
/// and the Node-name -> IP map needed to resolve `EndpointSlice.endpoints[].
/// nodeName` into `reconcile::Endpoint.node_ip`. Fed exclusively by
/// `apply_*_event`, then turned into dataplane map entries by `desired`.
#[derive(Default)]
pub struct WatchState {
    services: HashMap<ServiceKey, RawService>,
    // Keyed on (owning Service, this EndpointSlice's own object name): a
    // Service can be sharded across more than one EndpointSlice, and each
    // must be tracked (added/updated/removed) independently, or updating one
    // slice would silently drop every other slice's endpoints.
    slices: HashMap<ServiceKey, HashMap<String, RawEndpointSlice>>,
    node_ips: HashMap<String, Ipv4Addr>,
}

enum EventKind {
    Upsert,
    Delete,
}

fn event_kind(event: &Value) -> Option<EventKind> {
    match event["type"].as_str()? {
        "ADDED" | "MODIFIED" => Some(EventKind::Upsert),
        "DELETED" => Some(EventKind::Delete),
        // BOOKMARK carries no object of interest; anything else is unknown.
        _ => None,
    }
}

fn metadata_name(obj: &Value) -> Option<String> {
    obj["metadata"]["name"].as_str().map(str::to_owned)
}

fn service_key(obj: &Value) -> Option<ServiceKey> {
    Some(ServiceKey {
        namespace: obj["metadata"]["namespace"].as_str()?.to_owned(),
        name: metadata_name(obj)?,
    })
}

/// An `EndpointSlice`'s owning Service, read off the
/// `kubernetes.io/service-name` label the apiserver's EndpointSlice
/// controller always sets -- there is no other reference to the Service on
/// this object.
fn owning_service_key(obj: &Value) -> Option<ServiceKey> {
    Some(ServiceKey {
        namespace: obj["metadata"]["namespace"].as_str()?.to_owned(),
        name: obj["metadata"]["labels"]["kubernetes.io/service-name"]
            .as_str()?
            .to_owned(),
    })
}

fn parse_protocol(s: Option<&str>) -> Option<Protocol> {
    match s.unwrap_or("TCP") {
        "TCP" => Some(Protocol::Tcp),
        "UDP" => Some(Protocol::Udp),
        _ => None,
    }
}

/// Parses a `Service` object into its LoadBalancer front ports. Returns
/// `None` for a non-`LoadBalancer` Service (or one missing `spec` entirely)
/// -- this dataplane only ever fronts `type=LoadBalancer` traffic
/// (`ebpf-lb-dataplane.md`'s node-owned-address model), so anything else
/// must never reach `reconcile_service`.
fn parse_service(obj: &Value) -> Option<RawService> {
    if obj["spec"]["type"].as_str()? != "LoadBalancer" {
        return None;
    }
    let ports = obj["spec"]["ports"]
        .as_array()?
        .iter()
        .filter_map(|p| {
            Some(RawServicePort {
                name: p["name"].as_str().map(str::to_owned),
                port: u16::try_from(p["port"].as_u64()?).ok()?,
                protocol: parse_protocol(p["protocol"].as_str())?,
            })
        })
        .collect();
    Some(RawService { ports })
}

/// Parses an `EndpointSlice` object. `conditions.ready` defaults to `true`
/// when absent (the Kubernetes API's own documented default for that
/// field) -- treating a missing value as "not ready" would silently exclude
/// every endpoint an apiserver doesn't bother setting the field on.
fn parse_endpoint_slice(obj: &Value) -> Option<RawEndpointSlice> {
    let ports = obj["ports"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    Some(RawSlicePort {
                        name: p["name"].as_str().map(str::to_owned),
                        port: u16::try_from(p["port"].as_u64()?).ok()?,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let endpoints = obj["endpoints"]
        .as_array()?
        .iter()
        .filter_map(|e| {
            let pod_ip = e["addresses"].as_array()?.first()?.as_str()?.parse().ok()?;
            Some(RawEndpoint {
                pod_ip,
                node_name: e["nodeName"].as_str().map(str::to_owned),
                ready: e["conditions"]["ready"].as_bool().unwrap_or(true),
            })
        })
        .collect();
    Some(RawEndpointSlice { ports, endpoints })
}

/// Parses a `Node` object's first `InternalIP` address -- the value
/// `VipBackend.backend_node_ip` needs as the Geneve tunnel remote for a pod
/// hosted on this node (`reconcile::Endpoint.node_ip`'s doc comment).
fn parse_node_internal_ip(obj: &Value) -> Option<Ipv4Addr> {
    obj["status"]["addresses"]
        .as_array()?
        .iter()
        .find(|a| a["type"] == "InternalIP")?["address"]
        .as_str()?
        .parse()
        .ok()
}

impl WatchState {
    /// Returns the event's `ServiceKey` when it left the Service tracked as
    /// `type=LoadBalancer` (a fresh ADDED/MODIFIED), or `None` for a delete,
    /// a type change away from LoadBalancer, or an event this state doesn't
    /// track at all. Callers use this to scope a status-publish (or any
    /// other per-event follow-up) to just the Service that actually
    /// changed, instead of re-verifying every tracked Service on every
    /// event.
    pub fn apply_service_event(&mut self, event: &Value) -> Option<ServiceKey> {
        let kind = event_kind(event)?;
        let obj = &event["object"];
        let key = service_key(obj)?;
        match kind {
            EventKind::Delete => {
                self.services.remove(&key);
                None
            }
            // A Service that changed type away from LoadBalancer must stop
            // fronting traffic just like a delete -- `parse_service`
            // returning `None` here and `services.remove` covers both.
            EventKind::Upsert => match parse_service(obj) {
                Some(raw) => {
                    self.services.insert(key.clone(), raw);
                    Some(key)
                }
                None => {
                    self.services.remove(&key);
                    None
                }
            },
        }
    }

    pub fn apply_endpoint_slice_event(&mut self, event: &Value) {
        let Some(kind) = event_kind(event) else {
            return;
        };
        let obj = &event["object"];
        let (Some(owner), Some(slice_name)) = (owning_service_key(obj), metadata_name(obj)) else {
            return;
        };
        match kind {
            EventKind::Delete => {
                if let Some(slices) = self.slices.get_mut(&owner) {
                    slices.remove(&slice_name);
                }
            }
            EventKind::Upsert => {
                if let Some(raw) = parse_endpoint_slice(obj) {
                    self.slices
                        .entry(owner)
                        .or_default()
                        .insert(slice_name, raw);
                }
            }
        }
    }

    pub fn apply_node_event(&mut self, event: &Value) {
        let Some(kind) = event_kind(event) else {
            return;
        };
        let obj = &event["object"];
        let Some(name) = metadata_name(obj) else {
            return;
        };
        match kind {
            EventKind::Delete => {
                self.node_ips.remove(&name);
            }
            EventKind::Upsert => {
                if let Some(ip) = parse_node_internal_ip(obj) {
                    self.node_ips.insert(name, ip);
                }
            }
        }
    }

    /// Resolves a Service port's numeric target port against its
    /// EndpointSlices' `ports[]` by name -- or positionally when both sides
    /// have exactly one, unnamed port, the common single-port-Service case
    /// (naming is only mandatory once a Service exposes more than one port).
    /// Returns `None` when it can't be resolved unambiguously (e.g. no
    /// EndpointSlice observed yet), which drops this front from
    /// `reconcile_service`'s input -- the same "no entries yet" outcome as
    /// a Service with no ready endpoints.
    fn resolve_target_port(port: &RawServicePort, slice_ports: &[RawSlicePort]) -> Option<u16> {
        match &port.name {
            Some(name) => slice_ports
                .iter()
                .find(|sp| sp.name.as_deref() == Some(name.as_str()))
                .map(|sp| sp.port),
            None if slice_ports.len() == 1 => Some(slice_ports[0].port),
            None => None,
        }
    }

    /// Aggregates every known Service's `reconcile_service` output into one
    /// desired map state -- the controller writes all fronts from a single
    /// pass, not one dataplane write per Service.
    pub fn desired(&self, node: &NodeContext) -> DesiredEntries {
        let mut aggregate = DesiredEntries::default();
        let no_slices = HashMap::new();
        // The front-IP model (ebpf-lb-dataplane.md's "Packet flow" step 1):
        // every node's own address is a valid front for every Service, so
        // VIP_MAP/TARGET_PORTS need one entry per KNOWN node address, not
        // just this controller's own `node.node_ip` -- the backend node's
        // decap (`try_geneve_decap_forward`) looks up TARGET_PORTS keyed on
        // whichever node the client actually dialed, which is any node in
        // the cluster, not necessarily this one.
        // Startup ordering: `node_ips` is empty until the Node LIST (run
        // concurrently with the Service/EndpointSlice watches in
        // `run_controller_loop`'s `tokio::join!`) delivers its first event,
        // so a reconcile fired from an early Service/EndpointSlice event can
        // transiently program zero fronts for an already-known Service.
        // Accepted: fail-CLOSED (dropped connections, never misrouted ones),
        // and self-healing -- the Node LIST's own events each re-trigger a
        // full reconcile, so the correct front set lands as soon as it
        // catches up, with no restart or backoff needed.
        let front_ips: Vec<Ipv4Addr> = self.node_ips.values().copied().collect();
        for (key, svc) in &self.services {
            let slices = self.slices.get(key).unwrap_or(&no_slices);

            // Service ports name-resolve against the union of every known
            // slice's ports for this Service, not just one slice's -- a
            // Service sharded across multiple EndpointSlices still exposes
            // the same port set on all of them.
            let mut slice_ports: Vec<RawSlicePort> = Vec::new();
            for slice in slices.values() {
                for p in &slice.ports {
                    if !slice_ports
                        .iter()
                        .any(|existing| existing.name == p.name && existing.port == p.port)
                    {
                        slice_ports.push(p.clone());
                    }
                }
            }

            let ports: Vec<ServicePort> = svc
                .ports
                .iter()
                .filter_map(|p| {
                    Self::resolve_target_port(p, &slice_ports).map(|target_port| ServicePort {
                        port: p.port,
                        protocol: p.protocol,
                        target_port,
                    })
                })
                .collect();

            let endpoint_slices: Vec<EndpointSliceView> = slices
                .values()
                .map(|slice| EndpointSliceView {
                    endpoints: slice
                        .endpoints
                        .iter()
                        .filter_map(|e| {
                            // An endpoint whose node hasn't been resolved
                            // yet (Node watch/list lagging EndpointSlice) is
                            // dropped for THIS reconcile pass rather than
                            // guessed at -- the next Node event re-triggers
                            // a reconcile that picks it up correctly.
                            let node_ip = e
                                .node_name
                                .as_deref()
                                .and_then(|n| self.node_ips.get(n))
                                .copied()?;
                            Some(Endpoint {
                                pod_ip: e.pod_ip,
                                node_ip,
                                ready: e.ready,
                                ports: slice.ports.iter().map(|p| p.port).collect(),
                            })
                        })
                        .collect(),
                })
                .collect();

            for front_ip in &front_ips {
                let view = ServiceView {
                    vip_ip: *front_ip,
                    ports: ports.clone(),
                };
                let desired = reconcile::reconcile_service(&view, &endpoint_slices, node);
                aggregate.vip_map.extend(desired.vip_map);
                aggregate.target_ports.extend(desired.target_ports);
                aggregate.pod_targets.extend(desired.pod_targets);
            }
        }
        aggregate
    }
}

// ---------------------------------------------------------------------------
// List-then-watch reconnect loop
// ---------------------------------------------------------------------------

const INITIAL_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Whether a watch failure means its cached `resourceVersion` is no longer
/// valid and a fresh LIST (full relist) is required, rather than a bare
/// reconnect at the same `resourceVersion`. The apiserver reports this as
/// HTTP 410 Gone; `HyperApiClient::watch_stream` surfaces a non-success
/// status as `anyhow::bail!("watch returned HTTP {status}")`, so the code
/// lands in the error's `Display` text -- every other failure (idle
/// timeout, TCP reset, EOF) is a transient connection loss the same
/// `resourceVersion` can resume from without missing anything.
pub fn is_resource_expired(err: &anyhow::Error) -> bool {
    format!("{err:#}").contains("410")
}

/// Exponential backoff for the list-watch loop, capped so a persistently
/// unreachable apiserver doesn't get hammered, but this node's dataplane
/// maps also don't go stale forever waiting on a slow backoff. A successful
/// cycle resets to the floor immediately, so one bad connection doesn't
/// leave every later reconnect artificially slow.
pub fn next_backoff(current: Duration, succeeded: bool) -> Duration {
    if succeeded {
        INITIAL_BACKOFF
    } else {
        (current * 2).min(MAX_BACKOFF)
    }
}

/// Extracts `metadata.resourceVersion` from a LIST response body, so a
/// subsequent watch resumes from exactly the point the list snapshot was
/// taken. Starting a watch from an empty/unset `resourceVersion` instead
/// would silently miss any change made between the list and watch calls.
pub fn list_resource_version(list_body: &Value) -> Option<&str> {
    list_body["metadata"]["resourceVersion"].as_str()
}

async fn list(client: &HyperApiClient, path: &str) -> anyhow::Result<(Vec<Value>, String)> {
    let (status, body) = client
        .request(Method::GET, path, None)
        .await
        .with_context(|| format!("list {path}"))?;
    if !status.is_success() {
        anyhow::bail!("list {path} returned HTTP {status}");
    }
    let parsed: Value = serde_json::from_str(&body).context("parse list response")?;
    let resource_version = list_resource_version(&parsed)
        .context("list response missing metadata.resourceVersion")?
        .to_owned();
    let items = parsed["items"].as_array().cloned().unwrap_or_default();
    Ok((items, resource_version))
}

/// Lists `resource_path` (e.g. `/api/v1/services`, no query string) once,
/// then watches it from the list's `resourceVersion` forever, feeding every
/// object (list items wrapped as a synthetic `ADDED`, so callers have one
/// ingestion point) to `on_event`. On a watch failure, relists (fresh
/// `resourceVersion`) if the failure was a 410 Gone, otherwise reconnects at
/// the same `resourceVersion`; either way, backs off exponentially between
/// attempts. In practice this never returns (there is no persistent proxy
/// loop to hand control back to -- `ebpf-lb-dataplane.md`'s "Userspace
/// control plane" section); the declared `Result` (rather than `!`) is
/// solely so three of these compose cleanly under `tokio::join!`, which
/// mishandles literally-`!`-typed branches.
pub async fn run_list_watch(
    client: &HyperApiClient,
    resource_path: &str,
    mut on_event: impl FnMut(Value),
) -> anyhow::Result<()> {
    let mut backoff = INITIAL_BACKOFF;
    let mut resource_version: Option<String> = None;
    loop {
        if resource_version.is_none() {
            match list(client, resource_path).await {
                Ok((items, rv)) => {
                    for item in items {
                        on_event(serde_json::json!({"type": "ADDED", "object": item}));
                    }
                    resource_version = Some(rv);
                    backoff = INITIAL_BACKOFF;
                }
                Err(e) => {
                    eprintln!("controller: list {resource_path} failed: {e:#}");
                    backoff = next_backoff(backoff, false);
                    tokio::time::sleep(backoff).await;
                    continue;
                }
            }
        }

        let rv = resource_version.clone().expect("set above");
        let path = format!("{resource_path}?watch=true&resourceVersion={rv}");
        match client.watch_stream(&path, &mut on_event).await {
            Ok(()) => {
                // Clean EOF (apiserver closed the connection, e.g. its own
                // watch timeout) -- resume at the same resourceVersion, no
                // backoff needed.
                backoff = INITIAL_BACKOFF;
            }
            Err(e) => {
                eprintln!("controller: watch {path} failed: {e:#}");
                if is_resource_expired(&e) {
                    resource_version = None;
                }
                backoff = next_backoff(backoff, false);
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn node(ip: Ipv4Addr) -> NodeContext {
        NodeContext {
            node_ip: ip,
            pod_cidr: reconcile::Ipv4Cidr::new(Ipv4Addr::new(10, 244, 0, 0), 16),
        }
    }

    // A watch that skipped type=LoadBalancer filtering would program
    // VIP_MAP for a ClusterIP Service too -- exposing a Service never meant
    // to accept external traffic.
    #[test]
    fn cluster_ip_service_is_not_tracked() {
        let event = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"namespace": "default", "name": "svc-a"},
                "spec": {"type": "ClusterIP", "ports": [{"port": 80, "protocol": "TCP"}]},
            },
        });
        let mut state = WatchState::default();
        state.apply_service_event(&event);
        assert!(
            state.services.is_empty(),
            "a non-LoadBalancer Service must never reach reconcile_service, or this node would \
             front traffic for a Service that never asked to be externally exposed"
        );
    }

    // A rolling update that flips a Service's type away from LoadBalancer
    // must stop fronting it -- a MODIFIED event, not just DELETED, is the
    // real-world shape that transition takes.
    #[test]
    fn service_modified_to_non_load_balancer_type_is_removed() {
        let mut state = WatchState::default();
        state.apply_service_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"namespace": "default", "name": "svc-a"},
                "spec": {"type": "LoadBalancer", "ports": [{"port": 80, "protocol": "TCP"}]},
            },
        }));
        assert_eq!(
            state.services.len(),
            1,
            "setup: the LB Service must be tracked first"
        );

        state.apply_service_event(&serde_json::json!({
            "type": "MODIFIED",
            "object": {
                "metadata": {"namespace": "default", "name": "svc-a"},
                "spec": {"type": "ClusterIP", "ports": [{"port": 80, "protocol": "TCP"}]},
            },
        }));
        assert!(
            state.services.is_empty(),
            "a Service edited away from type=LoadBalancer must stop being fronted, or this node \
             keeps routing external traffic at a Service that opted out"
        );
    }

    // Deleting a Service must free its slot, or a later Service reusing the
    // same namespace/name would inherit stale reconcile state instead of
    // starting clean.
    #[test]
    fn deleted_service_is_removed_from_state() {
        let mut state = WatchState::default();
        let add = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"namespace": "default", "name": "svc-a"},
                "spec": {"type": "LoadBalancer", "ports": [{"port": 80, "protocol": "TCP"}]},
            },
        });
        state.apply_service_event(&add);
        state.apply_service_event(&serde_json::json!({
            "type": "DELETED",
            "object": add["object"],
        }));
        assert!(state.services.is_empty());
    }

    // The caller (`publish_ingress`) uses this return value to scope a
    // status-publish to only the Service that actually changed -- a `None`
    // here for a delete/non-LB transition must not trigger a wasted (or
    // outright failing, for a since-deleted Service) status GET/PATCH.
    #[test]
    fn apply_service_event_returns_key_only_for_a_tracked_upsert() {
        let mut state = WatchState::default();
        let added = state.apply_service_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"namespace": "default", "name": "svc-a"},
                "spec": {"type": "LoadBalancer", "ports": [{"port": 80, "protocol": "TCP"}]},
            },
        }));
        assert_eq!(
            added,
            Some(ServiceKey {
                namespace: "default".to_owned(),
                name: "svc-a".to_owned(),
            }),
            "an ADDED LoadBalancer Service must yield its own key, so publish_ingress targets \
             just this Service"
        );

        let deleted = state.apply_service_event(&serde_json::json!({
            "type": "DELETED",
            "object": {
                "metadata": {"namespace": "default", "name": "svc-a"},
                "spec": {"type": "LoadBalancer", "ports": [{"port": 80, "protocol": "TCP"}]},
            },
        }));
        assert_eq!(
            deleted, None,
            "a DELETED event must not yield a key -- publishing status for a Service that no \
             longer exists would just fail the GET"
        );

        let non_lb = state.apply_service_event(&serde_json::json!({
            "type": "MODIFIED",
            "object": {
                "metadata": {"namespace": "default", "name": "svc-b"},
                "spec": {"type": "ClusterIP", "ports": [{"port": 80, "protocol": "TCP"}]},
            },
        }));
        assert_eq!(
            non_lb, None,
            "a Service that isn't type=LoadBalancer must not yield a key -- this dataplane never \
             fronts it, so there is no status to publish"
        );
    }

    // A Service sharded across two EndpointSlices (the real-world shape once
    // a Service exceeds ~100 endpoints) must pool endpoints from BOTH, or
    // the reconcile's deterministic backend pick could silently ignore a
    // lower-IP endpoint that happens to land in the second slice.
    #[test]
    fn endpoints_from_multiple_slices_for_one_service_are_pooled() {
        let mut state = WatchState::default();
        state.apply_service_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"namespace": "default", "name": "svc-a"},
                "spec": {"type": "LoadBalancer", "ports": [{"port": 80, "protocol": "TCP"}]},
            },
        }));
        state.apply_node_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "node-a"},
                "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.5"}]},
            },
        }));
        for (slice_name, pod_ip) in [
            ("svc-a-abcde", "10.244.0.20"),
            ("svc-a-fghij", "10.244.0.2"),
        ] {
            state.apply_endpoint_slice_event(&serde_json::json!({
                "type": "ADDED",
                "object": {
                    "metadata": {
                        "namespace": "default",
                        "name": slice_name,
                        "labels": {"kubernetes.io/service-name": "svc-a"},
                    },
                    "ports": [{"port": 8080, "protocol": "TCP"}],
                    "endpoints": [{
                        "addresses": [pod_ip],
                        "nodeName": "node-a",
                        "conditions": {"ready": true},
                    }],
                },
            }));
        }

        let desired = state.desired(&node(Ipv4Addr::new(10, 0, 0, 5)));
        let (_, backend) = desired.vip_map.iter().next().expect("one front expected");
        assert_eq!(
            backend.pod_ip.to_le_bytes(),
            [10, 244, 0, 2],
            "the lowest-IP endpoint across BOTH EndpointSlices must win -- pooling only the \
             first-seen slice would wrongly pick .20"
        );
    }

    // Removing one of two slices for a Service must drop only that slice's
    // endpoints, not the other's -- otherwise any per-slice update (a
    // routine EndpointSlice controller resync) would transiently blackhole
    // every backend on this node.
    #[test]
    fn removing_one_slice_keeps_the_other_slices_endpoints() {
        let mut state = WatchState::default();
        state.apply_service_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"namespace": "default", "name": "svc-a"},
                "spec": {"type": "LoadBalancer", "ports": [{"port": 80, "protocol": "TCP"}]},
            },
        }));
        state.apply_node_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "node-a"},
                "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.5"}]},
            },
        }));
        let slice_a = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {
                    "namespace": "default",
                    "name": "svc-a-aaaaa",
                    "labels": {"kubernetes.io/service-name": "svc-a"},
                },
                "ports": [{"port": 8080, "protocol": "TCP"}],
                "endpoints": [{"addresses": ["10.244.0.9"], "nodeName": "node-a", "conditions": {"ready": true}}],
            },
        });
        let slice_b = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {
                    "namespace": "default",
                    "name": "svc-a-bbbbb",
                    "labels": {"kubernetes.io/service-name": "svc-a"},
                },
                "ports": [{"port": 8080, "protocol": "TCP"}],
                "endpoints": [{"addresses": ["10.244.0.40"], "nodeName": "node-a", "conditions": {"ready": true}}],
            },
        });
        state.apply_endpoint_slice_event(&slice_a);
        state.apply_endpoint_slice_event(&slice_b);

        state.apply_endpoint_slice_event(&serde_json::json!({
            "type": "DELETED",
            "object": slice_b["object"],
        }));

        let desired = state.desired(&node(Ipv4Addr::new(10, 0, 0, 5)));
        let (_, backend) = desired.vip_map.iter().next().expect("one front expected");
        assert_eq!(
            backend.pod_ip.to_le_bytes(),
            [10, 244, 0, 9],
            "slice_a's endpoint must survive slice_b's deletion -- losing it too would \
             blackhole this front instead of just narrowing its candidate set"
        );
    }

    // A single-port Service and its EndpointSlice both omit the port name
    // (legal when there is exactly one port) -- target-port resolution must
    // still succeed positionally, or every unnamed single-port Service
    // (the common case) would silently get zero VIP_MAP entries.
    #[test]
    fn unnamed_single_port_resolves_positionally() {
        let mut state = WatchState::default();
        state.apply_service_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"namespace": "default", "name": "svc-a"},
                "spec": {"type": "LoadBalancer", "ports": [{"port": 80, "protocol": "TCP"}]},
            },
        }));
        state.apply_node_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "node-a"},
                "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.5"}]},
            },
        }));
        state.apply_endpoint_slice_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {
                    "namespace": "default",
                    "name": "svc-a-aaaaa",
                    "labels": {"kubernetes.io/service-name": "svc-a"},
                },
                "ports": [{"port": 8080, "protocol": "TCP"}],
                "endpoints": [{"addresses": ["10.244.0.9"], "nodeName": "node-a", "conditions": {"ready": true}}],
            },
        }));

        let desired = state.desired(&node(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(
            desired.vip_map.len(),
            1,
            "an unnamed single Service port must still resolve against the sole unnamed \
             EndpointSlice port, not get silently dropped for lack of a name to match"
        );
        let target_port = desired.target_ports.values().next().unwrap();
        assert_eq!(
            target_port.to_le_bytes(),
            [0x1F, 0x90],
            "the resolved target port must be the EndpointSlice's 8080, not left unresolved"
        );
    }

    // Two named Service ports (HTTP + metrics) must each resolve against
    // their OWN matching EndpointSlice port by name -- resolving
    // positionally here (as the single-port case does) could silently
    // cross-wire the two ports' target ports.
    #[test]
    fn named_multi_port_service_resolves_each_port_by_name() {
        let mut state = WatchState::default();
        state.apply_service_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"namespace": "default", "name": "svc-a"},
                "spec": {
                    "type": "LoadBalancer",
                    "ports": [
                        {"name": "http", "port": 80, "protocol": "TCP"},
                        {"name": "metrics", "port": 9000, "protocol": "TCP"},
                    ],
                },
            },
        }));
        state.apply_node_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "node-a"},
                "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.5"}]},
            },
        }));
        state.apply_endpoint_slice_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {
                    "namespace": "default",
                    "name": "svc-a-aaaaa",
                    "labels": {"kubernetes.io/service-name": "svc-a"},
                },
                "ports": [
                    {"name": "http", "port": 8080, "protocol": "TCP"},
                    {"name": "metrics", "port": 9100, "protocol": "TCP"},
                ],
                "endpoints": [{
                    "addresses": ["10.244.0.9"],
                    "nodeName": "node-a",
                    "conditions": {"ready": true},
                }],
            },
        }));

        let desired = state.desired(&node(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(desired.target_ports.len(), 2);
        let ports: HashSet<u16> = desired.target_ports.values().map(|p| p.to_be()).collect();
        assert_eq!(
            ports,
            HashSet::from([9100, 8080]),
            "each named Service port must resolve its OWN EndpointSlice port by name -- \
             cross-wiring http<->metrics would route health checks at the wrong container port"
        );
    }

    // An endpoint on a node this controller hasn't resolved an IP for yet
    // (Node watch/list still catching up) must not be admitted with a
    // wrong/zero node_ip -- dropping it for this pass is safer than
    // fabricating a Geneve tunnel remote.
    #[test]
    fn endpoint_on_unresolved_node_is_dropped_for_this_reconcile() {
        let mut state = WatchState::default();
        state.apply_service_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"namespace": "default", "name": "svc-a"},
                "spec": {"type": "LoadBalancer", "ports": [{"port": 80, "protocol": "TCP"}]},
            },
        }));
        // Deliberately no `apply_node_event` for "node-a".
        state.apply_endpoint_slice_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {
                    "namespace": "default",
                    "name": "svc-a-aaaaa",
                    "labels": {"kubernetes.io/service-name": "svc-a"},
                },
                "ports": [{"port": 8080, "protocol": "TCP"}],
                "endpoints": [{"addresses": ["10.244.0.9"], "nodeName": "node-a", "conditions": {"ready": true}}],
            },
        }));

        let desired = state.desired(&node(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(
            desired.vip_map.is_empty(),
            "an endpoint on an unresolved node must not produce a VIP_MAP entry -- fabricating \
             a node_ip (e.g. 0.0.0.0) would misdirect the Geneve tunnel"
        );
    }

    // The front-IP model means EVERY node's own address is a valid ingress
    // for a Service (ebpf-lb-dataplane.md's "Packet flow" step 1) -- a
    // client dialing the OTHER node's address must still resolve on the
    // backend node's own TARGET_PORTS, or `try_geneve_decap_forward`'s
    // lookup misses and silently drops every forwarded packet before a
    // FLOW_TABLE entry is ever written -- this exact miss produced no
    // SYN-ACK and no FLOW_TABLE entry despite a working Geneve decap.
    #[test]
    fn desired_covers_every_known_node_as_a_front_not_just_the_local_one() {
        let mut state = WatchState::default();
        state.apply_service_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"namespace": "default", "name": "svc-a"},
                "spec": {"type": "LoadBalancer", "ports": [{"port": 80, "protocol": "TCP"}]},
            },
        }));
        state.apply_node_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "node-a"},
                "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.5"}]},
            },
        }));
        state.apply_node_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "node-b"},
                "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.6"}]},
            },
        }));
        state.apply_endpoint_slice_event(&serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": {
                    "namespace": "default",
                    "name": "svc-a-aaaaa",
                    "labels": {"kubernetes.io/service-name": "svc-a"},
                },
                "ports": [{"port": 8080, "protocol": "TCP"}],
                "endpoints": [{"addresses": ["10.244.0.9"], "nodeName": "node-b", "conditions": {"ready": true}}],
            },
        }));

        // Reconciling from node-b's own perspective (the backend node) --
        // the ingress node in this flow is node-a, a DIFFERENT node.
        let desired = state.desired(&node(Ipv4Addr::new(10, 0, 0, 6)));
        let fronts: HashSet<[u8; 4]> = desired
            .vip_map
            .keys()
            .map(|k| k.vip_ip.to_le_bytes())
            .collect();
        assert_eq!(
            fronts,
            HashSet::from([[10, 0, 0, 5], [10, 0, 0, 6]]),
            "TARGET_PORTS/VIP_MAP must cover every known node's address as a front, not just \
             this node's own -- otherwise the backend node can never decap a forward packet \
             whose client dialed a DIFFERENT node's front IP"
        );
    }

    // is_resource_expired must key off the HTTP 410 status watch_stream
    // embeds in its error text -- any other failure (idle timeout, reset)
    // must NOT trigger a full relist, or a merely-flaky connection would pay
    // a LIST round trip on every reconnect for no reason.
    #[test]
    fn only_410_gone_is_treated_as_resource_expired() {
        let gone = anyhow::anyhow!("watch returned HTTP 410 Gone");
        let reset = anyhow::anyhow!("watch stream idle timeout after 300s");
        assert!(is_resource_expired(&gone), "410 Gone must trigger a relist");
        assert!(
            !is_resource_expired(&reset),
            "a transient idle-timeout disconnect must resume at the same resourceVersion, not \
             pay for a full relist"
        );
    }

    // The backoff must grow on repeated failure (so a down apiserver isn't
    // hammered) but reset immediately on success (so one bad connection
    // doesn't leave every later reconnect artificially slow).
    #[test]
    fn backoff_grows_on_failure_and_resets_on_success() {
        let mut backoff = INITIAL_BACKOFF;
        backoff = next_backoff(backoff, false);
        assert_eq!(backoff, INITIAL_BACKOFF * 2);
        backoff = next_backoff(backoff, false);
        assert_eq!(backoff, INITIAL_BACKOFF * 4);
        backoff = next_backoff(backoff, true);
        assert_eq!(
            backoff, INITIAL_BACKOFF,
            "a successful reconnect must reset backoff to the floor immediately"
        );
    }

    #[test]
    fn backoff_is_capped_and_does_not_grow_unbounded() {
        let mut backoff = INITIAL_BACKOFF;
        for _ in 0..20 {
            backoff = next_backoff(backoff, false);
        }
        assert_eq!(
            backoff, MAX_BACKOFF,
            "repeated failures must not grow backoff past the cap -- an uncapped exponential \
             backoff would eventually wait hours between reconnect attempts"
        );
    }

    // list_resource_version is the one thing standing between "watch from
    // exactly where the list snapshot ended" and "watch from nothing,
    // silently missing every change made during the list call".
    #[test]
    fn list_resource_version_reads_metadata_field() {
        let body = serde_json::json!({"metadata": {"resourceVersion": "12345"}, "items": []});
        assert_eq!(list_resource_version(&body), Some("12345"));
    }

    #[test]
    fn list_resource_version_is_none_when_missing() {
        let body = serde_json::json!({"items": []});
        assert_eq!(list_resource_version(&body), None);
    }
}
