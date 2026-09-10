//! Ensures this node's own address is present in a `type=LoadBalancer`
//! Service's `status.loadBalancer.ingress` -- the field every
//! `jig.WaitForLoadBalancer`-style e2e spec (and any real client) polls
//! before it will attempt a connection. Per beep's node-owned-address model
//! (`docs/design/ebpf-lb-dataplane.md`) there is no single floating VIP to
//! elect one writer for: every node running this DaemonSet independently
//! advertises its OWN address for every `LoadBalancer` Service it fronts, so
//! this is an N-writer field and the writer here must add-if-absent and
//! never clobber another node's already-published entry.
//!
//! `ip` is the only field ever set on the entry this node writes.
//! `ipMode` is deliberately left unset -- it defaults to `VIP` semantics,
//! while explicit `Proxy` makes the upstream ESIPP e2e spec self-skip
//! (`test/e2e/network/loadbalancer.go:1054`, tracking
//! https://issues.k8s.io/123714).
//!
//! `status.loadBalancer.ingress` is `x-kubernetes-list-type: atomic` in this
//! cluster's OpenAPI schema (verified against a live k3s v1.36 apiserver:
//! `kubectl get --raw /openapi/v3/api/v1`) -- there is no per-item merge key,
//! so server-side apply can't add one node's entry without a field manager
//! owning (and therefore being able to wholesale replace) the entire list.
//! A get-modify-patch loop keyed on `metadata.resourceVersion`, retried on a
//! 409 Conflict from a racing writer, is the only clobber-free option left
//! against an atomic list.

use std::net::Ipv4Addr;

use anyhow::Context;
use beep_kubeconfig::HyperApiClient;
use hyper::Method;
use serde_json::{json, Value};

/// Computes the new `status.loadBalancer.ingress` list after adding
/// `node_ip`, or `None` if it is already present. `None` tells the caller to
/// skip the PATCH entirely: re-writing an already-correct list would be a
/// wasted round trip at best, and under a concurrent write from another
/// node, an unconditional overwrite risks dropping that node's entry.
pub fn merged_ingress(existing: &[Value], node_ip: Ipv4Addr) -> Option<Vec<Value>> {
    let ip = node_ip.to_string();
    if existing
        .iter()
        .any(|entry| entry["ip"].as_str() == Some(ip.as_str()))
    {
        return None;
    }
    let mut merged = existing.to_vec();
    merged.push(json!({ "ip": ip }));
    Some(merged)
}

/// Bounds the get-modify-patch loop against a persistently contended Service
/// (e.g. every node in a large DaemonSet racing to add its own entry at
/// once) -- an unbounded retry would let one hot Service wedge this node's
/// reconcile loop indefinitely instead of surfacing the failure and moving
/// on to the next event.
const MAX_CONFLICT_RETRIES: u32 = 5;

/// Idempotently ensures `node_ip` is present in the named Service's
/// `status.loadBalancer.ingress`. Safe to call repeatedly (every reconcile
/// tick re-asserts this node's own entry): a no-op GET when the entry is
/// already there costs one round trip and no write.
pub async fn ensure_node_ingress(
    client: &HyperApiClient,
    namespace: &str,
    name: &str,
    node_ip: Ipv4Addr,
) -> anyhow::Result<()> {
    let get_path = format!("/api/v1/namespaces/{namespace}/services/{name}");
    let status_path = format!("{get_path}/status");

    for _ in 0..MAX_CONFLICT_RETRIES {
        let (status, body) = client
            .request(Method::GET, &get_path, None)
            .await
            .with_context(|| format!("GET {get_path}"))?;
        if !status.is_success() {
            anyhow::bail!("GET {get_path} returned HTTP {status}");
        }
        let obj: Value = serde_json::from_str(&body).context("parse Service GET response")?;
        let resource_version = obj["metadata"]["resourceVersion"]
            .as_str()
            .context("Service GET response missing metadata.resourceVersion")?;
        let existing = obj["status"]["loadBalancer"]["ingress"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        let Some(new_ingress) = merged_ingress(&existing, node_ip) else {
            return Ok(());
        };

        // Including `metadata.resourceVersion` in a JSON merge patch body
        // gives the apiserver's own optimistic-concurrency check on this
        // patch, same as a PUT: a resourceVersion that no longer matches the
        // live object (another node's PATCH landed first) is rejected with
        // 409 Conflict rather than silently applied over a stale read.
        let patch = json!({
            "metadata": {"resourceVersion": resource_version},
            "status": {"loadBalancer": {"ingress": new_ingress}},
        });
        let (status, resp_body) = client
            .request_with_content_type(
                Method::PATCH,
                &status_path,
                Some(patch.to_string()),
                "application/merge-patch+json",
            )
            .await
            .with_context(|| format!("PATCH {status_path}"))?;
        if status.is_success() {
            return Ok(());
        }
        if status == hyper::StatusCode::CONFLICT {
            continue;
        }
        anyhow::bail!("PATCH {status_path} returned HTTP {status}: {resp_body}");
    }
    anyhow::bail!("PATCH {status_path} exceeded {MAX_CONFLICT_RETRIES} conflict retries")
}

#[cfg(test)]
mod tests {
    use super::*;

    // An empty ingress list must gain this node's entry, or no client (and
    // no jig.WaitForLoadBalancer-style e2e spec) can ever discover where to
    // connect, even though the dataplane is already programmed correctly.
    #[test]
    fn absent_entry_is_appended() {
        let merged = merged_ingress(&[], Ipv4Addr::new(10, 0, 0, 5))
            .expect("must produce a new list when this node's ip is absent");
        assert_eq!(merged, vec![json!({"ip": "10.0.0.5"})]);
    }

    // Calling this repeatedly (every reconcile tick) once the entry already
    // exists must be a no-op, or a raced PATCH against a concurrent writer
    // (another node) could clobber an entry that landed between our GET and
    // PATCH for no reason -- the entry is already correct, so there's
    // nothing to write.
    #[test]
    fn already_present_entry_is_a_noop() {
        let existing = vec![json!({"ip": "10.0.0.5"})];
        assert_eq!(
            merged_ingress(&existing, Ipv4Addr::new(10, 0, 0, 5)),
            None,
            "an already-present entry must not trigger a rewrite"
        );
    }

    // Two nodes in the same DaemonSet each add their own entry to the same
    // Service-level list; adding this node's entry must never drop another
    // node's -- a clobber here would make that OTHER node's address
    // disappear from status, breaking any client that had cached it.
    #[test]
    fn other_nodes_entries_are_preserved_when_appending() {
        let existing = vec![json!({"ip": "10.0.0.6"})];
        let merged = merged_ingress(&existing, Ipv4Addr::new(10, 0, 0, 5))
            .expect("this node's ip is absent, so a new list must be produced");
        assert_eq!(
            merged,
            vec![json!({"ip": "10.0.0.6"}), json!({"ip": "10.0.0.5"})],
            "the other node's entry must survive alongside this node's new one"
        );
    }

    // ipMode must never be set on the entry this controller writes: setting
    // it to Proxy makes the upstream ESIPP e2e spec self-skip
    // (https://issues.k8s.io/123714), silently defeating the very thing this
    // status write was meant to unblock.
    #[test]
    fn appended_entry_never_sets_ip_mode() {
        let merged = merged_ingress(&[], Ipv4Addr::new(10, 0, 0, 5)).unwrap();
        assert!(
            merged[0].get("ipMode").is_none(),
            "ipMode must be absent (defaults to VIP semantics), not just null or empty"
        );
    }
}
