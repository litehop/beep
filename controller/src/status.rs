//! Ensures this node's own address(es) are present in a `type=LoadBalancer`
//! Service's `status.loadBalancer.ingress` -- the field every
//! `jig.WaitForLoadBalancer`-style e2e spec (and any real client) polls
//! before it will attempt a connection. Per beep's node-owned-address model
//! (`docs/design/ebpf-lb-dataplane.md`) there is no single floating VIP to
//! elect one writer for: every node running this DaemonSet independently
//! advertises its OWN address for every `LoadBalancer` Service it fronts, so
//! this is an N-writer field and the writer here must add-if-absent and
//! never clobber another node's already-published entry. It also prunes its
//! OWN stale entries (a family this node stopped fronting, e.g. a Service
//! edited to a narrower `spec.ipFamilies`) -- see `merged_ingress`.
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

use std::{net::IpAddr, time::Duration};

use anyhow::Context;
use beep_kubeconfig::HyperApiClient;
use hyper::Method;
use serde_json::{json, Value};

/// Computes the corrected `status.loadBalancer.ingress` list for THIS node,
/// or `None` if it is already correct (telling the caller to skip the PATCH
/// entirely -- re-writing an already-correct list would be a wasted round
/// trip at best, and under a concurrent write from another node, an
/// unconditional overwrite risks dropping that node's entry).
///
/// `own_ips` is every address this node's own Node object reports (any
/// family, from `WatchState::own_node_ips`) -- the anchor set that decides
/// which `existing` entries are "this node's own" versus another node's.
/// `desired_ips` is the subset of `own_ips` that should be present right
/// now for the calling Service (`WatchState::ips_to_publish`'s own
/// `spec.ipFamilies` scoping). An `own_ips` entry present in `existing` but
/// missing from `desired_ips` is stale (this node stopped fronting that
/// family for this Service) and is dropped; a `desired_ips` entry missing
/// from `existing` is appended. Every entry whose `ip` is NOT in `own_ips`
/// belongs to another node and is never touched.
pub fn merged_ingress(
    existing: &[Value],
    own_ips: &[IpAddr],
    desired_ips: &[IpAddr],
) -> Option<Vec<Value>> {
    let is_own = |ip: &str| own_ips.iter().any(|o| o.to_string() == ip);
    let is_desired = |ip: &str| desired_ips.iter().any(|d| d.to_string() == ip);

    let mut merged: Vec<Value> = existing
        .iter()
        .filter(|entry| match entry["ip"].as_str() {
            Some(ip) => !is_own(ip) || is_desired(ip),
            None => true,
        })
        .cloned()
        .collect();
    let mut changed = merged.len() != existing.len();

    for ip in desired_ips {
        let ip = ip.to_string();
        if !merged
            .iter()
            .any(|entry| entry["ip"].as_str() == Some(ip.as_str()))
        {
            merged.push(json!({ "ip": ip }));
            changed = true;
        }
    }

    changed.then_some(merged)
}

/// Bounds the get-modify-patch loop against a persistently contended Service
/// (e.g. every node in a large DaemonSet racing to add its own entry at
/// once) -- an unbounded retry would let one hot Service wedge this node's
/// reconcile loop indefinitely instead of surfacing the failure and moving
/// on to the next event.
const MAX_CONFLICT_RETRIES: u32 = 5;

/// Backoff between conflict retries: without it, every node racing to add
/// its own entry to the same hot Service would retry back-to-back, each
/// attempt just as likely to re-collide with the others' PATCH as the last.
/// Grows with each attempt so a persistently contended Service backs off
/// further, but stays small and capped -- this loop's total worst case is
/// already bounded by `MAX_CONFLICT_RETRIES`.
const CONFLICT_RETRY_BASE_DELAY: Duration = Duration::from_millis(10);
const CONFLICT_RETRY_MAX_DELAY: Duration = Duration::from_millis(100);

fn conflict_retry_delay(attempt: u32) -> Duration {
    (CONFLICT_RETRY_BASE_DELAY.saturating_mul(1 << attempt.min(8))).min(CONFLICT_RETRY_MAX_DELAY)
}

/// Idempotently ensures exactly `desired_ips` (of the `own_ips` anchor set)
/// are present in the named Service's `status.loadBalancer.ingress` --
/// `merged_ingress`'s doc comment. Safe to call repeatedly (every reconcile
/// tick re-asserts this node's own entries): a no-op GET when the list is
/// already correct costs one round trip and no write.
pub async fn ensure_node_ingress(
    client: &HyperApiClient,
    namespace: &str,
    name: &str,
    own_ips: &[IpAddr],
    desired_ips: &[IpAddr],
) -> anyhow::Result<()> {
    let get_path = format!("/api/v1/namespaces/{namespace}/services/{name}");
    let status_path = format!("{get_path}/status");

    for attempt in 0..MAX_CONFLICT_RETRIES {
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

        let Some(new_ingress) = merged_ingress(&existing, own_ips, desired_ips) else {
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
            tokio::time::sleep(conflict_retry_delay(attempt)).await;
            continue;
        }
        anyhow::bail!("PATCH {status_path} returned HTTP {status}: {resp_body}");
    }
    anyhow::bail!("PATCH {status_path} exceeded {MAX_CONFLICT_RETRIES} conflict retries")
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    // Without a backoff, N nodes racing to add their own entry to the same
    // Service would retry a 409 Conflict back-to-back -- each attempt lands
    // at the same instant as the others' PATCH, so the collision just
    // repeats until MAX_CONFLICT_RETRIES is exhausted instead of a later
    // attempt succeeding once the retries are staggered.
    #[test]
    fn conflict_retry_delay_grows_with_attempt() {
        assert!(
            conflict_retry_delay(0) > Duration::ZERO,
            "the very first retry must still wait, or a revert to no delay wouldn't be caught"
        );
        assert!(
            conflict_retry_delay(1) > conflict_retry_delay(0),
            "later attempts against a persistently hot Service must back off further than the \
             first retry"
        );
    }

    // MAX_CONFLICT_RETRIES already bounds the number of attempts; the delay
    // itself must also stay capped, or a hot Service could still make this
    // node's reconcile loop wait an unreasonably long time on one Service
    // before moving on to the next watch event.
    #[test]
    fn conflict_retry_delay_is_capped() {
        assert_eq!(
            conflict_retry_delay(MAX_CONFLICT_RETRIES),
            CONFLICT_RETRY_MAX_DELAY,
            "the delay must not grow past the cap even after several retries"
        );
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(last: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last))
    }

    // An empty ingress list must gain this node's entry, or no client (and
    // no jig.WaitForLoadBalancer-style e2e spec) can ever discover where to
    // connect, even though the dataplane is already programmed correctly.
    #[test]
    fn absent_entry_is_appended() {
        let node_ip = v4(10, 0, 0, 5);
        let merged = merged_ingress(&[], &[node_ip], &[node_ip])
            .expect("must produce a new list when this node's ip is absent");
        assert_eq!(merged, vec![json!({"ip": "10.0.0.5"})]);
    }

    // A v6 --node-ip must be publishable too -- an Ipv4Addr-typed node_ip
    // parameter made this impossible before, leaving a v6-only node's
    // Service ingress permanently empty and unpollable by a v6 client.
    #[test]
    fn v6_node_ip_is_appended() {
        let node_ip = v6(5);
        let merged = merged_ingress(&[], &[node_ip], &[node_ip])
            .expect("must produce a new list when this node's ip is absent");
        assert_eq!(merged, vec![json!({"ip": "2001:db8::5"})]);
    }

    // A dual-stack Service on a dual-stack node must publish BOTH of this
    // node's addresses in one call, or a client of whichever family isn't
    // published can never discover this node as an ingress for the
    // Service.
    #[test]
    fn dual_stack_service_on_a_dual_stack_node_gets_a_two_entry_ingress() {
        let own = [v4(10, 0, 0, 5), v6(5)];
        let merged =
            merged_ingress(&[], &own, &own).expect("both entries are absent from an empty list");
        assert_eq!(
            merged,
            vec![json!({"ip": "10.0.0.5"}), json!({"ip": "2001:db8::5"})],
            "a dual-stack node fronting a dual-stack Service must publish both its own \
             addresses, not just one"
        );
    }

    // Calling this repeatedly (every reconcile tick) once every desired
    // entry already exists must be a no-op, or a raced PATCH against a
    // concurrent writer (another node) could clobber an entry that landed
    // between our GET and PATCH for no reason.
    #[test]
    fn already_present_entries_are_a_noop() {
        let node_ip = v4(10, 0, 0, 5);
        let existing = vec![json!({"ip": "10.0.0.5"})];
        assert_eq!(
            merged_ingress(&existing, &[node_ip], &[node_ip]),
            None,
            "an already-correct list must not trigger a rewrite"
        );
    }

    // Two nodes in the same DaemonSet each add their own entry to the same
    // Service-level list; adding/pruning THIS node's own entries must never
    // touch another node's -- a clobber here would make that OTHER node's
    // address disappear from status, breaking any client that had cached
    // it.
    #[test]
    fn other_nodes_entries_are_preserved() {
        let own = v4(10, 0, 0, 5);
        let other_node = json!({"ip": "10.0.0.6"});
        let existing = vec![other_node.clone()];
        let merged = merged_ingress(&existing, &[own], &[own])
            .expect("this node's ip is absent, so a new list must be produced");
        assert_eq!(
            merged,
            vec![other_node, json!({"ip": "10.0.0.5"})],
            "the other node's entry must survive alongside this node's new one"
        );
    }

    // A Service edited from RequireDualStack to a narrower SingleStack
    // [IPv4] must stop claiming readiness on this node's v6 address --
    // without pruning, a v6 client would keep polling an ingress entry
    // this node no longer actually fronts traffic for.
    #[test]
    fn a_family_this_node_stopped_fronting_is_pruned_from_its_own_entries() {
        let own = [v4(10, 0, 0, 5), v6(5)];
        // Both families were published earlier; the Service is now
        // SingleStack IPv4, so desired_ips only lists the v4 address.
        let existing = vec![json!({"ip": "10.0.0.5"}), json!({"ip": "2001:db8::5"})];
        let merged = merged_ingress(&existing, &own, &[own[0]])
            .expect("the v6 entry is stale and must be dropped");
        assert_eq!(
            merged,
            vec![json!({"ip": "10.0.0.5"})],
            "the v6 entry must be pruned once this node no longer fronts that family for this \
             Service, or a v6 client keeps being told this node is ready when it isn't"
        );
    }

    // Pruning must only ever touch entries in `own_ips` -- another node's
    // entry sharing no address with this node must survive a prune
    // untouched, even though it's also not in `desired_ips`.
    #[test]
    fn pruning_a_stale_family_never_touches_another_nodes_entry() {
        let own = [v4(10, 0, 0, 5), v6(5)];
        let other_node = json!({"ip": "10.0.0.6"});
        let existing = vec![
            other_node.clone(),
            json!({"ip": "10.0.0.5"}),
            json!({"ip": "2001:db8::5"}),
        ];
        let merged = merged_ingress(&existing, &own, &[own[0]])
            .expect("the v6 entry is stale and must be dropped");
        assert_eq!(
            merged,
            vec![other_node, json!({"ip": "10.0.0.5"})],
            "another node's entry must survive a prune of this node's own stale family"
        );
    }

    // ipMode must never be set on the entry this controller writes: setting
    // it to Proxy makes the upstream ESIPP e2e spec self-skip
    // (https://issues.k8s.io/123714), silently defeating the very thing this
    // status write was meant to unblock.
    #[test]
    fn appended_entry_never_sets_ip_mode() {
        let node_ip = v4(10, 0, 0, 5);
        let merged = merged_ingress(&[], &[node_ip], &[node_ip]).unwrap();
        assert!(
            merged[0].get("ipMode").is_none(),
            "ipMode must be absent (defaults to VIP semantics), not just null or empty"
        );
    }
}
