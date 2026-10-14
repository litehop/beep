//! Per-node liveness for `status.loadBalancer.ingress`. Each controller renews
//! one `coordination.k8s.io/v1` Lease (`beep-node-<node>`) carrying its node's
//! addresses; every controller prunes ingress entries whose address has no
//! live Lease, so a node whose beep pod died stops receiving new connections
//! even though nothing was left running to remove its own entry.
//!
//! Liveness is judged by observation, as leader election does: a Lease is
//! live while its `renewTime` keeps changing as seen by THIS process's
//! monotonic clock. Wall-clock skew between nodes therefore cannot expire a
//! healthy node or keep a dead one.
//!
//! Timing mirrors Kubernetes node leases: 40 s duration, 10 s renew. A dead
//! node leaves ingress after at most `LEASE_DURATION` plus one prune interval
//! (`LEASE_RENEW` plus jitter); four missed renewals are tolerated before a
//! healthy node is dropped.

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context};
use beep_kubeconfig::HyperApiClient;
use hyper::{Method, StatusCode};
use serde_json::{json, Value};

pub const LEASE_DURATION: Duration = Duration::from_secs(40);
pub const LEASE_RENEW: Duration = Duration::from_secs(10);
/// Upper bound of the random delay added to each prune interval so
/// controllers started together do not all prune at the same instant.
pub const PRUNE_JITTER_MAX: Duration = Duration::from_secs(5);

const NAME_PREFIX: &str = "beep-node-";
const LABEL_SELECTOR: &str = "app.kubernetes.io%2Fcomponent%3Dnode-lease";
const IPS_ANNOTATION: &str = "beep.litehop.io/node-ips";

pub fn lease_name(node: &str) -> String {
    format!("{NAME_PREFIX}{node}")
}

/// RFC 3339 with microseconds, the apiserver's `MicroTime` format.
pub fn micro_time(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (hour, minute, second) = ((secs % 86400) / 3600, (secs % 3600) / 60, secs % 60);
    // Days since epoch to civil date (Hinnant's algorithm).
    let z = (secs / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:06}Z",
        d.subsec_micros()
    )
}

fn lease_body(namespace: &str, node: &str, ips: &[IpAddr], renew_time: &str) -> Value {
    let ips: Vec<String> = ips.iter().map(IpAddr::to_string).collect();
    json!({
        "apiVersion": "coordination.k8s.io/v1",
        "kind": "Lease",
        "metadata": {
            "name": lease_name(node),
            "namespace": namespace,
            "labels": {"app.kubernetes.io/component": "node-lease"},
            "annotations": {IPS_ANNOTATION: ips.join(",")},
        },
        "spec": {
            "holderIdentity": node,
            "leaseDurationSeconds": LEASE_DURATION.as_secs(),
            "renewTime": renew_time,
        },
    })
}

/// Writes this node's Lease with a fresh `renewTime`, creating it if absent.
/// An update must carry the live `resourceVersion`, so it is read first.
pub async fn renew_lease(
    client: &HyperApiClient,
    namespace: &str,
    node: &str,
    ips: &[IpAddr],
) -> anyhow::Result<()> {
    let collection = format!("/apis/coordination.k8s.io/v1/namespaces/{namespace}/leases");
    let item = format!("{collection}/{}", lease_name(node));
    let mut body = lease_body(namespace, node, ips, &micro_time(SystemTime::now()));
    let (status, current) = client
        .request(Method::GET, &item, None)
        .await
        .with_context(|| format!("GET {item}"))?;
    if status == StatusCode::NOT_FOUND {
        let (status, _) = client
            .request(Method::POST, &collection, Some(body.to_string()))
            .await
            .with_context(|| format!("POST {collection}"))?;
        if !status.is_success() {
            bail!("POST {collection} returned HTTP {status}");
        }
        return Ok(());
    }
    if !status.is_success() {
        bail!("GET {item} returned HTTP {status}");
    }
    let current: Value = serde_json::from_str(&current).context("parse Lease GET response")?;
    body["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"].clone();
    let (status, _) = client
        .request(Method::PUT, &item, Some(body.to_string()))
        .await
        .with_context(|| format!("PUT {item}"))?;
    if !status.is_success() {
        bail!("PUT {item} returned HTTP {status}");
    }
    Ok(())
}

/// One node Lease as listed from the apiserver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedLease {
    pub name: String,
    pub renew_time: String,
    pub ips: Vec<String>,
}

pub fn parse_lease_list(body: &str) -> anyhow::Result<Vec<ListedLease>> {
    let list: Value = serde_json::from_str(body).context("parse Lease list response")?;
    let items = list["items"].as_array().cloned().unwrap_or_default();
    Ok(items
        .iter()
        .filter_map(|item| {
            let name = item["metadata"]["name"].as_str()?;
            let renew_time = item["spec"]["renewTime"].as_str()?;
            let ips = item["metadata"]["annotations"][IPS_ANNOTATION]
                .as_str()
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            Some(ListedLease {
                name: name.to_owned(),
                renew_time: renew_time.to_owned(),
                ips,
            })
        })
        .collect())
}

pub async fn list_leases(
    client: &HyperApiClient,
    namespace: &str,
) -> anyhow::Result<Vec<ListedLease>> {
    let path = format!(
        "/apis/coordination.k8s.io/v1/namespaces/{namespace}/leases?labelSelector={LABEL_SELECTOR}"
    );
    let (status, body) = client
        .request(Method::GET, &path, None)
        .await
        .with_context(|| format!("GET {path}"))?;
    if !status.is_success() {
        bail!("GET {path} returned HTTP {status}");
    }
    parse_lease_list(&body)
}

/// A Lease as last seen by this process: `changed_at` is when its
/// `renewTime` last differed from the previous observation.
#[derive(Debug, Clone)]
pub struct ObservedLease {
    renew_time: String,
    pub ips: Vec<String>,
    pub changed_at: Instant,
}

impl ObservedLease {
    fn is_live(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.changed_at) < LEASE_DURATION
    }
}

pub struct LeaseTracker {
    started: Instant,
    leases: HashMap<String, ObservedLease>,
}

impl LeaseTracker {
    pub fn new(now: Instant) -> Self {
        Self {
            started: now,
            leases: HashMap::new(),
        }
    }

    /// Records a full Lease listing: a Lease absent from it is forgotten, an
    /// unchanged `renewTime` keeps its old `changed_at`.
    pub fn observe(&mut self, listed: Vec<ListedLease>, now: Instant) {
        let mut previous = std::mem::take(&mut self.leases);
        for lease in listed {
            let changed_at = match previous.remove(&lease.name) {
                Some(old) if old.renew_time == lease.renew_time => old.changed_at,
                _ => now,
            };
            self.leases.insert(
                lease.name,
                ObservedLease {
                    renew_time: lease.renew_time,
                    ips: lease.ips,
                    changed_at,
                },
            );
        }
    }

    pub fn leases(&self) -> &HashMap<String, ObservedLease> {
        &self.leases
    }

    pub fn is_live(&self, lease_name: &str, now: Instant) -> bool {
        self.leases.get(lease_name).is_some_and(|l| l.is_live(now))
    }

    /// A process that just started has not watched long enough to call a
    /// missing or silent Lease dead: every live node needs a full
    /// `LEASE_DURATION` of renewals to show up as changing.
    pub fn warmed_up(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started) >= LEASE_DURATION
    }
}

/// Whether this process may prune at all: it must have observed leases for a
/// full duration and see its own Lease renewing. If the Lease path is broken
/// (e.g. RBAC) every node would otherwise look dead.
pub fn may_prune(tracker: &LeaseTracker, own_lease: &str, now: Instant) -> bool {
    tracker.warmed_up(now) && tracker.is_live(own_lease, now)
}

/// Drops every ingress entry whose address is not carried by a live Lease --
/// an expired Lease and a missing one are both a node whose beep is not
/// running. Entries without an `ip` (hostname-only) are not beep's and stay.
/// `None` when nothing needs pruning, so the caller skips the PATCH.
pub fn pruned_ingress(
    existing: &[Value],
    leases: &HashMap<String, ObservedLease>,
    now: Instant,
) -> Option<Vec<Value>> {
    let is_live = |ip: &str| {
        leases
            .values()
            .any(|l| l.is_live(now) && l.ips.iter().any(|i| i == ip))
    };
    let kept: Vec<Value> = existing
        .iter()
        .filter(|entry| entry["ip"].as_str().is_none_or(is_live))
        .cloned()
        .collect();
    (kept.len() != existing.len()).then_some(kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listed(name: &str, renew: &str, ips: &[&str]) -> ListedLease {
        ListedLease {
            name: name.to_owned(),
            renew_time: renew.to_owned(),
            ips: ips.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn tracker_with(base: Instant, leases: Vec<ListedLease>) -> LeaseTracker {
        let mut t = LeaseTracker::new(base);
        t.observe(leases, base);
        t
    }

    fn ingress(ips: &[&str]) -> Vec<Value> {
        ips.iter().map(|ip| json!({"ip": ip})).collect()
    }

    // The point of the feature: a node whose beep stopped renewing must stop
    // being advertised, or clients keep sending ~1/N of new connections to it.
    #[test]
    fn expired_lease_removes_the_dead_nodes_entry_so_clients_stop_hitting_it() {
        let base = Instant::now();
        let t = tracker_with(
            base,
            vec![
                listed("beep-node-a", "t0", &["10.0.0.1"]),
                listed("beep-node-b", "t0", &["10.0.0.2"]),
            ],
        );
        let now = base + LEASE_DURATION + Duration::from_secs(1);
        let pruned = pruned_ingress(&ingress(&["10.0.0.1", "10.0.0.2"]), t.leases(), now);
        assert_eq!(pruned, Some(vec![])); // both silent for > duration
    }

    // A node renewing on schedule must survive the prune, or every healthy
    // node would flap out of ingress each time any controller prunes.
    #[test]
    fn renewing_lease_keeps_its_entry_and_only_the_silent_node_is_pruned() {
        let base = Instant::now();
        let mut t = tracker_with(
            base,
            vec![
                listed("beep-node-a", "t0", &["10.0.0.1"]),
                listed("beep-node-b", "t0", &["10.0.0.2"]),
            ],
        );
        let later = base + Duration::from_secs(35);
        t.observe(
            vec![
                listed("beep-node-a", "t35", &["10.0.0.1"]),
                listed("beep-node-b", "t0", &["10.0.0.2"]),
            ],
            later,
        );
        let now = later + Duration::from_secs(10);
        assert_eq!(
            pruned_ingress(&ingress(&["10.0.0.1", "10.0.0.2"]), t.leases(), now),
            Some(ingress(&["10.0.0.1"]))
        );
    }

    // An entry with no Lease at all (a node that never ran this version, or
    // whose Lease was deleted) is a node we cannot prove alive.
    #[test]
    fn entry_with_no_lease_is_pruned_because_the_node_cannot_be_proven_alive() {
        let base = Instant::now();
        let t = tracker_with(base, vec![listed("beep-node-a", "t0", &["10.0.0.1"])]);
        assert_eq!(
            pruned_ingress(&ingress(&["10.0.0.1", "10.0.0.9"]), t.leases(), base),
            Some(ingress(&["10.0.0.1"]))
        );
    }

    // The common steady state must be a no-op, or every prune pass would
    // issue a pointless PATCH racing the nodes' own ingress writes.
    #[test]
    fn all_fresh_is_a_noop_so_steady_state_costs_no_write() {
        let base = Instant::now();
        let t = tracker_with(base, vec![listed("beep-node-a", "t0", &["10.0.0.1"])]);
        assert_eq!(
            pruned_ingress(
                &ingress(&["10.0.0.1"]),
                t.leases(),
                base + Duration::from_secs(39)
            ),
            None
        );
    }

    // Exactly LEASE_DURATION without a renewal is expired and one tick less is
    // not: pins the boundary so a healthy node missing one 10 s renew is never
    // dropped, while a dead one cannot linger past the documented bound.
    #[test]
    fn lease_expires_exactly_at_the_duration_boundary() {
        let base = Instant::now();
        let t = tracker_with(base, vec![listed("beep-node-a", "t0", &["10.0.0.1"])]);
        let existing = ingress(&["10.0.0.1"]);
        let just_before = base + LEASE_DURATION - Duration::from_millis(1);
        assert_eq!(pruned_ingress(&existing, t.leases(), just_before), None);
        assert_eq!(
            pruned_ingress(&existing, t.leases(), base + LEASE_DURATION),
            Some(vec![])
        );
    }

    // Liveness is "renewTime changed", never "renewTime is recent": a node
    // whose wall clock is hours off must still count as live while it keeps
    // renewing, or clock skew would drop healthy nodes from ingress.
    #[test]
    fn clock_skewed_node_stays_live_as_long_as_renew_time_keeps_changing() {
        let base = Instant::now();
        let mut t = tracker_with(
            base,
            vec![listed(
                "beep-node-a",
                "1999-01-01T00:00:00.000001Z",
                &["10.0.0.1"],
            )],
        );
        let later = base + Duration::from_secs(30);
        t.observe(
            vec![listed(
                "beep-node-a",
                "1999-01-01T00:00:10.000001Z",
                &["10.0.0.1"],
            )],
            later,
        );
        assert_eq!(
            pruned_ingress(
                &ingress(&["10.0.0.1"]),
                t.leases(),
                later + Duration::from_secs(39)
            ),
            None
        );
    }

    // A Lease that is deleted must be forgotten immediately rather than
    // lingering as live in this process's memory.
    #[test]
    fn deleted_lease_is_forgotten_so_its_node_is_pruned() {
        let base = Instant::now();
        let mut t = tracker_with(base, vec![listed("beep-node-a", "t0", &["10.0.0.1"])]);
        t.observe(vec![], base + Duration::from_secs(1));
        assert!(!t.is_live("beep-node-a", base + Duration::from_secs(1)));
        assert_eq!(
            pruned_ingress(
                &ingress(&["10.0.0.1"]),
                t.leases(),
                base + Duration::from_secs(1)
            ),
            Some(vec![])
        );
    }

    // Hostname-only entries are not written by beep; pruning them would
    // delete another component's status.
    #[test]
    fn entries_without_an_ip_are_never_pruned() {
        let base = Instant::now();
        let t = LeaseTracker::new(base);
        let existing = vec![json!({"hostname": "lb.example.com"})];
        assert_eq!(pruned_ingress(&existing, t.leases(), base), None);
    }

    // A controller that just started has seen no renewals; pruning on that
    // view would evict every healthy peer. Only after a full duration of
    // observation may it judge a silent or missing Lease dead.
    #[test]
    fn fresh_process_does_not_prune_until_it_has_watched_a_full_lease_duration() {
        let base = Instant::now();
        let t = LeaseTracker::new(base);
        assert!(!t.warmed_up(base + LEASE_DURATION - Duration::from_millis(1)));
        assert!(t.warmed_up(base + LEASE_DURATION));
    }

    // Broken Lease RBAC makes our own create/update fail, so our Lease never
    // changes; pruning then would wipe every Service's ingress.
    #[test]
    fn broken_rbac_must_not_wipe_every_services_ingress() {
        let base = Instant::now();
        let mut t = LeaseTracker::new(base);
        t.observe(vec![listed("beep-node-b", "t0", &["10.0.0.2"])], base);
        let later = base + LEASE_DURATION + Duration::from_secs(1);
        t.observe(vec![listed("beep-node-b", "t1", &["10.0.0.2"])], later);
        assert!(t.warmed_up(later));
        assert!(
            !may_prune(&t, "beep-node-a", later),
            "own Lease absent: pruning would evict healthy peers"
        );
    }

    #[test]
    fn fresh_controller_must_not_prune_even_with_its_own_lease_present() {
        let base = Instant::now();
        let t = tracker_with(base, vec![listed("beep-node-a", "t0", &["10.0.0.1"])]);
        assert!(!may_prune(&t, "beep-node-a", base + Duration::from_secs(1)));
    }

    #[test]
    fn warmed_up_controller_with_renewing_own_lease_may_prune() {
        let base = Instant::now();
        let mut t = tracker_with(base, vec![listed("beep-node-a", "t0", &["10.0.0.1"])]);
        let later = base + LEASE_DURATION;
        t.observe(vec![listed("beep-node-a", "t1", &["10.0.0.1"])], later);
        assert!(may_prune(&t, "beep-node-a", later));
    }

    #[test]
    fn micro_time_matches_known_rfc3339_instants() {
        let at = |s: u64, us: u32| UNIX_EPOCH + Duration::new(s, us * 1000);
        assert_eq!(micro_time(at(0, 0)), "1970-01-01T00:00:00.000000Z");
        assert_eq!(
            micro_time(at(951_782_400, 5)),
            "2000-02-29T00:00:00.000005Z"
        );
        assert_eq!(
            micro_time(at(1_700_000_000, 123_456)),
            "2023-11-14T22:13:20.123456Z"
        );
    }

    #[test]
    fn lease_list_yields_name_renew_time_and_ips_and_skips_unrenewed() {
        let body = json!({"items": [
            {"metadata": {"name": "beep-node-a",
                          "annotations": {IPS_ANNOTATION: "10.0.0.1,fd00::1"}},
             "spec": {"renewTime": "t0"}},
            {"metadata": {"name": "beep-node-x"}, "spec": {}},
        ]})
        .to_string();
        assert_eq!(
            parse_lease_list(&body).unwrap(),
            vec![listed("beep-node-a", "t0", &["10.0.0.1", "fd00::1"])]
        );
    }
}
