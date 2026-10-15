//! Best-effort Kubernetes Warning Events for a failed map restore.
//!
//! The controller exits non-zero on such a failure, so the pod crash-loops;
//! these Events tell `kubectl describe node|pod` why. Posting is never allowed
//! to change the exit behaviour or hide the original error.

use std::{
    future::Future,
    time::{Duration, SystemTime},
};

use beep::pin_migrate::{errno_name, restore_remediation, RestoreFailure};
use hyper::{Method, StatusCode};
use politeia::HyperApiClient;
use serde_json::{json, Value};
use tokio::time::timeout;

use crate::lease::micro_time;

pub const REASON: &str = "MapRestoreFailed";
const COMPONENT: &str = "beep-controller";
/// Where the kubelet records Node events.
const NODE_EVENT_NAMESPACE: &str = "default";

/// This pod, from the downward API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodRef {
    pub name: String,
    pub namespace: String,
    pub uid: Option<String>,
}

pub fn restore_failed_message(failure: &RestoreFailure) -> String {
    format!(
        "restoring migrated entries into map {} failed ({} write failures, first: {}): {}. \
         The previous programs keep serving from the old maps until this is fixed.",
        failure.map,
        failure.count,
        failure.errno.map_or("non-syscall error", errno_name),
        restore_remediation(failure.errno)
    )
}

fn event(namespace: &str, involved: Value, node: &str, message: &str, now: &str) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Event",
        "metadata": {"generateName": "beep-map-restore-failed-", "namespace": namespace},
        "involvedObject": involved,
        "reason": REASON,
        "message": message,
        "type": "Warning",
        "source": {"component": COMPONENT, "host": node},
        "reportingComponent": COMPONENT,
        "reportingInstance": node,
        "firstTimestamp": now,
        "lastTimestamp": now,
        "count": 1,
    })
}

/// `(namespace, Event)` pairs: one on the Node, one on the Pod if known.
/// `kubectl describe node` selects Events by `involvedObject.uid`, which the
/// kubelet sets to the node name.
pub fn restore_failed_events(
    node: &str,
    pod: Option<&PodRef>,
    message: &str,
    now: &str,
) -> Vec<(String, Value)> {
    let mut out = vec![(
        NODE_EVENT_NAMESPACE.to_owned(),
        event(
            NODE_EVENT_NAMESPACE,
            json!({"apiVersion": "v1", "kind": "Node", "name": node, "uid": node}),
            node,
            message,
            now,
        ),
    )];
    if let Some(pod) = pod {
        let mut involved = json!({
            "apiVersion": "v1", "kind": "Pod", "name": pod.name, "namespace": pod.namespace,
        });
        if let Some(uid) = &pod.uid {
            involved["uid"] = json!(uid);
        }
        out.push((
            pod.namespace.clone(),
            event(&pod.namespace, involved, node, message, now),
        ));
    }
    out
}

/// Posts the Events for `err` if it is a restore failure; any other error is
/// not this module's to report. Failures are logged and swallowed.
pub async fn report_restore_failure(
    client: &HyperApiClient,
    node: &str,
    pod: Option<&PodRef>,
    err: &anyhow::Error,
) {
    let Some(failure) = err.downcast_ref::<RestoreFailure>() else {
        return;
    };
    let message = restore_failed_message(failure);
    let now = micro_time(SystemTime::now());
    let events = restore_failed_events(node, pod, &message, &now);
    post_all(events, POST_DEADLINE, |path, body| async move {
        client.request(Method::POST, &path, Some(body)).await
    })
    .await;
}

/// Both POSTs together may not hold up the crash exit longer than this; the
/// client's own per-request timeout would otherwise stack once per Event.
const POST_DEADLINE: Duration = Duration::from_secs(10);

/// Posts every `(namespace, body)` through `post` within `deadline` overall.
/// Failures and a missed deadline are logged and swallowed.
async fn post_all<F, Fut>(events: Vec<(String, Value)>, deadline: Duration, mut post: F)
where
    F: FnMut(String, String) -> Fut,
    Fut: Future<Output = anyhow::Result<(StatusCode, String)>>,
{
    let all = async {
        for (namespace, body) in events {
            let path = format!("/api/v1/namespaces/{namespace}/events");
            match post(path.clone(), body.to_string()).await {
                Ok((status, _)) if status.is_success() => {
                    eprintln!("controller: posted {REASON} Event in {namespace}");
                }
                Ok((status, resp)) => {
                    eprintln!("controller: WARN posting {REASON} Event to {path} returned HTTP {status}: {resp}");
                }
                Err(e) => eprintln!("controller: WARN posting {REASON} Event to {path}: {e:#}"),
            }
        }
    };
    if timeout(deadline, all).await.is_err() {
        eprintln!("controller: WARN posting {REASON} Events exceeded {deadline:?}; giving up");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod() -> PodRef {
        PodRef {
            name: "beep-x".into(),
            namespace: "kube-system".into(),
            uid: Some("u-1".into()),
        }
    }

    #[test]
    fn events_target_node_in_default_and_pod_in_its_own_namespace() {
        // `kubectl describe node` only lists Events in `default` whose
        // involvedObject.uid is the node name; anything else is invisible.
        let events = restore_failed_events("n1", Some(&pod()), "msg", "T");
        assert_eq!(events.len(), 2);
        let (ns, node) = &events[0];
        assert_eq!(ns, "default");
        assert_eq!(node["metadata"]["namespace"], "default");
        assert_eq!(node["involvedObject"]["kind"], "Node");
        assert_eq!(node["involvedObject"]["name"], "n1");
        assert_eq!(node["involvedObject"]["uid"], "n1");
        assert_eq!(node["reason"], REASON);
        assert_eq!(node["type"], "Warning");
        let (ns, pod_ev) = &events[1];
        assert_eq!(ns, "kube-system");
        assert_eq!(pod_ev["metadata"]["namespace"], "kube-system");
        assert_eq!(pod_ev["involvedObject"]["kind"], "Pod");
        assert_eq!(pod_ev["involvedObject"]["name"], "beep-x");
        assert_eq!(pod_ev["involvedObject"]["namespace"], "kube-system");
        assert_eq!(pod_ev["involvedObject"]["uid"], "u-1");
    }

    #[tokio::test]
    async fn hung_apiserver_cannot_delay_the_crash_exit_past_the_deadline() {
        // Without the overall deadline, two hung POSTs stack their per-request
        // timeouts and the crash-looping pod exits ~60 s late.
        let events = restore_failed_events("n1", Some(&pod()), "msg", "T");
        let started = std::time::Instant::now();
        post_all(events, Duration::from_millis(50), |_, _| {
            std::future::pending::<anyhow::Result<(StatusCode, String)>>()
        })
        .await;
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_failed_node_post_does_not_stop_the_pod_post() {
        let events = restore_failed_events("n1", Some(&pod()), "msg", "T");
        let mut seen = Vec::new();
        post_all(events, Duration::from_secs(5), |path, _| {
            seen.push(path);
            async { Err(anyhow::anyhow!("boom")) }
        })
        .await;
        assert_eq!(
            seen,
            [
                "/api/v1/namespaces/default/events",
                "/api/v1/namespaces/kube-system/events"
            ]
        );
    }

    #[test]
    fn without_pod_identity_only_the_node_gets_an_event() {
        let events = restore_failed_events("n1", None, "msg", "T");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1["involvedObject"]["kind"], "Node");
    }

    #[test]
    fn message_names_map_errno_and_remediation() {
        let failure = RestoreFailure {
            map: "FRONT_META".into(),
            errno: Some(libc::ENOMEM),
            count: 3,
            first: vec![],
        };
        let m = restore_failed_message(&failure);
        assert!(m.contains("FRONT_META"), "{m}");
        assert!(m.contains("ENOMEM"), "{m}");
        assert!(m.contains("raise the pod memory limit"), "{m}");
        assert!(m.contains("keep serving"), "{m}");
    }
}
