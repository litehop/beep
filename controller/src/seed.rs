//! Cluster-wide flow-hash seed (`beep_common::Config::flow_hash_seed`): every
//! node must key `flow_hash` identically so a flow keeps its backend when a
//! different node becomes its ingress, and the value must not be derivable by
//! clients. It lives in one Kubernetes Secret that the first controller to
//! start creates and every other controller reads; the seed itself is never
//! logged or placed in an error message.

use std::path::Path;

use anyhow::{anyhow, bail, Context};
use aya::maps::{Array as AyaArray, Map, MapData};
use base64::Engine;
use beep::random_seed;
use beep_common::Config;
use beep_kubeconfig::HyperApiClient;
use hyper::{Method, StatusCode};
use serde_json::{json, Value};

pub const SEED_SECRET_NAME: &str = "servicelb-flow-hash-seed";
const SEED_KEY: &str = "seed";

/// What a seed-Secret create response means for this controller.
#[derive(Debug, PartialEq, Eq)]
pub enum CreateOutcome {
    /// This controller's own random seed is now the cluster's seed.
    Created,
    /// Another controller won the create race; read its seed instead.
    ReadExisting,
    Failed,
}

pub fn create_outcome(status: StatusCode) -> CreateOutcome {
    if status.is_success() {
        CreateOutcome::Created
    } else if status == StatusCode::CONFLICT {
        CreateOutcome::ReadExisting
    } else {
        CreateOutcome::Failed
    }
}

fn secret_body(namespace: &str, seed: u64) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": SEED_SECRET_NAME, "namespace": namespace},
        "type": "Opaque",
        "stringData": {SEED_KEY: format!("{seed:016x}")},
    })
}

fn parse_seed_secret(body: &str) -> anyhow::Result<u64> {
    let obj: Value = serde_json::from_str(body).context("parse seed Secret response")?;
    let encoded = obj["data"][SEED_KEY]
        .as_str()
        .ok_or_else(|| anyhow!("seed Secret has no data.{SEED_KEY}"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| anyhow!("seed Secret data.{SEED_KEY} is not valid base64"))?;
    let hex = String::from_utf8(raw)
        .map_err(|_| anyhow!("seed Secret data.{SEED_KEY} is not valid UTF-8"))?;
    u64::from_str_radix(hex.trim(), 16)
        .map_err(|_| anyhow!("seed Secret data.{SEED_KEY} is not a 64-bit hex value"))
}

/// What the Secret currently holds, as seen by a running controller.
#[derive(Debug, PartialEq, Eq)]
pub enum Observed {
    Stored(u64),
    Absent,
}

/// What a running controller does about the observed Secret.
#[derive(Debug, PartialEq, Eq)]
pub enum SeedAction {
    Keep,
    /// Another writer (an operator edit, or a controller that recreated the
    /// Secret first) changed the cluster seed: switch CONFIG to it.
    Adopt(u64),
    /// The Secret is gone: run the race-safe create-or-read again rather
    /// than keep a seed no restarting node can learn.
    Recreate,
}

pub fn seed_action(current: u64, observed: Observed) -> SeedAction {
    match observed {
        Observed::Stored(stored) if stored == current => SeedAction::Keep,
        Observed::Stored(stored) => SeedAction::Adopt(stored),
        Observed::Absent => SeedAction::Recreate,
    }
}

/// Operator-facing line for an action. Fixed text only: the seed is a secret.
pub fn action_log(action: &SeedAction) -> Option<&'static str> {
    match action {
        SeedAction::Keep => None,
        SeedAction::Adopt(_) => Some(
            "controller: WARN flow-hash seed Secret changed; adopting the stored value \
             (new flows re-home, pin-steered flows keep their backend)",
        ),
        SeedAction::Recreate => Some(
            "controller: WARN flow-hash seed Secret is missing; recreating it (first creator wins)",
        ),
    }
}

fn observe(status: StatusCode, body: &str) -> anyhow::Result<Observed> {
    if status == StatusCode::NOT_FOUND {
        Ok(Observed::Absent)
    } else if status.is_success() {
        parse_seed_secret(body).map(Observed::Stored)
    } else {
        bail!("GET seed Secret returned HTTP {status}")
    }
}

/// Creates the seed Secret holding `candidate`, or, if it already exists,
/// reads the stored one. The create is the arbiter, so concurrent
/// controllers converge on whichever create the apiserver accepted.
async fn create_or_read(
    client: &HyperApiClient,
    namespace: &str,
    candidate: u64,
) -> anyhow::Result<u64> {
    let collection = format!("/api/v1/namespaces/{namespace}/secrets");
    let (status, _) = client
        .request(
            Method::POST,
            &collection,
            Some(secret_body(namespace, candidate).to_string()),
        )
        .await
        .with_context(|| format!("POST {collection}"))?;
    match create_outcome(status) {
        CreateOutcome::Created => return Ok(candidate),
        CreateOutcome::ReadExisting => {}
        CreateOutcome::Failed => bail!("POST {collection} returned HTTP {status}"),
    }
    match read_seed(client, namespace).await? {
        Observed::Stored(seed) => Ok(seed),
        Observed::Absent => bail!("seed Secret vanished between create conflict and read"),
    }
}

async fn read_seed(client: &HyperApiClient, namespace: &str) -> anyhow::Result<Observed> {
    let item = format!("/api/v1/namespaces/{namespace}/secrets/{SEED_SECRET_NAME}");
    let (status, body) = client
        .request(Method::GET, &item, None)
        .await
        .with_context(|| format!("GET {item}"))?;
    observe(status, &body).with_context(|| format!("GET {item}"))
}

/// Startup: the cluster's seed, creating it from a fresh random value if no
/// controller has yet.
pub async fn load_or_create_seed(client: &HyperApiClient, namespace: &str) -> anyhow::Result<u64> {
    let candidate = random_seed().context("generating flow hash seed")?;
    create_or_read(client, namespace, candidate).await
}

/// One convergence pass for a running controller whose CONFIG holds
/// `current`. Returns the seed to switch to, if it differs. A recreate
/// republishes `current`, so a deleted Secret re-homes nothing unless another
/// controller won the create with a different value.
pub async fn converge_seed(
    client: &HyperApiClient,
    namespace: &str,
    current: u64,
) -> anyhow::Result<Option<u64>> {
    let mut action = seed_action(current, read_seed(client, namespace).await?);
    if let Some(line) = action_log(&action) {
        eprintln!("{line}");
    }
    if action == SeedAction::Recreate {
        let stored = create_or_read(client, namespace, current).await?;
        action = seed_action(current, Observed::Stored(stored));
        if let Some(line) = action_log(&action) {
            eprintln!("{line}");
        }
    }
    Ok(match action {
        SeedAction::Adopt(seed) => Some(seed),
        SeedAction::Keep | SeedAction::Recreate => None,
    })
}

/// Rewrites only `CONFIG.flow_hash_seed` in the pinned map, leaving the
/// startup-resolved Geneve ifindex as is.
pub fn write_config_seed(pin_dir: &Path, seed: u64) -> anyhow::Result<()> {
    let path = pin_dir.join("CONFIG");
    let map_data = MapData::from_pin(&path)
        .with_context(|| format!("opening pinned map `CONFIG` from {}", path.display()))?;
    let mut config: AyaArray<_, Config> = AyaArray::try_from(Map::Array(map_data))
        .context("map `CONFIG` is not a BPF_MAP_TYPE_ARRAY")?;
    let mut value = config.get(&0, 0).context("reading CONFIG[0]")?;
    value.flow_hash_seed = seed;
    config.set(0, value, 0).context("writing CONFIG[0]")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: u64 = 0x1111_2222_3333_4444;
    const NEW: u64 = 0x5555_6666_7777_8888;

    #[test]
    fn rotated_secret_is_adopted_or_nodes_keep_hashing_with_different_seeds() {
        assert_eq!(
            seed_action(OLD, Observed::Stored(NEW)),
            SeedAction::Adopt(NEW),
            "a running controller must follow the stored seed or nodes disagree on backends"
        );
    }

    #[test]
    fn unchanged_secret_is_a_no_op_so_polling_never_rewrites_config() {
        assert_eq!(seed_action(OLD, Observed::Stored(OLD)), SeedAction::Keep);
        assert_eq!(action_log(&SeedAction::Keep), None);
    }

    #[test]
    fn deleted_secret_is_recreated_not_silently_kept_private() {
        assert_eq!(seed_action(OLD, Observed::Absent), SeedAction::Recreate);
    }

    #[test]
    fn get_404_means_absent_and_other_failures_do_not_trigger_recreate() {
        assert_eq!(
            observe(StatusCode::NOT_FOUND, "").unwrap(),
            Observed::Absent
        );
        for status in [StatusCode::FORBIDDEN, StatusCode::INTERNAL_SERVER_ERROR] {
            assert!(
                observe(status, "").is_err(),
                "{status}: an apiserver hiccup must not be mistaken for deletion"
            );
        }
        let body = json!({"data": {SEED_KEY: base64::engine::general_purpose::STANDARD
            .encode(format!("{NEW:016x}"))}});
        assert_eq!(
            observe(StatusCode::OK, &body.to_string()).unwrap(),
            Observed::Stored(NEW)
        );
    }

    #[test]
    fn seed_value_never_appears_in_operator_logs() {
        for action in [
            SeedAction::Adopt(OLD),
            SeedAction::Adopt(NEW),
            SeedAction::Recreate,
        ] {
            let line = action_log(&action).expect("changes must be logged loudly");
            for seed in [OLD, NEW] {
                assert!(
                    !line.contains(&format!("{seed:016x}")) && !line.contains(&seed.to_string())
                );
            }
        }
    }

    #[test]
    fn already_exists_reads_the_stored_seed_or_each_node_would_key_its_own_hash() {
        assert_eq!(
            create_outcome(StatusCode::CONFLICT),
            CreateOutcome::ReadExisting,
            "losing the create race must adopt the winner's seed, not keep a private one"
        );
    }

    #[test]
    fn created_keeps_own_seed_and_other_errors_fail_closed() {
        assert_eq!(create_outcome(StatusCode::CREATED), CreateOutcome::Created);
        for status in [
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert_eq!(
                create_outcome(status),
                CreateOutcome::Failed,
                "{status}: starting with an unshared seed would split flows across nodes"
            );
        }
    }

    #[test]
    fn seed_survives_the_secret_round_trip_or_restarts_would_reshuffle_backends() {
        for seed in [0, 1, 0x0123_4567_89AB_CDEF, u64::MAX] {
            let created = secret_body("kube-system", seed);
            let stored = created["stringData"][SEED_KEY].as_str().unwrap();
            let read_back = json!({
                "data": {SEED_KEY: base64::engine::general_purpose::STANDARD.encode(stored)},
            });
            assert_eq!(parse_seed_secret(&read_back.to_string()).unwrap(), seed);
        }
    }

    #[test]
    fn malformed_secret_is_rejected_without_echoing_its_content() {
        let bad_hex = json!({"data": {SEED_KEY: base64::engine::general_purpose::STANDARD
            .encode("not-a-seed-xyz1")}});
        let err = parse_seed_secret(&bad_hex.to_string())
            .unwrap_err()
            .to_string();
        assert!(
            !err.contains("not-a-seed"),
            "seed material leaked into error: {err}"
        );
        assert!(parse_seed_secret(r#"{"data":{}}"#).is_err());
        assert!(parse_seed_secret(r#"{"data":{"seed":"!!!"}}"#).is_err());
    }
}
