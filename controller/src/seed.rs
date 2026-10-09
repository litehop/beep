//! Cluster-wide flow-hash seed (`beep_common::Config::flow_hash_seed`): every
//! node must key `flow_hash` identically so a flow keeps its backend when a
//! different node becomes its ingress, and the value must not be derivable by
//! clients. It lives in one Kubernetes Secret that the first controller to
//! start creates and every other controller reads; the seed itself is never
//! logged or placed in an error message.

use anyhow::{anyhow, bail, Context};
use base64::Engine;
use beep::random_seed;
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

/// Creates the seed Secret with a fresh random seed, or, if it already
/// exists, reads the stored one. The create is the arbiter, so concurrent
/// controllers converge on whichever create the apiserver accepted.
pub async fn load_or_create_seed(client: &HyperApiClient, namespace: &str) -> anyhow::Result<u64> {
    let collection = format!("/api/v1/namespaces/{namespace}/secrets");
    let own_seed = random_seed().context("generating flow hash seed")?;
    let (status, _) = client
        .request(
            Method::POST,
            &collection,
            Some(secret_body(namespace, own_seed).to_string()),
        )
        .await
        .with_context(|| format!("POST {collection}"))?;
    match create_outcome(status) {
        CreateOutcome::Created => return Ok(own_seed),
        CreateOutcome::ReadExisting => {}
        CreateOutcome::Failed => bail!("POST {collection} returned HTTP {status}"),
    }

    let item = format!("{collection}/{SEED_SECRET_NAME}");
    let (status, body) = client
        .request(Method::GET, &item, None)
        .await
        .with_context(|| format!("GET {item}"))?;
    if !status.is_success() {
        bail!("GET {item} returned HTTP {status}");
    }
    parse_seed_secret(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

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
