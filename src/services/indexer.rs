use std::{collections::HashSet, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{
    crypto::validate_agent_pubkey,
    domain::{KeyId, NearAccount, StrategyId},
    error::AppError,
    state::AppState,
    store::NewAccessKey,
};

const CURSOR: &str = "near-indexer";
const POLL_INTERVAL: Duration = Duration::from_secs(1);

pub async fn run(state: Arc<AppState>) {
    let Some(base_url) = state.config.indexer_url.clone() else {
        tracing::warn!("event indexer is disabled because APP_INDEXER_URL is unset");
        return;
    };
    let contracts: HashSet<String> = [
        state.config.key_registry_contract.clone(),
        state.config.attestation_contract.clone(),
        state.config.strategy_market_contract.clone(),
    ]
    .into_iter()
    .flatten()
    .collect();
    if contracts.is_empty() {
        tracing::warn!("event indexer is disabled because no contract ids are configured");
        return;
    }
    let client = match reqwest::Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(Duration::from_secs(20))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(error = %error, "could not build indexer HTTP client");
            return;
        }
    };

    loop {
        if let Err(error) = tick(&state, &client, &base_url, &contracts).await {
            tracing::warn!(error = %error, "indexer tick failed");
            tokio::time::sleep(Duration::from_secs(2)).await;
        } else {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

async fn tick(
    state: &AppState,
    client: &reqwest::Client,
    base_url: &str,
    contracts: &HashSet<String>,
) -> Result<(), AppError> {
    let latest = state.near.latest_block_height().await?;
    let target = latest - state.config.indexer_lag_blocks;
    if target <= 0 {
        return Ok(());
    }
    let mut height = match state.store.chain_cursor(CURSOR).await? {
        Some(height) => height + 1,
        None => state
            .config
            .indexer_start_height
            .unwrap_or_else(|| (target - 10).max(1)),
    };
    while height <= target {
        let block = fetch_block(client, base_url, height).await?;
        let block_hash = block
            .get("block")
            .and_then(|block| block.get("header"))
            .and_then(|header| header.get("hash"))
            .and_then(Value::as_str)
            .filter(|hash| !hash.is_empty())
            .ok_or(AppError::UpstreamUnavailable)?
            .to_owned();
        if let Err(error) = apply_block(state, &block, contracts).await {
            tracing::warn!(height, error = %error, "could not apply block");
            return Err(error);
        }
        state
            .store
            .save_chain_cursor(CURSOR, height, &block_hash)
            .await?;
        height += 1;
    }
    Ok(())
}

async fn fetch_block(
    client: &reqwest::Client,
    base_url: &str,
    height: i64,
) -> Result<Value, AppError> {
    let url = format!("{}/v0/block/{height}", base_url.trim_end_matches('/'));
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(AppError::UpstreamUnavailable);
    }
    response.json().await.map_err(AppError::from)
}

async fn apply_block(
    state: &AppState,
    block: &Value,
    contracts: &HashSet<String>,
) -> Result<(), AppError> {
    let Some(shards) = block.get("shards").and_then(Value::as_array) else {
        return Err(AppError::UpstreamUnavailable);
    };
    for outcome in shards
        .iter()
        .flat_map(|shard| {
            shard
                .get("receipt_execution_outcomes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|outcome| outcome.get("execution_outcome"))
    {
        let Some(execution) = outcome.get("outcome") else {
            continue;
        };
        let Some(executor) = execution.get("executor_id").and_then(Value::as_str) else {
            continue;
        };
        if !contracts.contains(executor) {
            continue;
        }
        let Some(logs) = execution.get("logs").and_then(Value::as_array) else {
            continue;
        };
        for log in logs.iter().filter_map(Value::as_str) {
            let Some(payload) = log.strip_prefix("EVENT_JSON:") else {
                continue;
            };
            if let Err(error) = apply_event(state, payload).await {
                match error {
                    AppError::Validation(_) | AppError::NotFound => {
                        tracing::warn!(contract = %executor, error = %error, "skipped malformed chain event");
                    }
                    error => return Err(error),
                }
            }
        }
    }
    Ok(())
}

async fn apply_event(state: &AppState, payload: &str) -> Result<(), AppError> {
    let event: Value =
        serde_json::from_str(payload).map_err(|_| AppError::Validation("invalid event".into()))?;
    event
        .get("standard")
        .and_then(Value::as_str)
        .filter(|standard| !standard.is_empty())
        .ok_or_else(|| AppError::Validation("event has no standard".into()))?;
    event
        .get("version")
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty())
        .ok_or_else(|| AppError::Validation("event has no version".into()))?;
    let name = event
        .get("event")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("event has no name".into()))?;
    let Some(data) = event.get("data") else {
        return Ok(());
    };
    let records: Vec<&Value> = match data {
        Value::Array(records) => records.iter().collect(),
        Value::Object(_) => vec![data],
        _ => return Ok(()),
    };
    for record in records {
        match name {
            "key_granted" => apply_key_granted(state, record).await?,
            "key_revoked" => apply_key_status(state, record, "revoked").await?,
            "key_expired" => apply_key_status(state, record, "expired").await?,
            "attestation_posted" => apply_attestation(state, record).await?,
            _ => {}
        }
    }
    Ok(())
}

async fn apply_key_granted(state: &AppState, data: &Value) -> Result<(), AppError> {
    let key_id = KeyId::parse(field_str(data, "key_id")?.into())?;
    let strategy_id = StrategyId::parse(field_str(data, "strategy_id")?.into())?;
    let holder: NearAccount = field_str(data, "holder")?.parse()?;
    let agent_pubkey = field_str(data, "agent_pubkey")?;
    validate_agent_pubkey(agent_pubkey)?;
    let tier = field_str(data, "tier")?;
    if tier != "live" && tier != "delayed" {
        return Err(AppError::Validation("unknown access tier".into()));
    }
    let expires_at = parse_timestamp(data.get("expires_at"))?;
    state
        .store
        .upsert_access_key(&NewAccessKey {
            key_id: &key_id,
            strategy_id: &strategy_id,
            holder: &holder,
            agent_pubkey,
            tier,
            expires_at,
            status: "active",
        })
        .await
}

async fn apply_key_status(state: &AppState, data: &Value, status: &str) -> Result<(), AppError> {
    let key_id = KeyId::parse(field_str(data, "key_id")?.into())?;
    if let Some(strategy_id) = state.store.mark_key_status(&key_id, status).await? {
        state.store.next_epoch(&strategy_id).await?;
    }
    Ok(())
}

async fn apply_attestation(state: &AppState, data: &Value) -> Result<(), AppError> {
    let strategy_id = StrategyId::parse(field_str(data, "strategy_id")?.into())?;
    let window = field_str(data, "window")?;
    let tx_hash = data
        .get("tx_hash")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    if let Some(tx_hash) = tx_hash {
        state
            .store
            .set_latest_attestation_tx(&strategy_id, window, tx_hash)
            .await?;
    }
    Ok(())
}

fn field_str<'a>(data: &'a Value, name: &str) -> Result<&'a str, AppError> {
    data.get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Validation(format!("event is missing {name}")))
}

fn parse_timestamp(value: Option<&Value>) -> Result<DateTime<Utc>, AppError> {
    let value = value.ok_or_else(|| AppError::Validation("event is missing expires_at".into()))?;
    if let Some(text) = value.as_str() {
        if let Ok(timestamp) = DateTime::parse_from_rfc3339(text) {
            return Ok(timestamp.with_timezone(&Utc));
        }
        let numeric: i64 = text
            .parse()
            .map_err(|_| AppError::Validation("invalid expires_at".into()))?;
        return from_unix_numeric(numeric);
    }
    value
        .as_i64()
        .ok_or_else(|| AppError::Validation("invalid expires_at".into()))
        .and_then(from_unix_numeric)
}

fn from_unix_numeric(value: i64) -> Result<DateTime<Utc>, AppError> {
    if value < 0 {
        return Err(AppError::Validation("expires_at is out of range".into()));
    }
    let (seconds, nanos) = if value > 10_000_000_000 {
        let nanos = u32::try_from(value % 1_000_000_000)
            .map_err(|_| AppError::Validation("expires_at is out of range".into()))?;
        (value / 1_000_000_000, nanos)
    } else {
        (value, 0)
    };
    DateTime::from_timestamp(seconds, nanos)
        .ok_or_else(|| AppError::Validation("expires_at is out of range".into()))
}
