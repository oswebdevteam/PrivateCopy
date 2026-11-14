use std::{collections::HashSet, sync::Arc};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rust_decimal::{Decimal, prelude::ToPrimitive};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    domain::{NearAccount, StrategyId},
    error::AppError,
    services::portfolio::TokenBook,
    signer::attestation_digest,
    state::AppState,
    store::{NewAttestation, NewSnapshot, SnapshotRow},
};

const WINDOWS: [(&str, i64); 2] = [("7d", 7), ("30d", 30)];

pub async fn run(state: Arc<AppState>) {
    let mut ticker = tokio::time::interval(state.config.attestation_interval);
    loop {
        ticker.tick().await;
        if let Err(error) = tick(&state).await {
            tracing::warn!(error = %error, "attestation round failed");
        }
    }
}

pub async fn tick(state: &Arc<AppState>) -> Result<(), AppError> {
    state.store.prune_expired_records().await?;
    let expired: HashSet<_> = state.store.expire_keys().await?.into_iter().collect();
    for strategy_id in expired {
        state.store.next_epoch(&strategy_id).await?;
    }
    let strategies = state.store.active_strategies().await?;
    let attestor = match state.config.attestor_account.as_deref() {
        Some(account) => Some(account.parse::<NearAccount>()?),
        None => None,
    };
    for strategy in strategies {
        let strategy_id = StrategyId::parse(strategy.strategy_id.clone())?;
        if let Err(error) = snapshot_strategy(state, &strategy_id, &strategy.vault_account).await {
            tracing::warn!(strategy_id = %strategy_id, error = %error, "snapshot failed");
            continue;
        }
        let Some(attestor) = &attestor else {
            continue;
        };
        if state.signers.signer(attestor).is_err() {
            continue;
        }
        if let Err(error) = attest_strategy(state, &strategy_id, attestor).await {
            tracing::warn!(strategy_id = %strategy_id, error = %error, "attestation failed");
        }
    }
    Ok(())
}

async fn snapshot_strategy(
    state: &Arc<AppState>,
    strategy_id: &StrategyId,
    vault: &str,
) -> Result<(), AppError> {
    let vault: NearAccount = vault.parse()?;
    let session = state.secrets.session(&vault)?;
    let balances = state.oneclick.balances(&session).await?;
    let tokens = TokenBook::load(state.as_ref()).await?;
    let value_usd_micros = tokens.nav_usd_micros(&balances.balances)?;
    let captured_at = Utc::now();
    let external_flow_usd_micros = 0_i64;
    let mut hasher = Sha256::new();
    hasher.update(strategy_id.as_str().as_bytes());
    hasher.update(captured_at.timestamp_millis().to_be_bytes());
    hasher.update(value_usd_micros.to_be_bytes());
    hasher.update(external_flow_usd_micros.to_be_bytes());
    let snapshot_hash: [u8; 32] = hasher.finalize().into();
    state
        .store
        .insert_snapshot(&NewSnapshot {
            strategy_id,
            captured_at,
            value_usd_micros,
            external_flow_usd_micros,
            snapshot_hash,
        })
        .await
}

async fn attest_strategy(
    state: &Arc<AppState>,
    strategy_id: &StrategyId,
    attestor: &NearAccount,
) -> Result<(), AppError> {
    let Some(first_fill) = state.store.first_fill_at(strategy_id).await? else {
        return Ok(());
    };
    let trade_count = state.store.fill_count(strategy_id).await?;
    let minimum_age = ChronoDuration::days(state.config.min_track_record_days);
    if Utc::now() - first_fill < minimum_age || trade_count < state.config.min_track_record_trades {
        return Ok(());
    }
    let now = Utc::now();
    let signer = state.signers.signer(attestor)?;
    let mut windows = Vec::with_capacity(WINDOWS.len() + 1);
    for (window, days) in WINDOWS {
        let period_start = now - ChronoDuration::days(days);
        if period_start < first_fill {
            continue;
        }
        windows.push((window, period_start));
    }
    windows.push(("all", first_fill));

    for (window, period_start) in windows {
        if let Err(error) =
            attest_window(state, strategy_id, signer, window, period_start, now).await
        {
            tracing::warn!(strategy_id = %strategy_id, window = %window, error = %error, "window skipped");
        }
    }
    Ok(())
}

async fn attest_window(
    state: &Arc<AppState>,
    strategy_id: &StrategyId,
    signer: &crate::signer::AgentSigner,
    window: &str,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
) -> Result<(), AppError> {
    let baseline = state
        .store
        .snapshot_before(strategy_id, period_start)
        .await?;
    let mut series = state
        .store
        .snapshots_between(strategy_id, period_start, period_end)
        .await?;
    if let Some(baseline) = baseline {
        series.insert(0, baseline);
    }
    if series.len() < 2 {
        return Ok(());
    }
    let twr_bps = time_weighted_return_bps(&series)?;
    let drawdown_bps = max_drawdown_bps(&series);
    let root = merkle_root(&series);
    let trade_count = state
        .store
        .fill_count_since(strategy_id, period_start)
        .await?;
    let latest = series.last().ok_or(AppError::Internal)?;
    let nav_bucket = nav_bucket(latest.value_usd_micros);
    let trade_count_bucket = trade_count_bucket(trade_count);
    let root_hex = encode_hex(&root);
    let payload = json!({
        "strategy_id": strategy_id.as_str(),
        "window": window,
        "period_start": period_start,
        "period_end": period_end,
        "twr_bps": twr_bps,
        "drawdown_bps": drawdown_bps,
        "nav_bucket": nav_bucket,
        "trade_count_bucket": trade_count_bucket,
        "snapshot_root": root_hex,
    });
    let digest = attestation_digest(&payload).map_err(AppError::Signer)?;
    let signature = signer.sign_message(&digest);
    state
        .store
        .insert_attestation(&NewAttestation {
            strategy_id,
            window,
            period_start,
            period_end,
            twr_bps,
            drawdown_bps,
            nav_bucket,
            trade_count_bucket,
            snapshot_root: root,
            tee_quote: &state.config.tee_quote,
            signature: &signature,
            tx_hash: None,
        })
        .await
}

fn time_weighted_return_bps(series: &[SnapshotRow]) -> Result<i64, AppError> {
    let mut product = Decimal::ONE;
    for pair in series.windows(2) {
        let previous = pair[0].value_usd_micros;
        if previous <= 0 {
            continue;
        }
        let numerator = pair[1]
            .value_usd_micros
            .checked_sub(pair[1].external_flow_usd_micros)
            .ok_or(AppError::Internal)?;
        let ratio = Decimal::from(numerator) / Decimal::from(previous);
        product = product.checked_mul(ratio).ok_or(AppError::Internal)?;
    }
    product
        .checked_sub(Decimal::ONE)
        .and_then(|value| value.checked_mul(Decimal::from(10_000_u32)))
        .and_then(|value| value.round().to_i64())
        .ok_or(AppError::Internal)
}

fn max_drawdown_bps(series: &[SnapshotRow]) -> i64 {
    let mut peak = 0_i64;
    let mut worst = 0_i64;
    for snapshot in series {
        peak = peak.max(snapshot.value_usd_micros);
        if peak <= 0 {
            continue;
        }
        let drawdown =
            (i128::from(peak) - i128::from(snapshot.value_usd_micros)) * 10_000 / i128::from(peak);
        if let Ok(drawdown) = i64::try_from(drawdown) {
            worst = worst.max(drawdown);
        }
    }
    worst
}

fn merkle_root(series: &[SnapshotRow]) -> [u8; 32] {
    if series.is_empty() {
        return [0; 32];
    }
    let mut level: Vec<[u8; 32]> = series
        .iter()
        .filter_map(|snapshot| snapshot.snapshot_hash.as_slice().try_into().ok())
        .collect();
    if level.is_empty() {
        return [0; 32];
    }
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(level.last().copied().unwrap_or([0; 32]));
        }
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|[left, right]| {
                let mut hasher = Sha256::new();
                hasher.update(left);
                hasher.update(right);
                hasher.finalize().into()
            })
            .collect();
    }
    level.first().copied().unwrap_or([0; 32])
}

fn nav_bucket(value_usd_micros: i64) -> &'static str {
    match value_usd_micros {
        ..=10_000_000_000 => "0-10k",
        10_000_000_001..=50_000_000_000 => "10k-50k",
        50_000_000_001..=100_000_000_000 => "50k-100k",
        100_000_000_001..=500_000_000_000 => "100k-500k",
        500_000_000_001..=1_000_000_000_000 => "500k-1m",
        _ => "1m+",
    }
}

const fn trade_count_bucket(count: i64) -> &'static str {
    match count {
        ..=10 => "0-10",
        11..=100 => "10-100",
        101..=1_000 => "100-1000",
        _ => "1000+",
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(time: i64, value: i64, flow: i64) -> SnapshotRow {
        SnapshotRow {
            strategy_id: StrategyId::new(),
            captured_at: DateTime::from_timestamp(time, 0).unwrap_or_default(),
            value_usd_micros: value,
            external_flow_usd_micros: flow,
            snapshot_hash: vec![1; 32],
        }
    }

    #[test]
    fn twr_removes_external_flow() {
        let series = [snapshot(0, 100, 0), snapshot(1, 200, 100)];
        assert_eq!(time_weighted_return_bps(&series).unwrap_or_default(), 0);
    }

    #[test]
    fn drawdown_is_peak_to_trough() {
        let series = [
            snapshot(0, 100, 0),
            snapshot(1, 150, 0),
            snapshot(2, 120, 0),
        ];
        assert_eq!(max_drawdown_bps(&series), 2_000);
    }

    #[test]
    fn buckets_are_banded() {
        assert_eq!(nav_bucket(5_000_000_000), "0-10k");
        assert_eq!(trade_count_bucket(11), "10-100");
    }
}
