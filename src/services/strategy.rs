use std::{collections::HashSet, sync::Arc};

use chrono::{Duration as ChronoDuration, Utc};
use rust_decimal::Decimal;
use secrecy::SecretString;
use sha2::{Digest, Sha256};

use crate::{
    crypto::{encode_ciphertext, encode_nonce, encrypt_signal},
    domain::{Amount, KeyId, NearAccount, Signal, SignalAction, StrategyId, StrategyStatus},
    error::AppError,
    services::{copy, portfolio::TokenBook, swaps},
    state::AppState,
    store::{NewFill, NewStrategy, StoredSignal},
};

pub struct NewStrategySpec<'a> {
    pub name: &'a str,
    pub vault_account: &'a NearAccount,
    pub assets: &'a [String],
    pub live_price: &'a str,
    pub delayed_price: Option<&'a str>,
    pub key_duration_seconds: u64,
    pub max_followers: i32,
}

pub struct TradeSpec {
    pub sell_asset: String,
    pub buy_asset: String,
    pub amount: Amount,
    pub max_slippage_bps: u16,
}

#[derive(Debug)]
pub struct TradeResult {
    pub seq: u64,
    pub epoch: u64,
    pub deposit_address: String,
    pub amount_in: String,
    pub amount_out: String,
    pub signal_valid_until: chrono::DateTime<Utc>,
    pub near_tx_hashes: Vec<String>,
}

pub async fn create_strategy(
    state: &Arc<AppState>,
    owner: &NearAccount,
    session: SecretString,
    spec: NewStrategySpec<'_>,
) -> Result<StrategyId, AppError> {
    validate_strategy(&spec)?;
    state.signers.signer(spec.vault_account)?;
    let tokens = TokenBook::load(state).await?;
    if let Some(asset) = spec.assets.iter().find(|asset| !tokens.supports(asset)) {
        return Err(AppError::Validation(format!(
            "asset {asset} is not supported by the price source"
        )));
    }
    match state.oneclick.balances(&session).await {
        Ok(_) => {}
        Err(AppError::UpstreamRejected) => return Err(AppError::Unauthorized),
        Err(error) => return Err(error),
    }

    let id = StrategyId::new();
    state
        .store
        .create_strategy(&NewStrategy {
            strategy_id: &id,
            owner,
            name: spec.name.trim(),
            vault_account: spec.vault_account,
            assets: spec.assets,
            live_price: spec.live_price,
            delayed_price: spec.delayed_price,
            key_duration_seconds: spec.key_duration_seconds,
            max_followers: spec.max_followers,
        })
        .await?;
    state
        .secrets
        .put_session(spec.vault_account.clone(), session);
    Ok(id)
}

struct TradeContext {
    vault: NearAccount,
    nav_usd_micros: i64,
}

async fn load_trade_context(
    state: &AppState,
    owner: &NearAccount,
    strategy_id: &StrategyId,
    replacement_session: Option<SecretString>,
    spec: &TradeSpec,
) -> Result<TradeContext, AppError> {
    let strategy = state.store.strategy_for_update(strategy_id, owner).await?;
    if strategy.status != status_name(StrategyStatus::Active) {
        return Err(AppError::Conflict("strategy is paused".into()));
    }
    if !strategy
        .assets
        .iter()
        .any(|asset| asset == &spec.sell_asset)
        || !strategy.assets.iter().any(|asset| asset == &spec.buy_asset)
    {
        return Err(AppError::Validation(
            "trade assets are outside the strategy allowlist".into(),
        ));
    }
    let vault: NearAccount = strategy.vault_account.parse()?;
    let balances = if let Some(session) = replacement_session {
        let balances = state.oneclick.balances(&session).await?;
        state.secrets.put_session(vault.clone(), session);
        balances
    } else {
        let session = state.secrets.session(&vault)?;
        state.oneclick.balances(&session).await?
    };
    let tokens = TokenBook::load(state).await?;
    let nav_usd_micros = tokens.nav_usd_micros(&balances.balances)?;
    if nav_usd_micros <= 0 {
        return Err(AppError::Conflict("strategy vault has no value".into()));
    }
    Ok(TradeContext {
        vault,
        nav_usd_micros,
    })
}

pub async fn execute_trade(
    state: &Arc<AppState>,
    owner: &NearAccount,
    strategy_id: &StrategyId,
    replacement_session: Option<SecretString>,
    spec: TradeSpec,
) -> Result<TradeResult, AppError> {
    validate_trade(&spec)?;
    let context = load_trade_context(state, owner, strategy_id, replacement_session, &spec).await?;
    let vault = &context.vault;
    let nav_usd_micros = context.nav_usd_micros;

    let execution = swaps::execute(
        state,
        &swaps::SwapParams {
            signer: vault,
            refund_to: vault,
            recipient: vault,
            origin_asset: &spec.sell_asset,
            destination_asset: &spec.buy_asset,
            amount: &spec.amount,
            max_slippage_bps: spec.max_slippage_bps,
        },
    )
    .await?;
    if !execution.succeeded() {
        return Err(swap_failure(execution.status));
    }
    let amount_out = execution.amount_out.ok_or(AppError::UpstreamRejected)?;
    let amount_in_usd = Decimal::from_str_exact(&execution.amount_in_usd)
        .map_err(|_| AppError::UpstreamRejected)?;
    let size_bps = size_bps_of_nav(amount_in_usd, nav_usd_micros)?;
    let seq = state.store.next_signal_seq(strategy_id).await?;
    let epoch_interval =
        i64::try_from(state.config.epoch_interval.as_secs()).map_err(|_| AppError::Internal)?;
    let epoch = state
        .store
        .ensure_epoch(strategy_id, epoch_interval)
        .await?;
    let key = state.epochs.key(strategy_id, epoch)?;
    let filled_at = Utc::now();
    let signal_valid_until = filled_at
        + ChronoDuration::from_std(state.config.signal_ttl).map_err(|_| AppError::Internal)?;
    let signal = Signal {
        strategy_id: strategy_id.clone(),
        seq,
        ts: filled_at,
        action: SignalAction::Swap,
        sell_asset: spec.sell_asset.clone(),
        buy_asset: spec.buy_asset.clone(),
        size_bps_of_nav: size_bps,
        max_slippage_bps: spec.max_slippage_bps,
        valid_until: signal_valid_until,
        seq_salt: None,
    };
    let encrypted = encrypt_signal(&key, &signal)?;
    state
        .store
        .commit_fill_and_signal(
            &NewFill {
                strategy_id,
                seq,
                asset_in: &spec.sell_asset,
                asset_out: &spec.buy_asset,
                amount_in: &execution.amount_in,
                amount_out: &amount_out,
                filled_at,
            },
            &StoredSignal {
                strategy_id,
                epoch,
                seq,
                ciphertext: &encrypted.ciphertext,
                nonce: &encrypted.nonce,
                valid_until: signal_valid_until,
            },
        )
        .await?;

    if let Err(error) = publish_signal(state, strategy_id, seq, epoch).await {
        tracing::error!(error = %error, "signal was persisted but not published to Redis");
    }
    let task_state = Arc::clone(state);
    let task_signal = signal.clone();
    tokio::spawn(async move {
        copy::fanout(task_state, task_signal).await;
    });

    Ok(TradeResult {
        seq,
        epoch,
        deposit_address: execution.deposit_address,
        amount_in: execution.amount_in,
        amount_out,
        signal_valid_until,
        near_tx_hashes: execution.near_tx_hashes,
    })
}

pub fn frame_for_signal(
    state: &AppState,
    holder: &crate::store::AccessKeyView,
    signal: &crate::store::SignalRow,
) -> Result<crate::domain::SignalFrame, AppError> {
    let key = state.epochs.key(&signal.strategy_id, signal.epoch)?;
    let key_id = KeyId::parse(holder.key_id.clone())?;
    let wrapped = crate::crypto::wrap_epoch_key(&key, &holder.agent_pubkey, &key_id)?;
    let mut plaintext = crate::crypto::decrypt_signal(
        &key,
        &signal.strategy_id,
        signal.seq,
        &signal.ciphertext,
        &signal.nonce,
    )?;
    watermark_signal(&key_id, &mut plaintext);
    let encrypted = encrypt_signal(&key, &plaintext)?;
    Ok(crate::domain::SignalFrame {
        frame_type: "signal",
        strategy_id: signal.strategy_id.clone(),
        epoch: signal.epoch,
        seq: signal.seq,
        wrapped_epoch_key: wrapped,
        ciphertext: encode_ciphertext(&encrypted.ciphertext),
        nonce: encode_nonce(&encrypted.nonce),
    })
}

pub(crate) fn watermark_signal(key_id: &KeyId, signal: &mut Signal) {
    let mut hasher = Sha256::new();
    hasher.update(b"privatecopy/watermark/v1");
    hasher.update(key_id.as_str().as_bytes());
    hasher.update(signal.strategy_id.as_str().as_bytes());
    hasher.update(signal.seq.to_be_bytes());
    let digest = hasher.finalize();
    let delta = if digest[0] & 1 == 0 { 1_i32 } else { -1_i32 };
    let adjusted = (i32::from(signal.size_bps_of_nav) + delta).clamp(1, 10_000);
    signal.size_bps_of_nav = u16::try_from(adjusted).unwrap_or(signal.size_bps_of_nav);
    signal.seq_salt = Some(bs58::encode(&digest[..8]).into_string());
}

#[must_use]
pub fn stream_key(strategy_id: &StrategyId) -> String {
    format!("signals:{strategy_id}")
}

async fn publish_signal(
    state: &AppState,
    strategy_id: &StrategyId,
    seq: u64,
    epoch: u64,
) -> Result<(), AppError> {
    let mut connection = state.redis.clone();
    redis::cmd("XADD")
        .arg(stream_key(strategy_id))
        .arg("MAXLEN")
        .arg("~")
        .arg(10_000)
        .arg("*")
        .arg("type")
        .arg("signal")
        .arg("seq")
        .arg(seq)
        .arg("epoch")
        .arg(epoch)
        .query_async::<String>(&mut connection)
        .await?;
    Ok(())
}

fn validate_strategy(spec: &NewStrategySpec<'_>) -> Result<(), AppError> {
    if spec.name.trim().is_empty() || spec.name.trim().len() > 64 {
        return Err(AppError::Validation(
            "strategy name must be 1 to 64 characters".into(),
        ));
    }
    if spec.assets.is_empty() || spec.assets.len() > 8 {
        return Err(AppError::Validation(
            "strategy must list between 1 and 8 assets".into(),
        ));
    }
    let unique: HashSet<&str> = spec.assets.iter().map(String::as_str).collect();
    if unique.len() != spec.assets.len() || unique.iter().any(|asset| !asset.starts_with("nep141:"))
    {
        return Err(AppError::Validation(
            "strategy assets must be unique NEP-141 ids".into(),
        ));
    }
    Amount::parse(spec.live_price)?;
    if let Some(delayed) = spec.delayed_price {
        Amount::parse(delayed)?;
    }
    if spec.key_duration_seconds == 0 || spec.key_duration_seconds > 365 * 24 * 60 * 60 {
        return Err(AppError::Validation("key duration is out of range".into()));
    }
    if !(1..=10_000).contains(&spec.max_followers) {
        return Err(AppError::Validation(
            "max_followers must be between 1 and 10000".into(),
        ));
    }
    Ok(())
}

fn validate_trade(spec: &TradeSpec) -> Result<(), AppError> {
    if spec.sell_asset == spec.buy_asset {
        return Err(AppError::Validation(
            "sell and buy assets must differ".into(),
        ));
    }
    if !(1..=1_000).contains(&spec.max_slippage_bps) {
        return Err(AppError::Validation(
            "max_slippage_bps must be between 1 and 1000".into(),
        ));
    }
    Ok(())
}

fn size_bps_of_nav(amount_in_usd: Decimal, nav_usd_micros: i64) -> Result<u16, AppError> {
    let nav = Decimal::from(nav_usd_micros) / Decimal::from(1_000_000_u64);
    let bps = amount_in_usd
        .checked_div(nav)
        .and_then(|ratio| ratio.checked_mul(Decimal::from(10_000_u32)))
        .ok_or(AppError::Internal)?
        .round();
    let clamped = bps.clamp(Decimal::ONE, Decimal::from(10_000_u32));
    clamped
        .to_string()
        .parse::<u16>()
        .map_err(|_| AppError::Internal)
}

const fn status_name(status: StrategyStatus) -> &'static str {
    match status {
        StrategyStatus::Active => "active",
        StrategyStatus::Paused => "paused",
    }
}

fn swap_failure(status: crate::oneclick::SwapStatus) -> AppError {
    match status {
        crate::oneclick::SwapStatus::Refunded => AppError::Conflict("swap was refunded".into()),
        crate::oneclick::SwapStatus::IncompleteDeposit => {
            AppError::Conflict("swap deposit was incomplete".into())
        }
        crate::oneclick::SwapStatus::Failed => AppError::Conflict("swap failed".into()),
        _ => AppError::UpstreamUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn signal() -> Signal {
        Signal {
            strategy_id: StrategyId::new(),
            seq: 7,
            ts: Utc::now(),
            action: SignalAction::Swap,
            sell_asset: "nep141:usdc".into(),
            buy_asset: "nep141:wrap.near".into(),
            size_bps_of_nav: 750,
            max_slippage_bps: 50,
            valid_until: Utc
                .timestamp_opt(2_000_000_000, 0)
                .single()
                .unwrap_or_default(),
            seq_salt: None,
        }
    }

    #[test]
    fn watermark_is_holder_specific_and_bounded() {
        let key_id = KeyId::new();
        let mut first = signal();
        let mut second = first.clone();
        watermark_signal(&key_id, &mut first);
        watermark_signal(&key_id, &mut second);
        assert_eq!(first.size_bps_of_nav, second.size_bps_of_nav);
        assert_eq!(first.seq_salt, second.seq_salt);
        assert!(first.seq_salt.is_some());

        let mut other = signal();
        watermark_signal(
            &KeyId::parse("other-holder".into()).unwrap_or_default(),
            &mut other,
        );
        assert_ne!(first.seq_salt, other.seq_salt);
        assert!(first.size_bps_of_nav.abs_diff(750) <= 1);
        assert!(first.size_bps_of_nav >= 1);
    }

    #[test]
    fn watermark_survives_boundary_values() {
        let mut one = signal();
        one.size_bps_of_nav = 1;
        watermark_signal(&KeyId::new(), &mut one);
        assert!((1..=2).contains(&one.size_bps_of_nav));

        let mut max = signal();
        max.size_bps_of_nav = 10_000;
        watermark_signal(&KeyId::new(), &mut max);
        assert!((9_999..=10_000).contains(&max.size_bps_of_nav));
    }
}
