use std::sync::Arc;

use chrono::Utc;
use tokio::task::JoinSet;

use crate::{
    domain::{AccessTier, Amount, CopyState, NearAccount, Signal},
    error::AppError,
    services::{portfolio::TokenBook, strategy::watermark_signal, swaps},
    state::AppState,
    store::{AccessKeyView, CopyOrderUpdate, FollowerSettings, VaultStateRow},
};

const BPS_DIVISOR: i128 = 10_000;
const MAX_CONCURRENT_COPIES: usize = 64;

#[derive(Debug, Clone, Copy)]
struct RiskDecision {
    target_usd_micros: i64,
    slippage_bps: u16,
}

pub async fn fanout(state: Arc<AppState>, signal: Signal) {
    let keys = match state
        .store
        .active_keys_for_strategy(&signal.strategy_id)
        .await
    {
        Ok(keys) => keys,
        Err(error) => {
            tracing::error!(error = %error, "could not load active copy keys");
            return;
        }
    };
    let mut tasks = JoinSet::new();
    for key in keys {
        if tasks.len() >= MAX_CONCURRENT_COPIES {
            join_copy_task(&mut tasks).await;
        }
        let state = Arc::clone(&state);
        let signal = signal.clone();
        tasks.spawn(async move {
            execute(state, key, signal).await;
        });
    }
    while !tasks.is_empty() {
        join_copy_task(&mut tasks).await;
    }
}

async fn join_copy_task(tasks: &mut JoinSet<()>) {
    if let Some(Err(error)) = tasks.join_next().await {
        tracing::warn!(error = %error, "copy task failed");
    }
}

async fn execute(state: Arc<AppState>, key: AccessKeyView, mut signal: Signal) {
    let Ok(key_id) = crate::domain::KeyId::parse(key.key_id.clone()) else {
        return;
    };
    watermark_signal(&key_id, &mut signal);
    let strategy_id = signal.strategy_id.clone();
    let created = match state
        .store
        .create_copy_order(&key_id, &strategy_id, signal.seq, CopyState::Received, None)
        .await
    {
        Ok(created) => created,
        Err(error) => {
            tracing::warn!(error = %error, key_id = %key.key_id, "could not create copy order");
            return;
        }
    };
    if !created {
        return;
    }

    if let Err(reason) = apply_delay(state.as_ref(), &key, &signal).await {
        finish_skipped(&state, &key_id, &strategy_id, signal.seq, reason).await;
        return;
    }

    match run_copy(&state, &key, &key_id, &strategy_id, &signal).await {
        Ok(()) => {}
        Err(reason) => {
            let terminal = terminal_state(reason);
            let _ = state
                .store
                .advance_copy_order(&CopyOrderUpdate {
                    key_id: &key_id,
                    strategy_id: &strategy_id,
                    seq: signal.seq,
                    state: terminal,
                    skip_reason: Some(reason),
                    quote_id: None,
                    status_ref: None,
                    amount_in: None,
                    copy_slippage_bps: None,
                })
                .await;
        }
    }
}

struct CopyContext {
    balances: Vec<crate::oneclick::BalanceEntry>,
    settings: FollowerSettings,
    tokens: TokenBook,
    nav_usd_micros: i64,
}

async fn load_copy_context(
    state: &AppState,
    key: &AccessKeyView,
    key_id: &crate::domain::KeyId,
    signal: &Signal,
) -> Result<CopyContext, &'static str> {
    let holder: NearAccount = key.holder.parse().map_err(|_| "invalid_holder")?;
    let active = state
        .store
        .active_key_for_holder(key_id, &holder)
        .await
        .map_err(|_| "access_expired")?;
    if active.strategy_id != signal.strategy_id.as_str() {
        return Err("access_expired");
    }
    let settings = state
        .store
        .follower_settings(key_id)
        .await
        .map_err(|_| "settings_unavailable")?
        .ok_or("settings_missing")?;
    if settings.paused {
        return Err("paused");
    }
    if signal.valid_until <= Utc::now() {
        return Err("signal_expired");
    }
    let strategy = state
        .store
        .strategy(&signal.strategy_id)
        .await
        .map_err(|_| "strategy_unavailable")?
        .ok_or("strategy_missing")?;
    if strategy.status != "active" {
        return Err("strategy_paused");
    }
    if !strategy
        .assets
        .iter()
        .any(|asset| asset == &signal.sell_asset)
        || !strategy
            .assets
            .iter()
            .any(|asset| asset == &signal.buy_asset)
    {
        return Err("asset_not_allowed");
    }
    let session = state
        .secrets
        .session(&settings.copy_vault_account)
        .map_err(|_| "session_required")?;
    state
        .signers
        .signer(&settings.copy_vault_account)
        .map_err(|_| "signer_unavailable")?;

    let balances = state
        .oneclick
        .balances(&session)
        .await
        .map_err(|_| "balances_unavailable")?;
    let tokens = TokenBook::load(state)
        .await
        .map_err(|_| "prices_unavailable")?;
    let nav_usd_micros = tokens
        .nav_usd_micros(&balances.balances)
        .map_err(|_| "nav_unavailable")?;
    if nav_usd_micros <= 0 {
        return Err("no_copy_budget");
    }
    Ok(CopyContext {
        balances: balances.balances,
        settings,
        tokens,
        nav_usd_micros,
    })
}

async fn ensure_risk_limits(
    state: &AppState,
    key_id: &crate::domain::KeyId,
    settings: &FollowerSettings,
    nav: i64,
) -> Result<(), &'static str> {
    let today = Utc::now().date_naive();
    let mut vault = state
        .store
        .vault_state(key_id)
        .await
        .map_err(|_| "risk_state_unavailable")?
        .unwrap_or(VaultStateRow {
            peak_nav_usd_micros: nav,
            day_start_nav_usd_micros: nav,
            day: today,
        });
    if vault.day != today {
        vault.day = today;
        vault.day_start_nav_usd_micros = nav;
    }
    vault.peak_nav_usd_micros = vault.peak_nav_usd_micros.max(nav);
    state
        .store
        .save_vault_state(key_id, &vault)
        .await
        .map_err(|_| "risk_state_unavailable")?;
    if below_threshold(nav, vault.peak_nav_usd_micros, settings.drawdown_stop_bps) {
        state
            .store
            .pause_copy(key_id)
            .await
            .map_err(|_| "risk_state_unavailable")?;
        return Err("drawdown_stop");
    }
    if below_threshold(nav, vault.day_start_nav_usd_micros, settings.daily_loss_bps) {
        return Err("daily_loss_stop");
    }
    Ok(())
}

fn sell_amount_for(
    context: &CopyContext,
    signal: &Signal,
) -> Result<(Amount, RiskDecision), &'static str> {
    let decision = size_order(
        &context.tokens,
        signal,
        &context.settings,
        context.nav_usd_micros,
        &context.balances,
    )?;
    if decision.target_usd_micros <= 0 {
        return Err("insufficient_balance");
    }
    let sell_amount = context
        .tokens
        .amount_for_usd_micros(&signal.sell_asset, decision.target_usd_micros)
        .map_err(|_| "sizing_failed")?;
    let available = context
        .tokens
        .balance(&context.balances, &signal.sell_asset);
    let sell_amount = sell_amount.min(available);
    if sell_amount == 0 {
        return Err("insufficient_balance");
    }
    let amount = Amount::parse(&sell_amount.to_string()).map_err(|_| "sizing_failed")?;
    Ok((amount, decision))
}

async fn run_copy(
    state: &Arc<AppState>,
    key: &AccessKeyView,
    key_id: &crate::domain::KeyId,
    strategy_id: &crate::domain::StrategyId,
    signal: &Signal,
) -> Result<(), &'static str> {
    let context = load_copy_context(state, key, key_id, signal).await?;
    ensure_risk_limits(state, key_id, &context.settings, context.nav_usd_micros).await?;
    let (sell_amount, decision) = sell_amount_for(&context, signal)?;
    state
        .store
        .advance_copy_order(&CopyOrderUpdate {
            key_id,
            strategy_id,
            seq: signal.seq,
            state: CopyState::Sized,
            skip_reason: None,
            quote_id: None,
            status_ref: None,
            amount_in: Some(sell_amount.as_str()),
            copy_slippage_bps: None,
        })
        .await
        .map_err(|_| "order_state_unavailable")?;

    let prepared = swaps::prepare(
        state.as_ref(),
        &swaps::SwapParams {
            signer: &context.settings.copy_vault_account,
            refund_to: &context.settings.copy_vault_account,
            recipient: &context.settings.copy_vault_account,
            origin_asset: &signal.sell_asset,
            destination_asset: &signal.buy_asset,
            amount: &sell_amount,
            max_slippage_bps: decision.slippage_bps,
        },
    )
    .await
    .map_err(|error| map_swap_error(&error))?;
    state
        .store
        .advance_copy_order(&CopyOrderUpdate {
            key_id,
            strategy_id,
            seq: signal.seq,
            state: CopyState::Quoted,
            skip_reason: None,
            quote_id: Some(&prepared.quote.correlation_id),
            status_ref: Some(&prepared.deposit_address),
            amount_in: Some(sell_amount.as_str()),
            copy_slippage_bps: None,
        })
        .await
        .map_err(|_| "order_state_unavailable")?;
    swaps::submit(state.as_ref(), &prepared)
        .await
        .map_err(|error| map_swap_error(&error))?;
    state
        .store
        .advance_copy_order(&CopyOrderUpdate {
            key_id,
            strategy_id,
            seq: signal.seq,
            state: CopyState::Funded,
            skip_reason: None,
            quote_id: None,
            status_ref: Some(&prepared.deposit_address),
            amount_in: Some(sell_amount.as_str()),
            copy_slippage_bps: None,
        })
        .await
        .map_err(|_| "order_state_unavailable")?;

    let execution = swaps::settlement(state.as_ref(), &prepared)
        .await
        .map_err(|error| map_swap_error(&error))?;
    settle_copy(
        state,
        key_id,
        strategy_id,
        signal,
        &context.tokens,
        execution,
    )
    .await
}

async fn settle_copy(
    state: &AppState,
    key_id: &crate::domain::KeyId,
    strategy_id: &crate::domain::StrategyId,
    signal: &Signal,
    tokens: &TokenBook,
    execution: swaps::SwapExecution,
) -> Result<(), &'static str> {
    if execution.status != crate::oneclick::SwapStatus::Success {
        return Err(settlement_reason(execution.status));
    }
    let amount_out = execution.amount_out.ok_or("missing_fill")?;
    let copy_slippage = state
        .store
        .fill(strategy_id, signal.seq)
        .await
        .ok()
        .flatten()
        .and_then(|trader| {
            tokens
                .copy_slippage_bps(
                    &trader.asset_in,
                    &trader.asset_out,
                    &trader.amount_in,
                    &trader.amount_out,
                    &execution.amount_in,
                    &amount_out,
                )
                .ok()
        });
    state
        .store
        .advance_copy_order(&CopyOrderUpdate {
            key_id,
            strategy_id,
            seq: signal.seq,
            state: CopyState::Settled,
            skip_reason: None,
            quote_id: None,
            status_ref: Some(&execution.deposit_address),
            amount_in: Some(&execution.amount_in),
            copy_slippage_bps: copy_slippage,
        })
        .await
        .map_err(|_| "order_state_unavailable")?;
    Ok(())
}

fn settlement_reason(status: crate::oneclick::SwapStatus) -> &'static str {
    match status {
        crate::oneclick::SwapStatus::Success => "settled",
        crate::oneclick::SwapStatus::Refunded => "refunded",
        crate::oneclick::SwapStatus::Failed | crate::oneclick::SwapStatus::IncompleteDeposit => {
            "swap_failed"
        }
        _ => "settlement_pending",
    }
}

fn size_order(
    tokens: &TokenBook,
    signal: &Signal,
    settings: &FollowerSettings,
    nav: i64,
    balances: &[crate::oneclick::BalanceEntry],
) -> Result<RiskDecision, &'static str> {
    let signal_bps = i128::from(signal.size_bps_of_nav);
    let multiplier = i128::from(settings.multiplier_bps);
    let cap = i128::from(nav) * i128::from(settings.trade_cap_bps) / BPS_DIVISOR;
    let target = i128::from(nav) * signal_bps * multiplier / (BPS_DIVISOR * BPS_DIVISOR);
    let available = tokens.balance(balances, &signal.sell_asset);
    let available_usd = tokens
        .amount_usd_micros(&signal.sell_asset, &available.to_string())
        .map_err(|_| "pricing_failed")?;
    let target = target.min(cap).min(i128::from(available_usd));
    let target = i64::try_from(target).map_err(|_| "sizing_failed")?;
    let setting_slippage = u16::try_from(settings.max_slippage_bps).unwrap_or_default();
    let slippage_bps = signal.max_slippage_bps.min(setting_slippage);
    Ok(RiskDecision {
        target_usd_micros: target,
        slippage_bps,
    })
}

async fn apply_delay(
    state: &AppState,
    key: &AccessKeyView,
    signal: &Signal,
) -> Result<(), &'static str> {
    if key.tier().map_err(|_| "invalid_tier")? != AccessTier::Delayed {
        return Ok(());
    }
    let due = signal.ts
        + chrono::Duration::from_std(state.config.delayed_tier).map_err(|_| "invalid_tier")?;
    if due >= signal.valid_until {
        return Err("signal_expired");
    }
    let wait = due - Utc::now();
    if let Ok(duration) = wait.to_std() {
        tokio::time::sleep(duration).await;
    }
    Ok(())
}

async fn finish_skipped(
    state: &AppState,
    key_id: &crate::domain::KeyId,
    strategy_id: &crate::domain::StrategyId,
    seq: u64,
    reason: &'static str,
) {
    let _ = state
        .store
        .advance_copy_order(&CopyOrderUpdate {
            key_id,
            strategy_id,
            seq,
            state: CopyState::Skipped,
            skip_reason: Some(reason),
            quote_id: None,
            status_ref: None,
            amount_in: None,
            copy_slippage_bps: None,
        })
        .await;
}

fn below_threshold(nav: i64, base: i64, stop_bps: i32) -> bool {
    if base <= 0 {
        return false;
    }
    i128::from(nav) * BPS_DIVISOR <= i128::from(base) * (BPS_DIVISOR - i128::from(stop_bps))
}

fn map_swap_error(error: &AppError) -> &'static str {
    match error {
        AppError::Signer(_) => "signer_unavailable",
        AppError::UpstreamRejected | AppError::UpstreamUnavailable => "execution_unavailable",
        _ => "execution_failed",
    }
}

fn terminal_state(reason: &str) -> CopyState {
    match reason {
        "refunded" => CopyState::Refunded,
        "access_expired"
        | "paused"
        | "signal_expired"
        | "strategy_paused"
        | "asset_not_allowed"
        | "settings_missing"
        | "session_required"
        | "no_copy_budget"
        | "drawdown_stop"
        | "daily_loss_stop"
        | "insufficient_balance" => CopyState::Skipped,
        _ => CopyState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_threshold_triggers_at_the_limit() {
        assert!(!below_threshold(9_501, 10_000, 500));
        assert!(below_threshold(9_500, 10_000, 500));
        assert!(below_threshold(9_499, 10_000, 500));
    }

    #[test]
    fn risk_threshold_ignores_invalid_base() {
        assert!(!below_threshold(0, 0, 500));
    }

    #[test]
    fn policy_rejections_are_skipped() {
        assert_eq!(terminal_state("daily_loss_stop"), CopyState::Skipped);
        assert_eq!(terminal_state("refunded"), CopyState::Refunded);
        assert_eq!(terminal_state("execution_failed"), CopyState::Failed);
    }
}
