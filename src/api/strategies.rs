use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        USER_SESSION,
        idempotency::{cached, claim, finish, idempotency_key},
    },
    domain::{Amount, AuthenticatedAccount, NearAccount, StrategyId},
    error::AppError,
    services::strategy::{self, NewStrategySpec, TradeSpec},
    state::AppState,
    store::StrategyView,
};

#[derive(Debug, Deserialize)]
pub struct CreateStrategyRequest {
    pub name: String,
    pub vault_account: NearAccount,
    pub assets: Vec<String>,
    pub live_price: String,
    pub delayed_price: Option<String>,
    pub key_duration_seconds: u64,
    pub max_followers: i32,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    account: AuthenticatedAccount,
    headers: HeaderMap,
    Json(request): Json<CreateStrategyRequest>,
) -> Result<(StatusCode, Json<StrategyView>), AppError> {
    let session = user_session(&headers)?;
    let id = match strategy::create_strategy(
        &state,
        &account.0,
        session,
        NewStrategySpec {
            name: &request.name,
            vault_account: &request.vault_account,
            assets: &request.assets,
            live_price: &request.live_price,
            delayed_price: request.delayed_price.as_deref(),
            key_duration_seconds: request.key_duration_seconds,
            max_followers: request.max_followers,
        },
    )
    .await
    {
        Ok(id) => id,
        Err(AppError::Database(error)) => {
            return Err(
                if error
                    .as_database_error()
                    .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
                {
                    AppError::Conflict("vault account is already registered".into())
                } else {
                    AppError::Database(error)
                },
            );
        }
        Err(error) => return Err(error),
    };
    let view = state.store.strategy(&id).await?.ok_or(AppError::Internal)?;
    Ok((StatusCode::CREATED, Json(view)))
}

#[derive(Debug, Deserialize)]
pub struct TradeRequest {
    pub sell_asset: String,
    pub buy_asset: String,
    pub amount: String,
    pub max_slippage_bps: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TradeResponse {
    pub status: String,
    pub seq: u64,
    pub epoch: u64,
    pub deposit_address: String,
    pub amount_in: String,
    pub amount_out: String,
    pub signal_valid_until: DateTime<Utc>,
    pub near_tx_hashes: Vec<String>,
}

pub async fn trade(
    State(state): State<Arc<AppState>>,
    account: AuthenticatedAccount,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<TradeRequest>,
) -> Result<Json<TradeResponse>, AppError> {
    let id = StrategyId::parse(id)?;
    let route = format!("/v1/strategies/{id}/trades");
    let key = idempotency_key(&headers)?;
    let session = optional_user_session(&headers);
    if let Some(response) = cached::<TradeResponse>(&state, &account, &route, key).await? {
        return Ok(Json(response));
    }
    let amount = Amount::parse(&request.amount)?;
    claim(&state, &account, &route, key).await?;
    let result = strategy::execute_trade(
        &state,
        &account.0,
        &id,
        session,
        TradeSpec {
            sell_asset: request.sell_asset,
            buy_asset: request.buy_asset,
            amount,
            max_slippage_bps: request.max_slippage_bps,
        },
    )
    .await
    .map(|result| TradeResponse {
        status: "settled".into(),
        seq: result.seq,
        epoch: result.epoch,
        deposit_address: result.deposit_address,
        amount_in: result.amount_in,
        amount_out: result.amount_out,
        signal_valid_until: result.signal_valid_until,
        near_tx_hashes: result.near_tx_hashes,
    });
    finish(&state, &account, &route, key, result)
        .await
        .map(Json)
}

fn user_session(headers: &HeaderMap) -> Result<SecretString, AppError> {
    optional_user_session(headers)
        .ok_or_else(|| AppError::Validation("x-1click-session header is required".into()))
}

fn optional_user_session(headers: &HeaderMap) -> Option<SecretString> {
    headers
        .get(USER_SESSION)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(|value| SecretString::from(value.to_owned()))
}
