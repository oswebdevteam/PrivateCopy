use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    middleware,
    routing::{get, post, put},
};
use chrono::{Duration as ChronoDuration, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{
    auth,
    domain::{Amount, AuthenticatedAccount},
    error::AppError,
    oneclick::{
        AccountType, BalancesResponse, Confidentiality, GenerateIntentRequest,
        GenerateIntentResponse, QuoteRequest, QuoteResponse, RecipientType, SwapType,
    },
    state::AppState,
};

pub mod copy;
mod idempotency;
pub mod keys;
pub mod public;
mod rate_limit;
pub mod relay;
pub mod strategies;

pub const USER_SESSION: &str = "x-1click-session";

pub fn router(state: Arc<AppState>) -> Router {
    let origin = HeaderValue::from_str(&state.config.public_origin)
        .unwrap_or_else(|_| HeaderValue::from_static("http://localhost:3000"));
    let cors = CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([Method::GET, Method::POST, Method::PUT])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderName::from_static(idempotency::IDEMPOTENCY_KEY),
            HeaderName::from_static(USER_SESSION),
        ]);
    let timeout = state.config.request_timeout;

    Router::new()
        .route("/health", get(health))
        .route("/v1/leaderboard", get(public::leaderboard))
        .route("/v1/strategies", post(strategies::create))
        .route("/v1/strategies/{id}", get(public::strategy))
        .route("/v1/strategies/{id}/trades", post(strategies::trade))
        .route("/v1/keys", get(keys::list))
        .route("/v1/keys/{id}/revoke", post(keys::revoke))
        .route("/v1/copy/{key_id}/settings", put(copy::update_settings))
        .route("/v1/copy/{key_id}/orders", get(copy::orders))
        .route("/v1/copy/{key_id}/pause", post(copy::pause))
        .route("/v1/signals/{strategy_id}", get(relay::connect))
        .route("/v1/auth/nonce", post(auth::nonce))
        .route("/v1/auth/verify", post(auth::verify))
        .route("/v1/vault/shield", post(shield))
        .route("/v1/vault/unshield", post(unshield))
        .route("/v1/vault/balance", get(balance))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            rate_limit::limit,
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

#[derive(Debug, Deserialize)]
pub struct ShieldRequest {
    pub asset: String,
    pub amount: Amount,
    pub source: ShieldSource,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldSource {
    Intents,
    OriginChain,
}

#[derive(Debug, Deserialize)]
pub struct UnshieldRequest {
    pub asset: String,
    pub amount: Amount,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultQuoteResponse {
    pub preview: QuoteResponse,
    pub quote: QuoteResponse,
    pub intent: Option<GenerateIntentResponse>,
}

async fn shield(
    State(state): State<Arc<AppState>>,
    account: AuthenticatedAccount,
    headers: HeaderMap,
    Json(request): Json<ShieldRequest>,
) -> Result<Json<VaultQuoteResponse>, AppError> {
    let key = idempotency::idempotency_key(&headers)?;
    if let Some(response) =
        idempotency::cached::<VaultQuoteResponse>(&state, &account, "/v1/vault/shield", key).await?
    {
        return Ok(Json(response));
    }

    idempotency::claim(&state, &account, "/v1/vault/shield", key).await?;
    let result = shield_inner(&state, &account, request).await;
    idempotency::finish(&state, &account, "/v1/vault/shield", key, result)
        .await
        .map(Json)
}

async fn shield_inner(
    state: &AppState,
    account: &AuthenticatedAccount,
    request: ShieldRequest,
) -> Result<VaultQuoteResponse, AppError> {
    validate_asset(&request.asset)?;
    let deposit_type = match request.source {
        ShieldSource::Intents => AccountType::Intents,
        ShieldSource::OriginChain => AccountType::OriginChain,
    };
    let refund_type = deposit_type;
    let deadline = quote_deadline(state)?;
    let mut quote_request = QuoteRequest {
        dry: true,
        swap_type: SwapType::ExactInput,
        slippage_tolerance: 0,
        origin_asset: request.asset.clone(),
        deposit_type,
        destination_asset: request.asset,
        amount: request.amount,
        refund_to: account.0.as_str().into(),
        refund_type,
        recipient: account.0.as_str().into(),
        recipient_type: RecipientType::ConfidentialIntents,
        confidentiality: Confidentiality::Basic,
        deadline,
    };
    let preview = state.oneclick.quote(&quote_request).await?;
    quote_request.dry = false;
    let quote = state.oneclick.quote(&quote_request).await?;
    let intent = if deposit_type == AccountType::Intents {
        Some(generate_intent(state, account, &quote).await?)
    } else {
        None
    };
    Ok(VaultQuoteResponse {
        preview,
        quote,
        intent,
    })
}

async fn unshield(
    State(state): State<Arc<AppState>>,
    account: AuthenticatedAccount,
    headers: HeaderMap,
    Json(request): Json<UnshieldRequest>,
) -> Result<Json<VaultQuoteResponse>, AppError> {
    let key = idempotency::idempotency_key(&headers)?;
    if let Some(response) =
        idempotency::cached::<VaultQuoteResponse>(&state, &account, "/v1/vault/unshield", key)
            .await?
    {
        return Ok(Json(response));
    }

    idempotency::claim(&state, &account, "/v1/vault/unshield", key).await?;
    let result = unshield_inner(&state, &account, request).await;
    idempotency::finish(&state, &account, "/v1/vault/unshield", key, result)
        .await
        .map(Json)
}

async fn unshield_inner(
    state: &AppState,
    account: &AuthenticatedAccount,
    request: UnshieldRequest,
) -> Result<VaultQuoteResponse, AppError> {
    validate_asset(&request.asset)?;
    let mut quote_request = QuoteRequest {
        dry: true,
        swap_type: SwapType::ExactInput,
        slippage_tolerance: 0,
        origin_asset: request.asset.clone(),
        deposit_type: AccountType::ConfidentialIntents,
        destination_asset: request.asset,
        amount: request.amount,
        refund_to: account.0.as_str().into(),
        refund_type: AccountType::ConfidentialIntents,
        recipient: account.0.as_str().into(),
        recipient_type: RecipientType::Intents,
        confidentiality: Confidentiality::Basic,
        deadline: quote_deadline(state)?,
    };
    let preview = state.oneclick.quote(&quote_request).await?;
    quote_request.dry = false;
    let quote = state.oneclick.quote(&quote_request).await?;
    let intent = Some(generate_intent(state, account, &quote).await?);
    Ok(VaultQuoteResponse {
        preview,
        quote,
        intent,
    })
}

async fn balance(
    State(state): State<Arc<AppState>>,
    account: AuthenticatedAccount,
    headers: HeaderMap,
) -> Result<Json<BalancesResponse>, AppError> {
    if let Some(value) = headers
        .get(USER_SESSION)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
    {
        let session = SecretString::from(value.to_owned());
        let balances = state.oneclick.balances(&session).await?;
        state.secrets.put_session(account.0, session);
        return Ok(Json(balances));
    }
    let session = state.secrets.session(&account.0)?;
    state.oneclick.balances(&session).await.map(Json)
}

async fn generate_intent(
    state: &AppState,
    account: &AuthenticatedAccount,
    quote: &QuoteResponse,
) -> Result<GenerateIntentResponse, AppError> {
    let deposit_address = quote
        .quote
        .deposit_address
        .as_deref()
        .ok_or(AppError::UpstreamRejected)?;
    state
        .oneclick
        .generate_intent(&GenerateIntentRequest {
            intent_type: "swap_transfer",
            standard: "nep413",
            signer_id: account.0.as_str(),
            deposit_address,
        })
        .await
}

fn quote_deadline(state: &AppState) -> Result<chrono::DateTime<Utc>, AppError> {
    let duration =
        ChronoDuration::from_std(state.config.quote_ttl).map_err(|_| AppError::Internal)?;
    Ok(Utc::now() + duration)
}

fn validate_asset(asset: &str) -> Result<(), AppError> {
    if !asset.starts_with("nep141:") || asset.len() > 256 {
        return Err(AppError::Validation("invalid asset id".into()));
    }
    Ok(())
}
