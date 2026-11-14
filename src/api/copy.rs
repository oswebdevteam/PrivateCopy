use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use secrecy::SecretString;

use crate::{
    api::USER_SESSION,
    domain::{AuthenticatedAccount, KeyId},
    error::AppError,
    state::AppState,
    store::{CopyOrderView, FollowerSettings},
};

pub async fn update_settings(
    State(state): State<Arc<AppState>>,
    account: AuthenticatedAccount,
    Path(key_id): Path<String>,
    headers: HeaderMap,
    Json(settings): Json<FollowerSettings>,
) -> Result<StatusCode, AppError> {
    settings.validate()?;
    let key_id = KeyId::parse(key_id)?;
    state
        .store
        .active_key_for_holder(&key_id, &account.0)
        .await?;
    state.signers.signer(&settings.copy_vault_account)?;
    let session = session_header(&headers).ok_or(AppError::Unauthorized)?;
    state
        .oneclick
        .balances(&session)
        .await
        .map_err(|_| AppError::Unauthorized)?;
    state.store.save_settings(&key_id, &settings).await?;
    state
        .secrets
        .put_session(settings.copy_vault_account, session);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn orders(
    State(state): State<Arc<AppState>>,
    account: AuthenticatedAccount,
    Path(key_id): Path<String>,
) -> Result<Json<Vec<CopyOrderView>>, AppError> {
    let key_id = KeyId::parse(key_id)?;
    state
        .store
        .access_key(&key_id, &account.0)
        .await?
        .ok_or(AppError::NotFound)?;
    state.store.copy_orders(&key_id, &account.0).await.map(Json)
}

pub async fn pause(
    State(state): State<Arc<AppState>>,
    account: AuthenticatedAccount,
    Path(key_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let key_id = KeyId::parse(key_id)?;
    state
        .store
        .access_key(&key_id, &account.0)
        .await?
        .ok_or(AppError::NotFound)?;
    state.store.set_copy_paused(&key_id, true).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn session_header(headers: &HeaderMap) -> Option<SecretString> {
    headers
        .get(USER_SESSION)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(|value| SecretString::from(value.to_owned()))
}
