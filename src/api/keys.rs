use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::{
    domain::{AuthenticatedAccount, KeyId},
    error::AppError,
    state::AppState,
    store::AccessKeyView,
};

pub async fn list(
    State(state): State<Arc<AppState>>,
    account: AuthenticatedAccount,
) -> Result<Json<Vec<AccessKeyView>>, AppError> {
    state.store.keys_for_account(&account.0).await.map(Json)
}

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    account: AuthenticatedAccount,
    Path(key_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let key_id = KeyId::parse(key_id)?;
    let strategy_id = state
        .store
        .revoke_key(&key_id, &account.0)
        .await?
        .ok_or(AppError::NotFound)?;
    state.store.next_epoch(&strategy_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
