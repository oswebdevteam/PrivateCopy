use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};

use crate::{
    domain::StrategyId,
    error::AppError,
    state::AppState,
    store::{AttestationView, LeaderboardEntry, StrategyView},
};

#[derive(Debug, Default, Deserialize)]
pub struct LeaderboardQuery {
    pub window: Option<String>,
    pub asset: Option<String>,
}

pub async fn leaderboard(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LeaderboardQuery>,
) -> Result<Json<Vec<LeaderboardEntry>>, AppError> {
    let window = query.window.as_deref().unwrap_or("7d");
    if !matches!(window, "7d" | "30d" | "all") {
        return Err(AppError::Validation(
            "window must be one of 7d, 30d or all".into(),
        ));
    }
    if let Some(asset) = query.asset.as_deref() {
        validate_asset(asset)?;
    }
    state
        .store
        .leaderboard(window, query.asset.as_deref())
        .await
        .map(Json)
}

#[derive(Debug, Serialize)]
pub struct StrategyDetail {
    pub strategy: StrategyView,
    pub attestations: Vec<AttestationView>,
}

pub async fn strategy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<StrategyDetail>, AppError> {
    let id = StrategyId::parse(id)?;
    let strategy = state.store.strategy(&id).await?.ok_or(AppError::NotFound)?;
    let attestations = state.store.attestation_history(&id, 100).await?;
    Ok(Json(StrategyDetail {
        strategy,
        attestations,
    }))
}

fn validate_asset(asset: &str) -> Result<(), AppError> {
    if !asset.starts_with("nep141:") || asset.len() > 256 {
        return Err(AppError::Validation("invalid asset id".into()));
    }
    Ok(())
}
