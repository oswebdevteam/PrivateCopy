use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{Method, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};

use crate::{error::AppError, state::AppState};

pub async fn limit(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }
    let is_write = !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    let account = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(|token| state.auth.authenticate(token).ok());

    let (scope, identity, limit) = if is_write && account.is_some() {
        (
            "write",
            account
                .as_ref()
                .map(|account| account.0.as_str().to_owned())
                .unwrap_or_default(),
            u64::from(state.config.write_rate_limit.get()),
        )
    } else {
        let address = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or_else(
                || "unknown".into(),
                |ConnectInfo(address)| address.ip().to_string(),
            );
        (
            "public",
            address,
            u64::from(state.config.public_rate_limit.get()),
        )
    };
    match increment(&state, scope, &identity, limit).await {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    }
}

async fn increment(
    state: &AppState,
    scope: &str,
    identity: &str,
    limit: u64,
) -> Result<(), AppError> {
    let window = chrono::Utc::now().timestamp() / 60;
    let digest = Sha256::digest(identity.as_bytes());
    let key = format!("ratelimit:{scope}:{}:{window}", encode_hex(&digest[..12]));
    let mut connection = state.redis.clone();
    let mut pipeline = redis::pipe();
    pipeline.atomic();
    pipeline.incr(&key, 1_u64);
    pipeline.expire(&key, 65).ignore();
    let (count,): (u64,) = pipeline.query_async(&mut connection).await?;
    if count > limit {
        return Err(AppError::RateLimited);
    }
    Ok(())
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
