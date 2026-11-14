use axum::http::HeaderMap;
use serde::{Serialize, de::DeserializeOwned};

use crate::{domain::AuthenticatedAccount, error::AppError, state::AppState};

pub const IDEMPOTENCY_KEY: &str = "idempotency-key";

pub fn idempotency_key(headers: &HeaderMap) -> Result<&str, AppError> {
    headers
        .get(IDEMPOTENCY_KEY)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| AppError::Validation("Idempotency-Key header is required".into()))
}

pub async fn cached<T>(
    state: &AppState,
    account: &AuthenticatedAccount,
    route: &str,
    key: &str,
) -> Result<Option<T>, AppError>
where
    T: DeserializeOwned,
{
    state
        .store
        .idempotency_response(&account.0, route, key)
        .await?
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| AppError::Internal)
}

pub async fn claim(
    state: &AppState,
    account: &AuthenticatedAccount,
    route: &str,
    key: &str,
) -> Result<(), AppError> {
    if state
        .store
        .claim_idempotency_key(&account.0, route, key)
        .await?
    {
        Ok(())
    } else {
        Err(AppError::Conflict("request is already in progress".into()))
    }
}

pub async fn finish<T>(
    state: &AppState,
    account: &AuthenticatedAccount,
    route: &str,
    key: &str,
    result: Result<T, AppError>,
) -> Result<T, AppError>
where
    T: Serialize,
{
    match result {
        Ok(response) => {
            let value = serde_json::to_value(&response).map_err(|_| AppError::Internal)?;
            state
                .store
                .complete_idempotency_key(&account.0, route, key, &value)
                .await?;
            Ok(response)
        }
        Err(error) => {
            state
                .store
                .release_idempotency_key(&account.0, route, key)
                .await?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::*;

    #[test]
    fn requires_a_bounded_idempotency_key() {
        let mut headers = HeaderMap::new();
        assert!(idempotency_key(&headers).is_err());

        headers.insert(IDEMPOTENCY_KEY, HeaderValue::from_static("request-1"));
        assert_eq!(idempotency_key(&headers).unwrap_or_default(), "request-1");

        let oversized =
            HeaderValue::from_str(&"x".repeat(129)).unwrap_or(HeaderValue::from_static(""));
        headers.insert(IDEMPOTENCY_KEY, oversized);
        assert!(idempotency_key(&headers).is_err());
    }
}
