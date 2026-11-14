use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

use crate::signer::SignerError;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("authentication is required")]
    Unauthorized,
    #[error("you do not have permission to perform this action")]
    Forbidden,
    #[error("{0}")]
    Validation(String),
    #[error("resource not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("upstream service unavailable")]
    UpstreamUnavailable,
    #[error("upstream rejected the request")]
    UpstreamRejected,
    #[error("database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error(transparent)]
    Signer(#[from] SignerError),
    #[error("internal server error")]
    Internal,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
    retryable: bool,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, retryable) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", false),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", false),
            Self::Validation(_) => (StatusCode::BAD_REQUEST, "invalid_request", false),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", false),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict", false),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", true),
            Self::UpstreamUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream_unavailable",
                true,
            ),
            Self::UpstreamRejected => (StatusCode::BAD_GATEWAY, "upstream_rejected", false),
            Self::Signer(SignerError::MissingKey(_)) => {
                (StatusCode::SERVICE_UNAVAILABLE, "signer_unavailable", true)
            }
            Self::Signer(_) => (StatusCode::INTERNAL_SERVER_ERROR, "signer_error", false),
            Self::Database(_) | Self::Redis(_) | Self::Internal => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", true)
            }
        };

        let message = match &self {
            Self::Database(error) => {
                tracing::error!(error = %error, "database request failed");
                "internal server error".into()
            }
            Self::Redis(error) => {
                tracing::error!(error = %error, "Redis request failed");
                "internal server error".into()
            }
            Self::Signer(_) => "signing service is unavailable".into(),
            Self::Internal => "internal server error".into(),
            _ => self.to_string(),
        };

        (
            status,
            Json(ErrorBody {
                code,
                message,
                retryable,
            }),
        )
            .into_response()
    }
}

impl From<reqwest::Error> for AppError {
    fn from(error: reqwest::Error) -> Self {
        if error.is_timeout() || error.is_connect() {
            tracing::warn!(kind = "transport", "upstream request unavailable");
            Self::UpstreamUnavailable
        } else {
            tracing::warn!(kind = "response", "upstream request failed");
            Self::UpstreamRejected
        }
    }
}
