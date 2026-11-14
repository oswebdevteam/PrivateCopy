use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{domain::NearAccount, error::AppError};

#[derive(Debug, Clone)]
pub struct NearClient {
    http: reqwest::Client,
    rpc_url: String,
}

impl NearClient {
    #[must_use]
    pub fn new(http: reqwest::Client, rpc_url: String) -> Self {
        Self { http, rpc_url }
    }

    pub async fn verify_full_access_key(
        &self,
        account: &NearAccount,
        public_key: &str,
    ) -> Result<bool, AppError> {
        let request = RpcRequest {
            jsonrpc: "2.0",
            id: "privatecopy-auth",
            method: "query",
            params: json!({
                "request_type": "view_access_key",
                "finality": "final",
                "account_id": account.as_str(),
                "public_key": public_key,
            }),
        };
        let response = self
            .http
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json::<RpcResponse>()
            .await?;

        if let Some(error) = response.error {
            tracing::warn!(code = error.code, "NEAR access-key query failed");
            return Ok(false);
        }

        let permission = response
            .result
            .and_then(|result| result.get("permission").cloned());
        Ok(matches!(permission, Some(Value::String(value)) if value == "FullAccess"))
    }

    pub async fn latest_block_height(&self) -> Result<i64, AppError> {
        let request = RpcRequest {
            jsonrpc: "2.0",
            id: "privatecopy-indexer",
            method: "block",
            params: json!({ "finality": "final" }),
        };
        let response = self
            .http
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json::<RpcResponse>()
            .await?;
        if response.error.is_some() {
            return Err(AppError::UpstreamUnavailable);
        }
        response
            .result
            .and_then(|result| result.get("header")?.get("height")?.as_i64())
            .ok_or(AppError::UpstreamRejected)
    }
}

#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: &'a str,
    method: &'static str,
    params: Value,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
}
