use chrono::{DateTime, Utc};
use reqwest::{StatusCode, header::HeaderValue};
use rust_decimal::Decimal;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{domain::Amount, error::AppError};

#[derive(Debug, Clone)]
pub struct OneClickClient {
    http: reqwest::Client,
    base_url: String,
    api_key: Option<HeaderValue>,
}

impl OneClickClient {
    #[must_use]
    pub fn new(
        http: reqwest::Client,
        base_url: impl Into<String>,
        api_key: Option<SecretString>,
    ) -> Self {
        let api_key = api_key.and_then(|key| HeaderValue::from_str(key.expose_secret()).ok());
        Self {
            http,
            base_url: base_url.into().trim_end_matches('/').into(),
            api_key,
        }
    }

    pub async fn quote(&self, request: &QuoteRequest) -> Result<QuoteResponse, AppError> {
        let builder = self
            .partner_auth(self.http.post(self.url("/v0/quote")))
            .json(request);
        self.send(builder).await
    }

    pub async fn balances(
        &self,
        user_session: &SecretString,
    ) -> Result<BalancesResponse, AppError> {
        let builder = self
            .http
            .get(self.url("/v0/account/balances"))
            .bearer_auth(user_session.expose_secret());
        self.send(builder).await
    }

    pub async fn tokens(&self) -> Result<Vec<TokenResponse>, AppError> {
        self.send(self.http.get(self.url("/v0/tokens"))).await
    }

    pub async fn generate_intent(
        &self,
        request: &GenerateIntentRequest<'_>,
    ) -> Result<GenerateIntentResponse, AppError> {
        let builder = self
            .partner_auth(self.http.post(self.url("/v0/generate-intent")))
            .json(request);
        self.send(builder).await
    }

    pub async fn submit_intent(
        &self,
        signed_data: &Value,
    ) -> Result<SubmitIntentResponse, AppError> {
        let request = SubmitIntentRequest {
            intent_type: "swap_transfer",
            signed_data,
        };
        let builder = self
            .partner_auth(self.http.post(self.url("/v0/submit-intent")))
            .json(&request);
        self.send(builder).await
    }

    pub async fn status(&self, deposit_address: &str) -> Result<TypedSwapStatus, AppError> {
        let builder = self
            .partner_auth(self.http.get(self.url("/v0/status")))
            .query(&[("depositAddress", deposit_address)]);
        self.send(builder).await
    }

    fn partner_auth(&self, mut builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(api_key) = &self.api_key {
            builder = builder.header("X-API-Key", api_key);
        }
        builder
    }

    async fn send<T>(&self, builder: reqwest::RequestBuilder) -> Result<T, AppError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let response = builder.send().await?;
        let status = response.status();
        if status.is_success() {
            return response.json().await.map_err(AppError::from);
        }

        match status {
            StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT => Err(AppError::UpstreamUnavailable),
            _ => Err(AppError::UpstreamRejected),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccountType {
    OriginChain,
    Intents,
    ConfidentialIntents,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipientType {
    DestinationChain,
    Intents,
    ConfidentialIntents,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteRequest {
    pub dry: bool,
    pub swap_type: SwapType,
    pub slippage_tolerance: u16,
    pub origin_asset: String,
    pub deposit_type: AccountType,
    pub destination_asset: String,
    pub amount: Amount,
    pub refund_to: String,
    pub refund_type: AccountType,
    pub recipient: String,
    pub recipient_type: RecipientType,
    pub confidentiality: Confidentiality,
    pub deadline: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidentiality {
    Basic,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SwapType {
    ExactInput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteResponse {
    pub correlation_id: String,
    pub timestamp: DateTime<Utc>,
    pub signature: String,
    pub quote_request: Value,
    pub quote: Quote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Quote {
    pub deposit_address: Option<String>,
    pub deposit_memo: Option<String>,
    pub amount_in: String,
    pub amount_in_formatted: String,
    pub amount_in_usd: String,
    pub min_amount_in: String,
    pub amount_out: String,
    pub amount_out_formatted: String,
    pub amount_out_usd: String,
    pub min_amount_out: String,
    pub deadline: Option<DateTime<Utc>>,
    pub time_when_inactive: Option<DateTime<Utc>>,
    pub time_estimate: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BalancesResponse {
    pub balances: Vec<BalanceEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceEntry {
    pub token_id: String,
    pub available: String,
    pub source: BalanceSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    pub asset_id: String,
    pub decimals: u32,
    pub blockchain: String,
    pub symbol: String,
    pub price: Decimal,
    pub price_updated_at: DateTime<Utc>,
    #[serde(default)]
    pub contract_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BalanceSource {
    Private,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateIntentRequest<'a> {
    #[serde(rename = "type")]
    pub intent_type: &'static str,
    pub standard: &'static str,
    pub signer_id: &'a str,
    pub deposit_address: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateIntentResponse {
    pub intent: Value,
    pub correlation_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitIntentRequest<'a> {
    #[serde(rename = "type")]
    intent_type: &'static str,
    signed_data: &'a Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitIntentResponse {
    pub intent_hash: String,
    pub correlation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SwapStatus {
    PendingDeposit,
    KnownDepositTx,
    Processing,
    Success,
    IncompleteDeposit,
    Refunded,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SwapStatusResponse {
    pub status: SwapStatus,
    #[serde(flatten)]
    pub details: serde_json::Map<String, Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypedSwapStatus {
    pub correlation_id: String,
    pub quote_response: QuoteResponse,
    pub status: SwapStatus,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub swap_details: SwapDetails,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwapDetails {
    #[serde(default)]
    pub intent_hashes: Vec<String>,
    #[serde(default)]
    pub near_tx_hashes: Vec<String>,
    #[serde(default)]
    pub amount_in: Option<String>,
    #[serde(default)]
    pub amount_out: Option<String>,
    #[serde(default)]
    pub amount_in_usd: Option<String>,
    #[serde(default)]
    pub amount_out_usd: Option<String>,
    #[serde(default)]
    pub slippage: Option<f64>,
}
