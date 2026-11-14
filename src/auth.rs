use std::{future::Future, sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::{header::AUTHORIZATION, request::Parts},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use borsh::BorshSerialize;
use chrono::{Duration as ChronoDuration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    domain::{AuthenticatedAccount, NearAccount},
    error::AppError,
    near::NearClient,
    state::AppState,
};

const NEP413_TAG: u32 = (1 << 31) + 413;

#[derive(Debug, Clone)]
pub struct AuthService {
    encoding_key: Arc<EncodingKey>,
    decoding_key: Arc<DecodingKey>,
    recipient: String,
    ttl: Duration,
    near: NearClient,
}

impl AuthService {
    #[must_use]
    pub fn new(secret: &SecretString, recipient: String, ttl: Duration, near: NearClient) -> Self {
        let bytes = secret.expose_secret().as_bytes();
        Self {
            encoding_key: Arc::new(EncodingKey::from_secret(bytes)),
            decoding_key: Arc::new(DecodingKey::from_secret(bytes)),
            recipient,
            ttl,
            near,
        }
    }

    #[must_use]
    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    pub async fn verify(
        &self,
        request: &VerifyRequest,
        expected_message: &str,
    ) -> Result<(), AppError> {
        if request.message != expected_message || request.recipient != self.recipient {
            return Err(AppError::Unauthorized);
        }

        verify_nep413_signature(request)?;
        if !self
            .near
            .verify_full_access_key(&request.account_id, &request.public_key)
            .await?
        {
            return Err(AppError::Unauthorized);
        }
        Ok(())
    }

    pub fn issue_token(&self, account: &NearAccount) -> Result<TokenResponse, AppError> {
        let issued_at = Utc::now();
        let expires_at =
            issued_at + ChronoDuration::from_std(self.ttl).map_err(|_| AppError::Internal)?;
        let claims = Claims {
            sub: account.as_str().into(),
            iat: issued_at.timestamp(),
            exp: expires_at.timestamp(),
        };
        let access_token = encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|_| AppError::Internal)?;
        Ok(TokenResponse {
            access_token,
            expires_at,
        })
    }

    pub fn authenticate(&self, token: &str) -> Result<AuthenticatedAccount, AppError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims(&["sub", "iat", "exp"]);
        let claims = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|_| AppError::Unauthorized)?
            .claims;
        Ok(AuthenticatedAccount(claims.sub.parse()?))
    }
}

#[derive(Debug, Deserialize)]
pub struct NonceRequest {
    pub account_id: NearAccount,
}

#[derive(Debug, Serialize)]
pub struct NonceResponse {
    pub nonce: String,
    pub message: String,
    pub recipient: String,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub account_id: NearAccount,
    pub public_key: String,
    pub signature: String,
    pub nonce: String,
    pub message: String,
    pub recipient: String,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: i64,
    exp: i64,
}

#[derive(BorshSerialize)]
struct Nep413Payload<'a> {
    message: &'a str,
    nonce: [u8; 32],
    recipient: &'a str,
    callback_url: Option<&'a str>,
}

pub async fn nonce(
    State(state): State<Arc<AppState>>,
    Json(request): Json<NonceRequest>,
) -> Result<Json<NonceResponse>, AppError> {
    let mut nonce = [0_u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    let encoded = BASE64.encode(nonce);
    let expires_at = Utc::now() + ChronoDuration::minutes(5);
    let message = "Sign in to KeyTrade";

    state
        .store
        .create_auth_nonce(
            &request.account_id,
            &nonce_hash(&nonce),
            message,
            expires_at,
        )
        .await?;

    Ok(Json(NonceResponse {
        nonce: encoded,
        message: message.into(),
        recipient: state.auth.recipient().into(),
        expires_at,
    }))
}

pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let nonce = decode_nonce(&request.nonce)?;
    let expected_message = state
        .store
        .auth_nonce_message(&request.account_id, &nonce_hash(&nonce))
        .await?
        .ok_or(AppError::Unauthorized)?;

    state.auth.verify(&request, &expected_message).await?;
    if !state
        .store
        .consume_auth_nonce(&request.account_id, &nonce_hash(&nonce))
        .await?
    {
        return Err(AppError::Unauthorized);
    }
    state.store.upsert_user(&request.account_id).await?;

    state.auth.issue_token(&request.account_id).map(Json)
}

impl FromRequestParts<Arc<AppState>> for AuthenticatedAccount {
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let auth = state.auth.clone();
        async move {
            let header = header.ok_or(AppError::Unauthorized)?;
            let token = header
                .strip_prefix("Bearer ")
                .ok_or(AppError::Unauthorized)?;
            auth.authenticate(token)
        }
    }
}

fn verify_nep413_signature(request: &VerifyRequest) -> Result<(), AppError> {
    let nonce = decode_nonce(&request.nonce)?;
    let payload = Nep413Payload {
        message: &request.message,
        nonce,
        recipient: &request.recipient,
        callback_url: request.callback_url.as_deref(),
    };
    let encoded = borsh::to_vec(&(NEP413_TAG, payload)).map_err(|_| AppError::Internal)?;
    let digest = Sha256::digest(encoded);
    let public_key = decode_tagged_base58::<32>(&request.public_key, "ed25519")?;
    let signature = decode_signature(&request.signature)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| AppError::Unauthorized)?;
    verifying_key
        .verify(&digest, &Signature::from_bytes(&signature))
        .map_err(|_| AppError::Unauthorized)
}

fn decode_nonce(encoded: &str) -> Result<[u8; 32], AppError> {
    BASE64
        .decode(encoded)
        .map_err(|_| AppError::Unauthorized)?
        .try_into()
        .map_err(|_| AppError::Unauthorized)
}

fn decode_signature(encoded: &str) -> Result<[u8; 64], AppError> {
    if encoded.starts_with("ed25519:") {
        return decode_tagged_base58(encoded, "ed25519");
    }
    BASE64
        .decode(encoded)
        .map_err(|_| AppError::Unauthorized)?
        .try_into()
        .map_err(|_| AppError::Unauthorized)
}

fn decode_tagged_base58<const N: usize>(
    value: &str,
    expected_tag: &str,
) -> Result<[u8; N], AppError> {
    let (tag, encoded) = value.split_once(':').ok_or(AppError::Unauthorized)?;
    if tag != expected_tag {
        return Err(AppError::Unauthorized);
    }
    bs58::decode(encoded)
        .into_vec()
        .map_err(|_| AppError::Unauthorized)?
        .try_into()
        .map_err(|_| AppError::Unauthorized)
}

fn nonce_hash(nonce: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(nonce).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_nonce_length() {
        assert!(decode_nonce("YQ==").is_err());
    }
}
