use std::{collections::HashMap, fmt, fs, path::Path, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use borsh::BorshSerialize;
use ed25519_dalek::{Signer, SigningKey};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::domain::NearAccount;

const NEP413_TAG: u32 = (1 << 31) + 413;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("agent key file is unreadable")]
    Unreadable(#[source] std::io::Error),
    #[error("agent key file is invalid")]
    InvalidFile(#[source] serde_json::Error),
    #[error("agent key file has insecure permissions")]
    InsecurePermissions,
    #[error("signing key for {0} is not provisioned")]
    MissingKey(NearAccount),
    #[error("signing key is malformed")]
    InvalidKey,
    #[error("intent payload is not NEP-413")]
    InvalidIntent,
}

#[derive(Debug, Clone)]
pub struct SignerRegistry {
    keys: Arc<HashMap<NearAccount, Arc<AgentSigner>>>,
}

impl SignerRegistry {
    pub fn load(path: Option<&Path>) -> Result<Self, SignerError> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        #[cfg(unix)]
        ensure_permissions(path)?;
        #[cfg(not(unix))]
        ensure_permissions(path);
        let bytes = fs::read(path).map_err(SignerError::Unreadable)?;
        let file: KeyFile = serde_json::from_slice(&bytes).map_err(SignerError::InvalidFile)?;
        let keys = file
            .accounts
            .into_iter()
            .map(|entry| {
                let signer = AgentSigner::parse(&entry.secret_key)?;
                Ok((entry.account, Arc::new(signer)))
            })
            .collect::<Result<_, SignerError>>()?;
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    pub fn signer(&self, account: &NearAccount) -> Result<&AgentSigner, SignerError> {
        self.keys
            .get(account)
            .map(AsRef::as_ref)
            .ok_or_else(|| SignerError::MissingKey(account.clone()))
    }

    /// Signs the payload exactly as returned by 1Click and returns the
    /// `MultiPayload` expected by `/v0/submit-intent`.
    pub fn sign_intent(&self, account: &NearAccount, intent: &Value) -> Result<Value, SignerError> {
        let standard = intent
            .get("standard")
            .and_then(Value::as_str)
            .ok_or(SignerError::InvalidIntent)?;
        if standard != "nep413" {
            return Err(SignerError::InvalidIntent);
        }
        let payload = intent
            .get("payload")
            .and_then(Value::as_object)
            .ok_or(SignerError::InvalidIntent)?;
        let message = payload
            .get("message")
            .and_then(Value::as_str)
            .ok_or(SignerError::InvalidIntent)?;
        let recipient = payload
            .get("recipient")
            .and_then(Value::as_str)
            .ok_or(SignerError::InvalidIntent)?;
        let callback_url = payload.get("callbackUrl").and_then(Value::as_str);
        let nonce = payload
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or(SignerError::InvalidIntent)
            .and_then(|encoded| {
                BASE64
                    .decode(encoded)
                    .map_err(|_| SignerError::InvalidIntent)?
                    .try_into()
                    .map_err(|_| SignerError::InvalidIntent)
            })?;

        let signer = self.signer(account)?;
        let signature = signer.sign_nep413(message, nonce, recipient, callback_url);
        Ok(json!({
            "standard": "nep413",
            "payload": intent.get("payload").cloned().ok_or(SignerError::InvalidIntent)?,
            "public_key": signer.public_key(),
            "signature": signature,
        }))
    }
}

impl Default for SignerRegistry {
    fn default() -> Self {
        Self {
            keys: Arc::new(HashMap::new()),
        }
    }
}

pub struct AgentSigner {
    key: SigningKey,
    public_key: String,
}

impl fmt::Debug for AgentSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AgentSigner([redacted])")
    }
}

impl AgentSigner {
    fn parse(secret: &SecretString) -> Result<Self, SignerError> {
        let encoded = secret
            .expose_secret()
            .strip_prefix("ed25519:")
            .ok_or(SignerError::InvalidKey)?;
        let mut decoded = bs58::decode(encoded)
            .into_vec()
            .map_err(|_| SignerError::InvalidKey)?;
        let seed: [u8; 32] = match decoded.len() {
            32 => decoded
                .as_slice()
                .try_into()
                .map_err(|_| SignerError::InvalidKey)?,
            64 => decoded[..32]
                .try_into()
                .map_err(|_| SignerError::InvalidKey)?,
            _ => {
                decoded.zeroize();
                return Err(SignerError::InvalidKey);
            }
        };
        let key = SigningKey::from_bytes(&seed);
        if decoded.len() == 64 && decoded[32..] != key.verifying_key().as_bytes()[..] {
            decoded.zeroize();
            return Err(SignerError::InvalidKey);
        }
        decoded.zeroize();
        let public_key = format!(
            "ed25519:{}",
            bs58::encode(key.verifying_key().as_bytes()).into_string()
        );
        Ok(Self { key, public_key })
    }

    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    #[must_use]
    pub fn sign_message(&self, message: &[u8]) -> String {
        let signature = self.key.sign(message);
        format!(
            "ed25519:{}",
            bs58::encode(signature.to_bytes()).into_string()
        )
    }

    fn sign_nep413(
        &self,
        message: &str,
        nonce: [u8; 32],
        recipient: &str,
        callback_url: Option<&str>,
    ) -> String {
        let payload = Nep413Payload {
            message,
            nonce,
            recipient,
            callback_url,
        };
        let encoded = borsh::to_vec(&(NEP413_TAG, payload))
            .unwrap_or_else(|_| unreachable!("NEP-413 payload contains only infallible fields"));
        let digest = Sha256::digest(encoded);
        self.sign_message(&digest)
    }
}

#[derive(BorshSerialize)]
struct Nep413Payload<'a> {
    message: &'a str,
    nonce: [u8; 32],
    recipient: &'a str,
    callback_url: Option<&'a str>,
}

#[derive(Deserialize)]
struct KeyFile {
    accounts: Vec<KeyEntry>,
}

#[derive(Deserialize)]
struct KeyEntry {
    account: NearAccount,
    secret_key: SecretString,
}

#[derive(Serialize)]
pub struct AttestationSignature {
    pub public_key: String,
    pub signature: String,
}

pub fn attestation_digest(payload: &Value) -> Result<[u8; 32], SignerError> {
    let canonical = serde_json::to_vec(payload).map_err(|_| SignerError::InvalidIntent)?;
    Ok(Sha256::digest(canonical).into())
}

#[cfg(unix)]
fn ensure_permissions(path: &Path) -> Result<(), SignerError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .map_err(SignerError::Unreadable)?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(SignerError::InsecurePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_permissions(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_near_64_byte_secret_keys() {
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let mut encoded = signing_key.to_bytes().to_vec();
        encoded.extend_from_slice(signing_key.verifying_key().as_bytes());
        let secret = SecretString::from(format!("ed25519:{}", bs58::encode(encoded).into_string()));
        let signer = AgentSigner::parse(&secret).expect("valid NEAR secret key");
        assert_eq!(
            signer.public_key(),
            format!(
                "ed25519:{}",
                bs58::encode(signing_key.verifying_key().as_bytes()).into_string()
            )
        );
    }

    #[test]
    fn signs_nep413_without_exposing_key() {
        let secret = SecretString::from(format!(
            "ed25519:{}",
            bs58::encode([3_u8; 32]).into_string()
        ));
        let signer = AgentSigner::parse(&secret).expect("valid key");
        let message = signer.sign_nep413("hello", [0; 32], "localhost", None);
        assert!(message.starts_with("ed25519:"));
        assert!(!format!("{signer:?}").contains("ed25519:"));
    }
}
