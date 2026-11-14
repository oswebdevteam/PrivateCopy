use std::{fmt, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use dashmap::DashMap;
use hkdf::Hkdf;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    domain::{KeyId, NearAccount, Signal, StrategyId},
    error::AppError,
};

#[derive(Default)]
pub struct SecretStore {
    sessions: DashMap<NearAccount, Arc<SecretString>>,
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretStore([redacted])")
    }
}

impl SecretStore {
    pub fn put_session(&self, account: NearAccount, token: SecretString) {
        self.sessions.insert(account, Arc::new(token));
    }

    pub fn session(&self, account: &NearAccount) -> Result<Arc<SecretString>, AppError> {
        self.sessions
            .get(account)
            .map(|entry| Arc::clone(entry.value()))
            .ok_or(AppError::Unauthorized)
    }

    pub fn remove_session(&self, account: &NearAccount) {
        self.sessions.remove(account);
    }
}

/// Derives epoch keys from a master key held only by the TEE. Raw epoch keys
/// are never persisted; the `(strategy_id, epoch)` pair is the derivation salt.
pub struct EpochKeyring {
    master: [u8; 32],
}

impl fmt::Debug for EpochKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EpochKeyring([redacted])")
    }
}

impl EpochKeyring {
    pub fn from_secret(secret: &SecretString) -> Result<Self, AppError> {
        let master: [u8; 32] = BASE64
            .decode(secret.expose_secret())
            .map_err(|_| AppError::Validation("epoch master key must be base64".into()))?
            .try_into()
            .map_err(|_| AppError::Validation("epoch master key must decode to 32 bytes".into()))?;
        Ok(Self { master })
    }

    pub fn key(&self, strategy_id: &StrategyId, epoch: u64) -> Result<EpochKey, AppError> {
        let hkdf = Hkdf::<Sha256>::new(Some(strategy_id.as_str().as_bytes()), &self.master);
        let mut bytes = [0_u8; 32];
        hkdf.expand(&epoch.to_be_bytes(), &mut bytes)
            .map_err(|_| AppError::Internal)?;
        Ok(EpochKey(bytes))
    }
}

impl Drop for EpochKeyring {
    fn drop(&mut self) {
        self.master.zeroize();
    }
}

pub struct EpochKey([u8; 32]);

impl fmt::Debug for EpochKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EpochKey([redacted])")
    }
}

impl Drop for EpochKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug)]
pub struct EncryptedSignal {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
}

pub fn encrypt_signal(key: &EpochKey, signal: &Signal) -> Result<EncryptedSignal, AppError> {
    let plaintext = Zeroizing::new(serde_json::to_vec(signal).map_err(|_| AppError::Internal)?);
    let mut nonce = [0_u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    let aad = signal_aad(&signal.strategy_id, signal.seq);
    let ciphertext = XChaCha20Poly1305::new((&key.0).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| AppError::Internal)?;
    Ok(EncryptedSignal { ciphertext, nonce })
}

pub fn decrypt_signal(
    key: &EpochKey,
    strategy_id: &StrategyId,
    seq: u64,
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Signal, AppError> {
    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| AppError::Validation("invalid signal nonce".into()))?;
    let aad = signal_aad(strategy_id, seq);
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new((&key.0).into())
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| AppError::Internal)?,
    );
    let signal: Signal = serde_json::from_slice(&plaintext).map_err(|_| AppError::Internal)?;
    if signal.strategy_id != *strategy_id || signal.seq != seq {
        return Err(AppError::Internal);
    }
    Ok(signal)
}

pub fn wrap_epoch_key(
    key: &EpochKey,
    agent_pubkey: &str,
    key_id: &KeyId,
) -> Result<String, AppError> {
    seal_to_agent(agent_pubkey, key_id.as_str().as_bytes(), &key.0)
}

/// Seals an arbitrary short payload to an X25519 public key. The envelope is
/// `ephemeral_public || nonce || ciphertext`, base64 encoded.
pub fn seal_to_agent(agent_pubkey: &str, aad: &[u8], plaintext: &[u8]) -> Result<String, AppError> {
    let public_bytes = decode_x25519_key(agent_pubkey)?;
    let recipient = PublicKey::from(public_bytes);
    let mut ephemeral_bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut ephemeral_bytes);
    let ephemeral = StaticSecret::from(ephemeral_bytes);
    ephemeral_bytes.zeroize();
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        return Err(AppError::Validation(
            "agent_pubkey is not contributory".into(),
        ));
    }
    let hkdf = Hkdf::<Sha256>::new(Some(aad), shared.as_bytes());
    let mut wrapping_key = [0_u8; 32];
    hkdf.expand(b"privatecopy/agent-seal/v1", &mut wrapping_key)
        .map_err(|_| AppError::Internal)?;

    let mut nonce = [0_u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new((&wrapping_key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AppError::Internal)?;
    wrapping_key.zeroize();

    let mut envelope = Vec::with_capacity(32 + 24 + ciphertext.len());
    envelope.extend_from_slice(ephemeral_public.as_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(envelope))
}

#[must_use]
pub fn encode_ciphertext(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

#[must_use]
pub fn encode_nonce(nonce: &[u8; 24]) -> String {
    BASE64.encode(nonce)
}

#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.ct_eq(right).into()
}

pub fn validate_agent_pubkey(value: &str) -> Result<(), AppError> {
    let public = PublicKey::from(decode_x25519_key(value)?);
    let probe = StaticSecret::from([1_u8; 32]);
    if probe.diffie_hellman(&public).was_contributory() {
        Ok(())
    } else {
        Err(AppError::Validation(
            "agent_pubkey is not contributory".into(),
        ))
    }
}

fn decode_x25519_key(value: &str) -> Result<[u8; 32], AppError> {
    let encoded = value
        .strip_prefix("x25519:")
        .ok_or_else(|| AppError::Validation("agent_pubkey must use x25519 encoding".into()))?;
    BASE64
        .decode(encoded)
        .map_err(|_| AppError::Validation("invalid agent_pubkey".into()))?
        .try_into()
        .map_err(|_| AppError::Validation("invalid agent_pubkey length".into()))
}

fn signal_aad(strategy_id: &StrategyId, seq: u64) -> String {
    format!("privatecopy/signal/v1/{strategy_id}/{seq}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::SignalAction;

    #[test]
    fn wraps_epoch_key_for_holder() {
        let recipient_secret = StaticSecret::from([7_u8; 32]);
        let recipient_public = PublicKey::from(&recipient_secret);
        let encoded = format!("x25519:{}", BASE64.encode(recipient_public.as_bytes()));
        let key = EpochKey([9_u8; 32]);
        let wrapped = wrap_epoch_key(&key, &encoded, &KeyId::new());
        assert!(wrapped.is_ok());
    }

    #[test]
    fn rejects_non_contributory_agent_keys() {
        let encoded = format!("x25519:{}", BASE64.encode([0_u8; 32]));
        assert!(validate_agent_pubkey(&encoded).is_err());
    }

    #[test]
    fn epoch_keys_are_stable_per_strategy_and_epoch() {
        let secret = SecretString::from(BASE64.encode([5_u8; 32]));
        let ring = EpochKeyring::from_secret(&secret).expect("valid keyring");
        let id = StrategyId::new();
        let first = ring.key(&id, 3).expect("derive").0;
        let second = ring.key(&id, 3).expect("derive").0;
        let next = ring.key(&id, 4).expect("derive").0;
        assert_eq!(first, second);
        assert_ne!(first, next);
    }

    #[test]
    fn signal_encryption_round_trips_with_bound_aad() {
        let strategy_id = StrategyId::new();
        let signal = Signal {
            strategy_id: strategy_id.clone(),
            seq: 11,
            ts: chrono::Utc::now(),
            action: SignalAction::Swap,
            sell_asset: "nep141:usdc".into(),
            buy_asset: "nep141:wrap.near".into(),
            size_bps_of_nav: 500,
            max_slippage_bps: 50,
            valid_until: chrono::Utc::now() + chrono::Duration::minutes(5),
            seq_salt: None,
        };
        let key = EpochKey([4_u8; 32]);
        let encrypted = encrypt_signal(&key, &signal).expect("encrypt signal");
        let decrypted = decrypt_signal(
            &key,
            &strategy_id,
            signal.seq,
            &encrypted.ciphertext,
            &encrypted.nonce,
        )
        .expect("decrypt signal");
        assert_eq!(decrypted.seq, signal.seq);
        assert_eq!(decrypted.sell_asset, signal.sell_asset);
    }
}
