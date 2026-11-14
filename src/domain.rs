use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use near_account_id::AccountId;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use ulid::Ulid;

use crate::error::AppError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NearAccount(AccountId);

impl NearAccount {
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl FromStr for NearAccount {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .parse()
            .map(Self)
            .map_err(|_| AppError::Validation("invalid NEAR account id".into()))
    }
}

impl<'de> Deserialize<'de> for NearAccount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

impl Serialize for NearAccount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl fmt::Display for NearAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

macro_rules! string_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new() -> Self {
                Self(format!(concat!($prefix, "{}"), Ulid::new()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn parse(value: String) -> Result<Self, AppError> {
                let suffix = value.strip_prefix($prefix).ok_or_else(|| {
                    AppError::Validation(concat!("invalid ", stringify!($name)).into())
                })?;
                suffix.parse::<Ulid>().map_err(|_| {
                    AppError::Validation(concat!("invalid ", stringify!($name)).into())
                })?;
                Ok(Self(value))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

string_id!(StrategyId, "st_");

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    #[must_use]
    pub fn new() -> Self {
        Self(format!("key_{}", Ulid::new()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(value: String) -> Result<Self, AppError> {
        let valid = !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':'));
        if valid {
            Ok(Self(value))
        } else {
            Err(AppError::Validation("invalid KeyId".into()))
        }
    }
}

impl Default for KeyId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Amount(String);

impl Amount {
    pub fn parse(value: &str) -> Result<Self, AppError> {
        let parsed = value
            .parse::<u128>()
            .map_err(|_| AppError::Validation("amount must be an integer string".into()))?;
        if parsed == 0 {
            return Err(AppError::Validation(
                "amount must be greater than zero".into(),
            ));
        }
        Ok(Self(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn as_u128(&self) -> u128 {
        self.0
            .parse()
            .unwrap_or_else(|_| unreachable!("Amount validates its digits during deserialization"))
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let parsed = value
            .parse::<u128>()
            .map_err(|_| de::Error::custom("amount must be an integer string"))?;
        if parsed == 0 {
            return Err(de::Error::custom("amount must be greater than zero"));
        }
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTier {
    Live,
    Delayed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKeyStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyStatus {
    Active,
    Paused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyState {
    Received,
    Sized,
    Quoted,
    Funded,
    Settled,
    Skipped,
    Refunded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub strategy_id: StrategyId,
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub action: SignalAction,
    pub sell_asset: String,
    pub buy_asset: String,
    pub size_bps_of_nav: u16,
    pub max_slippage_bps: u16,
    pub valid_until: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq_salt: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalAction {
    Swap,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignalFrame {
    #[serde(rename = "type")]
    pub frame_type: &'static str,
    pub strategy_id: StrategyId,
    pub epoch: u64,
    pub seq: u64,
    pub wrapped_epoch_key: String,
    pub ciphertext: String,
    pub nonce: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_accepts_contract_safe_identifiers() {
        let key = KeyId::parse("registry:42-key_A".into()).unwrap_or_default();
        assert_eq!(key.as_str(), "registry:42-key_A");
    }

    #[test]
    fn key_id_rejects_unsafe_identifiers() {
        assert!(KeyId::parse(String::new()).is_err());
        assert!(KeyId::parse("key/with/slashes".into()).is_err());
        assert!(KeyId::parse("x".repeat(129)).is_err());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedAccount(pub NearAccount);
