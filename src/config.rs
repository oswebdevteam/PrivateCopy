use std::{env, net::SocketAddr, num::NonZeroU32, path::PathBuf, str::FromStr, time::Duration};

use anyhow::{Context, bail};
use secrecy::SecretString;

#[derive(Debug)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub public_origin: String,
    pub auth_recipient: String,
    pub database_url: String,
    pub redis_url: String,
    pub near_rpc_url: String,
    pub oneclick_url: String,
    pub oneclick_api_key: Option<SecretString>,
    pub jwt_secret: SecretString,
    pub jwt_ttl: Duration,
    pub quote_ttl: Duration,
    pub signal_ttl: Duration,
    pub epoch_interval: Duration,
    pub upstream_timeout: Duration,
    pub request_timeout: Duration,
    pub public_rate_limit: NonZeroU32,
    pub write_rate_limit: NonZeroU32,
    pub epoch_master_key: SecretString,
    pub agent_keys_file: Option<PathBuf>,
    pub attestor_account: Option<String>,
    pub key_registry_contract: Option<String>,
    pub strategy_market_contract: Option<String>,
    pub attestation_contract: Option<String>,
    pub delayed_tier: Duration,
    pub attestation_interval: Duration,
    pub min_track_record_days: i64,
    pub min_track_record_trades: i64,
    pub trade_settle_timeout: Duration,
    pub tee_quote: String,
    pub indexer_url: Option<String>,
    pub indexer_start_height: Option<i64>,
    pub indexer_lag_blocks: i64,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let jwt_secret = required("APP_JWT_SECRET")?;
        if jwt_secret.len() < 32 {
            bail!("APP_JWT_SECRET must contain at least 32 bytes");
        }

        let config = Self {
            bind_addr: parse("APP_BIND_ADDR", "0.0.0.0:8080")?,
            public_origin: value("APP_PUBLIC_ORIGIN", "http://localhost:3000"),
            auth_recipient: value("APP_AUTH_RECIPIENT", "localhost"),
            database_url: required("APP_DATABASE_URL")?,
            redis_url: required("APP_REDIS_URL")?,
            near_rpc_url: value("APP_NEAR_RPC_URL", "https://rpc.testnet.near.org"),
            oneclick_url: value("APP_ONECLICK_URL", "https://1click.chaindefuser.com"),
            oneclick_api_key: optional("APP_ONECLICK_API_KEY").map(SecretString::from),
            jwt_secret: SecretString::from(jwt_secret),
            jwt_ttl: Duration::from_secs(parse("APP_JWT_TTL_SECONDS", "900")?),
            quote_ttl: Duration::from_secs(parse("APP_QUOTE_TTL_SECONDS", "300")?),
            signal_ttl: Duration::from_secs(parse("APP_SIGNAL_TTL_SECONDS", "3600")?),
            epoch_interval: Duration::from_secs(parse("APP_EPOCH_INTERVAL_SECONDS", "3600")?),
            upstream_timeout: Duration::from_secs(parse("APP_UPSTREAM_TIMEOUT_SECONDS", "20")?),
            request_timeout: Duration::from_secs(parse("APP_REQUEST_TIMEOUT_SECONDS", "120")?),
            public_rate_limit: parse("APP_RATE_LIMIT_PUBLIC_PER_MINUTE", "60")?,
            write_rate_limit: parse("APP_RATE_LIMIT_WRITE_PER_MINUTE", "20")?,
            epoch_master_key: SecretString::from(required("APP_EPOCH_MASTER_KEY")?),
            agent_keys_file: optional("APP_AGENT_KEYS_FILE").map(PathBuf::from),
            attestor_account: optional("APP_ATTESTOR_ACCOUNT"),
            key_registry_contract: optional("APP_KEY_REGISTRY_CONTRACT"),
            strategy_market_contract: optional("APP_STRATEGY_MARKET_CONTRACT"),
            attestation_contract: optional("APP_ATTESTATION_CONTRACT"),
            delayed_tier: Duration::from_secs(parse("APP_DELAYED_TIER_SECONDS", "900")?),
            attestation_interval: Duration::from_secs(parse(
                "APP_ATTESTATION_INTERVAL_SECONDS",
                "3600",
            )?),
            min_track_record_days: parse("APP_MIN_TRACK_RECORD_DAYS", "14")?,
            min_track_record_trades: parse("APP_MIN_TRACK_RECORD_TRADES", "10")?,
            trade_settle_timeout: Duration::from_secs(parse(
                "APP_TRADE_SETTLE_TIMEOUT_SECONDS",
                "90",
            )?),
            tee_quote: value("APP_TEE_QUOTE", "unconfigured"),
            indexer_url: optional("APP_INDEXER_URL"),
            indexer_start_height: optional("APP_INDEXER_START_HEIGHT")
                .map(|value| value.parse().context("parse APP_INDEXER_START_HEIGHT"))
                .transpose()?,
            indexer_lag_blocks: parse("APP_INDEXER_LAG_BLOCKS", "2")?,
        };
        if config.epoch_interval.is_zero() {
            bail!("APP_EPOCH_INTERVAL_SECONDS must be greater than zero");
        }
        if config.quote_ttl.is_zero() {
            bail!("APP_QUOTE_TTL_SECONDS must be greater than zero");
        }
        if config.signal_ttl <= config.delayed_tier {
            bail!("APP_SIGNAL_TTL_SECONDS must exceed APP_DELAYED_TIER_SECONDS");
        }
        if config.attestation_interval.is_zero() {
            bail!("APP_ATTESTATION_INTERVAL_SECONDS must be greater than zero");
        }
        if config.min_track_record_days < 0 || config.min_track_record_trades < 0 {
            bail!("minimum track-record settings cannot be negative");
        }
        if config.indexer_lag_blocks < 0 {
            bail!("APP_INDEXER_LAG_BLOCKS cannot be negative");
        }
        if config.attestor_account.is_some() && config.tee_quote == "unconfigured" {
            bail!("APP_TEE_QUOTE is required when APP_ATTESTOR_ACCOUNT is configured");
        }
        Ok(config)
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    optional(name).with_context(|| format!("{name} is required"))
}

fn optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn value(name: &str, default: &str) -> String {
    optional(name).unwrap_or_else(|| default.into())
}

fn parse<T>(name: &str, default: &str) -> anyhow::Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    value(name, default)
        .parse()
        .with_context(|| format!("parse {name}"))
}
