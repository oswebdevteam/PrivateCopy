use std::collections::HashMap;

use rust_decimal::{Decimal, prelude::ToPrimitive};

use crate::{error::AppError, oneclick::TokenResponse, state::AppState};

#[derive(Debug, Clone)]
pub struct TokenBook {
    tokens: HashMap<String, TokenResponse>,
}

impl TokenBook {
    pub async fn load(state: &AppState) -> Result<Self, AppError> {
        let tokens = state.oneclick.tokens().await?;
        Ok(Self {
            tokens: tokens
                .into_iter()
                .map(|token| (token.asset_id.clone(), token))
                .collect(),
        })
    }

    #[must_use]
    pub fn supports(&self, asset: &str) -> bool {
        self.tokens.contains_key(asset)
    }

    pub fn token(&self, asset: &str) -> Result<&TokenResponse, AppError> {
        self.tokens.get(asset).ok_or_else(|| {
            AppError::Validation("asset is not supported by the price source".into())
        })
    }

    pub fn nav_usd_micros(
        &self,
        balances: &[crate::oneclick::BalanceEntry],
    ) -> Result<i64, AppError> {
        balances
            .iter()
            .try_fold(Decimal::ZERO, |total, balance| {
                let atomic = parse_atomic(&balance.available)?;
                if atomic.is_zero() {
                    return Ok(total);
                }
                let token = self.token(&balance.token_id)?;
                let value = decimal_from_atomic(atomic, token.decimals)?
                    .checked_mul(token.price)
                    .ok_or(AppError::Internal)?;
                total.checked_add(value).ok_or(AppError::Internal)
            })
            .and_then(usd_to_micros)
    }

    pub fn amount_usd_micros(&self, asset: &str, atomic: &str) -> Result<i64, AppError> {
        let token = self.token(asset)?;
        let value = decimal_from_atomic(parse_atomic(atomic)?, token.decimals)?
            .checked_mul(token.price)
            .ok_or(AppError::Internal)?;
        usd_to_micros(value)
    }

    #[must_use]
    pub fn balance(&self, balances: &[crate::oneclick::BalanceEntry], asset: &str) -> u128 {
        balances
            .iter()
            .find(|balance| balance.token_id == asset)
            .and_then(|balance| balance.available.parse().ok())
            .unwrap_or_default()
    }

    pub fn amount_for_usd_micros(&self, asset: &str, usd_micros: i64) -> Result<u128, AppError> {
        let token = self.token(asset)?;
        if usd_micros <= 0 || token.price <= Decimal::ZERO {
            return Ok(0);
        }
        let usd = Decimal::from(usd_micros) / Decimal::from(1_000_000_u64);
        let units = usd
            .checked_div(token.price)
            .and_then(|value| value.checked_mul(pow10(token.decimals)?))
            .ok_or(AppError::Internal)?
            .trunc();
        units
            .to_u128()
            .ok_or_else(|| AppError::Validation("asset amount is too large".into()))
    }

    pub fn copy_slippage_bps(
        &self,
        asset_in: &str,
        asset_out: &str,
        trader_in: &str,
        trader_out: &str,
        follower_in: &str,
        follower_out: &str,
    ) -> Result<i32, AppError> {
        let trader_in =
            decimal_from_atomic(parse_atomic(trader_in)?, self.token(asset_in)?.decimals)?;
        let trader_out =
            decimal_from_atomic(parse_atomic(trader_out)?, self.token(asset_out)?.decimals)?;
        let follower_in =
            decimal_from_atomic(parse_atomic(follower_in)?, self.token(asset_in)?.decimals)?;
        let follower_out =
            decimal_from_atomic(parse_atomic(follower_out)?, self.token(asset_out)?.decimals)?;
        if trader_in.is_zero() || trader_out.is_zero() || follower_out.is_zero() {
            return Ok(0);
        }
        let trader_price = trader_in
            .checked_div(trader_out)
            .ok_or(AppError::Internal)?;
        let follower_price = follower_in
            .checked_div(follower_out)
            .ok_or(AppError::Internal)?;
        let difference = follower_price
            .checked_div(trader_price)
            .and_then(|ratio| ratio.checked_sub(Decimal::ONE))
            .and_then(|value| value.checked_mul(Decimal::from(10_000_u32)))
            .ok_or(AppError::Internal)?;
        difference
            .round()
            .to_i32()
            .ok_or_else(|| AppError::Validation("slippage is out of range".into()))
    }
}

fn parse_atomic(value: &str) -> Result<Decimal, AppError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AppError::Validation("balance is not an integer".into()));
    }
    Decimal::from_str_exact(value).map_err(|_| AppError::Validation("invalid balance".into()))
}

fn pow10(decimals: u32) -> Option<Decimal> {
    (0..decimals).try_fold(Decimal::ONE, |value, _| {
        value.checked_mul(Decimal::from(10_u64))
    })
}

fn decimal_from_atomic(atomic: Decimal, decimals: u32) -> Result<Decimal, AppError> {
    atomic
        .checked_div(pow10(decimals).ok_or(AppError::Internal)?)
        .ok_or(AppError::Internal)
}

fn usd_to_micros(value: Decimal) -> Result<i64, AppError> {
    value
        .checked_mul(Decimal::from(1_000_000_u64))
        .and_then(|micros| micros.round().to_i64())
        .ok_or_else(|| AppError::Validation("portfolio value is out of range".into()))
}
