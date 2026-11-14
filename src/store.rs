use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use sqlx::{PgPool, Row, postgres::PgRow};

use crate::{
    domain::{AccessTier, CopyState, KeyId, NearAccount, StrategyId},
    error::AppError,
};

#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_auth_nonce(
        &self,
        account: &NearAccount,
        nonce_hash: &[u8; 32],
        message: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO auth_nonces (nonce_hash, near_account, message, expires_at) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(nonce_hash.as_slice())
        .bind(account.as_str())
        .bind(message)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn auth_nonce_message(
        &self,
        account: &NearAccount,
        nonce_hash: &[u8; 32],
    ) -> Result<Option<String>, AppError> {
        sqlx::query_scalar(
            "SELECT message FROM auth_nonces \
             WHERE nonce_hash = $1 AND near_account = $2 AND consumed_at IS NULL \
             AND expires_at > now()",
        )
        .bind(nonce_hash.as_slice())
        .bind(account.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::from)
    }

    pub async fn consume_auth_nonce(
        &self,
        account: &NearAccount,
        nonce_hash: &[u8; 32],
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            "UPDATE auth_nonces SET consumed_at = now() \
             WHERE nonce_hash = $1 AND near_account = $2 AND consumed_at IS NULL \
             AND expires_at > now()",
        )
        .bind(nonce_hash.as_slice())
        .bind(account.as_str())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn upsert_user(&self, account: &NearAccount) -> Result<(), AppError> {
        sqlx::query("INSERT INTO users (near_account) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(account.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn prune_expired_records(&self) -> Result<(), AppError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM auth_nonces WHERE expires_at < now()")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM idempotency_keys WHERE expires_at < now()")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "DELETE FROM signals AS sig USING strategies AS st \
             WHERE sig.strategy_id = st.strategy_id \
             AND sig.created_at < now() \
                 - make_interval(secs => st.key_duration_seconds::double precision) \
                 - interval '30 days'",
        )
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn idempotency_response(
        &self,
        account: &NearAccount,
        route: &str,
        key: &str,
    ) -> Result<Option<serde_json::Value>, AppError> {
        sqlx::query_scalar(
            "SELECT response FROM idempotency_keys \
             WHERE near_account = $1 AND route = $2 AND idempotency_key = $3 \
             AND expires_at > now()",
        )
        .bind(account.as_str())
        .bind(route)
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::from)
    }

    pub async fn claim_idempotency_key(
        &self,
        account: &NearAccount,
        route: &str,
        key: &str,
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            "INSERT INTO idempotency_keys \
             (near_account, route, idempotency_key, expires_at) \
             VALUES ($1, $2, $3, now() + interval '24 hours') \
             ON CONFLICT (near_account, route, idempotency_key) DO UPDATE \
             SET response = NULL, expires_at = EXCLUDED.expires_at \
             WHERE idempotency_keys.expires_at <= now()",
        )
        .bind(account.as_str())
        .bind(route)
        .bind(key)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn complete_idempotency_key(
        &self,
        account: &NearAccount,
        route: &str,
        key: &str,
        response: &serde_json::Value,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE idempotency_keys SET response = $4 \
             WHERE near_account = $1 AND route = $2 AND idempotency_key = $3",
        )
        .bind(account.as_str())
        .bind(route)
        .bind(key)
        .bind(response)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn release_idempotency_key(
        &self,
        account: &NearAccount,
        route: &str,
        key: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "DELETE FROM idempotency_keys \
             WHERE near_account = $1 AND route = $2 AND idempotency_key = $3 AND response IS NULL",
        )
        .bind(account.as_str())
        .bind(route)
        .bind(key)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn create_strategy(&self, strategy: &NewStrategy<'_>) -> Result<(), AppError> {
        let duration = i64::try_from(strategy.key_duration_seconds)
            .map_err(|_| AppError::Validation("key duration is too large".into()))?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO strategies \
             (strategy_id, owner, name, vault_account, assets, live_price, delayed_price, \
              key_duration_seconds, max_followers) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(strategy.strategy_id.as_str())
        .bind(strategy.owner.as_str())
        .bind(strategy.name)
        .bind(strategy.vault_account.as_str())
        .bind(strategy.assets)
        .bind(strategy.live_price)
        .bind(strategy.delayed_price)
        .bind(duration)
        .bind(strategy.max_followers)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("INSERT INTO epochs (strategy_id, epoch_no, starts_at) VALUES ($1, 0, now())")
            .bind(strategy.strategy_id.as_str())
            .execute(&mut *transaction)
            .await?;
        sqlx::query("INSERT INTO signal_counters (strategy_id, next_seq) VALUES ($1, 1)")
            .bind(strategy.strategy_id.as_str())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn strategy(&self, id: &StrategyId) -> Result<Option<StrategyView>, AppError> {
        sqlx::query(
            "SELECT s.strategy_id, s.owner, s.name, s.vault_account, s.assets, s.live_price, \
                    s.delayed_price, s.key_duration_seconds, s.max_followers, s.status::text, \
                    count(k.key_id) FILTER (WHERE k.status = 'active' AND k.expires_at > now()) AS follower_count \
             FROM strategies s LEFT JOIN access_keys k ON k.strategy_id = s.strategy_id \
             WHERE s.strategy_id = $1 GROUP BY s.strategy_id",
        )
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await?
        .map(|row| strategy_from_row(&row))
        .transpose()
    }

    pub async fn strategy_for_update(
        &self,
        id: &StrategyId,
        owner: &NearAccount,
    ) -> Result<StrategyView, AppError> {
        self.strategy(id)
            .await?
            .filter(|strategy| strategy.owner == owner.as_str())
            .ok_or(AppError::NotFound)
    }

    pub async fn active_strategies(&self) -> Result<Vec<StrategyView>, AppError> {
        sqlx::query(
            "SELECT s.strategy_id, s.owner, s.name, s.vault_account, s.assets, s.live_price, \
                    s.delayed_price, s.key_duration_seconds, s.max_followers, s.status::text, \
                    count(k.key_id) FILTER (WHERE k.status = 'active' AND k.expires_at > now()) AS follower_count \
             FROM strategies s LEFT JOIN access_keys k ON k.strategy_id = s.strategy_id \
             WHERE s.status = 'active' GROUP BY s.strategy_id",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| strategy_from_row(&row))
        .collect()
    }

    pub async fn active_keys_for_strategy(
        &self,
        strategy_id: &StrategyId,
    ) -> Result<Vec<AccessKeyView>, AppError> {
        sqlx::query(
            "SELECT key_id, strategy_id, holder, agent_pubkey, tier::text, expires_at, status::text \
             FROM access_keys WHERE strategy_id = $1 AND status = 'active' AND expires_at > now() \
             ORDER BY created_at",
        )
        .bind(strategy_id.as_str())
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| access_key_from_row(&row))
        .collect()
    }

    pub async fn active_key_for_holder(
        &self,
        key_id: &KeyId,
        holder: &NearAccount,
    ) -> Result<AccessKeyView, AppError> {
        self.access_key(key_id, holder)
            .await?
            .filter(AccessKeyView::is_active)
            .ok_or(AppError::Forbidden)
    }

    pub async fn revoke_key(
        &self,
        key_id: &KeyId,
        owner: &NearAccount,
    ) -> Result<Option<StrategyId>, AppError> {
        let strategy_id: Option<String> = sqlx::query_scalar(
            "UPDATE access_keys k SET status = 'revoked' \
             FROM strategies s \
             WHERE k.strategy_id = s.strategy_id AND k.key_id = $1 AND s.owner = $2 \
             AND k.status <> 'revoked' RETURNING k.strategy_id",
        )
        .bind(key_id.as_str())
        .bind(owner.as_str())
        .fetch_optional(&self.pool)
        .await?;
        strategy_id.map(StrategyId::parse).transpose()
    }

    pub async fn next_epoch(&self, strategy_id: &StrategyId) -> Result<u64, AppError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(strategy_id.as_str())
            .execute(&mut *transaction)
            .await?;
        let epoch: i64 = sqlx::query_scalar(
            "INSERT INTO epochs (strategy_id, epoch_no, starts_at) \
             SELECT $1, COALESCE(max(epoch_no), -1) + 1, now() FROM epochs WHERE strategy_id = $1 \
             RETURNING epoch_no",
        )
        .bind(strategy_id.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        u64::try_from(epoch).map_err(|_| AppError::Internal)
    }

    pub async fn next_signal_seq(&self, strategy_id: &StrategyId) -> Result<u64, AppError> {
        let value: i64 = sqlx::query_scalar(
            "INSERT INTO signal_counters (strategy_id, next_seq) VALUES ($1, 2) \
             ON CONFLICT (strategy_id) DO UPDATE \
             SET next_seq = signal_counters.next_seq + 1 \
             RETURNING next_seq - 1",
        )
        .bind(strategy_id.as_str())
        .fetch_one(&self.pool)
        .await?;
        u64::try_from(value).map_err(|_| AppError::Internal)
    }

    pub async fn ensure_epoch(
        &self,
        strategy_id: &StrategyId,
        duration_seconds: i64,
    ) -> Result<u64, AppError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(strategy_id.as_str())
            .execute(&mut *transaction)
            .await?;
        let current: Option<(i64, DateTime<Utc>)> = sqlx::query_as(
            "SELECT epoch_no, starts_at FROM epochs WHERE strategy_id = $1 \
             ORDER BY epoch_no DESC LIMIT 1",
        )
        .bind(strategy_id.as_str())
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some((epoch, starts_at)) = current {
            let expires_at = starts_at + chrono::Duration::seconds(duration_seconds);
            if expires_at > Utc::now() {
                transaction.commit().await?;
                return u64::try_from(epoch).map_err(|_| AppError::Internal);
            }
        }
        let next: i64 = sqlx::query_scalar(
            "INSERT INTO epochs (strategy_id, epoch_no, starts_at) \
             SELECT $1, COALESCE(max(epoch_no), -1) + 1, now() FROM epochs WHERE strategy_id = $1 \
             RETURNING epoch_no",
        )
        .bind(strategy_id.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        u64::try_from(next).map_err(|_| AppError::Internal)
    }

    pub async fn commit_fill_and_signal(
        &self,
        fill: &NewFill<'_>,
        signal: &StoredSignal<'_>,
    ) -> Result<(), AppError> {
        let seq = i64::try_from(fill.seq).map_err(|_| AppError::Internal)?;
        let epoch = i64::try_from(signal.epoch).map_err(|_| AppError::Internal)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO fills \
             (strategy_id, seq, asset_in, asset_out, amount_in, amount_out, filled_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(fill.strategy_id.as_str())
        .bind(seq)
        .bind(fill.asset_in)
        .bind(fill.asset_out)
        .bind(fill.amount_in)
        .bind(fill.amount_out)
        .bind(fill.filled_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO signals \
             (strategy_id, epoch_no, seq, ciphertext, nonce, valid_until) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(signal.strategy_id.as_str())
        .bind(epoch)
        .bind(seq)
        .bind(signal.ciphertext)
        .bind(signal.nonce.as_slice())
        .bind(signal.valid_until)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn fill(
        &self,
        strategy_id: &StrategyId,
        seq: u64,
    ) -> Result<Option<FillRow>, AppError> {
        let seq = i64::try_from(seq).map_err(|_| AppError::Internal)?;
        sqlx::query(
            "SELECT strategy_id, seq, asset_in, asset_out, amount_in, amount_out, filled_at \
             FROM fills WHERE strategy_id = $1 AND seq = $2",
        )
        .bind(strategy_id.as_str())
        .bind(seq)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| {
            Ok(FillRow {
                strategy_id: StrategyId::parse(row.try_get("strategy_id")?)?,
                seq: u64::try_from(row.try_get::<i64, _>("seq")?)
                    .map_err(|_| AppError::Internal)?,
                asset_in: row.try_get("asset_in")?,
                asset_out: row.try_get("asset_out")?,
                amount_in: row.try_get("amount_in")?,
                amount_out: row.try_get("amount_out")?,
                filled_at: row.try_get("filled_at")?,
            })
        })
        .transpose()
    }

    pub async fn record_fill(&self, fill: &NewFill<'_>) -> Result<(), AppError> {
        let seq = i64::try_from(fill.seq).map_err(|_| AppError::Internal)?;
        sqlx::query(
            "INSERT INTO fills \
             (strategy_id, seq, asset_in, asset_out, amount_in, amount_out, filled_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (strategy_id, seq) DO NOTHING",
        )
        .bind(fill.strategy_id.as_str())
        .bind(seq)
        .bind(fill.asset_in)
        .bind(fill.asset_out)
        .bind(fill.amount_in)
        .bind(fill.amount_out)
        .bind(fill.filled_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn signals_after(
        &self,
        strategy_id: &StrategyId,
        after: u64,
        limit: i64,
    ) -> Result<Vec<SignalRow>, AppError> {
        let after = i64::try_from(after).map_err(|_| AppError::Internal)?;
        sqlx::query(
            "SELECT strategy_id, epoch_no, seq, ciphertext, nonce, valid_until, created_at \
             FROM signals WHERE strategy_id = $1 AND seq > $2 ORDER BY seq LIMIT $3",
        )
        .bind(strategy_id.as_str())
        .bind(after)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| signal_from_row(&row))
        .collect()
    }

    pub async fn attestation_history(
        &self,
        strategy_id: &StrategyId,
        limit: i64,
    ) -> Result<Vec<AttestationView>, AppError> {
        sqlx::query(
            "SELECT strategy_id, window, period_start, period_end, twr_bps, drawdown_bps, \
                    nav_bucket, trade_count_bucket, encode(snapshot_root, 'hex') AS snapshot_root, \
                    tee_quote, signature, tx_hash, created_at \
             FROM attestations WHERE strategy_id = $1 ORDER BY period_end DESC LIMIT $2",
        )
        .bind(strategy_id.as_str())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| attestation_from_row(&row))
        .collect()
    }

    pub async fn insert_snapshot(&self, snapshot: &NewSnapshot<'_>) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO snapshots \
             (strategy_id, captured_at, value_usd_micros, external_flow_usd_micros, snapshot_hash) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(snapshot.strategy_id.as_str())
        .bind(snapshot.captured_at)
        .bind(snapshot.value_usd_micros)
        .bind(snapshot.external_flow_usd_micros)
        .bind(snapshot.snapshot_hash.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn snapshots_between(
        &self,
        strategy_id: &StrategyId,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<SnapshotRow>, AppError> {
        sqlx::query(
            "SELECT strategy_id, captured_at, value_usd_micros, external_flow_usd_micros, snapshot_hash \
             FROM snapshots WHERE strategy_id = $1 AND captured_at > $2 AND captured_at <= $3 \
             ORDER BY captured_at",
        )
        .bind(strategy_id.as_str())
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| snapshot_from_row(&row))
        .collect()
    }

    pub async fn snapshot_before(
        &self,
        strategy_id: &StrategyId,
        at: DateTime<Utc>,
    ) -> Result<Option<SnapshotRow>, AppError> {
        sqlx::query(
            "SELECT strategy_id, captured_at, value_usd_micros, external_flow_usd_micros, snapshot_hash \
             FROM snapshots WHERE strategy_id = $1 AND captured_at <= $2 \
             ORDER BY captured_at DESC LIMIT 1",
        )
        .bind(strategy_id.as_str())
        .bind(at)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| snapshot_from_row(&row))
        .transpose()
    }

    pub async fn fill_count_since(
        &self,
        strategy_id: &StrategyId,
        from: DateTime<Utc>,
    ) -> Result<i64, AppError> {
        sqlx::query_scalar("SELECT count(*) FROM fills WHERE strategy_id = $1 AND filled_at >= $2")
            .bind(strategy_id.as_str())
            .bind(from)
            .fetch_one(&self.pool)
            .await
            .map_err(AppError::from)
    }

    pub async fn insert_attestation(
        &self,
        attestation: &NewAttestation<'_>,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO attestations \
             (strategy_id, window, period_start, period_end, twr_bps, drawdown_bps, \
              nav_bucket, trade_count_bucket, snapshot_root, tee_quote, signature, tx_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (strategy_id, window, period_end) DO NOTHING",
        )
        .bind(attestation.strategy_id.as_str())
        .bind(attestation.window)
        .bind(attestation.period_start)
        .bind(attestation.period_end)
        .bind(attestation.twr_bps)
        .bind(attestation.drawdown_bps)
        .bind(attestation.nav_bucket)
        .bind(attestation.trade_count_bucket)
        .bind(attestation.snapshot_root.as_slice())
        .bind(attestation.tee_quote)
        .bind(attestation.signature)
        .bind(attestation.tx_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn fill_count(&self, strategy_id: &StrategyId) -> Result<i64, AppError> {
        sqlx::query_scalar("SELECT count(*) FROM fills WHERE strategy_id = $1")
            .bind(strategy_id.as_str())
            .fetch_one(&self.pool)
            .await
            .map_err(AppError::from)
    }

    pub async fn first_fill_at(
        &self,
        strategy_id: &StrategyId,
    ) -> Result<Option<DateTime<Utc>>, AppError> {
        sqlx::query_scalar("SELECT min(filled_at) FROM fills WHERE strategy_id = $1")
            .bind(strategy_id.as_str())
            .fetch_one(&self.pool)
            .await
            .map_err(AppError::from)
    }

    pub async fn follower_settings(
        &self,
        key_id: &KeyId,
    ) -> Result<Option<FollowerSettings>, AppError> {
        sqlx::query(
            "SELECT multiplier_bps, trade_cap_bps, daily_loss_bps, drawdown_stop_bps, \
                    max_slippage_bps, copy_vault_account, paused \
             FROM follower_settings WHERE key_id = $1",
        )
        .bind(key_id.as_str())
        .fetch_optional(&self.pool)
        .await?
        .map(|row| {
            let copy_vault_account = row.try_get::<String, _>("copy_vault_account")?;
            Ok(FollowerSettings {
                multiplier_bps: row.try_get("multiplier_bps")?,
                trade_cap_bps: row.try_get("trade_cap_bps")?,
                daily_loss_bps: row.try_get("daily_loss_bps")?,
                drawdown_stop_bps: row.try_get("drawdown_stop_bps")?,
                max_slippage_bps: row.try_get("max_slippage_bps")?,
                copy_vault_account: copy_vault_account.parse()?,
                paused: row.try_get("paused")?,
            })
        })
        .transpose()
    }

    pub async fn pause_copy(&self, key_id: &KeyId) -> Result<(), AppError> {
        let result = sqlx::query(
            "UPDATE follower_settings SET paused = true, updated_at = now() WHERE key_id = $1",
        )
        .bind(key_id.as_str())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    pub async fn create_copy_order(
        &self,
        key_id: &KeyId,
        strategy_id: &StrategyId,
        seq: u64,
        state: CopyState,
        skip_reason: Option<&str>,
    ) -> Result<bool, AppError> {
        let seq = i64::try_from(seq).map_err(|_| AppError::Internal)?;
        let result = sqlx::query(
            "INSERT INTO copy_orders (key_id, strategy_id, seq, state, skip_reason) \
             VALUES ($1, $2, $3, $4::copy_state, $5) ON CONFLICT DO NOTHING",
        )
        .bind(key_id.as_str())
        .bind(strategy_id.as_str())
        .bind(seq)
        .bind(copy_state_name(state))
        .bind(skip_reason)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn advance_copy_order(&self, order: &CopyOrderUpdate<'_>) -> Result<(), AppError> {
        let seq = i64::try_from(order.seq).map_err(|_| AppError::Internal)?;
        sqlx::query(
            "UPDATE copy_orders SET state = $4::copy_state, \
             skip_reason = COALESCE($5, skip_reason), \
             quote_id = COALESCE($6, quote_id), \
             status_ref = COALESCE($7, status_ref), \
             amount_in = COALESCE($8, amount_in), \
             copy_slippage_bps = COALESCE($9, copy_slippage_bps), \
             updated_at = now() \
             WHERE key_id = $1 AND strategy_id = $2 AND seq = $3",
        )
        .bind(order.key_id.as_str())
        .bind(order.strategy_id.as_str())
        .bind(seq)
        .bind(copy_state_name(order.state))
        .bind(order.skip_reason)
        .bind(order.quote_id)
        .bind(order.status_ref)
        .bind(order.amount_in)
        .bind(order.copy_slippage_bps)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn vault_state(&self, key_id: &KeyId) -> Result<Option<VaultStateRow>, AppError> {
        sqlx::query(
            "SELECT peak_nav_usd_micros, day_start_nav_usd_micros, day \
             FROM follower_vault_state WHERE key_id = $1",
        )
        .bind(key_id.as_str())
        .fetch_optional(&self.pool)
        .await?
        .map(|row| {
            Ok(VaultStateRow {
                peak_nav_usd_micros: row.try_get("peak_nav_usd_micros")?,
                day_start_nav_usd_micros: row.try_get("day_start_nav_usd_micros")?,
                day: row.try_get("day")?,
            })
        })
        .transpose()
    }

    pub async fn save_vault_state(
        &self,
        key_id: &KeyId,
        state: &VaultStateRow,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO follower_vault_state \
             (key_id, peak_nav_usd_micros, day_start_nav_usd_micros, day) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (key_id) DO UPDATE SET peak_nav_usd_micros = EXCLUDED.peak_nav_usd_micros, \
             day_start_nav_usd_micros = EXCLUDED.day_start_nav_usd_micros, day = EXCLUDED.day, \
             updated_at = now()",
        )
        .bind(key_id.as_str())
        .bind(state.peak_nav_usd_micros)
        .bind(state.day_start_nav_usd_micros)
        .bind(state.day)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn leaderboard(
        &self,
        window: &str,
        asset: Option<&str>,
    ) -> Result<Vec<LeaderboardEntry>, AppError> {
        sqlx::query(
            "SELECT s.strategy_id, s.name, s.assets, \
                    a.twr_bps, a.drawdown_bps, a.nav_bucket, a.trade_count_bucket, \
                    a.period_end, encode(a.snapshot_root, 'hex') AS snapshot_root, \
                    count(k.key_id) FILTER (WHERE k.status = 'active' AND k.expires_at > now()) AS follower_count \
             FROM strategies s \
             JOIN LATERAL (SELECT * FROM attestations a WHERE a.strategy_id = s.strategy_id \
                           AND a.window = $1 ORDER BY a.period_end DESC LIMIT 1) a ON true \
             LEFT JOIN access_keys k ON k.strategy_id = s.strategy_id \
             WHERE s.status = 'active' AND ($2::text IS NULL OR $2 = ANY(s.assets)) \
             GROUP BY s.strategy_id, a.twr_bps, a.drawdown_bps, a.nav_bucket, \
                      a.trade_count_bucket, a.period_end, a.snapshot_root \
             ORDER BY (a.twr_bps::numeric / GREATEST(a.drawdown_bps, 1)) DESC",
        )
        .bind(window)
        .bind(asset)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| leaderboard_from_row(&row))
        .collect()
    }

    pub async fn keys_for_account(
        &self,
        account: &NearAccount,
    ) -> Result<Vec<AccessKeyView>, AppError> {
        sqlx::query(
            "SELECT k.key_id, k.strategy_id, k.holder, k.agent_pubkey, k.tier::text, \
                    k.expires_at, k.status::text \
             FROM access_keys k JOIN strategies s ON s.strategy_id = k.strategy_id \
             WHERE k.holder = $1 OR s.owner = $1 ORDER BY k.created_at DESC",
        )
        .bind(account.as_str())
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| access_key_from_row(&row))
        .collect()
    }

    pub async fn access_key(
        &self,
        key_id: &KeyId,
        holder: &NearAccount,
    ) -> Result<Option<AccessKeyView>, AppError> {
        sqlx::query(
            "SELECT key_id, strategy_id, holder, agent_pubkey, tier::text, expires_at, status::text \
             FROM access_keys WHERE key_id = $1 AND holder = $2",
        )
        .bind(key_id.as_str())
        .bind(holder.as_str())
        .fetch_optional(&self.pool)
        .await?
        .map(|row| access_key_from_row(&row))
        .transpose()
    }

    pub async fn save_settings(
        &self,
        key_id: &KeyId,
        settings: &FollowerSettings,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO follower_settings \
             (key_id, copy_vault_account, multiplier_bps, trade_cap_bps, daily_loss_bps, drawdown_stop_bps, max_slippage_bps, paused) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (key_id) DO UPDATE SET copy_vault_account = EXCLUDED.copy_vault_account, \
             multiplier_bps = EXCLUDED.multiplier_bps, \
             trade_cap_bps = EXCLUDED.trade_cap_bps, daily_loss_bps = EXCLUDED.daily_loss_bps, \
             drawdown_stop_bps = EXCLUDED.drawdown_stop_bps, max_slippage_bps = EXCLUDED.max_slippage_bps, \
             paused = EXCLUDED.paused, updated_at = now()",
        )
        .bind(key_id.as_str())
        .bind(settings.copy_vault_account.as_str())
        .bind(settings.multiplier_bps)
        .bind(settings.trade_cap_bps)
        .bind(settings.daily_loss_bps)
        .bind(settings.drawdown_stop_bps)
        .bind(settings.max_slippage_bps)
        .bind(settings.paused)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_copy_paused(&self, key_id: &KeyId, paused: bool) -> Result<(), AppError> {
        let result = sqlx::query(
            "UPDATE follower_settings SET paused = $2, updated_at = now() WHERE key_id = $1",
        )
        .bind(key_id.as_str())
        .bind(paused)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    pub async fn copy_orders(
        &self,
        key_id: &KeyId,
        holder: &NearAccount,
    ) -> Result<Vec<CopyOrderView>, AppError> {
        sqlx::query(
            "SELECT o.key_id, o.strategy_id, o.seq, o.state::text, o.skip_reason, o.quote_id, \
                    o.status_ref, o.amount_in, o.copy_slippage_bps, o.created_at, o.updated_at \
             FROM copy_orders o JOIN access_keys k ON k.key_id = o.key_id \
             WHERE o.key_id = $1 AND k.holder = $2 ORDER BY o.seq DESC",
        )
        .bind(key_id.as_str())
        .bind(holder.as_str())
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| copy_order_from_row(&row))
        .collect()
    }

    pub async fn current_epoch(&self, strategy_id: &StrategyId) -> Result<u64, AppError> {
        let value: Option<i64> =
            sqlx::query_scalar("SELECT max(epoch_no) FROM epochs WHERE strategy_id = $1")
                .bind(strategy_id.as_str())
                .fetch_one(&self.pool)
                .await?;
        value
            .and_then(|epoch| u64::try_from(epoch).ok())
            .ok_or(AppError::NotFound)
    }

    pub async fn insert_signal(&self, signal: &StoredSignal<'_>) -> Result<(), AppError> {
        let epoch = i64::try_from(signal.epoch).map_err(|_| AppError::Internal)?;
        let seq = i64::try_from(signal.seq).map_err(|_| AppError::Internal)?;
        sqlx::query(
            "INSERT INTO signals \
             (strategy_id, epoch_no, seq, ciphertext, nonce, valid_until) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(signal.strategy_id.as_str())
        .bind(epoch)
        .bind(seq)
        .bind(signal.ciphertext)
        .bind(signal.nonce.as_slice())
        .bind(signal.valid_until)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn signal(
        &self,
        strategy_id: &StrategyId,
        seq: u64,
    ) -> Result<Option<SignalRow>, AppError> {
        let seq = i64::try_from(seq).map_err(|_| AppError::Internal)?;
        sqlx::query(
            "SELECT strategy_id, epoch_no, seq, ciphertext, nonce, valid_until, created_at \
             FROM signals WHERE strategy_id = $1 AND seq = $2",
        )
        .bind(strategy_id.as_str())
        .bind(seq)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| signal_from_row(&row))
        .transpose()
    }

    pub async fn upsert_access_key(&self, key: &NewAccessKey<'_>) -> Result<(), AppError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("INSERT INTO users (near_account) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(key.holder.as_str())
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "INSERT INTO access_keys \
             (key_id, strategy_id, holder, agent_pubkey, tier, expires_at, status) \
             VALUES ($1, $2, $3, $4, $5::access_tier, $6, $7::access_key_status) \
             ON CONFLICT (key_id) DO UPDATE SET agent_pubkey = EXCLUDED.agent_pubkey, \
             tier = EXCLUDED.tier, expires_at = EXCLUDED.expires_at, status = EXCLUDED.status",
        )
        .bind(key.key_id.as_str())
        .bind(key.strategy_id.as_str())
        .bind(key.holder.as_str())
        .bind(key.agent_pubkey)
        .bind(key.tier)
        .bind(key.expires_at)
        .bind(key.status)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mark_key_status(
        &self,
        key_id: &KeyId,
        status: &str,
    ) -> Result<Option<StrategyId>, AppError> {
        let strategy_id: Option<String> = sqlx::query_scalar(
            "UPDATE access_keys SET status = $2::access_key_status \
             WHERE key_id = $1 AND status <> $2::access_key_status RETURNING strategy_id",
        )
        .bind(key_id.as_str())
        .bind(status)
        .fetch_optional(&self.pool)
        .await?;
        strategy_id.map(StrategyId::parse).transpose()
    }

    pub async fn expire_keys(&self) -> Result<Vec<StrategyId>, AppError> {
        sqlx::query_scalar(
            "UPDATE access_keys SET status = 'expired' \
             WHERE status = 'active' AND expires_at <= now() RETURNING strategy_id",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(StrategyId::parse)
        .collect()
    }

    pub async fn set_attestation_tx(
        &self,
        strategy_id: &StrategyId,
        window: &str,
        period_end: DateTime<Utc>,
        tx_hash: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE attestations SET tx_hash = $4 \
             WHERE strategy_id = $1 AND window = $2 AND period_end = $3",
        )
        .bind(strategy_id.as_str())
        .bind(window)
        .bind(period_end)
        .bind(tx_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_latest_attestation_tx(
        &self,
        strategy_id: &StrategyId,
        window: &str,
        tx_hash: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE attestations SET tx_hash = $3 WHERE (strategy_id, window, period_end) = \
             (SELECT strategy_id, window, period_end FROM attestations \
              WHERE strategy_id = $1 AND window = $2 ORDER BY period_end DESC LIMIT 1)",
        )
        .bind(strategy_id.as_str())
        .bind(window)
        .bind(tx_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn chain_cursor(&self, source: &str) -> Result<Option<i64>, AppError> {
        sqlx::query_scalar("SELECT block_height FROM chain_cursor WHERE contract_id = $1")
            .bind(source)
            .fetch_optional(&self.pool)
            .await
            .map_err(AppError::from)
    }

    pub async fn save_chain_cursor(
        &self,
        source: &str,
        height: i64,
        block_hash: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO chain_cursor (contract_id, block_height, block_hash) VALUES ($1, $2, $3) \
             ON CONFLICT (contract_id) DO UPDATE SET block_height = EXCLUDED.block_height, \
             block_hash = EXCLUDED.block_hash, updated_at = now()",
        )
        .bind(source)
        .bind(height)
        .bind(block_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct NewStrategy<'a> {
    pub strategy_id: &'a StrategyId,
    pub owner: &'a NearAccount,
    pub name: &'a str,
    pub vault_account: &'a NearAccount,
    pub assets: &'a [String],
    pub live_price: &'a str,
    pub delayed_price: Option<&'a str>,
    pub key_duration_seconds: u64,
    pub max_followers: i32,
}

#[derive(Debug, Serialize)]
pub struct StrategyView {
    pub strategy_id: String,
    pub owner: String,
    pub name: String,
    pub vault_account: String,
    pub assets: Vec<String>,
    pub live_price: String,
    pub delayed_price: Option<String>,
    pub key_duration_seconds: i64,
    pub max_followers: i32,
    pub status: String,
    pub follower_count: i64,
}

#[derive(Debug, Serialize)]
pub struct LeaderboardEntry {
    pub strategy_id: String,
    pub name: String,
    pub assets: Vec<String>,
    pub twr_bps: i64,
    pub drawdown_bps: i64,
    pub nav_bucket: String,
    pub trade_count_bucket: String,
    pub period_end: DateTime<Utc>,
    pub snapshot_root: String,
    pub follower_count: i64,
}

#[derive(Debug, Serialize)]
pub struct AccessKeyView {
    pub key_id: String,
    pub strategy_id: String,
    pub holder: String,
    pub agent_pubkey: String,
    pub tier: String,
    pub expires_at: DateTime<Utc>,
    pub status: String,
}

impl AccessKeyView {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == "active" && self.expires_at > Utc::now()
    }

    pub fn tier(&self) -> Result<AccessTier, AppError> {
        match self.tier.as_str() {
            "live" => Ok(AccessTier::Live),
            "delayed" => Ok(AccessTier::Delayed),
            _ => Err(AppError::Internal),
        }
    }
}

#[derive(Debug, serde::Deserialize, Serialize)]
pub struct FollowerSettings {
    pub multiplier_bps: i32,
    pub trade_cap_bps: i32,
    pub daily_loss_bps: i32,
    pub drawdown_stop_bps: i32,
    pub max_slippage_bps: i32,
    pub copy_vault_account: NearAccount,
    #[serde(default)]
    pub paused: bool,
}

impl FollowerSettings {
    pub fn validate(&self) -> Result<(), AppError> {
        let positive_basis_points = [
            self.trade_cap_bps,
            self.daily_loss_bps,
            self.drawdown_stop_bps,
        ];
        if !(1..=100_000).contains(&self.multiplier_bps)
            || positive_basis_points
                .iter()
                .any(|value| !(1..=10_000).contains(value))
            || !(0..=10_000).contains(&self.max_slippage_bps)
        {
            return Err(AppError::Validation("risk setting is out of range".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct CopyOrderView {
    pub key_id: String,
    pub strategy_id: String,
    pub seq: i64,
    pub state: String,
    pub skip_reason: Option<String>,
    pub quote_id: Option<String>,
    pub status_ref: Option<String>,
    pub amount_in: Option<String>,
    pub copy_slippage_bps: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct StoredSignal<'a> {
    pub strategy_id: &'a StrategyId,
    pub epoch: u64,
    pub seq: u64,
    pub ciphertext: &'a [u8],
    pub nonce: &'a [u8; 24],
    pub valid_until: DateTime<Utc>,
}

pub struct NewAccessKey<'a> {
    pub key_id: &'a KeyId,
    pub strategy_id: &'a StrategyId,
    pub holder: &'a NearAccount,
    pub agent_pubkey: &'a str,
    pub tier: &'a str,
    pub expires_at: DateTime<Utc>,
    pub status: &'a str,
}

#[derive(Debug, Clone)]
pub struct FillRow {
    pub strategy_id: StrategyId,
    pub seq: u64,
    pub asset_in: String,
    pub asset_out: String,
    pub amount_in: String,
    pub amount_out: String,
    pub filled_at: DateTime<Utc>,
}

pub struct NewFill<'a> {
    pub strategy_id: &'a StrategyId,
    pub seq: u64,
    pub asset_in: &'a str,
    pub asset_out: &'a str,
    pub amount_in: &'a str,
    pub amount_out: &'a str,
    pub filled_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SignalRow {
    pub strategy_id: StrategyId,
    pub epoch: u64,
    pub seq: u64,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub valid_until: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttestationView {
    pub strategy_id: String,
    pub window: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub twr_bps: i64,
    pub drawdown_bps: i64,
    pub nav_bucket: String,
    pub trade_count_bucket: String,
    pub snapshot_root: String,
    pub tee_quote: String,
    pub signature: String,
    pub tx_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub struct NewSnapshot<'a> {
    pub strategy_id: &'a StrategyId,
    pub captured_at: DateTime<Utc>,
    pub value_usd_micros: i64,
    pub external_flow_usd_micros: i64,
    pub snapshot_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SnapshotRow {
    pub strategy_id: StrategyId,
    pub captured_at: DateTime<Utc>,
    pub value_usd_micros: i64,
    pub external_flow_usd_micros: i64,
    pub snapshot_hash: Vec<u8>,
}

pub struct NewAttestation<'a> {
    pub strategy_id: &'a StrategyId,
    pub window: &'a str,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub twr_bps: i64,
    pub drawdown_bps: i64,
    pub nav_bucket: &'a str,
    pub trade_count_bucket: &'a str,
    pub snapshot_root: [u8; 32],
    pub tee_quote: &'a str,
    pub signature: &'a str,
    pub tx_hash: Option<&'a str>,
}

pub struct CopyOrderUpdate<'a> {
    pub key_id: &'a KeyId,
    pub strategy_id: &'a StrategyId,
    pub seq: u64,
    pub state: CopyState,
    pub skip_reason: Option<&'a str>,
    pub quote_id: Option<&'a str>,
    pub status_ref: Option<&'a str>,
    pub amount_in: Option<&'a str>,
    pub copy_slippage_bps: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct VaultStateRow {
    pub peak_nav_usd_micros: i64,
    pub day_start_nav_usd_micros: i64,
    pub day: NaiveDate,
}

const fn copy_state_name(state: CopyState) -> &'static str {
    match state {
        CopyState::Received => "received",
        CopyState::Sized => "sized",
        CopyState::Quoted => "quoted",
        CopyState::Funded => "funded",
        CopyState::Settled => "settled",
        CopyState::Skipped => "skipped",
        CopyState::Refunded => "refunded",
        CopyState::Failed => "failed",
    }
}

fn signal_from_row(row: &PgRow) -> Result<SignalRow, AppError> {
    let epoch: i64 = row.try_get("epoch_no")?;
    let seq: i64 = row.try_get("seq")?;
    Ok(SignalRow {
        strategy_id: StrategyId::parse(row.try_get("strategy_id")?)?,
        epoch: u64::try_from(epoch).map_err(|_| AppError::Internal)?,
        seq: u64::try_from(seq).map_err(|_| AppError::Internal)?,
        ciphertext: row.try_get("ciphertext")?,
        nonce: row.try_get("nonce")?,
        valid_until: row.try_get("valid_until")?,
        created_at: row.try_get("created_at")?,
    })
}

fn snapshot_from_row(row: &PgRow) -> Result<SnapshotRow, AppError> {
    Ok(SnapshotRow {
        strategy_id: StrategyId::parse(row.try_get("strategy_id")?)?,
        captured_at: row.try_get("captured_at")?,
        value_usd_micros: row.try_get("value_usd_micros")?,
        external_flow_usd_micros: row.try_get("external_flow_usd_micros")?,
        snapshot_hash: row.try_get("snapshot_hash")?,
    })
}

fn attestation_from_row(row: &PgRow) -> Result<AttestationView, AppError> {
    Ok(AttestationView {
        strategy_id: row.try_get("strategy_id")?,
        window: row.try_get("window")?,
        period_start: row.try_get("period_start")?,
        period_end: row.try_get("period_end")?,
        twr_bps: row.try_get("twr_bps")?,
        drawdown_bps: row.try_get("drawdown_bps")?,
        nav_bucket: row.try_get("nav_bucket")?,
        trade_count_bucket: row.try_get("trade_count_bucket")?,
        snapshot_root: row.try_get("snapshot_root")?,
        tee_quote: row.try_get("tee_quote")?,
        signature: row.try_get("signature")?,
        tx_hash: row.try_get("tx_hash")?,
        created_at: row.try_get("created_at")?,
    })
}

fn strategy_from_row(row: &PgRow) -> Result<StrategyView, AppError> {
    Ok(StrategyView {
        strategy_id: row.try_get("strategy_id")?,
        owner: row.try_get("owner")?,
        name: row.try_get("name")?,
        vault_account: row.try_get("vault_account")?,
        assets: row.try_get("assets")?,
        live_price: row.try_get("live_price")?,
        delayed_price: row.try_get("delayed_price")?,
        key_duration_seconds: row.try_get("key_duration_seconds")?,
        max_followers: row.try_get("max_followers")?,
        status: row.try_get("status")?,
        follower_count: row.try_get("follower_count")?,
    })
}

fn leaderboard_from_row(row: &PgRow) -> Result<LeaderboardEntry, AppError> {
    Ok(LeaderboardEntry {
        strategy_id: row.try_get("strategy_id")?,
        name: row.try_get("name")?,
        assets: row.try_get("assets")?,
        twr_bps: row.try_get("twr_bps")?,
        drawdown_bps: row.try_get("drawdown_bps")?,
        nav_bucket: row.try_get("nav_bucket")?,
        trade_count_bucket: row.try_get("trade_count_bucket")?,
        period_end: row.try_get("period_end")?,
        snapshot_root: row.try_get("snapshot_root")?,
        follower_count: row.try_get("follower_count")?,
    })
}

fn access_key_from_row(row: &PgRow) -> Result<AccessKeyView, AppError> {
    Ok(AccessKeyView {
        key_id: row.try_get("key_id")?,
        strategy_id: row.try_get("strategy_id")?,
        holder: row.try_get("holder")?,
        agent_pubkey: row.try_get("agent_pubkey")?,
        tier: row.try_get("tier")?,
        expires_at: row.try_get("expires_at")?,
        status: row.try_get("status")?,
    })
}

fn copy_order_from_row(row: &PgRow) -> Result<CopyOrderView, AppError> {
    Ok(CopyOrderView {
        key_id: row.try_get("key_id")?,
        strategy_id: row.try_get("strategy_id")?,
        seq: row.try_get("seq")?,
        state: row.try_get("state")?,
        skip_reason: row.try_get("skip_reason")?,
        quote_id: row.try_get("quote_id")?,
        status_ref: row.try_get("status_ref")?,
        amount_in: row.try_get("amount_in")?,
        copy_slippage_bps: row.try_get("copy_slippage_bps")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
