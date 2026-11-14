CREATE TYPE strategy_status AS ENUM ('active', 'paused');
CREATE TYPE access_tier AS ENUM ('live', 'delayed');
CREATE TYPE access_key_status AS ENUM ('active', 'expired', 'revoked');
CREATE TYPE copy_state AS ENUM ('received', 'sized', 'quoted', 'funded', 'settled', 'skipped', 'refunded', 'failed');

CREATE TABLE users (
    near_account TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth_nonces (
    nonce_hash BYTEA PRIMARY KEY,
    near_account TEXT NOT NULL,
    message TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);
CREATE INDEX auth_nonces_expiry_idx ON auth_nonces (expires_at);

CREATE TABLE strategies (
    strategy_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL REFERENCES users(near_account),
    name TEXT NOT NULL,
    vault_account TEXT NOT NULL UNIQUE,
    assets TEXT[] NOT NULL,
    live_price TEXT NOT NULL,
    delayed_price TEXT,
    key_duration_seconds BIGINT NOT NULL CHECK (key_duration_seconds > 0),
    max_followers INTEGER NOT NULL CHECK (max_followers > 0),
    status strategy_status NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (cardinality(assets) > 0)
);

CREATE TABLE access_keys (
    key_id TEXT PRIMARY KEY,
    strategy_id TEXT NOT NULL REFERENCES strategies(strategy_id),
    holder TEXT NOT NULL REFERENCES users(near_account),
    agent_pubkey TEXT NOT NULL,
    tier access_tier NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status access_key_status NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX access_keys_holder_idx ON access_keys (holder, status);
CREATE INDEX access_keys_strategy_idx ON access_keys (strategy_id, status);

CREATE TABLE epochs (
    strategy_id TEXT NOT NULL REFERENCES strategies(strategy_id),
    epoch_no BIGINT NOT NULL CHECK (epoch_no >= 0),
    starts_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (strategy_id, epoch_no)
);

CREATE TABLE signals (
    strategy_id TEXT NOT NULL REFERENCES strategies(strategy_id),
    epoch_no BIGINT NOT NULL,
    seq BIGINT NOT NULL CHECK (seq > 0),
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (strategy_id, seq),
    FOREIGN KEY (strategy_id, epoch_no) REFERENCES epochs(strategy_id, epoch_no)
);

CREATE TABLE fills (
    strategy_id TEXT NOT NULL REFERENCES strategies(strategy_id),
    seq BIGINT NOT NULL,
    asset_in TEXT NOT NULL,
    asset_out TEXT NOT NULL,
    amount_in TEXT NOT NULL,
    amount_out TEXT NOT NULL,
    filled_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (strategy_id, seq)
);

CREATE TABLE follower_settings (
    key_id TEXT PRIMARY KEY REFERENCES access_keys(key_id),
    multiplier_bps INTEGER NOT NULL DEFAULT 10000 CHECK (multiplier_bps BETWEEN 1 AND 100000),
    trade_cap_bps INTEGER NOT NULL DEFAULT 2000 CHECK (trade_cap_bps BETWEEN 1 AND 10000),
    daily_loss_bps INTEGER NOT NULL DEFAULT 500 CHECK (daily_loss_bps BETWEEN 1 AND 10000),
    drawdown_stop_bps INTEGER NOT NULL DEFAULT 2500 CHECK (drawdown_stop_bps BETWEEN 1 AND 10000),
    max_slippage_bps INTEGER NOT NULL DEFAULT 50 CHECK (max_slippage_bps BETWEEN 0 AND 10000),
    paused BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE copy_orders (
    key_id TEXT NOT NULL REFERENCES access_keys(key_id),
    strategy_id TEXT NOT NULL REFERENCES strategies(strategy_id),
    seq BIGINT NOT NULL,
    state copy_state NOT NULL,
    skip_reason TEXT,
    quote_id TEXT,
    status_ref TEXT,
    amount_in TEXT,
    copy_slippage_bps INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (key_id, strategy_id, seq)
);

CREATE TABLE snapshots (
    strategy_id TEXT NOT NULL REFERENCES strategies(strategy_id),
    captured_at TIMESTAMPTZ NOT NULL,
    value_usd_micros BIGINT NOT NULL CHECK (value_usd_micros >= 0),
    external_flow_usd_micros BIGINT NOT NULL DEFAULT 0,
    snapshot_hash BYTEA NOT NULL,
    PRIMARY KEY (strategy_id, captured_at)
);

CREATE TABLE signal_counters (
    strategy_id TEXT PRIMARY KEY REFERENCES strategies(strategy_id),
    next_seq BIGINT NOT NULL DEFAULT 1 CHECK (next_seq > 0)
);

CREATE TABLE follower_vault_state (
    key_id TEXT PRIMARY KEY REFERENCES access_keys(key_id),
    peak_nav_usd_micros BIGINT NOT NULL CHECK (peak_nav_usd_micros >= 0),
    day_start_nav_usd_micros BIGINT NOT NULL CHECK (day_start_nav_usd_micros >= 0),
    day DATE NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE attestations (
    strategy_id TEXT NOT NULL REFERENCES strategies(strategy_id),
    "window" TEXT NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    twr_bps BIGINT NOT NULL,
    drawdown_bps BIGINT NOT NULL,
    nav_bucket TEXT NOT NULL,
    trade_count_bucket TEXT NOT NULL,
    snapshot_root BYTEA NOT NULL,
    tee_quote TEXT NOT NULL,
    signature TEXT NOT NULL,
    tx_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (strategy_id, "window", period_end)
);
CREATE INDEX attestations_latest_idx ON attestations (strategy_id, "window", period_end DESC);

CREATE TABLE chain_cursor (
    contract_id TEXT PRIMARY KEY,
    block_height BIGINT NOT NULL,
    block_hash TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE idempotency_keys (
    near_account TEXT NOT NULL,
    route TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    response JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (near_account, route, idempotency_key)
);
CREATE INDEX idempotency_expiry_idx ON idempotency_keys (expires_at);
