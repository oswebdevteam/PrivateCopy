# PrivateCopy server

Single-process Rust backend for KeyTrade / PrivateCopy. It contains the HTTP gateway, strategy execution service, encrypted signal relay, copy engine, attestor, and NEAR event indexer.

## Run locally

1. Copy `.env.example` to `.env`.
2. Replace `APP_JWT_SECRET` and `APP_EPOCH_MASTER_KEY`. Generate the latter with `openssl rand -base64 32`.
3. Configure `APP_AGENT_KEYS_FILE` for every strategy vault, follower copy vault, and attestor account the process must sign for.
4. Run `docker compose up --build`.

Migrations run automatically at startup. The server listens on port `8080`; `GET /health` returns `204`.

Agent key file format:

```json
{
  "accounts": [
    {
      "account": "vault.testnet",
      "secret_key": "ed25519:..."
    }
  ]
}
```

The file should be owner-readable only on Unix. Standard 64-byte NEAR Ed25519 secret keys and 32-byte seeds are accepted.

## Authentication and secrets

- Obtain a NEP-413 challenge from `POST /v1/auth/nonce`, sign it with a full-access NEAR key, then exchange it through `POST /v1/auth/verify`.
- Send the resulting JWT as `Authorization: Bearer <token>`.
- Value-moving POST requests require an `Idempotency-Key` header.
- Supply a 1Click user-session token through `x-1click-session` when registering a strategy or configuring a follower copy vault. Strategy trade requests may include a replacement token to renew the in-memory vault session.
- Session tokens remain memory-only and must be supplied again after a restart.
- `APP_SIGNAL_TTL_SECONDS` must exceed `APP_DELAYED_TIER_SECONDS`; epoch rotation uses the independent `APP_EPOCH_INTERVAL_SECONDS` setting.

`PUT /v1/copy/{key_id}/settings` requires a dedicated `copy_vault_account`:

```json
{
  "copy_vault_account": "copy-vault.testnet",
  "multiplier_bps": 10000,
  "trade_cap_bps": 2000,
  "daily_loss_bps": 500,
  "drawdown_stop_bps": 2500,
  "max_slippage_bps": 50,
  "paused": false
}
```

The access-key holder authorizes settings changes, while balances, risk state, session lookup, signing, refunds, and swap proceeds use the dedicated copy vault.

## API

- Public: `GET /v1/leaderboard`, `GET /v1/strategies/{id}`
- Auth: `POST /v1/auth/nonce`, `POST /v1/auth/verify`
- Vault: `POST /v1/vault/shield`, `POST /v1/vault/unshield`, `GET /v1/vault/balance`
- Strategy: `POST /v1/strategies`, `POST /v1/strategies/{id}/trades`
- Access: `GET /v1/keys`, `POST /v1/keys/{id}/revoke`
- Copy: `PUT /v1/copy/{key_id}/settings`, `GET /v1/copy/{key_id}/orders`, `POST /v1/copy/{key_id}/pause`
- Relay: `GET /v1/signals/{strategy_id}?key_id=...&since=...`

WebSocket authentication supports the `Authorization` header or `Sec-WebSocket-Protocol: bearer, <jwt>`. The relay then requires proof of possession of the access key's X25519 agent key.

## External integration boundaries

- `APP_INDEXER_URL` must expose NEAR Lake-style blocks at `/v0/block/{height}`.
- Access-key grants, revocations, and expirations are mirrored from NEP-297 contract events.
- Contract transaction schemas are deployment-specific. The current revoke endpoint updates the mirror and rotates the signal epoch; direct on-chain revoke submission is not wired.
- Attestations are signed and exposed through the API. Direct `post_attestation` transaction submission requires the deployed contract ABI.
- External shield/unshield flow ingestion is not yet wired, so snapshot external flow is currently zero.

## Verification

```sh
cargo fmt --all -- --check
cargo check --locked --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```
