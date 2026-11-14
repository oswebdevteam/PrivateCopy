-- Demo seed for a local privatecopy-server: enough rows for the public
-- leaderboard, strategy pages, keys, settings and copy orders.
BEGIN;

INSERT INTO users (near_account) VALUES
  ('atlas.testnet'), ('nocturne.testnet'), ('kestrel.testnet'),
  ('meridian.testnet'), ('vesper.testnet'), ('demo.testnet'),
  ('follower-one.testnet'), ('copybot.testnet')
ON CONFLICT DO NOTHING;

INSERT INTO strategies (strategy_id, owner, name, vault_account, assets, live_price, delayed_price, key_duration_seconds, max_followers, status) VALUES
  ('st_01HQZK7M8N3P4R5S6T7V8W9X0Y','atlas.testnet','Atlas Momentum','atlas-vault.testnet',
    ARRAY['nep141:usdc.fakes.testnet','nep141:wrap.testnet','nep141:eth.fakes.testnet'],'25000000','8000000',2592000,250,'active'),
  ('st_02HQZK7M8N3P4R5S6T7V8W9X0Y','nocturne.testnet','Nocturne Basis','nocturne-vault.testnet',
    ARRAY['nep141:usdc.fakes.testnet','nep141:btc.fakes.testnet'],'40000000',NULL,1209600,60,'active'),
  ('st_03HQZK7M8N3P4R5S6T7V8W9X0Y','kestrel.testnet','Kestrel Mean Reversion','kestrel-vault.testnet',
    ARRAY['nep141:usdc.fakes.testnet','nep141:wrap.testnet'],'12000000','4000000',604800,500,'active'),
  ('st_04HQZK7M8N3P4R5S6T7V8W9X0Y','meridian.testnet','Meridian Carry','meridian-vault.testnet',
    ARRAY['nep141:usdc.fakes.testnet','nep141:eth.fakes.testnet','nep141:btc.fakes.testnet'],'60000000','20000000',2592000,100,'active'),
  ('st_05HQZK7M8N3P4R5S6T7V8W9X0Y','vesper.testnet','Vesper Breakout','vesper-vault.testnet',
    ARRAY['nep141:usdc.fakes.testnet','nep141:wrap.testnet','nep141:btc.fakes.testnet'],'18000000','6000000',1209600,150,'active')
ON CONFLICT DO NOTHING;

-- One attestation every 12 hours for the last week, per strategy and window.
INSERT INTO attestations (strategy_id, "window", period_start, period_end, twr_bps, drawdown_bps,
                          nav_bucket, trade_count_bucket, snapshot_root, tee_quote, signature, tx_hash)
SELECT
  s.strategy_id,
  w.win,
  now() - (step * interval '12 hours') - interval '30 days',
  now() - (step * interval '12 hours'),
  round(s.final_twr * w.scale * (1 - step::numeric / 16) + 60 * sin(step))::bigint,
  round(s.final_dd * w.scale * (1 - step::numeric / 20))::bigint,
  s.nav_bucket,
  s.trade_bucket,
  sha256(decode(md5(s.strategy_id || w.win || step), 'hex')),
  'sgx:' || md5(s.strategy_id || step),
  'ed25519:' || md5(w.win || s.strategy_id || step),
  CASE WHEN step % 2 = 0 THEN md5(s.strategy_id || step || 'tx') ELSE NULL END
FROM (VALUES
    ('st_01HQZK7M8N3P4R5S6T7V8W9X0Y', 1842, 412, '100k–250k', '50–100'),
    ('st_02HQZK7M8N3P4R5S6T7V8W9X0Y',  940, 118, '250k–1M',  '100–250'),
    ('st_03HQZK7M8N3P4R5S6T7V8W9X0Y',  612, 734, '25k–100k', '250+'),
    ('st_04HQZK7M8N3P4R5S6T7V8W9X0Y',  428,  96, '1M+',      '10–50'),
    ('st_05HQZK7M8N3P4R5S6T7V8W9X0Y', -214,1180, '25k–100k', '50–100')
  ) AS s(strategy_id, final_twr, final_dd, nav_bucket, trade_bucket),
  (VALUES ('7d', 0.42), ('30d', 1.0), ('all', 1.65)) AS w(win, scale),
  generate_series(0, 13) AS step
ON CONFLICT DO NOTHING;

-- Keys the demo account holds, plus keys sold on the strategy it owns.
INSERT INTO access_keys (key_id, strategy_id, holder, agent_pubkey, tier, expires_at, status) VALUES
  ('key_01HQZK7M8N3P4R5S6T7V8W9X0Y','st_02HQZK7M8N3P4R5S6T7V8W9X0Y','demo.testnet','x25519:8Ht4Qm2VxJpR7sNf1LbYc3Kd9Wg5Tz6Aq0Ue','live',   now() + interval '9 days', 'active'),
  ('key_02HQZK7M8N3P4R5S6T7V8W9X0Y','st_04HQZK7M8N3P4R5S6T7V8W9X0Y','demo.testnet','x25519:3Bf8Km5PwQnT2xLd6Ryc9Jh4Vg7Zs1Mo0Ai','delayed',now() + interval '21 days','active'),
  ('key_03HQZK7M8N3P4R5S6T7V8W9X0Y','st_03HQZK7M8N3P4R5S6T7V8W9X0Y','demo.testnet','x25519:7Yn2Lq9TcWmP4zKf8Dbs3Rh6Vj1Xg5Uo0Ei','live',   now() - interval '2 days', 'expired'),
  ('key_11HQZK7M8N3P4R5S6T7V8W9X0Y','st_01HQZK7M8N3P4R5S6T7V8W9X0Y','follower-one.testnet','x25519:2Qp7Rn4McXvT8yLd5Fbs1Kh9Wj3Zg6Uo0Ai','live',   now() + interval '17 days','active'),
  ('key_12HQZK7M8N3P4R5S6T7V8W9X0Y','st_01HQZK7M8N3P4R5S6T7V8W9X0Y','copybot.testnet',     'x25519:9Jd3Vn8QcTmP2xKf4Rbs7Lh1Wg5Zo0Ue6Ai','delayed',now() + interval '4 days', 'active')
ON CONFLICT DO NOTHING;

INSERT INTO follower_settings (key_id, copy_vault_account, multiplier_bps, trade_cap_bps, daily_loss_bps, drawdown_stop_bps, max_slippage_bps, paused) VALUES
  ('key_01HQZK7M8N3P4R5S6T7V8W9X0Y', 'demo-copy-vault.testnet',  10000, 2000, 500, 2500, 50, false),
  ('key_02HQZK7M8N3P4R5S6T7V8W9X0Y', 'demo-copy-vault2.testnet',  7500, 1500, 400, 2000, 30, false)
ON CONFLICT DO NOTHING;

INSERT INTO copy_orders (key_id, strategy_id, seq, state, skip_reason, quote_id, status_ref, amount_in, copy_slippage_bps, created_at, updated_at) VALUES
  ('key_01HQZK7M8N3P4R5S6T7V8W9X0Y','st_02HQZK7M8N3P4R5S6T7V8W9X0Y',142,'settled', NULL,                           'q_142','ref_142','4820000000',18, now() - interval '24 minutes', now() - interval '23 minutes'),
  ('key_01HQZK7M8N3P4R5S6T7V8W9X0Y','st_02HQZK7M8N3P4R5S6T7V8W9X0Y',141,'settled', NULL,                           'q_141','ref_141','4810000000',31, now() - interval '3 hours',    now() - interval '3 hours'),
  ('key_01HQZK7M8N3P4R5S6T7V8W9X0Y','st_02HQZK7M8N3P4R5S6T7V8W9X0Y',140,'skipped', 'trade_cap_bps exceeded',       NULL,   NULL,     NULL,        NULL, now() - interval '5 hours',   now() - interval '5 hours'),
  ('key_01HQZK7M8N3P4R5S6T7V8W9X0Y','st_02HQZK7M8N3P4R5S6T7V8W9X0Y',139,'settled', NULL,                           'q_139','ref_139','2400000000',12, now() - interval '10 hours',   now() - interval '10 hours'),
  ('key_01HQZK7M8N3P4R5S6T7V8W9X0Y','st_02HQZK7M8N3P4R5S6T7V8W9X0Y',138,'refunded','quote expired before deposit', 'q_138','ref_138','2400000000',NULL, now() - interval '14 hours',  now() - interval '14 hours'),
  ('key_01HQZK7M8N3P4R5S6T7V8W9X0Y','st_02HQZK7M8N3P4R5S6T7V8W9X0Y',137,'skipped', 'daily_loss_bps reached',       NULL,   NULL,     NULL,        NULL, now() - interval '21 hours',  now() - interval '21 hours'),
  ('key_01HQZK7M8N3P4R5S6T7V8W9X0Y','st_02HQZK7M8N3P4R5S6T7V8W9X0Y',136,'settled', NULL,                           'q_136','ref_136','4760000000',24, now() - interval '1 day',      now() - interval '1 day'),
  ('key_01HQZK7M8N3P4R5S6T7V8W9X0Y','st_02HQZK7M8N3P4R5S6T7V8W9X0Y',135,'failed',  'solver returned no fill',      'q_135','ref_135','1200000000',NULL, now() - interval '31 hours',  now() - interval '31 hours')
ON CONFLICT DO NOTHING;

COMMIT;
