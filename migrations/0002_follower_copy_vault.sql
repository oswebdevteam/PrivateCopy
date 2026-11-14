ALTER TABLE follower_settings ADD COLUMN copy_vault_account TEXT;

UPDATE follower_settings f
SET copy_vault_account = k.holder
FROM access_keys k
WHERE k.key_id = f.key_id;

ALTER TABLE follower_settings ALTER COLUMN copy_vault_account SET NOT NULL;
