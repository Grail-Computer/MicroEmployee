CREATE TABLE IF NOT EXISTS secrets (
  key TEXT PRIMARY KEY,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  updated_at INTEGER NOT NULL
);

ALTER TABLE settings ADD COLUMN shell_network_access INTEGER NOT NULL DEFAULT 0;
