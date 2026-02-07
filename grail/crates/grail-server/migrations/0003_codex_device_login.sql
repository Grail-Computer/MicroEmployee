CREATE TABLE IF NOT EXISTS codex_device_logins (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL, -- pending | completed | failed | cancelled
  verification_url TEXT NOT NULL,
  user_code TEXT NOT NULL,
  device_auth_id TEXT NOT NULL,
  interval_sec INTEGER NOT NULL,
  error_text TEXT,
  created_at INTEGER NOT NULL,
  completed_at INTEGER
);

CREATE INDEX IF NOT EXISTS codex_device_logins_status_created_at_idx
  ON codex_device_logins(status, created_at);

