CREATE TABLE IF NOT EXISTS worker_lock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  owner_id TEXT,
  lease_until INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

INSERT INTO worker_lock (id, lease_until, updated_at)
  VALUES (1, 0, unixepoch())
  ON CONFLICT(id) DO NOTHING;

