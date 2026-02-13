-- Persist a non-secret GitHub OAuth app client id so device login can be
-- configured from the admin UI without requiring an env restart.
ALTER TABLE settings ADD COLUMN github_client_id TEXT NOT NULL DEFAULT '';
