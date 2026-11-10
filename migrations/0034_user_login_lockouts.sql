CREATE TABLE IF NOT EXISTS user_login_lockouts (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 5),
  locked_until TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_login_lockouts_expiry
  ON user_login_lockouts(locked_until);
