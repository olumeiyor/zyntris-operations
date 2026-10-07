ALTER TABLE organization_settings ADD COLUMN approval_workflows_json TEXT NOT NULL DEFAULT '{"Operational":"Manager","Access":"Manager","HR":"HR Admin","Leave":"HR Admin","Other":"Manager"}';

CREATE TABLE IF NOT EXISTS calendar_feed_tokens (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_calendar_feed_org_active
  ON calendar_feed_tokens(organization_id, revoked_at);
