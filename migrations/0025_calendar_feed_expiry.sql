ALTER TABLE calendar_feed_tokens ADD COLUMN expires_at TEXT;

-- Existing subscription links receive one 90-day transition window. New links
-- are also issued for 90 days and can be rotated or revoked earlier.
UPDATE calendar_feed_tokens
SET expires_at = datetime('now', '+90 days')
WHERE expires_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_calendar_feed_active_expiry
  ON calendar_feed_tokens(organization_id, revoked_at, expires_at);
