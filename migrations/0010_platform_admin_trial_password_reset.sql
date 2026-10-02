-- Enforce the 15-day policy for existing trials, measured from verified signup.
UPDATE subscriptions
SET trial_ends_at = COALESCE(
  datetime((SELECT MIN(u.email_verified_at) FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.organization_id = subscriptions.organization_id AND u.email_verified_at IS NOT NULL), '+15 days'),
  datetime(created_at, '+15 days')
)
WHERE status = 'trialing'
  AND organization_id IN (SELECT id FROM organizations WHERE is_demo = 0);

UPDATE subscriptions SET status = 'expired'
WHERE status = 'trialing' AND trial_ends_at <= CURRENT_TIMESTAMP
  AND organization_id IN (SELECT id FROM organizations WHERE is_demo = 0);

UPDATE organizations SET status = 'suspended'
WHERE is_demo = 0 AND EXISTS (
  SELECT 1 FROM subscriptions s WHERE s.organization_id = organizations.id AND s.status = 'expired'
);

DELETE FROM sessions
WHERE organization_id IN (
  SELECT organization_id FROM subscriptions WHERE status = 'expired'
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  claim_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_password_reset_expiry ON password_reset_tokens(expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_password_reset_active_user
  ON password_reset_tokens(user_id) WHERE used_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_subscriptions_trial_expiry
  ON subscriptions(status, trial_ends_at);
