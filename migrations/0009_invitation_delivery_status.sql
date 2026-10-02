ALTER TABLE employee_invites ADD COLUMN email_status TEXT NOT NULL DEFAULT 'accepted'
  CHECK (email_status IN ('pending','accepted','failed'));
ALTER TABLE employee_invites ADD COLUMN email_message_id TEXT;
ALTER TABLE employee_invites ADD COLUMN last_error TEXT;
ALTER TABLE employee_invites ADD COLUMN last_attempt_at TEXT;

UPDATE employee_invites
SET last_attempt_at = COALESCE(last_attempt_at, created_at);

CREATE INDEX IF NOT EXISTS idx_employee_invites_delivery ON employee_invites(organization_id, email_status, created_at DESC);
