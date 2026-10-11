ALTER TABLE approval_requests ADD COLUMN due_at TEXT;
ALTER TABLE approval_requests ADD COLUMN reminder_sent_at TEXT;
ALTER TABLE approval_requests ADD COLUMN escalated_at TEXT;

ALTER TABLE employee_exit_cases ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'approved' CHECK (approval_status IN ('pending','approved','rejected'));
ALTER TABLE employee_exit_cases ADD COLUMN approval_role TEXT NOT NULL DEFAULT 'CEO';
ALTER TABLE employee_exit_cases ADD COLUMN approval_note TEXT;
ALTER TABLE employee_exit_cases ADD COLUMN approved_by TEXT REFERENCES users(id);
ALTER TABLE employee_exit_cases ADD COLUMN approved_at TEXT;
ALTER TABLE organization_settings ADD COLUMN exit_approval_role TEXT NOT NULL DEFAULT 'CEO' CHECK (exit_approval_role IN ('CEO','HR Admin'));
ALTER TABLE payroll_runs ADD COLUMN preflight_warnings_json TEXT NOT NULL DEFAULT '[]';

CREATE TABLE IF NOT EXISTS workflow_templates (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('onboarding','offboarding','task')),
  steps_json TEXT NOT NULL DEFAULT '[]',
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, category, name)
);
CREATE TABLE IF NOT EXISTS workflow_sla_settings (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  request_type TEXT NOT NULL,
  due_hours INTEGER NOT NULL DEFAULT 48 CHECK (due_hours BETWEEN 1 AND 8760),
  reminder_hours INTEGER NOT NULL DEFAULT 24 CHECK (reminder_hours BETWEEN 1 AND 8760),
  escalation_role TEXT NOT NULL DEFAULT 'HR Admin' CHECK (escalation_role IN ('HR Admin','CEO','Organization Admin')),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (organization_id, request_type)
);

CREATE TABLE IF NOT EXISTS tenant_backup_settings (
  organization_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
  frequency TEXT NOT NULL DEFAULT 'daily' CHECK (frequency IN ('daily','weekly')),
  retention_days INTEGER NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 7 AND 365),
  alert_email TEXT,
  last_run_at TEXT,
  last_status TEXT,
  last_error TEXT,
  last_verified_at TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS purchase_requests (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  requester_id TEXT NOT NULL REFERENCES users(id),
  vendor_id TEXT REFERENCES vendors(id),
  budget_id TEXT REFERENCES budgets(id),
  amount REAL NOT NULL CHECK (amount > 0),
  currency TEXT NOT NULL DEFAULT 'NGN',
  items_json TEXT NOT NULL DEFAULT '[]',
  quotes_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending_approval','approved','rejected','ordered','partially_received','received','matched','cancelled')),
  receipt_reference TEXT,
  invoice_reference TEXT,
  received_amount REAL NOT NULL DEFAULT 0,
  matched_at TEXT,
  approval_request_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_purchase_requests_tenant_status ON purchase_requests(organization_id,status,created_at DESC);
CREATE TABLE IF NOT EXISTS budget_reservations (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  budget_id TEXT NOT NULL REFERENCES budgets(id) ON DELETE CASCADE,
  purchase_request_id TEXT NOT NULL UNIQUE REFERENCES purchase_requests(id) ON DELETE CASCADE,
  amount REAL NOT NULL CHECK (amount > 0),
  status TEXT NOT NULL DEFAULT 'reserved' CHECK (status IN ('reserved','released','consumed')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS purchase_orders (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  purchase_request_id TEXT NOT NULL UNIQUE REFERENCES purchase_requests(id),
  po_number TEXT NOT NULL,
  issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  issued_by TEXT REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'issued' CHECK (status IN ('issued','partially_received','received','closed')),
  UNIQUE(organization_id, po_number)
);

CREATE TABLE IF NOT EXISTS calendar_provider_connections (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('google','microsoft')),
  encrypted_tokens TEXT NOT NULL,
  scopes TEXT NOT NULL,
  sync_cursor TEXT,
  expires_at TEXT,
  last_synced_at TEXT,
  sync_error TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,user_id,provider)
);
CREATE TABLE IF NOT EXISTS calendar_oauth_states (
  token_hash TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('google','microsoft')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE calendar_events ADD COLUMN external_provider TEXT;
ALTER TABLE calendar_events ADD COLUMN external_id TEXT;
ALTER TABLE calendar_events ADD COLUMN connection_id TEXT REFERENCES calendar_provider_connections(id) ON DELETE SET NULL;
ALTER TABLE calendar_events ADD COLUMN external_updated_at TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_calendar_external_unique ON calendar_events(organization_id, connection_id, external_id) WHERE external_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS calendar_event_links (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  calendar_event_id TEXT NOT NULL REFERENCES calendar_events(id) ON DELETE CASCADE,
  connection_id TEXT NOT NULL REFERENCES calendar_provider_connections(id) ON DELETE CASCADE,
  provider_event_id TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(calendar_event_id,connection_id),
  UNIQUE(connection_id,provider_event_id)
);

CREATE TABLE IF NOT EXISTS mobile_push_tokens (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  platform TEXT NOT NULL CHECK (platform IN ('ios','android')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
