CREATE TABLE IF NOT EXISTS tenant_backups (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  object_key TEXT NOT NULL UNIQUE,
  checksum TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  record_count INTEGER NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tenant_backups_org_created
  ON tenant_backups(organization_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_expenses_org_employee_amount_date
  ON expenses(organization_id, employee_id, amount, expense_date, status);

CREATE INDEX IF NOT EXISTS idx_payroll_period_lookup
  ON payroll_runs(organization_id, period_start, period_end, status);
