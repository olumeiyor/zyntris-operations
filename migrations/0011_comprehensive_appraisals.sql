CREATE TABLE IF NOT EXISTS appraisal_cycles (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  self_review_due TEXT NOT NULL,
  manager_review_due TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (period_end >= period_start),
  CHECK (manager_review_due >= self_review_due)
);

CREATE TABLE IF NOT EXISTS appraisals (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  cycle_id TEXT NOT NULL REFERENCES appraisal_cycles(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id),
  reviewer_user_id TEXT NOT NULL REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'self_review' CHECK (status IN ('self_review','manager_review','acknowledgment','complete')),
  self_review_json TEXT,
  manager_review_json TEXT,
  employee_acknowledgment TEXT,
  self_submitted_at TEXT,
  manager_submitted_at TEXT,
  acknowledged_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, cycle_id, employee_id)
);

CREATE INDEX IF NOT EXISTS idx_appraisal_cycles_tenant_status ON appraisal_cycles(organization_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_appraisals_employee_status ON appraisals(organization_id, employee_id, status);
CREATE INDEX IF NOT EXISTS idx_appraisals_reviewer_status ON appraisals(organization_id, reviewer_user_id, status);

INSERT OR IGNORE INTO permissions (id, code, description) VALUES
  ('perm-appraisals-view', 'appraisals.view', 'View assigned appraisal reviews'),
  ('perm-appraisals-manage', 'appraisals.manage', 'Create and administer appraisal cycles'),
  ('perm-appraisals-self-view', 'appraisals.self.view', 'View and complete own performance appraisals');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN ('appraisals.view','appraisals.manage')
WHERE r.name IN ('Organization Admin','HR Admin','CEO');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN ('appraisals.view','appraisals.self.view')
WHERE r.name = 'Manager';

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code = 'appraisals.self.view'
WHERE r.name = 'Employee';
