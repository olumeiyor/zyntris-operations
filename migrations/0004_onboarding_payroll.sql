ALTER TABLE users ADD COLUMN email_verified_at TEXT;
ALTER TABLE organizations ADD COLUMN description TEXT;

CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_rate_limits (
  bucket_key TEXT PRIMARY KEY,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  window_started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS payroll_settings (
  organization_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  currency TEXT NOT NULL DEFAULT 'NGN',
  pay_frequency TEXT NOT NULL DEFAULT 'monthly' CHECK (pay_frequency IN ('weekly','biweekly','semimonthly','monthly')),
  tax_country TEXT NOT NULL DEFAULT 'NG',
  tax_region TEXT,
  tax_year INTEGER NOT NULL DEFAULT 2026,
  tax_free_allowance REAL NOT NULL DEFAULT 0,
  tax_bands_json TEXT NOT NULL DEFAULT '[]',
  employee_pension_rate REAL NOT NULL DEFAULT 0,
  employer_pension_rate REAL NOT NULL DEFAULT 0,
  pension_basis TEXT NOT NULL DEFAULT 'base_salary' CHECK (pension_basis IN ('base_salary','gross')),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS employee_pay_profiles (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  base_salary REAL NOT NULL CHECK (base_salary >= 0),
  currency TEXT NOT NULL DEFAULT 'NGN',
  pay_frequency TEXT NOT NULL DEFAULT 'monthly',
  effective_from TEXT NOT NULL,
  bank_details_enc TEXT,
  tax_reference TEXT,
  pension_reference TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, employee_id)
);

CREATE TABLE IF NOT EXISTS payroll_components (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('earning','deduction','employer_contribution')),
  taxable INTEGER NOT NULL DEFAULT 1 CHECK (taxable IN (0,1)),
  pensionable INTEGER NOT NULL DEFAULT 0 CHECK (pensionable IN (0,1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, code),
  UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS employee_pay_components (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  component_id TEXT NOT NULL REFERENCES payroll_components(id) ON DELETE CASCADE,
  amount REAL NOT NULL CHECK (amount >= 0),
  effective_from TEXT NOT NULL,
  effective_to TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, employee_id, component_id, effective_from)
);

CREATE TABLE IF NOT EXISTS payroll_runs (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  payment_date TEXT NOT NULL,
  currency TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','reviewed','approved','paid','void')),
  employee_count INTEGER NOT NULL DEFAULT 0,
  gross_total REAL NOT NULL DEFAULT 0,
  deductions_total REAL NOT NULL DEFAULT 0,
  employer_cost_total REAL NOT NULL DEFAULT 0,
  net_total REAL NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL REFERENCES users(id),
  reviewed_by TEXT REFERENCES users(id),
  approved_by TEXT REFERENCES users(id),
  paid_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, period_start, period_end)
);

CREATE TABLE IF NOT EXISTS payroll_run_items (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  payroll_run_id TEXT NOT NULL REFERENCES payroll_runs(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id),
  employee_number TEXT NOT NULL,
  employee_name TEXT NOT NULL,
  job_title TEXT NOT NULL,
  base_salary REAL NOT NULL,
  gross_pay REAL NOT NULL,
  taxable_pay REAL NOT NULL,
  paye_tax REAL NOT NULL,
  employee_pension REAL NOT NULL,
  employer_pension REAL NOT NULL,
  other_deductions REAL NOT NULL,
  employer_contributions REAL NOT NULL,
  net_pay REAL NOT NULL,
  breakdown_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (payroll_run_id, employee_id)
);

CREATE INDEX IF NOT EXISTS idx_pay_profiles_org_status ON employee_pay_profiles(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_payroll_runs_org_period ON payroll_runs(organization_id, period_start DESC);
CREATE INDEX IF NOT EXISTS idx_payroll_items_org_employee ON payroll_run_items(organization_id, employee_id);

INSERT OR IGNORE INTO permissions (id, code, description) VALUES
  ('perm-payroll-view', 'payroll.view', 'View payroll data and payslips'),
  ('perm-payroll-manage', 'payroll.manage', 'Manage pay policies and employee compensation'),
  ('perm-payroll-run', 'payroll.run', 'Create and calculate payroll runs'),
  ('perm-payroll-approve', 'payroll.approve', 'Review, approve and mark payroll paid'),
  ('perm-employees-view', 'employees.view', 'View employee records'),
  ('perm-employees-manage', 'employees.manage', 'Manage employee records'),
  ('perm-expenses-view', 'expenses.view', 'View expense records'),
  ('perm-expenses-manage', 'expenses.manage', 'Manage expense records'),
  ('perm-requests-manage', 'requests.manage', 'Review operational requests'),
  ('perm-settings-manage', 'settings.manage', 'Manage organization settings');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'Organization Admin' AND p.code IN (
  'payroll.view','payroll.manage','payroll.run','payroll.approve',
  'employees.view','employees.manage','expenses.view','expenses.manage','requests.manage','settings.manage'
);

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'HR Admin' AND p.code IN ('payroll.view','payroll.manage','payroll.run','employees.view','employees.manage');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'Finance Admin' AND p.code IN ('payroll.view','payroll.run','payroll.approve','expenses.view','expenses.manage','requests.manage');
