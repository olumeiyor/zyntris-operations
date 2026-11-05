CREATE UNIQUE INDEX IF NOT EXISTS idx_departments_id_org_eci ON departments(id,organization_id);

CREATE TABLE IF NOT EXISTS employee_cost_components (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  employee_id TEXT,
  department_id TEXT,
  category TEXT NOT NULL CHECK (category IN ('benefit','operational','recruitment','bonus','other_employer_cost')),
  name TEXT NOT NULL,
  amount_minor INTEGER NOT NULL CHECK (amount_minor >= 0),
  currency TEXT NOT NULL CHECK (length(currency)=3),
  cadence TEXT NOT NULL CHECK (cadence IN ('monthly','annual','one_time')),
  amortization_months INTEGER NOT NULL DEFAULT 1 CHECK (amortization_months BETWEEN 1 AND 600),
  effective_from TEXT NOT NULL,
  effective_to TEXT,
  renewal_date TEXT,
  allocation_method TEXT NOT NULL DEFAULT 'equal' CHECK (allocation_method IN ('equal','direct')),
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (employee_id,organization_id) REFERENCES employees(id,organization_id) ON DELETE CASCADE,
  FOREIGN KEY (department_id,organization_id) REFERENCES departments(id,organization_id) ON DELETE CASCADE,
  CHECK ((employee_id IS NOT NULL AND department_id IS NULL) OR (employee_id IS NULL AND department_id IS NOT NULL)),
  CHECK (effective_to IS NULL OR effective_to >= effective_from),
  UNIQUE (id,organization_id)
);
CREATE INDEX IF NOT EXISTS idx_eci_components_employee ON employee_cost_components(organization_id,employee_id,effective_from,effective_to);
CREATE INDEX IF NOT EXISTS idx_eci_components_department ON employee_cost_components(organization_id,department_id,effective_from,effective_to);

CREATE TABLE IF NOT EXISTS employee_cost_snapshots (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL,
  period_start TEXT NOT NULL,
  currency TEXT NOT NULL CHECK (length(currency)=3),
  gross_minor INTEGER NOT NULL CHECK (gross_minor>=0),
  statutory_minor INTEGER NOT NULL CHECK (statutory_minor>=0),
  benefits_minor INTEGER NOT NULL CHECK (benefits_minor>=0),
  operations_minor INTEGER NOT NULL CHECK (operations_minor>=0),
  total_minor INTEGER NOT NULL CHECK (total_minor>=0),
  captured_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (employee_id,organization_id) REFERENCES employees(id,organization_id) ON DELETE CASCADE,
  UNIQUE (organization_id,employee_id,period_start,currency)
);
CREATE INDEX IF NOT EXISTS idx_eci_snapshots_period ON employee_cost_snapshots(organization_id,period_start,currency);

CREATE TABLE IF NOT EXISTS employee_cost_compensation_history (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL,
  base_salary REAL NOT NULL CHECK (base_salary>=0),
  currency TEXT NOT NULL CHECK (length(currency)=3),
  pay_frequency TEXT NOT NULL,
  effective_from TEXT NOT NULL,
  effective_to TEXT NOT NULL,
  recorded_by TEXT NOT NULL REFERENCES users(id),
  recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (employee_id,organization_id) REFERENCES employees(id,organization_id) ON DELETE CASCADE,
  CHECK (effective_to>=effective_from),
  UNIQUE (organization_id,employee_id,effective_from)
);
CREATE INDEX IF NOT EXISTS idx_eci_compensation_history ON employee_cost_compensation_history(organization_id,employee_id,effective_from DESC);

CREATE TABLE IF NOT EXISTS employer_contribution_rules (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  country_code TEXT NOT NULL CHECK (length(country_code)=2),
  name TEXT NOT NULL,
  basis TEXT NOT NULL CHECK (basis IN ('base_salary','gross_compensation')),
  rate_bps INTEGER NOT NULL CHECK (rate_bps BETWEEN 0 AND 10000),
  cap_minor INTEGER CHECK (cap_minor IS NULL OR cap_minor >= 0),
  effective_from TEXT NOT NULL,
  effective_to TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','superseded','rejected')),
  created_by TEXT NOT NULL REFERENCES users(id),
  approved_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (effective_to IS NULL OR effective_to >= effective_from),
  UNIQUE (id,organization_id)
);
CREATE INDEX IF NOT EXISTS idx_eci_contribution_rules ON employer_contribution_rules(organization_id,country_code,status,effective_from);

CREATE TABLE IF NOT EXISTS workforce_budgets (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  department_id TEXT,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  currency TEXT NOT NULL CHECK (length(currency)=3),
  budget_minor INTEGER NOT NULL CHECK (budget_minor >= 0),
  headcount_target INTEGER CHECK (headcount_target IS NULL OR headcount_target >= 0),
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending','approved','rejected','superseded')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
  notes TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  approved_by TEXT REFERENCES users(id),
  approved_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (department_id,organization_id) REFERENCES departments(id,organization_id) ON DELETE CASCADE,
  CHECK (period_end >= period_start),
  UNIQUE (id,organization_id)
);
CREATE INDEX IF NOT EXISTS idx_eci_budgets_period ON workforce_budgets(organization_id,currency,status,period_start,period_end);
CREATE INDEX IF NOT EXISTS idx_eci_budgets_department ON workforce_budgets(organization_id,department_id,period_start);

CREATE TABLE IF NOT EXISTS workforce_budget_versions (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  budget_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  budget_minor INTEGER NOT NULL CHECK (budget_minor >= 0),
  headcount_target INTEGER,
  notes TEXT,
  changed_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (budget_id,organization_id) REFERENCES workforce_budgets(id,organization_id) ON DELETE CASCADE,
  UNIQUE (organization_id,budget_id,version)
);

CREATE TABLE IF NOT EXISTS hiring_scenarios (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  currency TEXT NOT NULL CHECK (length(currency)=3),
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending','approved','rejected')),
  assumptions_json TEXT NOT NULL DEFAULT '{}',
  result_json TEXT NOT NULL DEFAULT '{}',
  created_by TEXT NOT NULL REFERENCES users(id),
  approved_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (id,organization_id)
);
CREATE TABLE IF NOT EXISTS hiring_scenario_items (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scenario_id TEXT NOT NULL,
  department_id TEXT,
  job_title TEXT NOT NULL,
  location TEXT,
  employment_type TEXT NOT NULL DEFAULT 'full_time',
  proposed_salary_minor INTEGER NOT NULL CHECK (proposed_salary_minor >= 0),
  cadence TEXT NOT NULL CHECK (cadence IN ('monthly','annual')),
  start_date TEXT NOT NULL,
  benefits_minor INTEGER NOT NULL DEFAULT 0 CHECK (benefits_minor >= 0),
  equipment_minor INTEGER NOT NULL DEFAULT 0 CHECK (equipment_minor >= 0),
  recruitment_minor INTEGER NOT NULL DEFAULT 0 CHECK (recruitment_minor >= 0),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (scenario_id,organization_id) REFERENCES hiring_scenarios(id,organization_id) ON DELETE CASCADE,
  FOREIGN KEY (department_id,organization_id) REFERENCES departments(id,organization_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_eci_hiring_scenario ON hiring_scenario_items(organization_id,scenario_id);

CREATE TABLE IF NOT EXISTS workforce_forecasts (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  currency TEXT NOT NULL CHECK (length(currency)=3),
  horizon_months INTEGER NOT NULL CHECK (horizon_months IN (3,6,12,24,36)),
  scenario TEXT NOT NULL CHECK (scenario IN ('baseline','optimistic','conservative')),
  assumptions_json TEXT NOT NULL,
  projection_json TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO permissions(id,code,description) VALUES
 ('perm-eci-view-aggregate','eci.view.aggregate','View organization workforce cost aggregates'),
 ('perm-eci-view-profiles','eci.view.profiles','View employee-level employment costs'),
 ('perm-eci-manage','eci.manage','Manage employee cost adjustments and configurations'),
 ('perm-eci-department-view','eci.department.view','View own department workforce cost aggregates'),
 ('perm-eci-self-view','eci.self.view','View own authorized employment cost summary'),
 ('perm-eci-budget-manage','eci.budget.manage','Create and revise workforce budgets and hiring scenarios'),
 ('perm-eci-budget-approve','eci.budget.approve','Approve workforce budgets and hiring scenarios'),
 ('perm-eci-config-manage','eci.config.manage','Configure statutory contribution rules and cost settings'),
 ('perm-eci-report-export','eci.report.export','Export workforce cost reports');

INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('eci.view.aggregate','eci.view.profiles','eci.manage','eci.budget.manage','eci.config.manage','eci.report.export') WHERE r.name='HR Admin';
INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('eci.view.aggregate','eci.view.profiles','eci.manage','eci.budget.manage','eci.config.manage','eci.budget.approve','eci.report.export') WHERE r.name IN ('Admin','Organization Admin');
INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('eci.view.aggregate','eci.budget.manage','eci.budget.approve','eci.report.export') WHERE r.name IN ('CEO','Finance Admin');
INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('eci.department.view') WHERE r.name='Manager';
INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('eci.self.view') WHERE r.name='Employee';
