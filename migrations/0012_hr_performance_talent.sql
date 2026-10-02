ALTER TABLE appraisals ADD COLUMN employee_decision TEXT CHECK (employee_decision IN ('accepted','declined'));
ALTER TABLE appraisals ADD COLUMN decision_note TEXT;
ALTER TABLE appraisals ADD COLUMN manager_recommendation TEXT;

CREATE TABLE IF NOT EXISTS performance_kpis (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  metric TEXT NOT NULL,
  target TEXT NOT NULL,
  weight INTEGER NOT NULL DEFAULT 100 CHECK (weight BETWEEN 1 AND 100),
  team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
  employee_id TEXT REFERENCES employees(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (team_id IS NULL OR employee_id IS NULL)
);
CREATE INDEX IF NOT EXISTS idx_performance_kpis_scope ON performance_kpis(organization_id, status, team_id, employee_id);

CREATE TABLE IF NOT EXISTS appraisal_kpi_scores (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  appraisal_id TEXT NOT NULL REFERENCES appraisals(id) ON DELETE CASCADE,
  kpi_id TEXT NOT NULL REFERENCES performance_kpis(id) ON DELETE CASCADE,
  self_rating INTEGER CHECK (self_rating BETWEEN 1 AND 5),
  self_result TEXT,
  manager_rating INTEGER CHECK (manager_rating BETWEEN 1 AND 5),
  manager_comment TEXT,
  UNIQUE (appraisal_id, kpi_id)
);
CREATE INDEX IF NOT EXISTS idx_appraisal_kpi_scores ON appraisal_kpi_scores(organization_id, appraisal_id);

CREATE TABLE IF NOT EXISTS appraisal_360_feedback (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  appraisal_id TEXT NOT NULL REFERENCES appraisals(id) ON DELETE CASCADE,
  respondent_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  relationship TEXT NOT NULL CHECK (relationship IN ('peer','direct_report','cross_functional')),
  status TEXT NOT NULL DEFAULT 'assigned' CHECK (status IN ('assigned','submitted')),
  feedback_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  submitted_at TEXT,
  UNIQUE (appraisal_id, respondent_user_id)
);
CREATE INDEX IF NOT EXISTS idx_appraisal_360_inbox ON appraisal_360_feedback(organization_id, respondent_user_id, status);

CREATE TABLE IF NOT EXISTS performance_improvement_plans (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  created_by TEXT NOT NULL REFERENCES users(id),
  manager_user_id TEXT REFERENCES users(id),
  title TEXT NOT NULL,
  concern TEXT NOT NULL,
  expected_outcomes TEXT NOT NULL,
  support_plan TEXT NOT NULL,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed','active','completed','extended','unsuccessful','cancelled')),
  outcome_note TEXT,
  employee_acknowledgment TEXT,
  acknowledged_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (end_date >= start_date)
);
CREATE INDEX IF NOT EXISTS idx_pips_tenant_status ON performance_improvement_plans(organization_id, status, end_date);

CREATE TABLE IF NOT EXISTS pip_check_ins (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  pip_id TEXT NOT NULL REFERENCES performance_improvement_plans(id) ON DELETE CASCADE,
  created_by TEXT NOT NULL REFERENCES users(id),
  check_in_date TEXT NOT NULL,
  progress TEXT NOT NULL,
  employee_comment TEXT,
  next_steps TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_pip_checkins ON pip_check_ins(organization_id, pip_id, check_in_date DESC);

CREATE TABLE IF NOT EXISTS job_requisitions (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  department_id TEXT REFERENCES departments(id),
  description TEXT NOT NULL,
  employment_type TEXT NOT NULL,
  location TEXT,
  headcount INTEGER NOT NULL DEFAULT 1 CHECK (headcount BETWEEN 1 AND 1000),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','on_hold','closed')),
  owner_user_id TEXT NOT NULL REFERENCES users(id),
  target_date TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_job_requisitions ON job_requisitions(organization_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS job_candidates (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  job_id TEXT NOT NULL REFERENCES job_requisitions(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT,
  source TEXT,
  stage TEXT NOT NULL DEFAULT 'applied' CHECK (stage IN ('applied','screening','interview','assessment','offer','hired','rejected')),
  notes TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_job_candidates ON job_candidates(organization_id, job_id, stage, created_at DESC);

CREATE TABLE IF NOT EXISTS learning_courses (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  provider TEXT,
  category TEXT NOT NULL DEFAULT 'Professional development',
  duration_hours REAL NOT NULL DEFAULT 0 CHECK (duration_hours >= 0),
  due_days INTEGER CHECK (due_days IS NULL OR due_days BETWEEN 1 AND 730),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, title)
);
CREATE TABLE IF NOT EXISTS learning_enrollments (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  course_id TEXT NOT NULL REFERENCES learning_courses(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  assigned_by TEXT NOT NULL REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'assigned' CHECK (status IN ('assigned','in_progress','completed','waived')),
  due_date TEXT,
  completed_at TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, course_id, employee_id)
);
CREATE INDEX IF NOT EXISTS idx_learning_enrollments ON learning_enrollments(organization_id, employee_id, status);

INSERT OR IGNORE INTO permissions (id, code, description) VALUES
  ('perm-hr-talent-view','hr.talent.view','View assigned employee development records'),
  ('perm-hr-talent-manage','hr.talent.manage','Manage HR teams, performance, recruitment and learning');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN ('hr.talent.view','hr.talent.manage')
WHERE r.name IN ('Organization Admin','HR Admin','CEO');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code = 'hr.talent.view'
WHERE r.name IN ('Manager','Employee');
