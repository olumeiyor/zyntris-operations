CREATE TABLE IF NOT EXISTS hr_compliance_items (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  title TEXT NOT NULL, item_type TEXT NOT NULL CHECK(item_type IN ('policy','training','certification')),
  description TEXT NOT NULL DEFAULT '', due_date TEXT, created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS hr_compliance_assignments (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  item_id TEXT NOT NULL REFERENCES hr_compliance_items(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'assigned' CHECK(status IN ('assigned','acknowledged','completed','expired')),
  evidence_note TEXT NOT NULL DEFAULT '', expires_on TEXT, completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(organization_id,item_id,employee_id)
);
CREATE TABLE IF NOT EXISTS hr_cases (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  case_type TEXT NOT NULL CHECK(case_type IN ('grievance','conduct','wellbeing','accommodation','investigation','other')),
  title TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'submitted' CHECK(status IN ('submitted','reviewing','action_required','resolved','closed')),
  assigned_user_id TEXT REFERENCES users(id), resolution_note TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS hr_compensation_cycles (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL, period_start TEXT NOT NULL, period_end TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','open','review','approved','closed')),
  created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS hr_compensation_reviews (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  cycle_id TEXT NOT NULL REFERENCES hr_compensation_cycles(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  proposed_salary REAL, proposed_bonus REAL, currency TEXT NOT NULL DEFAULT 'NGN', rationale TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'proposed' CHECK(status IN ('proposed','approved','declined','applied')),
  reviewed_by TEXT REFERENCES users(id), reviewed_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,cycle_id,employee_id)
);
CREATE TABLE IF NOT EXISTS hr_personnel_records (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE, title TEXT NOT NULL,
  record_type TEXT NOT NULL CHECK(record_type IN ('offer','contract','policy','form','other')),
  document_id TEXT REFERENCES documents(id) ON DELETE SET NULL, due_date TEXT,
  created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS hr_personnel_acknowledgements (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  record_id TEXT NOT NULL REFERENCES hr_personnel_records(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  response TEXT NOT NULL CHECK(response IN ('acknowledged','declined')), note TEXT NOT NULL DEFAULT '',
  responded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(organization_id,record_id,employee_id)
);
CREATE TABLE IF NOT EXISTS hr_employee_skills (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE, skill TEXT NOT NULL,
  proficiency INTEGER NOT NULL CHECK(proficiency BETWEEN 1 AND 5), evidence TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL REFERENCES users(id), updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,employee_id,skill)
);
CREATE TABLE IF NOT EXISTS hr_succession_plans (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  critical_role TEXT NOT NULL, successor_employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  readiness TEXT NOT NULL CHECK(readiness IN ('ready_now','1_2_years','2_5_years','development_needed')),
  development_notes TEXT NOT NULL DEFAULT '', reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_by TEXT NOT NULL REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS hr_benefit_plans (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL, provider TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
  enrollment_opens TEXT, enrollment_closes TEXT, status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','archived')),
  created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,name)
);
CREATE TABLE IF NOT EXISTS hr_benefit_elections (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  plan_id TEXT NOT NULL REFERENCES hr_benefit_plans(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'requested' CHECK(status IN ('requested','active','declined','ended')),
  employee_note TEXT NOT NULL DEFAULT '', reviewed_by TEXT REFERENCES users(id), reviewed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(organization_id,plan_id,employee_id)
);
CREATE INDEX IF NOT EXISTS idx_hr_compliance_assignments_tenant_employee ON hr_compliance_assignments(organization_id,employee_id,status);
CREATE INDEX IF NOT EXISTS idx_hr_cases_tenant_employee ON hr_cases(organization_id,employee_id,status);
CREATE INDEX IF NOT EXISTS idx_hr_comp_reviews_tenant_cycle ON hr_compensation_reviews(organization_id,cycle_id,status);
CREATE INDEX IF NOT EXISTS idx_hr_personnel_tenant_employee ON hr_personnel_records(organization_id,employee_id);
CREATE INDEX IF NOT EXISTS idx_hr_skills_tenant_employee ON hr_employee_skills(organization_id,employee_id);
CREATE INDEX IF NOT EXISTS idx_hr_succession_tenant_role ON hr_succession_plans(organization_id,critical_role);
CREATE INDEX IF NOT EXISTS idx_hr_benefit_elections_tenant_employee ON hr_benefit_elections(organization_id,employee_id,status);
