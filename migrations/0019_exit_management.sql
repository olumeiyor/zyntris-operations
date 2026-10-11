CREATE TABLE IF NOT EXISTS employee_exit_cases (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id),
  manager_id TEXT REFERENCES employees(id),
  separation_type TEXT NOT NULL CHECK (separation_type IN ('resignation','retirement','end_of_contract','redundancy','termination','other')),
  reason TEXT NOT NULL,
  notice_date TEXT NOT NULL,
  last_working_date TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','completed','cancelled')),
  exit_interview_date TEXT,
  exit_interview_notes TEXT,
  employee_feedback TEXT,
  final_salary REAL NOT NULL DEFAULT 0 CHECK (final_salary >= 0),
  leave_payout REAL NOT NULL DEFAULT 0 CHECK (leave_payout >= 0),
  deductions REAL NOT NULL DEFAULT 0 CHECK (deductions >= 0),
  outstanding_balance REAL NOT NULL DEFAULT 0 CHECK (outstanding_balance >= 0),
  finance_notes TEXT,
  reference_documents TEXT,
  initiated_by TEXT NOT NULL REFERENCES users(id),
  completed_by TEXT REFERENCES users(id),
  completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_employee_exit_one_active
  ON employee_exit_cases(organization_id, employee_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_employee_exit_org_status
  ON employee_exit_cases(organization_id, status, last_working_date);

CREATE TABLE IF NOT EXISTS employee_exit_tasks (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  exit_case_id TEXT NOT NULL REFERENCES employee_exit_cases(id) ON DELETE CASCADE,
  category TEXT NOT NULL CHECK (category IN ('employee','manager','hr','it','finance')),
  title TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed','waived')),
  notes TEXT,
  completed_by TEXT REFERENCES users(id),
  completed_at TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_employee_exit_tasks_case
  ON employee_exit_tasks(organization_id, exit_case_id, sort_order);
