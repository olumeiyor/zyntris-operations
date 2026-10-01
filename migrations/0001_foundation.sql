PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  industry TEXT,
  logo_url TEXT,
  timezone TEXT NOT NULL DEFAULT 'Africa/Lagos',
  currency TEXT NOT NULL DEFAULT 'NGN',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'trial')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS organization_settings (
  organization_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  working_days_json TEXT NOT NULL DEFAULT '[1,2,3,4,5]',
  working_hours_json TEXT NOT NULL DEFAULT '{"start":"08:00","end":"17:00"}',
  fiscal_year_start TEXT NOT NULL DEFAULT '01-01',
  public_holidays_json TEXT NOT NULL DEFAULT '[]',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  avatar_url TEXT,
  password_hash TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'invited', 'suspended')),
  last_seen_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS roles (
  id TEXT PRIMARY KEY,
  organization_id TEXT REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  is_system INTEGER NOT NULL DEFAULT 0,
  UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS permissions (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS memberships (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id TEXT NOT NULL REFERENCES roles(id),
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS departments (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  head_user_id TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  department_id TEXT REFERENCES departments(id),
  name TEXT NOT NULL,
  lead_user_id TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS employees (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT REFERENCES users(id),
  employee_number TEXT NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  email TEXT NOT NULL,
  job_title TEXT NOT NULL,
  department_id TEXT REFERENCES departments(id),
  team_id TEXT REFERENCES teams(id),
  manager_id TEXT REFERENCES employees(id),
  employment_type TEXT NOT NULL DEFAULT 'Full-time',
  work_location TEXT NOT NULL DEFAULT 'Hybrid',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'on_leave', 'inactive')),
  start_date TEXT NOT NULL,
  avatar_color TEXT NOT NULL DEFAULT '#dbeafe',
  deleted_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, employee_number)
);

CREATE TABLE IF NOT EXISTS leave_types (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  days_per_year REAL NOT NULL DEFAULT 0,
  requires_approval INTEGER NOT NULL DEFAULT 1,
  UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS leave_requests (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id),
  leave_type_id TEXT NOT NULL REFERENCES leave_types(id),
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  days REAL NOT NULL,
  reason TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
  approver_id TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  owner_id TEXT REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'planning' CHECK (status IN ('planning', 'active', 'at_risk', 'completed', 'archived')),
  progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
  start_date TEXT,
  end_date TEXT,
  budget REAL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id),
  title TEXT NOT NULL,
  description TEXT,
  assignee_id TEXT REFERENCES employees(id),
  creator_id TEXT REFERENCES users(id),
  priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
  status TEXT NOT NULL DEFAULT 'todo' CHECK (status IN ('todo', 'in_progress', 'review', 'completed')),
  due_date TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS expenses (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id),
  category TEXT NOT NULL,
  amount REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'NGN',
  expense_date TEXT NOT NULL,
  description TEXT,
  receipt_key TEXT,
  status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted', 'approved', 'rejected', 'paid')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  owner_id TEXT REFERENCES employees(id),
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  r2_key TEXT NOT NULL UNIQUE,
  content_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  read_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  organization_id TEXT REFERENCES organizations(id) ON DELETE CASCADE,
  actor_user_id TEXT REFERENCES users(id),
  action TEXT NOT NULL,
  module TEXT NOT NULL,
  record_type TEXT,
  record_id TEXT,
  ip_address TEXT,
  previous_value_json TEXT,
  new_value_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  plan TEXT NOT NULL DEFAULT 'business' CHECK (plan IN ('starter', 'business', 'enterprise')),
  status TEXT NOT NULL DEFAULT 'trialing',
  employee_limit INTEGER NOT NULL DEFAULT 100,
  storage_limit_bytes INTEGER NOT NULL DEFAULT 10737418240,
  trial_ends_at TEXT,
  renews_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_employees_tenant_status ON employees(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_leave_tenant_status ON leave_requests(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_tasks_tenant_status ON tasks(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_expenses_tenant_status ON expenses(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, read_at);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_created ON audit_logs(organization_id, created_at);

INSERT OR IGNORE INTO organizations (id, name, slug, industry, status)
VALUES ('org-demo', 'Zyntris Technologies', 'zyntris-technologies', 'Technology', 'active');

INSERT OR IGNORE INTO organization_settings (organization_id) VALUES ('org-demo');
INSERT OR IGNORE INTO users (id, email, full_name, status) VALUES ('user-demo', 'admin@zyntris.org', 'Amaka Okafor', 'active');
INSERT OR IGNORE INTO roles (id, organization_id, name, description, is_system) VALUES
  ('role-org-admin', 'org-demo', 'Organization Admin', 'Full access to the organization workspace', 1),
  ('role-hr-admin', 'org-demo', 'HR Admin', 'People, leave, performance and learning access', 1),
  ('role-manager', 'org-demo', 'Manager', 'Team-level operational access', 1),
  ('role-finance', 'org-demo', 'Finance Admin', 'Expense and finance access', 1);

INSERT OR IGNORE INTO memberships (id, organization_id, user_id, role_id) VALUES ('membership-demo', 'org-demo', 'user-demo', 'role-org-admin');
INSERT OR IGNORE INTO departments (id, organization_id, name) VALUES
  ('dept-exec', 'org-demo', 'Executive'),
  ('dept-hr', 'org-demo', 'Human Resources'),
  ('dept-finance', 'org-demo', 'Finance'),
  ('dept-tech', 'org-demo', 'Technology'),
  ('dept-operations', 'org-demo', 'Operations'),
  ('dept-sales', 'org-demo', 'Sales & Marketing');

INSERT OR IGNORE INTO teams (id, organization_id, department_id, name) VALUES
  ('team-product', 'org-demo', 'dept-tech', 'Product & Engineering'),
  ('team-people', 'org-demo', 'dept-hr', 'People Operations'),
  ('team-growth', 'org-demo', 'dept-sales', 'Growth');

INSERT OR IGNORE INTO employees (id, organization_id, user_id, employee_number, first_name, last_name, email, job_title, department_id, team_id, employment_type, work_location, status, start_date, avatar_color) VALUES
  ('emp-amaka', 'org-demo', 'user-demo', 'EMP-1001', 'Amaka', 'Okafor', 'admin@zyntris.org', 'Chief Operations Officer', 'dept-exec', NULL, 'Full-time', 'Hybrid', 'active', '2022-01-10', '#dbeafe'),
  ('emp-daniel', 'org-demo', NULL, 'EMP-1002', 'Daniel', 'Adeyemi', 'daniel@zyntris.org', 'Engineering Lead', 'dept-tech', 'team-product', 'Full-time', 'Remote', 'active', '2023-04-17', '#dcfce7'),
  ('emp-nneka', 'org-demo', NULL, 'EMP-1003', 'Nneka', 'Eze', 'nneka@zyntris.org', 'People Partner', 'dept-hr', 'team-people', 'Full-time', 'On-site', 'on_leave', '2023-07-03', '#fce7f3'),
  ('emp-tunde', 'org-demo', NULL, 'EMP-1004', 'Tunde', 'Bello', 'tunde@zyntris.org', 'Product Designer', 'dept-tech', 'team-product', 'Full-time', 'Hybrid', 'active', '2024-02-12', '#fef3c7'),
  ('emp-fatima', 'org-demo', NULL, 'EMP-1005', 'Fatima', 'Musa', 'fatima@zyntris.org', 'Growth Manager', 'dept-sales', 'team-growth', 'Full-time', 'Hybrid', 'active', '2024-06-24', '#ede9fe'),
  ('emp-ifeanyi', 'org-demo', NULL, 'EMP-1006', 'Ifeanyi', 'Obi', 'ifeanyi@zyntris.org', 'Finance Analyst', 'dept-finance', NULL, 'Full-time', 'On-site', 'active', '2024-09-16', '#cffafe');

INSERT OR IGNORE INTO leave_types (id, organization_id, name, days_per_year) VALUES
  ('leave-annual', 'org-demo', 'Annual leave', 20),
  ('leave-sick', 'org-demo', 'Sick leave', 10),
  ('leave-personal', 'org-demo', 'Personal time', 5);

INSERT OR IGNORE INTO leave_requests (id, organization_id, employee_id, leave_type_id, start_date, end_date, days, reason, status) VALUES
  ('leave-001', 'org-demo', 'emp-nneka', 'leave-annual', '2026-09-28', '2026-10-02', 5, 'Family time', 'approved'),
  ('leave-002', 'org-demo', 'emp-tunde', 'leave-personal', '2026-10-05', '2026-10-06', 2, 'Personal appointment', 'pending');

INSERT OR IGNORE INTO projects (id, organization_id, name, description, owner_id, status, progress, start_date, end_date) VALUES
  ('project-platform', 'org-demo', 'Zyntris platform launch', 'Core SaaS foundation and customer pilot', 'user-demo', 'active', 68, '2026-07-01', '2026-11-30'),
  ('project-people', 'org-demo', 'People operations refresh', 'Modernise HR workflows and reporting', 'user-demo', 'at_risk', 42, '2026-08-15', '2026-10-31'),
  ('project-crm', 'org-demo', 'Customer success workspace', 'Unified customer and renewal view', 'user-demo', 'planning', 12, '2026-10-01', '2026-12-15');

INSERT OR IGNORE INTO tasks (id, organization_id, project_id, title, assignee_id, creator_id, priority, status, due_date) VALUES
  ('task-001', 'org-demo', 'project-platform', 'Finalize tenant isolation tests', 'emp-daniel', 'user-demo', 'urgent', 'in_progress', '2026-09-30'),
  ('task-002', 'org-demo', 'project-platform', 'Review onboarding flow', 'emp-tunde', 'user-demo', 'high', 'review', '2026-10-02'),
  ('task-003', 'org-demo', 'project-people', 'Publish 2026 leave calendar', 'emp-nneka', 'user-demo', 'medium', 'todo', '2026-10-01'),
  ('task-004', 'org-demo', 'project-crm', 'Define customer health score', 'emp-fatima', 'user-demo', 'low', 'todo', '2026-10-15');

INSERT OR IGNORE INTO expenses (id, organization_id, employee_id, category, amount, currency, expense_date, description, status) VALUES
  ('expense-001', 'org-demo', 'emp-daniel', 'Software', 185000, 'NGN', '2026-09-23', 'Developer tooling renewal', 'submitted'),
  ('expense-002', 'org-demo', 'emp-fatima', 'Travel', 420000, 'NGN', '2026-09-18', 'Customer workshop travel', 'approved'),
  ('expense-003', 'org-demo', 'emp-ifeanyi', 'Operations', 96000, 'NGN', '2026-09-16', 'Office supplies', 'paid');

INSERT OR IGNORE INTO notifications (id, organization_id, user_id, type, title, body) VALUES
  ('note-001', 'org-demo', 'user-demo', 'approval', '2 approvals need your attention', 'Leave and expense requests are waiting for review.'),
  ('note-002', 'org-demo', 'user-demo', 'project', 'Platform launch is 68% complete', 'The launch workspace has moved into its final delivery phase.'),
  ('note-003', 'org-demo', 'user-demo', 'document', '3 documents expire next month', 'Review employee and vendor documents before 31 October.');

INSERT OR IGNORE INTO subscriptions (id, organization_id, plan, status, employee_limit, trial_ends_at) VALUES
  ('subscription-demo', 'org-demo', 'business', 'trialing', 100, '2026-10-12');
