CREATE TABLE IF NOT EXISTS organization_modules (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  module_key TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  features_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (organization_id,module_key)
);
INSERT OR IGNORE INTO organization_modules (organization_id,module_key,enabled,features_json)
SELECT id,'projects',1,'{"portfolios":false,"programmes":false,"gantt":false,"timesheets":true,"budgets":true,"risks":true,"client_portal":false,"advanced_reports":false,"ai":false}' FROM organizations;
INSERT OR IGNORE INTO organization_modules (organization_id,module_key,enabled,features_json)
SELECT id,'crm',1,'{}' FROM organizations;

ALTER TABLE projects ADD COLUMN project_code TEXT;
ALTER TABLE projects ADD COLUMN project_manager_id TEXT REFERENCES users(id);
ALTER TABLE projects ADD COLUMN sponsor_id TEXT REFERENCES users(id);
ALTER TABLE projects ADD COLUMN department_id TEXT REFERENCES departments(id);
ALTER TABLE projects ADD COLUMN methodology TEXT;
ALTER TABLE projects ADD COLUMN priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low','medium','high','urgent'));
ALTER TABLE projects ADD COLUMN health TEXT NOT NULL DEFAULT 'green' CHECK (health IN ('green','amber','red'));
ALTER TABLE projects ADD COLUMN currency TEXT NOT NULL DEFAULT 'NGN';
ALTER TABLE projects ADD COLUMN expected_revenue REAL NOT NULL DEFAULT 0 CHECK (expected_revenue >= 0);
ALTER TABLE projects ADD COLUMN actual_end_date TEXT;
ALTER TABLE projects ADD COLUMN objectives TEXT;
ALTER TABLE projects ADD COLUMN scope TEXT;
ALTER TABLE projects ADD COLUMN out_of_scope TEXT;
ALTER TABLE projects ADD COLUMN expected_outcomes TEXT;
ALTER TABLE projects ADD COLUMN success_criteria TEXT;
ALTER TABLE projects ADD COLUMN created_by TEXT REFERENCES users(id);
ALTER TABLE projects ADD COLUMN updated_by TEXT REFERENCES users(id);
ALTER TABLE projects ADD COLUMN archived_at TEXT;
UPDATE projects SET project_code='PRJ-' || upper(substr(replace(id,'project-',''),1,10)) WHERE project_code IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_org_code ON projects(organization_id,project_code);
CREATE INDEX IF NOT EXISTS idx_projects_owner_status ON projects(organization_id,owner_id,status);

CREATE TABLE IF NOT EXISTS project_members (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  project_role TEXT NOT NULL DEFAULT 'member',
  allocation_percent INTEGER NOT NULL DEFAULT 100 CHECK (allocation_percent BETWEEN 1 AND 100),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,project_id,employee_id)
);
CREATE INDEX IF NOT EXISTS idx_project_members_employee ON project_members(organization_id,employee_id);

CREATE TABLE IF NOT EXISTS project_phases (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  start_date TEXT,
  end_date TEXT,
  status TEXT NOT NULL DEFAULT 'planned' CHECK (status IN ('planned','active','completed','cancelled')),
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_project_phases_project ON project_phases(organization_id,project_id,sort_order);
ALTER TABLE tasks ADD COLUMN start_date TEXT;
ALTER TABLE tasks ADD COLUMN phase_id TEXT REFERENCES project_phases(id) ON DELETE SET NULL;
ALTER TABLE tasks ADD COLUMN progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100);
ALTER TABLE tasks ADD COLUMN estimated_hours REAL;
ALTER TABLE tasks ADD COLUMN actual_hours REAL NOT NULL DEFAULT 0;
ALTER TABLE tasks ADD COLUMN blocked_flag INTEGER NOT NULL DEFAULT 0 CHECK (blocked_flag IN (0,1));
CREATE INDEX IF NOT EXISTS idx_tasks_project_status_due ON tasks(organization_id,project_id,status,due_date);
CREATE TABLE IF NOT EXISTS task_dependencies (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  depends_on_task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  dependency_type TEXT NOT NULL DEFAULT 'finish_to_start' CHECK (dependency_type IN ('finish_to_start','start_to_start','finish_to_finish','start_to_finish')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK(task_id <> depends_on_task_id),
  UNIQUE(organization_id,task_id,depends_on_task_id)
);
CREATE INDEX IF NOT EXISTS idx_task_dependencies_dependent ON task_dependencies(organization_id,depends_on_task_id);
CREATE TABLE IF NOT EXISTS task_comments (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id),
  comment TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS project_milestones (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  owner_id TEXT REFERENCES users(id),
  target_date TEXT NOT NULL,
  completed_at TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','in_progress','completed','cancelled')),
  deliverables_json TEXT NOT NULL DEFAULT '[]',
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_project_milestones_due ON project_milestones(organization_id,project_id,status,target_date);

CREATE TABLE IF NOT EXISTS project_risks (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT,
  category TEXT NOT NULL DEFAULT 'general',
  probability INTEGER NOT NULL DEFAULT 3 CHECK (probability BETWEEN 1 AND 5),
  impact INTEGER NOT NULL DEFAULT 3 CHECK (impact BETWEEN 1 AND 5),
  owner_id TEXT REFERENCES users(id),
  mitigation TEXT,
  contingency TEXT,
  due_date TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','mitigating','accepted','closed')),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_project_risks_project_status ON project_risks(organization_id,project_id,status);
CREATE TABLE IF NOT EXISTS project_issues (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low','medium','high','critical')),
  owner_id TEXT REFERENCES users(id),
  resolution_plan TEXT,
  target_date TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','resolving','resolved','closed')),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_project_issues_project_status ON project_issues(organization_id,project_id,status);

CREATE TABLE IF NOT EXISTS project_timesheets (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  task_id TEXT REFERENCES tasks(id) ON DELETE SET NULL,
  employee_id TEXT NOT NULL REFERENCES employees(id),
  work_date TEXT NOT NULL,
  hours REAL NOT NULL CHECK (hours > 0 AND hours <= 24),
  billable INTEGER NOT NULL DEFAULT 0 CHECK (billable IN (0,1)),
  description TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','submitted','approved','rejected')),
  reviewed_by TEXT REFERENCES users(id),
  reviewed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_project_timesheets_review ON project_timesheets(organization_id,project_id,status,work_date);

CREATE TABLE IF NOT EXISTS project_budget_lines (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  description TEXT,
  allocated INTEGER NOT NULL DEFAULT 0 CHECK (allocated >= 0),
  committed INTEGER NOT NULL DEFAULT 0 CHECK (committed >= 0),
  actual INTEGER NOT NULL DEFAULT 0 CHECK (actual >= 0),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_project_budget_lines_project ON project_budget_lines(organization_id,project_id);

CREATE TABLE IF NOT EXISTS project_health_history (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  health TEXT NOT NULL CHECK (health IN ('green','amber','red')),
  reason TEXT,
  recorded_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO permissions (id,code,description) VALUES
 ('perm-projects-view','projects.view','View authorized projects'),
 ('perm-projects-view-all','projects.view.all','View all organization projects'),
 ('perm-projects-create','projects.create','Create projects'),
 ('perm-projects-edit','projects.edit','Edit projects'),
 ('perm-projects-manage','projects.manage','Manage project teams, plans and governance'),
 ('perm-projects-approve','projects.approve','Approve project proposals and changes'),
 ('perm-projects-close','projects.close','Close projects'),
 ('perm-projects-reports','projects.reports','View project reports'),
 ('perm-projects-timesheet-approve','timesheets.approve','Approve submitted project timesheets'),
 ('perm-projects-risk-manage','risks.manage','Manage project risks and issues');
INSERT OR IGNORE INTO roles (id,organization_id,name,description,is_system)
SELECT 'project-role-' || substr(o.id,1,25) || '-manager',o.id,'Project Manager','Manage assigned project delivery',1 FROM organizations o;
INSERT OR IGNORE INTO roles (id,organization_id,name,description,is_system)
SELECT 'project-role-' || substr(o.id,1,25) || '-member',o.id,'Project Member','Contribute to assigned project work',1 FROM organizations o;
INSERT OR IGNORE INTO roles (id,organization_id,name,description,is_system)
SELECT 'project-role-' || substr(o.id,1,25) || '-portfolio',o.id,'Portfolio Manager','Manage portfolios and organization project reporting',1 FROM organizations o;
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name='Organization Admin' AND p.code IN ('projects.view','projects.create','projects.edit','projects.manage','projects.approve','projects.close','projects.reports','timesheets.approve','risks.manage');
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name IN ('Manager','CEO') AND p.code IN ('projects.view','projects.create','projects.edit','projects.manage','projects.approve','projects.reports','timesheets.approve','risks.manage');
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name='Project Manager' AND p.code IN ('projects.view','projects.view.all','projects.create','projects.edit','projects.manage','projects.approve','projects.close','projects.reports','timesheets.approve','risks.manage');
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name='Project Member' AND p.code='projects.view';
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name='Portfolio Manager' AND p.code IN ('projects.view','projects.view.all','projects.create','projects.edit','projects.manage','projects.approve','projects.reports','timesheets.approve','risks.manage');
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name IN ('Organization Admin','Manager','CEO') AND p.code='projects.view.all';
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name IN ('Employee','HR Admin','Finance Admin') AND p.code='projects.view';
