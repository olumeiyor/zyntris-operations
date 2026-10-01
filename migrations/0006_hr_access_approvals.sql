ALTER TABLE employees ADD COLUMN onboarding_status TEXT NOT NULL DEFAULT 'active'
  CHECK (onboarding_status IN ('active','invited','declined'));

CREATE TABLE IF NOT EXISTS employee_invites (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  accepted_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO permissions (id, code, description) VALUES
  ('perm-hr-approve', 'hr.onboarding.approve', 'Approve employee onboarding'),
  ('perm-roles-manage', 'roles.manage', 'Assign organization access roles'),
  ('perm-teams-manage', 'teams.manage', 'Manage departments and teams'),
  ('perm-operations-view', 'operations.view', 'View organization operations modules'),
  ('perm-operations-manage', 'operations.manage', 'Manage organization operations modules'),
  ('perm-payroll-self-view', 'payroll.self.view', 'View own finalized payslips');

INSERT OR IGNORE INTO roles (id, organization_id, name, description, is_system)
SELECT 'role-' || substr(o.id, 5) || '-hr-admin', o.id, 'HR Admin', 'Manage employee records, teams and onboarding', 1 FROM organizations o;
INSERT OR IGNORE INTO roles (id, organization_id, name, description, is_system)
SELECT 'role-' || substr(o.id, 5) || '-ceo', o.id, 'CEO', 'Executive review and final approval authority', 1 FROM organizations o;
INSERT OR IGNORE INTO roles (id, organization_id, name, description, is_system)
SELECT 'role-' || substr(o.id, 5) || '-finance-admin', o.id, 'Finance Admin', 'Manage finance operations and approvals', 1 FROM organizations o;
INSERT OR IGNORE INTO roles (id, organization_id, name, description, is_system)
SELECT 'role-' || substr(o.id, 5) || '-manager', o.id, 'Manager', 'Manage team work and submit approvals', 1 FROM organizations o;
INSERT OR IGNORE INTO roles (id, organization_id, name, description, is_system)
SELECT 'role-' || substr(o.id, 5) || '-employee', o.id, 'Employee', 'Standard employee workspace access', 1 FROM organizations o;

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN
  ('employees.view','employees.manage','payroll.view','payroll.manage','payroll.run','hr.onboarding.approve','roles.manage','teams.manage','operations.view')
WHERE r.name = 'HR Admin';
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN
  ('employees.view','payroll.view','payroll.approve','requests.manage','hr.onboarding.approve','operations.view','operations.manage','expenses.view','expenses.manage')
WHERE r.name = 'CEO';
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN
  ('payroll.view','payroll.run','payroll.approve','expenses.view','expenses.manage','requests.manage','operations.view','operations.manage')
WHERE r.name = 'Finance Admin';
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN ('employees.view','operations.view','expenses.view','payroll.self.view')
WHERE r.name = 'Employee';
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN ('employees.view','operations.view','operations.manage','expenses.view','requests.manage','payroll.self.view')
WHERE r.name = 'Manager';

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN ('hr.onboarding.approve','roles.manage','teams.manage')
WHERE r.name = 'Organization Admin';
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN ('operations.view','operations.manage')
WHERE r.name = 'Organization Admin';
