CREATE TABLE IF NOT EXISTS goals (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  parent_goal_id TEXT REFERENCES goals(id) ON DELETE SET NULL,
  level TEXT NOT NULL CHECK (level IN ('company', 'department', 'team', 'individual')),
  department_id TEXT REFERENCES departments(id) ON DELETE SET NULL,
  team_id TEXT REFERENCES teams(id) ON DELETE SET NULL,
  owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  description TEXT,
  start_date TEXT,
  due_date TEXT,
  weight INTEGER NOT NULL DEFAULT 100 CHECK (weight BETWEEN 1 AND 100),
  progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
  status TEXT NOT NULL DEFAULT 'not_started' CHECK (status IN ('not_started', 'in_progress', 'at_risk', 'completed', 'cancelled')),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS goal_key_results (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  goal_id TEXT NOT NULL REFERENCES goals(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  unit TEXT NOT NULL DEFAULT '%',
  target_value REAL NOT NULL DEFAULT 100,
  current_value REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS announcements (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  target_type TEXT NOT NULL CHECK (target_type IN ('all', 'department', 'team', 'employee')),
  target_id TEXT,
  status TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('draft', 'published', 'archived')),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS announcement_reads (
  announcement_id TEXT NOT NULL REFERENCES announcements(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  read_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (announcement_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_goals_org_scope ON goals(organization_id, level, status, due_date);
CREATE INDEX IF NOT EXISTS idx_goal_results_goal ON goal_key_results(organization_id, goal_id);
CREATE INDEX IF NOT EXISTS idx_announcements_org_date ON announcements(organization_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_announcement_reads_user ON announcement_reads(user_id, read_at);

INSERT OR IGNORE INTO permissions (id, code, description) VALUES
  ('perm-goals-view', 'goals.view', 'View goals and key results'),
  ('perm-goals-manage', 'goals.manage', 'Create and manage organization goals'),
  ('perm-announcements-view', 'announcements.view', 'View targeted organization announcements'),
  ('perm-announcements-manage', 'announcements.manage', 'Publish and manage organization announcements');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN ('goals.view','announcements.view')
WHERE r.name IN ('Organization Admin','HR Admin','CEO','Finance Admin','Manager','Employee');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN ('goals.manage','announcements.manage')
WHERE r.name IN ('Organization Admin','HR Admin','CEO');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code = 'goals.manage'
WHERE r.name = 'Manager';
