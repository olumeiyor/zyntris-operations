ALTER TABLE customers ADD COLUMN customer_status TEXT NOT NULL DEFAULT 'prospect' CHECK (customer_status IN ('prospect','active','inactive','dormant','former'));
ALTER TABLE customers ADD COLUMN industry TEXT;
ALTER TABLE customers ADD COLUMN website TEXT;
ALTER TABLE customers ADD COLUMN phone TEXT;
ALTER TABLE customers ADD COLUMN country TEXT;
ALTER TABLE customers ADD COLUMN city TEXT;
ALTER TABLE customers ADD COLUMN source TEXT;
ALTER TABLE customers ADD COLUMN updated_by TEXT REFERENCES users(id);

CREATE TABLE IF NOT EXISTS crm_lead_sources (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,name)
);
CREATE TABLE IF NOT EXISTS crm_leads (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  lead_number TEXT NOT NULL,
  name TEXT NOT NULL,
  company TEXT,
  email TEXT,
  phone TEXT,
  website TEXT,
  industry TEXT,
  country TEXT,
  region TEXT,
  source TEXT,
  interest TEXT,
  estimated_value REAL NOT NULL DEFAULT 0 CHECK (estimated_value >= 0),
  currency TEXT NOT NULL DEFAULT 'NGN',
  owner_id TEXT REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','contacted','qualified','converted','disqualified')),
  temperature TEXT NOT NULL DEFAULT 'cold' CHECK (temperature IN ('hot','warm','cold')),
  score INTEGER NOT NULL DEFAULT 0 CHECK (score BETWEEN 0 AND 100),
  description TEXT,
  tags_json TEXT NOT NULL DEFAULT '[]',
  converted_customer_id TEXT REFERENCES customers(id),
  converted_opportunity_id TEXT,
  created_by TEXT REFERENCES users(id),
  updated_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_activity_at TEXT,
  next_follow_up_at TEXT,
  UNIQUE(organization_id,lead_number)
);
CREATE INDEX IF NOT EXISTS idx_crm_leads_tenant_status_created ON crm_leads(organization_id,status,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_crm_leads_owner_status ON crm_leads(organization_id,owner_id,status);
CREATE INDEX IF NOT EXISTS idx_crm_leads_email ON crm_leads(organization_id,email);
CREATE INDEX IF NOT EXISTS idx_crm_leads_company ON crm_leads(organization_id,company);

CREATE TABLE IF NOT EXISTS crm_opportunities (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  opportunity_number TEXT NOT NULL,
  name TEXT NOT NULL,
  customer_id TEXT REFERENCES customers(id),
  lead_id TEXT REFERENCES crm_leads(id),
  owner_id TEXT REFERENCES users(id),
  stage TEXT NOT NULL DEFAULT 'qualification' CHECK (stage IN ('qualification','discovery','proposal','negotiation','won','lost')),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','won','lost')),
  value REAL NOT NULL DEFAULT 0 CHECK (value >= 0),
  currency TEXT NOT NULL DEFAULT 'NGN',
  probability INTEGER NOT NULL DEFAULT 10 CHECK (probability BETWEEN 0 AND 100),
  expected_close_date TEXT,
  source TEXT,
  product TEXT,
  priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low','medium','high','urgent')),
  description TEXT,
  loss_reason TEXT,
  won_at TEXT,
  lost_at TEXT,
  created_by TEXT REFERENCES users(id),
  updated_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_activity_at TEXT,
  UNIQUE(organization_id,opportunity_number)
);
CREATE INDEX IF NOT EXISTS idx_crm_opportunities_stage_close ON crm_opportunities(organization_id,status,stage,expected_close_date);
CREATE INDEX IF NOT EXISTS idx_crm_opportunities_owner ON crm_opportunities(organization_id,owner_id,status);
CREATE INDEX IF NOT EXISTS idx_crm_opportunities_customer ON crm_opportunities(organization_id,customer_id);

CREATE TABLE IF NOT EXISTS crm_pipeline_stages (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  stage_key TEXT NOT NULL,
  name TEXT NOT NULL,
  probability INTEGER NOT NULL DEFAULT 0 CHECK (probability BETWEEN 0 AND 100),
  sort_order INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  UNIQUE(organization_id,stage_key),
  UNIQUE(organization_id,name)
);

CREATE TABLE IF NOT EXISTS crm_activities (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  activity_type TEXT NOT NULL CHECK (activity_type IN ('call','email','meeting','task','follow_up','demo','presentation','site_visit','note')),
  subject TEXT NOT NULL,
  description TEXT,
  owner_id TEXT REFERENCES users(id),
  lead_id TEXT REFERENCES crm_leads(id) ON DELETE CASCADE,
  customer_id TEXT REFERENCES customers(id) ON DELETE CASCADE,
  opportunity_id TEXT REFERENCES crm_opportunities(id) ON DELETE CASCADE,
  starts_at TEXT,
  due_at TEXT,
  priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low','medium','high','urgent')),
  status TEXT NOT NULL DEFAULT 'planned' CHECK (status IN ('planned','in_progress','completed','cancelled')),
  outcome TEXT,
  reminder_sent_at TEXT,
  overdue_notified_at TEXT,
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (lead_id IS NOT NULL OR customer_id IS NOT NULL OR opportunity_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_crm_activities_due ON crm_activities(organization_id,owner_id,status,due_at);
CREATE INDEX IF NOT EXISTS idx_crm_activities_lead ON crm_activities(organization_id,lead_id,due_at);
CREATE INDEX IF NOT EXISTS idx_crm_activities_opportunity ON crm_activities(organization_id,opportunity_id,due_at);

CREATE TABLE IF NOT EXISTS crm_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processed','failed')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  processed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_crm_events_pending ON crm_events(organization_id,status,created_at);

INSERT OR IGNORE INTO crm_lead_sources (id,organization_id,name)
SELECT 'crm-source-' || substr(o.id,1,32) || '-' || lower(replace(s.name,' ','-')), o.id, s.name
FROM organizations o CROSS JOIN (SELECT 'Website' name UNION ALL SELECT 'Referral' UNION ALL SELECT 'Social Media' UNION ALL SELECT 'LinkedIn' UNION ALL SELECT 'Event' UNION ALL SELECT 'Webinar' UNION ALL SELECT 'Advertisement' UNION ALL SELECT 'Email Campaign' UNION ALL SELECT 'Direct Outreach' UNION ALL SELECT 'Partner' UNION ALL SELECT 'Existing Customer' UNION ALL SELECT 'Walk-in' UNION ALL SELECT 'Other') s;

INSERT OR IGNORE INTO crm_pipeline_stages (id,organization_id,stage_key,name,probability,sort_order)
SELECT 'crm-stage-' || substr(o.id,1,28) || '-' || s.stage_key,o.id,s.stage_key,s.name,s.probability,s.sort_order FROM organizations o
CROSS JOIN (SELECT 'qualification' stage_key,'Qualification' name,10 probability,1 sort_order UNION ALL SELECT 'discovery','Discovery',25,2 UNION ALL SELECT 'proposal','Proposal',50,3 UNION ALL SELECT 'negotiation','Negotiation',75,4 UNION ALL SELECT 'won','Won',100,5 UNION ALL SELECT 'lost','Lost',0,6) s;

INSERT OR IGNORE INTO permissions (id,code,description) VALUES
 ('perm-crm-view','crm.view','View authorized CRM records'),
 ('perm-crm-view-all','crm.view.all','View organization-wide CRM records and analytics'),
 ('perm-crm-manage','crm.manage','Create and edit CRM leads, opportunities and activities'),
 ('perm-crm-assign','crm.assign','Assign and reassign CRM records'),
 ('perm-crm-configure','crm.configure','Configure CRM sources, scoring and pipeline settings'),
 ('perm-crm-report','crm.report','View and export CRM reports');
INSERT OR IGNORE INTO roles (id,organization_id,name,description,is_system)
SELECT 'crm-role-' || substr(o.id,1,28) || '-crm-admin',o.id,'CRM Admin','Configure CRM and manage organization CRM data',1 FROM organizations o;
INSERT OR IGNORE INTO roles (id,organization_id,name,description,is_system)
SELECT 'crm-role-' || substr(o.id,1,28) || '-sales-manager',o.id,'Sales Manager','Manage organization sales pipeline and CRM reporting',1 FROM organizations o;
INSERT OR IGNORE INTO roles (id,organization_id,name,description,is_system)
SELECT 'crm-role-' || substr(o.id,1,28) || '-sales-rep',o.id,'Sales Representative','Manage assigned leads, opportunities and activities',1 FROM organizations o;
INSERT OR IGNORE INTO roles (id,organization_id,name,description,is_system)
SELECT 'crm-role-' || substr(o.id,1,28) || '-crm-exec',o.id,'CRM Executive','View organization-wide CRM performance and reports',1 FROM organizations o;
INSERT OR IGNORE INTO roles (id,organization_id,name,description,is_system)
SELECT 'crm-role-' || substr(o.id,1,28) || '-crm-viewer',o.id,'CRM Viewer','Read authorized CRM records',1 FROM organizations o;
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
WHERE r.name='Organization Admin' AND p.code IN ('crm.view','crm.view.all','crm.manage','crm.assign','crm.configure','crm.report');
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
WHERE r.name='CEO' AND p.code IN ('crm.view','crm.view.all','crm.report');
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
WHERE r.name IN ('Manager','HR Admin') AND p.code IN ('crm.view','crm.manage','crm.assign');
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
WHERE r.name='CRM Admin' AND p.code IN ('crm.view','crm.view.all','crm.manage','crm.assign','crm.configure','crm.report');
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
WHERE r.name='Sales Manager' AND p.code IN ('crm.view','crm.view.all','crm.manage','crm.assign','crm.report');
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
WHERE r.name='Sales Representative' AND p.code IN ('crm.view','crm.manage');
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
WHERE r.name='CRM Executive' AND p.code IN ('crm.view','crm.view.all','crm.report');
INSERT OR IGNORE INTO role_permissions (role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
WHERE r.name='CRM Viewer' AND p.code='crm.view';
