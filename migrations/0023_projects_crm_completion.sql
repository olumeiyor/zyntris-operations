-- Projects portfolio, governance, client access and CRM completion models.
CREATE TABLE IF NOT EXISTS project_portfolios (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  owner_id TEXT REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','closed')),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,name)
);
CREATE TABLE IF NOT EXISTS project_programmes (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  portfolio_id TEXT REFERENCES project_portfolios(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  description TEXT,
  owner_id TEXT REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','completed','closed')),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,name)
);
ALTER TABLE projects ADD COLUMN portfolio_id TEXT REFERENCES project_portfolios(id);
ALTER TABLE projects ADD COLUMN programme_id TEXT REFERENCES project_programmes(id);
ALTER TABLE projects ADD COLUMN budget_minor INTEGER CHECK (budget_minor IS NULL OR budget_minor >= 0);
ALTER TABLE projects ADD COLUMN expected_revenue_minor INTEGER NOT NULL DEFAULT 0 CHECK (expected_revenue_minor >= 0);
UPDATE projects SET budget_minor=CAST(ROUND(COALESCE(budget,0)*100) AS INTEGER), expected_revenue_minor=CAST(ROUND(COALESCE(expected_revenue,0)*100) AS INTEGER);
CREATE INDEX IF NOT EXISTS idx_projects_portfolio ON projects(organization_id,portfolio_id,status);

CREATE TABLE IF NOT EXISTS module_subscriptions (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  module_key TEXT NOT NULL,
  plan_code TEXT NOT NULL DEFAULT 'manual',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','paused','cancelled','expired')),
  billing_contact TEXT,
  requested_by TEXT REFERENCES users(id),
  activated_by TEXT REFERENCES users(id),
  starts_at TEXT,
  ends_at TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,module_key)
);

ALTER TABLE crm_leads ADD COLUMN estimated_value_minor INTEGER NOT NULL DEFAULT 0 CHECK (estimated_value_minor >= 0);
UPDATE crm_leads SET estimated_value_minor=CAST(ROUND(estimated_value*100) AS INTEGER);
ALTER TABLE crm_opportunities ADD COLUMN value_minor INTEGER NOT NULL DEFAULT 0 CHECK (value_minor >= 0);
UPDATE crm_opportunities SET value_minor=CAST(ROUND(value*100) AS INTEGER);

CREATE TABLE IF NOT EXISTS project_change_requests (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  approval_request_id TEXT REFERENCES approval_requests(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  reason TEXT NOT NULL,
  scope_impact TEXT,
  schedule_impact_days INTEGER NOT NULL DEFAULT 0,
  budget_impact_minor INTEGER NOT NULL DEFAULT 0,
  resource_impact TEXT,
  risk_impact TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','submitted','approved','rejected','implemented')),
  requested_by TEXT NOT NULL REFERENCES users(id),
  reviewed_by TEXT REFERENCES users(id),
  reviewed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_project_changes_status ON project_change_requests(organization_id,project_id,status);

CREATE TABLE IF NOT EXISTS project_meetings (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  location TEXT,
  agenda TEXT,
  minutes TEXT,
  decisions TEXT,
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS project_meeting_attendees (
  meeting_id TEXT NOT NULL REFERENCES project_meetings(id) ON DELETE CASCADE,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  response TEXT NOT NULL DEFAULT 'invited' CHECK (response IN ('invited','accepted','declined')),
  PRIMARY KEY(meeting_id,user_id)
);
CREATE TABLE IF NOT EXISTS project_decisions (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  decision TEXT NOT NULL,
  context TEXT,
  reason TEXT,
  impact TEXT,
  decision_maker_id TEXT NOT NULL REFERENCES users(id),
  decided_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS project_templates (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  methodology TEXT,
  template_json TEXT NOT NULL DEFAULT '{}',
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,name)
);
CREATE TABLE IF NOT EXISTS project_client_portal_tokens (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_project_portal_active ON project_client_portal_tokens(token_hash,expires_at,revoked_at);

CREATE TABLE IF NOT EXISTS crm_contacts (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  customer_id TEXT REFERENCES customers(id) ON DELETE CASCADE,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  job_title TEXT,
  department TEXT,
  email TEXT,
  phone TEXT,
  alternative_phone TEXT,
  linkedin_url TEXT,
  decision_maker INTEGER NOT NULL DEFAULT 0 CHECK (decision_maker IN (0,1)),
  influence_level TEXT CHECK (influence_level IN ('low','medium','high')),
  preferred_communication TEXT,
  notes TEXT,
  tags_json TEXT NOT NULL DEFAULT '[]',
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_crm_contacts_company ON crm_contacts(organization_id,customer_id);
CREATE TABLE IF NOT EXISTS crm_products (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  code TEXT,
  description TEXT,
  currency TEXT NOT NULL DEFAULT 'NGN',
  price_minor INTEGER NOT NULL DEFAULT 0 CHECK (price_minor >= 0),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,name)
);
CREATE TABLE IF NOT EXISTS crm_quotations (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  quote_number TEXT NOT NULL,
  customer_id TEXT REFERENCES customers(id),
  opportunity_id TEXT REFERENCES crm_opportunities(id),
  contact_id TEXT REFERENCES crm_contacts(id),
  currency TEXT NOT NULL DEFAULT 'NGN',
  subtotal_minor INTEGER NOT NULL DEFAULT 0 CHECK (subtotal_minor >= 0),
  tax_minor INTEGER NOT NULL DEFAULT 0 CHECK (tax_minor >= 0),
  total_minor INTEGER NOT NULL DEFAULT 0 CHECK (total_minor >= 0),
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','sent','accepted','rejected','expired')),
  valid_until TEXT,
  notes TEXT,
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,quote_number)
);
CREATE TABLE IF NOT EXISTS crm_quotation_lines (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  quotation_id TEXT NOT NULL REFERENCES crm_quotations(id) ON DELETE CASCADE,
  product_id TEXT REFERENCES crm_products(id),
  description TEXT NOT NULL,
  quantity_milli INTEGER NOT NULL DEFAULT 1000 CHECK (quantity_milli > 0),
  unit_price_minor INTEGER NOT NULL DEFAULT 0 CHECK (unit_price_minor >= 0),
  line_total_minor INTEGER NOT NULL DEFAULT 0 CHECK (line_total_minor >= 0)
);
CREATE TABLE IF NOT EXISTS crm_scoring_rules (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  factor_key TEXT NOT NULL,
  label TEXT NOT NULL,
  points INTEGER NOT NULL DEFAULT 0 CHECK (points BETWEEN 0 AND 100),
  condition_json TEXT NOT NULL DEFAULT '{}',
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  updated_by TEXT REFERENCES users(id),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,factor_key)
);
INSERT OR IGNORE INTO crm_scoring_rules(id,organization_id,factor_key,label,points,condition_json)
 SELECT 'score-'||substr(o.id,1,28)||'-'||r.factor_key,o.id,r.factor_key,r.label,r.points,r.condition_json
 FROM organizations o CROSS JOIN (
  SELECT 'has_email' factor_key,'Email available' label,15 points,'{}' condition_json UNION ALL
  SELECT 'has_phone','Phone available',10,'{}' UNION ALL
  SELECT 'has_company','Company identified',10,'{}' UNION ALL
  SELECT 'has_website','Website available',5,'{}' UNION ALL
  SELECT 'estimated_value_min','Estimated deal is at least ₦1,000,000',20,'{"min":1000000}' UNION ALL
  SELECT 'interest','Product/service interest recorded',10,'{}'
 ) r;
CREATE TABLE IF NOT EXISTS crm_sales_targets (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id TEXT REFERENCES users(id),
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  target_minor INTEGER NOT NULL CHECK (target_minor >= 0),
  currency TEXT NOT NULL DEFAULT 'NGN',
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(organization_id,user_id,period_start,period_end)
);

INSERT OR IGNORE INTO permissions (id,code,description) VALUES
 ('perm-projects-billing','projects.billing.manage','Manage project module entitlement and billing settings'),
 ('perm-projects-portal','projects.client_portal.manage','Manage read-only client portal access'),
 ('perm-crm-config','crm.configure','Configure CRM sources, stages and scoring rules'),
 ('perm-crm-quotes','crm.quotes.manage','Manage CRM products and quotations'),
 ('perm-crm-import','crm.import','Import and export CRM data');
INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
 SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name='Organization Admin' AND p.code IN ('projects.billing.manage','projects.client_portal.manage','crm.configure','crm.quotes.manage','crm.import');
INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
 SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name IN ('CRM Admin','Sales Manager') AND p.code IN ('crm.configure','crm.quotes.manage','crm.import');
INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
 SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name='Project Manager' AND p.code IN ('projects.client_portal.manage');
