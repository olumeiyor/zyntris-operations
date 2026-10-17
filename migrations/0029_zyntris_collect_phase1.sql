-- Zyntris Collect Phase 1: AR foundation. Monetary values are stored as
-- integer minor units; FX rates are text to avoid binary floating-point loss.
CREATE TABLE IF NOT EXISTS collect_legal_entities (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  registration_number TEXT,
  tax_identifier TEXT,
  country TEXT NOT NULL DEFAULT 'NG',
  base_currency TEXT NOT NULL DEFAULT 'NGN' CHECK (length(base_currency) = 3 AND base_currency = upper(base_currency)),
  billing_address TEXT,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, name),
  UNIQUE (id, organization_id)
);
CREATE INDEX IF NOT EXISTS idx_collect_entities_org_active ON collect_legal_entities(organization_id, active, name);

CREATE TABLE IF NOT EXISTS collect_customer_profiles (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  customer_type TEXT NOT NULL DEFAULT 'business' CHECK (customer_type IN ('business','individual','government','nonprofit','other')),
  registration_number TEXT,
  tax_identifier TEXT,
  country TEXT,
  currency TEXT NOT NULL DEFAULT 'NGN' CHECK (length(currency) = 3 AND currency = upper(currency)),
  billing_address TEXT,
  payment_terms_days INTEGER NOT NULL DEFAULT 30 CHECK (payment_terms_days BETWEEN 0 AND 365),
  credit_limit_minor INTEGER NOT NULL DEFAULT 0 CHECK (credit_limit_minor >= 0),
  account_manager_id TEXT REFERENCES users(id),
  collector_user_id TEXT REFERENCES users(id),
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, customer_id),
  UNIQUE (id, organization_id)
);
CREATE INDEX IF NOT EXISTS idx_collect_customer_profiles_org_collector ON collect_customer_profiles(organization_id, collector_user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_id_org_collect_fk ON customers(id, organization_id);

CREATE TABLE IF NOT EXISTS collect_invoices (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  legal_entity_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  invoice_number TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','sent','open','due_soon','overdue','partially_paid','paid','disputed','written_off','cancelled')),
  transaction_currency TEXT NOT NULL CHECK (length(transaction_currency) = 3 AND transaction_currency = upper(transaction_currency)),
  transaction_subtotal_minor INTEGER NOT NULL CHECK (transaction_subtotal_minor >= 0),
  transaction_tax_minor INTEGER NOT NULL DEFAULT 0 CHECK (transaction_tax_minor >= 0),
  transaction_discount_minor INTEGER NOT NULL DEFAULT 0 CHECK (transaction_discount_minor >= 0),
  transaction_total_minor INTEGER NOT NULL CHECK (transaction_total_minor >= 0),
  transaction_paid_minor INTEGER NOT NULL DEFAULT 0 CHECK (transaction_paid_minor >= 0),
  paid_at TEXT,
  base_currency TEXT NOT NULL CHECK (length(base_currency) = 3 AND base_currency = upper(base_currency)),
  base_total_minor INTEGER NOT NULL CHECK (base_total_minor >= 0),
  base_paid_minor INTEGER NOT NULL DEFAULT 0 CHECK (base_paid_minor >= 0),
  exchange_rate TEXT NOT NULL DEFAULT '1',
  exchange_rate_at TEXT,
  invoice_date TEXT NOT NULL,
  due_date TEXT NOT NULL,
  payment_terms_days INTEGER NOT NULL DEFAULT 30 CHECK (payment_terms_days BETWEEN 0 AND 365),
  purchase_order TEXT,
  notes TEXT,
  collector_user_id TEXT REFERENCES users(id),
  created_by TEXT NOT NULL REFERENCES users(id),
  sent_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (due_date >= invoice_date),
  CHECK (transaction_total_minor = transaction_subtotal_minor + transaction_tax_minor - transaction_discount_minor),
  CHECK (transaction_discount_minor <= transaction_subtotal_minor + transaction_tax_minor),
  CHECK (transaction_paid_minor <= transaction_total_minor),
  UNIQUE (organization_id, legal_entity_id, invoice_number),
  UNIQUE (id, organization_id),
  FOREIGN KEY (legal_entity_id, organization_id) REFERENCES collect_legal_entities(id, organization_id),
  FOREIGN KEY (customer_id, organization_id) REFERENCES customers(id, organization_id)
);
CREATE INDEX IF NOT EXISTS idx_collect_invoices_org_status_due ON collect_invoices(organization_id, status, due_date);
CREATE INDEX IF NOT EXISTS idx_collect_invoices_org_customer ON collect_invoices(organization_id, customer_id, invoice_date DESC);
CREATE INDEX IF NOT EXISTS idx_collect_invoices_org_collector ON collect_invoices(organization_id, collector_user_id, due_date);

CREATE TABLE IF NOT EXISTS collect_invoice_items (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  invoice_id TEXT NOT NULL,
  description TEXT NOT NULL,
  quantity_milli INTEGER NOT NULL CHECK (quantity_milli > 0),
  unit_price_minor INTEGER NOT NULL CHECK (unit_price_minor >= 0),
  tax_rate_bps INTEGER NOT NULL DEFAULT 0 CHECK (tax_rate_bps BETWEEN 0 AND 10000),
  discount_minor INTEGER NOT NULL DEFAULT 0 CHECK (discount_minor >= 0),
  line_subtotal_minor INTEGER NOT NULL CHECK (line_subtotal_minor >= 0),
  line_tax_minor INTEGER NOT NULL CHECK (line_tax_minor >= 0),
  line_total_minor INTEGER NOT NULL CHECK (line_total_minor >= 0),
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (invoice_id, organization_id) REFERENCES collect_invoices(id, organization_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_collect_invoice_items_invoice ON collect_invoice_items(organization_id, invoice_id, sort_order);

CREATE TABLE IF NOT EXISTS collect_idempotency_keys (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  idempotency_key TEXT NOT NULL,
  operation TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  response_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (organization_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS collect_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  event_key TEXT NOT NULL,
  event_type TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  processing_status TEXT NOT NULL DEFAULT 'pending' CHECK (processing_status IN ('pending','processing','processed','failed')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  processed_at TEXT,
  UNIQUE (organization_id, event_key)
);
CREATE INDEX IF NOT EXISTS idx_collect_events_pending ON collect_events(processing_status, occurred_at);

INSERT OR IGNORE INTO collect_legal_entities (id, organization_id, name, country, base_currency)
SELECT 'collect-entity-default-' || id, id, name, 'NG', upper(currency) FROM organizations;

INSERT OR IGNORE INTO organization_modules (organization_id, module_key, enabled, features_json)
SELECT id, 'collect', 1, '{"invoices":true,"receivables":true,"customers":true,"dashboard":true}' FROM organizations;

INSERT OR IGNORE INTO permissions (id, code, description) VALUES
  ('perm-collect-view', 'collect.view', 'View assigned receivables and Collect dashboards'),
  ('perm-collect-view-all', 'collect.view.all', 'View organization-wide receivables and customers'),
  ('perm-collect-manage', 'collect.manage', 'Manage customers, legal entities and invoices'),
  ('perm-collect-invoice-create', 'collect.invoice.create', 'Create invoices'),
  ('perm-collect-export', 'collect.export', 'Export Collect financial reports');

INSERT OR IGNORE INTO roles (id, organization_id, name, description, is_system)
SELECT 'role-collect-manager-' || lower(hex(randomblob(10))), id, 'Collections Manager', 'Manage organization receivables and invoice workflows', 1 FROM organizations;
INSERT OR IGNORE INTO roles (id, organization_id, name, description, is_system)
SELECT 'role-collector-' || lower(hex(randomblob(10))), id, 'Collector', 'Work assigned customer accounts and receivables', 1 FROM organizations;
INSERT OR IGNORE INTO roles (id, organization_id, name, description, is_system)
SELECT 'role-collect-analyst-' || lower(hex(randomblob(10))), id, 'Finance Analyst', 'Analyze organization receivables and collections reports', 1 FROM organizations;
INSERT OR IGNORE INTO roles (id, organization_id, name, description, is_system)
SELECT 'role-collect-auditor-' || lower(hex(randomblob(10))), id, 'Viewer/Auditor', 'Read-only access to organization Collect records', 1 FROM organizations;

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN ('collect.view','collect.view.all','collect.manage','collect.invoice.create','collect.export')
WHERE r.name IN ('Organization Admin','Finance Admin','Collections Manager');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN ('collect.view','collect.view.all')
WHERE r.name IN ('CEO','Finance Analyst','Viewer/Auditor');
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code IN ('collect.view','collect.invoice.create')
WHERE r.name = 'Collector';
