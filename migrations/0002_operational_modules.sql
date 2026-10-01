PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS approval_requests (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  request_type TEXT NOT NULL,
  source_record_id TEXT,
  title TEXT NOT NULL,
  requester_id TEXT NOT NULL REFERENCES users(id),
  amount REAL,
  currency TEXT NOT NULL DEFAULT 'NGN',
  required_role TEXT NOT NULL DEFAULT 'Organization Admin',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'paid', 'cancelled')),
  current_step INTEGER NOT NULL DEFAULT 1,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_tag TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  serial_number TEXT,
  status TEXT NOT NULL DEFAULT 'available' CHECK (status IN ('available', 'assigned', 'maintenance', 'retired')),
  assigned_employee_id TEXT REFERENCES employees(id),
  location TEXT,
  purchase_date TEXT,
  purchase_price REAL NOT NULL DEFAULT 0,
  current_value REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, asset_tag)
);

CREATE TABLE IF NOT EXISTS asset_history (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  employee_id TEXT REFERENCES employees(id),
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vendors (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  contact_name TEXT,
  email TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'review', 'expired')),
  contract_end TEXT,
  spend REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS support_tickets (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  ticket_number TEXT NOT NULL,
  subject TEXT NOT NULL,
  category TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'assigned', 'in_progress', 'resolved', 'closed')),
  requester_id TEXT NOT NULL REFERENCES users(id),
  assignee_id TEXT REFERENCES users(id),
  description TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id, ticket_number)
);

CREATE TABLE IF NOT EXISTS calendar_events (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  event_type TEXT NOT NULL,
  start_at TEXT NOT NULL,
  end_at TEXT NOT NULL,
  location TEXT,
  owner_id TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  company TEXT,
  email TEXT,
  stage TEXT NOT NULL DEFAULT 'lead' CHECK (stage IN ('lead', 'qualified', 'proposal', 'negotiation', 'won', 'lost')),
  value REAL NOT NULL DEFAULT 0,
  owner_id TEXT REFERENCES users(id),
  last_activity_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS budgets (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  period TEXT NOT NULL,
  allocated REAL NOT NULL DEFAULT 0,
  spent REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'on_track',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_requests_tenant_status ON approval_requests(organization_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_assets_tenant_status ON assets(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_vendors_tenant_status ON vendors(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_tickets_tenant_status ON support_tickets(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_events_tenant_start ON calendar_events(organization_id, start_at);
CREATE INDEX IF NOT EXISTS idx_customers_tenant_stage ON customers(organization_id, stage);

INSERT OR IGNORE INTO approval_requests (id, organization_id, request_type, source_record_id, title, requester_id, amount, currency, required_role, status, created_at)
SELECT 'request-expense-001', organization_id, 'Expense', id, description, 'user-demo', amount, currency, 'Finance Admin', status, created_at FROM expenses WHERE id = 'expense-001';
INSERT OR IGNORE INTO approval_requests (id, organization_id, request_type, source_record_id, title, requester_id, amount, currency, required_role, status, created_at)
SELECT 'request-expense-002', organization_id, 'Expense', id, description, 'user-demo', amount, currency, 'Finance Admin', status, created_at FROM expenses WHERE id = 'expense-002';
INSERT OR IGNORE INTO approval_requests (id, organization_id, request_type, source_record_id, title, requester_id, amount, currency, required_role, status, created_at)
SELECT 'request-expense-003', organization_id, 'Expense', id, description, 'user-demo', amount, currency, 'Finance Admin', status, created_at FROM expenses WHERE id = 'expense-003';

INSERT OR IGNORE INTO assets (id, organization_id, asset_tag, name, category, serial_number, status, assigned_employee_id, location, purchase_price, current_value) VALUES
  ('asset-001', 'org-demo', 'AST-0104', 'MacBook Pro 14-inch', 'Laptop', 'C02ZX1A0MD6T', 'assigned', 'emp-daniel', 'Lagos / Remote', 2200000, 1850000),
  ('asset-002', 'org-demo', 'AST-0105', 'Dell UltraSharp Monitor', 'Equipment', 'CN0D35P7', 'available', NULL, 'Lagos office', 500000, 420000),
  ('asset-003', 'org-demo', 'AST-0106', 'iPhone 15 Pro', 'Mobile', 'F2LQW0D5', 'maintenance', 'emp-fatima', 'Lagos office', 1500000, 1280000);

INSERT OR IGNORE INTO vendors (id, organization_id, name, category, contact_name, email, status, contract_end, spend) VALUES
  ('vendor-001', 'org-demo', 'Cloudline Systems', 'Technology', 'Mariam Yusuf', 'mariam@cloudline.example', 'active', '2026-12-31', 6200000),
  ('vendor-002', 'org-demo', 'Cedar People Partners', 'Professional services', 'Kelechi Umeh', 'kelechi@cedar.example', 'review', '2026-10-15', 1850000),
  ('vendor-003', 'org-demo', 'Workplace House', 'Facilities', 'Tosin Adebayo', 'tosin@workplace.example', 'expired', '2026-08-30', 940000);

INSERT OR IGNORE INTO support_tickets (id, organization_id, ticket_number, subject, category, priority, status, requester_id, assignee_id, created_at) VALUES
  ('ticket-001', 'org-demo', 'ZD-1042', 'Unable to access payroll folder', 'IT', 'high', 'in_progress', 'user-demo', 'user-demo', '2026-09-28 09:35:00'),
  ('ticket-002', 'org-demo', 'ZD-1041', 'Update emergency contact details', 'HR', 'medium', 'assigned', 'user-demo', 'user-demo', '2026-09-28 08:00:00'),
  ('ticket-003', 'org-demo', 'ZD-1040', 'Request a second monitor', 'Facilities', 'low', 'open', 'user-demo', NULL, '2026-09-27 12:00:00');

INSERT OR IGNORE INTO calendar_events (id, organization_id, title, event_type, start_at, end_at, location, owner_id) VALUES
  ('event-001', 'org-demo', 'Product leadership sync', 'Meeting', '2026-09-28 09:30:00', '2026-09-28 10:15:00', 'Google Meet', 'user-demo'),
  ('event-002', 'org-demo', 'Nneka on annual leave', 'Leave', '2026-09-28 00:00:00', '2026-10-02 23:59:00', '', 'user-demo'),
  ('event-003', 'org-demo', 'Security awareness training', 'Training', '2026-09-29 14:00:00', '2026-09-29 15:00:00', 'Training room', 'user-demo');

INSERT OR IGNORE INTO customers (id, organization_id, name, company, email, stage, value, owner_id, last_activity_at) VALUES
  ('customer-001', 'org-demo', 'Maya Okoro', 'Northstar Foods', 'maya@northstar.example', 'proposal', 4200000, 'user-demo', '2026-09-28'),
  ('customer-002', 'org-demo', 'Chidi Nwankwo', 'Fieldstone Logistics', 'chidi@fieldstone.example', 'qualified', 1800000, 'user-demo', '2026-09-27'),
  ('customer-003', 'org-demo', 'Aisha Bello', 'Sundial Energy', 'aisha@sundial.example', 'won', 7600000, 'user-demo', '2026-09-18');

INSERT OR IGNORE INTO budgets (id, organization_id, name, category, period, allocated, spent, status) VALUES
  ('budget-001', 'org-demo', 'People & culture', 'People', 'Q4 2026', 12000000, 7600000, 'on_track'),
  ('budget-002', 'org-demo', 'Technology operations', 'Technology', 'Q4 2026', 28000000, 22400000, 'watch'),
  ('budget-003', 'org-demo', 'Customer growth', 'Sales & Marketing', 'Q4 2026', 18000000, 9200000, 'on_track');
