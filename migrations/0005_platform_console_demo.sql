ALTER TABLE organizations ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0, 1));
ALTER TABLE sessions ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0, 1));

UPDATE organizations SET is_demo = 1 WHERE id = 'org-demo';
UPDATE subscriptions SET status = 'active', trial_ends_at = NULL WHERE organization_id = 'org-demo';

INSERT OR IGNORE INTO users (id, email, full_name, status, email_verified_at)
VALUES ('usr-zyntris-demo', 'demo@demo.zyntris.invalid', 'Zyntris Demo Viewer', 'active', CURRENT_TIMESTAMP);

INSERT OR IGNORE INTO roles (id, organization_id, name, description, is_system)
VALUES ('role-demo-viewer', 'org-demo', 'Demo Viewer', 'Read-only access to fictional sandbox records', 1);

INSERT OR IGNORE INTO memberships (id, organization_id, user_id, role_id)
VALUES ('membership-demo-viewer', 'org-demo', 'usr-zyntris-demo', 'role-demo-viewer');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT 'role-demo-viewer', id FROM permissions WHERE code IN ('payroll.view', 'employees.view', 'expenses.view');

INSERT OR IGNORE INTO payroll_settings
  (organization_id, currency, pay_frequency, tax_country, tax_region, tax_year, tax_free_allowance, tax_bands_json, employee_pension_rate, employer_pension_rate, pension_basis)
VALUES
  ('org-demo', 'NGN', 'monthly', 'NG', 'Lagos (sample)', 2026, 0,
   '[{"upTo":300000,"rate":0.07},{"upTo":1000000,"rate":0.11},{"upTo":null,"rate":0.18}]', 0.08, 0.10, 'base_salary');

INSERT OR IGNORE INTO employee_pay_profiles
  (id, organization_id, employee_id, base_salary, currency, pay_frequency, effective_from, status)
VALUES
  ('demo-pay-daniel', 'org-demo', 'emp-daniel', 1250000, 'NGN', 'monthly', '2026-01-01', 'active'),
  ('demo-pay-nneka', 'org-demo', 'emp-nneka', 920000, 'NGN', 'monthly', '2026-01-01', 'active');

INSERT OR IGNORE INTO payroll_components (id, organization_id, code, name, kind, taxable, pensionable)
VALUES
  ('demo-component-housing', 'org-demo', 'HOUSING', 'Housing allowance (sample)', 'earning', 1, 0),
  ('demo-component-loan', 'org-demo', 'LOAN', 'Staff loan repayment (sample)', 'deduction', 0, 0);

INSERT OR IGNORE INTO employee_pay_components
  (id, organization_id, employee_id, component_id, amount, effective_from)
VALUES
  ('demo-line-daniel-housing', 'org-demo', 'emp-daniel', 'demo-component-housing', 150000, '2026-01-01'),
  ('demo-line-nneka-housing', 'org-demo', 'emp-nneka', 'demo-component-housing', 100000, '2026-01-01'),
  ('demo-line-nneka-loan', 'org-demo', 'emp-nneka', 'demo-component-loan', 25000, '2026-01-01');

INSERT OR IGNORE INTO payroll_runs
  (id, organization_id, period_start, period_end, payment_date, currency, status, employee_count, gross_total, deductions_total, employer_cost_total, net_total, created_by)
VALUES
  ('demo-payroll-run-2026-08', 'org-demo', '2026-08-01', '2026-08-31', '2026-08-31', 'NGN', 'reviewed', 2, 2420000, 443000, 217000, 1977000, 'usr-zyntris-demo');

INSERT OR IGNORE INTO payroll_run_items
  (id, organization_id, payroll_run_id, employee_id, employee_number, employee_name, job_title, base_salary, gross_pay, taxable_pay, paye_tax, employee_pension, employer_pension, other_deductions, employer_contributions, net_pay, breakdown_json)
VALUES
  ('demo-pay-item-daniel', 'org-demo', 'demo-payroll-run-2026-08', 'emp-daniel', 'EMP-1002', 'Daniel Adeyemi', 'Engineering Lead', 1250000, 1400000, 1400000, 150000, 100000, 125000, 0, 0, 1150000, '{"lines":[{"code":"HOUSING","name":"Housing allowance (sample)","kind":"earning","amount":150000}]}'),
  ('demo-pay-item-nneka', 'org-demo', 'demo-payroll-run-2026-08', 'emp-nneka', 'EMP-1003', 'Nneka Eze', 'People Partner', 920000, 1020000, 1020000, 94400, 73600, 92000, 25000, 0, 827000, '{"lines":[{"code":"HOUSING","name":"Housing allowance (sample)","kind":"earning","amount":100000},{"code":"LOAN","name":"Staff loan repayment (sample)","kind":"deduction","amount":25000}]}');

CREATE INDEX IF NOT EXISTS idx_org_demo_created ON organizations(is_demo, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_created_global ON audit_logs(created_at DESC);
