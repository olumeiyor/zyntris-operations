ALTER TABLE organization_settings ADD COLUMN expense_max_amount REAL;
ALTER TABLE organization_settings ADD COLUMN expense_receipt_required INTEGER NOT NULL DEFAULT 0;
ALTER TABLE customers ADD COLUMN won_at TEXT;

UPDATE customers
SET won_at = COALESCE(last_activity_at, created_at)
WHERE stage = 'won' AND won_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_expenses_org_date ON expenses(organization_id, expense_date);
CREATE INDEX IF NOT EXISTS idx_customers_org_won ON customers(organization_id, stage, won_at);
