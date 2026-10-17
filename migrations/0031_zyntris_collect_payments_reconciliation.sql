-- Phase 3: record incoming funds and reconcile imported bank statement lines.
CREATE TABLE IF NOT EXISTS collect_payments (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  customer_id TEXT NOT NULL,
  payment_reference TEXT,
  amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
  currency TEXT NOT NULL CHECK (length(currency)=3 AND currency=upper(currency)),
  paid_date TEXT NOT NULL,
  method TEXT NOT NULL CHECK (method IN ('bank_transfer','cash','cheque','card','provider','other')),
  source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','provider','bank_import')),
  status TEXT NOT NULL DEFAULT 'confirmed' CHECK (status IN ('confirmed','voided')),
  notes TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (customer_id,organization_id) REFERENCES customers(id,organization_id),
  UNIQUE (organization_id,payment_reference),
  UNIQUE (id,organization_id)
);
CREATE INDEX IF NOT EXISTS idx_collect_payments_customer_date ON collect_payments(organization_id,customer_id,paid_date DESC);

CREATE TABLE IF NOT EXISTS collect_payment_allocations (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  payment_id TEXT NOT NULL,
  invoice_id TEXT NOT NULL,
  amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
  base_amount_minor INTEGER NOT NULL CHECK (base_amount_minor >= 0),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (payment_id,organization_id) REFERENCES collect_payments(id,organization_id),
  FOREIGN KEY (invoice_id,organization_id) REFERENCES collect_invoices(id,organization_id),
  UNIQUE (organization_id,payment_id,invoice_id)
);
CREATE INDEX IF NOT EXISTS idx_collect_allocations_invoice ON collect_payment_allocations(organization_id,invoice_id);

CREATE TRIGGER IF NOT EXISTS trg_collect_allocation_validate
BEFORE INSERT ON collect_payment_allocations
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM collect_payments p JOIN collect_invoices i
      ON i.id=NEW.invoice_id AND i.organization_id=NEW.organization_id
    WHERE p.id=NEW.payment_id AND p.organization_id=NEW.organization_id
      AND p.status='confirmed' AND p.customer_id=i.customer_id AND p.currency=i.transaction_currency
  ) THEN RAISE(ABORT,'payment allocation customer or currency mismatch') END;
  SELECT CASE WHEN NEW.amount_minor + COALESCE((SELECT SUM(amount_minor) FROM collect_payment_allocations WHERE organization_id=NEW.organization_id AND payment_id=NEW.payment_id),0) >
    (SELECT amount_minor FROM collect_payments WHERE id=NEW.payment_id AND organization_id=NEW.organization_id)
    THEN RAISE(ABORT,'payment allocation exceeds payment amount') END;
  SELECT CASE WHEN NEW.amount_minor + (SELECT transaction_paid_minor FROM collect_invoices WHERE id=NEW.invoice_id AND organization_id=NEW.organization_id) >
    (SELECT transaction_total_minor FROM collect_invoices WHERE id=NEW.invoice_id AND organization_id=NEW.organization_id)
    THEN RAISE(ABORT,'payment allocation exceeds invoice balance') END;
  SELECT CASE WHEN NEW.base_amount_minor + (SELECT base_paid_minor FROM collect_invoices WHERE id=NEW.invoice_id AND organization_id=NEW.organization_id) >
    (SELECT base_total_minor FROM collect_invoices WHERE id=NEW.invoice_id AND organization_id=NEW.organization_id)
    THEN RAISE(ABORT,'base payment allocation exceeds invoice base balance') END;
END;

CREATE TRIGGER IF NOT EXISTS trg_collect_allocation_apply
AFTER INSERT ON collect_payment_allocations
BEGIN
  UPDATE collect_invoices SET
    transaction_paid_minor=transaction_paid_minor+NEW.amount_minor,
    base_paid_minor=base_paid_minor+NEW.base_amount_minor,
    status=CASE WHEN status='disputed' THEN status WHEN transaction_paid_minor+NEW.amount_minor=transaction_total_minor THEN 'paid' ELSE 'partially_paid' END,
    paid_at=CASE WHEN transaction_paid_minor+NEW.amount_minor=transaction_total_minor THEN CURRENT_TIMESTAMP ELSE paid_at END,
    updated_at=CURRENT_TIMESTAMP
  WHERE id=NEW.invoice_id AND organization_id=NEW.organization_id;
END;

CREATE TABLE IF NOT EXISTS collect_bank_transactions (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  bank_reference TEXT NOT NULL,
  payer_name TEXT,
  invoice_reference TEXT,
  amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
  currency TEXT NOT NULL CHECK (length(currency)=3 AND currency=upper(currency)),
  transaction_date TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'unmatched' CHECK (status IN ('unmatched','matched','ignored')),
  imported_by TEXT NOT NULL REFERENCES users(id),
  imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (organization_id,bank_reference),
  UNIQUE (id,organization_id)
);
CREATE INDEX IF NOT EXISTS idx_collect_bank_transactions_status ON collect_bank_transactions(organization_id,status,transaction_date DESC);

CREATE TABLE IF NOT EXISTS collect_reconciliation_matches (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  bank_transaction_id TEXT NOT NULL,
  payment_id TEXT NOT NULL,
  confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
  match_reasons_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'suggested' CHECK (status IN ('suggested','confirmed','rejected')),
  matched_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (bank_transaction_id,organization_id) REFERENCES collect_bank_transactions(id,organization_id) ON DELETE CASCADE,
  FOREIGN KEY (payment_id,organization_id) REFERENCES collect_payments(id,organization_id),
  UNIQUE (organization_id,bank_transaction_id,payment_id)
);
CREATE INDEX IF NOT EXISTS idx_collect_reconciliation_status ON collect_reconciliation_matches(organization_id,status,confidence DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_collect_reconciliation_one_bank_match ON collect_reconciliation_matches(organization_id,bank_transaction_id) WHERE status='confirmed';
CREATE UNIQUE INDEX IF NOT EXISTS idx_collect_reconciliation_one_payment_match ON collect_reconciliation_matches(organization_id,payment_id) WHERE status='confirmed';

CREATE TRIGGER IF NOT EXISTS trg_collect_reconciliation_validate
BEFORE INSERT ON collect_reconciliation_matches
WHEN NEW.status='confirmed'
BEGIN
  SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM collect_bank_transactions b JOIN collect_payments p ON p.id=NEW.payment_id AND p.organization_id=NEW.organization_id WHERE b.id=NEW.bank_transaction_id AND b.organization_id=NEW.organization_id AND b.status='unmatched' AND p.status='confirmed' AND b.amount_minor=p.amount_minor AND b.currency=p.currency)
    THEN RAISE(ABORT,'confirmed reconciliation must match exact amount and currency on an unmatched bank row') END;
END;

CREATE TRIGGER IF NOT EXISTS trg_collect_payment_received_event
AFTER INSERT ON collect_payments
BEGIN
  INSERT OR IGNORE INTO collect_events(id,organization_id,event_key,event_type,resource_type,resource_id,payload_json,processing_status,processed_at)
  VALUES('collect-event-payment-'||NEW.id,NEW.organization_id,'payment.received:'||NEW.id,'payment.received','payment',NEW.id,json_object('customerId',NEW.customer_id,'amountMinor',NEW.amount_minor,'currency',NEW.currency,'paidDate',NEW.paid_date),'processed',CURRENT_TIMESTAMP);
END;

CREATE TRIGGER IF NOT EXISTS trg_collect_payment_matched_event
AFTER INSERT ON collect_reconciliation_matches
WHEN NEW.status='confirmed'
BEGIN
  INSERT OR IGNORE INTO collect_events(id,organization_id,event_key,event_type,resource_type,resource_id,payload_json,processing_status,processed_at)
  VALUES('collect-event-match-'||NEW.id,NEW.organization_id,'payment.matched:'||NEW.id,'payment.matched','payment',NEW.payment_id,json_object('bankTransactionId',NEW.bank_transaction_id,'confidence',NEW.confidence),'processed',CURRENT_TIMESTAMP);
END;

INSERT OR IGNORE INTO permissions(id,code,description) VALUES
 ('perm-collect-payments-record','collect.payments.record','Record incoming customer payments'),
 ('perm-collect-reconciliation-manage','collect.reconciliation.manage','Import bank activity and confirm reconciliation matches');
INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('collect.payments.record','collect.reconciliation.manage')
WHERE r.name IN ('Organization Admin','Finance Admin','Collections Manager');
