-- Phase 2: persistent collection queue, promises, disputes and action history.
CREATE TABLE IF NOT EXISTS collect_promises (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  customer_id TEXT NOT NULL,
  invoice_id TEXT,
  promised_amount_minor INTEGER NOT NULL CHECK (promised_amount_minor > 0),
  paid_before_minor INTEGER NOT NULL DEFAULT 0 CHECK (paid_before_minor >= 0),
  currency TEXT NOT NULL CHECK (length(currency)=3 AND currency=upper(currency)),
  promise_date TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'collector' CHECK (source IN ('customer','collector','email','phone','portal','other')),
  notes TEXT,
  collector_user_id TEXT REFERENCES users(id),
  confidence INTEGER CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 100),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','kept','partially_kept','broken','cancelled')),
  resolved_at TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (customer_id, organization_id) REFERENCES customers(id, organization_id),
  FOREIGN KEY (invoice_id, organization_id) REFERENCES collect_invoices(id, organization_id)
);
CREATE INDEX IF NOT EXISTS idx_collect_promises_due ON collect_promises(organization_id,status,promise_date);
CREATE INDEX IF NOT EXISTS idx_collect_promises_customer ON collect_promises(organization_id,customer_id,created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_collect_promises_one_active_per_invoice ON collect_promises(organization_id,invoice_id) WHERE status='active' AND invoice_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS collect_disputes (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  invoice_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  amount_minor INTEGER NOT NULL CHECK (amount_minor >= 0),
  currency TEXT NOT NULL CHECK (length(currency)=3 AND currency=upper(currency)),
  reason TEXT NOT NULL CHECK (reason IN ('incorrect_amount','goods_not_received','service_issue','duplicate_invoice','incorrect_po','payment_already_made','other')),
  description TEXT NOT NULL,
  owner_user_id TEXT REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','awaiting_customer','resolved','rejected')),
  previous_invoice_status TEXT NOT NULL DEFAULT 'open',
  sla_due_at TEXT,
  resolution TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  resolved_by TEXT REFERENCES users(id),
  resolved_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (invoice_id, organization_id) REFERENCES collect_invoices(id, organization_id),
  FOREIGN KEY (customer_id, organization_id) REFERENCES customers(id, organization_id)
);
CREATE INDEX IF NOT EXISTS idx_collect_disputes_status ON collect_disputes(organization_id,status,created_at DESC);

CREATE TABLE IF NOT EXISTS collect_actions (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  customer_id TEXT NOT NULL,
  invoice_id TEXT,
  action_type TEXT NOT NULL CHECK (action_type IN ('call','email','whatsapp','note','task','escalate','other')),
  outcome TEXT,
  notes TEXT,
  next_action TEXT,
  next_action_at TEXT,
  actor_user_id TEXT NOT NULL REFERENCES users(id),
  idempotency_key TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (customer_id, organization_id) REFERENCES customers(id, organization_id),
  FOREIGN KEY (invoice_id, organization_id) REFERENCES collect_invoices(id, organization_id),
  UNIQUE (organization_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_collect_actions_customer ON collect_actions(organization_id,customer_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_collect_actions_next ON collect_actions(organization_id,next_action_at);

CREATE TRIGGER IF NOT EXISTS trg_collect_promise_status_event
AFTER UPDATE OF status ON collect_promises
WHEN OLD.status <> NEW.status
BEGIN
  INSERT OR IGNORE INTO collect_events(id,organization_id,event_key,event_type,resource_type,resource_id,payload_json,processing_status,processed_at)
  VALUES('collect-event-promise-'||NEW.id||'-'||NEW.status,NEW.organization_id,'promise.'||NEW.status||':'||NEW.id,'promise.'||NEW.status,'promise',NEW.id,json_object('invoiceId',NEW.invoice_id,'amountMinor',NEW.promised_amount_minor,'promiseDate',NEW.promise_date),'processed',CURRENT_TIMESTAMP);
END;

INSERT OR IGNORE INTO permissions(id,code,description) VALUES
 ('perm-collect-promises-manage','collect.promises.manage','Record and resolve promises to pay'),
 ('perm-collect-disputes-manage','collect.disputes.manage','Manage invoice disputes'),
 ('perm-collect-actions-create','collect.actions.create','Record collection activity');
INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('collect.promises.manage','collect.disputes.manage','collect.actions.create')
WHERE r.name IN ('Organization Admin','Finance Admin','Collections Manager','Collector');
