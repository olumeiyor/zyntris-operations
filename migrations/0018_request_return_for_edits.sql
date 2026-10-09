-- Preserve existing requests while adding a first-class return-for-edits state.
CREATE TABLE approval_requests_v2 (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  request_type TEXT NOT NULL,
  source_record_id TEXT,
  title TEXT NOT NULL,
  requester_id TEXT NOT NULL REFERENCES users(id),
  amount REAL,
  currency TEXT NOT NULL DEFAULT 'NGN',
  required_role TEXT NOT NULL DEFAULT 'Organization Admin',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'returned', 'approved', 'rejected', 'paid', 'cancelled')),
  current_step INTEGER NOT NULL DEFAULT 1,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  return_note TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO approval_requests_v2 (
  id, organization_id, request_type, source_record_id, title, requester_id,
  amount, currency, required_role, status, current_step, metadata_json,
  created_at, updated_at
)
SELECT id, organization_id, request_type, source_record_id, title, requester_id,
  amount, currency, required_role, status, current_step, metadata_json,
  created_at, updated_at
FROM approval_requests;

DROP TABLE approval_requests;
ALTER TABLE approval_requests_v2 RENAME TO approval_requests;
CREATE INDEX idx_requests_tenant_status ON approval_requests(organization_id, status, created_at);
ALTER TABLE organization_settings ADD COLUMN financial_fallback_role TEXT NOT NULL DEFAULT 'HR Admin';

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code = 'requests.manage'
WHERE r.name = 'HR Admin';
