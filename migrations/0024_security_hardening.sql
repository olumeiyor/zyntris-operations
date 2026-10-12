ALTER TABLE user_two_factor ADD COLUMN pending_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE expenses ADD COLUMN receipt_size_bytes INTEGER NOT NULL DEFAULT 0 CHECK (receipt_size_bytes >= 0);

-- Keep an atomic per-tenant document-storage counter so concurrent uploads
-- cannot race past the subscription quota. It is derived from documents.
CREATE TABLE tenant_storage_usage (
  organization_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  used_bytes INTEGER NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO tenant_storage_usage (organization_id, used_bytes)
SELECT organization_id, SUM(size_bytes) FROM (
  SELECT organization_id, size_bytes FROM documents
  UNION ALL
  SELECT organization_id, receipt_size_bytes AS size_bytes FROM expenses
) GROUP BY organization_id;
