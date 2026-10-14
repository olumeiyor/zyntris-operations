ALTER TABLE tenant_backups
  ADD COLUMN storage_target TEXT NOT NULL DEFAULT 'local'
  CHECK (storage_target IN ('local', 'external_r2'));
