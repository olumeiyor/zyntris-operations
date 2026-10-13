-- Existing tenants start with daily 30-day snapshots unless they already have
-- explicit backup settings. Alert the tenant's highest-privilege administrator.
INSERT INTO tenant_backup_settings (organization_id, enabled, frequency, retention_days, alert_email)
SELECT o.id, 1, 'daily', 30, (
  SELECT u.email
  FROM memberships m
  JOIN users u ON u.id = m.user_id
  JOIN roles r ON r.id = m.role_id AND r.organization_id = m.organization_id
  WHERE m.organization_id = o.id
    AND m.status = 'active'
    AND u.status = 'active'
    AND r.name IN ('Organization Admin', 'CEO')
  ORDER BY CASE r.name WHEN 'Organization Admin' THEN 0 ELSE 1 END, u.created_at
  LIMIT 1
)
FROM organizations o
WHERE NOT EXISTS (
  SELECT 1 FROM tenant_backup_settings existing WHERE existing.organization_id = o.id
);
