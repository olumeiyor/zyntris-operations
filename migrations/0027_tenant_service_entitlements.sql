-- Provision existing workspaces with the full current product surface. The
-- platform administrator can subsequently activate or deactivate each module
-- per tenant through organization_modules.
INSERT OR IGNORE INTO organization_modules (organization_id, module_key, enabled, features_json)
SELECT id, 'hr', 1, '{}' FROM organizations;
INSERT OR IGNORE INTO organization_modules (organization_id, module_key, enabled, features_json)
SELECT id, 'payroll', 1, '{}' FROM organizations;
INSERT OR IGNORE INTO organization_modules (organization_id, module_key, enabled, features_json)
SELECT id, 'finance', 1, '{}' FROM organizations;
INSERT OR IGNORE INTO organization_modules (organization_id, module_key, enabled, features_json)
SELECT id, 'operations', 1, '{}' FROM organizations;
INSERT OR IGNORE INTO organization_modules (organization_id, module_key, enabled, features_json)
SELECT id, 'reports', 1, '{}' FROM organizations;
