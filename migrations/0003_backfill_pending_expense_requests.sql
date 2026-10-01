PRAGMA foreign_keys = ON;

-- Submitted expenses belong in the approval queue as pending requests.
INSERT OR IGNORE INTO approval_requests (id, organization_id, request_type, source_record_id, title, requester_id, amount, currency, required_role, status, created_at)
SELECT 'request-' || id, organization_id, 'Expense', id, description, 'user-demo', amount, currency, 'Finance Admin', 'pending', created_at
FROM expenses
WHERE status = 'submitted'
  AND NOT EXISTS (SELECT 1 FROM approval_requests existing WHERE existing.source_record_id = expenses.id AND existing.organization_id = expenses.organization_id);
