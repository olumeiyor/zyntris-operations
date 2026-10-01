-- Route all open financial approvals to the CEO, irrespective of the amount.
UPDATE approval_requests
SET required_role = 'CEO'
WHERE status = 'pending'
  AND (
    amount IS NOT NULL
    OR lower(trim(request_type)) IN (
      'expense', 'purchase', 'budget', 'payroll', 'reimbursement',
      'payment', 'financial', 'asset purchase'
    )
  );
