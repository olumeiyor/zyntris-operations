# Zyntris Collect — implementation status (Phases 1–3 foundation)

## Delivered in this increment

- Collect appears as a tenant module and is controlled by the existing platform-admin module entitlement.
- Existing authentication, tenant membership and role/permission system is reused; Collect does not create a second user or organization directory.
- Customer receivable profiles extend the current tenant CRM customer records with account type, legal/tax identifiers, billing currency/address, terms, credit limit, account manager, collector, and notes.
- Tenant-scoped legal entities with their own base currency support organizations with more than one billing entity.
- Draft invoices support multiple lines, quantities to three decimal places, currency-aware minor units, discounts, tax rates, FX conversion to the entity base currency, purchase-order reference, payment terms, and due dates.
- Invoice creation accepts an idempotency key; invoice rows, lines, event record, and idempotency result are inserted atomically.
- The dashboard provides live outstanding/overdue balances by base currency, ageing buckets, assigned-account visibility, top debtors, and an explicit no-forecast state until sufficient verified payment history exists.
- Receivables/invoice/customer views, draft-to-open issue transition, invoice detail, and CSV export are wired to authenticated APIs. Export permission is checked before the control is shown and at the server boundary.
- A prioritized collection queue, append-only action history, promises to pay, and dispute workflow are available. Disputes pause queue eligibility and restore the prior invoice status when closed. Expired promises are classified by the scheduled Worker against later invoice payments and emit domain events.
- Finance users can record payments already received, optionally allocate them across invoices, and leave unapplied cash. Database triggers verify tenant, customer and currency consistency, prevent over-allocation, update invoice paid balances, and create payment events.
- Finance users can add bank statement rows, review scored match suggestions, and explicitly confirm exact-amount/exact-currency reconciliations. No suggestion is auto-confirmed.
- Mutating API calls use the app's existing origin checks. Database reads/writes are parameterized and scoped to the active organization. Customer and legal-entity references have tenant-aware foreign keys.

## Not delivered / required next phases

This is a functional AR foundation, not a completed end-to-end collections/payments product. In particular:

1. **Automated collections:** configurable multi-step workflows, scheduled reminders, email/WhatsApp/SMS delivery, templates, delivery tracking, workflow retries, collector assignment rules and escalation/SLA configuration are not connected yet. Logged email/WhatsApp actions are records only, not sends.
2. **Payments/reconciliation extensions:** manual payment recording and single-payment/single-invoice exact-match reconciliation are available. CSV file upload, statement parser, partial/one-to-many reconciliation, provider interfaces/webhooks/signature validation, refunds/chargebacks, payment links and processor integrations are not implemented. Zyntris does not initiate payment from this increment.
3. **Customer-facing functions:** branded invoice PDF/email delivery, authenticated or expiring customer portal, secure document delivery, and customer self-service are not implemented.
4. **AI and analytics:** no model calls, AI-generated copy or risk scores are active. Forecasting intentionally reports unavailable rather than fabricating a prediction. Any later AI work needs consent/retention controls and human review.
5. **Integrations and compliance:** accounting/ERP connectors, tax configuration validation by each organization, verified sender/domain configuration, and legal review for the countries in which each tenant operates.
6. **Production readiness:** tenant-specific UAT, finance sign-off of entity/currency/tax configuration, permission review, production D1 migration/deployment, and end-to-end integration tests remain separate steps. This change has not been deployed or pushed.

## Data and calculation notes

- All transaction and base amounts are integer minor units. FX rates are decimal strings, parsed and rounded using integer arithmetic; no binary floating-point is used for invoice totals.
- Currency exponent handling supports zero-, two-, and three-decimal currencies. Statutory tax rates and legal invoice requirements remain organization-configured and need professional verification.
- Customer-list balances are shown in the profile's billing currency; invoices in a different transaction currency are not combined into that balance. The dashboard groups totals by legal-entity base currency.
- Collection promise and payment/reconciliation events are recorded. A general-purpose event consumer with retry/dead-letter management is not yet implemented.

## Verification performed

- `npm run build`
- `npm run test:security` (includes Collect money parsing/calculation tests)
- All repository SQL migrations, including migrations 0029–0031, applied in order to a temporary SQLite database; `PRAGMA foreign_key_check` returned no rows. Payment allocation triggers were exercised with a temporary fixture and updated the invoice balance/status as expected. Allocation and reconciliation database triggers enforce tenant-safe relationships and over-allocation/matching rules.

Wrangler's local D1 runner could not start in the restricted environment because it could not bind loopback, so the SQLite migration-chain verification was used instead. No remote database was touched.
