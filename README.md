# Zyntris Operations Platform

Cloudflare-native operations SaaS for **Zyntris — One Platform. Every Operation.**

- React/Vite responsive operations workspace with a premium enterprise UI.
- Cloudflare Worker API with secure response headers, tenant-scoped D1 queries, audit logging and R2 file storage.
- D1 schema for organizations, memberships, roles, permissions, employees, leave, projects, tasks, expenses, documents, notifications, subscriptions and audit logs.
- Operational modules for expense claims, approval requests, budgets, assets, vendors, helpdesk, calendar and customer pipeline.
- Branded Zyntris logo system with SVG favicon, responsive brand lockup and the `One Platform. Every Operation.` visual language.
- Organization registration with verified-email activation, tenant-specific administrator membership, and a 30-day trial.
- Organization profile, time zone, and currency settings stored in D1.
- Remuneration records: employee compensation profiles, recurring earnings/deductions, configurable tax/contribution bands, draft calculations, review/approval, employee self-service payslips and payroll-register CSV. Payroll-authorized admins can collect bank details encrypted at rest for record keeping (masked in the UI); no payout files or bank transfers are initiated, and “paid” is a manual record status only.
- HR-controlled employee onboarding with tenant-scoped department/team profiles, assigned access roles, Brevo email invitations, single-use 72-hour account-setup links, and resend support.
- Server-enforced role/permission access for HR and operations modules, with employee self-scoping on expense/request records; CEO approval escalation for expense claims above ₦1m.
- Read-only platform administration for onboarded organization and audit-activity summaries, restricted to explicitly allowlisted verified accounts.
- Password-gated, read-only demo sandbox backed only by fictional demo-tenant records.
- Custom Domain configuration for `app.zyntris.org`.

## Local development

```bash
npm install
npm run dev
```

To exercise the D1/R2 API locally, create a `.dev.vars` file from `.dev.vars.example`, set a real email provider key and verified sender for signup tests, apply migrations, and start Wrangler:

```bash
cp .dev.vars.example .dev.vars
npm run db:migrate:local
npx wrangler dev
```

## Cloudflare setup

Authenticate Wrangler first:

```bash
npx wrangler login
```

Create the production resources. The D1 command can update `wrangler.jsonc` with the real database ID:

```bash
npm run db:create
npm run r2:create
npm run db:migrate:remote
```

Set production secrets in Wrangler (the values are entered interactively and must never be committed):

```bash
npx wrangler secret put SESSION_SECRET
npx wrangler secret put BREVO_API_KEY
npx wrangler secret put PLATFORM_ADMIN_EMAILS
npx wrangler secret put DEMO_ACCESS_PASSWORD
npm run deploy
```

`EMAIL_SENDER` must be a sender identity registered and verified with Brevo. The Worker sends signup-verification and employee-invitation links through Brevo's transactional email API; these actions fail closed when `BREVO_API_KEY` is absent or delivery fails. Keep the existing `SESSION_SECRET` stable for session security and encryption of stored employee bank details.

`wrangler.jsonc` declares the custom domain `app.zyntris.org`. Cloudflare will provision the DNS record and certificate when the zone is active in the same account. If the hostname currently has a CNAME, remove that record before deploying the Custom Domain.

Before the first production deployment, confirm that `database_id` in `wrangler.jsonc` is no longer `REPLACE_WITH_D1_DATABASE_ID`, and that the `zyntris-files` R2 bucket exists in the account selected by Wrangler.

## Tenant and security model

Every organization-owned table has an `organization_id`. The Worker derives the tenant from the authenticated membership and binds it into every data query; the browser never chooses a tenant ID. Sessions are HTTP-only, Secure, SameSite cookies. R2 keys are prefixed with the tenant ID, and the bucket is private by default. Important mutations write to `audit_logs`.

The shared demo administrator login has been removed. Account passwords are PBKDF2-hashed; verified users receive short-lived HTTP-only, Secure, SameSite cookies backed by hashed D1 session tokens. Organization membership and role permissions determine access. Signup/login attempts are rate-limited in D1.

Platform administration is read-only and enabled only for verified email addresses listed in the `PLATFORM_ADMIN_EMAILS` Worker secret (comma-separated for multiple admins). Platform admins still need a normal verified Zyntris account; never add a public/shared demo address to this allowlist. The console excludes the demo tenant and shows organization-level counts plus audit events without payroll or bank data.

The demo sandbox uses the synthetic `org-demo` tenant and the reserved sign-in ID `demo@demo.zyntris.invalid`. Set `DEMO_ACCESS_PASSWORD` to a long random value. Demo sessions are marked in D1 and every write request is rejected server-side; demo access cannot read other tenants. Sample payroll rates and amounts are fictional and must not be used for actual payroll.

## API surface currently wired

- `GET /api/health`
- `GET /api/auth/config`
- `POST /api/auth/register`
- `POST /api/auth/verify`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/me`
- `GET /api/dashboard`
- `GET|POST /api/employees`
- `POST /api/employees/:id/invite`
- `GET /api/hr/options`
- `POST /api/hr/teams`
- `POST /api/auth/accept-invite`
- `GET /api/leave`
- `GET /api/tasks`
- `GET|POST /api/expenses`
- `GET|PATCH /api/requests`
- `GET|POST /api/assets`
- `GET|POST /api/vendors`
- `GET|POST /api/tickets`
- `GET /api/calendar`
- `GET|POST /api/customers`
- `GET|POST /api/files`
- `/api/settings/organization` — organization profile and trial subscription details.
- `/api/payroll/*` — policy, employee remuneration/bank records, recurring components, runs, employee-owned payslips, and payroll register exports. Bank details are never included in exports.

## Operational workflows now included

- Expense submission creates a D1 expense record and a linked approval request.
- Approval decisions update both the request and its source expense, and write to the audit log.
- Asset register supports ownership, location, lifecycle status and current value.
- Vendor register surfaces contract expiry and spend risk.
- Helpdesk tickets have category, priority, status, requester and assignee fields.
- Calendar combines meetings, leave and training events.
- CRM customer pipeline supports lead, qualified, proposal, negotiation and won stages.

Remaining product phases include MFA, paid-plan checkout, password recovery, and extended talent modules (performance, goals, LMS, recruitment and AI).

## Payroll policy setup

Payroll does not preload statutory tax rates or pension percentages. Configure the organization's effective policy for its country, region and payroll period, then validate it with a local payroll/tax professional before approval. Tax bands are progressive and entered with ascending `upTo` thresholds and a final `null` threshold, for example `[ { "upTo": 1000000, "rate": 0.07 }, { "upTo": null, "rate": 0.1 } ]`. Rates are decimals. Employee base remuneration and recurring amounts are entered per pay period. Admins may store bank details encrypted for record purposes; account numbers are masked on screen and excluded from generated documents/exports. The app documents remuneration, prepares employee payslips and records approval/payment status; actual bank transfers are outside the platform.

Paid-plan checkout, password recovery, MFA and team-member invitation flows are not yet integrated. Trial access is limited to 30 days; organizations must contact Zyntris to arrange a paid plan before expiry.
