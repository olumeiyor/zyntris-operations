# Zyntris Operations Platform

Repository: `zyntris-operations` — Zyntris Operation

Cloudflare-native operations SaaS for **Zyntris — One Platform. Every Operation.**

- React/Vite responsive operations workspace with a premium enterprise UI.
- Cloudflare Worker API with secure response headers, tenant-scoped D1 queries, audit logging and R2 file storage.
- D1 schema for organizations, memberships, roles, permissions, employees, leave, projects, tasks, expenses, documents, notifications, subscriptions and audit logs.
- Operational modules for expense claims, approval requests, budgets, assets, vendors, helpdesk, calendar and customer pipeline.
- Branded Zyntris logo system with SVG favicon, responsive brand lockup and the `One Platform. Every Operation.` visual language.
- Organization registration with verified-email activation, tenant-specific administrator membership, and a 15-day trial.
- Organization profile, time zone, and currency settings stored in D1.
- Remuneration records: employee compensation profiles, recurring earnings/deductions, configurable tax/contribution bands, draft calculations, review/approval, employee self-service payslips and payroll-register CSV. Payroll-authorized admins can collect bank details encrypted at rest for record keeping (masked in the UI); no payout files or bank transfers are initiated, and “paid” is a manual record status only.
- HR-controlled employee onboarding with tenant-scoped department/team profiles, assigned access roles, Brevo email invitations, single-use 72-hour account-setup links, and resend support. Requesters receive Brevo email notices when a request or payroll run is approved.
- Server-enforced role/permission access for HR and operations modules, with employee self-scoping on expense/request records; every financial request requires CEO approval.
- Persistent user-and-tenant-scoped in-app notifications and Brevo email to each assigned approver when an expense, operational request, or payroll review is awaiting action.
- Separate Expo / React Native iOS and Android app in [`mobile/`](mobile/README.md). It uses a mobile-only bearer-token API prefix and does not enter the Cloudflare web build.
- Read-only platform administration for onboarded organization and audit-activity summaries, restricted to explicitly allowlisted verified accounts.
- Password-gated, read-only demo sandbox backed only by fictional demo-tenant records.
- Optional authenticator-app two-factor authentication for web and mobile sign-in, with encrypted TOTP secrets, replay protection and one-use recovery codes.
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
npx wrangler secret put DEMO_ACCESS_PASSWORD
npm run deploy
```

The allowlisted main administrator email is a non-secret Worker variable in `wrangler.jsonc` (`PLATFORM_ADMIN_EMAILS`). Change that config only when deliberately changing platform-admin access. `Olumeiyor@gmail.com` is the configured main administrator for this deployment.

`EMAIL_SENDER` must be a sender identity registered and verified with Brevo. The Worker sends signup-verification and employee-invitation links through Brevo's transactional email API; these actions fail closed when `BREVO_API_KEY` is absent or delivery fails. Keep the existing `SESSION_SECRET` stable for session security and encryption of stored employee bank details.

`wrangler.jsonc` declares the custom domain `app.zyntris.org`. Cloudflare will provision the DNS record and certificate when the zone is active in the same account. If the hostname currently has a CNAME, remove that record before deploying the Custom Domain.

Before the first production deployment, confirm that `database_id` in `wrangler.jsonc` is no longer `REPLACE_WITH_D1_DATABASE_ID`, and that the `zyntris-files` R2 bucket exists in the account selected by Wrangler.

## Tenant and security model

Every organization-owned table has an `organization_id`. The Worker derives the tenant from the authenticated membership and binds it into every data query; the browser never chooses a tenant ID. Sessions are HTTP-only, Secure, SameSite cookies. R2 keys are prefixed with the tenant ID, and the bucket is private by default. Important mutations write to `audit_logs`.

The shared demo administrator login has been removed. Account passwords are PBKDF2-hashed; verified users receive short-lived HTTP-only, Secure, SameSite cookies backed by hashed D1 session tokens. Organization membership and role permissions determine access. Signup/login attempts are rate-limited in D1.

Platform administration is enabled only for verified email addresses listed in the `PLATFORM_ADMIN_EMAILS` Worker variable (comma-separated for multiple admins). Platform admins still need a normal verified Zyntris account; never add a public/shared demo address to this allowlist. The console lists every tenant, including the protected synthetic demo tenant, with operational counts and audit events but no payroll or bank data. Admins may suspend or enable customer tenant access; re-enabling an expired trial explicitly converts its subscription to active and is recorded in the audit log. Tenant password resets send a one-use, 30-minute link through Brevo and revoke the user's active sessions; admins never see or set the user's password.

Users can enable two-factor authentication from Account security. TOTP secrets are encrypted with `SESSION_SECRET`; sign-in challenges expire after five minutes and allow at most five code attempts. Recovery codes are stored only as hashes and each can be used once. Apply the D1 migration before deploying this feature. Keep `SESSION_SECRET` stable because it protects both payroll bank details and authenticator secrets.

The demo sandbox uses the synthetic `org-demo` tenant and the reserved sign-in ID `demo@demo.zyntris.invalid`. Set `DEMO_ACCESS_PASSWORD` to a long random value. Demo sessions are marked in D1 and every write request is rejected server-side; demo access cannot read other tenants. Sample payroll rates and amounts are fictional and must not be used for actual payroll.

## API surface currently wired

- `GET /api/health`
- `GET /api/auth/config`
- `POST /api/auth/register`
- `POST /api/auth/verify`
- `POST /api/auth/login`
- `POST /api/auth/request-password-reset` — self-service reset request with generic responses and rate limiting.
- `POST /api/auth/reset-password` — consume the one-use, 30-minute link sent through Brevo.
- `POST /api/auth/2fa/verify` — complete a password sign-in using an authenticator or recovery code.
- `/api/auth/2fa/*` — inspect status, begin setup, verify/enable, and disable 2FA for the current account.
- `POST /api/auth/logout`
- `GET /api/me`
- `GET /api/dashboard`
- `/api/platform/*` — allowlisted main-administrator tenant controls, session revocation, and one-use Brevo password-reset links.
- `GET|POST /api/employees`
- `GET /api/appraisals` and `POST /api/appraisal-cycles` — employee self-reviews, assigned manager feedback, goal and competency scoring, acknowledgment, and cycle tracking.
- `/api/appraisals/*` and `/api/appraisal-360/*` — KPI scoring, confidential multi-rater feedback, recommendations, and employee acceptance/decline.
- `/api/hr/talent/*` — scoped KPI administration, improvement plans and check-ins, recruitment requisitions and candidate stages, plus learning assignment/progress.
- `PATCH /api/employees/:id/manager` — HR-controlled line-manager assignment.
- `POST /api/employees/:id/invite`
- `GET /api/hr/options`
- `POST /api/hr/teams`
- `POST /api/auth/accept-invite`
- `GET /api/leave`
- `GET /api/tasks`
- `GET|POST /api/expenses`, `GET /api/expenses/export`, `GET /api/expenses/:id/receipt`, and `GET|PATCH /api/expense-policy` — tenant-scoped CSV and private R2 receipts, with enforced claim limits and receipt requirements.
- `GET|POST /api/requests`, `GET /api/requests/:id/history`, and `PATCH /api/requests/:id` — filterable approvals and tenant-scoped audit history.
- `/api/attendance/*` — employee time-clock, HR shift schedules, and manager review of submitted time records.
- `GET|POST /api/assets`
- `GET|POST /api/vendors`
- `GET|POST /api/tickets`
- `GET /api/calendar`
- `GET|POST /api/customers` and `PATCH /api/customers/:id` — tenant-scoped editable profiles and won-date reporting.
- `GET|POST /api/files`
- `/api/settings/organization` — organization profile and trial subscription details.
- `/api/payroll/*` — policy, employee remuneration/bank records, recurring components, runs, employee-owned payslips, and payroll register exports. Bank details are never included in exports.

## Operational workflows now included

- Expense submission creates a D1 expense record and a linked approval request. Optional or policy-required PDF/JPEG/PNG/WebP receipts are stored in private R2; CSV export is permission-scoped and protects against spreadsheet formula injection.
- Expense policies can enforce per-claim limits and receipt submission. The policies do not replace finance approval or local accounting controls.
- Attendance supports in/out time-clock entries, tenant-admin shift schedules, review, and overtime measured against the configured shift. Overtime is not calculated where no matching schedule exists; local legal and contractual rules must be checked by HR. Overnight shifts and retroactive employee-edited timesheets are not yet supported.
- CRM tracks the date a customer enters the won stage and calculates current-quarter won totals from actual records. Authorized operations managers can edit customer profiles.
- General operational requests can be submitted from web or mobile; financial requests are routed to the CEO, and other requests to their selected role. Approvers are alerted through both email and the in-app inbox.
- Approval decisions update both the request and its source expense, and write to the audit log.
- Asset register supports ownership, location, lifecycle status and current value.
- Vendor register surfaces contract expiry and spend risk.
- Helpdesk tickets have category, priority, status, requester and assignee fields.
- Calendar combines meetings, leave and training events.
- CRM customer pipeline supports lead, qualified, proposal, negotiation and won stages.

Implemented HR talent modules include line-manager assignments, organization/team/employee KPI libraries, multi-rater 360 feedback, employee appraisal decisions, PIP plans and check-ins, recruitment candidate pipelines, and course assignment/completion tracking. Self-service password recovery is implemented with Brevo and an enumeration-safe response. Paid subscription onboarding is sales-led and manual; there is no online checkout or automatic bank transfer. Google/Outlook two-way calendar sync remains unconfigured pending provider selection and OAuth credentials. The Expo app is separate from the web deployment; store submission and OS push notifications still require the organization’s Apple/Google/EAS accounts and push credentials.

## Payroll policy setup

Payroll does not preload statutory tax rates or pension percentages. Configure the organization's effective policy for its country, region and payroll period, then validate it with a local payroll/tax professional before approval. Tax bands are progressive and entered with ascending `upTo` thresholds and a final `null` threshold, for example `[ { "upTo": 1000000, "rate": 0.07 }, { "upTo": null, "rate": 0.1 } ]`. Rates are decimals. Employee base remuneration and recurring amounts are entered per pay period. Admins may store bank details encrypted for record purposes; account numbers are masked on screen and excluded from generated documents/exports. The app documents remuneration, prepares employee payslips and records approval/payment status; actual bank transfers are outside the platform.

Paid plans are activated manually by the Business Development Manager; this application does not collect subscription payments. New trials last 15 days from email verification. Expired trials are automatically suspended by the hourly Worker cron and cannot sign in; existing sessions are revoked. Organizations should arrange their plan before expiry.
