import { useEffect, useState, type FormEvent } from "react";
import { Building2, Check, CheckCircle2, Copy, CreditCard, DatabaseBackup, Download, Globe2, Mail, RotateCcw, Send, ShieldCheck } from "lucide-react";

type Organization = { id: string; name: string; slug: string; industry: string | null; description: string | null; timezone: string; currency: string; status: string };
type Subscription = { plan: string; status: string; trialEndsAt: string | null; renewsAt: string | null; employeeLimit: number; storageLimitBytes: number };
type TenantBackup = { id: string; checksum: string; sizeBytes: number; recordCount: number; createdAt: string };

async function settingsApi<T>(path: string, init?: RequestInit) { const response = await fetch(path, { credentials: "include", ...init }); if (!response.ok) throw new Error((await response.json().catch(() => null))?.error || "Settings could not be saved."); return response.json() as Promise<T>; }

export function OrganizationSettings({ onToast, currentEmail }: { onToast: (message: string) => void; currentEmail: string }) {
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [testingEmail, setTestingEmail] = useState(false);
  const [emailTestError, setEmailTestError] = useState("");
  const [emailTestResult, setEmailTestResult] = useState("");
  const [backups, setBackups] = useState<TenantBackup[]>([]);
  const [backupBusy, setBackupBusy] = useState(false);
  const [backupError, setBackupError] = useState("");
  const [restorePreview, setRestorePreview] = useState("");
  useEffect(() => { void settingsApi<{ organization: Organization; subscription: Subscription }>("/api/settings/organization").then((data) => { setOrganization(data.organization); setSubscription(data.subscription); }).catch((cause) => setError(cause instanceof Error ? cause.message : "Could not load organization settings.")); }, []);
  useEffect(() => { void settingsApi<{ data: TenantBackup[] }>("/api/settings/backups").then((data) => setBackups(data.data)).catch((cause) => setBackupError(cause instanceof Error ? cause.message : "Could not load backups.")); }, []);

  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setSaving(true); setError("");
    const values = Object.fromEntries(new FormData(event.currentTarget).entries());
    try { await settingsApi("/api/settings/organization", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(values) }); const updated = await settingsApi<{ organization: Organization; subscription: Subscription }>("/api/settings/organization"); setOrganization(updated.organization); setSubscription(updated.subscription); onToast("Organization settings saved"); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not save settings."); }
    finally { setSaving(false); }
  };

  const testEmail = async () => {
    setTestingEmail(true); setEmailTestError(""); setEmailTestResult("");
    try {
      const result = await settingsApi<{ accepted: boolean; recipient: string; sender: string }>("/api/settings/email/test", { method: "POST" });
      setEmailTestResult(`Brevo accepted the test email to ${result.recipient} from ${result.sender}. Check your inbox and spam folder.`);
    } catch (cause) { setEmailTestError(cause instanceof Error ? cause.message : "Could not send a test email."); }
    finally { setTestingEmail(false); }
  };

  const createBackup = async () => {
    setBackupBusy(true); setBackupError("");
    try { const created = await settingsApi<TenantBackup & { fileCount: number }>("/api/settings/backups", { method: "POST" }); setBackups((current) => [{ ...created }, ...current]); onToast(`Backup created: ${created.recordCount} records and ${created.fileCount} files`); }
    catch (cause) { setBackupError(cause instanceof Error ? cause.message : "Backup creation failed."); }
    finally { setBackupBusy(false); }
  };

  const restoreBackup = async (backup: TenantBackup) => {
    setBackupBusy(true); setBackupError(""); setRestorePreview("");
    try {
      const preview = await settingsApi<{ valid: boolean; rows: Record<string, number>; fileCount: number; note: string }>(`/api/settings/backups/${backup.id}/restore`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ dryRun: true }) });
      const summary = Object.entries(preview.rows).filter(([, count]) => count > 0).map(([table, count]) => `${table}: ${count}`).join(" · ");
      setRestorePreview(`Verified ${Object.values(preview.rows).reduce((sum, count) => sum + count, 0)} records and ${preview.fileCount} files. ${summary}`);
      const confirmation = window.prompt("This restores only missing records/files. Existing records will not be overwritten or deleted. Type RESTORE MERGE to continue:");
      if (confirmation !== "RESTORE MERGE") return;
      const restored = await settingsApi<{ restoredCount: number; restoredFiles: number }>(`/api/settings/backups/${backup.id}/restore`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ confirmation }) });
      onToast(`Recovery merge completed: ${restored.restoredCount} records and ${restored.restoredFiles} files restored`);
    } catch (cause) { setBackupError(cause instanceof Error ? cause.message : "Restore preview failed."); }
    finally { setBackupBusy(false); }
  };

  return <><div className="page-header"><div><div className="eyebrow">WORKSPACE / ADMINISTRATION</div><h1>Organization settings</h1><p>Manage your organization identity, regional defaults and subscription.</p></div></div>{error && <div className="payroll-error">{error}</div>}<div className="settings-layout"><div className="settings-nav card"><button className="active"><Building2 size={16} /> Organization</button><button><ShieldCheck size={16} /> Security & roles</button><button><Globe2 size={16} /> Regional defaults</button><button><CreditCard size={16} /> Subscription</button></div><div className="settings-content"><section className="card settings-panel"><div className="card-heading"><div><h2>Organization profile</h2><p>The workspace details used across your Zyntris instance.</p></div></div>{organization && <form className="settings-form" onSubmit={save}><label>Organization name<input name="name" defaultValue={organization.name} required maxLength={120} /></label><label>Industry<select name="industry" defaultValue={organization.industry || "Other"}><option>Professional services</option><option>Technology</option><option>Financial services</option><option>Healthcare</option><option>Education</option><option>Retail & commerce</option><option>Manufacturing</option><option>Nonprofit</option><option>Other</option></select></label><label>Workspace address<input value={`${window.location.host}/${organization.slug}`} readOnly /></label><label>Time zone<select name="timezone" defaultValue={organization.timezone}><option>Africa/Lagos</option><option>Africa/Accra</option><option>Africa/Nairobi</option><option>Europe/London</option><option>America/New_York</option><option>Asia/Dubai</option></select></label><label>Default currency<select name="currency" defaultValue={organization.currency}><option value="NGN">NGN · Nigerian naira</option><option value="GHS">GHS · Ghanaian cedi</option><option value="KES">KES · Kenyan shilling</option><option value="USD">USD · US dollar</option><option value="GBP">GBP · British pound</option></select></label><label className="full">Company description<textarea name="description" defaultValue={organization.description || ""} placeholder="A short introduction to your organization" /></label><div className="full"><button className="button primary" disabled={saving}><CheckCircle2 size={15} /> {saving ? "Saving…" : "Save changes"}</button></div></form>}<div className="security-note"><ShieldCheck size={17} /><div><strong>Tenant isolation is enabled</strong><span>All organization-owned records are scoped by the Worker from your verified membership.</span></div></div></section>
      <section className="card settings-panel email-test-panel"><div className="card-heading"><div><h2>Email delivery</h2><p>Test the configured Brevo sender with a message to your signed-in account.</p></div><Mail size={18} /></div><div className="email-test-row"><div><span>Test recipient</span><strong>{currentEmail}</strong></div><button className="button primary" type="button" onClick={() => void testEmail()} disabled={testingEmail}>{testingEmail ? "Sending test…" : <><Send size={14} /> Send test email</>}</button></div>{emailTestError && <div className="email-test-feedback is-error" role="alert">{emailTestError}</div>}{emailTestResult && <div className="email-test-feedback is-success" role="status">{emailTestResult}</div>}<p className="subscription-note">“Accepted” confirms Brevo queued the message, not final inbox delivery. If it doesn’t arrive, check spam and verify your sender plus SPF/DKIM domain authentication in Brevo.</p></section>
      <section className="card settings-panel backup-panel"><div className="card-heading"><div><h2>Backup & recovery</h2><p>Create a tenant-scoped snapshot of HR, operations, approvals, payroll records and uploaded documents in private R2 storage.</p></div><DatabaseBackup size={19} /></div><div className="security-note"><ShieldCheck size={17} /><div><strong>Recovery is a non-destructive merge</strong><span>Restore adds missing records and files only. It never overwrites or deletes current data. Identity, access credentials and billing records are excluded.</span></div></div><p className="subscription-note">Uploaded file contents are copied separately within R2. The JSON download is a data manifest, not a portable archive; in-app recovery uses the stored snapshot.</p><button className="button primary" type="button" onClick={() => void createBackup()} disabled={backupBusy}><DatabaseBackup size={15} /> {backupBusy ? "Working…" : "Create backup now"}</button>{backupError && <div className="payroll-error" role="alert">{backupError}</div>}{restorePreview && <p className="subscription-note" role="status">{restorePreview}</p>}{backups.length > 0 ? <div className="backup-list">{backups.map((backup) => <div className="backup-row" key={backup.id}><div><strong>{new Date(`${backup.createdAt.replace(" ", "T")}Z`).toLocaleString("en-NG")}</strong><span>{backup.recordCount} records · {(backup.sizeBytes / 1024).toFixed(1)} KB · SHA-256 {backup.checksum.slice(0, 12)}…</span></div><div className="backup-actions"><a className="button secondary" href={`/api/settings/backups/${backup.id}/download`}><Download size={14} /> Download manifest</a><button className="button secondary" type="button" disabled={backupBusy} onClick={() => void restoreBackup(backup)}><RotateCcw size={14} /> Verify / restore</button></div></div>)}</div> : !backupError && <p className="subscription-note">No snapshots yet. Create one before making major changes.</p>}</section>
      <section className="card settings-panel subscription-card"><div className="card-heading"><div><h2>Subscription</h2><p>Your organization’s plan and trial details.</p></div><span className={`status-badge ${subscription?.status || "trialing"}`}>{subscription?.status || "Loading"}</span></div><div className="subscription-facts"><div><small>Plan</small><strong>{subscription?.plan || "—"}</strong></div><div><small>Employee capacity</small><strong>{subscription?.employeeLimit || "—"}</strong></div><div><small>Trial ends</small><strong>{subscription?.trialEndsAt ? new Date(subscription.trialEndsAt).toLocaleDateString("en-NG", { dateStyle: "long" }) : "—"}</strong></div></div><p className="subscription-note">Your 15-day trial requires no payment method. Workspace access turns off automatically when the trial expires. Contact Zyntris to arrange a paid plan before then.</p></section></div></div></>;
}

type TwoFactorStatus = { enabled: boolean; enabledAt: string | null; recoveryCodesRemaining: number };
type TwoFactorSetup = { secret: string; provisioningUri: string };

export function AccountSecurity({ onToast }: { onToast: (message: string) => void }) {
  const [status, setStatus] = useState<TwoFactorStatus | null>(null);
  const [setup, setSetup] = useState<TwoFactorSetup | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = async () => setStatus(await settingsApi<TwoFactorStatus>("/api/auth/2fa/status"));
  useEffect(() => { void refresh().catch((cause) => setError(cause instanceof Error ? cause.message : "Could not load account security.")); }, []);

  const start = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setBusy(true); setError("");
    try { setSetup(await settingsApi<TwoFactorSetup>("/api/auth/2fa/setup", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password }) })); setPassword(""); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not start authenticator setup."); }
    finally { setBusy(false); }
  };

  const enable = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setBusy(true); setError("");
    try { const result = await settingsApi<{ recoveryCodes: string[] }>("/api/auth/2fa/enable", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code }) }); setRecoveryCodes(result.recoveryCodes); setSetup(null); setCode(""); await refresh(); onToast("Two-factor authentication is enabled"); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not verify authenticator."); }
    finally { setBusy(false); }
  };

  const disable = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setBusy(true); setError("");
    try { await settingsApi("/api/auth/2fa/disable", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password, code }) }); setPassword(""); setCode(""); setRecoveryCodes([]); await refresh(); onToast("Two-factor authentication is disabled"); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not disable two-factor authentication."); }
    finally { setBusy(false); }
  };

  return <><div className="page-header"><div><div className="eyebrow">YOUR ACCOUNT / SECURITY</div><h1>Account security</h1><p>Protect sign-ins to your Zyntris account with an authenticator app.</p></div></div>{error && <div className="payroll-error" role="alert">{error}</div>}
    <section className="card settings-panel account-security-card"><div className="card-heading"><div><h2>Two-factor authentication</h2><p>Use a time-based code from an authenticator app in addition to your password.</p></div><span className={`status-badge ${status?.enabled ? "active" : "pending"}`}>{status ? status.enabled ? "Enabled" : "Not enabled" : "Loading"}</span></div>
      {!status ? <p className="subscription-note">Loading security status…</p> : status.enabled ? <><div className="security-note"><ShieldCheck size={18} /><div><strong>Your account requires an authenticator code at sign-in</strong><span>{status.recoveryCodesRemaining} unused recovery codes remain. Keep them somewhere private.</span></div></div>
        <form className="two-factor-form" onSubmit={disable}><label>Current password<input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label><label>Authenticator or recovery code<input value={code} onChange={(event) => setCode(event.target.value)} autoComplete="one-time-code" required placeholder="6-digit code or one-time recovery code" /></label><button className="button secondary" disabled={busy}>{busy ? "Please wait…" : "Disable two-factor authentication"}</button></form></>
        : setup ? <><div className="security-note"><ShieldCheck size={18} /><div><strong>Add this account to an authenticator app</strong><span>In Google Authenticator, Microsoft Authenticator, 1Password or another TOTP app, choose manual setup and enter the secret below. Setup expires in 10 minutes.</span></div></div><div className="totp-secret"><span>Setup key</span><code>{setup.secret}</code><button className="button secondary" type="button" onClick={() => void navigator.clipboard?.writeText(setup.secret)}><Copy size={14} /> Copy key</button></div><details className="totp-details"><summary>Advanced setup URI</summary><code>{setup.provisioningUri}</code></details><form className="two-factor-form" onSubmit={enable}><label>6-digit code from your authenticator<input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(event) => setCode(event.target.value)} required pattern="[0-9 ]{6,8}" placeholder="000000" /></label><div className="full"><button className="button primary" disabled={busy}>{busy ? "Verifying…" : "Verify and enable"}</button><button className="button secondary" type="button" onClick={() => { setSetup(null); setCode(""); }}>Cancel</button></div></form></>
        : <><div className="security-note"><ShieldCheck size={18} /><div><strong>Additional sign-in protection is off</strong><span>After enabling, each sign-in on web and mobile will require a code from your authenticator.</span></div></div><form className="two-factor-form" onSubmit={start}><label>Confirm your current password<input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label><button className="button primary" disabled={busy}>{busy ? "Preparing…" : "Set up two-factor authentication"}</button></form></>}
    </section>
    {recoveryCodes.length > 0 && <section className="card settings-panel recovery-panel"><div className="card-heading"><div><h2>Save your recovery codes</h2><p>Each code works once if you cannot access your authenticator. This list is shown only now.</p></div><Check size={18} /></div><div className="recovery-code-grid">{recoveryCodes.map((item) => <code key={item}>{item}</code>)}</div><button className="button secondary" onClick={() => void navigator.clipboard?.writeText(recoveryCodes.join("\n"))}><Copy size={14} /> Copy recovery codes</button><p className="subscription-note">Store these codes securely. You cannot view them again after leaving this page.</p></section>}
  </>;
}
