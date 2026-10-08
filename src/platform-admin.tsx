import { useCallback, useEffect, useState } from "react";
import { Activity, Building2, Clock3, KeyRound, LockKeyhole, RefreshCw, Search, ShieldCheck, Users, type LucideIcon } from "lucide-react";
import "./platform-admin.css";

type Summary = { organizations: number; active: number; trialing: number; suspended: number; users: number; employees: number };
type Organization = { id: string; name: string; slug: string; industry: string | null; status: string; isDemo: number; serviceEnabled: number; createdAt: string; plan: string | null; subscriptionStatus: string | null; trialEndsAt: string | null; members: number; employees: number; lastActivity: string | null };
type TenantUser = { id: string; fullName: string; email: string; status: string; emailVerifiedAt: string | null; role: string; createdAt: string };
type ActivityEntry = { id: string; organizationName: string; actorName: string | null; action: string; module: string; recordType: string | null; createdAt: string };

async function platformApi<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: "include", ...init, headers: { "content-type": "application/json", ...(init?.headers || {}) } });
  const data = await response.json().catch(() => ({})) as { error?: string };
  if (!response.ok) throw new Error(data.error || "Platform action could not be completed.");
  return data as T;
}

const date = (value: string | null) => value ? new Date(`${value.replace(" ", "T")}Z`).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "No activity yet";

export function PlatformAdminWorkspace() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [activity, setActivity] = useState<ActivityEntry[]>([]);
  const [tenantUsers, setTenantUsers] = useState<TenantUser[]>([]);
  const [tenantActivity, setTenantActivity] = useState<ActivityEntry[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [orgOffset, setOrgOffset] = useState(0);
  const [activityOffset, setActivityOffset] = useState(0);
  const [orgTotal, setOrgTotal] = useState(0);
  const [activityTotal, setActivityTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError(""); setNotice("");
    try {
      const [summaryData, orgData, activityData] = await Promise.all([
        platformApi<Summary>("/api/platform/summary"),
        platformApi<{ data: Organization[]; total: number }>(`/api/platform/organizations?limit=50&offset=0&search=${encodeURIComponent(query)}`),
        platformApi<{ data: ActivityEntry[]; total: number }>("/api/platform/activity?limit=50&offset=0"),
      ]);
      setSummary(summaryData); setOrganizations(orgData.data); setActivity(activityData.data);
      setOrgTotal(orgData.total); setActivityTotal(activityData.total);
      setOrgOffset(orgData.data.length); setActivityOffset(activityData.data.length);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Platform overview could not be loaded."); }
    finally { setLoading(false); }
  }, [query]);

  const loadMoreOrganizations = async () => {
    setLoading(true); setError("");
    try {
      const result = await platformApi<{ data: Organization[]; total: number }>(`/api/platform/organizations?limit=50&offset=${orgOffset}&search=${encodeURIComponent(query)}`);
      setOrganizations((current) => [...current, ...result.data]); setOrgOffset((current) => current + result.data.length); setOrgTotal(result.total);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Tenants could not be loaded."); }
    finally { setLoading(false); }
  };

  const loadMoreActivity = async () => {
    setLoading(true); setError("");
    try {
      const result = await platformApi<{ data: ActivityEntry[]; total: number }>(`/api/platform/activity?limit=50&offset=${activityOffset}`);
      setActivity((current) => [...current, ...result.data]); setActivityOffset((current) => current + result.data.length); setActivityTotal(result.total);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Activity could not be loaded."); }
    finally { setLoading(false); }
  };

  const manageTenant = async (org: Organization) => {
    if (selectedOrg === org.id) { setSelectedOrg(null); setTenantUsers([]); setTenantActivity([]); return; }
    setSelectedOrg(org.id); setTenantUsers([]); setTenantActivity([]); setError("");
    try {
      const [users, events] = await Promise.all([
        platformApi<{ data: TenantUser[] }>(`/api/platform/organizations/${encodeURIComponent(org.id)}/users`),
        platformApi<{ data: ActivityEntry[] }>(`/api/platform/activity?organizationId=${encodeURIComponent(org.id)}&limit=20&offset=0`),
      ]);
      setTenantUsers(users.data); setTenantActivity(events.data);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Tenant maintenance details could not be loaded."); }
  };

  const toggleTenant = async (org: Organization) => {
    const enabled = !Boolean(org.serviceEnabled);
    const message = enabled
      ? `Enable services for ${org.name}? If its trial expired, this administrator action activates the subscription.`
      : `Disable services for ${org.name}? All current tenant sessions will be signed out.`;
    if (!window.confirm(message)) return;
    setBusyAction(`service:${org.id}`); setError(""); setNotice("");
    try {
      await platformApi(`/api/platform/organizations/${encodeURIComponent(org.id)}/service`, { method: "PATCH", body: JSON.stringify({ enabled }) });
      await load();
      setNotice(`${org.name} services ${enabled ? "enabled" : "disabled"}.`);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Tenant services could not be updated."); }
    finally { setBusyAction(""); }
  };

  const sendPasswordReset = async (org: Organization, user: TenantUser) => {
    if (!window.confirm(`Send a one-time hard-reset link to ${user.role} ${user.email} for ${org.name}? Their existing sessions will be signed out after Brevo accepts the email.`)) return;
    setBusyAction(`reset:${user.id}`); setError(""); setNotice("");
    try {
      const result = await platformApi<{ recipient: string; expiresIn: number; sessionsRevoked: boolean }>(`/api/platform/organizations/${encodeURIComponent(org.id)}/users/${encodeURIComponent(user.id)}/password-reset`, { method: "POST", body: "{}" });
      setNotice(`Brevo accepted a 30-minute hard-reset link for ${result.recipient}; their existing sessions were revoked.`);
      const events = await platformApi<{ data: ActivityEntry[] }>(`/api/platform/activity?organizationId=${encodeURIComponent(org.id)}&limit=20&offset=0`);
      if (selectedOrg === org.id) setTenantActivity(events.data);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "The password reset email could not be sent."); }
    finally { setBusyAction(""); }
  };

  useEffect(() => { void load(); }, [load]);

  return <div className="platform-admin">
    <header className="page-header"><div><div className="eyebrow">ZYNTRIS / PLATFORM</div><h1>Main administrator</h1><p>View every tenant, manage service access and assist with account recovery.</p></div><button className="button secondary" onClick={() => void load()} disabled={loading}><RefreshCw size={15} /> Refresh</button></header>
    <div className="platform-privacy"><ShieldCheck size={17} /><span>Privileged controls are audited. Tenant financial records, payroll, bank details and customer content are not shown. The demo tenant is visible but protected from administrative changes.</span></div>
    {error && <div className="platform-error" role="alert">{error}</div>}
    {notice && <div className="platform-notice" role="status">{notice}</div>}
    <div className="platform-stats">
      <Stat icon={Building2} label="Tenants" value={summary?.organizations} detail={`${summary?.active || 0} active services`} />
      <Stat icon={Clock3} label="Trials" value={summary?.trialing} detail={`${summary?.suspended || 0} suspended or expired`} />
      <Stat icon={Users} label="People" value={summary?.users} detail={`${summary?.employees || 0} employee records`} />
      <Stat icon={Activity} label="Audit events" value={activityTotal} detail="All tenants" />
    </div>

    <section className="card platform-card">
      <div className="card-heading"><div><h2>All tenants</h2><p>{orgTotal.toLocaleString()} workspaces, including the protected demo tenant</p></div><form className="platform-search" onSubmit={(event) => { event.preventDefault(); setOrgOffset(0); setQuery(search.trim()); }}><Search size={16} /><input aria-label="Search tenants" placeholder="Search tenants" value={search} onChange={(event) => setSearch(event.target.value)} /><button type="submit">Search</button></form></div>
      <div className="table-scroll"><table><thead><tr><th>Tenant</th><th>Subscription</th><th>Service access</th><th>Plan</th><th>Members</th><th>Employees</th><th>Last activity</th><th>Onboarded</th><th>Manage</th></tr></thead><tbody>
        {organizations.map((org) => <TenantRows key={org.id} org={org} selected={selectedOrg === org.id} users={tenantUsers} activity={tenantActivity} busyAction={busyAction} onManage={() => void manageTenant(org)} onToggle={() => void toggleTenant(org)} onReset={(user) => void sendPasswordReset(org, user)} />)}
        {!loading && !organizations.length && <tr><td colSpan={9} className="platform-empty">No tenants match this search.</td></tr>}
      </tbody></table></div>
      {orgOffset < orgTotal && <div className="platform-more"><button className="button secondary" onClick={() => void loadMoreOrganizations()} disabled={loading}>Load more tenants</button></div>}
    </section>

    <section className="card platform-card">
      <div className="card-heading"><div><h2>Recent activity</h2><p>Audit events across all tenants</p></div></div>
      <div className="table-scroll"><table><thead><tr><th>Tenant</th><th>Activity</th><th>Module</th><th>Actor</th><th>Time</th></tr></thead><tbody>
        {activity.map((entry) => <tr key={entry.id}><td><strong>{entry.organizationName}</strong></td><td>{entry.action.replaceAll("_", " ")}{entry.recordType ? ` · ${entry.recordType.replaceAll("_", " ")}` : ""}</td><td>{entry.module}</td><td>{entry.actorName || "System"}</td><td>{date(entry.createdAt)}</td></tr>)}
        {!loading && !activity.length && <tr><td colSpan={5} className="platform-empty">No activity has been recorded yet.</td></tr>}
      </tbody></table></div>
      {activityOffset < activityTotal && <div className="platform-more"><button className="button secondary" onClick={() => void loadMoreActivity()} disabled={loading}>Load older activity</button></div>}
    </section>
  </div>;
}

function TenantRows({ org, selected, users, activity, busyAction, onManage, onToggle, onReset }: { org: Organization; selected: boolean; users: TenantUser[]; activity: ActivityEntry[]; busyAction: string; onManage: () => void; onToggle: () => void; onReset: (user: TenantUser) => void }) {
  const enabled = Boolean(org.serviceEnabled);
  return <>
    <tr>
      <td><strong>{org.name}{Boolean(org.isDemo) && <span className="platform-demo-tag">Demo</span>}</strong><span className="platform-org-meta">{org.industry || org.slug}</span></td>
      <td><span className={`platform-status ${org.subscriptionStatus || org.status}`}>{org.subscriptionStatus || org.status}</span>{org.trialEndsAt && org.subscriptionStatus === "trialing" && <span className="platform-org-meta">Ends {date(org.trialEndsAt)}</span>}</td>
      <td><span className={`platform-status ${enabled ? "active" : "suspended"}`}>{enabled ? "Enabled" : "Disabled"}</span></td>
      <td>{org.plan || "—"}</td><td>{org.members}</td><td>{org.employees}</td><td>{date(org.lastActivity)}</td><td>{date(org.createdAt)}</td>
      <td className="platform-row-actions"><button className="platform-link-button" onClick={onManage}>{selected ? "Close" : "Manage"}</button><button className="button secondary platform-toggle" onClick={onToggle} disabled={Boolean(org.isDemo) || busyAction === `service:${org.id}`}>{busyAction === `service:${org.id}` ? "Saving…" : enabled ? <><LockKeyhole size={13} /> Disable</> : <><ShieldCheck size={13} /> Enable</>}</button></td>
    </tr>
    {selected && <tr><td colSpan={9} className="platform-members-cell"><div className="platform-members"><div className="platform-members-heading"><div><strong>Tenant maintenance</strong><span>{users.length} tenant accounts · service access is managed above</span></div></div><div className="table-scroll"><table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Account</th><th>Verified</th><th>Admin recovery</th></tr></thead><tbody>
      {users.map((user) => { const isTenantAdmin = user.role === "Organization Admin" || user.role === "CEO"; return <tr key={user.id}><td><strong>{user.fullName}</strong></td><td>{user.email}</td><td>{user.role}</td><td>{user.status}</td><td>{user.emailVerifiedAt ? "Yes" : "No"}</td><td>{isTenantAdmin ? <button className="platform-reset-button" onClick={() => onReset(user)} disabled={!user.emailVerifiedAt || user.status !== "active" || Boolean(org.isDemo) || busyAction === `reset:${user.id}`}>{busyAction === `reset:${user.id}` ? "Sending…" : <><KeyRound size={13} /> Send hard-reset link</>}</button> : <span className="platform-reset-note">Admin only</span>}</td></tr>; })}
      {!users.length && <tr><td colSpan={6} className="platform-empty">No member accounts are attached to this tenant.</td></tr>}
    </tbody></table></div><p className="platform-reset-note">Hard resets are available only for verified Organization Admin or CEO accounts. The one-time email link expires in 30 minutes; sessions are revoked only after Brevo accepts the email.</p>
      <div className="platform-maintenance-activity"><div className="platform-members-heading"><div><strong>Tenant audit history</strong><span>Recent administrative and workspace events for {org.name}</span></div></div><div className="table-scroll"><table><thead><tr><th>Activity</th><th>Module</th><th>Actor</th><th>Time</th></tr></thead><tbody>{activity.map((entry) => <tr key={entry.id}><td>{entry.action.replaceAll("_", " ")}{entry.recordType ? ` · ${entry.recordType.replaceAll("_", " ")}` : ""}</td><td>{entry.module}</td><td>{entry.actorName || "System"}</td><td>{date(entry.createdAt)}</td></tr>)}{!activity.length && <tr><td colSpan={4} className="platform-empty">No audit events recorded for this tenant.</td></tr>}</tbody></table></div></div>
      </div></td></tr>}
  </>;
}

function Stat({ icon: Icon, label, value, detail }: { icon: LucideIcon; label: string; value?: number; detail: string }) {
  return <div className="card platform-stat"><span><Icon size={17} /></span><small>{label}</small><strong>{value?.toLocaleString() ?? "—"}</strong><em>{detail}</em></div>;
}
