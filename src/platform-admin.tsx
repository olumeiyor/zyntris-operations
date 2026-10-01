import { useCallback, useEffect, useState } from "react";
import { Activity, Building2, Clock3, RefreshCw, Search, ShieldCheck, Users, type LucideIcon } from "lucide-react";
import "./platform-admin.css";

type Summary = { organizations: number; active: number; trialing: number; suspended: number; users: number; employees: number };
type Organization = { id: string; name: string; slug: string; industry: string | null; status: string; createdAt: string; plan: string | null; subscriptionStatus: string | null; trialEndsAt: string | null; members: number; employees: number; lastActivity: string | null };
type ActivityEntry = { id: string; organizationName: string; actorName: string | null; action: string; module: string; recordType: string | null; createdAt: string };

async function readApi<T>(path: string): Promise<T> {
  const response = await fetch(path, { credentials: "include" });
  if (!response.ok) throw new Error((await response.json().catch(() => null))?.error || "Platform overview could not be loaded.");
  return response.json() as Promise<T>;
}

const date = (value: string | null) => value ? new Date(`${value.replace(" ", "T")}Z`).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "No activity yet";

export function PlatformAdminWorkspace() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [activity, setActivity] = useState<ActivityEntry[]>([]);
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [orgOffset, setOrgOffset] = useState(0);
  const [activityOffset, setActivityOffset] = useState(0);
  const [orgTotal, setOrgTotal] = useState(0);
  const [activityTotal, setActivityTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [summaryData, orgData, activityData] = await Promise.all([
        readApi<Summary>("/api/platform/summary"),
        readApi<{ data: Organization[]; total: number }>(`/api/platform/organizations?limit=50&offset=0&search=${encodeURIComponent(query)}`),
        readApi<{ data: ActivityEntry[]; total: number }>("/api/platform/activity?limit=50&offset=0"),
      ]);
      setSummary(summaryData);
      setOrganizations(orgData.data);
      setActivity(activityData.data);
      setOrgTotal(orgData.total); setActivityTotal(activityData.total);
      setOrgOffset(orgData.data.length); setActivityOffset(activityData.data.length);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Platform overview could not be loaded."); }
    finally { setLoading(false); }
  }, [query]);

  const loadMoreOrganizations = async () => {
    setLoading(true); setError("");
    try {
      const result = await readApi<{ data: Organization[]; total: number }>(`/api/platform/organizations?limit=50&offset=${orgOffset}&search=${encodeURIComponent(query)}`);
      setOrganizations((current) => [...current, ...result.data]); setOrgOffset((current) => current + result.data.length); setOrgTotal(result.total);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Organizations could not be loaded."); }
    finally { setLoading(false); }
  };

  const loadMoreActivity = async () => {
    setLoading(true); setError("");
    try {
      const result = await readApi<{ data: ActivityEntry[]; total: number }>(`/api/platform/activity?limit=50&offset=${activityOffset}`);
      setActivity((current) => [...current, ...result.data]); setActivityOffset((current) => current + result.data.length); setActivityTotal(result.total);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Activity could not be loaded."); }
    finally { setLoading(false); }
  };

  useEffect(() => { void load(); }, [load]);

  return <div className="platform-admin">
    <header className="page-header"><div><div className="eyebrow">ZYNTRIS / PLATFORM</div><h1>Organization overview</h1><p>Monitor onboarding and recent workspace activity across customer organizations.</p></div><button className="button secondary" onClick={() => void load()} disabled={loading}><RefreshCw size={15} /> Refresh</button></header>
    <div className="platform-privacy"><ShieldCheck size={17} /><span>Read-only platform view. Demo records, payroll details, bank information and customer content are excluded.</span></div>
    {error && <div className="platform-error" role="alert">{error}</div>}
    <div className="platform-stats">
      <Stat icon={Building2} label="Organizations" value={summary?.organizations} detail={`${summary?.active || 0} active`} />
      <Stat icon={Clock3} label="Trials" value={summary?.trialing} detail={`${summary?.suspended || 0} suspended`} />
      <Stat icon={Users} label="People" value={summary?.users} detail={`${summary?.employees || 0} employee records`} />
      <Stat icon={Activity} label="Audit events" value={activityTotal} detail="Customer organizations only" />
    </div>

    <section className="card platform-card">
      <div className="card-heading"><div><h2>Onboarded organizations</h2><p>{orgTotal.toLocaleString()} customer workspaces</p></div><form className="platform-search" onSubmit={(event) => { event.preventDefault(); setOrgOffset(0); setQuery(search.trim()); }}><Search size={16} /><input aria-label="Search organizations" placeholder="Search organizations" value={search} onChange={(event) => setSearch(event.target.value)} /><button type="submit">Search</button></form></div>
      <div className="table-scroll"><table><thead><tr><th>Organization</th><th>Status</th><th>Plan</th><th>Members</th><th>Employees</th><th>Last activity</th><th>Onboarded</th></tr></thead><tbody>
        {organizations.map((org) => <tr key={org.id}><td><strong>{org.name}</strong><span className="platform-org-meta">{org.industry || org.slug}</span></td><td><span className={`platform-status ${org.subscriptionStatus || org.status}`}>{org.subscriptionStatus || org.status}</span></td><td>{org.plan || "—"}</td><td>{org.members}</td><td>{org.employees}</td><td>{date(org.lastActivity)}</td><td>{date(org.createdAt)}</td></tr>)}
        {!loading && !organizations.length && <tr><td colSpan={7} className="platform-empty">No organizations match this search.</td></tr>}
      </tbody></table></div>
      {orgOffset < orgTotal && <div className="platform-more"><button className="button secondary" onClick={() => void loadMoreOrganizations()} disabled={loading}>Load more organizations</button></div>}
    </section>

    <section className="card platform-card">
      <div className="card-heading"><div><h2>Recent activity</h2><p>Audit events across onboarded organizations</p></div></div>
      <div className="table-scroll"><table><thead><tr><th>Organization</th><th>Activity</th><th>Module</th><th>Actor</th><th>Time</th></tr></thead><tbody>
        {activity.map((entry) => <tr key={entry.id}><td><strong>{entry.organizationName}</strong></td><td>{entry.action.replaceAll("_", " ")}{entry.recordType ? ` · ${entry.recordType.replaceAll("_", " ")}` : ""}</td><td>{entry.module}</td><td>{entry.actorName || "System"}</td><td>{date(entry.createdAt)}</td></tr>)}
        {!loading && !activity.length && <tr><td colSpan={5} className="platform-empty">No activity has been recorded yet.</td></tr>}
      </tbody></table></div>
      {activityOffset < activityTotal && <div className="platform-more"><button className="button secondary" onClick={() => void loadMoreActivity()} disabled={loading}>Load older activity</button></div>}
    </section>
  </div>;
}

function Stat({ icon: Icon, label, value, detail }: { icon: LucideIcon; label: string; value?: number; detail: string }) {
  return <div className="card platform-stat"><span><Icon size={17} /></span><small>{label}</small><strong>{value?.toLocaleString() ?? "—"}</strong><em>{detail}</em></div>;
}
