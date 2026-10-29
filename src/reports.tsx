import { useEffect, useState, type FormEvent } from "react";
import { BarChart3, BriefcaseBusiness, CheckCircle2, ClipboardCheck, FileText, FolderKanban, Truck, Users, WalletCards } from "lucide-react";

type ReportSummary = {
  period: { from: string; to: string };
  people: { total?: number; active?: number };
  expenses: { count?: number; total?: number; pending?: number };
  leave: { pending?: number; approved?: number; rejected?: number };
  tasks: { total?: number; completed?: number; overdue?: number };
  tickets: { open?: number; resolved?: number };
  approvals: { pending?: number; approved?: number; rejected?: number };
  appraisals: { total?: number; completed?: number; inProgress?: number };
  projects: { total?: number; active?: number; atRisk?: number };
  purchases: { total?: number; open?: number; matched?: number };
  crm: { leads?: number; openOpportunities?: number; wonOpportunities?: number };
  fleet: { vehicles?: number; trips?: number; openIncidents?: number };
  departments: { name: string; count: number }[];
  monthlySpend: { month: string; amount: number }[];
};
const isoToday = () => new Date().toISOString().slice(0, 10);
const isoSixMonthsBack = () => { const date = new Date(); date.setUTCDate(1); date.setUTCMonth(date.getUTCMonth() - 5); return date.toISOString().slice(0, 10); };

export function ReportsWorkspace({ onToast }: { onToast: (message: string) => void }) {
  const [range, setRange] = useState({ from: isoSixMonthsBack(), to: isoToday() });
  const [draft, setDraft] = useState(range);
  const [data, setData] = useState<ReportSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true; setLoading(true); const params = new URLSearchParams(range);
    void fetch(`/api/reports/summary?${params}`, { credentials: "include" }).then(async (response) => {
      if (!response.ok) throw new Error((await response.json().catch(() => null))?.error || "Could not load reports.");
      return response.json() as Promise<ReportSummary>;
    }).then((result) => { if (active) { setData(result); setError(""); } }).catch((cause) => {
      if (active) setError(cause instanceof Error ? cause.message : "Could not load reports.");
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [range]);
  const apply = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); setRange(draft); };
  const exportCsv = () => {
    if (!data) return;
    const rows: (string | number)[][] = [
      ["Metric", "Value"], ["From", data.period.from], ["To", data.period.to],
      ["Employees", data.people.total || 0], ["Active employees", data.people.active || 0],
      ["Expense total", data.expenses.total || 0], ["Expense claims", data.expenses.count || 0], ["Pending expenses", data.expenses.pending || 0],
      ["Pending leave", data.leave.pending || 0], ["Tasks", data.tasks.total || 0], ["Completed tasks", data.tasks.completed || 0], ["Overdue tasks", data.tasks.overdue || 0],
      ["Open tickets", data.tickets.open || 0], ["Pending approvals", data.approvals.pending || 0], ["Appraisals", data.appraisals.total || 0],
      ["Projects", data.projects.total || 0], ["Projects at risk", data.projects.atRisk || 0], ["Purchase requests", data.purchases.total || 0], ["Open purchases", data.purchases.open || 0],
      ["CRM leads", data.crm.leads || 0], ["Open opportunities", data.crm.openOpportunities || 0], ["Won opportunities", data.crm.wonOpportunities || 0],
      ["Active fleet vehicles", data.fleet.vehicles || 0], ["Trips in range", data.fleet.trips || 0], ["Open fleet incidents", data.fleet.openIncidents || 0],
      ...data.monthlySpend.map((item) => [`Expense spend ${item.month}`, item.amount]),
    ];
    const csv = rows.map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(",")).join("\r\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" })); const link = document.createElement("a");
    link.href = url; link.download = `zyntris-operations-${data.period.from}-${data.period.to}.csv`; link.click(); URL.revokeObjectURL(url); onToast("Filtered live report exported as CSV.");
  };
  const months = (() => { const result: { key: string; amount: number }[] = []; const cursor = new Date(`${range.from.slice(0, 7)}-01T00:00:00Z`); const last = new Date(`${range.to.slice(0, 7)}-01T00:00:00Z`); while (cursor <= last && result.length < 13) { const key = cursor.toISOString().slice(0, 7); result.push({ key, amount: data?.monthlySpend.find((item) => item.month === key)?.amount || 0 }); cursor.setUTCMonth(cursor.getUTCMonth() + 1); } return result; })();
  const maxSpend = Math.max(1, ...months.map((month) => month.amount));
  const cards = data ? [
    { icon: Users, label: "Headcount", value: data.people.total || 0, note: `${data.people.active || 0} active employees` },
    { icon: WalletCards, label: "Expenses", value: (data.expenses.total || 0).toLocaleString(), note: `${data.expenses.count || 0} claims in range` },
    { icon: CheckCircle2, label: "Pending approvals", value: data.approvals.pending || 0, note: `${data.leave.pending || 0} leave requests pending` },
    { icon: ClipboardCheck, label: "Tasks", value: data.tasks.total || 0, note: `${data.tasks.overdue || 0} overdue · ${data.tasks.completed || 0} complete` },
    { icon: FolderKanban, label: "Projects", value: data.projects.total || 0, note: `${data.projects.atRisk || 0} currently at risk` },
    { icon: BriefcaseBusiness, label: "Purchasing", value: data.purchases.total || 0, note: `${data.purchases.open || 0} open · ${data.purchases.matched || 0} matched` },
    { icon: Users, label: "CRM", value: data.crm.leads || 0, note: `${data.crm.openOpportunities || 0} open · ${data.crm.wonOpportunities || 0} won` },
    { icon: Truck, label: "Fleet", value: data.fleet.vehicles || 0, note: `${data.fleet.trips || 0} trips · ${data.fleet.openIncidents || 0} open incidents` },
  ] : [];

  return <section className="page-section">
    <div className="page-heading"><div><div className="eyebrow">INSIGHTS / REPORTING</div><h1>Reports & analytics</h1><p>Live organization metrics across people, finance, delivery, customers and fleet.</p></div><button className="secondary-button" disabled={!data} onClick={exportCsv}><FileText size={15} /> Export CSV</button></div>
    <form className="card table-card report-filters" style={{ display: "flex", alignItems: "end", gap: 12, flexWrap: "wrap", marginBottom: 18 }} onSubmit={apply}><label style={{ display: "grid", gap: 6 }}>From<input type="date" value={draft.from} max={draft.to} required onChange={(event) => setDraft((value) => ({ ...value, from: event.target.value }))} /></label><label style={{ display: "grid", gap: 6 }}>To<input type="date" value={draft.to} min={draft.from} max={isoToday()} required onChange={(event) => setDraft((value) => ({ ...value, to: event.target.value }))} /></label><button className="button primary" disabled={loading}>Apply date range</button><small style={{ flex: "1 1 300px", color: "#718096" }}>Range is limited to 367 calendar days. Current headcount and open-work counts are snapshots.</small></form>
    {error && <div className="work-error" role="alert">{error}</div>}{loading ? <div className="work-loading">Loading live reports…</div> : data && <>
      <div className="report-grid">{cards.map(({ icon: Icon, label, value, note }) => <article className="card report-card" key={label}><span className="report-icon blue"><Icon size={19} /></span><div><strong>{label}: {value}</strong><span>{note}</span></div></article>)}</div>
      <section className="card report-preview"><div className="card-heading"><div><h2>Expense trend</h2><p>{data.period.from} to {data.period.to}</p></div><BarChart3 size={18} /></div><div className="pulse-grid"><div className="pulse-number"><span>Total recorded</span><strong>₦{new Intl.NumberFormat("en-NG", { notation: "compact", maximumFractionDigits: 1 }).format(data.expenses.total || 0)}</strong><small>{data.expenses.pending || 0} pending NGN claims by amount</small></div><div className="pulse-bars">{months.map((month) => <div key={month.key} title={`${month.key}: ₦${month.amount.toLocaleString()}`}><i style={{ height: `${Math.max(2, month.amount / maxSpend * 96)}%` }} /><span>{new Date(`${month.key}-01T00:00:00Z`).toLocaleDateString("en-NG", { month: "short", year: "2-digit", timeZone: "UTC" })}</span></div>)}</div></div></section>
      <section className="card report-preview"><div className="card-heading"><div><h2>Department headcount</h2><p>Current employee records by department</p></div></div>{data.departments.length ? <div className="report-departments">{data.departments.map((item) => <div key={item.name}><span>{item.name}</span><strong>{item.count}</strong></div>)}</div> : <div className="work-empty">No department records yet.</div>}<p className="report-note">Also tracked: {data.tickets.open || 0} open support tickets, {data.leave.rejected || 0} rejected leave requests, and {data.appraisals.inProgress || 0} in-progress appraisals ({data.appraisals.completed || 0} completed).</p></section>
    </>}
  </section>;
}
