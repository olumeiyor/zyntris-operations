import { useEffect, useMemo, useState, type FormEvent } from "react";
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, Award, BarChart3, Bell, BriefcaseBusiness, Building2,
  CalendarDays, CheckCircle2, ChevronDown, ChevronLeft, CircleHelp, ClipboardCheck, Clock3, Cloud,
  Command, CreditCard, FileText, FolderKanban, Grid2x2, LayoutDashboard, LifeBuoy, ListTodo, LockKeyhole,
  Menu, MessageSquareText, MoreHorizontal, PanelLeftClose, PanelLeftOpen, Plus, Search, Settings, ShieldCheck,
  Sparkles, TrendingUp, UploadCloud, UserRound, Users, WalletCards, X,
} from "lucide-react";
import { demoDashboard, demoEmployees, demoLeave, demoTasks, demoUser } from "./data/demo";
import { OperationalWorkspace } from "./operations";
import { Onboarding } from "./onboarding";
import { EmployeePayslips, PayrollWorkspace } from "./payroll";
import { PlatformAdminWorkspace } from "./platform-admin";
import { AccountSecurity, OrganizationSettings } from "./settings";
import { Appraisals } from "./appraisals";
import { HRTalentWorkspace } from "./hr-talent";
import type { DashboardData, Employee, LeaveRequest, PageId, Task } from "./types";

type IconComponent = typeof LayoutDashboard;
type InboxNotification = { id: string; type: string; title: string; body: string; readAt: string | null; createdAt: string };

type NavItem = { id: PageId; label: string; icon: IconComponent; badge?: string; section?: string; soon?: boolean };

const navItems: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "employees", label: "Employees", icon: Users, section: "People" },
  { id: "appraisals", label: "Performance & appraisals", icon: Award, section: "People" },
  { id: "talent", label: "Teams & talent", icon: Users, section: "People" },
  { id: "leave", label: "Leave & attendance", icon: CalendarDays, badge: "12", section: "People" },
  { id: "payroll", label: "Payroll", icon: WalletCards, section: "People" },
  { id: "projects", label: "Projects", icon: FolderKanban, section: "Work" },
  { id: "tasks", label: "Tasks", icon: ListTodo, section: "Work" },
  { id: "expenses", label: "Expenses", icon: WalletCards, section: "Finance" },
  { id: "requests", label: "Requests & approvals", icon: ClipboardCheck, badge: "4", section: "Finance" },
  { id: "budgets", label: "Budgets", icon: CreditCard, section: "Finance" },
  { id: "assets", label: "Assets", icon: BriefcaseBusiness, section: "Operations" },
  { id: "documents", label: "Documents", icon: FileText, section: "Operations" },
  { id: "vendors", label: "Vendors", icon: Building2, section: "Operations" },
  { id: "helpdesk", label: "Helpdesk", icon: LifeBuoy, section: "Operations" },
  { id: "calendar", label: "Calendar", icon: CalendarDays, section: "Work" },
  { id: "customers", label: "Customers & CRM", icon: UserRound, section: "Customers" },
  { id: "reports", label: "Reports & analytics", icon: BarChart3, section: "Insights" },
  { id: "settings", label: "Administration", icon: Settings, section: "Workspace" },
  { id: "security", label: "Account security", icon: ShieldCheck, section: "Workspace" },
  { id: "platform", label: "Platform admin", icon: ShieldCheck, section: "Platform" },
];

const formatNaira = (value: number) => `₦${new Intl.NumberFormat("en-NG", { notation: "compact", maximumFractionDigits: 1 }).format(value)}`;
const initials = (first: string, last: string) => `${first[0]}${last[0]}`.toUpperCase();
const titleCase = (value: string) => value.replace(/_/g, " ").replace(/\b\w/g, (match) => match.toUpperCase());

class ApiError extends Error { constructor(message: string, readonly status: number) { super(message); } }

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: "include", ...init });
  if (!response.ok) throw new ApiError((await response.json().catch(() => null))?.error || "Request failed", response.status);
  return response.json() as Promise<T>;
}

export default function App() {
  const [page, setPage] = useState<PageId>("dashboard");
  const [collapsed, setCollapsed] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const [user, setUser] = useState<{ id: string; fullName: string; email: string; role: string; organizationId: string; organizationName: string; permissions?: string[]; trialEndsAt?: string | null; subscriptionStatus?: string; isPlatformAdmin?: boolean; isDemo?: boolean } | null>(null);
  const [dashboard, setDashboard] = useState<DashboardData>(demoDashboard);
  const [employees, setEmployees] = useState<Employee[]>(demoEmployees);
  const [leave, setLeave] = useState<LeaveRequest[]>(demoLeave);
  const [tasks, setTasks] = useState<Task[]>(demoTasks);
  const [connected, setConnected] = useState(false);
  const [authLoading, setAuthLoading] = useState(true);
  const [authNotice, setAuthNotice] = useState("");
  const [showAddEmployee, setShowAddEmployee] = useState(false);
  const [showUpload, setShowUpload] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [notifications, setNotifications] = useState<InboxNotification[]>([]);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const [notificationOpen, setNotificationOpen] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const token = new URLSearchParams(window.location.search).get("verify");
        if (token) {
          await api("/api/auth/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });
          window.history.replaceState({}, "", window.location.pathname);
          setAuthNotice("Your email is verified. Your organization workspace is ready.");
        }
        const [me, data, people, leaveData, taskData] = await Promise.all([
          api<NonNullable<typeof user>>("/api/me"), api<DashboardData>("/api/dashboard"), api<{ data: Employee[] }>("/api/employees"), api<{ data: LeaveRequest[] }>("/api/leave"), api<{ data: Task[] }>("/api/tasks"),
        ]);
        setUser(me); setDashboard(data); setEmployees(people.data); setLeave(leaveData.data); setTasks(taskData.data); setConnected(true);
      } catch {
        setConnected(false);
      } finally {
        setAuthLoading(false);
      }
    };
    void load();
  }, []);

  const refreshNotifications = async () => {
    try {
      const data = await api<{ data: InboxNotification[]; unread: number }>("/api/notifications");
      setNotifications(data.data); setUnreadNotifications(data.unread);
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) {
        setUser(null); setConnected(false); setNotifications([]); setUnreadNotifications(0);
        setAuthNotice("This workspace is no longer active. Contact Zyntris to restore tenant service.");
      }
    }
  };

  useEffect(() => {
    if (!user?.id) return;
    void refreshNotifications();
    const interval = window.setInterval(() => void refreshNotifications(), 45_000);
    return () => window.clearInterval(interval);
  }, [user?.id]);

  const markNotificationRead = async (id: string) => {
    try { await api(`/api/notifications/${id}/read`, { method: "PATCH" }); await refreshNotifications(); }
    catch (cause) { setToast(cause instanceof Error ? cause.message : "Could not update notification"); }
  };

  const markAllNotificationsRead = async () => {
    try { await api("/api/notifications/read-all", { method: "PATCH" }); await refreshNotifications(); }
    catch (cause) { setToast(cause instanceof Error ? cause.message : "Could not update notifications"); }
  };

  const reloadWorkspace = async () => {
    setAuthLoading(true);
    try {
      const [me, data, people, leaveData, taskData] = await Promise.all([
        api<NonNullable<typeof user>>("/api/me"), api<DashboardData>("/api/dashboard"), api<{ data: Employee[] }>("/api/employees"), api<{ data: LeaveRequest[] }>("/api/leave"), api<{ data: Task[] }>("/api/tasks"),
      ]);
      setUser(me); setDashboard(data); setEmployees(people.data); setLeave(leaveData.data); setTasks(taskData.data); setConnected(true); setAuthNotice("");
    } catch { setUser(null); }
    finally { setAuthLoading(false); }
  };

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(null), 3600);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  const currentLabel = navItems.find((item) => item.id === page)?.label || "Dashboard";
  const userPermissions = new Set(user?.permissions || []);
  const visibleNavItems = navItems.filter((item) => {
    if (item.id === "platform") return Boolean(user?.isPlatformAdmin);
    if (item.id === "settings") return userPermissions.has("settings.manage");
    if (item.id === "security") return true;
    if (["employees", "leave"].includes(item.id)) return userPermissions.has("employees.view");
    if (item.id === "payroll") return userPermissions.has("payroll.view") || userPermissions.has("payroll.manage") || userPermissions.has("payroll.self.view");
    if (item.id === "appraisals") return userPermissions.has("appraisals.view") || userPermissions.has("appraisals.manage") || userPermissions.has("appraisals.self.view");
    if (item.id === "talent") return userPermissions.has("hr.talent.view") || userPermissions.has("hr.talent.manage");
    if (item.id === "expenses") return userPermissions.has("expenses.view") || userPermissions.has("expenses.manage");
    if (item.id === "requests") return userPermissions.has("requests.manage") || userPermissions.has("employees.view");
    if (["dashboard", "reports"].includes(item.id)) return userPermissions.has("employees.view") || userPermissions.has("operations.view");
    return userPermissions.has("operations.view");
  });
  const openPage = (next: PageId) => { setPage(next); setMobileNav(false); };

  if (authLoading) return <main className="auth-loading"><img src="/zyntris-mark.png" alt="" /><span>Opening your secure workspace…</span></main>;
  if (!user) return <Onboarding onAuthenticated={() => void reloadWorkspace()} initialNotice={authNotice} />;

  const createEmployee = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const body = Object.fromEntries(form.entries());
    try {
      const result = await api<{ id: string; employeeNumber: string; onboardingStatus: "invited"; accessRole: string; invitationEmailAccepted: boolean; invitationEmailStatus: "accepted" | "failed"; invitationEmailError?: string }>("/api/employees", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const manager = employees.find((person) => person.id === body.managerId);
      setEmployees((current) => [{ id: result.id, employeeNumber: result.employeeNumber, firstName: String(body.firstName), lastName: String(body.lastName), email: String(body.email), jobTitle: String(body.jobTitle), department: String(body.departmentName || "Unassigned"), team: String(body.teamName || ""), managerId: String(body.managerId || "") || null, managerName: manager ? `${manager.firstName} ${manager.lastName}` : null, status: "inactive", onboardingStatus: result.onboardingStatus, invitationEmailStatus: result.invitationEmailStatus, accessRole: result.accessRole, workLocation: String(body.workLocation || "Hybrid"), startDate: String(body.startDate), avatarColor: "#dbeafe" }, ...current]);
      setToast(result.invitationEmailAccepted ? `Brevo accepted the onboarding email for ${String(body.email)}. Ask them to check spam if it doesn’t arrive shortly.` : `Employee added, but the invitation email failed: ${result.invitationEmailError || "unknown email error"} Retry it from the employee list after correcting email settings.`); setShowAddEmployee(false);
    } catch (cause) { setToast(cause instanceof Error ? cause.message : "Could not invite employee"); }
  };

  const uploadDocument = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api<{ id: string }>("/api/files", { method: "POST", body: form });
      setToast("Document uploaded to private R2 storage");
    } catch {
      setToast("Demo mode: connect the Worker to upload documents");
    }
    setShowUpload(false);
  };

  return (
    <div className="app-shell">
      <aside className={`sidebar ${collapsed ? "is-collapsed" : ""} ${mobileNav ? "is-mobile-open" : ""}`}>
        <div className="brand-row">
          {collapsed ? <img className="brand-logo-compact" src="/zyntris-mark.png" alt="Zyntris" /> : <div className="brand-lockup"><img className="brand-logo" src="/zyntris-mark.png" alt="" /><span>Zyntris</span></div>}
          <button className="icon-button sidebar-close" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X size={18} /></button>
        </div>
        <div className="workspace-switcher">
          <div className="workspace-avatar">{user.organizationName.split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase()}</div>
          {!collapsed && <><div className="workspace-copy"><strong>{user.organizationName}</strong><span>Business workspace</span></div><ChevronDown size={15} className="muted-icon" /></>}
        </div>
        <nav className="side-nav">
          {visibleNavItems.map((item, index) => (
            <div key={item.id}>
              {!collapsed && item.section && (index === 1 || visibleNavItems[index - 1]?.section !== item.section) && <div className="nav-section-label">{item.section}</div>}
              <button className={`nav-item ${page === item.id ? "active" : ""}`} onClick={() => openPage(item.id)} title={collapsed ? item.label : undefined}>
                <item.icon size={18} strokeWidth={page === item.id ? 2.2 : 1.8} />
                {!collapsed && <><span>{item.id === "payroll" && !userPermissions.has("payroll.view") && !userPermissions.has("payroll.manage") ? "My payslips" : item.label}</span>{item.badge && <span className="nav-badge">{item.badge}</span>}</>}
              </button>
            </div>
          ))}
        </nav>
        {!collapsed && <div className="sidebar-bottom"><div className="help-card"><div className="help-icon"><CircleHelp size={16} /></div><div><strong>Need a hand?</strong><span>Visit the help centre</span></div><ChevronLeft size={14} /></div><div className="sidebar-footer"><span className="status-dot"></span><span>{user.isDemo ? "Read-only demo" : connected ? "Cloud connected" : "Demo workspace"}</span><Cloud size={14} /></div></div>}
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="topbar-left"><button className="icon-button mobile-menu" onClick={() => setMobileNav(true)}><Menu size={20} /></button><button className="collapse-button" onClick={() => setCollapsed(!collapsed)} aria-label="Toggle sidebar">{collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}</button><div className="breadcrumb"><span>Workspace</span><ChevronLeft size={14} className="breadcrumb-chevron" /><strong>{currentLabel}</strong></div></div>
          <div className="topbar-actions"><button className="search-trigger" onClick={() => setToast("Global search is ready for employees, tasks, documents and more")}><Search size={17} /><span>Search anything</span><kbd>⌘ K</kbd></button><div className="notification-wrap"><button className="icon-button notification-button" aria-label={`Notifications, ${unreadNotifications} unread`} aria-expanded={notificationOpen} onClick={() => { setNotificationOpen(!notificationOpen); if (!notificationOpen) void refreshNotifications(); }}><Bell size={18} />{unreadNotifications > 0 && <span className="notification-count">{unreadNotifications > 9 ? "9+" : unreadNotifications}</span>}</button>{notificationOpen && <section className="notification-popover"><div className="notification-heading"><div><strong>Notifications</strong><span>{unreadNotifications ? `${unreadNotifications} unread` : "All caught up"}</span></div>{unreadNotifications > 0 && <button onClick={() => void markAllNotificationsRead()}>Mark all read</button>}</div><div className="notification-list">{notifications.length ? notifications.map((item) => <button className={`notification-item ${item.readAt ? "is-read" : ""}`} key={item.id} onClick={() => { if (!item.readAt) void markNotificationRead(item.id); }}><span className="notification-indicator"><Bell size={14} /></span><span className="notification-copy"><strong>{item.title}</strong><span>{item.body}</span><small>{new Date(item.createdAt).toLocaleString()}</small></span></button>) : <div className="notification-empty">No notifications yet. New approvals will appear here.</div>}</div></section>}</div><div className="topbar-divider"></div><button className="profile-chip" onClick={async () => { await api("/api/auth/logout", { method: "POST" }); setUser(null); }}><div className="avatar avatar-sm">{user.fullName.split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase()}</div><span>{user.fullName.split(" ")[0]}</span><ChevronDown size={14} /></button></div>
        </header>

        <div className="page-wrap">
          {user.isDemo && <div className="trial-banner"><span><ShieldCheck size={16} /> Demo sandbox</span><span>Fictional data · read-only · changes are disabled</span></div>}
          {user.subscriptionStatus === "trialing" && user.trialEndsAt && <div className="trial-banner"><span><CheckCircle2 size={16} /> 15-day trial</span><span>Your trial ends {new Date(user.trialEndsAt).toLocaleDateString("en-NG", { dateStyle: "medium" })}. <button onClick={() => openPage("settings")}>Subscription options</button></span></div>}
          {page === "dashboard" && <Dashboard data={dashboard} user={user} onNavigate={openPage} onToast={setToast} />}
          {page === "employees" && <Employees employees={employees} onAdd={() => setShowAddEmployee(true)} canManage={userPermissions.has("employees.manage")} onToast={setToast} onDeliveryUpdated={(id, status) => setEmployees((current) => current.map((employee) => employee.id === id ? { ...employee, invitationEmailStatus: status } : employee))} />}
          {page === "appraisals" && <Appraisals user={{ id: user.id, permissions: user.permissions }} onToast={setToast} />}
          {page === "talent" && <HRTalentWorkspace user={{ id: user.id, permissions: user.permissions || [] }} employees={employees} onToast={setToast} onEmployeesUpdated={async () => { try { const people = await api<{ data: Employee[] }>("/api/employees"); setEmployees(people.data); } catch { /* handled in the workspace */ } }} />}
          {page === "leave" && <Leave requests={leave} onToast={setToast} />}
          {page === "tasks" && <Tasks tasks={tasks} onToast={setToast} />}
          {page === "projects" && <Projects onToast={setToast} />}
          {(["expenses", "requests", "budgets", "assets", "vendors", "helpdesk", "calendar", "customers"] as PageId[]).includes(page) && <OperationalWorkspace page={page} role={user.role} onToast={setToast} />}
          {page === "documents" && <Documents onUpload={() => setShowUpload(true)} onToast={setToast} />}
          {page === "reports" && <Reports onToast={setToast} />}
          {page === "payroll" && (userPermissions.has("payroll.view") || userPermissions.has("payroll.manage") ? <PayrollWorkspace onToast={setToast} role={user.role} readOnly={Boolean(user.isDemo)} /> : <EmployeePayslips />)}
          {page === "settings" && <OrganizationSettings onToast={setToast} currentEmail={user.email} />}
          {page === "security" && <AccountSecurity onToast={setToast} />}
          {page === "platform" && user.isPlatformAdmin && <PlatformAdminWorkspace />}
        </div>
      </main>

      {showAddEmployee && <Modal title="Onboard employee" onClose={() => setShowAddEmployee(false)}><form className="modal-form" onSubmit={createEmployee}><div className="security-note"><ShieldCheck size={17} /><div><strong>HR-controlled onboarding</strong><span>We’ll create the employee profile, assign the selected least-privilege role and email a one-time setup link.</span></div></div><div className="form-grid"><label>First name<input name="firstName" required placeholder="e.g. Ada" /></label><label>Last name<input name="lastName" required placeholder="e.g. Nwosu" /></label></div><label>Work email<input type="email" name="email" required placeholder="ada@company.com" /></label><div className="form-grid"><label>Job title<input name="jobTitle" required placeholder="e.g. Product Manager" /></label><label>Access level<select name="roleName" defaultValue="Employee"><option>Employee</option><option>Manager</option><option>Finance Admin</option><option>HR Admin</option>{user.role === "Organization Admin" && <><option>CEO</option><option>Organization Admin</option></>}</select></label></div><div className="form-grid"><label>Department<input name="departmentName" placeholder="e.g. Operations" /></label><label>Team<input name="teamName" placeholder="e.g. Customer Success" /></label></div><div className="form-grid"><label>Employment type<select name="employmentType" defaultValue="Full-time"><option>Full-time</option><option>Part-time</option><option>Contract</option><option>Temporary</option><option>Intern</option></select></label><label>Work location<select name="workLocation" defaultValue="Hybrid"><option>Office</option><option>Hybrid</option><option>Remote</option></select></label></div><label>Start date<input type="date" name="startDate" required /></label><div className="modal-actions"><button type="button" className="button secondary" onClick={() => setShowAddEmployee(false)}>Cancel</button><button className="button primary" type="submit"><Plus size={16} /> Send onboarding invite</button></div></form></Modal>}
      {showUpload && <Modal title="Upload document" onClose={() => setShowUpload(false)}><form className="modal-form" onSubmit={uploadDocument}><label>Document category<select name="category" defaultValue="Policy"><option>Policy</option><option>Employee document</option><option>Vendor contract</option><option>Finance</option></select></label><label className="file-drop"><UploadCloud size={24} /><span>Choose a file or drop it here</span><small>Private R2 storage · 10MB max</small><input name="file" type="file" required /></label><div className="modal-actions"><button type="button" className="button secondary" onClick={() => setShowUpload(false)}>Cancel</button><button className="button primary" type="submit"><UploadCloud size={16} /> Upload securely</button></div></form></Modal>}
      {toast && <div className="toast"><CheckCircle2 size={18} /><span>{toast}</span><button className="toast-close" onClick={() => setToast(null)}><X size={14} /></button></div>}
    </div>
  );
}

function PageHeader({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: React.ReactNode }) {
  return <div className="page-header"><div><div className="eyebrow">{eyebrow || "ZYNTRIS OPERATIONS"}</div><h1>{title}</h1>{description && <p>{description}</p>}</div>{action && <div className="page-header-action">{action}</div>}</div>;
}

function Dashboard({ data, user, onNavigate, onToast }: { data: DashboardData; user: { fullName: string; organizationName: string }; onNavigate: (page: PageId) => void; onToast: (message: string) => void }) {
  return <>
    <PageHeader eyebrow={`GOOD MORNING, ${user.fullName.split(" ")[0].toUpperCase()}`} title="Your operations, at a glance." description={`Here’s what’s happening across ${user.organizationName} today.`} action={<button className="button primary" onClick={() => onToast("Quick actions are available from each workspace module")}><Plus size={16} /> Quick action</button>} />
    <div className="insight-strip"><div className="insight-mark"><Sparkles size={17} /></div><div><strong>Your organization workspace is ready</strong><span>Invite your people, add employee records and configure the workflows your team needs.</span></div><button onClick={() => onNavigate("employees")}>Add employees <ArrowUpRight size={15} /></button></div>
    <section className="kpi-grid"><KpiCard label="Total employees" value={data.people.total} change={`${data.people.active} active`} note={`${data.people.onLeave} currently on leave`} icon={Users} tone="blue" trend="neutral" /><KpiCard label="Pending leave" value={data.leave.pending} change="Open requests" note="across your organization" icon={ClipboardCheck} tone="violet" trend="neutral" /><KpiCard label="Active projects" value={data.projects.active} change={`${data.tasks.overdue} overdue tasks`} note="need your attention" icon={FolderKanban} tone="orange" trend="neutral" /><KpiCard label="This month’s spend" value={formatNaira(Number(data.expenses.total))} change="Expense claims" note="month to date" icon={WalletCards} tone="green" trend="neutral" /></section>
    <div className="dashboard-grid"><section className="card workforce-card"><CardHeading title="Workforce overview" subtitle="Current organization headcount" action={<button className="small-link" onClick={() => onNavigate("employees")}>View people <ArrowUpRight size={14} /></button>} /><div className="workforce-summary"><strong>{data.people.active}</strong><span>active employees</span><small>{data.people.onLeave} currently on leave · {data.people.total} total records</small></div><div className="chart-legend"><span><i className="legend-dot blue"></i>Active employees</span><span><i className="legend-dot pale"></i>On leave</span></div></section><section className="card department-card"><CardHeading title="By department" subtitle="Current team distribution" /><div className="donut-wrap"><div className="donut"><div className="donut-center"><strong>{data.people.total}</strong><span>people</span></div></div><div className="department-legend">{data.departments.length ? data.departments.slice(0, 5).map((department, index) => <div key={department.name}><span><i className={`legend-dot dept-${index}`}></i>{department.name}</span><strong>{department.count}</strong></div>) : <span className="muted-text">Add departments to see team distribution.</span>}</div></div><button className="full-width-link" onClick={() => onNavigate("employees")}>Explore directory <ArrowUpRight size={14} /></button></section></div>
    <div className="dashboard-grid lower-grid"><section className="card action-card"><CardHeading title="Action centre" subtitle="Live items that may need attention" action={<span className="count-pill">{data.leave.pending + data.tasks.overdue} open</span>} /><div className="action-list"><ActionRow icon={CalendarDays} tone="violet" title="Leave requests" detail={`${data.leave.pending} pending requests`} onClick={() => onNavigate("leave")} /><ActionRow icon={Clock3} tone="orange" title="Overdue tasks" detail={`${data.tasks.overdue} tasks past their due date`} onClick={() => onNavigate("tasks")} /><ActionRow icon={Users} tone="blue" title="Employee records" detail={`${data.people.active} active employees`} onClick={() => onNavigate("employees")} /><ActionRow icon={WalletCards} tone="green" title="Expense claims" detail={`${formatNaira(Number(data.expenses.total))} submitted this month`} onClick={() => onNavigate("expenses")} /></div></section><section className="card activity-card"><CardHeading title="Recent activity" subtitle="Latest workspace updates" action={<button className="small-link" onClick={() => onNavigate("reports")}>View all <ArrowUpRight size={14} /></button>} />{data.recentActivity.length ? <div className="activity-list">{data.recentActivity.map((activity, index) => <div className="activity-row" key={`${activity.module}-${index}`}><div className={`activity-avatar activity-${index}`}><Activity size={15} /></div><div><p><strong>{user.fullName}</strong> {activity.action}</p><span>{activity.module} · {new Date(activity.created_at).toLocaleString()}</span></div></div>)}</div> : <div className="payroll-empty"><Activity size={22} /><strong>No activity yet</strong><span>Important workspace changes will appear here.</span></div>}<div className="activity-footer"><ShieldCheck size={14} /> All activity is protected by your organization audit trail.</div></section></div>
  </>;
}

function KpiCard({ label, value, change, note, icon: Icon, tone, trend }: { label: string; value: string | number; change: string; note: string; icon: IconComponent; tone: string; trend: "up" | "down" | "neutral" }) {
  return <div className="card kpi-card"><div className={`kpi-icon ${tone}`}><Icon size={18} /></div><div className="kpi-label">{label}<MoreHorizontal size={16} /></div><div className="kpi-value">{value}</div><div className="kpi-meta"><span className={`trend ${trend}`}>{trend === "up" && <ArrowUpRight size={13} />}{trend === "down" && <ArrowDownRight size={13} />}{change}</span><span>{note}</span></div></div>;
}

function CardHeading({ title, subtitle, action }: { title: string; subtitle?: string; action?: React.ReactNode }) { return <div className="card-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</div>; }
function ActionRow({ icon: Icon, tone, title, detail, onClick }: { icon: IconComponent; tone: string; title: string; detail: string; onClick: () => void }) { return <button className="action-row" onClick={onClick}><span className={`action-icon ${tone}`}><Icon size={17} /></span><span><strong>{title}</strong><small>{detail}</small></span><ArrowUpRight size={16} className="row-arrow" /></button>; }

function Employees({ employees, onAdd, canManage, onToast, onDeliveryUpdated }: { employees: Employee[]; onAdd: () => void; canManage: boolean; onToast: (message: string) => void; onDeliveryUpdated: (id: string, status: "accepted" | "failed") => void }) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => employees.filter((employee) => `${employee.firstName} ${employee.lastName} ${employee.jobTitle} ${employee.department}`.toLowerCase().includes(query.toLowerCase())), [employees, query]);
  const resendInvite = async (employee: Employee) => {
    try {
      const result = await api<{ invitationEmailAccepted: boolean; invitationEmailError?: string }>(`/api/employees/${employee.id}/invite`, { method: "POST" });
      onDeliveryUpdated(employee.id, result.invitationEmailAccepted ? "accepted" : "failed");
      onToast(result.invitationEmailAccepted ? `Brevo accepted a fresh setup email for ${employee.email}. Ask them to check spam if it doesn’t arrive shortly.` : `Invitation email failed: ${result.invitationEmailError || "unknown email error"}`);
    }
    catch (cause) { onToast(cause instanceof Error ? cause.message : "Could not resend the invitation"); }
  };
  const departments = new Set(employees.map((employee) => employee.department).filter((name) => name && name !== "Unassigned"));
  const teams = new Set(employees.map((employee) => employee.team).filter((name): name is string => Boolean(name)));
  return <><PageHeader eyebrow="PEOPLE / DIRECTORY" title="Employees" description="A single source of truth for your people, teams and organization chart." action={canManage && <button className="button primary" onClick={onAdd}><Plus size={16} /> Onboard employee</button>} /><div className="page-tabs"><button className="active">All employees <span>{employees.length}</span></button><button>Departments <span>{departments.size}</span></button><button>Teams <span>{teams.size}</span></button><button>Org chart</button></div>{teams.size > 0 && <section className="mini-stat-grid">{[...teams].slice(0, 4).map((team) => <MiniStat key={team} label={team} value={String(employees.filter((person) => person.team === team).length)} detail={employees.find((person) => person.team === team)?.department || "Team profile"} tone="blue" />)}</section>}<section className="card table-card"><div className="table-toolbar"><div className="table-search"><Search size={16} /><input placeholder="Search by name, role or department" value={query} onChange={(event) => setQuery(event.target.value)} /></div><div className="toolbar-actions"><button className="filter-button"><Building2 size={15} /> Department <ChevronDown size={14} /></button><button className="filter-button"><MoreHorizontal size={16} /></button></div></div><div className="table-scroll"><table><thead><tr><th>Employee</th><th>Job, access & team</th><th>Onboarding</th><th>Location</th><th>Start date</th><th></th></tr></thead><tbody>{filtered.map((employee) => <tr key={employee.id}><td><div className="employee-cell"><div className="avatar" style={{ background: employee.avatarColor }}>{initials(employee.firstName, employee.lastName)}</div><div><strong>{employee.firstName} {employee.lastName}</strong><span>{employee.employeeNumber} · {employee.email}</span></div></div></td><td><strong className="table-primary">{employee.jobTitle}</strong><span className="table-secondary">{employee.accessRole || "Employee"} · {employee.department}{employee.team ? ` / ${employee.team}` : ""}</span></td><td><span title={employee.invitationEmailError || undefined} className={`status-badge ${employee.onboardingStatus === "invited" ? employee.invitationEmailStatus === "failed" ? "inactive" : "pending" : employee.status}`}>{employee.onboardingStatus === "invited" ? employee.invitationEmailStatus === "failed" ? "Email failed" : employee.invitationEmailStatus === "pending" ? "Sending invite" : "Invite pending" : employee.status === "active" ? "Active" : employee.status === "on_leave" ? "On leave" : "Inactive"}</span></td><td><span className="location-pill"><span></span>{employee.workLocation}</span></td><td>{new Date(employee.startDate).toLocaleDateString("en-NG", { day: "2-digit", month: "short", year: "numeric" })}</td><td>{employee.onboardingStatus === "invited" && canManage ? <button className="text-button" onClick={() => void resendInvite(employee)}>{employee.invitationEmailStatus === "failed" ? "Retry invitation" : "Resend invite"}</button> : <button className="icon-button" onClick={() => onToast(`${employee.firstName}'s profile · ${employee.accessRole || "Employee"} access`)}><MoreHorizontal size={17} /></button>}</td></tr>)}</tbody></table></div><div className="table-footer"><span>Showing <strong>{filtered.length}</strong> of {employees.length} employee records</span><div><button className="pagination-button" disabled><ChevronLeft size={15} /></button><button className="pagination-button active">1</button></div></div></section></>;
}

function Leave({ requests, onToast }: { requests: LeaveRequest[]; onToast: (message: string) => void }) { return <><PageHeader eyebrow="PEOPLE / TIME OFF" title="Leave & attendance" description="Keep your teams moving with clear availability and approval workflows." action={<button className="button primary" onClick={() => onToast("Leave request form is available to employees from their workspace")}><Plus size={16} /> Request leave</button>} /><div className="mini-stat-grid"><MiniStat label="Annual leave used" value="42%" detail="Across the organization" tone="blue" /><MiniStat label="People on leave today" value="8" detail="6.5% of headcount" tone="violet" /><MiniStat label="Pending approvals" value="12" detail="Needs manager review" tone="orange" /><MiniStat label="Attendance rate" value="96.8%" detail="This month" tone="green" /></div><section className="card table-card"><div className="table-toolbar"><div><h2 className="toolbar-title">Recent requests</h2><p className="toolbar-subtitle">Review, approve and keep an audit trail.</p></div><button className="filter-button">All statuses <ChevronDown size={14} /></button></div><div className="table-scroll"><table><thead><tr><th>Employee</th><th>Leave type</th><th>Dates</th><th>Days</th><th>Status</th><th></th></tr></thead><tbody>{requests.map((request) => <tr key={request.id}><td><div className="employee-cell"><div className="avatar avatar-small">{request.employee.split(" ").map((name) => name[0]).join("")}</div><div><strong>{request.employee}</strong><span>{request.reason}</span></div></div></td><td>{request.leaveType}</td><td>{request.startDate} – {request.endDate}</td><td>{request.days}</td><td><span className={`status-badge ${request.status}`}>{titleCase(request.status)}</span></td><td><button className="text-button" onClick={() => onToast(request.status === "pending" ? "Approval drawer opened" : "Request details opened")}>{request.status === "pending" ? "Review" : "View"}</button></td></tr>)}</tbody></table></div></section></> }
function MiniStat({ label, value, detail, tone }: { label: string; value: string; detail: string; tone: string }) { return <div className="card mini-stat"><span className={`mini-stat-line ${tone}`}></span><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>; }

function Tasks({ tasks, onToast }: { tasks: Task[]; onToast: (message: string) => void }) { return <><PageHeader eyebrow="WORK / TASKS" title="Tasks" description="Make progress visible and keep every commitment moving forward." action={<button className="button primary" onClick={() => onToast("New task composer opened")}><Plus size={16} /> New task</button>} /><div className="task-summary"><div><strong>24</strong><span>Open tasks</span></div><div><strong>7</strong><span>Overdue</span></div><div><strong>68%</strong><span>On track</span></div><div className="task-progress"><span>Team completion</span><div><i style={{ width: "68%" }}></i></div></div></div><section className="card kanban-card"><div className="kanban-header"><div><h2>This week</h2><p>Prioritized work across active projects</p></div><div className="view-toggle"><button className="active"><Grid2x2 size={15} /> Board</button><button><ListTodo size={15} /> List</button></div></div><div className="kanban-grid">{(["todo", "in_progress", "review", "completed"] as const).map((status) => <div className="kanban-column" key={status}><div className="column-title"><span><i className={`column-dot ${status}`}></i>{status === "todo" ? "To do" : status === "in_progress" ? "In progress" : status === "review" ? "In review" : "Completed"}</span><b>{tasks.filter((task) => task.status === status).length}</b></div>{tasks.filter((task) => task.status === status).map((task) => <button className="task-card" key={task.id} onClick={() => onToast(`Opened task: ${task.title}`)}><div className="task-card-top"><span className={`priority ${task.priority}`}>{task.priority}</span><MoreHorizontal size={16} /></div><strong>{task.title}</strong><small>{task.project}</small><div className="task-card-bottom"><span className="assignee-mini">{task.assignee.split(" ").map((name) => name[0]).join("")}</span><span><Clock3 size={13} />{task.dueDate}</span></div></button>)}</div>)}</div></section></> }

function Projects({ onToast }: { onToast: (message: string) => void }) { const projects = [{ name: "Zyntris platform launch", owner: "Amaka Okafor", progress: 68, status: "Active", color: "blue" }, { name: "People operations refresh", owner: "Nneka Eze", progress: 42, status: "At risk", color: "orange" }, { name: "Customer success workspace", owner: "Fatima Musa", progress: 12, status: "Planning", color: "violet" }]; return <><PageHeader eyebrow="WORK / PROJECTS" title="Projects" description="Align teams around outcomes, milestones and the work that matters." action={<button className="button primary" onClick={() => onToast("New project composer opened")}><Plus size={16} /> New project</button>} /><div className="project-grid">{projects.map((project) => <button className="card project-card" key={project.name} onClick={() => onToast(`Opened project: ${project.name}`)}><div className="project-top"><span className={`project-icon ${project.color}`}><FolderKanban size={18} /></span><span className={`status-badge ${project.status === "At risk" ? "pending" : project.status === "Active" ? "active" : "neutral"}`}>{project.status}</span></div><h2>{project.name}</h2><p>Owned by {project.owner}</p><div className="progress-line"><i className={project.color} style={{ width: `${project.progress}%` }}></i></div><div className="project-meta"><span>{project.progress}% complete</span><span>12 tasks</span></div><div className="project-footer"><span className="stacked-avatars"><i>AO</i><i>DA</i><i>TB</i><b>+4</b></span><span>View workspace <ArrowUpRight size={14} /></span></div></button>)}</div></> }

function Expenses({ onToast }: { onToast: (message: string) => void }) { const expenses = [{ name: "Daniel Adeyemi", category: "Software", amount: "₦185,000", status: "Submitted", date: "23 Sep 2026" }, { name: "Fatima Musa", category: "Travel", amount: "₦420,000", status: "Approved", date: "18 Sep 2026" }, { name: "Ifeanyi Obi", category: "Operations", amount: "₦96,000", status: "Paid", date: "16 Sep 2026" }]; return <><PageHeader eyebrow="FINANCE / EXPENSES" title="Expenses" description="Bring spend visibility and approvals into one calm, auditable workflow." action={<button className="button primary" onClick={() => onToast("Expense claim composer opened")}><Plus size={16} /> Submit expense</button>} /><div className="mini-stat-grid"><MiniStat label="Total this month" value="₦18.45m" detail="12.6% vs last month" tone="blue" /><MiniStat label="Awaiting approval" value="₦605k" detail="3 claims" tone="orange" /><MiniStat label="Approved this month" value="₦12.2m" detail="71 claims" tone="green" /><MiniStat label="Average claim" value="₦258k" detail="Across all departments" tone="violet" /></div><section className="card table-card"><div className="table-toolbar"><div><h2 className="toolbar-title">Recent expenses</h2><p className="toolbar-subtitle">A complete audit trail for every claim.</p></div><button className="filter-button">This month <ChevronDown size={14} /></button></div><div className="table-scroll"><table><thead><tr><th>Employee</th><th>Category</th><th>Date</th><th>Amount</th><th>Status</th><th></th></tr></thead><tbody>{expenses.map((expense) => <tr key={expense.name}><td><div className="employee-cell"><div className="avatar avatar-small">{expense.name.split(" ").map((name) => name[0]).join("")}</div><strong>{expense.name}</strong></div></td><td>{expense.category}</td><td>{expense.date}</td><td><strong>{expense.amount}</strong></td><td><span className={`status-badge ${expense.status.toLowerCase()}`}>{expense.status}</span></td><td><button className="text-button" onClick={() => onToast("Expense detail opened")}>View</button></td></tr>)}</tbody></table></div></section></> }

function Documents({ onUpload, onToast }: { onUpload: () => void; onToast: (message: string) => void }) { const docs = [{ name: "Employee handbook 2026.pdf", category: "Policies", owner: "People Operations", updated: "Today", size: "2.8 MB" }, { name: "Vendor master agreement.pdf", category: "Contracts", owner: "Finance", updated: "Yesterday", size: "1.4 MB" }, { name: "Remote work policy.docx", category: "Policies", owner: "People Operations", updated: "22 Sep 2026", size: "480 KB" }]; return <><PageHeader eyebrow="OPERATIONS / DOCUMENTS" title="Documents" description="A secure home for the files your business relies on." action={<button className="button primary" onClick={onUpload}><UploadCloud size={16} /> Upload document</button>} /><div className="storage-banner"><div className="storage-icon"><LockKeyhole size={18} /></div><div><strong>Private R2 storage is active</strong><span>Your documents are tenant-isolated, encrypted in transit and never public by default.</span></div><div className="storage-meter"><span>2.4 GB of 10 GB</span><div><i style={{ width: "24%" }}></i></div></div><button onClick={() => onToast("Storage settings opened")}>Manage storage <ArrowUpRight size={14} /></button></div><section className="card table-card"><div className="table-toolbar"><div className="table-search"><Search size={16} /><input placeholder="Search documents" /></div><div className="toolbar-actions"><button className="filter-button"><FileText size={15} /> All folders <ChevronDown size={14} /></button></div></div><div className="document-grid">{docs.map((doc) => <button className="document-card" key={doc.name} onClick={() => onToast(`Opened ${doc.name}`)}><div className="document-card-top"><span className="file-icon"><FileText size={19} /></span><MoreHorizontal size={17} /></div><strong>{doc.name}</strong><span>{doc.category} · {doc.size}</span><div className="document-footer"><span>{doc.owner}</span><span>{doc.updated}</span></div></button>)}</div></section></> }

function Reports({ onToast }: { onToast: (message: string) => void }) { return <><PageHeader eyebrow="INSIGHTS / REPORTING" title="Reports & analytics" description="Turn everyday operations into decisions your teams can act on." action={<button className="button secondary" onClick={() => onToast("Export options opened")}><FileText size={16} /> Export report</button>} /><div className="report-grid">{[{ icon: Users, title: "Headcount & turnover", detail: "HR analytics", color: "blue" }, { icon: Clock3, title: "Attendance & absence", detail: "Time analytics", color: "violet" }, { icon: TrendingUp, title: "Goals & performance", detail: "People analytics", color: "green" }, { icon: WalletCards, title: "Expense overview", detail: "Finance analytics", color: "orange" }].map(({ icon: Icon, title, detail, color }) => <button className="card report-card" key={title} onClick={() => onToast(`${title} report opened`)}><span className={`report-icon ${color}`}><Icon size={19} /></span><div><strong>{title}</strong><span>{detail}</span></div><ArrowUpRight size={16} /></button>)}</div><section className="card report-preview"><CardHeading title="Monthly operating pulse" subtitle="A snapshot of the signals that matter most" action={<button className="filter-button">September 2026 <ChevronDown size={14} /></button>} /><div className="pulse-grid"><div className="pulse-number"><span>Operating score</span><strong>86<span>/100</span></strong><small><TrendingUp size={14} /> 6.2% from August</small></div><div className="pulse-bars">{[58, 72, 66, 84, 76, 92, 88, 96].map((height, index) => <div key={index}><i style={{ height: `${height}%` }}></i><span>{["W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8"][index]}</span></div>)}</div></div></section></> }

function SettingsPage({ onToast, organizationName }: { onToast: (message: string) => void; organizationName: string }) { return <><PageHeader eyebrow="WORKSPACE / ADMINISTRATION" title="Administration" description="Configure the operating system behind your organization." /><div className="settings-layout"><div className="settings-nav card"><button className="active"><Building2 size={16} /> Organization</button><button><Users size={16} /> People & roles</button><button><Clock3 size={16} /> HR policies</button><button><ShieldCheck size={16} /> Security</button><button><Cloud size={16} /> Integrations</button><button><CreditCard size={16} /> Subscription</button></div><section className="card settings-panel"><CardHeading title="Organization profile" subtitle="The basics your people see across Zyntris" action={<button className="button primary" onClick={() => onToast("Organization profile saved")}>Save changes</button>} /><div className="settings-form"><label>Company name<input defaultValue={organizationName} /></label><label>Industry<select defaultValue="Technology"><option>Technology</option><option>Professional services</option><option>Retail</option></select></label><label>Workspace URL<input defaultValue="app.zyntris.org" /></label><label>Time zone<select defaultValue="Africa/Lagos"><option>Africa/Lagos</option><option>Europe/London</option><option>America/New_York</option></select></label><label className="full">Company description<textarea defaultValue="One platform for every operation." /></label></div><div className="security-note"><ShieldCheck size={17} /><div><strong>Tenant isolation is enabled</strong><span>All organization-owned records are scoped through the Worker before any D1 query executes.</span></div></div></section></div></> }

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) { return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><div className="modal"><div className="modal-header"><div><div className="eyebrow">ZYNTRIS WORKSPACE</div><h2>{title}</h2></div><button className="icon-button" onClick={onClose}><X size={18} /></button></div>{children}</div></div>; }
