import { useEffect, useMemo, useState, type FormEvent } from "react";
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, Award, BarChart3, Bell, BriefcaseBusiness, Building2,
  CalendarDays, CheckCircle2, ChevronDown, ChevronLeft, CircleHelp, ClipboardCheck, Clock3, Cloud,
  Command, CreditCard, FileText, FolderKanban, Grid2x2, LayoutDashboard, LifeBuoy, ListTodo, LockKeyhole,
  Menu, MessageSquareText, Megaphone, MoreHorizontal, PanelLeftClose, PanelLeftOpen, Plus, Search, Settings, ShieldCheck, Target,
  Sparkles, TrendingUp, UploadCloud, UserRound, Users, WalletCards, X,
} from "lucide-react";
import { demoDashboard, demoEmployees, demoUser } from "./data/demo";
import { AttendanceWorkspace, OperationalWorkspace } from "./operations";
import { Onboarding } from "./onboarding";
import { EmployeePayslips, PayrollWorkspace } from "./payroll";
import { PlatformAdminWorkspace } from "./platform-admin";
import { AccountSecurity, OrganizationSettings } from "./settings";
import { Appraisals } from "./appraisals";
import { HRTalentWorkspace } from "./hr-talent";
import { AnnouncementsWorkspace, GoalsWorkspace } from "./company-modules";
import { WorkCalendarWorkspace, WorkLeaveWorkspace, WorkProjectsWorkspace, WorkTasksWorkspace } from "./workspaces";
import type { DashboardData, Employee, LeaveRequest, PageId, Task } from "./types";

type IconComponent = typeof LayoutDashboard;
type InboxNotification = { id: string; type: string; title: string; body: string; readAt: string | null; createdAt: string };
type GlobalSearchResult = { id: string; title: string; subtitle: string; module: string };

type NavItem = { id: PageId; label: string; icon: IconComponent; badge?: string; section?: string; soon?: boolean };

const navItems: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "employees", label: "Employees", icon: Users, section: "People" },
  { id: "goals", label: "Goals & OKRs", icon: Target, section: "People" },
  { id: "appraisals", label: "Performance & appraisals", icon: Award, section: "People" },
  { id: "talent", label: "Teams & talent", icon: Users, section: "People" },
  { id: "leave", label: "Leave & attendance", icon: CalendarDays, badge: "12", section: "People" },
  { id: "attendance", label: "Time & shifts", icon: Clock3, section: "People" },
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
  { id: "announcements", label: "Announcements", icon: Megaphone, section: "Communication" },
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
  const adminPortal = window.location.pathname === "/admin" || window.location.pathname === "/platform-admin";
  const [page, setPage] = useState<PageId>(adminPortal ? "platform" : "dashboard");
  const [collapsed, setCollapsed] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const [user, setUser] = useState<{ id: string; fullName: string; email: string; role: string; organizationId: string; organizationName: string; permissions?: string[]; trialEndsAt?: string | null; subscriptionStatus?: string; isPlatformAdmin?: boolean; isDemo?: boolean } | null>(null);
  const [dashboard, setDashboard] = useState<DashboardData>(demoDashboard);
  const [employees, setEmployees] = useState<Employee[]>(demoEmployees);
  const [connected, setConnected] = useState(false);
  const [authLoading, setAuthLoading] = useState(true);
  const [authNotice, setAuthNotice] = useState("");
  const [showAddEmployee, setShowAddEmployee] = useState(false);
  const [showUpload, setShowUpload] = useState(false);
  const [documentsVersion, setDocumentsVersion] = useState(0);
  const [toast, setToast] = useState<string | null>(null);
  const [notifications, setNotifications] = useState<InboxNotification[]>([]);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const [notificationOpen, setNotificationOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<GlobalSearchResult[]>([]);
  const [searchLoading, setSearchLoading] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const token = new URLSearchParams(window.location.search).get("verify");
        if (token) {
          await api("/api/auth/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });
          window.history.replaceState({}, "", window.location.pathname);
          setAuthNotice("Your email is verified. Your organization workspace is ready.");
        }
        if (adminPortal) {
          const me = await api<NonNullable<typeof user>>("/api/me");
          setUser(me); setConnected(true);
        } else {
          const [me, data, people] = await Promise.all([
            api<NonNullable<typeof user>>("/api/me"), api<DashboardData>("/api/dashboard"), api<{ data: Employee[] }>("/api/employees"),
          ]);
          setUser(me); setDashboard(data); setEmployees(people.data); setConnected(true);
        }
      } catch {
        setConnected(false);
      } finally {
        setAuthLoading(false);
      }
    };
    void load();
  }, []);

  useEffect(() => {
    const keyboard = (event: KeyboardEvent) => { if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setSearchOpen(true); } if (event.key === "Escape") setSearchOpen(false); };
    window.addEventListener("keydown", keyboard); return () => window.removeEventListener("keydown", keyboard);
  }, []);
  useEffect(() => {
    if (!searchOpen || searchQuery.trim().length < 2) { setSearchResults([]); setSearchLoading(false); return; }
    let active = true; setSearchLoading(true); const timeout = window.setTimeout(() => { void api<{ data: GlobalSearchResult[] }>(`/api/search?q=${encodeURIComponent(searchQuery.trim())}`).then((result) => { if (active) setSearchResults(result.data); }).catch((cause) => { if (active) setToast(cause instanceof Error ? cause.message : "Search is unavailable."); }).finally(() => { if (active) setSearchLoading(false); }); }, 220);
    return () => { active = false; window.clearTimeout(timeout); };
  }, [searchOpen, searchQuery]);

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
      if (adminPortal) {
        const me = await api<NonNullable<typeof user>>("/api/me");
        setUser(me); setConnected(true); setAuthNotice("");
      } else {
        const [me, data, people] = await Promise.all([
          api<NonNullable<typeof user>>("/api/me"), api<DashboardData>("/api/dashboard"), api<{ data: Employee[] }>("/api/employees"),
        ]);
        setUser(me); setDashboard(data); setEmployees(people.data); setConnected(true); setAuthNotice("");
      }
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
    if (["employees", "leave", "attendance"].includes(item.id)) return userPermissions.has("employees.view");
    if (item.id === "payroll") return userPermissions.has("payroll.view") || userPermissions.has("payroll.manage") || userPermissions.has("payroll.self.view");
    if (item.id === "appraisals") return userPermissions.has("appraisals.view") || userPermissions.has("appraisals.manage") || userPermissions.has("appraisals.self.view");
    if (item.id === "talent") return userPermissions.has("hr.talent.view") || userPermissions.has("hr.talent.manage");
    if (item.id === "goals") return userPermissions.has("goals.view");
    if (item.id === "announcements") return userPermissions.has("announcements.view");
    if (item.id === "expenses") return userPermissions.has("expenses.view") || userPermissions.has("expenses.manage");
    if (item.id === "requests") return userPermissions.has("requests.manage") || userPermissions.has("employees.view");
    if (["dashboard", "reports"].includes(item.id)) return userPermissions.has("employees.view") || userPermissions.has("operations.view");
    return userPermissions.has("operations.view");
  });
  const openPage = (next: PageId) => {
    if (next === "platform") { window.location.assign("/admin"); return; }
    setPage(next); setMobileNav(false);
  };

  const openSearchResult = (result: GlobalSearchResult) => {
    const destinations: Record<string, PageId> = { employees: "employees", projects: "projects", tasks: "tasks", documents: "documents", customers: "customers", vendors: "vendors", helpdesk: "helpdesk", talent: "talent", goals: "goals" };
    const destination = destinations[result.module]; if (destination) openPage(destination); setSearchOpen(false); setSearchQuery("");
  };

  if (authLoading) return <main className="auth-loading"><img src="/zyntris-mark.png" alt="" /><span>Opening your secure workspace…</span></main>;
  if (!user) return <Onboarding onAuthenticated={() => void reloadWorkspace()} initialNotice={authNotice} adminPortal={adminPortal} />;

  if (adminPortal) return <div className="admin-portal-shell">
    <header className="admin-portal-header"><a className="admin-portal-brand" href="/admin"><img src="/zyntris-mark.png" alt="" /><span>Zyntris <small>Platform Admin</small></span></a><div className="admin-portal-account"><span><strong>{user.fullName}</strong><small>{user.email}</small></span><button className="button secondary" onClick={async () => { await api("/api/auth/logout", { method: "POST" }); setUser(null); }}>Sign out</button></div></header>
    <main className="admin-portal-content">{user.isPlatformAdmin ? <PlatformAdminWorkspace /> : <section className="admin-portal-denied"><ShieldCheck size={30} /><h1>Administrator access required</h1><p>This account is not authorized for the Zyntris platform dashboard. Contact the platform administrator if you believe this is an error.</p><button className="button secondary" onClick={async () => { await api("/api/auth/logout", { method: "POST" }); setUser(null); }}>Sign out</button></section>}</main>
  </div>;

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
      setDocumentsVersion((version) => version + 1);
      setToast("Document uploaded to private R2 storage");
      setShowUpload(false);
    } catch (cause) {
      setToast(cause instanceof Error ? cause.message : "Could not upload document");
    }
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
          <div className="topbar-actions"><button className="search-trigger" onClick={() => setSearchOpen(true)}><Search size={17} /><span>Search anything</span><kbd>⌘ K</kbd></button><div className="notification-wrap"><button className="icon-button notification-button" aria-label={`Notifications, ${unreadNotifications} unread`} aria-expanded={notificationOpen} onClick={() => { setNotificationOpen(!notificationOpen); if (!notificationOpen) void refreshNotifications(); }}><Bell size={18} />{unreadNotifications > 0 && <span className="notification-count">{unreadNotifications > 9 ? "9+" : unreadNotifications}</span>}</button>{notificationOpen && <section className="notification-popover"><div className="notification-heading"><div><strong>Notifications</strong><span>{unreadNotifications ? `${unreadNotifications} unread` : "All caught up"}</span></div>{unreadNotifications > 0 && <button onClick={() => void markAllNotificationsRead()}>Mark all read</button>}</div><div className="notification-list">{notifications.length ? notifications.map((item) => <button className={`notification-item ${item.readAt ? "is-read" : ""}`} key={item.id} onClick={() => { if (!item.readAt) void markNotificationRead(item.id); }}><span className="notification-indicator"><Bell size={14} /></span><span className="notification-copy"><strong>{item.title}</strong><span>{item.body}</span><small>{new Date(item.createdAt).toLocaleString()}</small></span></button>) : <div className="notification-empty">No notifications yet. New approvals will appear here.</div>}</div></section>}</div><div className="topbar-divider"></div><button className="profile-chip" onClick={async () => { await api("/api/auth/logout", { method: "POST" }); setUser(null); }}><div className="avatar avatar-sm">{user.fullName.split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase()}</div><span>{user.fullName.split(" ")[0]}</span><ChevronDown size={14} /></button></div>
        </header>

        <div className="page-wrap">
          {user.isDemo && <div className="trial-banner"><span><ShieldCheck size={16} /> Demo sandbox</span><span>Fictional data · read-only · changes are disabled</span></div>}
          {user.subscriptionStatus === "trialing" && user.trialEndsAt && <div className="trial-banner"><span><CheckCircle2 size={16} /> 15-day trial</span><span>Your trial ends {new Date(user.trialEndsAt).toLocaleDateString("en-NG", { dateStyle: "medium" })}. <button onClick={() => openPage("settings")}>Subscription options</button></span></div>}
          {page === "dashboard" && <Dashboard data={dashboard} user={user} onNavigate={openPage} onToast={setToast} />}
          {page === "employees" && <Employees employees={employees} onAdd={() => setShowAddEmployee(true)} canManage={userPermissions.has("employees.manage")} canManageStructure={userPermissions.has("teams.manage") || userPermissions.has("hr.talent.manage")} onToast={setToast} onDeliveryUpdated={(id, status) => setEmployees((current) => current.map((employee) => employee.id === id ? { ...employee, invitationEmailStatus: status } : employee))} />}
          {page === "appraisals" && <Appraisals user={{ id: user.id, permissions: user.permissions }} onToast={setToast} />}
          {page === "talent" && <HRTalentWorkspace user={{ id: user.id, permissions: user.permissions || [] }} employees={employees} onToast={setToast} onEmployeesUpdated={async () => { try { const people = await api<{ data: Employee[] }>("/api/employees"); setEmployees(people.data); } catch { /* handled in the workspace */ } }} />}
          {page === "leave" && <WorkLeaveWorkspace canManage={userPermissions.has("employees.manage") || userPermissions.has("hr.onboarding.approve")} isDemo={Boolean(user.isDemo)} onToast={setToast} />}
          {page === "attendance" && <AttendanceWorkspace isDemo={Boolean(user.isDemo)} onToast={setToast} />}
          {page === "goals" && <GoalsWorkspace isDemo={Boolean(user.isDemo)} onToast={setToast} />}
          {page === "announcements" && <AnnouncementsWorkspace isDemo={Boolean(user.isDemo)} onToast={setToast} />}
          {page === "tasks" && <WorkTasksWorkspace canManage={userPermissions.has("operations.manage")} isDemo={Boolean(user.isDemo)} onToast={setToast} />}
          {page === "projects" && <WorkProjectsWorkspace canManage={userPermissions.has("operations.manage")} isDemo={Boolean(user.isDemo)} onToast={setToast} />}
          {page === "calendar" && <WorkCalendarWorkspace canManage={userPermissions.has("operations.manage")} isDemo={Boolean(user.isDemo)} onToast={setToast} />}
          {(["expenses", "requests", "budgets", "assets", "vendors", "helpdesk", "customers"] as PageId[]).includes(page) && <OperationalWorkspace page={page} role={user.role} onToast={setToast} />}
          {page === "documents" && <Documents version={documentsVersion} onUpload={() => setShowUpload(true)} onToast={setToast} />}
          {page === "reports" && <Reports onToast={setToast} />}
          {page === "payroll" && (userPermissions.has("payroll.view") || userPermissions.has("payroll.manage") ? <PayrollWorkspace onToast={setToast} role={user.role} readOnly={Boolean(user.isDemo)} /> : <EmployeePayslips />)}
          {page === "settings" && <OrganizationSettings onToast={setToast} currentEmail={user.email} />}
          {page === "security" && <AccountSecurity onToast={setToast} />}
          {page === "platform" && user.isPlatformAdmin && <PlatformAdminWorkspace />}
        </div>
      </main>

      {showAddEmployee && <Modal title="Onboard employee" onClose={() => setShowAddEmployee(false)}><form className="modal-form" onSubmit={createEmployee}><div className="security-note"><ShieldCheck size={17} /><div><strong>HR-controlled onboarding</strong><span>We’ll create the employee profile, assign the selected least-privilege role and email a one-time setup link.</span></div></div><div className="form-grid"><label>First name<input name="firstName" required placeholder="e.g. Ada" /></label><label>Last name<input name="lastName" required placeholder="e.g. Nwosu" /></label></div><label>Work email<input type="email" name="email" required placeholder="ada@company.com" /></label><div className="form-grid"><label>Job title<input name="jobTitle" required placeholder="e.g. Product Manager" /></label><label>Access level<select name="roleName" defaultValue="Employee"><option>Employee</option><option>Manager</option><option>Finance Admin</option><option>HR Admin</option>{user.role === "Organization Admin" && <><option>CEO</option><option>Organization Admin</option></>}</select></label></div><div className="form-grid"><label>Department<input name="departmentName" placeholder="e.g. Operations" /></label><label>Team<input name="teamName" placeholder="e.g. Customer Success" /></label></div><div className="form-grid"><label>Employment type<select name="employmentType" defaultValue="Full-time"><option>Full-time</option><option>Part-time</option><option>Contract</option><option>Temporary</option><option>Intern</option></select></label><label>Work location<select name="workLocation" defaultValue="Hybrid"><option>Office</option><option>Hybrid</option><option>Remote</option></select></label></div><label>Start date<input type="date" name="startDate" required /></label><div className="modal-actions"><button type="button" className="button secondary" onClick={() => setShowAddEmployee(false)}>Cancel</button><button className="button primary" type="submit"><Plus size={16} /> Send onboarding invite</button></div></form></Modal>}
      {showUpload && <Modal title="Upload document" onClose={() => setShowUpload(false)}><form className="modal-form" onSubmit={uploadDocument}><label>Document category<select name="category" defaultValue="Policy"><option>Policy</option><option>Employee document</option><option>Vendor contract</option><option>Finance</option></select></label><label className="file-drop"><UploadCloud size={24} /><span>Choose a file or drop it here</span><small>Private R2 storage · 10MB max</small><input name="file" type="file" required /></label><div className="modal-actions"><button type="button" className="button secondary" onClick={() => setShowUpload(false)}>Cancel</button><button className="button primary" type="submit"><UploadCloud size={16} /> Upload securely</button></div></form></Modal>}
      {searchOpen && <div className="modal-backdrop search-overlay" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setSearchOpen(false); }}><section className="modal global-search-modal"><div className="global-search-input"><Search size={18} /><input autoFocus value={searchQuery} onChange={(event) => setSearchQuery(event.target.value)} placeholder="Search authorized workspace records…" /><kbd>ESC</kbd><button className="icon-button" aria-label="Close search" onClick={() => setSearchOpen(false)}><X size={16} /></button></div><div className="global-search-results">{searchQuery.trim().length < 2 ? <div className="work-empty">Search across records you’re authorized to access.</div> : searchLoading ? <div className="work-loading">Searching…</div> : searchResults.length ? searchResults.map((result) => <button key={`${result.module}-${result.id}`} onClick={() => openSearchResult(result)}><span className="search-result-icon"><Search size={14} /></span><span><strong>{result.title}</strong><small>{titleCase(result.module)} · {result.subtitle}</small></span><ArrowUpRight size={14} /></button>) : <div className="work-empty">No matching records found.</div>}</div></section></div>}
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

function Employees({ employees, onAdd, canManage, canManageStructure, onToast, onDeliveryUpdated }: { employees: Employee[]; onAdd: () => void; canManage: boolean; canManageStructure: boolean; onToast: (message: string) => void; onDeliveryUpdated: (id: string, status: "accepted" | "failed") => void }) {
  type Structure = { departments: { id: string; name: string; employeeCount: number; teamCount: number }[]; teams: { id: string; name: string; departmentId: string | null; department: string | null; employeeCount: number }[] };
  type Tab = "employees" | "departments" | "teams" | "org-chart";
  const [tab, setTab] = useState<Tab>("employees");
  const [query, setQuery] = useState("");
  const [structure, setStructure] = useState<Structure>({ departments: [], teams: [] });
  const [structureError, setStructureError] = useState("");
  const [structureLoading, setStructureLoading] = useState(true);
  const [createKind, setCreateKind] = useState<"department" | "team" | null>(null);
  const [savingStructure, setSavingStructure] = useState(false);
  const loadStructure = async () => {
    setStructureLoading(true);
    try {
      const result = await api<Structure>("/api/hr/org-structure");
      setStructure(result);
      setStructureError("");
    } catch (cause) {
      setStructureError(cause instanceof Error ? cause.message : "Could not load organization structure.");
    }
    finally { setStructureLoading(false); }
  };
  useEffect(() => { void loadStructure(); }, []);
  const filtered = useMemo(() => employees.filter((employee) => `${employee.firstName} ${employee.lastName} ${employee.jobTitle} ${employee.department} ${employee.team || ""}`.toLowerCase().includes(query.toLowerCase())), [employees, query]);
  const resendInvite = async (employee: Employee) => {
    try {
      const result = await api<{ invitationEmailAccepted: boolean; invitationEmailError?: string }>(`/api/employees/${employee.id}/invite`, { method: "POST" });
      onDeliveryUpdated(employee.id, result.invitationEmailAccepted ? "accepted" : "failed");
      onToast(result.invitationEmailAccepted ? `Brevo accepted a fresh setup email for ${employee.email}. Ask them to check spam if it doesn’t arrive shortly.` : `Invitation email failed: ${result.invitationEmailError || "unknown email error"}`);
    }
    catch (cause) { onToast(cause instanceof Error ? cause.message : "Could not resend the invitation"); }
  };
  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: "employees", label: "All employees", count: employees.length },
    { id: "departments", label: "Departments", count: structure.departments.length },
    { id: "teams", label: "Teams", count: structure.teams.length },
    { id: "org-chart", label: "Org chart" },
  ];
  const personCard = (employee: Employee) => <div className="org-person" key={employee.id}><div className="avatar" style={{ background: employee.avatarColor }}>{initials(employee.firstName, employee.lastName)}</div><div><strong>{employee.firstName} {employee.lastName}</strong><span>{employee.jobTitle}</span><small>{employee.email}</small></div></div>;
  const handleCreateStructure = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!createKind) return;
    const form = new FormData(event.currentTarget);
    setSavingStructure(true);
    try {
      await api("/api/hr/teams", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ kind: createKind, name: String(form.get("name") || "").trim(), departmentId: form.get("departmentId") || null }) });
      setCreateKind(null);
      onToast(`${createKind === "department" ? "Department" : "Team"} created.`);
      await loadStructure();
    } catch (cause) { onToast(cause instanceof Error ? cause.message : "Could not create this structure."); }
    finally { setSavingStructure(false); }
  };
  const renderEmployeeTable = () => <section className="card table-card"><div className="table-toolbar"><div className="table-search"><Search size={16} /><input placeholder="Search by name, role or department" value={query} onChange={(event) => setQuery(event.target.value)} /></div><div className="toolbar-actions"><span className="filter-button"><Building2 size={15} /> {filtered.length} people</span></div></div><div className="table-scroll"><table><thead><tr><th>Employee</th><th>Job, access & team</th><th>Onboarding</th><th>Location</th><th>Start date</th><th></th></tr></thead><tbody>{filtered.map((employee) => <tr key={employee.id}><td><div className="employee-cell"><div className="avatar" style={{ background: employee.avatarColor }}>{initials(employee.firstName, employee.lastName)}</div><div><strong>{employee.firstName} {employee.lastName}</strong><span>{employee.employeeNumber} · {employee.email}</span></div></div></td><td><strong className="table-primary">{employee.jobTitle}</strong><span className="table-secondary">{employee.accessRole || "Employee"} · {employee.department}{employee.team ? ` / ${employee.team}` : ""}</span></td><td><span title={employee.invitationEmailError || undefined} className={`status-badge ${employee.onboardingStatus === "invited" ? employee.invitationEmailStatus === "failed" ? "inactive" : "pending" : employee.status}`}>{employee.onboardingStatus === "invited" ? employee.invitationEmailStatus === "failed" ? "Email failed" : employee.invitationEmailStatus === "pending" ? "Sending invite" : "Invite pending" : employee.status === "active" ? "Active" : employee.status === "on_leave" ? "On leave" : "Inactive"}</span></td><td><span className="location-pill"><span></span>{employee.workLocation}</span></td><td>{new Date(employee.startDate).toLocaleDateString("en-NG", { day: "2-digit", month: "short", year: "numeric" })}</td><td>{employee.onboardingStatus === "invited" && canManage ? <button className="text-button" onClick={() => void resendInvite(employee)}>{employee.invitationEmailStatus === "failed" ? "Retry invitation" : "Resend invite"}</button> : <button className="icon-button" onClick={() => onToast(`${employee.firstName}'s profile · ${employee.accessRole || "Employee"} access`)}><MoreHorizontal size={17} /></button>}</td></tr>)}</tbody></table></div><div className="table-footer"><span>Showing <strong>{filtered.length}</strong> of {employees.length} employee records</span><div><button className="pagination-button" disabled><ChevronLeft size={15} /></button><button className="pagination-button active">1</button></div></div></section>;
  const directReports = employees.filter((person) => person.managerId);
  const managers = employees.filter((person) => directReports.some((report) => report.managerId === person.id));
  const renderReports = (manager: Employee, visited = new Set<string>()): React.ReactNode => {
    if (visited.has(manager.id)) return null;
    const nextVisited = new Set(visited).add(manager.id);
    return <div className="org-chart-node" key={manager.id}>{personCard(manager)}{employees.some((person) => person.managerId === manager.id) && <div className="org-chart-children">{employees.filter((person) => person.managerId === manager.id).map((person) => renderReports(person, nextVisited))}</div>}</div>;
  };
  return <><PageHeader eyebrow="PEOPLE / DIRECTORY" title="Employees" description="A single source of truth for your people, teams and organization chart." action={<div className="header-actions">{canManageStructure && tab !== "employees" && tab !== "org-chart" && <button className="button secondary" onClick={() => setCreateKind(tab === "departments" ? "department" : "team")}><Plus size={16} /> Add {tab === "departments" ? "department" : "team"}</button>}{canManage && tab === "employees" && <button className="button primary" onClick={onAdd}><Plus size={16} /> Onboard employee</button>}</div>} /><div className="page-tabs" role="tablist" aria-label="People directory views">{tabs.map((item) => <button key={item.id} role="tab" aria-selected={tab === item.id} className={tab === item.id ? "active" : ""} onClick={() => { setTab(item.id); setQuery(""); }} type="button">{item.label}{item.count !== undefined && <span>{item.count}</span>}</button>)}</div>
    {structureError && <div className="structure-notice" role="status">Couldn’t load saved teams and departments: {structureError}. The directory views below use available employee records.</div>}
    {tab === "employees" && renderEmployeeTable()}
    {tab !== "employees" && tab !== "org-chart" && <div className="table-toolbar org-search"><div className="table-search"><Search size={16} /><input placeholder={`Search ${tab}`} value={query} onChange={(event) => setQuery(event.target.value)} /></div><span className="muted-text">Organization structure</span></div>}
    {tab === "departments" && <div className="org-structure-grid">{structureLoading ? <div className="card org-empty"><Building2 size={24} /><strong>Loading departments…</strong></div> : structure.departments.length ? structure.departments.filter((department) => department.name.toLowerCase().includes(query.toLowerCase())).map((department) => { const people = employees.filter((employee) => employee.department.toLowerCase() === department.name.toLowerCase() && `${employee.firstName} ${employee.lastName} ${employee.jobTitle}`.toLowerCase().includes(query.toLowerCase())); return <section className="card org-unit-card" key={department.id}><div className="org-unit-heading"><span className="org-unit-icon"><Building2 size={19} /></span><div><h2>{department.name}</h2><p>{department.teamCount} {department.teamCount === 1 ? "team" : "teams"} · {department.employeeCount} {department.employeeCount === 1 ? "employee" : "employees"}</p></div></div><div className="org-unit-people">{people.slice(0, 5).map(personCard)}{!people.length && <span className="muted-text">No employee records in this department yet.</span>}{people.length > 5 && <span className="org-more">and {people.length - 5} more</span>}</div></section>; }) : <div className="card org-empty"><Building2 size={24} /><strong>No departments yet</strong><span>Create a department or add one while onboarding an employee.</span>{canManageStructure && <button className="button primary" onClick={() => setCreateKind("department")}><Plus size={15} /> Add department</button>}</div>}</div>}
    {tab === "teams" && <div className="org-structure-grid">{structureLoading ? <div className="card org-empty"><Users size={24} /><strong>Loading teams…</strong></div> : structure.teams.length ? structure.teams.filter((team) => `${team.name} ${team.department || ""}`.toLowerCase().includes(query.toLowerCase())).map((team) => { const people = employees.filter((employee) => employee.team?.toLowerCase() === team.name.toLowerCase()); return <section className="card org-unit-card" key={team.id}><div className="org-unit-heading"><span className="org-unit-icon team"><Users size={19} /></span><div><h2>{team.name}</h2><p>{team.department || "No department assigned"} · {team.employeeCount} {team.employeeCount === 1 ? "member" : "members"}</p></div></div><div className="org-unit-people">{people.slice(0, 5).map(personCard)}{!people.length && <span className="muted-text">No employee records in this team yet.</span>}{people.length > 5 && <span className="org-more">and {people.length - 5} more</span>}</div></section>; }) : <div className="card org-empty"><Users size={24} /><strong>No teams yet</strong><span>Create a team and assign employees from their profile or onboarding form.</span>{canManageStructure && <button className="button primary" onClick={() => setCreateKind("team")}><Plus size={15} /> Add team</button>}</div>}</div>}
    {tab === "org-chart" && <section className="card org-chart-card"><div className="org-chart-heading"><div><h2>Reporting lines</h2><p>People are grouped by their assigned line manager.</p></div><span className="count-pill">{employees.length} people</span></div>{managers.length ? <div className="org-chart-roots">{managers.filter((person) => !person.managerId || !employees.some((candidate) => candidate.id === person.managerId)).map((manager) => renderReports(manager))}</div> : <div className="org-empty inline"><Users size={23} /><strong>No reporting lines configured</strong><span>Assign line managers to employee profiles to build the organization chart.</span></div>}{employees.some((person) => !person.managerId && !managers.some((manager) => manager.id === person.id)) && <div className="org-unassigned"><strong>Without a line manager</strong><div className="org-people-row">{employees.filter((person) => !person.managerId && !managers.some((manager) => manager.id === person.id)).map(personCard)}</div></div>}</section>}
    {createKind && <Modal title={`Add ${createKind}`} onClose={() => setCreateKind(null)}><form className="modal-form" onSubmit={handleCreateStructure}><label>{createKind === "department" ? "Department name" : "Team name"}<input autoFocus name="name" required maxLength={100} placeholder={createKind === "department" ? "e.g. People & Culture" : "e.g. Customer Success"} /></label>{createKind === "team" && <label>Department<select name="departmentId" defaultValue=""><option value="">No department</option>{structure.departments.map((department) => <option value={department.id} key={department.id}>{department.name}</option>)}</select></label>}<div className="modal-actions"><button type="button" className="button secondary" onClick={() => setCreateKind(null)}>Cancel</button><button className="button primary" disabled={savingStructure} type="submit"><Plus size={16} /> {savingStructure ? "Saving…" : `Create ${createKind}`}</button></div></form></Modal>}</>;
}

function Leave({ requests, onToast }: { requests: LeaveRequest[]; onToast: (message: string) => void }) { return <><PageHeader eyebrow="PEOPLE / TIME OFF" title="Leave & attendance" description="Keep your teams moving with clear availability and approval workflows." action={<button className="button primary" onClick={() => onToast("Leave request form is available to employees from their workspace")}><Plus size={16} /> Request leave</button>} /><div className="mini-stat-grid"><MiniStat label="Annual leave used" value="42%" detail="Across the organization" tone="blue" /><MiniStat label="People on leave today" value="8" detail="6.5% of headcount" tone="violet" /><MiniStat label="Pending approvals" value="12" detail="Needs manager review" tone="orange" /><MiniStat label="Attendance rate" value="96.8%" detail="This month" tone="green" /></div><section className="card table-card"><div className="table-toolbar"><div><h2 className="toolbar-title">Recent requests</h2><p className="toolbar-subtitle">Review, approve and keep an audit trail.</p></div><button className="filter-button">All statuses <ChevronDown size={14} /></button></div><div className="table-scroll"><table><thead><tr><th>Employee</th><th>Leave type</th><th>Dates</th><th>Days</th><th>Status</th><th></th></tr></thead><tbody>{requests.map((request) => <tr key={request.id}><td><div className="employee-cell"><div className="avatar avatar-small">{request.employee.split(" ").map((name) => name[0]).join("")}</div><div><strong>{request.employee}</strong><span>{request.reason}</span></div></div></td><td>{request.leaveType}</td><td>{request.startDate} – {request.endDate}</td><td>{request.days}</td><td><span className={`status-badge ${request.status}`}>{titleCase(request.status)}</span></td><td><button className="text-button" onClick={() => onToast(request.status === "pending" ? "Approval drawer opened" : "Request details opened")}>{request.status === "pending" ? "Review" : "View"}</button></td></tr>)}</tbody></table></div></section></> }
function MiniStat({ label, value, detail, tone }: { label: string; value: string; detail: string; tone: string }) { return <div className="card mini-stat"><span className={`mini-stat-line ${tone}`}></span><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>; }

function Tasks({ tasks, onToast }: { tasks: Task[]; onToast: (message: string) => void }) { return <><PageHeader eyebrow="WORK / TASKS" title="Tasks" description="Make progress visible and keep every commitment moving forward." action={<button className="button primary" onClick={() => onToast("New task composer opened")}><Plus size={16} /> New task</button>} /><div className="task-summary"><div><strong>24</strong><span>Open tasks</span></div><div><strong>7</strong><span>Overdue</span></div><div><strong>68%</strong><span>On track</span></div><div className="task-progress"><span>Team completion</span><div><i style={{ width: "68%" }}></i></div></div></div><section className="card kanban-card"><div className="kanban-header"><div><h2>This week</h2><p>Prioritized work across active projects</p></div><div className="view-toggle"><button className="active"><Grid2x2 size={15} /> Board</button><button><ListTodo size={15} /> List</button></div></div><div className="kanban-grid">{(["todo", "in_progress", "review", "completed"] as const).map((status) => <div className="kanban-column" key={status}><div className="column-title"><span><i className={`column-dot ${status}`}></i>{status === "todo" ? "To do" : status === "in_progress" ? "In progress" : status === "review" ? "In review" : "Completed"}</span><b>{tasks.filter((task) => task.status === status).length}</b></div>{tasks.filter((task) => task.status === status).map((task) => <button className="task-card" key={task.id} onClick={() => onToast(`Opened task: ${task.title}`)}><div className="task-card-top"><span className={`priority ${task.priority}`}>{task.priority}</span><MoreHorizontal size={16} /></div><strong>{task.title}</strong><small>{task.project}</small><div className="task-card-bottom"><span className="assignee-mini">{task.assignee.split(" ").map((name) => name[0]).join("")}</span><span><Clock3 size={13} />{task.dueDate}</span></div></button>)}</div>)}</div></section></> }

function Projects({ onToast }: { onToast: (message: string) => void }) { const projects = [{ name: "Zyntris platform launch", owner: "Amaka Okafor", progress: 68, status: "Active", color: "blue" }, { name: "People operations refresh", owner: "Nneka Eze", progress: 42, status: "At risk", color: "orange" }, { name: "Customer success workspace", owner: "Fatima Musa", progress: 12, status: "Planning", color: "violet" }]; return <><PageHeader eyebrow="WORK / PROJECTS" title="Projects" description="Align teams around outcomes, milestones and the work that matters." action={<button className="button primary" onClick={() => onToast("New project composer opened")}><Plus size={16} /> New project</button>} /><div className="project-grid">{projects.map((project) => <button className="card project-card" key={project.name} onClick={() => onToast(`Opened project: ${project.name}`)}><div className="project-top"><span className={`project-icon ${project.color}`}><FolderKanban size={18} /></span><span className={`status-badge ${project.status === "At risk" ? "pending" : project.status === "Active" ? "active" : "neutral"}`}>{project.status}</span></div><h2>{project.name}</h2><p>Owned by {project.owner}</p><div className="progress-line"><i className={project.color} style={{ width: `${project.progress}%` }}></i></div><div className="project-meta"><span>{project.progress}% complete</span><span>12 tasks</span></div><div className="project-footer"><span className="stacked-avatars"><i>AO</i><i>DA</i><i>TB</i><b>+4</b></span><span>View workspace <ArrowUpRight size={14} /></span></div></button>)}</div></> }

function Expenses({ onToast }: { onToast: (message: string) => void }) { const expenses = [{ name: "Daniel Adeyemi", category: "Software", amount: "₦185,000", status: "Submitted", date: "23 Sep 2026" }, { name: "Fatima Musa", category: "Travel", amount: "₦420,000", status: "Approved", date: "18 Sep 2026" }, { name: "Ifeanyi Obi", category: "Operations", amount: "₦96,000", status: "Paid", date: "16 Sep 2026" }]; return <><PageHeader eyebrow="FINANCE / EXPENSES" title="Expenses" description="Bring spend visibility and approvals into one calm, auditable workflow." action={<button className="button primary" onClick={() => onToast("Expense claim composer opened")}><Plus size={16} /> Submit expense</button>} /><div className="mini-stat-grid"><MiniStat label="Total this month" value="₦18.45m" detail="12.6% vs last month" tone="blue" /><MiniStat label="Awaiting approval" value="₦605k" detail="3 claims" tone="orange" /><MiniStat label="Approved this month" value="₦12.2m" detail="71 claims" tone="green" /><MiniStat label="Average claim" value="₦258k" detail="Across all departments" tone="violet" /></div><section className="card table-card"><div className="table-toolbar"><div><h2 className="toolbar-title">Recent expenses</h2><p className="toolbar-subtitle">A complete audit trail for every claim.</p></div><button className="filter-button">This month <ChevronDown size={14} /></button></div><div className="table-scroll"><table><thead><tr><th>Employee</th><th>Category</th><th>Date</th><th>Amount</th><th>Status</th><th></th></tr></thead><tbody>{expenses.map((expense) => <tr key={expense.name}><td><div className="employee-cell"><div className="avatar avatar-small">{expense.name.split(" ").map((name) => name[0]).join("")}</div><strong>{expense.name}</strong></div></td><td>{expense.category}</td><td>{expense.date}</td><td><strong>{expense.amount}</strong></td><td><span className={`status-badge ${expense.status.toLowerCase()}`}>{expense.status}</span></td><td><button className="text-button" onClick={() => onToast("Expense detail opened")}>View</button></td></tr>)}</tbody></table></div></section></> }

type StoredDocument = { id: string; name: string; category: string; contentType: string; sizeBytes: number; createdAt: string };
function Documents({ onUpload, onToast, version }: { onUpload: () => void; onToast: (message: string) => void; version: number }) {
  const [docs, setDocs] = useState<StoredDocument[]>([]); const [query, setQuery] = useState(""); const [error, setError] = useState(""); const [loading, setLoading] = useState(true);
  useEffect(() => { let active = true; setLoading(true); fetch("/api/files", { credentials: "include" }).then(async (response) => { if (!response.ok) throw new Error((await response.json().catch(() => null))?.error || "Could not load documents"); return response.json() as Promise<{ data: StoredDocument[] }>; }).then((result) => { if (active) { setDocs(result.data); setError(""); } }).catch((cause) => { if (active) setError(cause instanceof Error ? cause.message : "Could not load documents"); }).finally(() => { if (active) setLoading(false); }); return () => { active = false; }; }, [version]);
  const download = async (doc: StoredDocument) => { try { const response = await fetch(`/api/files/${encodeURIComponent(doc.id)}`, { credentials: "include" }); if (!response.ok) throw new Error((await response.json().catch(() => null))?.error || "Could not download document"); const url = URL.createObjectURL(await response.blob()); const anchor = document.createElement("a"); anchor.href = url; anchor.download = doc.name; anchor.click(); URL.revokeObjectURL(url); } catch (cause) { onToast(cause instanceof Error ? cause.message : "Could not download document"); } };
  const filtered = docs.filter((doc) => `${doc.name} ${doc.category}`.toLowerCase().includes(query.toLowerCase())); const totalBytes = docs.reduce((sum, doc) => sum + doc.sizeBytes, 0); const sizeLabel = totalBytes >= 1024 * 1024 ? `${(totalBytes / 1024 / 1024).toFixed(1)} MB` : `${Math.ceil(totalBytes / 1024)} KB`;
  return <><PageHeader eyebrow="OPERATIONS / DOCUMENTS" title="Documents" description="A secure home for the files your business relies on." action={<button className="button primary" onClick={onUpload}><UploadCloud size={16} /> Upload document</button>} /><div className="storage-banner"><div className="storage-icon"><LockKeyhole size={18} /></div><div><strong>Private R2 storage</strong><span>Files are private to this organization and only served after access checks.</span></div><div className="storage-meter"><span>{sizeLabel} · {docs.length} files</span><div><i style={{ width: `${Math.min(100, totalBytes / (10 * 1024 * 1024 * 1024) * 100)}%` }} /></div></div></div>{error && <div className="work-error" role="alert">{error}</div>}<section className="card table-card"><div className="table-toolbar"><div className="table-search"><Search size={16} /><input placeholder="Search documents" value={query} onChange={(event) => setQuery(event.target.value)} /></div></div>{loading ? <div className="work-loading">Loading documents…</div> : filtered.length ? <div className="document-grid">{filtered.map((doc) => <button className="document-card" key={doc.id} onClick={() => void download(doc)}><div className="document-card-top"><span className="file-icon"><FileText size={19} /></span><MoreHorizontal size={17} /></div><strong>{doc.name}</strong><span>{doc.category} · {doc.sizeBytes < 1024 * 1024 ? `${Math.ceil(doc.sizeBytes / 1024)} KB` : `${(doc.sizeBytes / 1024 / 1024).toFixed(1)} MB`}</span><div className="document-footer"><span>{new Date(doc.createdAt).toLocaleDateString()}</span><span>Download</span></div></button>)}</div> : <div className="work-empty">{query ? "No documents match your search." : "No documents uploaded yet. Upload policies, contracts, and employee files to keep them organized."}</div>}</section></>;
}

type ReportSummary = { people: { total?: number; active?: number }; expenses: { count?: number; total?: number; pending?: number }; leave: { pending?: number; approved?: number; rejected?: number }; tasks: { total?: number; completed?: number; overdue?: number }; tickets: { open?: number; resolved?: number }; approvals: { pending?: number; approved?: number; rejected?: number }; appraisals: { total?: number; completed?: number; inProgress?: number }; departments: { name: string; count: number }[]; monthlySpend: { month: string; amount: number }[] };
function Reports({ onToast }: { onToast: (message: string) => void }) {
  const [data, setData] = useState<ReportSummary | null>(null); const [error, setError] = useState(""); const [loading, setLoading] = useState(true);
  useEffect(() => { let active = true; fetch("/api/reports/summary", { credentials: "include" }).then(async (response) => { if (!response.ok) throw new Error((await response.json().catch(() => null))?.error || "Could not load reports"); return response.json() as Promise<ReportSummary>; }).then((result) => { if (active) { setData(result); setError(""); } }).catch((cause) => { if (active) setError(cause instanceof Error ? cause.message : "Could not load reports"); }).finally(() => { if (active) setLoading(false); }); return () => { active = false; }; }, []);
  const exportCsv = () => { if (!data) return; const rows = [["Metric","Value"],["Employees",data.people.total || 0],["Active employees",data.people.active || 0],["Expense total (6 months)",data.expenses.total || 0],["Claims",data.expenses.count || 0],["Pending expenses (6 months)",data.expenses.pending || 0],["Pending leave",data.leave.pending || 0],["Tasks",data.tasks.total || 0],["Completed tasks",data.tasks.completed || 0],["Overdue tasks",data.tasks.overdue || 0],["Open support tickets",data.tickets.open || 0],["Pending approvals",data.approvals.pending || 0],["Appraisals",data.appraisals.total || 0],["Appraisals completed",data.appraisals.completed || 0],...[...data.monthlySpend].map((item) => [`Spend ${item.month}`,item.amount])]; const csv = rows.map((row) => row.map((cell) => `"${String(cell).replace(/"/g,"\"\"")}"`).join(",")).join("\r\n"); const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" })); const link = document.createElement("a"); link.href = url; link.download = "zyntris-operations-report.csv"; link.click(); URL.revokeObjectURL(url); onToast("Live report exported as CSV."); };
  const months = Array.from({ length: 6 }, (_, index) => { const date = new Date(); date.setUTCDate(1); date.setUTCMonth(date.getUTCMonth() - (5 - index)); const key = date.toISOString().slice(0, 7); return { key, label: date.toLocaleDateString("en-NG", { month: "short" }), amount: data?.monthlySpend.find((item) => item.month === key)?.amount || 0 }; }); const maxSpend = Math.max(1, ...months.map((item) => item.amount));
  return <><PageHeader eyebrow="INSIGHTS / REPORTING" title="Reports & analytics" description="Live organization metrics from HR, finance, approvals, work and support records." action={<button className="button secondary" disabled={!data} onClick={exportCsv}><FileText size={16} /> Export CSV</button>} />{error && <div className="work-error" role="alert">{error}</div>}{loading ? <div className="work-loading">Loading live reports…</div> : data && <><div className="report-grid">{[{ icon: Users, title: "Headcount", value: data.people.total || 0, detail: `${data.people.active || 0} active employees`, color: "blue" }, { icon: Clock3, title: "Leave", value: data.leave.pending || 0, detail: `${data.leave.approved || 0} approved`, color: "violet" }, { icon: TrendingUp, title: "Tasks", value: data.tasks.total || 0, detail: `${data.tasks.overdue || 0} overdue · ${data.tasks.completed || 0} completed`, color: "green" }, { icon: WalletCards, title: "Expenses", value: `₦${new Intl.NumberFormat("en-NG", { notation: "compact" }).format(data.expenses.total || 0)}`, detail: `${data.expenses.count || 0} claims · 6 months`, color: "orange" }].map(({ icon: Icon, title, value, detail, color }) => <div className="card report-card" key={title}><span className={`report-icon ${color}`}><Icon size={19} /></span><div><strong>{title}: {value}</strong><span>{detail}</span></div></div>)}</div><section className="card report-preview"><CardHeading title="Expense trend" subtitle="Recorded expense claims for the last six calendar months" /><div className="pulse-grid"><div className="pulse-number"><span>Total recorded</span><strong>₦{new Intl.NumberFormat("en-NG", { notation: "compact", maximumFractionDigits: 1 }).format(data.expenses.total || 0)}</strong><small>{data.expenses.pending || 0} pending NGN claims by amount</small></div><div className="pulse-bars">{months.map((month) => <div key={month.key} title={`${month.key}: ₦${month.amount.toLocaleString()}`}><i style={{ height: `${Math.max(2, month.amount / maxSpend * 96)}%` }} /><span>{month.label}</span></div>)}</div></div></section><section className="card report-preview"><CardHeading title="Department headcount" subtitle="Active and historical employee records by department" />{data.departments.length ? <div className="report-departments">{data.departments.map((item) => <div key={item.name}><span>{item.name}</span><strong>{item.count}</strong></div>)}</div> : <div className="work-empty">No department records yet.</div>}<p className="report-note">Also tracked: {data.approvals.pending || 0} pending approvals, {data.tickets.open || 0} open support tickets, {data.leave.rejected || 0} rejected leave requests, and {data.appraisals.inProgress || 0} in-progress appraisals ({data.appraisals.completed || 0} completed).</p></section></>}</>;
}

function SettingsPage({ onToast, organizationName }: { onToast: (message: string) => void; organizationName: string }) { return <><PageHeader eyebrow="WORKSPACE / ADMINISTRATION" title="Administration" description="Configure the operating system behind your organization." /><div className="settings-layout"><div className="settings-nav card"><button className="active"><Building2 size={16} /> Organization</button><button><Users size={16} /> People & roles</button><button><Clock3 size={16} /> HR policies</button><button><ShieldCheck size={16} /> Security</button><button><Cloud size={16} /> Integrations</button><button><CreditCard size={16} /> Subscription</button></div><section className="card settings-panel"><CardHeading title="Organization profile" subtitle="The basics your people see across Zyntris" action={<button className="button primary" onClick={() => onToast("Organization profile saved")}>Save changes</button>} /><div className="settings-form"><label>Company name<input defaultValue={organizationName} /></label><label>Industry<select defaultValue="Technology"><option>Technology</option><option>Professional services</option><option>Retail</option></select></label><label>Workspace URL<input defaultValue="app.zyntris.org" /></label><label>Time zone<select defaultValue="Africa/Lagos"><option>Africa/Lagos</option><option>Europe/London</option><option>America/New_York</option></select></label><label className="full">Company description<textarea defaultValue="One platform for every operation." /></label></div><div className="security-note"><ShieldCheck size={17} /><div><strong>Tenant isolation is enabled</strong><span>All organization-owned records are scoped through the Worker before any D1 query executes.</span></div></div></section></div></> }

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) { return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><div className="modal"><div className="modal-header"><div><div className="eyebrow">ZYNTRIS WORKSPACE</div><h2>{title}</h2></div><button className="icon-button" onClick={onClose}><X size={18} /></button></div>{children}</div></div>; }
