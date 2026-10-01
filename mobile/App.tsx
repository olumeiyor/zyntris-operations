import { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Alert, Image, KeyboardAvoidingView, Platform, Pressable, RefreshControl, SafeAreaView, ScrollView, StatusBar, StyleSheet, Text, TextInput, View } from "react-native";
import * as SecureStore from "expo-secure-store";
import { StatusBar as ExpoStatusBar } from "expo-status-bar";
import zyntrisMark from "./assets/zyntris-mark.png";

const API_URL = "https://app.zyntris.org";
const TOKEN_KEY = "zyntris_mobile_access_token";
type Tab = "home" | "approvals" | "payroll" | "new" | "inbox";
type User = { id: string; fullName: string; email: string; role: string; organizationName: string; permissions: string[] };
type Approval = { id: string; requestType: string; title: string; details?: string | null; requester: string; amount: number | null; status: string; requiredRole: string; createdAt: string };
type PayrollRun = { id: string; periodStart: string; periodEnd: string; paymentDate: string; currency: string; status: string; employeeCount: number; netTotal: number };
type Notice = { id: string; title: string; body: string; type: string; readAt: string | null; createdAt: string };
type Dashboard = { people: { total: number; active: number; onLeave: number }; leave: { pending: number }; projects: { active: number }; tasks: { overdue: number }; expenses: { total: number } };

async function request<T>(path: string, token?: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}/api/mobile${path}`, {
    ...init,
    headers: { ...(init?.body ? { "content-type": "application/json" } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}), ...init?.headers },
  });
  const data = await response.json().catch(() => ({})) as T & { error?: string };
  if (!response.ok) throw new Error(data.error || "Could not connect to your workspace.");
  return data;
}

export default function App() {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [payrollRuns, setPayrollRuns] = useState<PayrollRun[]>([]);
  const [notices, setNotices] = useState<Notice[]>([]);
  const [tab, setTab] = useState<Tab>("home");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [requestTitle, setRequestTitle] = useState("");
  const [requestDetails, setRequestDetails] = useState("");
  const [requestAmount, setRequestAmount] = useState("");
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [restoringSession, setRestoringSession] = useState(true);

  const loadWorkspace = useCallback(async (accessToken: string) => {
    const me = await request<User>("/me", accessToken);
    const canViewPayroll = me.permissions.includes("payroll.view") || me.permissions.includes("payroll.manage");
    const [stats, requestData, notificationData, payrollData] = await Promise.all([
      request<Dashboard>("/dashboard", accessToken),
      request<{ data: Approval[] }>("/requests", accessToken),
      request<{ data: Notice[] }>("/notifications", accessToken),
      canViewPayroll ? request<{ data: PayrollRun[] }>("/payroll/runs", accessToken) : Promise.resolve({ data: [] as PayrollRun[] }),
    ]);
    setUser(me); setDashboard(stats); setApprovals(requestData.data); setNotices(notificationData.data); setPayrollRuns(payrollData.data);
  }, []);

  useEffect(() => {
    void SecureStore.getItemAsync(TOKEN_KEY).then(async (savedToken: string | null) => {
      if (!savedToken) return;
      try { await loadWorkspace(savedToken); setToken(savedToken); }
      catch { await SecureStore.deleteItemAsync(TOKEN_KEY); }
    }).catch(() => undefined).finally(() => setRestoringSession(false));
  }, [loadWorkspace]);

  useEffect(() => {
    if (!token) return;
    const interval = setInterval(() => { void loadWorkspace(token).catch(() => undefined); }, 45_000);
    return () => clearInterval(interval);
  }, [token, loadWorkspace]);

  const refresh = async () => {
    if (!token) return;
    setRefreshing(true);
    try { await loadWorkspace(token); } catch (cause) { Alert.alert("Refresh failed", cause instanceof Error ? cause.message : "Try again."); }
    finally { setRefreshing(false); }
  };

  const signIn = async () => {
    if (!email.trim() || !password) return Alert.alert("Sign in", "Enter your work email and password.");
    setBusy(true);
    try {
      const result = await request<{ accessToken: string }>("/auth/login", undefined, { method: "POST", body: JSON.stringify({ email: email.trim(), password }) });
      await SecureStore.setItemAsync(TOKEN_KEY, result.accessToken);
      await loadWorkspace(result.accessToken); setToken(result.accessToken);
    } catch (cause) { await SecureStore.deleteItemAsync(TOKEN_KEY); Alert.alert("Could not sign in", cause instanceof Error ? cause.message : "Please try again."); }
    finally { setBusy(false); }
  };

  const decide = async (approval: Approval, status: "approved" | "rejected") => {
    try {
      await request(`/requests/${approval.id}`, token || undefined, { method: "PATCH", body: JSON.stringify({ status }) });
      await refresh();
    } catch (cause) { Alert.alert("Could not update request", cause instanceof Error ? cause.message : "Please try again."); }
  };

  const readNotice = async (notice: Notice) => {
    if (!token || notice.readAt) return;
    try {
      await request(`/notifications/${notice.id}/read`, token, { method: "PATCH" });
      setNotices((items) => items.map((item) => item.id === notice.id ? { ...item, readAt: new Date().toISOString() } : item));
    } catch { /* It remains unread and can be refreshed later. */ }
  };

  const submitRequest = async () => {
    if (!token || !requestTitle.trim() || !requestDetails.trim()) return Alert.alert("New request", "Add a title and details before submitting.");
    const amount = requestAmount.trim() ? Number(requestAmount) : undefined;
    if (amount !== undefined && (!Number.isFinite(amount) || amount <= 0)) return Alert.alert("New request", "Enter a positive amount or leave it blank for a non-financial request.");
    setBusy(true);
    try {
      const result = await request<{ requiredRole: string }>("/requests", token, { method: "POST", body: JSON.stringify({ requestType: "Operational", title: requestTitle.trim(), details: requestDetails.trim(), amount, approverRole: "Manager" }) });
      setRequestTitle(""); setRequestDetails(""); setRequestAmount(""); await refresh(); setTab("inbox");
      Alert.alert("Request submitted", `${result.requiredRole} has been notified by email and in-app.`);
    } catch (cause) { Alert.alert("Could not submit request", cause instanceof Error ? cause.message : "Please try again."); }
    finally { setBusy(false); }
  };

  const payrollAction = async (run: PayrollRun, action: "review" | "approve" | "pay") => {
    if (!token) return;
    try {
      await request(`/payroll/runs/${run.id}/action`, token, { method: "POST", body: JSON.stringify({ action }) });
      await refresh();
      Alert.alert("Payroll updated", action === "pay" ? "The payroll payment status was recorded. No bank transfer was initiated." : `Payroll run ${action === "review" ? "sent to the CEO for approval" : "approved"}.`);
    } catch (cause) { Alert.alert("Could not update payroll", cause instanceof Error ? cause.message : "Please try again."); }
  };

  const signOut = async () => {
    try { if (token) await request("/auth/logout", token, { method: "POST" }); } finally { await SecureStore.deleteItemAsync(TOKEN_KEY); setToken(null); setUser(null); }
  };

  if (restoringSession) return <SafeAreaView style={styles.safe}><ExpoStatusBar style="light" /><View style={styles.restore}><Image source={zyntrisMark} style={styles.loginLogo} resizeMode="contain" /><ActivityIndicator color="#D8AA54" /></View></SafeAreaView>;
  if (!user) return <SafeAreaView style={styles.safe}><ExpoStatusBar style="light" /><KeyboardAvoidingView style={styles.loginWrap} behavior={Platform.OS === "ios" ? "padding" : undefined}><View style={styles.logoPlate}><Image source={zyntrisMark} style={styles.loginLogo} resizeMode="contain" /></View><Text style={styles.brand}>ZYNTRIS</Text><Text style={styles.loginTitle}>Your work, in one place.</Text><Text style={styles.loginCaption}>Sign in with your organization account.</Text><TextInput style={styles.input} autoCapitalize="none" autoComplete="email" keyboardType="email-address" placeholder="Work email" placeholderTextColor="#9BA8AE" value={email} onChangeText={setEmail} /><TextInput style={styles.input} secureTextEntry autoComplete="current-password" placeholder="Password" placeholderTextColor="#9BA8AE" value={password} onChangeText={setPassword} /><Pressable style={styles.primaryButton} onPress={() => void signIn()} disabled={busy}>{busy ? <ActivityIndicator color="#10212B" /> : <Text style={styles.primaryText}>Sign in securely</Text>}</Pressable><Text style={styles.privacy}>Protected organization workspace · 30-day trials supported</Text></KeyboardAvoidingView></SafeAreaView>;

  const unread = notices.filter((item) => !item.readAt).length;
  return <SafeAreaView style={styles.safe}><ExpoStatusBar style="light" /><View style={styles.header}><View style={styles.headerBrand}><View style={styles.headerMark}><Image source={zyntrisMark} style={styles.headerLogo} resizeMode="contain" /></View><View><Text style={styles.headerTitle}>ZYNTRIS</Text><Text style={styles.orgName}>{user.organizationName}</Text></View></View><Pressable onPress={() => void signOut()}><Text style={styles.signOut}>Sign out</Text></Pressable></View><ScrollView contentContainerStyle={styles.content} refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => void refresh()} tintColor="#D8AA54" />}>
    {tab === "home" && <><Text style={styles.eyebrow}>OPERATIONS SNAPSHOT</Text><Text style={styles.pageTitle}>Good day, {user.fullName.split(" ")[0]}</Text><Text style={styles.subTitle}>{user.role} · {user.organizationName}</Text><View style={styles.statsGrid}><Stat label="People" value={dashboard?.people.active ?? 0} detail={`${dashboard?.people.total ?? 0} profiles`} /><Stat label="Leave requests" value={dashboard?.leave.pending ?? 0} detail="Pending" /><Stat label="Active projects" value={dashboard?.projects.active ?? 0} detail={`${dashboard?.tasks.overdue ?? 0} overdue tasks`} /><Stat label="Month-to-date spend" value={`₦${Number(dashboard?.expenses.total ?? 0).toLocaleString("en-NG")}`} detail="Expense claims" /></View><View style={styles.card}><Text style={styles.cardTitle}>Your approvals</Text><Text style={styles.cardText}>{approvals.filter((item) => item.status === "pending" && item.requiredRole === user.role).length} items are awaiting your review.</Text><Pressable onPress={() => setTab("approvals")}><Text style={styles.link}>Open approval queue →</Text></Pressable></View></>}
    {tab === "new" && <><Text style={styles.eyebrow}>WORKFLOW</Text><Text style={styles.pageTitle}>Submit a request</Text><Text style={styles.subTitle}>The right approver receives an email and in-app alert. Financial requests always go to the CEO.</Text><View style={styles.card}><Text style={styles.formLabel}>Request title</Text><TextInput style={styles.formInput} value={requestTitle} onChangeText={setRequestTitle} placeholder="What do you need?" placeholderTextColor="#9BA8AE" maxLength={120} /><Text style={styles.formLabel}>Details</Text><TextInput style={[styles.formInput, styles.multiline]} value={requestDetails} onChangeText={setRequestDetails} placeholder="Add the context the approver needs" placeholderTextColor="#9BA8AE" multiline textAlignVertical="top" maxLength={2000} /><Text style={styles.formLabel}>Amount in NGN · optional</Text><TextInput style={styles.formInput} value={requestAmount} onChangeText={setRequestAmount} placeholder="Leave blank if non-financial" placeholderTextColor="#9BA8AE" keyboardType="decimal-pad" /><Pressable style={styles.approveButton} onPress={() => void submitRequest()} disabled={busy}><Text style={styles.approveText}>{busy ? "Submitting…" : "Submit request"}</Text></Pressable></View></>}
    {tab === "payroll" && <><Text style={styles.eyebrow}>PEOPLE / PAYROLL</Text><Text style={styles.pageTitle}>Payroll records</Text><Text style={styles.subTitle}>Review, approve and record payroll status. Zyntris never initiates a bank transfer.</Text>{payrollRuns.map((run) => <View key={run.id} style={styles.card}><View style={styles.cardTop}><Text style={styles.pill}>{run.status.toUpperCase()}</Text><Text style={styles.amount}>{run.employeeCount} people</Text></View><Text style={styles.cardTitle}>{run.periodStart} – {run.periodEnd}</Text><Text style={styles.cardText}>Pay date {run.paymentDate} · Net record {run.currency} {Number(run.netTotal).toLocaleString()}</Text>{run.status === "draft" && user.permissions.includes("payroll.run") && <Pressable style={styles.approveButton} onPress={() => void payrollAction(run, "review")}><Text style={styles.approveText}>Complete finance review</Text></Pressable>}{run.status === "reviewed" && user.role === "CEO" && user.permissions.includes("payroll.approve") && <Pressable style={styles.approveButton} onPress={() => void payrollAction(run, "approve")}><Text style={styles.approveText}>Approve payroll</Text></Pressable>}{run.status === "approved" && user.permissions.includes("payroll.approve") && <Pressable style={styles.approveButton} onPress={() => void payrollAction(run, "pay")}><Text style={styles.approveText}>Record as paid</Text></Pressable>}</View>)}{payrollRuns.length === 0 && <Empty text="No payroll runs are available to this account." />}</>}
    {tab === "approvals" && <><Text style={styles.eyebrow}>WORKFLOW</Text><Text style={styles.pageTitle}>Requests & approvals</Text><Text style={styles.subTitle}>Review the requests routed to your access level.</Text>{approvals.filter((item) => item.status === "pending").map((item) => <View key={item.id} style={styles.card}><View style={styles.cardTop}><Text style={styles.pill}>{item.requestType}</Text><Text style={styles.amount}>{item.amount == null ? "" : `₦${Number(item.amount).toLocaleString("en-NG")}`}</Text></View><Text style={styles.cardTitle}>{item.title}</Text><Text style={styles.cardText}>Requested by {item.requester} · {item.requiredRole} approval</Text>{item.details && <Text style={styles.cardText}>{item.details}</Text>}{item.requiredRole === user.role || (user.role === "Organization Admin" && item.amount == null && item.requiredRole !== "CEO") ? <View style={styles.actionRow}><Pressable style={styles.rejectButton} onPress={() => void decide(item, "rejected")}><Text style={styles.rejectText}>Decline</Text></Pressable><Pressable style={styles.approveButton} onPress={() => void decide(item, "approved")}><Text style={styles.approveText}>Approve</Text></Pressable></View> : <Text style={styles.pendingText}>Assigned to {item.requiredRole}</Text>}</View>)}{approvals.filter((item) => item.status === "pending").length === 0 && <Empty text="There are no pending requests." />}</>}
    {tab === "inbox" && <><Text style={styles.eyebrow}>WORKSPACE</Text><Text style={styles.pageTitle}>Notifications</Text><Text style={styles.subTitle}>{unread ? `${unread} unread` : "You're all caught up"}</Text>{notices.map((item) => <Pressable key={item.id} style={[styles.card, !item.readAt && styles.unreadCard]} onPress={() => void readNotice(item)}><Text style={styles.cardTitle}>{item.title}</Text><Text style={styles.cardText}>{item.body}</Text><Text style={styles.dateText}>{new Date(item.createdAt).toLocaleString()}</Text></Pressable>)}{notices.length === 0 && <Empty text="New approval notifications will show here." />}</>}
    </ScrollView><View style={styles.tabBar}>{(["home", "approvals", ...(user.permissions.includes("payroll.view") || user.permissions.includes("payroll.manage") ? ["payroll" as const] : []), "new", "inbox"] as Tab[]).map((item) => <Pressable key={item} style={styles.tabItem} onPress={() => setTab(item)}><Text style={[styles.tabLabel, tab === item && styles.tabActive]}>{item === "inbox" && unread ? `Inbox · ${unread}` : item === "home" ? "Home" : item === "approvals" ? "Approvals" : item === "payroll" ? "Payroll" : item === "new" ? "New" : "Inbox"}</Text></Pressable>)}</View></SafeAreaView>;
}

function Stat({ label, value, detail }: { label: string; value: string | number; detail: string }) { return <View style={styles.statCard}><Text style={styles.statLabel}>{label}</Text><Text numberOfLines={1} style={styles.statValue}>{value}</Text><Text style={styles.statDetail}>{detail}</Text></View>; }
function Empty({ text }: { text: string }) { return <View style={styles.empty}><Text style={styles.emptyText}>{text}</Text></View>; }

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: "#10212B", paddingTop: Platform.OS === "android" ? StatusBar.currentHeight : 0 },
  loginWrap: { flex: 1, justifyContent: "center", paddingHorizontal: 28, backgroundColor: "#10212B" },
  restore: { flex: 1, alignItems: "center", justifyContent: "center", gap: 20 }, logoPlate: { alignSelf: "center", width: 92, height: 72, borderRadius: 17, backgroundColor: "#fff", alignItems: "center", justifyContent: "center", padding: 8, marginBottom: 12 }, loginLogo: { width: 76, height: 54 }, brand: { color: "#D8AA54", textAlign: "center", fontSize: 16, fontWeight: "800", letterSpacing: 3 },
  loginTitle: { color: "#fff", fontSize: 26, fontWeight: "700", marginTop: 54, marginBottom: 8 }, loginCaption: { color: "#B3C0C4", fontSize: 14, marginBottom: 28 },
  input: { height: 54, color: "#10212B", backgroundColor: "#fff", borderRadius: 13, paddingHorizontal: 15, marginBottom: 12, fontSize: 15 }, primaryButton: { height: 54, borderRadius: 13, backgroundColor: "#D8AA54", justifyContent: "center", alignItems: "center", marginTop: 8 }, primaryText: { color: "#10212B", fontWeight: "800", fontSize: 15 }, privacy: { textAlign: "center", color: "#9DAEB3", fontSize: 11, marginTop: 22 },
  header: { minHeight: 72, backgroundColor: "#10212B", paddingHorizontal: 20, paddingVertical: 10, flexDirection: "row", justifyContent: "space-between", alignItems: "center" }, headerBrand: { flexDirection: "row", alignItems: "center", gap: 10 }, headerMark: { width: 41, height: 41, borderRadius: 12, backgroundColor: "#fff", justifyContent: "center", alignItems: "center", padding: 4 }, headerLogo: { width: 34, height: 30 }, headerTitle: { fontWeight: "800", fontSize: 17, color: "#fff" }, orgName: { fontSize: 10, color: "#AEBBC0", marginTop: 2 }, signOut: { color: "#E0BA72", fontWeight: "700", fontSize: 12 },
  content: { padding: 20, paddingBottom: 30, backgroundColor: "#F3F6F6", flexGrow: 1 }, eyebrow: { fontSize: 10, color: "#9C7B3E", fontWeight: "800", letterSpacing: 1.4, marginTop: 9 }, pageTitle: { color: "#142630", fontSize: 27, fontWeight: "800", marginTop: 8 }, subTitle: { color: "#73828A", fontSize: 13, marginTop: 6, marginBottom: 21 },
  statsGrid: { flexDirection: "row", flexWrap: "wrap", gap: 11, marginBottom: 14 }, statCard: { width: "47%", flexGrow: 1, minHeight: 112, borderRadius: 15, backgroundColor: "#fff", padding: 15, borderWidth: 1, borderColor: "#E6EBE9" }, statLabel: { color: "#829098", fontSize: 11, fontWeight: "600" }, statValue: { color: "#172C35", fontSize: 24, fontWeight: "800", marginTop: 9 }, statDetail: { color: "#A1ACB0", fontSize: 10, marginTop: 5 },
  card: { backgroundColor: "#fff", borderRadius: 15, padding: 16, borderWidth: 1, borderColor: "#E6EBE9", marginBottom: 12 }, cardTop: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }, pill: { color: "#8C6A2C", backgroundColor: "#FBF3E4", overflow: "hidden", borderRadius: 20, paddingVertical: 5, paddingHorizontal: 9, fontSize: 10, fontWeight: "700" }, amount: { color: "#172C35", fontWeight: "800", fontSize: 14 }, cardTitle: { fontSize: 15, color: "#1B3039", fontWeight: "700" }, cardText: { color: "#75838A", fontSize: 12, lineHeight: 18, marginTop: 6 }, link: { color: "#9B762F", fontSize: 12, fontWeight: "800", marginTop: 17 }, actionRow: { flexDirection: "row", justifyContent: "flex-end", gap: 9, marginTop: 17 }, rejectButton: { borderRadius: 10, paddingVertical: 10, paddingHorizontal: 14, backgroundColor: "#FFF1EF" }, rejectText: { color: "#B55349", fontSize: 12, fontWeight: "700" }, approveButton: { borderRadius: 10, paddingVertical: 10, paddingHorizontal: 17, backgroundColor: "#10212B" }, approveText: { color: "#fff", fontSize: 12, fontWeight: "700" }, pendingText: { color: "#9C7B3E", fontWeight: "700", fontSize: 11, marginTop: 14 }, unreadCard: { borderColor: "#D8AA54", borderLeftWidth: 4 }, dateText: { color: "#9BA8AE", fontSize: 10, marginTop: 10 }, empty: { padding: 28, alignItems: "center" }, emptyText: { color: "#8A989D", fontSize: 13, textAlign: "center" },
  formLabel: { color: "#35464E", fontSize: 12, fontWeight: "700", marginBottom: 7, marginTop: 9 }, formInput: { minHeight: 48, borderWidth: 1, borderColor: "#E2E9E6", borderRadius: 10, paddingHorizontal: 12, color: "#172C35", fontSize: 13, marginBottom: 8 }, multiline: { minHeight: 110, paddingTop: 12 },
  tabBar: { flexDirection: "row", justifyContent: "space-around", paddingTop: 12, paddingBottom: Platform.OS === "ios" ? 22 : 13, backgroundColor: "#fff", borderTopColor: "#E6EBE9", borderTopWidth: 1 }, tabItem: { flex: 1, minWidth: 0, alignItems: "center", paddingVertical: 4 }, tabLabel: { color: "#89979C", fontSize: 10, fontWeight: "700" }, tabActive: { color: "#9B762F" },
});
