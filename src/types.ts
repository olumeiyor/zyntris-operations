export type PageId = "dashboard" | "employees" | "leave" | "attendance" | "appraisals" | "talent" | "projects" | "tasks" | "expenses" | "requests" | "budgets" | "assets" | "documents" | "vendors" | "helpdesk" | "calendar" | "customers" | "reports" | "payroll" | "settings" | "security" | "platform";

export type Employee = {
  id: string;
  employeeNumber: string;
  firstName: string;
  lastName: string;
  email: string;
  jobTitle: string;
  department: string;
  status: "active" | "on_leave" | "inactive";
  onboardingStatus?: "active" | "invited" | "declined";
  invitationEmailStatus?: "pending" | "accepted" | "failed" | null;
  invitationEmailError?: string | null;
  accessRole?: string;
  managerId?: string | null;
  managerName?: string | null;
  team?: string;
  workLocation: string;
  startDate: string;
  avatarColor: string;
};

export type DashboardData = {
  people: { total: number; active: number; onLeave: number };
  leave: { pending: number };
  projects: { active: number };
  tasks: { overdue: number };
  expenses: { total: number };
  departments: { name: string; count: number }[];
  recentActivity: { action: string; module: string; created_at: string }[];
};

export type LeaveRequest = { id: string; startDate: string; endDate: string; days: number; reason: string; status: string; employee: string; leaveType: string };
export type Task = { id: string; title: string; priority: string; status: string; dueDate: string; assignee: string; project: string };

export type Expense = { id: string; employee: string; category: string; amount: number; currency: string; expenseDate: string; description: string; status: "submitted" | "approved" | "rejected" | "paid"; project?: string; receiptAvailable?: boolean };
export type ApprovalRequest = { id: string; requestType: string; title: string; details?: string | null; requester: string; amount?: number | null; status: "pending" | "approved" | "rejected" | "paid"; requiredRole: string; createdAt: string };
export type Asset = { id: string; assetTag: string; name: string; category: string; serialNumber: string; status: "available" | "assigned" | "maintenance" | "retired"; assignee?: string; assignedEmployeeId?: string | null; location: string; value: number };
export type Vendor = { id: string; name: string; category: string; contactName: string; email: string; status: "active" | "review" | "expired"; contractEnd?: string; spend: number };
export type SupportTicket = { id: string; ticketNumber: string; subject: string; category: string; priority: "low" | "medium" | "high" | "urgent"; status: "open" | "assigned" | "in_progress" | "resolved" | "closed"; requester: string; assignee?: string; assigneeId?: string | null; description?: string | null; createdAt: string };
export type CalendarEvent = { id: string; title: string; eventType: string; startAt: string; endAt: string; location?: string; owner?: string };
export type Customer = { id: string; name: string; company?: string; email: string; stage: "lead" | "qualified" | "proposal" | "negotiation" | "won" | "lost"; value: number; owner?: string; lastActivity?: string; wonAt?: string | null };
