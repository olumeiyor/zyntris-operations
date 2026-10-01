import type { ApprovalRequest, Asset, CalendarEvent, Customer, DashboardData, Employee, Expense, LeaveRequest, SupportTicket, Task, Vendor } from "../types";

export const demoUser = { fullName: "Amaka Okafor", email: "admin@zyntris.org", role: "Organization Admin", organizationName: "Zyntris Technologies" };

export const demoDashboard: DashboardData = {
  people: { total: 124, active: 116, onLeave: 8 },
  leave: { pending: 12 },
  projects: { active: 18 },
  tasks: { overdue: 7 },
  expenses: { total: 18450000 },
  departments: [
    { name: "Technology", count: 34 },
    { name: "Sales & Marketing", count: 27 },
    { name: "Operations", count: 22 },
    { name: "Human Resources", count: 16 },
    { name: "Finance", count: 14 },
    { name: "Executive", count: 11 },
  ],
  recentActivity: [
    { action: "approved leave request", module: "Leave", created_at: "2026-09-28T09:35:00Z" },
    { action: "uploaded a policy document", module: "Documents", created_at: "2026-09-28T08:55:00Z" },
    { action: "created a new task", module: "Projects", created_at: "2026-09-27T16:20:00Z" },
  ],
};

export const demoEmployees: Employee[] = [
  { id: "emp-001", employeeNumber: "EMP-1024", firstName: "Amaka", lastName: "Okafor", email: "amaka@zyntris.org", jobTitle: "Chief Operations Officer", department: "Executive", status: "active", workLocation: "Hybrid", startDate: "2022-01-10", avatarColor: "#dbeafe" },
  { id: "emp-002", employeeNumber: "EMP-1025", firstName: "Daniel", lastName: "Adeyemi", email: "daniel@zyntris.org", jobTitle: "Engineering Lead", department: "Technology", status: "active", workLocation: "Remote", startDate: "2023-04-17", avatarColor: "#dcfce7" },
  { id: "emp-003", employeeNumber: "EMP-1026", firstName: "Nneka", lastName: "Eze", email: "nneka@zyntris.org", jobTitle: "People Partner", department: "Human Resources", status: "on_leave", workLocation: "On-site", startDate: "2023-07-03", avatarColor: "#fce7f3" },
  { id: "emp-004", employeeNumber: "EMP-1027", firstName: "Tunde", lastName: "Bello", email: "tunde@zyntris.org", jobTitle: "Product Designer", department: "Technology", status: "active", workLocation: "Hybrid", startDate: "2024-02-12", avatarColor: "#fef3c7" },
  { id: "emp-005", employeeNumber: "EMP-1028", firstName: "Fatima", lastName: "Musa", email: "fatima@zyntris.org", jobTitle: "Growth Manager", department: "Sales & Marketing", status: "active", workLocation: "Hybrid", startDate: "2024-06-24", avatarColor: "#ede9fe" },
  { id: "emp-006", employeeNumber: "EMP-1029", firstName: "Ifeanyi", lastName: "Obi", email: "ifeanyi@zyntris.org", jobTitle: "Finance Analyst", department: "Finance", status: "active", workLocation: "On-site", startDate: "2024-09-16", avatarColor: "#cffafe" },
];

export const demoLeave: LeaveRequest[] = [
  { id: "leave-001", startDate: "28 Sep 2026", endDate: "02 Oct 2026", days: 5, reason: "Family time", status: "approved", employee: "Nneka Eze", leaveType: "Annual leave" },
  { id: "leave-002", startDate: "05 Oct 2026", endDate: "06 Oct 2026", days: 2, reason: "Personal appointment", status: "pending", employee: "Tunde Bello", leaveType: "Personal time" },
  { id: "leave-003", startDate: "08 Oct 2026", endDate: "09 Oct 2026", days: 2, reason: "Medical appointment", status: "pending", employee: "Daniel Adeyemi", leaveType: "Sick leave" },
];

export const demoTasks: Task[] = [
  { id: "task-001", title: "Finalize tenant isolation tests", priority: "urgent", status: "in_progress", dueDate: "30 Sep 2026", assignee: "Daniel Adeyemi", project: "Zyntris platform launch" },
  { id: "task-002", title: "Review onboarding flow", priority: "high", status: "review", dueDate: "02 Oct 2026", assignee: "Tunde Bello", project: "Zyntris platform launch" },
  { id: "task-003", title: "Publish 2026 leave calendar", priority: "medium", status: "todo", dueDate: "01 Oct 2026", assignee: "Nneka Eze", project: "People operations refresh" },
  { id: "task-004", title: "Define customer health score", priority: "low", status: "todo", dueDate: "15 Oct 2026", assignee: "Fatima Musa", project: "Customer success workspace" },
];

export const demoExpenses: Expense[] = [
  { id: "expense-001", employee: "Daniel Adeyemi", category: "Software", amount: 185000, currency: "NGN", expenseDate: "23 Sep 2026", description: "Developer tooling renewal", status: "submitted", project: "Zyntris platform launch" },
  { id: "expense-002", employee: "Fatima Musa", category: "Travel", amount: 420000, currency: "NGN", expenseDate: "18 Sep 2026", description: "Customer workshop travel", status: "approved", project: "Customer success workspace" },
  { id: "expense-003", employee: "Ifeanyi Obi", category: "Operations", amount: 96000, currency: "NGN", expenseDate: "16 Sep 2026", description: "Office supplies", status: "paid" },
];

export const demoRequests: ApprovalRequest[] = [
  { id: "request-001", requestType: "Expense", title: "Developer tooling renewal", requester: "Daniel Adeyemi", amount: 185000, status: "pending", requiredRole: "Finance Admin", createdAt: "24 min ago" },
  { id: "request-002", requestType: "Leave", title: "Personal time · 05–06 Oct", requester: "Tunde Bello", status: "pending", requiredRole: "Manager", createdAt: "1 hr ago" },
  { id: "request-003", requestType: "Purchase", title: "Customer workshop equipment", requester: "Fatima Musa", amount: 760000, status: "approved", requiredRole: "Finance Admin", createdAt: "Yesterday" },
  { id: "request-004", requestType: "Document", title: "Vendor master agreement", requester: "Ifeanyi Obi", status: "pending", requiredRole: "Organization Admin", createdAt: "Yesterday" },
];

export const demoAssets: Asset[] = [
  { id: "asset-001", assetTag: "AST-0104", name: "MacBook Pro 14-inch", category: "Laptop", serialNumber: "C02ZX1A0MD6T", status: "assigned", assignee: "Daniel Adeyemi", location: "Lagos / Remote", value: 1850000 },
  { id: "asset-002", assetTag: "AST-0105", name: "Dell UltraSharp Monitor", category: "Equipment", serialNumber: "CN0D35P7", status: "available", location: "Lagos office", value: 420000 },
  { id: "asset-003", assetTag: "AST-0106", name: "iPhone 15 Pro", category: "Mobile", serialNumber: "F2LQW0D5", status: "maintenance", assignee: "Fatima Musa", location: "Lagos office", value: 1280000 },
];

export const demoVendors: Vendor[] = [
  { id: "vendor-001", name: "Cloudline Systems", category: "Technology", contactName: "Mariam Yusuf", email: "mariam@cloudline.example", status: "active", contractEnd: "31 Dec 2026", spend: 6200000 },
  { id: "vendor-002", name: "Cedar People Partners", category: "Professional services", contactName: "Kelechi Umeh", email: "kelechi@cedar.example", status: "review", contractEnd: "15 Oct 2026", spend: 1850000 },
  { id: "vendor-003", name: "Workplace House", category: "Facilities", contactName: "Tosin Adebayo", email: "tosin@workplace.example", status: "expired", contractEnd: "30 Aug 2026", spend: 940000 },
];

export const demoTickets: SupportTicket[] = [
  { id: "ticket-001", ticketNumber: "ZD-1042", subject: "Unable to access payroll folder", category: "IT", priority: "high", status: "in_progress", requester: "Nneka Eze", assignee: "Daniel Adeyemi", createdAt: "24 min ago" },
  { id: "ticket-002", ticketNumber: "ZD-1041", subject: "Update emergency contact details", category: "HR", priority: "medium", status: "assigned", requester: "Tunde Bello", assignee: "Nneka Eze", createdAt: "2 hrs ago" },
  { id: "ticket-003", ticketNumber: "ZD-1040", subject: "Request a second monitor", category: "Facilities", priority: "low", status: "open", requester: "Fatima Musa", createdAt: "Yesterday" },
];

export const demoEvents: CalendarEvent[] = [
  { id: "event-001", title: "Product leadership sync", eventType: "Meeting", startAt: "09:30", endAt: "10:15", location: "Google Meet", owner: "Amaka Okafor" },
  { id: "event-002", title: "Nneka on annual leave", eventType: "Leave", startAt: "All day", endAt: "02 Oct", location: "", owner: "People Operations" },
  { id: "event-003", title: "Security awareness training", eventType: "Training", startAt: "14:00", endAt: "15:00", location: "Training room", owner: "People Operations" },
];

export const demoCustomers: Customer[] = [
  { id: "customer-001", name: "Maya Okoro", company: "Northstar Foods", email: "maya@northstar.example", stage: "proposal", value: 4200000, owner: "Fatima Musa", lastActivity: "Today" },
  { id: "customer-002", name: "Chidi Nwankwo", company: "Fieldstone Logistics", email: "chidi@fieldstone.example", stage: "qualified", value: 1800000, owner: "Fatima Musa", lastActivity: "Yesterday" },
  { id: "customer-003", name: "Aisha Bello", company: "Sundial Energy", email: "aisha@sundial.example", stage: "won", value: 7600000, owner: "Amaka Okafor", lastActivity: "18 Sep 2026" },
];
