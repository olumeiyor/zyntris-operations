import { allowedBrowserOrigin, isTenantObjectKey, isTenantBackupObjectKey, tenantBackupKey, tenantDocumentKey, tenantReceiptKey } from "./security-boundaries";
import { passwordHash, verifyPassword } from "./password-hashing";

export interface Env {
  DB: D1Database;
  FILES: R2Bucket;
  BACKUPS: R2Bucket;
  ASSETS: Fetcher;
  APP_ORIGIN: string;
  ENVIRONMENT: string;
  SESSION_SECRET?: string;
  PASSWORD_PEPPER?: string;
  BREVO_API_KEY?: string;
  EMAIL_SENDER?: string;
  PLATFORM_ADMIN_EMAILS?: string;
  DEMO_ACCESS_PASSWORD?: string;
  GOOGLE_CALENDAR_CLIENT_ID?: string;
  GOOGLE_CALENDAR_CLIENT_SECRET?: string;
  MICROSOFT_CALENDAR_CLIENT_ID?: string;
  MICROSOFT_CALENDAR_CLIENT_SECRET?: string;
  EXPO_ACCESS_TOKEN?: string;
}

type AuthContext = {
  userId: string;
  organizationId: string;
  email: string;
  role: string;
  isDemo: boolean;
  isPlatformAdmin: boolean;
  mfaMandatory: boolean;
  mfaEnrollmentRequired: boolean;
  permissions: Set<string>;
};

const json = (data: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(data), {
    ...init,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "private, no-store", ...(init.headers || {}) },
  });

const error = (message: string, status = 400) => json({ error: message }, { status });

const requestId = () => crypto.randomUUID();
const isIsoCalendarDate = (value: string) => /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00.000Z`)) && new Date(`${value}T00:00:00.000Z`).toISOString().slice(0, 10) === value;

// Tenant-owned business data only. Credentials, global identities, sessions, billing,
// role grants and platform-control tables are intentionally excluded.
const BACKUP_TABLES = [
  "organization_settings", "departments", "teams", "employees", "leave_types", "leave_requests", "projects", "tasks",
  "expenses", "documents", "notifications", "approval_requests", "assets", "asset_history",
  "vendors", "support_tickets", "calendar_events", "customers", "budgets", "payroll_settings",
  "employee_pay_profiles", "payroll_components", "employee_pay_components", "payroll_runs",
  "payroll_run_items", "appraisal_cycles", "appraisals", "performance_kpis", "appraisal_kpi_scores",
  "appraisal_360_feedback", "performance_improvement_plans", "pip_check_ins", "job_requisitions",
  "job_candidates", "learning_courses", "learning_enrollments", "attendance_records", "shift_schedules", "audit_logs",
  "workflow_templates", "workflow_sla_settings", "tenant_backup_settings", "purchase_requests", "purchase_orders", "budget_reservations",
  "crm_lead_sources", "crm_leads", "crm_opportunities", "crm_pipeline_stages", "crm_activities", "crm_events", "organization_modules",
  "project_members", "project_phases", "task_dependencies", "task_comments", "project_milestones", "project_risks", "project_issues", "project_timesheets", "project_budget_lines", "project_health_history",
] as const;

const isoDate = (value: string) => /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`)) && new Date(`${value}T00:00:00Z`).toISOString().slice(0, 10) === value;

async function getTenantBackupObject(env: Env, organizationId: string, backupId: string, key: string) {
  if (!isTenantBackupObjectKey(key, organizationId, backupId)) return null;
  // New snapshots are in a dedicated bucket; fall back to the application bucket
  // only for snapshots written before the backup-target migration.
  return await env.BACKUPS.get(key) || await env.FILES.get(key);
}

async function createTenantBackup(env: Env, organizationId: string, createdBy: string) {
  const id = `backup-${crypto.randomUUID()}`;
  const tableSnapshots = await env.DB.batch(BACKUP_TABLES.map((table) => env.DB.prepare(`SELECT * FROM ${table} WHERE organization_id = ?`).bind(organizationId)));
  const tables: Record<string, unknown[]> = {};
  let recordCount = 0;
  for (const [index, table] of BACKUP_TABLES.entries()) { const rows = tableSnapshots[index].results || []; tables[table] = rows as unknown[]; recordCount += rows.length; }
  const files: { originalKey: string; backupKey: string }[] = [];
  for (const doc of (tables.documents || []) as { r2_key?: string }[]) {
    if (!doc.r2_key) continue;
    if (!isTenantObjectKey(doc.r2_key, organizationId)) throw new Error("A document references storage outside its organization boundary.");
    const source = await env.FILES.get(doc.r2_key);
    if (!source) throw new Error("A referenced document is missing from R2 storage.");
    const backupKey = tenantBackupKey(organizationId, id, `files/${await hashToken(doc.r2_key)}`);
    await env.BACKUPS.put(backupKey, source.body, { httpMetadata: source.httpMetadata, customMetadata: { originalKeyHash: await hashToken(doc.r2_key) } });
    files.push({ originalKey: doc.r2_key, backupKey });
  }
  const payload = JSON.stringify({ schemaVersion: 1, organizationId, generatedAt: new Date().toISOString(), tables, files });
  const checksum = await hashToken(payload); const objectKey = tenantBackupKey(organizationId, id, "snapshot.json");
  await env.BACKUPS.put(objectKey, payload, { httpMetadata: { contentType: "application/json" }, customMetadata: { checksum, schemaVersion: "1" } });
  await env.DB.prepare(`INSERT INTO tenant_backups (id, organization_id, object_key, checksum, size_bytes, record_count, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, organizationId, objectKey, checksum, new TextEncoder().encode(payload).byteLength, recordCount, createdBy).run();
  return { id, checksum, recordCount, fileCount: files.length, createdAt: new Date().toISOString(), objectKey };
}

async function calendarCipherKey(env: Env) {
  if (!env.SESSION_SECRET) throw new Error("SESSION_SECRET must be configured before calendar OAuth tokens can be stored.");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(env.SESSION_SECRET));
  return crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function encryptCalendarTokens(env: Env, value: unknown) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); const key = await calendarCipherKey(env);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(value)));
  return `${btoa(String.fromCharCode(...iv))}.${btoa(String.fromCharCode(...new Uint8Array(encrypted)))}`;
}
async function decryptCalendarTokens(env: Env, value: string) {
  const [ivPart, dataPart] = value.split("."); if (!ivPart || !dataPart) throw new Error("Stored calendar credentials are malformed.");
  const toBytes = (part: string) => Uint8Array.from(atob(part), (character) => character.charCodeAt(0));
  const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: toBytes(ivPart) }, await calendarCipherKey(env), toBytes(dataPart));
  return JSON.parse(new TextDecoder().decode(clear)) as { access_token: string; refresh_token?: string; expires_in?: number; token_type?: string };
}

type CalendarConnection = { id: string; organizationId: string; userId: string; provider: "google" | "microsoft"; encryptedTokens: string; syncCursor: string | null };
async function calendarAccessToken(env: Env, connection: CalendarConnection) {
  const tokens = await decryptCalendarTokens(env, connection.encryptedTokens);
  const id = connection.provider === "google" ? env.GOOGLE_CALENDAR_CLIENT_ID : env.MICROSOFT_CALENDAR_CLIENT_ID;
  const secret = connection.provider === "google" ? env.GOOGLE_CALENDAR_CLIENT_SECRET : env.MICROSOFT_CALENDAR_CLIENT_SECRET;
  const expires = await env.DB.prepare(`SELECT expires_at as expiresAt FROM calendar_provider_connections WHERE id = ? AND organization_id = ?`).bind(connection.id, connection.organizationId).first<{ expiresAt: string | null }>();
  if (expires?.expiresAt && Date.parse(expires.expiresAt) > Date.now() + 120000) return tokens.access_token;
  if (!tokens.refresh_token || !id || !secret) throw new Error("Calendar token expired or refresh credentials are not configured. Reconnect the provider.");
  const url = connection.provider === "google" ? "https://oauth2.googleapis.com/token" : "https://login.microsoftonline.com/common/oauth2/v2.0/token";
  const response = await fetch(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: id, client_secret: secret, refresh_token: tokens.refresh_token, grant_type: "refresh_token", ...(connection.provider === "microsoft" ? { scope: "offline_access https://graph.microsoft.com/Calendars.ReadWrite" } : {}) }) });
  const refreshed = await response.json() as typeof tokens;
  if (!response.ok || !refreshed.access_token) throw new Error("Calendar provider could not refresh access. Reconnect the provider.");
  const merged = { ...tokens, ...refreshed, refresh_token: refreshed.refresh_token || tokens.refresh_token };
  await env.DB.prepare(`UPDATE calendar_provider_connections SET encrypted_tokens = ?, expires_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(await encryptCalendarTokens(env, merged), new Date(Date.now() + Number(refreshed.expires_in || 3600) * 1000).toISOString(), connection.id, connection.organizationId).run();
  return merged.access_token;
}

async function pushCalendarEvent(env: Env, organizationId: string, eventId: string) {
  const event = await env.DB.prepare(`SELECT id, title, event_type as eventType, start_at as startAt, end_at as endAt, location FROM calendar_events WHERE id = ? AND organization_id = ?`).bind(eventId, organizationId).first<{ id: string; title: string; eventType: string; startAt: string; endAt: string; location: string | null }>();
  if (!event) return;
  const connections = await env.DB.prepare(`SELECT id, organization_id as organizationId, user_id as userId, provider, encrypted_tokens as encryptedTokens, sync_cursor as syncCursor FROM calendar_provider_connections WHERE organization_id = ? AND revoked_at IS NULL`).bind(organizationId).all<CalendarConnection>();
  for (const connection of connections.results || []) {
    try {
      const token = await calendarAccessToken(env, connection);
      const link = await env.DB.prepare(`SELECT provider_event_id as providerEventId FROM calendar_event_links WHERE calendar_event_id = ? AND connection_id = ? AND organization_id = ?`).bind(event.id, connection.id, organizationId).first<{ providerEventId: string }>();
      let endpoint: string; let method: string; let payload: Record<string, unknown>;
      if (connection.provider === "google") {
        endpoint = `https://www.googleapis.com/calendar/v3/calendars/primary/events${link ? `/${encodeURIComponent(link.providerEventId)}` : ""}`; method = link ? "PATCH" : "POST";
        payload = { summary: event.title, description: `Zyntris · ${event.eventType}`, location: event.location || undefined, start: { dateTime: event.startAt }, end: { dateTime: event.endAt }, extendedProperties: { private: { zyntrisEventId: event.id, zyntrisOrganizationId: organizationId } } };
      } else {
        endpoint = `https://graph.microsoft.com/v1.0/me/events${link ? `/${encodeURIComponent(link.providerEventId)}` : ""}`; method = link ? "PATCH" : "POST";
        payload = { subject: event.title, body: { contentType: "text", content: `Zyntris · ${event.eventType}` }, location: { displayName: event.location || "" }, start: { dateTime: event.startAt, timeZone: "UTC" }, end: { dateTime: event.endAt, timeZone: "UTC" }, transactionId: event.id };
      }
      let response = await fetch(endpoint, { method, headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(payload) });
      if (link && response.status === 404) response = await fetch(endpoint.replace(`/${encodeURIComponent(link.providerEventId)}`, ""), { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(payload) });
      const result = await response.json().catch(() => ({})) as { id?: string };
      if (!response.ok || !result.id) throw new Error(`Provider rejected event sync (${response.status}).`);
      await env.DB.prepare(`INSERT INTO calendar_event_links (organization_id, calendar_event_id, connection_id, provider_event_id, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(calendar_event_id,connection_id) DO UPDATE SET provider_event_id = excluded.provider_event_id, updated_at = CURRENT_TIMESTAMP`).bind(organizationId, event.id, connection.id, result.id).run();
      await env.DB.prepare(`UPDATE calendar_provider_connections SET sync_error = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(connection.id, organizationId).run();
    } catch (cause) {
      await env.DB.prepare(`UPDATE calendar_provider_connections SET sync_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(cause instanceof Error ? cause.message.slice(0, 300) : "Calendar event sync failed", connection.id, organizationId).run();
    }
  }
}

async function syncExternalCalendars(env: Env) {
  const data = await env.DB.prepare(`SELECT id, organization_id as organizationId, user_id as userId, provider, encrypted_tokens as encryptedTokens, sync_cursor as syncCursor FROM calendar_provider_connections WHERE revoked_at IS NULL`).all<CalendarConnection>();
  for (const connection of data.results || []) {
    try {
      const token = await calendarAccessToken(env, connection);
      // First publish organization events created in Zyntris, then fetch incremental provider changes.
      const localEvents = await env.DB.prepare(`SELECT e.id FROM calendar_events e LEFT JOIN calendar_event_links l ON l.calendar_event_id = e.id AND l.connection_id = ? WHERE e.organization_id = ? AND e.external_provider IS NULL AND l.calendar_event_id IS NULL ORDER BY e.created_at LIMIT 100`).bind(connection.id, connection.organizationId).all<{ id: string }>();
      for (const event of localEvents.results || []) await pushCalendarEvent(env, connection.organizationId, event.id);
      if (connection.provider === "google") {
        let pageToken: string | undefined; let nextSyncToken: string | undefined; let resetCursor = false; let keepPaging = true;
        while (keepPaging) {
          const endpoint = new URL("https://www.googleapis.com/calendar/v3/calendars/primary/events");
          endpoint.searchParams.set("singleEvents", "true"); endpoint.searchParams.set("showDeleted", "true"); endpoint.searchParams.set("maxResults", "2500");
          if (connection.syncCursor && !resetCursor) endpoint.searchParams.set("syncToken", connection.syncCursor);
          if (pageToken) endpoint.searchParams.set("pageToken", pageToken);
          const response = await fetch(endpoint, { headers: { authorization: `Bearer ${token}` } });
          if (response.status === 410 && connection.syncCursor && !resetCursor) { resetCursor = true; pageToken = undefined; continue; }
          const result = await response.json() as { items?: Array<{ id: string; status?: string; summary?: string; start?: { dateTime?: string; date?: string }; end?: { dateTime?: string; date?: string }; location?: string; updated?: string }>; nextPageToken?: string; nextSyncToken?: string; error?: { message?: string } };
          if (!response.ok) throw new Error(result.error?.message || `Google Calendar sync failed (${response.status}).`);
          for (const item of result.items || []) await upsertExternalCalendarEvent(env, connection, item.id, item.status === "cancelled", item.summary || "Calendar event", item.start?.dateTime || `${item.start?.date}T00:00:00.000Z`, item.end?.dateTime || `${item.end?.date}T00:00:00.000Z`, item.location || null, item.updated || null);
          pageToken = result.nextPageToken; keepPaging = Boolean(pageToken); nextSyncToken = result.nextSyncToken || nextSyncToken;
        }
        if (nextSyncToken) await env.DB.prepare(`UPDATE calendar_provider_connections SET sync_cursor = ?, last_synced_at = CURRENT_TIMESTAMP, sync_error = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(nextSyncToken, connection.id).run();
      } else {
        const cursor = connection.syncCursor || `https://graph.microsoft.com/v1.0/me/calendarView/delta?startDateTime=${encodeURIComponent(new Date(Date.now() - 90 * 86400000).toISOString())}&endDateTime=${encodeURIComponent(new Date(Date.now() + 365 * 86400000).toISOString())}`;
        let next: string | undefined = cursor; let deltaLink: string | undefined;
        while (next) {
          const response = await fetch(next, { headers: { authorization: `Bearer ${token}` } });
          const result = await response.json() as { value?: Array<{ id: string; subject?: string; isCancelled?: boolean; start?: { dateTime?: string }; end?: { dateTime?: string }; location?: { displayName?: string }; lastModifiedDateTime?: string; "@removed"?: unknown }>; "@odata.nextLink"?: string; "@odata.deltaLink"?: string; error?: { message?: string } };
          if (!response.ok) throw new Error(result.error?.message || `Microsoft calendar sync failed (${response.status}).`);
          for (const item of result.value || []) await upsertExternalCalendarEvent(env, connection, item.id, Boolean(item["@removed"] || item.isCancelled), item.subject || "Calendar event", item.start?.dateTime ? new Date(item.start.dateTime).toISOString() : new Date().toISOString(), item.end?.dateTime ? new Date(item.end.dateTime).toISOString() : new Date().toISOString(), item.location?.displayName || null, item.lastModifiedDateTime || null);
          next = result["@odata.nextLink"]; deltaLink = result["@odata.deltaLink"] || deltaLink;
        }
        if (deltaLink) await env.DB.prepare(`UPDATE calendar_provider_connections SET sync_cursor = ?, last_synced_at = CURRENT_TIMESTAMP, sync_error = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(deltaLink, connection.id).run();
      }
    } catch (cause) {
      const message = cause instanceof Error ? cause.message.slice(0, 300) : "Calendar synchronization failed.";
      await env.DB.prepare(`UPDATE calendar_provider_connections SET sync_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(message, connection.id, connection.organizationId).run();
    }
  }
}

async function upsertExternalCalendarEvent(env: Env, connection: CalendarConnection, providerEventId: string, deleted: boolean, title: string, startAt: string, endAt: string, location: string | null, updatedAt: string | null) {
  const linked = await env.DB.prepare(`SELECT calendar_event_id as eventId FROM calendar_event_links WHERE connection_id = ? AND provider_event_id = ? AND organization_id = ?`).bind(connection.id, providerEventId, connection.organizationId).first<{ eventId: string }>();
  const external = await env.DB.prepare(`SELECT id FROM calendar_events WHERE organization_id = ? AND connection_id = ? AND external_id = ?`).bind(connection.organizationId, connection.id, providerEventId).first<{ id: string }>();
  const targetId = linked?.eventId || external?.id;
  if (deleted) { if (external?.id) await env.DB.prepare(`DELETE FROM calendar_events WHERE id = ? AND organization_id = ?`).bind(external.id, connection.organizationId).run(); return; }
  if (!targetId) {
    const id = `external-event-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO calendar_events (id, organization_id, title, event_type, start_at, end_at, location, owner_id, external_provider, external_id, connection_id, external_updated_at) VALUES (?, ?, ?, 'Meeting', ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, connection.organizationId, title.slice(0,160), startAt, endAt, location?.slice(0,250) || null, connection.userId, connection.provider, providerEventId, connection.id, updatedAt).run();
    await env.DB.prepare(`INSERT OR IGNORE INTO calendar_event_links (organization_id, calendar_event_id, connection_id, provider_event_id) VALUES (?, ?, ?, ?)`).bind(connection.organizationId, id, connection.id, providerEventId).run();
  } else {
    await env.DB.prepare(`UPDATE calendar_events SET title = ?, start_at = ?, end_at = ?, location = ?, external_updated_at = ? WHERE id = ? AND organization_id = ?`).bind(title.slice(0,160), startAt, endAt, location?.slice(0,250) || null, updatedAt, targetId, connection.organizationId).run();
  }
}

async function handleCalendarOAuthCallback(request: Request, env: Env) {
  const url = new URL(request.url); const provider = url.searchParams.get("provider");
  const state = url.searchParams.get("state") || ""; const code = url.searchParams.get("code");
  const home = `${env.APP_ORIGIN}/?calendar_connection=`;
  if (!state || !code) return Response.redirect(`${home}failed`, 302);
  const record = await env.DB.prepare(`SELECT organization_id as organizationId, user_id as userId, provider, expires_at as expiresAt FROM calendar_oauth_states WHERE token_hash = ?`).bind(await hashToken(state)).first<{ organizationId: string; userId: string; provider: string; expiresAt: string }>();
  if (!record || !['google','microsoft'].includes(record.provider) || provider && record.provider !== provider || Date.parse(`${record.expiresAt.replace(" ", "T")}Z`) <= Date.now()) return Response.redirect(`${home}expired`, 302);
  await env.DB.prepare(`DELETE FROM calendar_oauth_states WHERE token_hash = ?`).bind(await hashToken(state)).run();
  const providerKind = record.provider;
  const google = providerKind === "google";
  const clientId = google ? env.GOOGLE_CALENDAR_CLIENT_ID : env.MICROSOFT_CALENDAR_CLIENT_ID;
  const clientSecret = google ? env.GOOGLE_CALENDAR_CLIENT_SECRET : env.MICROSOFT_CALENDAR_CLIENT_SECRET;
  if (!clientId || !clientSecret) return Response.redirect(`${home}not_configured`, 302);
  const redirectUri = `${env.APP_ORIGIN}/api/calendar/oauth/callback`;
  const tokenUrl = google ? "https://oauth2.googleapis.com/token" : "https://login.microsoftonline.com/common/oauth2/v2.0/token";
  try {
    const response = await fetch(tokenUrl, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, grant_type: "authorization_code" }) });
    const tokens = await response.json() as { access_token?: string; refresh_token?: string; expires_in?: number; scope?: string; token_type?: string };
    if (!response.ok || !tokens.access_token) return Response.redirect(`${home}failed`, 302);
    const id = `calendar-${record.organizationId}-${record.userId}-${providerKind}`;
    const encrypted = await encryptCalendarTokens(env, tokens);
    await env.DB.prepare(`INSERT INTO calendar_provider_connections (id, organization_id, user_id, provider, encrypted_tokens, scopes, expires_at, revoked_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, CURRENT_TIMESTAMP) ON CONFLICT(organization_id,user_id,provider) DO UPDATE SET id = excluded.id, encrypted_tokens = excluded.encrypted_tokens, scopes = excluded.scopes, expires_at = excluded.expires_at, sync_cursor = NULL, revoked_at = NULL, sync_error = NULL, updated_at = CURRENT_TIMESTAMP`).bind(id, record.organizationId, record.userId, providerKind, encrypted, tokens.scope || (google ? "https://www.googleapis.com/auth/calendar.events.owned" : "offline_access Calendars.ReadWrite"), new Date(Date.now() + Number(tokens.expires_in || 3600) * 1000).toISOString()).run();
    return Response.redirect(`${home}${providerKind}_connected`, 302);
  } catch (cause) { console.error("Calendar OAuth token exchange failed", cause instanceof Error ? cause.name : "unknown"); return Response.redirect(`${home}failed`, 302); }
}
const validTaxBands = (bands: unknown): bands is { upTo: number | null; rate: number }[] => Array.isArray(bands) && bands.length > 0 && bands.length <= 20 && bands.every((band, index) => band && Number.isFinite(band.rate) && band.rate >= 0 && band.rate <= 1 && (band.upTo === null || (Number.isFinite(band.upTo) && band.upTo > 0 && (index === 0 || bands[index - 1].upTo !== null && band.upTo > bands[index - 1].upTo)))) && bands.at(-1)?.upTo === null && bands.slice(0, -1).every((band) => band.upTo !== null);

function withSecurityHeaders(response: Response) {
  const headers = new Headers(response.headers);
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("referrer-policy", "strict-origin-when-cross-origin");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
  headers.set("content-security-policy", "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self' https://app.zyntris.org");
  headers.set("strict-transport-security", "max-age=31536000; includeSubDomains");
  headers.set("x-request-id", requestId());
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function setCookie(name: string, value: string, maxAge: number) {
  return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function getCookie(request: Request, name: string) {
  const cookies = request.headers.get("cookie") || "";
  return cookies.split(";").map((entry) => entry.trim()).find((entry) => entry.startsWith(`${name}=`))?.split("=").slice(1).join("=");
}

async function hashToken(value: string) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function validUploadContent(file: File, allowedTypes: string[]) {
  if (!allowedTypes.includes(file.type)) return false;
  const bytes = new Uint8Array(await file.slice(0, 16).arrayBuffer());
  const startsWith = (...signature: number[]) => signature.every((byte, index) => bytes[index] === byte);
  if (file.type === "application/pdf") return new TextDecoder().decode(bytes.slice(0, 5)) === "%PDF-";
  if (file.type === "image/jpeg") return startsWith(0xff, 0xd8, 0xff);
  if (file.type === "image/png") return startsWith(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);
  if (file.type === "image/webp") return new TextDecoder().decode(bytes.slice(0, 4)) === "RIFF" && new TextDecoder().decode(bytes.slice(8, 12)) === "WEBP";
  if (file.type === "application/vnd.openxmlformats-officedocument.wordprocessingml.document") return file.name.toLowerCase().endsWith(".docx") && startsWith(0x50, 0x4b, 0x03, 0x04);
  if (file.type === "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") return file.name.toLowerCase().endsWith(".xlsx") && startsWith(0x50, 0x4b, 0x03, 0x04);
  if (file.type === "text/csv") {
    if (!file.name.toLowerCase().endsWith(".csv")) return false;
    try { const sample = await file.slice(0, 4096).text(); return !sample.includes("\u0000"); } catch { return false; }
  }
  return false;
}

async function reserveTenantStorage(env: Env, organizationId: string, bytes: number) {
  const storage = await env.DB.prepare(`SELECT storage_limit_bytes as storageLimit FROM subscriptions WHERE organization_id = ?`).bind(organizationId).first<{ storageLimit: number }>();
  if (!storage) return { available: false, withinLimit: false };
  const reservation = await env.DB.batch([
    env.DB.prepare(`INSERT OR IGNORE INTO tenant_storage_usage (organization_id, used_bytes) VALUES (?, 0)`).bind(organizationId),
    env.DB.prepare(`UPDATE tenant_storage_usage SET used_bytes = used_bytes + ?, updated_at = CURRENT_TIMESTAMP WHERE organization_id = ? AND used_bytes + ? <= ?`).bind(bytes, organizationId, bytes, storage.storageLimit),
  ]);
  return { available: true, withinLimit: reservation[1].meta.changes === 1 };
}

async function releaseTenantStorage(env: Env, organizationId: string, bytes: number) {
  if (bytes > 0) await env.DB.prepare(`UPDATE tenant_storage_usage SET used_bytes = MAX(0, used_bytes - ?), updated_at = CURRENT_TIMESTAMP WHERE organization_id = ?`).bind(bytes, organizationId).run();
}

const escapeIcs = (value: string) => value.replace(/\\/g, "\\\\").replace(/\r?\n/g, "\\n").replace(/,/g, "\\,").replace(/;/g, "\\;");
const icsDate = (value: string) => new Date(value).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");

async function publicCalendarFeed(token: string, env: Env) {
  if (!/^[a-f0-9]{64}$/i.test(token)) return error("Calendar feed not found.", 404);
  const feed = await env.DB.prepare(`SELECT organization_id as organizationId FROM calendar_feed_tokens WHERE token_hash = ? AND revoked_at IS NULL AND datetime(expires_at) > CURRENT_TIMESTAMP`).bind(await hashToken(token)).first<{ organizationId: string }>();
  if (!feed) return error("Calendar feed not found or revoked.", 404);
  const [organization, events] = await Promise.all([
    env.DB.prepare(`SELECT name FROM organizations WHERE id = ?`).bind(feed.organizationId).first<{ name: string }>(),
    env.DB.prepare(`SELECT id, title, event_type as eventType, start_at as startAt, end_at as endAt, location FROM calendar_events WHERE organization_id = ? AND end_at >= datetime('now', '-90 days') ORDER BY start_at LIMIT 1000`).bind(feed.organizationId).all<{ id: string; title: string; eventType: string; startAt: string; endAt: string; location: string | null }>(),
  ]);
  const lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Zyntris//Operations Calendar//EN", "CALSCALE:GREGORIAN", "METHOD:PUBLISH", `X-WR-CALNAME:${escapeIcs(organization?.name || "Zyntris")}`];
  for (const event of events.results || []) lines.push("BEGIN:VEVENT", `UID:${event.id}@zyntris.org`, `DTSTAMP:${icsDate(new Date().toISOString())}`, `DTSTART:${icsDate(event.startAt)}`, `DTEND:${icsDate(event.endAt)}`, `SUMMARY:${escapeIcs(event.title)}`, `CATEGORIES:${escapeIcs(event.eventType)}`, ...(event.location ? [`LOCATION:${escapeIcs(event.location)}`] : []), "END:VEVENT");
  lines.push("END:VCALENDAR");
  return new Response(`${lines.join("\r\n")}\r\n`, { headers: { "content-type": "text/calendar; charset=utf-8", "cache-control": "no-store", "content-disposition": "attachment; filename=zyntris-calendar.ics" } });
}

async function publicProjectPortal(token: string, env: Env, asPage = false) {
  if (token.length < 32 || token.length > 200) return error("Project portal link is invalid or expired.", 404);
  const row = await env.DB.prepare(`SELECT p.project_code as projectCode,p.name,p.description,p.status,p.health,p.progress,p.start_date as startDate,p.end_date as endDate,t.organization_id as organizationId,t.project_id as projectId FROM project_client_portal_tokens t JOIN projects p ON p.id=t.project_id AND p.organization_id=t.organization_id WHERE t.token_hash=? AND t.revoked_at IS NULL AND t.expires_at>CURRENT_TIMESTAMP`).bind(await hashToken(token)).first<Record<string, unknown>>();
  if (!row) return error("Project portal link is invalid or expired.", 404);
  const [milestones, tasks] = await Promise.all([
    env.DB.prepare(`SELECT name,target_date as targetDate,status FROM project_milestones WHERE organization_id=? AND project_id=? ORDER BY target_date`).bind(row.organizationId,row.projectId).all(),
    env.DB.prepare(`SELECT title,status,due_date as dueDate,progress FROM tasks WHERE organization_id=? AND project_id=? AND status IN ('in_progress','review','completed') ORDER BY due_date LIMIT 100`).bind(row.organizationId,row.projectId).all(),
  ]);
  const project={projectCode:row.projectCode,name:row.name,description:row.description,status:row.status,health:row.health,progress:row.progress,startDate:row.startDate,endDate:row.endDate},milestoneRows=(milestones.results||[]) as Record<string,unknown>[],taskRows=(tasks.results||[]) as Record<string,unknown>[];
  if(!asPage)return json({project,milestones:milestoneRows,tasks:taskRows},{headers:{"cache-control":"private, no-store","x-robots-tag":"noindex, nofollow"}});
  const esc=(value:unknown)=>String(value??"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;");
  const html=`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${esc(project.name)} · Project update</title><style>body{margin:0;background:#f4f7f8;color:#142a33;font:16px system-ui,sans-serif}.wrap{max-width:920px;margin:48px auto;padding:0 20px}.brand{color:#b78936;font-weight:700;letter-spacing:.12em}.card{background:white;border:1px solid #dce5e8;border-radius:18px;padding:24px;margin:18px 0;box-shadow:0 8px 30px #1231}.muted{color:#60747b}.meta{display:flex;gap:24px;flex-wrap:wrap}.bar{height:10px;background:#e6ecef;border-radius:9px;overflow:hidden}.bar i{display:block;height:100%;background:#147e70;width:${Math.max(0,Math.min(100,Number(project.progress)||0))}%}li{padding:10px 0;border-bottom:1px solid #edf1f2}h1{margin:8px 0}small{color:#60747b}</style><body><main class="wrap"><div class="brand">ZYNTRIS · CLIENT UPDATE</div><section class="card"><small>${esc(project.projectCode)}</small><h1>${esc(project.name)}</h1><p class="muted">${esc(project.description||"Project status and milestones")}</p><div class="meta"><span>Status: <b>${esc(project.status)}</b></span><span>Health: <b>${esc(project.health)}</b></span><span>Progress: <b>${esc(project.progress)}%</b></span></div><p class="bar" aria-label="${esc(project.progress)} percent complete"><i></i></p><small>${esc(project.startDate||"Start date not set")} – ${esc(project.endDate||"End date not set")}</small></section><section class="card"><h2>Milestones</h2><ul>${milestoneRows.map(x=>`<li><b>${esc(x.name)}</b> · ${esc(x.status)} <small>— ${esc(x.targetDate)}</small></li>`).join("")||"<li>No milestones have been shared yet.</li>"}</ul></section><section class="card"><h2>Recent work</h2><ul>${taskRows.map(x=>`<li><b>${esc(x.title)}</b> · ${esc(x.status)} <small>— ${esc(x.dueDate||"No due date")}</small></li>`).join("")||"<li>No work updates have been shared yet.</li>"}</ul></section><p class="muted"><small>This is a private, read-only status page. The link can be revoked by the organization.</small></p></main></body></html>`;
  return new Response(html,{headers:{"content-type":"text/html; charset=utf-8","cache-control":"private, no-store","x-content-type-options":"nosniff","x-frame-options":"DENY","content-security-policy":"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'","x-robots-tag":"noindex, nofollow"}});
}

async function auth(request: Request, env: Env): Promise<AuthContext | null> {
  const mobileRequest = new URL(request.url).pathname.startsWith("/api/mobile/");
  const authorization = mobileRequest ? request.headers.get("authorization") : null;
  const token = authorization?.match(/^Bearer\s+([a-f0-9]{64})$/i)?.[1] || getCookie(request, "zyntris_session");
  if (!token) return null;
  const tokenHash = await hashToken(token);
  if (mobileRequest) {
    const touched = await env.DB.prepare(`UPDATE sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP AND last_seen_at > datetime('now', '-2 minutes')`).bind(tokenHash).run();
    if (touched.meta.changes !== 1) return null;
  } else {
    const active = await env.DB.prepare(`SELECT 1 as active FROM sessions WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP AND last_seen_at > datetime('now', '-2 minutes')`).bind(tokenHash).first();
    if (!active) return null;
  }
  const result = await env.DB.prepare(`
    SELECT m.user_id as userId, m.organization_id as organizationId, u.email as email, r.name as role, r.id as roleId, s.is_demo as isDemo
    FROM sessions s
    JOIN users u ON u.id = s.user_id AND u.email_verified_at IS NOT NULL AND u.status = 'active'
    JOIN memberships m ON m.user_id = s.user_id AND m.organization_id = s.organization_id
    JOIN roles r ON r.id = m.role_id
    JOIN organizations o ON o.id = m.organization_id AND o.status != 'suspended'
    JOIN subscriptions sub ON sub.organization_id = o.id AND sub.status IN ('active','trialing') AND (sub.status != 'trialing' OR sub.trial_ends_at > CURRENT_TIMESTAMP)
    WHERE s.token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP AND m.status = 'active'
    LIMIT 1
  `).bind(tokenHash).first<{ userId: string; organizationId: string; email: string; role: string; roleId: string; isDemo: number }>();
  if (!result) return null;
  const rows = await env.DB.prepare(`SELECT p.code FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = ?`).bind(result.roleId).all<{ code: string }>();
  const platformEmails = (env.PLATFORM_ADMIN_EMAILS || "").split(",").map((email) => email.trim().toLowerCase()).filter(Boolean);
  const isPlatformAdmin = platformEmails.includes(result.email.toLowerCase());
  const permissions = new Set((rows.results || []).map((row) => row.code));
  const privilegedRole = ["admin", "organization admin", "hr admin", "finance admin", "ceo"].includes(result.role.trim().toLowerCase());
  const requiresMfa = isPlatformAdmin || privilegedRole || permissions.has("roles.manage") || permissions.has("settings.manage");
  const factor = await env.DB.prepare(`SELECT 1 as enabled FROM user_two_factor WHERE user_id = ? AND enabled_at IS NOT NULL`).bind(result.userId).first<{ enabled: number }>();
  return {
    userId: result.userId,
    organizationId: result.organizationId,
    email: result.email,
    role: result.role,
    isDemo: result.isDemo === 1,
    isPlatformAdmin,
    mfaMandatory: requiresMfa,
    mfaEnrollmentRequired: requiresMfa && !factor,
    permissions,
  };
}

function mfaEnrollmentAllowed(path: string, method: string) {
  return (path === "/api/me" && method === "GET")
    || (path === "/api/auth/activity" && method === "POST")
    || (path === "/api/auth/2fa/status" && method === "GET")
    || (path === "/api/auth/2fa/setup" && method === "POST")
    || (path === "/api/auth/2fa/enable" && method === "POST");
}

function hasPermission(context: AuthContext, permission: string) {
  return context.permissions.has(permission);
}

function requiredTenantModule(path: string): string | null {
  if (path === "/api/projects/subscription") return null;
  if (path === "/api/projects" || path.startsWith("/api/projects/")) return "projects";
  if (path === "/api/crm" || path.startsWith("/api/crm/") || path === "/api/customers" || path.startsWith("/api/customers/")) return "crm";
  if (path === "/api/payroll" || path.startsWith("/api/payroll/")) return "payroll";
  if (["/api/employees", "/api/leave", "/api/attendance", "/api/appraisals", "/api/appraisal-cycles", "/api/hr"]
    .some((prefix) => path === prefix || path.startsWith(`${prefix}/`)) || path.startsWith("/api/appraisal-360/")) return "hr";
  if (["/api/expenses", "/api/expense-policy", "/api/requests", "/api/approval-workflows", "/api/budgets", "/api/purchases"]
    .some((prefix) => path === prefix || path.startsWith(`${prefix}/`))) return "finance";
  if (["/api/tasks", "/api/assets", "/api/vendors", "/api/tickets", "/api/calendar", "/api/files", "/api/announcements", "/api/operations/members"]
    .some((prefix) => path === prefix || path.startsWith(`${prefix}/`))) return "operations";
  if (path === "/api/reports" || path.startsWith("/api/reports/")) return "reports";
  return null;
}

async function workspaceAccessError(env: Env, organizationId: string) {
  const workspace = await env.DB.prepare(`SELECT o.status as organizationStatus, s.status as subscriptionStatus, s.trial_ends_at as trialEndsAt FROM organizations o LEFT JOIN subscriptions s ON s.organization_id = o.id WHERE o.id = ?`).bind(organizationId).first<{ organizationStatus: string; subscriptionStatus: string | null; trialEndsAt: string | null }>();
  if (!workspace) return "The organization workspace is unavailable. Contact Zyntris support.";
  const trialExpired = workspace.subscriptionStatus === "expired" || (workspace.subscriptionStatus === "trialing" && (!workspace.trialEndsAt || new Date(`${workspace.trialEndsAt.replace(" ", "T")}Z`).getTime() <= Date.now()));
  if (trialExpired) return "This organization’s trial has ended and its services are off. Contact Zyntris to reactivate the workspace.";
  if (workspace.organizationStatus === "suspended" || !["active", "trialing"].includes(workspace.subscriptionStatus || "")) return "This organization’s services are currently disabled. Contact your Zyntris administrator.";
  return null;
}

function safeEqual(left: string, right: string) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i += 1) difference |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return difference === 0;
}

function randomToken(bytes = 32) {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  return [...value].map((part) => part.toString(16).padStart(2, "0")).join("");
}

async function upgradeLegacyPassword(env: Env, userId: string, password: string, encoded: string) {
  if (!env.PASSWORD_PEPPER || encoded.startsWith("$argon2id$")) return;
  const upgraded = await passwordHash(password, env.PASSWORD_PEPPER);
  await env.DB.prepare(`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND password_hash = ?`).bind(upgraded, userId, encoded).run();
}

function base32Encode(bytes: Uint8Array) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0, output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { output += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, buffer = 0;
  const output: number[] = [];
  for (const char of value.toUpperCase().replace(/=+$/g, "")) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Invalid authenticator secret");
    buffer = (buffer << 5) | index; bits += 5;
    if (bits >= 8) { output.push((buffer >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(output);
}

async function encryptTwoFactorSecret(env: Env, secret: string) {
  if (!env.SESSION_SECRET) throw new Error("Two-factor encryption secret is unavailable.");
  const rawKey = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`zyntris/totp/v1:${env.SESSION_SECRET}`));
  const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(secret));
  const bytes = new Uint8Array(iv.length + encrypted.byteLength); bytes.set(iv); bytes.set(new Uint8Array(encrypted), iv.length);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function decryptTwoFactorSecret(env: Env, ciphertext: string) {
  if (!env.SESSION_SECRET || !/^(?:[0-9a-f]{2})+$/.test(ciphertext)) throw new Error("Two-factor encryption key is unavailable or data is malformed.");
  const rawKey = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`zyntris/totp/v1:${env.SESSION_SECRET}`));
  const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
  const bytes = new Uint8Array(ciphertext.match(/.{2}/g)!.map((byte) => Number.parseInt(byte, 16)));
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12) }, key, bytes.slice(12));
  return new TextDecoder().decode(decrypted);
}

async function matchTotp(secret: string, input: string) {
  const code = input.replace(/\s+/g, "");
  if (!/^\d{6}$/.test(code)) return null;
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const now = Math.floor(Date.now() / 30_000);
  for (const counter of [now - 1, now, now + 1]) {
    const message = new Uint8Array(8);
    let remaining = counter;
    for (let index = 7; index >= 0; index -= 1) { message[index] = remaining & 255; remaining = Math.floor(remaining / 256); }
    const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
    const offset = digest[digest.length - 1] & 15;
    const number = (((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) % 1_000_000;
    if (safeEqual(String(number).padStart(6, "0"), code)) return counter;
  }
  return null;
}

function makeRecoveryCodes() {
  return Array.from({ length: 10 }, () => {
    const raw = randomToken(5).toUpperCase();
    return `${raw.slice(0, 5)}-${raw.slice(5)}`;
  });
}

async function issueTwoFactorChallenge(env: Env, userId: string, organizationId: string, mobile: boolean) {
  const token = randomToken();
  await env.DB.prepare(`DELETE FROM two_factor_challenges WHERE expires_at <= CURRENT_TIMESTAMP OR created_at < datetime('now', '-1 day')`).run();
  await env.DB.prepare(`INSERT INTO two_factor_challenges (id, token_hash, user_id, organization_id, is_mobile, expires_at) VALUES (?, ?, ?, ?, ?, datetime('now', '+5 minutes'))`)
    .bind(requestId(), await hashToken(token), userId, organizationId, mobile ? 1 : 0).run();
  return json({ twoFactorRequired: true, challengeToken: token, expiresIn: 300 });
}

async function encryptBankDetails(env: Env, details: { bankName: string; accountName: string; accountNumber: string }) {
  if (!env.SESSION_SECRET) throw new Error("Payroll encryption secret is unavailable.");
  const keyMaterial = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`zyntris/payroll-bank/v1:${env.SESSION_SECRET}`));
  const key = await crypto.subtle.importKey("raw", keyMaterial, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(details)));
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv); combined.set(new Uint8Array(ciphertext), iv.length);
  return [...combined].map((part) => part.toString(16).padStart(2, "0")).join("");
}

async function decryptBankDetails(env: Env, ciphertextHex: string) {
  if (!env.SESSION_SECRET || !/^(?:[0-9a-f]{2})+$/.test(ciphertextHex)) throw new Error("Payroll encryption key is unavailable or bank data is malformed.");
  const keyMaterial = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`zyntris/payroll-bank/v1:${env.SESSION_SECRET}`));
  const key = await crypto.subtle.importKey("raw", keyMaterial, { name: "AES-GCM" }, false, ["decrypt"]);
  const bytes = new Uint8Array(ciphertextHex.match(/.{2}/g)!.map((part) => Number.parseInt(part, 16)));
  const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12) }, key, bytes.slice(12));
  return JSON.parse(new TextDecoder().decode(clear)) as { bankName: string; accountName: string; accountNumber: string };
}

async function createSession(env: Env, userId: string, organizationId: string, isDemo = false) {
  const token = randomToken();
  await env.DB.prepare(`INSERT INTO sessions (id, user_id, organization_id, token_hash, expires_at, is_demo) VALUES (?, ?, ?, ?, datetime('now', '+12 hours'), ?)`)
    .bind(requestId(), userId, organizationId, await hashToken(token), isDemo ? 1 : 0).run();
  return token;
}

function cookieResponse(data: unknown, token: string, maxAge = 12 * 60 * 60, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "private, no-store", "set-cookie": setCookie("zyntris_session", token, maxAge) } });
}

function originAllowed(request: Request, env: Env) {
  const origin = request.headers.get("origin");
  return allowedBrowserOrigin(origin, request.headers.get("referer"), env.APP_ORIGIN);
}

async function consumeAuthLimit(env: Env, request: Request, action: string, limit: number, windowMinutes: number, subject?: string) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const scope = subject ? `subject:${await hashToken(subject.trim().toLowerCase())}` : `ip:${await hashToken(ip)}`;
  const key = `${action}:${scope}`;
  await env.DB.prepare(`INSERT INTO auth_rate_limits (bucket_key, attempt_count, window_started_at) VALUES (?, 1, CURRENT_TIMESTAMP)
    ON CONFLICT(bucket_key) DO UPDATE SET attempt_count = CASE WHEN window_started_at <= datetime('now', ?) THEN 1 ELSE attempt_count + 1 END,
    window_started_at = CASE WHEN window_started_at <= datetime('now', ?) THEN CURRENT_TIMESTAMP ELSE window_started_at END`)
    .bind(key, `-${windowMinutes} minutes`, `-${windowMinutes} minutes`).run();
  const row = await env.DB.prepare(`SELECT attempt_count as count FROM auth_rate_limits WHERE bucket_key = ?`).bind(key).first<{ count: number }>();
  return (row?.count || 0) <= limit;
}

async function sendVerificationEmail(env: Env, email: string, fullName: string, token: string) {
  if (!env.BREVO_API_KEY) return false;
  const url = `${env.APP_ORIGIN}/?verify=${encodeURIComponent(token)}`;
  const escapedName = fullName.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[char] || char);
  const configuredSender = env.EMAIL_SENDER || "Zyntris <no-reply@zyntris.org>";
  const senderMatch = configuredSender.match(/^\s*(.*?)\s*<([^<>]+)>\s*$/);
  const sender = senderMatch ? { name: senderMatch[1] || "Zyntris", email: senderMatch[2] } : { name: "Zyntris", email: configuredSender.trim() };
  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": env.BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      sender, to: [{ email, name: fullName }], subject: "Verify your Zyntris account",
      textContent: `Hello ${fullName}, verify your Zyntris account using this link: ${url}. This link expires in 24 hours.`,
      htmlContent: `<p>Hello ${escapedName},</p><p>Verify your Zyntris account to open your organization workspace.</p><p><a href="${url}">Verify email address</a></p><p>This link expires in 24 hours.</p>`,
    }),
  });
  return response.ok;
}

function brevoSender(env: Env) {
  const configuredSender = env.EMAIL_SENDER || "Zyntris <no-reply@zyntris.org>";
  const senderMatch = configuredSender.match(/^\s*(.*?)\s*<([^<>]+)>\s*$/);
  return senderMatch ? { name: senderMatch[1] || "Zyntris", email: senderMatch[2] } : { name: "Zyntris", email: configuredSender.trim() };
}

type InviteEmailResult = { accepted: true; messageId?: string } | { accepted: false; cause: "not_configured" | "provider_rejected" | "network_error"; status?: number };

async function sendEmployeeInviteEmail(env: Env, email: string, fullName: string, organizationName: string, token: string): Promise<InviteEmailResult> {
  if (!env.BREVO_API_KEY) return { accepted: false, cause: "not_configured" } as const;
  const url = `${env.APP_ORIGIN}/?invite=${encodeURIComponent(token)}`;
  const safe = (value: string) => value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[char] || char);
  try {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST", headers: { "api-key": env.BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ sender: brevoSender(env), to: [{ email, name: fullName }], subject: `You’re invited to ${organizationName} on Zyntris`,
        textContent: `Hello ${fullName}, ${organizationName} invited you to its Zyntris workspace. Set up your account here: ${url}. This link expires in 72 hours.`,
        htmlContent: `<p>Hello ${safe(fullName)},</p><p>${safe(organizationName)} invited you to its Zyntris workspace.</p><p><a href="${url}">Accept invitation and set up your account</a></p><p>This link expires in 72 hours.</p>` }),
    });
    const result = await response.json().catch(() => ({})) as { messageId?: string; code?: string; message?: string };
    if (!response.ok) {
      console.error("Brevo rejected an employee invitation", { status: response.status, code: result.code || "unknown", message: result.message?.slice(0, 240) || "No provider detail" });
      return { accepted: false, cause: "provider_rejected", status: response.status };
    }
    return { accepted: true, messageId: result.messageId };
  } catch (cause) {
    console.error("Brevo invitation request failed", cause instanceof Error ? cause.name : "Unknown network error");
    return { accepted: false, cause: "network_error" };
  }
}

function inviteDeliveryError(result: Exclude<InviteEmailResult, { accepted: true }>) {
  if (result.cause === "not_configured") return "Employee invitation email isn’t configured. Add BREVO_API_KEY to the Worker secrets.";
  if (result.cause === "network_error") return "Brevo could not be reached, so no invitation was sent. Please retry shortly.";
  if (result.status === 401 || result.status === 403) return "Brevo rejected its API key. Update BREVO_API_KEY in Cloudflare and try again.";
  if (result.status === 400) return "Brevo rejected the invitation. Verify the sender in Brevo and check the recipient address.";
  return `Brevo rejected the invitation (HTTP ${result.status || "unknown"}). Check the verified sender and domain authentication, then retry.`;
}

async function sendPasswordResetEmail(env: Env, email: string, fullName: string, organizationName: string, token: string) {
  if (!env.BREVO_API_KEY) return { accepted: false as const, message: "Password reset email is not configured. Contact Zyntris support." };
  const url = `${env.APP_ORIGIN}/?reset=${encodeURIComponent(token)}`;
  const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] || char);
  try {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": env.BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        sender: brevoSender(env), to: [{ email, name: fullName }], subject: "Reset your Zyntris password",
        textContent: `You requested a password reset for your ${organizationName} Zyntris account. Set a new password here: ${url}. This one-time link expires in 30 minutes. If you did not request this, you can ignore this email.`,
        htmlContent: `<p>Hello ${escapeHtml(fullName)},</p><p>You requested a password reset for your <strong>${escapeHtml(organizationName)}</strong> Zyntris account.</p><p><a href="${url}">Set a new password</a></p><p>This one-time link expires in 30 minutes. If you did not request this, you can ignore this email.</p>`,
      }),
    });
    if (response.ok) return { accepted: true as const };
    const result = await response.json().catch(() => ({})) as { code?: string; message?: string };
    console.error("Brevo rejected a platform password reset", { status: response.status, code: result.code || "unknown", message: result.message?.slice(0, 200) || "No provider detail" });
    if (response.status === 401 || response.status === 403) return { accepted: false as const, message: "Brevo rejected its API key. Update the BREVO_API_KEY Worker secret." };
    return { accepted: false as const, message: "Brevo did not accept the password reset email. Verify the sender and retry." };
  } catch (cause) {
    console.error("Brevo password-reset request failed", cause instanceof Error ? cause.name : "Unknown network error");
    return { accepted: false as const, message: "Zyntris could not reach Brevo. Retry after checking email service connectivity." };
  }
}

async function sendApprovalNotificationEmail(env: Env, email: string, fullName: string, organizationName: string, subject: string, message: string) {
  if (!env.BREVO_API_KEY) return false;
  const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[char] || char);
  const configuredSender = env.EMAIL_SENDER || "Zyntris <no-reply@zyntris.org>";
  const senderMatch = configuredSender.match(/^\s*(.*?)\s*<([^<>]+)>\s*$/);
  const sender = senderMatch ? { name: senderMatch[1] || "Zyntris", email: senderMatch[2] } : { name: "Zyntris", email: configuredSender.trim() };
  const safeName = escapeHtml(fullName);
  const safeOrganization = escapeHtml(organizationName);
  const safeMessage = escapeHtml(message);
  try {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": env.BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        sender,
        to: [{ email, name: fullName }],
        subject,
        textContent: `Hello ${fullName},\n\n${message}\n\nSign in to your ${organizationName} workspace: ${env.APP_ORIGIN}`,
        htmlContent: `<p>Hello ${safeName},</p><p>${safeMessage}</p><p>Sign in to your <strong>${safeOrganization}</strong> workspace to view the details.</p><p><a href="${env.APP_ORIGIN}">Open Zyntris</a></p>`,
      }),
    });
    if (!response.ok) console.warn("Brevo rejected an approval notification", response.status);
    return response.ok;
  } catch (cause) {
    console.warn("Could not deliver an approval notification", cause);
    return false;
  }
}

async function sendMobilePush(env: Env, organizationId: string, userId: string, title: string, body: string) {
  const tokens = await env.DB.prepare(`SELECT token FROM mobile_push_tokens WHERE organization_id = ? AND user_id = ?`).bind(organizationId, userId).all<{ token: string }>();
  if (!tokens.results?.length) return;
  const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json" };
  if (env.EXPO_ACCESS_TOKEN) headers.authorization = `Bearer ${env.EXPO_ACCESS_TOKEN}`;
  try {
    const response = await fetch("https://exp.host/--/api/v2/push/send", { method: "POST", headers, body: JSON.stringify(tokens.results.map(({ token }) => ({ to: token, title: title.slice(0, 100), body: body.slice(0, 500), sound: "default", channelId: "default", priority: "high" }))) });
    if (!response.ok) console.warn("Expo push service rejected a notification", response.status);
  } catch (cause) { console.warn("Could not send Expo push notification", cause instanceof Error ? cause.name : "unknown"); }
}

async function notifyApprovers(env: Env, context: AuthContext, requiredRole: string, title: string, body: string) {
  const organization = await env.DB.prepare(`SELECT name FROM organizations WHERE id = ?`).bind(context.organizationId).first<{ name: string }>();
  const requester = await env.DB.prepare(`SELECT full_name as fullName FROM users WHERE id = ?`).bind(context.userId).first<{ fullName: string }>();
  const approvers = await env.DB.prepare(`SELECT DISTINCT u.id, u.email, u.full_name as fullName FROM memberships m JOIN users u ON u.id = m.user_id JOIN roles r ON r.id = m.role_id WHERE m.organization_id = ? AND r.name = ? AND m.status = 'active' AND u.status = 'active' AND u.email_verified_at IS NOT NULL`).bind(context.organizationId, requiredRole).all<{ id: string; email: string; fullName: string }>();
  const targets = approvers.results || [];
  if (!targets.length) {
    const admins = await env.DB.prepare(`SELECT DISTINCT u.id, u.email, u.full_name as fullName FROM memberships m JOIN users u ON u.id = m.user_id JOIN roles r ON r.id = m.role_id WHERE m.organization_id = ? AND r.name = 'Organization Admin' AND m.status = 'active' AND u.status = 'active' AND u.email_verified_at IS NOT NULL`).bind(context.organizationId).all<{ id: string; email: string; fullName: string }>();
    const alert = `No active ${requiredRole} approver is assigned. Assign an approver to review ${title}.`;
    const adminStatements = (admins.results || []).map((admin) => env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'approval_setup', ?, ?)`).bind(requestId(), context.organizationId, admin.id, `${requiredRole} approval needs setup`, alert));
    if (adminStatements.length) await env.DB.batch(adminStatements);
    if (organization) await Promise.all((admins.results || []).map((admin) => sendApprovalNotificationEmail(env, admin.email, admin.fullName, organization.name, `${requiredRole} approval routing needs setup`, alert)));
    return;
  }
  const details = `${requester?.fullName || "A team member"} submitted “${title.replace(/[\r\n]+/g, " ").slice(0, 120)}”. ${body.slice(0, 1800)}`;
  const subjectTitle = title.replace(/[\r\n]+/g, " ").slice(0, 120);
  await env.DB.batch(targets.map((approver) => env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'approval_pending', ?, ?)`).bind(requestId(), context.organizationId, approver.id, "Approval pending", details)));
  await Promise.all(targets.map((approver) => sendMobilePush(env, context.organizationId, approver.id, "Approval pending", `${subjectTitle}: ${details}`)));
  if (organization) await Promise.all(targets.map((approver) => sendApprovalNotificationEmail(env, approver.email, approver.fullName, organization.name, `Approval pending: ${subjectTitle}`, details)));
}

async function handlePublicAuth(request: Request, env: Env, path: string, mobile = false): Promise<Response | null> {
  if (request.method === "GET" && path === "/api/auth/config") return json({ emailVerificationEnabled: Boolean(env.BREVO_API_KEY), demoEnabled: Boolean(env.DEMO_ACCESS_PASSWORD) });
  if (request.method === "POST" && path === "/api/auth/accept-invite") {
    if (!originAllowed(request, env)) return error("Request origin rejected", 403);
    if (!env.PASSWORD_PEPPER) return error("Secure password setup is temporarily unavailable. Contact Zyntris support.", 503);
    if (!(await consumeAuthLimit(env, request, "accept-invite", 10, 30))) return error("Too many attempts. Try again later.", 429);
    const body = await request.json<{ token?: string; password?: string }>();
    if (!body.token || body.token.length !== 64 || !body.password || body.password.length < 12 || body.password.length > 128) return error("Use a valid invitation and a password of at least 12 characters.");
    const invite = await env.DB.prepare(`SELECT i.id as inviteId, i.user_id as userId, i.organization_id as organizationId, i.employee_id as employeeId FROM employee_invites i JOIN users u ON u.id = i.user_id AND u.status = 'invited' JOIN employees e ON e.id = i.employee_id AND e.onboarding_status = 'invited' WHERE i.token_hash = ? AND i.accepted_at IS NULL AND i.expires_at > CURRENT_TIMESTAMP LIMIT 1`).bind(await hashToken(body.token)).first<{ inviteId: string; userId: string; organizationId: string; employeeId: string }>();
    if (!invite) return error("This invitation is invalid, expired, or already used.", 400);
    const inviteAccessError = await workspaceAccessError(env, invite.organizationId);
    if (inviteAccessError) return error(inviteAccessError, 403);
    const claimedInvite = await env.DB.prepare(`UPDATE employee_invites SET accepted_at = CURRENT_TIMESTAMP WHERE id = ? AND accepted_at IS NULL AND expires_at > CURRENT_TIMESTAMP`).bind(invite.inviteId).run();
    if (!claimedInvite.meta.changes) return error("This invitation has already been used.", 409);
    await env.DB.batch([
      env.DB.prepare(`UPDATE users SET password_hash = ?, status = 'active', email_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(await passwordHash(body.password, env.PASSWORD_PEPPER), invite.userId),
      env.DB.prepare(`UPDATE memberships SET status = 'active' WHERE user_id = ? AND organization_id = ?`).bind(invite.userId, invite.organizationId),
      env.DB.prepare(`UPDATE employees SET onboarding_status = 'active', status = 'active', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(invite.employeeId, invite.organizationId),
      env.DB.prepare(`INSERT INTO audit_logs (id, organization_id, actor_user_id, action, module, record_type, record_id) VALUES (?, ?, ?, 'accepted_invitation', 'hr', 'employee', ?)`).bind(`audit-${crypto.randomUUID()}`, invite.organizationId, invite.userId, invite.employeeId),
    ]);
    const session = await createSession(env, invite.userId, invite.organizationId);
    return cookieResponse({ ok: true }, session);
  }
  if (request.method === "POST" && path === "/api/auth/demo") {
    if (!originAllowed(request, env)) return error("Request origin rejected", 403);
    if (!env.DEMO_ACCESS_PASSWORD) return error("The demo sandbox is not enabled yet.", 503);
    if (!(await consumeAuthLimit(env, request, "demo", 10, 15))) return error("Too many demo sign-in attempts. Try again later.", 429);
    const body = await request.json<{ password?: string }>();
    if (!body.password || !safeEqual(body.password, env.DEMO_ACCESS_PASSWORD)) return error("The demo password is incorrect.", 401);
    const demo = await env.DB.prepare(`SELECT m.user_id as userId, m.organization_id as organizationId FROM memberships m JOIN users u ON u.id = m.user_id AND u.email_verified_at IS NOT NULL AND u.status = 'active' JOIN organizations o ON o.id = m.organization_id AND o.is_demo = 1 AND o.status != 'suspended' JOIN subscriptions s ON s.organization_id = o.id AND s.status = 'active' WHERE m.user_id = 'usr-zyntris-demo' AND m.status = 'active' LIMIT 1`).first<{ userId: string; organizationId: string }>();
    if (!demo) return error("The demo workspace is unavailable. Contact Zyntris support.", 503);
    const session = await createSession(env, demo.userId, demo.organizationId, true);
    return cookieResponse({ ok: true, demo: true }, session);
  }
  if (request.method === "POST" && path === "/api/auth/register") {
    if (!originAllowed(request, env)) return error("Request origin rejected", 403);
    if (!env.PASSWORD_PEPPER) return error("Secure account setup is temporarily unavailable. Contact Zyntris support.", 503);
    if (!env.BREVO_API_KEY) return error("Email verification is not configured yet. Contact Zyntris support to finish account setup.", 503);
    if (!(await consumeAuthLimit(env, request, "register", 8, 60))) return error("Too many signup attempts. Try again later.", 429);
    const body = await request.json<{ organizationName?: string; industry?: string; fullName?: string; email?: string; password?: string }>();
    const organizationName = body.organizationName?.trim();
    const fullName = body.fullName?.trim();
    const email = body.email?.trim().toLowerCase();
    const password = body.password || "";
    if (!organizationName || organizationName.length < 2 || organizationName.length > 120 || !fullName || fullName.length < 2 || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12 || password.length > 128) {
      return error("Enter an organization name, full name, valid email, and password of at least 12 characters.");
    }
    if (await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first()) return error("An account with this email already exists. Sign in or contact support.", 409);
    const userId = `usr-${crypto.randomUUID()}`;
    const orgId = `org-${crypto.randomUUID()}`;
    const roleId = `role-${crypto.randomUUID()}`;
    const subscriptionId = `sub-${crypto.randomUUID()}`;
    const hrRoleId = `role-${crypto.randomUUID()}`;
    const ceoRoleId = `role-${crypto.randomUUID()}`;
    const financeRoleId = `role-${crypto.randomUUID()}`;
    const managerRoleId = `role-${crypto.randomUUID()}`;
    const employeeRoleId = `role-${crypto.randomUUID()}`;
    const crmAdminRoleId = `role-${crypto.randomUUID()}`, salesManagerRoleId = `role-${crypto.randomUUID()}`, salesRepRoleId = `role-${crypto.randomUUID()}`, crmExecutiveRoleId = `role-${crypto.randomUUID()}`, crmViewerRoleId = `role-${crypto.randomUUID()}`;
    const projectManagerRoleId = `role-${crypto.randomUUID()}`, projectMemberRoleId = `role-${crypto.randomUUID()}`, portfolioManagerRoleId = `role-${crypto.randomUUID()}`;
    const slug = `${organizationName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "organization"}-${orgId.slice(-8)}`;
    const token = randomToken();
    const now = new Date();
    try {
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO organizations (id, name, slug, industry, status) VALUES (?, ?, ?, ?, 'trial')`).bind(orgId, organizationName, slug, body.industry?.trim() || null),
        env.DB.prepare(`INSERT INTO organization_modules (organization_id,module_key,enabled,features_json) VALUES (?,'projects',1,'{"portfolios":true,"programmes":true,"gantt":true,"timesheets":true,"budgets":true,"risks":true,"change_control":true,"meetings":true,"templates":true,"client_portal":true,"advanced_reports":true,"ai":false}'),(?,'crm',1,'{}'),(?,'hr',1,'{}'),(?,'payroll',1,'{}'),(?,'finance',1,'{}'),(?,'operations',1,'{}'),(?,'reports',1,'{}')`).bind(orgId,orgId,orgId,orgId,orgId,orgId,orgId),
        env.DB.prepare(`WITH sources(name) AS (VALUES ('Website'),('Referral'),('Social Media'),('LinkedIn'),('Event'),('Webinar'),('Advertisement'),('Email Campaign'),('Direct Outreach'),('Partner'),('Existing Customer'),('Walk-in'),('Other')) INSERT INTO crm_lead_sources (id,organization_id,name) SELECT 'crm-source-' || ? || '-' || lower(replace(name,' ','-')), ?, name FROM sources`).bind(orgId,orgId),
        env.DB.prepare(`INSERT INTO crm_pipeline_stages (id,organization_id,stage_key,name,probability,sort_order) VALUES ('crm-stage-' || ? || '-qualification',?,'qualification','Qualification',10,1),('crm-stage-' || ? || '-discovery',?,'discovery','Discovery',25,2),('crm-stage-' || ? || '-proposal',?,'proposal','Proposal',50,3),('crm-stage-' || ? || '-negotiation',?,'negotiation','Negotiation',75,4),('crm-stage-' || ? || '-won',?,'won','Won',100,5),('crm-stage-' || ? || '-lost',?,'lost','Lost',0,6)`).bind(orgId,orgId,orgId,orgId,orgId,orgId,orgId,orgId,orgId,orgId,orgId,orgId),
        env.DB.prepare(`INSERT INTO organization_settings (organization_id) VALUES (?)`).bind(orgId),
        env.DB.prepare(`INSERT INTO tenant_backup_settings (organization_id, enabled, frequency, retention_days, alert_email) VALUES (?, 1, 'daily', 30, ?)`).bind(orgId, email),
        env.DB.prepare(`INSERT INTO users (id, email, full_name, password_hash, status) VALUES (?, ?, ?, ?, 'active')`).bind(userId, email, fullName, await passwordHash(password, env.PASSWORD_PEPPER)),
        env.DB.prepare(`INSERT INTO roles (id, organization_id, name, description, is_system) VALUES (?, ?, 'Organization Admin', 'Organization owner and administrator', 1)`).bind(roleId, orgId),
        env.DB.prepare(`INSERT INTO roles (id, organization_id, name, description, is_system) VALUES (?, ?, 'HR Admin', 'Manage people, teams and onboarding', 1)`).bind(hrRoleId, orgId),
        env.DB.prepare(`INSERT INTO roles (id, organization_id, name, description, is_system) VALUES (?, ?, 'CEO', 'Executive review and final approvals', 1)`).bind(ceoRoleId, orgId),
        env.DB.prepare(`INSERT INTO roles (id, organization_id, name, description, is_system) VALUES (?, ?, 'Finance Admin', 'Manage finance operations and approvals', 1)`).bind(financeRoleId, orgId),
        env.DB.prepare(`INSERT INTO roles (id, organization_id, name, description, is_system) VALUES (?, ?, 'Manager', 'Manage team work and submit approvals', 1)`).bind(managerRoleId, orgId),
        env.DB.prepare(`INSERT INTO roles (id, organization_id, name, description, is_system) VALUES (?, ?, 'Employee', 'Standard employee workspace access', 1)`).bind(employeeRoleId, orgId),
        ...[[crmAdminRoleId,"CRM Admin","Configure CRM and manage organization CRM data"],[salesManagerRoleId,"Sales Manager","Manage organization sales pipeline and CRM reporting"],[salesRepRoleId,"Sales Representative","Manage assigned leads, opportunities and activities"],[crmExecutiveRoleId,"CRM Executive","View organization-wide CRM performance and reports"],[crmViewerRoleId,"CRM Viewer","Read authorized CRM records"],[projectManagerRoleId,"Project Manager","Manage assigned project delivery"],[projectMemberRoleId,"Project Member","Contribute to assigned project work"],[portfolioManagerRoleId,"Portfolio Manager","Manage portfolios and project reporting"]].map(([id,name,description])=>env.DB.prepare(`INSERT INTO roles (id,organization_id,name,description,is_system) VALUES (?,?,?,?,1)`).bind(id,orgId,name,description)),
        env.DB.prepare(`INSERT INTO memberships (id, organization_id, user_id, role_id) VALUES (?, ?, ?, ?)`).bind(`mem-${crypto.randomUUID()}`, orgId, userId, roleId),
        env.DB.prepare(`INSERT INTO subscriptions (id, organization_id, plan, status, employee_limit, trial_ends_at) VALUES (?, ?, 'business', 'trialing', 100, NULL)`).bind(subscriptionId, orgId),
        env.DB.prepare(`INSERT INTO payroll_settings (organization_id, currency, tax_year) VALUES (?, 'NGN', ?)`).bind(orgId, now.getUTCFullYear()),
        env.DB.prepare(`INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now', '+24 hours'))`).bind(`evt-${crypto.randomUUID()}`, userId, await hashToken(token)),
        env.DB.prepare(`INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions`).bind(roleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE code IN ('employees.view','employees.manage','payroll.view','payroll.manage','payroll.run','hr.onboarding.approve','roles.manage','teams.manage','requests.manage','operations.view','goals.view','goals.manage','announcements.view','announcements.manage')`).bind(hrRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE code IN ('employees.view','payroll.view','payroll.approve','requests.manage','hr.onboarding.approve','operations.view','operations.manage','expenses.view','expenses.manage','goals.view','goals.manage','announcements.view','announcements.manage')`).bind(ceoRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE code IN ('payroll.view','payroll.run','payroll.approve','expenses.view','expenses.manage','requests.manage','operations.view','operations.manage','goals.view','announcements.view')`).bind(financeRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE code IN ('employees.view','operations.view','expenses.view','payroll.self.view','goals.view','announcements.view')`).bind(employeeRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE code IN ('employees.view','operations.view','operations.manage','expenses.view','requests.manage','payroll.self.view','goals.view','goals.manage','announcements.view')`).bind(managerRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id,permission_id) SELECT ?,id FROM permissions WHERE code IN ('crm.view','crm.view.all','crm.manage','crm.assign','crm.configure','crm.report','crm.quotes.manage','crm.import')`).bind(crmAdminRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id,permission_id) SELECT ?,id FROM permissions WHERE code IN ('crm.view','crm.view.all','crm.manage','crm.assign','crm.report','crm.quotes.manage','crm.import')`).bind(salesManagerRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id,permission_id) SELECT ?,id FROM permissions WHERE code IN ('crm.view','crm.manage')`).bind(salesRepRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id,permission_id) SELECT ?,id FROM permissions WHERE code IN ('crm.view','crm.view.all','crm.report')`).bind(crmExecutiveRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id,permission_id) SELECT ?,id FROM permissions WHERE code='crm.view'`).bind(crmViewerRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id,permission_id) SELECT ?,id FROM permissions WHERE code IN ('projects.view','projects.view.all','projects.create','projects.edit','projects.manage','projects.approve','projects.close','projects.reports','projects.client_portal.manage','timesheets.approve','risks.manage')`).bind(projectManagerRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id,permission_id) SELECT ?,id FROM permissions WHERE code='projects.view'`).bind(projectMemberRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id,permission_id) SELECT ?,id FROM permissions WHERE code IN ('projects.view','projects.view.all','projects.create','projects.edit','projects.manage','projects.approve','projects.reports','timesheets.approve','risks.manage')`).bind(portfolioManagerRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id,permission_id) SELECT ?,id FROM permissions WHERE code IN ('crm.view','crm.view.all','crm.report','projects.view','projects.view.all','projects.create','projects.edit','projects.manage','projects.approve','projects.reports','timesheets.approve','risks.manage')`).bind(ceoRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id,permission_id) SELECT ?,id FROM permissions WHERE code IN ('projects.view','projects.view.all','projects.create','projects.edit','projects.manage','projects.approve','projects.close','projects.reports','timesheets.approve','risks.manage')`).bind(managerRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id,permission_id) SELECT ?,id FROM permissions WHERE code='projects.view'`).bind(employeeRoleId),
        env.DB.prepare(`INSERT INTO audit_logs (id, organization_id, actor_user_id, action, module, record_type, record_id, new_value_json) VALUES (?, ?, ?, 'created', 'organization', 'organization', ?, ?)`).bind(`audit-${crypto.randomUUID()}`, orgId, userId, orgId, JSON.stringify({ industry: body.industry?.trim() || null, onboardingStatus: "email_verification_pending" })),
      ]);
    } catch (cause) {
      console.error("Signup persistence failed", cause);
      return error("Unable to create the workspace. Please try again.", 500);
    }
    try {
      if (!(await sendVerificationEmail(env, email, fullName, token))) throw new Error("Verification email provider rejected the message");
    } catch (cause) {
      console.error("Signup verification delivery failed", cause);
      await env.DB.prepare(`DELETE FROM organizations WHERE id = ?`).bind(orgId).run();
      await env.DB.prepare(`DELETE FROM users WHERE id = ?`).bind(userId).run();
      return error("We could not send your verification email. Please try again shortly.", 503);
    }
    return json({ ok: true, verificationRequired: true, email }, { status: 201 });
  }
  if (request.method === "POST" && path === "/api/auth/verify") {
    if (!originAllowed(request, env)) return error("Request origin rejected", 403);
    const body = await request.json<{ token?: string }>();
    if (!body.token || body.token.length !== 64) return error("Verification link is invalid or expired", 400);
    const row = await env.DB.prepare(`SELECT v.id as tokenId, v.user_id as userId, m.organization_id as organizationId FROM email_verification_tokens v JOIN users u ON u.id = v.user_id JOIN memberships m ON m.user_id = u.id WHERE v.token_hash = ? AND v.used_at IS NULL AND v.expires_at > CURRENT_TIMESTAMP AND u.email_verified_at IS NULL LIMIT 1`).bind(await hashToken(body.token)).first<{ tokenId: string; userId: string; organizationId: string }>();
    if (!row) return error("Verification link is invalid or expired", 400);
    await env.DB.batch([
      env.DB.prepare(`UPDATE users SET email_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(row.userId),
      env.DB.prepare(`UPDATE email_verification_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(row.tokenId),
      env.DB.prepare(`UPDATE subscriptions SET trial_ends_at = datetime('now', '+15 days') WHERE organization_id = ? AND status = 'trialing' AND trial_ends_at IS NULL`).bind(row.organizationId),
    ]);
    const session = await createSession(env, row.userId, row.organizationId);
    return cookieResponse({ ok: true }, session);
  }
  if (request.method === "POST" && path === "/api/auth/request-password-reset") {
    if (!mobile && !originAllowed(request, env)) return error("Request origin rejected", 403);
    if (!env.PASSWORD_PEPPER) return error("Secure password recovery is temporarily unavailable. Contact your administrator.", 503);
    if (!(await consumeAuthLimit(env, request, "forgot-password", 5, 30))) return error("Too many password reset requests. Try again later.", 429);
    const body = await request.json<{ email?: string }>();
    const email = body.email?.trim().toLowerCase();
    if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return error("Enter a valid email address.");
    if (!(await consumeAuthLimit(env, request, "forgot-password", 3, 60, email))) return error("Too many password reset requests. Try again later.", 429);
    const user = await env.DB.prepare(`SELECT u.id as userId, u.email, u.full_name as fullName, m.organization_id as organizationId, o.name as organizationName FROM users u JOIN memberships m ON m.user_id = u.id JOIN organizations o ON o.id = m.organization_id WHERE lower(u.email) = ? AND u.status = 'active' AND m.status = 'active' ORDER BY m.created_at LIMIT 1`).bind(email).first<{ userId: string; email: string; fullName: string; organizationId: string; organizationName: string }>();
    if (user) {
      const token = [...crypto.getRandomValues(new Uint8Array(32))].map((byte) => byte.toString(16).padStart(2, "0")).join("");
      const tokenId = `reset-${crypto.randomUUID()}`;
      await env.DB.prepare(`DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL`).bind(user.userId).run();
      await env.DB.prepare(`INSERT INTO password_reset_tokens (id, user_id, organization_id, token_hash, expires_at) VALUES (?, ?, ?, ?, datetime('now', '+30 minutes'))`).bind(tokenId, user.userId, user.organizationId, await hashToken(token)).run();
      const delivered = await sendPasswordResetEmail(env, user.email, user.fullName, user.organizationName, token);
      if (!delivered.accepted) {
        await env.DB.prepare(`DELETE FROM password_reset_tokens WHERE id = ?`).bind(tokenId).run();
        console.warn("Self-service password reset email could not be delivered", delivered.message);
      } else {
        await env.DB.prepare(`INSERT INTO audit_logs (id, organization_id, actor_user_id, action, module, record_type, record_id) VALUES (?, ?, NULL, 'password_reset_requested', 'authentication', 'user', ?)`).bind(`audit-${crypto.randomUUID()}`, user.organizationId, user.userId).run();
      }
    }
    return json({ ok: true });
  }
  if (request.method === "POST" && path === "/api/auth/reset-password") {
    if (!mobile && !originAllowed(request, env)) return error("Request origin rejected", 403);
    if (!env.PASSWORD_PEPPER) return error("Secure password reset is temporarily unavailable. Contact your administrator.", 503);
    if (!(await consumeAuthLimit(env, request, "reset-password", 10, 30))) return error("Too many password reset attempts. Try again later.", 429);
    const body = await request.json<{ token?: string; password?: string }>();
    if (!body.token || body.token.length !== 64 || !body.password || body.password.length < 12 || body.password.length > 128) return error("Use a valid reset link and a password of at least 12 characters.");
    const reset = await env.DB.prepare(`SELECT id, user_id as userId FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP LIMIT 1`).bind(await hashToken(body.token)).first<{ id: string; userId: string }>();
    if (!reset) return error("This password reset link is invalid, expired, or already used. Ask the platform administrator to send a new one.", 400);
    const claimId = requestId();
    const claimed = await env.DB.prepare(`UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP, claim_id = ? WHERE id = ? AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP`).bind(claimId, reset.id).run();
    if (!claimed.meta.changes) return error("This password reset link has already been used. Ask the platform administrator to send a new one.", 409);
    const saved = await env.DB.prepare(`UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'active'`).bind(await passwordHash(body.password, env.PASSWORD_PEPPER), reset.userId).run();
    if (!saved.meta.changes) return error("This account cannot reset its password. Contact your organization administrator.", 409);
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(reset.userId),
      env.DB.prepare(`DELETE FROM two_factor_challenges WHERE user_id = ?`).bind(reset.userId),
      env.DB.prepare(`DELETE FROM password_reset_tokens WHERE user_id = ? AND id != ?`).bind(reset.userId, reset.id),
      env.DB.prepare(`INSERT INTO audit_logs (id, organization_id, actor_user_id, action, module, record_type, record_id) SELECT ?, organization_id, NULL, 'password_reset_completed', 'authentication', 'user', ? FROM password_reset_tokens WHERE id = ? AND claim_id = ?`).bind(`audit-${crypto.randomUUID()}`, reset.userId, reset.id, claimId),
    ]);
    return json({ ok: true });
  }
  if (request.method === "POST" && path === "/api/auth/2fa/verify") {
    if (!mobile && !originAllowed(request, env)) return error("Request origin rejected", 403);
    if (!(await consumeAuthLimit(env, request, "2fa-verify", 12, 15))) return error("Too many verification attempts. Try again later.", 429);
    const body = await request.json<{ challengeToken?: string; code?: string }>();
    if (!body.challengeToken || body.challengeToken.length !== 64 || !body.code || body.code.length > 32) return error("Enter your six-digit authenticator code or a recovery code.");
    const challenge = await env.DB.prepare(`SELECT id, user_id as userId, organization_id as organizationId, is_mobile as isMobile, attempts FROM two_factor_challenges WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP LIMIT 1`)
      .bind(await hashToken(body.challengeToken)).first<{ id: string; userId: string; organizationId: string; isMobile: number; attempts: number }>();
    if (!challenge || challenge.isMobile !== (mobile ? 1 : 0)) return error("This sign-in challenge is invalid or expired. Sign in again.", 401);
    const challengeAccessError = await workspaceAccessError(env, challenge.organizationId);
    if (challengeAccessError) { await env.DB.prepare(`DELETE FROM two_factor_challenges WHERE id = ?`).bind(challenge.id).run(); return error(challengeAccessError, 403); }
    if (challenge.attempts >= 5) { await env.DB.prepare(`DELETE FROM two_factor_challenges WHERE id = ?`).bind(challenge.id).run(); return error("Too many incorrect codes. Sign in again.", 429); }
    const factor = await env.DB.prepare(`SELECT secret_enc as secretEnc, enabled_at as enabledAt, last_counter as lastCounter FROM user_two_factor WHERE user_id = ?`).bind(challenge.userId).first<{ secretEnc: string | null; enabledAt: string | null; lastCounter: number }>();
    let valid = false;
    if (factor?.enabledAt && factor.secretEnc && /^\d{6}$/.test(body.code.replace(/\s+/g, ""))) {
      const counter = await matchTotp(await decryptTwoFactorSecret(env, factor.secretEnc), body.code);
      if (counter !== null && counter > factor.lastCounter) {
        const saved = await env.DB.prepare(`UPDATE user_two_factor SET last_counter = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND last_counter < ? AND enabled_at IS NOT NULL`).bind(counter, challenge.userId, counter).run();
        valid = saved.meta.changes > 0;
      }
    } else if (factor?.enabledAt && !/^\d{6}$/.test(body.code.replace(/\s+/g, ""))) {
      const normalized = body.code.replace(/-/g, "").trim().toLowerCase();
      if (/^[a-f0-9]{10}$/.test(normalized)) {
        const recovery = await env.DB.prepare(`UPDATE two_factor_recovery_codes SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`).bind(challenge.userId, await hashToken(normalized)).run();
        valid = recovery.meta.changes > 0;
      }
    }
    if (!valid) {
      await env.DB.prepare(`UPDATE two_factor_challenges SET attempts = attempts + 1 WHERE id = ?`).bind(challenge.id).run();
      return error("The verification code is incorrect or has already been used.", 401);
    }
    await env.DB.prepare(`DELETE FROM two_factor_challenges WHERE id = ?`).bind(challenge.id).run();
    await env.DB.prepare(`INSERT INTO audit_logs (id, organization_id, actor_user_id, action, module, record_type) VALUES (?, ?, ?, 'signed_in_with_two_factor', 'authentication', ?)`)
      .bind(`audit-${crypto.randomUUID()}`, challenge.organizationId, challenge.userId, mobile ? "mobile_session" : "session").run();
    const session = await createSession(env, challenge.userId, challenge.organizationId);
    return mobile ? json({ accessToken: session, tokenType: "Bearer", expiresIn: 43200 }) : cookieResponse({ ok: true }, session);
  }
  if (request.method === "POST" && path === "/api/auth/login") {
    if (!originAllowed(request, env)) return error("Request origin rejected", 403);
    if (!(await consumeAuthLimit(env, request, "login", 20, 15))) return error("Too many sign-in attempts. Try again later.", 429);
    const body = await request.json<{ email?: string; password?: string }>();
    const email = body.email?.trim().toLowerCase() || "";
    if (email && !(await consumeAuthLimit(env, request, "login", 8, 15, email))) return error("Too many sign-in attempts. Try again later.", 429);
    const user = await env.DB.prepare(`SELECT id, password_hash as passwordHash, email_verified_at as verifiedAt, status FROM users WHERE email = ?`).bind(email).first<{ id: string; passwordHash: string | null; verifiedAt: string | null; status: string }>();
    if (!user?.passwordHash || user.status !== "active" || !(await verifyPassword(body.password || "", user.passwordHash, env.PASSWORD_PEPPER))) return error("Email or password is incorrect.", 401);
    await upgradeLegacyPassword(env, user.id, body.password || "", user.passwordHash);
    if (!user.verifiedAt) return error("Please verify your email address before signing in.", 403);
    const membership = await env.DB.prepare(`SELECT organization_id as organizationId FROM memberships WHERE user_id = ? AND status = 'active' ORDER BY created_at LIMIT 1`).bind(user.id).first<{ organizationId: string }>();
    if (!membership) return error("No active organization is linked to this account.", 403);
    const accessError = await workspaceAccessError(env, membership.organizationId);
    if (accessError) return error(accessError, 403);
    const factor = await env.DB.prepare(`SELECT enabled_at as enabledAt FROM user_two_factor WHERE user_id = ?`).bind(user.id).first<{ enabledAt: string | null }>();
    if (factor?.enabledAt) return issueTwoFactorChallenge(env, user.id, membership.organizationId, false);
    await env.DB.prepare(`INSERT INTO audit_logs (id, organization_id, actor_user_id, action, module, record_type) VALUES (?, ?, ?, 'signed_in', 'authentication', 'session')`)
      .bind(`audit-${crypto.randomUUID()}`, membership.organizationId, user.id).run();
    const session = await createSession(env, user.id, membership.organizationId);
    return cookieResponse({ ok: true }, session);
  }
  return null;
}

async function requireAuth(request: Request, env: Env) {
  const context = await auth(request, env);
  if (!context) return { response: error("Authentication required", 401) } as const;
  return { context } as const;
}

async function audit(env: Env, context: AuthContext, action: string, module: string, recordId?: string, newValue?: unknown, previousValue?: unknown) {
  await env.DB.prepare(`INSERT INTO audit_logs (id, organization_id, actor_user_id, action, module, record_id, previous_value_json, new_value_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(requestId(), context.organizationId, context.userId, action, module, recordId || null, previousValue ? JSON.stringify(previousValue) : null, newValue ? JSON.stringify(newValue) : null).run();
}

async function recordCrmEvent(env: Env, context: AuthContext, eventType: string, entityType: string, entityId: string, payload: unknown) {
  await env.DB.prepare(`INSERT INTO crm_events (id, organization_id, event_type, entity_type, entity_id, payload_json) VALUES (?, ?, ?, ?, ?, ?)`).bind(requestId(), context.organizationId, eventType, entityType, entityId, JSON.stringify(payload)).run();
}

async function evaluateCrmLead(env: Env, organizationId: string, lead: Record<string, unknown>) {
  const rules=await env.DB.prepare(`SELECT factor_key as factorKey,points,condition_json as conditionJson FROM crm_scoring_rules WHERE organization_id=? AND active=1`).bind(organizationId).all<{factorKey:string;points:number;conditionJson:string}>();
  let score=0;
  for(const rule of rules.results||[]){
    let condition:Record<string,unknown>={};try{condition=JSON.parse(rule.conditionJson||"{}");}catch{continue;}
    const value=lead[rule.factorKey];let matches=false;
    if(rule.factorKey.startsWith("has_"))matches=Boolean(value);
    else if(condition.equals!==undefined)matches=String(value||"").toLowerCase()===String(condition.equals).toLowerCase();
    else if(condition.contains!==undefined)matches=String(value||"").toLowerCase().includes(String(condition.contains).toLowerCase());
    else if(condition.min!==undefined)matches=Number(value||0)>=Number(condition.min);
    else matches=Boolean(value);
    if(matches)score+=rule.points;
  }
  score=Math.min(100,Math.max(0,score));return {score,temperature:score>=70?"hot":score>=40?"warm":"cold"};
}

function validAppraisalReview(body: Record<string, unknown>) {
  const overallRating = Number(body.overallRating);
  const goals = Array.isArray(body.goals) ? body.goals as Array<Record<string, unknown>> : [];
  const competencies = Array.isArray(body.competencies) ? body.competencies as Array<Record<string, unknown>> : [];
  const kpiScores = Array.isArray(body.kpiScores) ? body.kpiScores as Array<Record<string, unknown>> : [];
  const validRating = (value: unknown) => Number.isInteger(Number(value)) && Number(value) >= 1 && Number(value) <= 5;
  if (!validRating(overallRating) || typeof body.summary !== "string" || !body.summary.trim() || body.summary.length > 4000 || typeof body.strengths !== "string" || typeof body.developmentPlan !== "string") return null;
  if (goals.length > 12 || competencies.length > 12 || goals.some((goal) => typeof goal.title !== "string" || !goal.title.trim() || goal.title.length > 250 || typeof goal.successMeasure !== "string" || !validRating(goal.rating) || typeof goal.result !== "string") || competencies.some((item) => typeof item.name !== "string" || !item.name.trim() || item.name.length > 160 || !validRating(item.rating) || typeof item.comments !== "string")) return null;
  if (kpiScores.length > 100 || kpiScores.some((score) => typeof score.kpiId !== "string" || !validRating(score.rating) || typeof score.evidence !== "string" || typeof score.comment !== "string")) return null;
  return { overallRating, summary: body.summary.trim(), strengths: body.strengths.slice(0, 4000), developmentPlan: body.developmentPlan.slice(0, 4000), recommendation: typeof body.recommendation === "string" ? body.recommendation.slice(0, 4000) : "", goals, competencies, kpiScores };
}

async function saveAppraisalKpiScores(env: Env, context: AuthContext, appraisalId: string, scores: Array<Record<string, unknown>>, side: "self" | "manager") {
  const assigned = await env.DB.prepare(`SELECT kpi_id as kpiId FROM appraisal_kpi_scores WHERE organization_id = ? AND appraisal_id = ?`).bind(context.organizationId, appraisalId).all<{ kpiId: string }>();
  if ((assigned.results || []).length !== scores.length || new Set(scores.map((score) => score.kpiId)).size !== scores.length || (assigned.results || []).some((row) => !scores.some((score) => score.kpiId === row.kpiId))) return false;
  if (!scores.length) return true;
  await env.DB.batch(scores.map((score) => side === "self"
    ? env.DB.prepare(`UPDATE appraisal_kpi_scores SET self_rating = ?, self_result = ? WHERE organization_id = ? AND appraisal_id = ? AND kpi_id = ?`).bind(Number(score.rating), String(score.evidence).slice(0, 2000), context.organizationId, appraisalId, score.kpiId)
    : env.DB.prepare(`UPDATE appraisal_kpi_scores SET manager_rating = ?, manager_comment = ? WHERE organization_id = ? AND appraisal_id = ? AND kpi_id = ?`).bind(Number(score.rating), String(score.comment).slice(0, 2000), context.organizationId, appraisalId, score.kpiId)));
  return true;
}

async function handleAppraisals(request: Request, env: Env, context: AuthContext, path: string): Promise<Response | null> {
  const canManage = hasPermission(context, "appraisals.manage");
  const canReview = hasPermission(context, "appraisals.view");
  const canSelfReview = hasPermission(context, "appraisals.self.view");
  if (!path.startsWith("/api/appraisals") && !path.startsWith("/api/appraisal-cycles") && !path.startsWith("/api/appraisal-360/")) return null;

  if (path === "/api/appraisals" && request.method === "GET") {
    if (!canManage && !canReview && !canSelfReview) return error("Appraisal access is not enabled for this account.", 403);
    const appraisals = await env.DB.prepare(`
      SELECT a.id, a.cycle_id as cycleId, c.name as cycleName, c.period_start as periodStart, c.period_end as periodEnd,
        c.self_review_due as selfReviewDue, c.manager_review_due as managerReviewDue, c.status as cycleStatus,
        a.employee_id as employeeId, e.user_id as employeeUserId, e.first_name || ' ' || e.last_name as employeeName,
        e.job_title as jobTitle, d.name as department, a.reviewer_user_id as reviewerUserId,
        ru.full_name as reviewerName, a.status, a.self_review_json as selfReviewJson,
        a.manager_review_json as managerReviewJson, a.employee_acknowledgment as employeeAcknowledgment,
        a.employee_decision as employeeDecision, a.decision_note as decisionNote, a.manager_recommendation as managerRecommendation,
        a.self_submitted_at as selfSubmittedAt, a.manager_submitted_at as managerSubmittedAt,
        a.acknowledged_at as acknowledgedAt, a.updated_at as updatedAt
      FROM appraisals a JOIN appraisal_cycles c ON c.id = a.cycle_id AND c.organization_id = a.organization_id
      JOIN employees e ON e.id = a.employee_id AND e.organization_id = a.organization_id
      LEFT JOIN departments d ON d.id = e.department_id JOIN users ru ON ru.id = a.reviewer_user_id
      WHERE a.organization_id = ? AND (? = 1 OR e.user_id = ? OR a.reviewer_user_id = ?)
      ORDER BY c.created_at DESC, e.first_name, e.last_name
    `).bind(context.organizationId, canManage ? 1 : 0, context.userId, canReview ? context.userId : "").all();
    const appraisalKpis = await env.DB.prepare(`
      SELECT s.appraisal_id as appraisalId, s.kpi_id as kpiId, k.name, k.metric, k.target, k.weight,
        s.self_rating as selfRating, s.self_result as selfResult, s.manager_rating as managerRating, s.manager_comment as managerComment
      FROM appraisal_kpi_scores s JOIN appraisals a ON a.id = s.appraisal_id AND a.organization_id = s.organization_id
      JOIN employees e ON e.id = a.employee_id AND e.organization_id = a.organization_id
      JOIN performance_kpis k ON k.id = s.kpi_id AND k.organization_id = s.organization_id
      WHERE s.organization_id = ? AND (? = 1 OR e.user_id = ? OR a.reviewer_user_id = ?)
      ORDER BY k.name
    `).bind(context.organizationId, canManage ? 1 : 0, context.userId, canReview ? context.userId : "").all<{ appraisalId: string; kpiId: string; name: string; metric: string; target: string; weight: number; selfRating: number | null; selfResult: string | null; managerRating: number | null; managerComment: string | null }>();
    const kpiMap = new Map<string, typeof appraisalKpis.results>();
    for (const score of appraisalKpis.results || []) kpiMap.set(score.appraisalId, [...(kpiMap.get(score.appraisalId) || []), score]);
    const cycles = await env.DB.prepare(`
      SELECT c.id, c.name, c.period_start as periodStart, c.period_end as periodEnd,
        c.self_review_due as selfReviewDue, c.manager_review_due as managerReviewDue, c.status,
        c.created_at as createdAt, COUNT(a.id) as totalReviews,
        SUM(CASE WHEN a.status = 'complete' THEN 1 ELSE 0 END) as completedReviews
      FROM appraisal_cycles c LEFT JOIN appraisals a ON a.cycle_id = c.id AND a.organization_id = c.organization_id
      WHERE c.organization_id = ? AND (? = 1 OR a.employee_id IN (SELECT id FROM employees WHERE user_id = ?) OR a.reviewer_user_id = ?)
      GROUP BY c.id ORDER BY c.created_at DESC
    `).bind(context.organizationId, canManage ? 1 : 0, context.userId, canReview ? context.userId : "").all();
    return json({ cycles: cycles.results || [], appraisals: (appraisals.results || []).map((item) => ({ ...item, kpis: kpiMap.get(String(item.id)) || [] })), canManage });
  }

  if (path === "/api/appraisals/360-inbox" && request.method === "GET") {
    const inbox = await env.DB.prepare(`SELECT f.id, f.relationship, f.status, c.name as cycleName, e.first_name || ' ' || e.last_name as employeeName, e.job_title as jobTitle FROM appraisal_360_feedback f JOIN appraisals a ON a.id = f.appraisal_id AND a.organization_id = f.organization_id JOIN appraisal_cycles c ON c.id = a.cycle_id AND c.organization_id = a.organization_id JOIN employees e ON e.id = a.employee_id AND e.organization_id = a.organization_id WHERE f.organization_id = ? AND f.respondent_user_id = ? ORDER BY f.created_at DESC`).bind(context.organizationId, context.userId).all();
    return json({ data: inbox.results || [] });
  }

  const feedbackPath = path.match(/^\/api\/appraisals\/([^/]+)\/360-feedback$/);
  if (request.method === "GET" && feedbackPath) {
    const record = await env.DB.prepare(`SELECT a.id, e.user_id as employeeUserId, a.reviewer_user_id as reviewerUserId FROM appraisals a JOIN employees e ON e.id = a.employee_id AND e.organization_id = a.organization_id WHERE a.id = ? AND a.organization_id = ?`).bind(feedbackPath[1], context.organizationId).first<{ id: string; employeeUserId: string | null; reviewerUserId: string }>();
    if (!record) return error("Appraisal not found.", 404);
    if (context.userId !== record.employeeUserId && context.userId !== record.reviewerUserId && !canManage) return error("You are not authorized to view this appraisal feedback.", 403);
    const results = await env.DB.prepare(`SELECT feedback_json as feedbackJson, submitted_at as submittedAt FROM appraisal_360_feedback WHERE organization_id = ? AND appraisal_id = ? AND status = 'submitted' ORDER BY submitted_at`).bind(context.organizationId, record.id).all<{ feedbackJson: string; submittedAt: string }>();
    const minimumReached = (results.results || []).length >= 3;
    return json({ submittedCount: (results.results || []).length, minimumRequired: 3, feedback: minimumReached ? (results.results || []).map((row) => ({ ...JSON.parse(row.feedbackJson), submittedAt: row.submittedAt })) : [], anonymous: true });
  }

  const invite360Path = path.match(/^\/api\/appraisals\/([^/]+)\/360-invitations$/);
  if (request.method === "POST" && invite360Path) {
    const body = await request.json<{ respondents?: { employeeId: string; relationship: string }[] }>();
    const appraisal = await env.DB.prepare(`SELECT a.id, a.status, c.status as cycleStatus, e.user_id as employeeUserId, e.first_name || ' ' || e.last_name as employeeName FROM appraisals a JOIN appraisal_cycles c ON c.id = a.cycle_id AND c.organization_id = a.organization_id JOIN employees e ON e.id = a.employee_id AND e.organization_id = a.organization_id WHERE a.id = ? AND a.organization_id = ?`).bind(invite360Path[1], context.organizationId).first<{ id: string; status: string; cycleStatus: string; employeeUserId: string | null; employeeName: string }>();
    if (!appraisal) return error("Appraisal not found.", 404);
    if (!canManage && context.userId !== appraisal.employeeUserId) return error("Only the employee or HR administrator can nominate 360 reviewers.", 403);
    if (appraisal.cycleStatus !== "open" || appraisal.status !== "self_review") return error("360 reviewers must be nominated before the employee submits their self-review.", 409);
    if (!body.respondents?.length || body.respondents.length > 8 || body.respondents.some((item) => !['peer','direct_report','cross_functional'].includes(item.relationship))) return error("Choose 1–8 reviewers and classify each relationship.");
    const eligible: { userId: string; relationship: string }[] = [];
    for (const respondent of body.respondents) {
      const person = await env.DB.prepare(`SELECT e.user_id as userId FROM employees e WHERE e.id = ? AND e.organization_id = ? AND e.status = 'active' AND e.deleted_at IS NULL`).bind(respondent.employeeId, context.organizationId).first<{ userId: string | null }>();
      if (!person?.userId || person.userId === appraisal.employeeUserId) return error("Each 360 reviewer must be a different active employee in this organization.");
      eligible.push({ userId: person.userId, relationship: respondent.relationship });
    }
    if (new Set(eligible.map((item) => item.userId)).size !== eligible.length) return error("Select each 360 reviewer only once.");
    const statements: D1PreparedStatement[] = [];
    for (const item of eligible) {
      statements.push(env.DB.prepare(`INSERT INTO appraisal_360_feedback (id, organization_id, appraisal_id, respondent_user_id, relationship) VALUES (?, ?, ?, ?, ?)`).bind(`360-${crypto.randomUUID()}`, context.organizationId, appraisal.id, item.userId, item.relationship));
      statements.push(env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'appraisal_360', ?, ?)`).bind(requestId(), context.organizationId, item.userId, "360 feedback requested", `Please provide confidential peer feedback for ${appraisal.employeeName}.`));
    }
    await env.DB.batch(statements);
    await audit(env, context, "360_reviewers_nominated", "appraisals", appraisal.id, { reviewerCount: eligible.length });
    return json({ invitedCount: eligible.length }, { status: 201 });
  }

  const feedbackSubmit = path.match(/^\/api\/appraisal-360\/([^/]+)\/submit$/);
  if (request.method === "POST" && feedbackSubmit) {
    const assignment = await env.DB.prepare(`SELECT f.id, f.status, a.employee_id as employeeId, a.organization_id as organizationId, e.first_name || ' ' || e.last_name as employeeName, a.reviewer_user_id as reviewerUserId, c.status as cycleStatus FROM appraisal_360_feedback f JOIN appraisals a ON a.id = f.appraisal_id AND a.organization_id = f.organization_id JOIN appraisal_cycles c ON c.id = a.cycle_id AND c.organization_id = a.organization_id JOIN employees e ON e.id = a.employee_id AND e.organization_id = a.organization_id WHERE f.id = ? AND f.organization_id = ? AND f.respondent_user_id = ?`).bind(feedbackSubmit[1], context.organizationId, context.userId).first<{ id: string; status: string; employeeId: string; organizationId: string; employeeName: string; reviewerUserId: string; cycleStatus: string }>();
    if (!assignment) return error("360 feedback assignment not found.", 404);
    if (assignment.status !== "assigned" || assignment.cycleStatus !== "open") return error("This 360 feedback request is no longer open.", 409);
    const body = await request.json<Record<string, unknown>>();
    if (!Number.isInteger(Number(body.overallRating)) || Number(body.overallRating) < 1 || Number(body.overallRating) > 5 || typeof body.summary !== "string" || body.summary.trim().length < 5 || typeof body.strengths !== "string" || typeof body.improvements !== "string" || typeof body.recommendation !== "string") return error("Provide an overall rating, evidence-based feedback, strengths and growth suggestions.");
    await env.DB.batch([
      env.DB.prepare(`UPDATE appraisal_360_feedback SET status = 'submitted', feedback_json = ?, submitted_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND respondent_user_id = ? AND status = 'assigned'`).bind(JSON.stringify({ overallRating: Number(body.overallRating), summary: body.summary.trim().slice(0, 3000), strengths: body.strengths.trim().slice(0, 2000), improvements: body.improvements.trim().slice(0, 2000), recommendation: body.recommendation.trim().slice(0, 2000) }), assignment.id, context.organizationId, context.userId),
      env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'appraisal_360_received', ?, ?)`).bind(requestId(), context.organizationId, assignment.reviewerUserId, "360 feedback received", `A confidential 360 response for ${assignment.employeeName} has been submitted.`),
    ]);
    await audit(env, context, "360_feedback_submitted", "appraisals", assignment.id);
    return json({ ok: true });
  }

  if (path === "/api/appraisal-cycles" && request.method === "POST") {
    if (!canManage) return error("HR or organization administrator access is required to create an appraisal cycle.", 403);
    const body = await request.json<{ name?: string; periodStart?: string; periodEnd?: string; selfReviewDue?: string; managerReviewDue?: string }>();
    const name = body.name?.trim();
    const validDate = (value?: string) => Boolean(value && /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`)));
    if (!name || name.length > 120 || !validDate(body.periodStart) || !validDate(body.periodEnd) || !validDate(body.selfReviewDue) || !validDate(body.managerReviewDue) || body.periodEnd! < body.periodStart! || body.managerReviewDue! < body.selfReviewDue!) return error("Enter a cycle name and valid review-period and deadline dates.");
    const employeeCount = await env.DB.prepare(`SELECT COUNT(*) as total FROM employees e JOIN users u ON u.id = e.user_id AND u.status = 'active' JOIN memberships m ON m.user_id = u.id AND m.organization_id = e.organization_id AND m.status = 'active' WHERE e.organization_id = ? AND e.deleted_at IS NULL AND e.status = 'active'`).bind(context.organizationId).first<{ total: number }>();
    if (!employeeCount?.total) return error("No active, onboarded employees are eligible for this appraisal cycle.", 409);
    const cycleId = `cycle-${crypto.randomUUID()}`;
    const statements: D1PreparedStatement[] = [
      env.DB.prepare(`INSERT INTO appraisal_cycles (id, organization_id, name, period_start, period_end, self_review_due, manager_review_due, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(cycleId, context.organizationId, name, body.periodStart, body.periodEnd, body.selfReviewDue, body.managerReviewDue, context.userId),
      env.DB.prepare(`INSERT INTO appraisals (id, organization_id, cycle_id, employee_id, reviewer_user_id) SELECT 'appraisal-' || lower(hex(randomblob(16))), e.organization_id, ?, e.id, COALESCE(mm.user_id, ?) FROM employees e JOIN users eu ON eu.id = e.user_id AND eu.status = 'active' JOIN memberships em ON em.user_id = eu.id AND em.organization_id = e.organization_id AND em.status = 'active' LEFT JOIN employees manager ON manager.id = e.manager_id AND manager.organization_id = e.organization_id AND manager.deleted_at IS NULL LEFT JOIN users mu ON mu.id = manager.user_id AND mu.status = 'active' LEFT JOIN memberships mm ON mm.user_id = mu.id AND mm.organization_id = e.organization_id AND mm.status = 'active' WHERE e.organization_id = ? AND e.deleted_at IS NULL AND e.status = 'active'`).bind(cycleId, context.userId, context.organizationId),
      env.DB.prepare(`INSERT INTO appraisal_kpi_scores (id, organization_id, appraisal_id, kpi_id) SELECT 'kpiscore-' || lower(hex(randomblob(16))), a.organization_id, a.id, k.id FROM appraisals a JOIN employees e ON e.id = a.employee_id AND e.organization_id = a.organization_id JOIN performance_kpis k ON k.organization_id = a.organization_id AND k.status = 'active' AND (k.employee_id = e.id OR k.team_id = e.team_id OR (k.employee_id IS NULL AND k.team_id IS NULL)) WHERE a.organization_id = ? AND a.cycle_id = ?`).bind(context.organizationId, cycleId),
      env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) SELECT 'notif-' || lower(hex(randomblob(16))), e.organization_id, eu.id, 'appraisal_assigned', 'Self-review assigned', ? || ': complete your self-review by ' || ? || '.' FROM employees e JOIN users eu ON eu.id = e.user_id AND eu.status = 'active' JOIN memberships em ON em.user_id = eu.id AND em.organization_id = e.organization_id AND em.status = 'active' WHERE e.organization_id = ? AND e.deleted_at IS NULL AND e.status = 'active'`).bind(name, body.selfReviewDue, context.organizationId),
      env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) SELECT 'notif-' || lower(hex(randomblob(16))), a.organization_id, a.reviewer_user_id, 'appraisal_assigned', 'Manager reviews assigned', COUNT(*) || ' manager review(s) for ' || c.name || ' are due by ' || c.manager_review_due || '.' FROM appraisals a JOIN appraisal_cycles c ON c.id = a.cycle_id AND c.organization_id = a.organization_id JOIN employees e ON e.id = a.employee_id AND e.organization_id = a.organization_id WHERE a.organization_id = ? AND a.cycle_id = ? AND a.reviewer_user_id != e.user_id GROUP BY a.reviewer_user_id`).bind(context.organizationId, cycleId),
      env.DB.prepare(`INSERT INTO audit_logs (id, organization_id, actor_user_id, action, module, record_type, record_id, new_value_json) VALUES (?, ?, ?, 'created', 'appraisals', 'appraisal_cycle', ?, ?)`).bind(requestId(), context.organizationId, context.userId, cycleId, JSON.stringify({ name, employeeCount: employeeCount.total, periodStart: body.periodStart, periodEnd: body.periodEnd })),
    ];
    await env.DB.batch(statements);
    return json({ id: cycleId, assignedCount: employeeCount.total }, { status: 201 });
  }

  const cycleMatch = path.match(/^\/api\/appraisal-cycles\/([^/]+)$/);
  if (request.method === "PATCH" && cycleMatch) {
    if (!canManage) return error("HR or organization administrator access is required to close an appraisal cycle.", 403);
    const body = await request.json<{ status?: string }>();
    if (body.status !== "closed") return error("Appraisal cycles can only be closed through this action.");
    const result = await env.DB.prepare(`UPDATE appraisal_cycles SET status = 'closed', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = 'open'`).bind(cycleMatch[1], context.organizationId).run();
    if (!result.meta.changes) return error("Open appraisal cycle not found.", 404);
    await audit(env, context, "closed", "appraisals", cycleMatch[1]);
    return json({ ok: true, status: "closed" });
  }

  const actionMatch = path.match(/^\/api\/appraisals\/([^/]+)\/(self-review|manager-review|acknowledge|decision)$/);
  if (request.method === "POST" && actionMatch) {
    const [, appraisalId, action] = actionMatch;
    const appraisal = await env.DB.prepare(`SELECT a.id, e.user_id as employeeUserId, e.first_name || ' ' || e.last_name as employeeName, a.reviewer_user_id as reviewerUserId, a.status, c.name as cycleName, c.status as cycleStatus FROM appraisals a JOIN employees e ON e.id = a.employee_id AND e.organization_id = a.organization_id JOIN appraisal_cycles c ON c.id = a.cycle_id AND c.organization_id = a.organization_id WHERE a.id = ? AND a.organization_id = ?`)
      .bind(appraisalId, context.organizationId).first<{ id: string; employeeUserId: string; employeeName: string; reviewerUserId: string; status: string; cycleName: string; cycleStatus: string }>();
    if (!appraisal) return error("Appraisal not found.", 404);
    if (appraisal.cycleStatus !== "open") return error("This appraisal cycle is closed.", 409);
    if (action === "self-review") {
      if (context.userId !== appraisal.employeeUserId || !canSelfReview) return error("Only the assigned employee can submit their self-review.", 403);
      if (appraisal.status !== "self_review") return error("This self-review has already been submitted.", 409);
      const review = validAppraisalReview(await request.json<Record<string, unknown>>());
      if (!review) return error("Complete the 1–5 overall rating, summary, strengths, development plan, and valid goal and competency ratings.");
      if (!await saveAppraisalKpiScores(env, context, appraisalId, review.kpiScores, "self")) return error("Complete the rating and evidence for every KPI assigned to this appraisal.");
      await env.DB.batch([
        env.DB.prepare(`UPDATE appraisals SET self_review_json = ?, status = 'manager_review', self_submitted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = 'self_review'`).bind(JSON.stringify(review), appraisalId, context.organizationId),
        env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'appraisal_ready', ?, ?)`).bind(requestId(), context.organizationId, appraisal.reviewerUserId, "Self-review submitted", `${appraisal.employeeName} submitted their self-review for ${appraisal.cycleName}.`),
      ]);
    } else if (action === "manager-review") {
      if (appraisal.reviewerUserId !== context.userId && !canManage) return error("Only the assigned reviewer or HR administrator can submit this manager review.", 403);
      if (appraisal.status !== "manager_review") return error("The employee must submit their self-review before manager review.", 409);
      const review = validAppraisalReview(await request.json<Record<string, unknown>>());
      if (!review) return error("Complete the 1–5 overall rating, summary, strengths, development plan, and valid goal and competency ratings.");
      if (!await saveAppraisalKpiScores(env, context, appraisalId, review.kpiScores, "manager")) return error("Complete the manager rating and comment for every KPI assigned to this appraisal.");
      await env.DB.batch([
        env.DB.prepare(`UPDATE appraisals SET manager_review_json = ?, manager_recommendation = ?, status = 'acknowledgment', manager_submitted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = 'manager_review'`).bind(JSON.stringify(review), review.recommendation, appraisalId, context.organizationId),
        env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'appraisal_acknowledgment', ?, ?)`).bind(requestId(), context.organizationId, appraisal.employeeUserId, "Appraisal ready to acknowledge", `Your manager completed the ${appraisal.cycleName} review. Please read and acknowledge it.`),
      ]);
    } else {
      if (context.userId !== appraisal.employeeUserId || !canSelfReview) return error("Only the assigned employee can acknowledge this appraisal.", 403);
      if (appraisal.status !== "acknowledgment") return error("There is no manager review awaiting acknowledgment.", 409);
      const body = await request.json<{ acknowledgment?: string; decision?: string; note?: string }>();
      const decision = action === "acknowledge" ? "accepted" : body.decision;
      if (!['accepted','declined'].includes(decision || "") || typeof body.note !== "string" || body.note.trim().length < 3 || body.note.length > 2000) return error("Choose accept or decline and include a brief comment.");
      await env.DB.prepare(`UPDATE appraisals SET employee_acknowledgment = ?, employee_decision = ?, decision_note = ?, status = 'complete', acknowledged_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = 'acknowledgment'`).bind(body.acknowledgment?.trim() || body.note.trim(), decision, body.note.trim(), appraisalId, context.organizationId).run();
      await env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'appraisal_decision', ?, ?)`).bind(requestId(), context.organizationId, appraisal.reviewerUserId, decision === "accepted" ? "Appraisal accepted" : "Appraisal declined", `${appraisal.employeeName} ${decision} the ${appraisal.cycleName} appraisal.`).run();
    }
    await audit(env, context, action.replace("-", "_"), "appraisals", appraisalId, { cycle: appraisal.cycleName });
    return json({ ok: true });
  }
  return error("Appraisal endpoint not found.", 404);
}

async function handleExitManagement(request: Request, env: Env, context: AuthContext, path: string): Promise<Response | null> {
  const base = "/api/hr/exits";
  if (path !== base && !path.startsWith(`${base}/`)) return null;
  const canManage = hasPermission(context, "employees.manage") || hasPermission(context, "hr.onboarding.approve") || context.role === "Admin" || context.role === "Organization Admin";
  const canFinance = hasPermission(context, "payroll.manage") || hasPermission(context, "expenses.manage");
  const canIT = hasPermission(context, "operations.manage");
  const selfEmployee = await env.DB.prepare(`SELECT id FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string }>();
  if (!canManage && !canFinance && !canIT && !selfEmployee) return error("Exit management is not enabled for this account.", 403);

  if (path === base && request.method === "GET") {
    const cases = await env.DB.prepare(`SELECT c.id, c.employee_id as employeeId, e.employee_number as employeeNumber, e.first_name as firstName, e.last_name as lastName, e.email, e.job_title as jobTitle, e.department_id as departmentId, d.name as department, c.manager_id as managerId, COALESCE(m.first_name || ' ' || m.last_name, '') as managerName, c.separation_type as separationType, CASE WHEN ? = 1 OR e.user_id = ? THEN c.reason ELSE NULL END as reason, c.notice_date as noticeDate, c.last_working_date as lastWorkingDate, c.status, CASE WHEN ? = 1 OR e.user_id = ? THEN c.exit_interview_date ELSE NULL END as exitInterviewDate, CASE WHEN ? = 1 OR e.user_id = ? THEN c.exit_interview_notes ELSE NULL END as exitInterviewNotes, CASE WHEN ? = 1 OR e.user_id = ? THEN c.employee_feedback ELSE NULL END as employeeFeedback, CASE WHEN ? = 1 OR ? = 1 THEN c.final_salary ELSE NULL END as finalSalary, CASE WHEN ? = 1 OR ? = 1 THEN c.leave_payout ELSE NULL END as leavePayout, CASE WHEN ? = 1 OR ? = 1 THEN c.deductions ELSE NULL END as deductions, CASE WHEN ? = 1 OR ? = 1 THEN c.outstanding_balance ELSE NULL END as outstandingBalance, CASE WHEN ? = 1 OR ? = 1 THEN c.finance_notes ELSE NULL END as financeNotes, CASE WHEN ? = 1 OR ? = 1 THEN c.reference_documents ELSE NULL END as referenceDocuments, c.created_at as createdAt, c.completed_at as completedAt, (SELECT COUNT(*) FROM employee_exit_tasks t WHERE t.exit_case_id = c.id AND t.organization_id = c.organization_id) as taskCount, (SELECT COUNT(*) FROM employee_exit_tasks t WHERE t.exit_case_id = c.id AND t.organization_id = c.organization_id AND t.status IN ('completed','waived')) as completedTaskCount FROM employee_exit_cases c JOIN employees e ON e.id = c.employee_id AND e.organization_id = c.organization_id LEFT JOIN departments d ON d.id = e.department_id AND d.organization_id = e.organization_id LEFT JOIN employees m ON m.id = c.manager_id AND m.organization_id = c.organization_id WHERE c.organization_id = ? AND (? = 1 OR e.user_id = ? OR m.user_id = ? OR ((? = 1 OR ? = 1) AND c.status = 'active')) ORDER BY CASE c.status WHEN 'active' THEN 0 WHEN 'completed' THEN 1 ELSE 2 END, c.last_working_date DESC, c.created_at DESC`).bind(canManage ? 1 : 0, context.userId, canManage ? 1 : 0, context.userId, canManage ? 1 : 0, context.userId, canManage ? 1 : 0, context.userId, canManage ? 1 : 0, canFinance ? 1 : 0, canManage ? 1 : 0, canFinance ? 1 : 0, canManage ? 1 : 0, canFinance ? 1 : 0, canManage ? 1 : 0, canFinance ? 1 : 0, canManage ? 1 : 0, canFinance ? 1 : 0, context.organizationId, canManage ? 1 : 0, context.userId, context.userId, canFinance ? 1 : 0, canIT ? 1 : 0).all();
    const tasks = await env.DB.prepare(`SELECT t.id, t.exit_case_id as exitCaseId, t.category, t.title, t.details, t.status, t.notes, t.completed_at as completedAt, u.full_name as completedBy, t.sort_order as sortOrder, CASE WHEN ? = 1 OR (t.category = 'finance' AND ? = 1) OR (t.category = 'it' AND ? = 1) OR (t.category = 'employee' AND e.user_id = ?) OR (t.category = 'manager' AND m.user_id = ?) THEN 1 ELSE 0 END as canUpdate FROM employee_exit_tasks t JOIN employee_exit_cases c ON c.id = t.exit_case_id AND c.organization_id = t.organization_id JOIN employees e ON e.id = c.employee_id AND e.organization_id = c.organization_id LEFT JOIN employees m ON m.id = c.manager_id AND m.organization_id = c.organization_id LEFT JOIN users u ON u.id = t.completed_by WHERE t.organization_id = ? AND (? = 1 OR (t.category = 'finance' AND ? = 1) OR (t.category = 'it' AND ? = 1) OR (t.category = 'employee' AND e.user_id = ?) OR (t.category = 'manager' AND m.user_id = ?)) ORDER BY t.exit_case_id, t.sort_order`).bind(canManage ? 1 : 0, canFinance ? 1 : 0, canIT ? 1 : 0, context.userId, context.userId, context.organizationId, canManage ? 1 : 0, canFinance ? 1 : 0, canIT ? 1 : 0, context.userId, context.userId).all();
    const approvalRows = await env.DB.prepare(`SELECT id, approval_status as approvalStatus, approval_role as approvalRole, approval_note as approvalNote FROM employee_exit_cases WHERE organization_id = ?`).bind(context.organizationId).all<{ id: string; approvalStatus: string; approvalRole: string; approvalNote: string | null }>();
    const approvals = new Map((approvalRows.results || []).map((row) => [row.id, row]));
    const visibleCases = (cases.results || []).map((row) => ({ ...row, ...approvals.get(String((row as { id: string }).id)) }));
    const pendingCases = context.role === "CEO" || context.role === "HR Admin" || context.role === "Organization Admin"
      ? await env.DB.prepare(`SELECT c.id, c.employee_id as employeeId, e.employee_number as employeeNumber, e.first_name as firstName, e.last_name as lastName, e.email, e.job_title as jobTitle, d.name as department, c.manager_id as managerId, COALESCE(m.first_name || ' ' || m.last_name, '') as managerName, c.separation_type as separationType, c.reason, c.notice_date as noticeDate, c.last_working_date as lastWorkingDate, c.status, c.approval_status as approvalStatus, c.approval_role as approvalRole, c.approval_note as approvalNote, NULL as exitInterviewDate, NULL as exitInterviewNotes, NULL as employeeFeedback, NULL as finalSalary, NULL as leavePayout, NULL as deductions, NULL as outstandingBalance, NULL as financeNotes, NULL as referenceDocuments, c.created_at as createdAt, c.completed_at as completedAt, (SELECT COUNT(*) FROM employee_exit_tasks t WHERE t.exit_case_id = c.id AND t.organization_id = c.organization_id) as taskCount, 0 as completedTaskCount FROM employee_exit_cases c JOIN employees e ON e.id = c.employee_id AND e.organization_id = c.organization_id LEFT JOIN departments d ON d.id = e.department_id AND d.organization_id = e.organization_id LEFT JOIN employees m ON m.id = c.manager_id AND m.organization_id = e.organization_id WHERE c.organization_id = ? AND c.approval_status = 'pending' AND c.approval_role = ?`).bind(context.organizationId, context.role === "Organization Admin" ? "CEO" : context.role).all()
      : { results: [] };
    const allCases = [...visibleCases, ...(pendingCases.results || []).filter((row) => !visibleCases.some((item) => (item as { id: string }).id === (row as { id: string }).id))];
    return json({ data: allCases, tasks: tasks.results || [], canManage, canFinance, canIT, canApproveExit: ["CEO","HR Admin","Organization Admin"].includes(context.role), employeeId: selfEmployee?.id || null });
  }

  if (path === base && request.method === "POST") {
    if (!canManage) return error("Only HR or an organization administrator can initiate an employee separation.", 403);
    const body = await request.json<{ employeeId?: string; separationType?: string; reason?: string; noticeDate?: string; lastWorkingDate?: string }>();
    const validTypes = ["resignation", "retirement", "end_of_contract", "redundancy", "termination", "other"];
    const noticeDate = body.noticeDate || "", lastWorkingDate = body.lastWorkingDate || "";
    const employee = body.employeeId ? await env.DB.prepare(`SELECT e.id, e.manager_id as managerId, e.first_name as firstName, e.last_name as lastName, e.user_id as userId FROM employees e WHERE e.id = ? AND e.organization_id = ? AND e.deleted_at IS NULL AND e.status != 'inactive'`).bind(body.employeeId, context.organizationId).first<{ id: string; managerId: string | null; firstName: string; lastName: string; userId: string | null }>() : null;
    if (!employee || !validTypes.includes(body.separationType || "") || !body.reason?.trim() || body.reason.trim().length > 2000 || !isIsoCalendarDate(noticeDate) || !isIsoCalendarDate(lastWorkingDate) || lastWorkingDate < noticeDate) return error("Choose an active employee and provide a separation type, reason, notice date and valid last working date.");
    const existing = await env.DB.prepare(`SELECT id FROM employee_exit_cases WHERE organization_id = ? AND employee_id = ? AND status != 'cancelled' AND approval_status != 'rejected'`).bind(context.organizationId, employee.id).first();
    if (existing) return error("This employee already has an active exit case.", 409);
    const id = `exit-${crypto.randomUUID()}`;
    const checklist: Array<[string, string, string]> = [
      ["employee", "Return organization property", "Return company devices, keys, ID cards, documents and any other assigned property; record exceptions in notes."],
      ["employee", "Submit handover and outstanding work notes", "Document current responsibilities, open work, key contacts, deadlines and locations of work materials."],
      ["manager", "Review handover and reassign responsibilities", "Confirm work ownership, project access, customer handover, open approvals and continuity arrangements."],
      ["hr", "Conduct and document exit interview", "Record the interview date, employee feedback, reason for leaving and any agreed follow-up."],
      ["hr", "Prepare exit documents and archive personnel records", "Confirm required notices, acknowledgements, service/experience documents and secure personnel-file retention."],
      ["hr", "Confirm benefits and policy close-out", "Confirm benefit end dates, pension/insurance administration and employee communication under applicable policy."],
      ["it", "Recover devices and remove physical access", "Record returned devices and remove building, badge, VPN and other physical access on the approved date."],
      ["it", "Revoke application and organization access", "Disable organization membership and revoke email, SaaS, shared-secret and privileged access at the approved separation time."],
      ["finance", "Reconcile expenses, advances and outstanding balances", "Reconcile submitted claims, advances, loans, recoverables and approved deductions; attach references in finance notes."],
      ["finance", "Validate final remuneration and leave balance", "Document final salary, eligible leave payout, deductions and outstanding balance. This records amounts only; it does not initiate a bank transfer."],
      ["finance", "Complete finance clearance", "Confirm the final reconciliation is reviewed and all amounts are documented in the case before HR closes it."],
    ];
    const workflow = await env.DB.prepare(`SELECT exit_approval_role as approvalRole FROM organization_settings WHERE organization_id = ?`).bind(context.organizationId).first<{ approvalRole: string }>();
    const approvalRole = workflow?.approvalRole || "CEO";
    const statements = [env.DB.prepare(`INSERT INTO employee_exit_cases (id, organization_id, employee_id, manager_id, separation_type, reason, notice_date, last_working_date, initiated_by, approval_status, approval_role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`).bind(id, context.organizationId, employee.id, employee.managerId, body.separationType, body.reason.trim(), noticeDate, lastWorkingDate, context.userId, approvalRole), ...checklist.map(([category, title, details], index) => env.DB.prepare(`INSERT INTO employee_exit_tasks (id, organization_id, exit_case_id, category, title, details, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(`exit-task-${crypto.randomUUID()}`, context.organizationId, id, category, title, details, index + 1))];
    await env.DB.batch(statements);
    const approvers = await env.DB.prepare(`SELECT COUNT(*) as count FROM memberships m JOIN roles r ON r.id = m.role_id WHERE m.organization_id = ? AND m.status = 'active' AND r.name = ?`).bind(context.organizationId, approvalRole).first<{ count: number }>();
    const actualApprovalRole = (approvers?.count || 0) > 0 ? approvalRole : approvalRole === "CEO" ? "HR Admin" : "CEO";
    if (actualApprovalRole !== approvalRole) await env.DB.prepare(`UPDATE employee_exit_cases SET approval_role = ? WHERE id = ? AND organization_id = ?`).bind(actualApprovalRole, id, context.organizationId).run();
    await notifyApprovers(env, context, actualApprovalRole, `Separation approval · ${employee.firstName} ${employee.lastName}`, `An HR separation request is waiting for your sign-off. Planned last working date: ${lastWorkingDate}. No offboarding tasks start until approval.`);
    await audit(env, context, "created", "employee_exit_cases", id, { employeeId: employee.id, separationType: body.separationType, lastWorkingDate });
    return json({ id }, { status: 201 });
  }

  const exitDecision = path.match(/^\/api\/hr\/exits\/([^/]+)\/decision$/);
  if (exitDecision && request.method === "POST") {
    const body = await request.json<{ decision?: string; note?: string }>();
    if (!["approved","rejected"].includes(body.decision || "") || !body.note?.trim() || body.note.length > 2000) return error("Choose approve or reject and include the decision rationale (maximum 2,000 characters).");
    const current = await env.DB.prepare(`SELECT c.employee_id as employeeId, c.approval_role as approvalRole, c.approval_status as approvalStatus, e.user_id as employeeUserId, e.email, e.first_name as firstName, e.last_name as lastName FROM employee_exit_cases c JOIN employees e ON e.id = c.employee_id AND e.organization_id = c.organization_id WHERE c.id = ? AND c.organization_id = ?`).bind(exitDecision[1], context.organizationId).first<{ employeeId: string; approvalRole: string; approvalStatus: string; employeeUserId: string | null; email: string; firstName: string; lastName: string }>();
    if (!current) return error("Exit case not found.", 404);
    if (current.approvalStatus !== "pending") return error("This separation request has already been decided.", 409);
    if (context.role !== current.approvalRole && context.role !== "Organization Admin") return error(`This separation requires approval from ${current.approvalRole}.`, 403);
    const decision = body.decision as "approved" | "rejected";
    await env.DB.prepare(`UPDATE employee_exit_cases SET approval_status = ?, approval_note = ?, approved_by = ?, approved_at = CURRENT_TIMESTAMP, status = CASE WHEN ? = 'rejected' THEN 'cancelled' ELSE status END, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND approval_status = 'pending'`).bind(decision, body.note.trim(), context.userId, decision, exitDecision[1], context.organizationId).run();
    if (current.employeeUserId) {
      const title = decision === "approved" ? "Separation process approved" : "Separation request declined";
      const message = decision === "approved" ? `The separation request was approved. HR will coordinate the offboarding steps and planned final working date.` : `The separation request was not approved. Decision note: ${body.note.trim()}`;
      await env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'employee_exit', ?, ?)`).bind(requestId(), context.organizationId, current.employeeUserId, title, message).run();
      const organization = await env.DB.prepare(`SELECT name FROM organizations WHERE id = ?`).bind(context.organizationId).first<{ name: string }>();
      await sendApprovalNotificationEmail(env, current.email, `${current.firstName} ${current.lastName}`, organization?.name || "your organization", title, message);
    }
    await audit(env, context, `separation_${decision}`, "employee_exit_cases", exitDecision[1], { approvalRole: current.approvalRole, note: body.note.trim() });
    return json({ ok: true, approvalStatus: decision });
  }

  const taskMatch = path.match(/^\/api\/hr\/exits\/([^/]+)\/tasks\/([^/]+)$/);
  if (taskMatch && request.method === "PATCH") {
    const body = await request.json<{ status?: string; notes?: string }>();
    const status = body.status || "";
    if (!["pending", "completed", "waived"].includes(status) || (body.notes || "").length > 2000 || (status !== "pending" && !body.notes?.trim())) return error("Choose a valid status; add a completion or waiver note, with no more than 2,000 characters.");
    const task = await env.DB.prepare(`SELECT t.category, c.status as caseStatus, c.approval_status as approvalStatus, e.user_id as employeeUserId, m.user_id as managerUserId FROM employee_exit_tasks t JOIN employee_exit_cases c ON c.id = t.exit_case_id AND c.organization_id = t.organization_id JOIN employees e ON e.id = c.employee_id AND e.organization_id = c.organization_id LEFT JOIN employees m ON m.id = c.manager_id AND m.organization_id = c.organization_id WHERE t.id = ? AND t.exit_case_id = ? AND t.organization_id = ?`).bind(taskMatch[2], taskMatch[1], context.organizationId).first<{ category: string; caseStatus: string; approvalStatus: string; employeeUserId: string | null; managerUserId: string | null }>();
    const mayUpdateTask = Boolean(task && task.caseStatus === "active" && task.approvalStatus === "approved" && (canManage || (task.category === "finance" && canFinance) || (task.category === "it" && canIT) || (task.category === "employee" && task.employeeUserId === context.userId) || (task.category === "manager" && task.managerUserId === context.userId)));
    if (!mayUpdateTask) return error("This checklist item is not assigned to your role or the exit case is closed.", 403);
    const result = await env.DB.prepare(`UPDATE employee_exit_tasks SET status = ?, notes = ?, completed_by = CASE WHEN ? = 'pending' THEN NULL ELSE ? END, completed_at = CASE WHEN ? = 'pending' THEN NULL ELSE CURRENT_TIMESTAMP END, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND exit_case_id = ? AND organization_id = ? AND EXISTS (SELECT 1 FROM employee_exit_cases c WHERE c.id = exit_case_id AND c.organization_id = ? AND c.status = 'active')`).bind(status, body.notes?.trim() || null, status, context.userId, status, taskMatch[2], taskMatch[1], context.organizationId, context.organizationId).run();
    if (!result.meta.changes) return error("Active exit case or checklist task not found.", 404);
    await audit(env, context, status === "pending" ? "reopened" : status, "employee_exit_tasks", taskMatch[2], { exitCaseId: taskMatch[1], status });
    return json({ ok: true });
  }

  const caseMatch = path.match(/^\/api\/hr\/exits\/([^/]+)$/);
  if (caseMatch && request.method === "PATCH") {
    const body = await request.json<{ status?: string; exitInterviewDate?: string | null; exitInterviewNotes?: string | null; employeeFeedback?: string | null; finalSalary?: number; leavePayout?: number; deductions?: number; outstandingBalance?: number; financeNotes?: string | null; referenceDocuments?: string | null }>();
    const current = await env.DB.prepare(`SELECT id, employee_id as employeeId, status, approval_status as approvalStatus FROM employee_exit_cases WHERE id = ? AND organization_id = ?`).bind(caseMatch[1], context.organizationId).first<{ id: string; employeeId: string; status: string; approvalStatus: string }>();
    if (!current) return error("Exit case not found.", 404);
    if (!canManage && !canFinance) return error("HR or finance administrator access is required to update this case.", 403);
    const financeKeys = ["finalSalary", "leavePayout", "deductions", "outstandingBalance", "financeNotes", "referenceDocuments"];
    const hrKeys = ["status", "exitInterviewDate", "exitInterviewNotes", "employeeFeedback"];
    if (!canManage && hrKeys.some((key) => body[key as keyof typeof body] !== undefined)) return error("Only HR may update the interview or close an exit case.", 403);
    if (!canFinance && !canManage && financeKeys.some((key) => body[key as keyof typeof body] !== undefined)) return error("Finance administrator access is required to update financial reconciliation.", 403);
    if (current.status !== "active") return error("Only active exit cases can be updated.", 409);
    if (current.approvalStatus !== "approved" && body.status !== "cancelled") return error("HR, finance, employee and IT exit actions are locked until the required separation sign-off is approved.", 409);
    const amountFields = [body.finalSalary, body.leavePayout, body.deductions, body.outstandingBalance].filter((value) => value !== undefined);
    if (amountFields.some((value) => !Number.isFinite(value) || Number(value) < 0 || Number(value) > 1_000_000_000_000) || (body.exitInterviewDate && !isIsoCalendarDate(body.exitInterviewDate)) || [body.exitInterviewNotes, body.employeeFeedback, body.financeNotes, body.referenceDocuments].some((value) => value != null && value.length > 4000)) return error("Check the date, finance amounts (0–1 trillion NGN) and notes (maximum 4,000 characters).");
    if (body.status && !["completed", "cancelled"].includes(body.status)) return error("An exit case can only be completed or cancelled.");
    if (body.status === "completed") {
      const openTasks = await env.DB.prepare(`SELECT COUNT(*) as count FROM employee_exit_tasks WHERE organization_id = ? AND exit_case_id = ? AND status = 'pending'`).bind(context.organizationId, current.id).first<{ count: number }>();
      const financeClearance = await env.DB.prepare(`SELECT COUNT(*) as count FROM employee_exit_tasks WHERE organization_id = ? AND exit_case_id = ? AND category = 'finance' AND title = 'Complete finance clearance' AND status = 'completed'`).bind(context.organizationId, current.id).first<{ count: number }>();
      const requiredSignoffs = await env.DB.prepare(`SELECT COUNT(*) as count FROM employee_exit_tasks WHERE organization_id = ? AND exit_case_id = ? AND ((category = 'hr' AND title = 'Conduct and document exit interview' AND status = 'completed') OR (category = 'it' AND title = 'Revoke application and organization access' AND status = 'completed'))`).bind(context.organizationId, current.id).first<{ count: number }>();
      const closureDetails = await env.DB.prepare(`SELECT c.finance_notes as financeNotes, c.exit_interview_date as exitInterviewDate, c.exit_interview_notes as exitInterviewNotes, e.user_id as employeeUserId FROM employee_exit_cases c JOIN employees e ON e.id = c.employee_id AND e.organization_id = c.organization_id WHERE c.id = ? AND c.organization_id = ?`).bind(current.id, context.organizationId).first<{ financeNotes: string | null; exitInterviewDate: string | null; exitInterviewNotes: string | null; employeeUserId: string | null }>();
      if ((openTasks?.count || 0) > 0 || !(financeClearance?.count || 0) || requiredSignoffs?.count !== 2 || !closureDetails?.financeNotes?.trim() || !closureDetails.exitInterviewDate || !closureDetails.exitInterviewNotes?.trim()) return error("Complete or explicitly waive checklist items, record the exit interview, revoke organization access, and complete finance clearance with reconciliation notes before closing.", 409);
      if (closureDetails.employeeUserId === context.userId) return error("You cannot complete your own employee exit case.", 409);
      if (closureDetails.employeeUserId) {
        const adminMembership = await env.DB.prepare(`SELECT r.name as roleName FROM memberships m JOIN roles r ON r.id = m.role_id WHERE m.organization_id = ? AND m.user_id = ? AND m.status = 'active' AND r.name IN ('Organization Admin','CEO') LIMIT 1`).bind(context.organizationId, closureDetails.employeeUserId).first<{ roleName: string }>();
        if (adminMembership) {
          const otherAdmins = await env.DB.prepare(`SELECT COUNT(*) as count FROM memberships m JOIN roles r ON r.id = m.role_id JOIN users u ON u.id = m.user_id AND u.status = 'active' WHERE m.organization_id = ? AND m.status = 'active' AND m.user_id != ? AND r.name IN ('Organization Admin','CEO')`).bind(context.organizationId, closureDetails.employeeUserId).first<{ count: number }>();
          if (!(otherAdmins?.count || 0)) return error("Assign another active Organization Admin or CEO before completing this exit so the organization retains an administrator.", 409);
        }
      }
    }
    const updates: Array<[string, unknown]> = [];
    const fields: Record<string, string> = { exitInterviewDate: "exit_interview_date", exitInterviewNotes: "exit_interview_notes", employeeFeedback: "employee_feedback", finalSalary: "final_salary", leavePayout: "leave_payout", deductions: "deductions", outstandingBalance: "outstanding_balance", financeNotes: "finance_notes", referenceDocuments: "reference_documents" };
    for (const [key, column] of Object.entries(fields)) if (body[key as keyof typeof body] !== undefined) updates.push([column, body[key as keyof typeof body] ?? null]);
    if (body.status === "completed") updates.push(["status", "completed"], ["completed_by", context.userId], ["completed_at", new Date().toISOString()]);
    if (body.status === "cancelled") updates.push(["status", "cancelled"]);
    if (updates.length) {
      const setClause = updates.map(([column]) => `${column} = ?`).join(", ");
      const statements = [env.DB.prepare(`UPDATE employee_exit_cases SET ${setClause}, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = 'active'`).bind(...updates.map(([, value]) => value), current.id, context.organizationId)];
      if (body.status === "completed") statements.push(
        env.DB.prepare(`UPDATE employees SET status = 'inactive', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(current.employeeId, context.organizationId),
        env.DB.prepare(`UPDATE memberships SET status = 'inactive' WHERE organization_id = ? AND user_id = (SELECT user_id FROM employees WHERE id = ? AND organization_id = ?) AND status = 'active'`).bind(context.organizationId, current.employeeId, context.organizationId),
      );
      await env.DB.batch(statements);
    }
    await audit(env, context, body.status || "updated", "employee_exit_cases", current.id, { changedFields: updates.map(([column]) => column) });
    return json({ ok: true });
  }
  return error("Exit management endpoint not found.", 404);
}

async function handleHRTalent(request: Request, env: Env, context: AuthContext, path: string): Promise<Response | null> {
  if (!path.startsWith("/api/hr/talent")) return null;
  const canManage = hasPermission(context, "hr.talent.manage");
  const canView = hasPermission(context, "hr.talent.view") || canManage;
  if (!canView) return error("HR talent workspace access is not enabled for this account.", 403);
  const base = "/api/hr/talent";
  if (path === base && request.method === "GET") {
    const employee = await env.DB.prepare(`SELECT id FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string }>();
    const [departments, teams, kpis, pips, checkins, jobs, candidates, courses, enrollments] = await Promise.all([
      env.DB.prepare(`SELECT id, name FROM departments WHERE organization_id = ? ORDER BY name`).bind(context.organizationId).all(),
      env.DB.prepare(`SELECT t.id, t.name, t.department_id as departmentId, d.name as department FROM teams t LEFT JOIN departments d ON d.id = t.department_id WHERE t.organization_id = ? ORDER BY t.name`).bind(context.organizationId).all(),
      canManage ? env.DB.prepare(`SELECT k.id, k.name, k.description, k.metric, k.target, k.weight, k.team_id as teamId, k.employee_id as employeeId, t.name as team, e.first_name || ' ' || e.last_name as employee, k.status, k.created_at as createdAt FROM performance_kpis k LEFT JOIN teams t ON t.id = k.team_id AND t.organization_id = k.organization_id LEFT JOIN employees e ON e.id = k.employee_id AND e.organization_id = k.organization_id WHERE k.organization_id = ? ORDER BY k.status, k.name`).bind(context.organizationId).all() : Promise.resolve({ results: [] }),
      env.DB.prepare(`SELECT p.id, p.employee_id as employeeId, p.created_by as createdBy, p.manager_user_id as managerUserId, p.title, p.concern, p.expected_outcomes as expectedOutcomes, p.support_plan as supportPlan, p.start_date as startDate, p.end_date as endDate, p.status, p.outcome_note as outcomeNote, p.employee_acknowledgment as employeeAcknowledgment, p.acknowledged_at as acknowledgedAt, e.user_id as employeeUserId, e.first_name || ' ' || e.last_name as employeeName, e.job_title as jobTitle, creator.full_name as createdByName FROM performance_improvement_plans p JOIN employees e ON e.id = p.employee_id AND e.organization_id = p.organization_id JOIN users creator ON creator.id = p.created_by WHERE p.organization_id = ? AND (? = 1 OR e.user_id = ? OR p.manager_user_id = ?) ORDER BY p.created_at DESC`).bind(context.organizationId, canManage ? 1 : 0, context.userId, context.userId).all(),
      env.DB.prepare(`SELECT c.id, c.pip_id as pipId, c.check_in_date as checkInDate, c.progress, c.employee_comment as employeeComment, c.next_steps as nextSteps, c.created_by as createdBy, u.full_name as createdByName FROM pip_check_ins c JOIN performance_improvement_plans p ON p.id = c.pip_id AND p.organization_id = c.organization_id JOIN employees e ON e.id = p.employee_id AND e.organization_id = p.organization_id JOIN users u ON u.id = c.created_by WHERE c.organization_id = ? AND (? = 1 OR e.user_id = ? OR p.manager_user_id = ?) ORDER BY c.check_in_date DESC`).bind(context.organizationId, canManage ? 1 : 0, context.userId, context.userId).all(),
      canManage ? env.DB.prepare(`SELECT j.id, j.title, j.department_id as departmentId, d.name as department, j.description, j.employment_type as employmentType, j.location, j.headcount, j.status, j.target_date as targetDate, (SELECT COUNT(*) FROM job_candidates c WHERE c.job_id = j.id AND c.organization_id = j.organization_id) as candidateCount FROM job_requisitions j LEFT JOIN departments d ON d.id = j.department_id AND d.organization_id = j.organization_id WHERE j.organization_id = ? ORDER BY j.created_at DESC`).bind(context.organizationId).all() : Promise.resolve({ results: [] }),
      canManage ? env.DB.prepare(`SELECT c.id, c.job_id as jobId, j.title as jobTitle, c.full_name as fullName, c.email, c.phone, c.source, c.stage, c.notes, c.created_at as createdAt FROM job_candidates c JOIN job_requisitions j ON j.id = c.job_id AND j.organization_id = c.organization_id WHERE c.organization_id = ? ORDER BY c.updated_at DESC`).bind(context.organizationId).all() : Promise.resolve({ results: [] }),
      env.DB.prepare(`SELECT id, title, description, provider, category, duration_hours as durationHours, due_days as dueDays, status FROM learning_courses WHERE organization_id = ? AND status = 'active' ORDER BY title`).bind(context.organizationId).all(),
      env.DB.prepare(`SELECT n.id, n.course_id as courseId, c.title as courseTitle, n.employee_id as employeeId, e.user_id as employeeUserId, e.first_name || ' ' || e.last_name as employeeName, n.status, n.due_date as dueDate, n.completed_at as completedAt, n.notes FROM learning_enrollments n JOIN learning_courses c ON c.id = n.course_id AND c.organization_id = n.organization_id JOIN employees e ON e.id = n.employee_id AND e.organization_id = n.organization_id WHERE n.organization_id = ? AND (? = 1 OR e.user_id = ? OR e.manager_id = ?) ORDER BY n.due_date`).bind(context.organizationId, canManage ? 1 : 0, context.userId, employee?.id || "").all(),
    ]);
    return json({ canManage, employeeId: employee?.id || null, departments: departments.results || [], teams: teams.results || [], kpis: kpis.results || [], pips: pips.results || [], checkins: checkins.results || [], jobs: jobs.results || [], candidates: candidates.results || [], courses: courses.results || [], enrollments: enrollments.results || [] });
  }

  if (request.method === "POST" && path === `${base}/kpis`) {
    if (!canManage) return error("HR administrator access is required to define KPIs.", 403);
    const body = await request.json<{ name?: string; description?: string; metric?: string; target?: string; weight?: number; teamId?: string; employeeId?: string }>();
    const name = body.name?.trim(), metric = body.metric?.trim(), target = body.target?.trim(), weight = Number(body.weight ?? 100);
    if (!name || name.length > 140 || !metric || !target || !Number.isInteger(weight) || weight < 1 || weight > 100 || (body.teamId && body.employeeId)) return error("Enter a KPI name, measurement, target, weight (1–100), and at most one team or employee scope.");
    if (body.teamId && !await env.DB.prepare(`SELECT id FROM teams WHERE id = ? AND organization_id = ?`).bind(body.teamId, context.organizationId).first()) return error("Team not found in this organization.");
    if (body.employeeId && !await env.DB.prepare(`SELECT id FROM employees WHERE id = ? AND organization_id = ? AND deleted_at IS NULL`).bind(body.employeeId, context.organizationId).first()) return error("Employee not found in this organization.");
    const id = `kpi-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO performance_kpis (id, organization_id, name, description, metric, target, weight, team_id, employee_id, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, name, body.description?.trim().slice(0, 2000) || null, metric, target, weight, body.teamId || null, body.employeeId || null, context.userId).run();
    await audit(env, context, "created", "performance_kpis", id, { name, teamId: body.teamId || null, employeeId: body.employeeId || null });
    return json({ id }, { status: 201 });
  }
  const kpiMatch = path.match(/^\/api\/hr\/talent\/kpis\/([^/]+)$/);
  if (request.method === "PATCH" && kpiMatch) {
    if (!canManage) return error("HR administrator access is required.", 403);
    const body = await request.json<{ status?: string }>();
    if (!['active','archived'].includes(body.status || "")) return error("Choose active or archived.");
    const result = await env.DB.prepare(`UPDATE performance_kpis SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(body.status, kpiMatch[1], context.organizationId).run();
    if (!result.meta.changes) return error("KPI not found.", 404);
    await audit(env, context, body.status === "archived" ? "archived" : "restored", "performance_kpis", kpiMatch[1]);
    return json({ ok: true });
  }

  if (request.method === "POST" && path === `${base}/pips`) {
    if (!canManage) return error("HR administrator access is required to open a performance improvement plan.", 403);
    const body = await request.json<{ employeeId?: string; title?: string; concern?: string; expectedOutcomes?: string; supportPlan?: string; startDate?: string; endDate?: string }>();
    const employee = body.employeeId ? await env.DB.prepare(`SELECT e.id, e.user_id as userId, e.manager_id as managerId, manager.user_id as managerUserId FROM employees e LEFT JOIN employees manager ON manager.id = e.manager_id AND manager.organization_id = e.organization_id WHERE e.id = ? AND e.organization_id = ? AND e.deleted_at IS NULL`).bind(body.employeeId, context.organizationId).first<{ id: string; userId: string | null; managerId: string | null; managerUserId: string | null }>() : null;
    if (!employee || !body.title?.trim() || !body.concern?.trim() || !body.expectedOutcomes?.trim() || !body.supportPlan?.trim() || !body.startDate || !body.endDate || body.endDate < body.startDate) return error("Choose an employee and enter the concern, measurable outcomes, support plan and valid plan dates.");
    const id = `pip-${crypto.randomUUID()}`;
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO performance_improvement_plans (id, organization_id, employee_id, created_by, manager_user_id, title, concern, expected_outcomes, support_plan, start_date, end_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, employee.id, context.userId, employee.managerUserId || context.userId, body.title.trim(), body.concern.trim(), body.expectedOutcomes.trim(), body.supportPlan.trim(), body.startDate, body.endDate),
      ...(employee.userId ? [env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'pip_assigned', ?, ?)`).bind(requestId(), context.organizationId, employee.userId, "Performance improvement plan", `${body.title.trim()} is ready for you to review. Please read the support plan and acknowledge it.`)] : []),
    ]);
    await audit(env, context, "created", "performance_improvement_plans", id, { employeeId: employee.id, endDate: body.endDate });
    return json({ id }, { status: 201 });
  }
  const pipMatch = path.match(/^\/api\/hr\/talent\/pips\/([^/]+)(?:\/(checkins|acknowledge))?$/);
  if (pipMatch && request.method === "POST" && pipMatch[2] === "checkins") {
    const pip = await env.DB.prepare(`SELECT p.id, e.user_id as employeeUserId, p.manager_user_id as managerUserId FROM performance_improvement_plans p JOIN employees e ON e.id = p.employee_id AND e.organization_id = p.organization_id WHERE p.id = ? AND p.organization_id = ?`).bind(pipMatch[1], context.organizationId).first<{ id: string; employeeUserId: string | null; managerUserId: string | null }>();
    if (!pip) return error("Improvement plan not found.", 404);
    if (!canManage && context.userId !== pip.managerUserId && context.userId !== pip.employeeUserId) return error("Only HR, the employee or their line manager may add a check-in.", 403);
    const body = await request.json<{ checkInDate?: string; progress?: string; employeeComment?: string; nextSteps?: string }>();
    if (!body.checkInDate || !/^\d{4}-\d{2}-\d{2}$/.test(body.checkInDate) || !body.progress?.trim() || !body.nextSteps?.trim()) return error("Enter the check-in date, progress update and next steps.");
    const id = `pip-checkin-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO pip_check_ins (id, organization_id, pip_id, created_by, check_in_date, progress, employee_comment, next_steps) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, pip.id, context.userId, body.checkInDate, body.progress.trim(), body.employeeComment?.trim() || null, body.nextSteps.trim()).run();
    await audit(env, context, "created", "pip_check_ins", id, { pipId: pip.id });
    return json({ id }, { status: 201 });
  }
  if (pipMatch && request.method === "POST" && pipMatch[2] === "acknowledge") {
    const body = await request.json<{ acknowledgment?: string }>();
    const result = await env.DB.prepare(`UPDATE performance_improvement_plans SET employee_acknowledgment = ?, acknowledged_at = CURRENT_TIMESTAMP, status = CASE WHEN status = 'proposed' THEN 'active' ELSE status END, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND employee_id IN (SELECT id FROM employees WHERE user_id = ? AND organization_id = ?)`).bind(body.acknowledgment?.trim() || "Acknowledged", pipMatch[1], context.organizationId, context.userId, context.organizationId).run();
    if (!result.meta.changes) return error("This improvement plan is not assigned to your employee profile.", 404);
    await audit(env, context, "employee_acknowledged", "performance_improvement_plans", pipMatch[1]);
    return json({ ok: true });
  }
  if (pipMatch && request.method === "PATCH" && !pipMatch[2]) {
    if (!canManage) return error("HR administrator access is required to update plan status.", 403);
    const body = await request.json<{ status?: string; outcomeNote?: string }>();
    if (!['proposed','active','completed','extended','unsuccessful','cancelled'].includes(body.status || "")) return error("Choose a valid improvement plan status.");
    const result = await env.DB.prepare(`UPDATE performance_improvement_plans SET status = ?, outcome_note = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(body.status, body.outcomeNote?.trim() || null, pipMatch[1], context.organizationId).run();
    if (!result.meta.changes) return error("Improvement plan not found.", 404);
    await audit(env, context, `status_${body.status}`, "performance_improvement_plans", pipMatch[1]);
    return json({ ok: true });
  }

  if (request.method === "POST" && path === `${base}/jobs`) {
    if (!canManage) return error("HR administrator access is required to open a recruitment request.", 403);
    const body = await request.json<{ title?: string; departmentId?: string; description?: string; employmentType?: string; location?: string; headcount?: number; targetDate?: string }>();
    const headcount = Number(body.headcount || 1);
    if (!body.title?.trim() || !body.description?.trim() || !body.employmentType?.trim() || !Number.isInteger(headcount) || headcount < 1 || headcount > 1000) return error("Enter the position, description, employment type and a valid headcount.");
    if (body.departmentId && !await env.DB.prepare(`SELECT id FROM departments WHERE id = ? AND organization_id = ?`).bind(body.departmentId, context.organizationId).first()) return error("Department not found.");
    const id = `job-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO job_requisitions (id, organization_id, title, department_id, description, employment_type, location, headcount, owner_user_id, target_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, body.title.trim(), body.departmentId || null, body.description.trim(), body.employmentType, body.location?.trim() || null, headcount, context.userId, body.targetDate || null).run();
    await audit(env, context, "opened", "job_requisitions", id, { title: body.title, headcount });
    return json({ id }, { status: 201 });
  }
  const jobMatch = path.match(/^\/api\/hr\/talent\/jobs\/([^/]+)$/);
  if (request.method === "PATCH" && jobMatch) {
    if (!canManage) return error("HR administrator access is required.", 403);
    const body = await request.json<{ status?: string }>();
    if (!['open','on_hold','closed'].includes(body.status || "")) return error("Choose open, on hold or closed.");
    const result = await env.DB.prepare(`UPDATE job_requisitions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(body.status, jobMatch[1], context.organizationId).run();
    if (!result.meta.changes) return error("Recruitment requisition not found.", 404);
    await audit(env, context, `requisition_${body.status}`, "job_requisitions", jobMatch[1]);
    return json({ ok: true });
  }
  const candidateMatch = path.match(/^\/api\/hr\/talent\/candidates\/([^/]+)$/);
  if (request.method === "POST" && path === `${base}/candidates`) {
    if (!canManage) return error("HR administrator access is required to add candidates.", 403);
    const body = await request.json<{ jobId?: string; fullName?: string; email?: string; phone?: string; source?: string; notes?: string }>();
    const job = body.jobId ? await env.DB.prepare(`SELECT id FROM job_requisitions WHERE id = ? AND organization_id = ? AND status != 'closed'`).bind(body.jobId, context.organizationId).first() : null;
    if (!job || !body.fullName?.trim() || !body.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) return error("Choose an open role and enter the candidate name and a valid email.");
    const id = `candidate-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO job_candidates (id, organization_id, job_id, full_name, email, phone, source, notes, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, body.jobId, body.fullName.trim(), body.email.trim().toLowerCase(), body.phone?.trim() || null, body.source?.trim() || null, body.notes?.trim() || null, context.userId).run();
    await audit(env, context, "candidate_added", "job_candidates", id, { jobId: body.jobId });
    return json({ id }, { status: 201 });
  }
  if (request.method === "PATCH" && candidateMatch) {
    if (!canManage) return error("HR administrator access is required.", 403);
    const body = await request.json<{ stage?: string; notes?: string }>();
    if (!['applied','screening','interview','assessment','offer','hired','rejected'].includes(body.stage || "")) return error("Choose a valid recruitment stage.");
    const result = await env.DB.prepare(`UPDATE job_candidates SET stage = ?, notes = COALESCE(?, notes), updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(body.stage, body.notes?.trim() || null, candidateMatch[1], context.organizationId).run();
    if (!result.meta.changes) return error("Candidate not found.", 404);
    await audit(env, context, `candidate_${body.stage}`, "job_candidates", candidateMatch[1]);
    return json({ ok: true });
  }

  if (request.method === "POST" && path === `${base}/courses`) {
    if (!canManage) return error("HR administrator access is required to create learning content.", 403);
    const body = await request.json<{ title?: string; description?: string; provider?: string; category?: string; durationHours?: number; dueDays?: number }>();
    const hours = Number(body.durationHours || 0), dueDays = body.dueDays ? Number(body.dueDays) : null;
    if (!body.title?.trim() || !body.description?.trim() || !Number.isFinite(hours) || hours < 0 || (dueDays !== null && (!Number.isInteger(dueDays) || dueDays < 1 || dueDays > 730))) return error("Enter a course title, description and valid duration or deadline.");
    const id = `course-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO learning_courses (id, organization_id, title, description, provider, category, duration_hours, due_days, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, body.title.trim(), body.description.trim(), body.provider?.trim() || null, body.category?.trim() || "Professional development", hours, dueDays, context.userId).run();
    await audit(env, context, "created", "learning_courses", id, { title: body.title });
    return json({ id }, { status: 201 });
  }
  if (request.method === "POST" && path === `${base}/enrollments`) {
    if (!canManage) return error("HR administrator access is required to assign courses.", 403);
    const body = await request.json<{ courseId?: string; employeeId?: string; dueDate?: string }>();
    const valid = body.courseId && body.employeeId && await env.DB.prepare(`SELECT c.id FROM learning_courses c JOIN employees e ON e.id = ? AND e.organization_id = c.organization_id AND e.status = 'active' WHERE c.id = ? AND c.organization_id = ? AND c.status = 'active'`).bind(body.employeeId, body.courseId, context.organizationId).first();
    if (!valid) return error("Choose an active course and an active employee in this organization.");
    const id = `learning-${crypto.randomUUID()}`;
    try { await env.DB.prepare(`INSERT INTO learning_enrollments (id, organization_id, course_id, employee_id, assigned_by, due_date) VALUES (?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, body.courseId, body.employeeId, context.userId, body.dueDate || null).run(); }
    catch { return error("This course has already been assigned to that employee.", 409); }
    const user = await env.DB.prepare(`SELECT user_id as userId FROM employees WHERE id = ? AND organization_id = ?`).bind(body.employeeId, context.organizationId).first<{ userId: string | null }>();
    if (user?.userId) await env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'learning_assigned', ?, ?)`).bind(requestId(), context.organizationId, user.userId, "Learning assigned", "A new learning course is available in your HR workspace.").run();
    await audit(env, context, "assigned", "learning_enrollments", id, { employeeId: body.employeeId, courseId: body.courseId });
    return json({ id }, { status: 201 });
  }
  const enrollmentMatch = path.match(/^\/api\/hr\/talent\/enrollments\/([^/]+)$/);
  if (request.method === "PATCH" && enrollmentMatch) {
    const body = await request.json<{ status?: string; notes?: string }>();
    const assignment = await env.DB.prepare(`SELECT n.id, e.user_id as employeeUserId FROM learning_enrollments n JOIN employees e ON e.id = n.employee_id AND e.organization_id = n.organization_id WHERE n.id = ? AND n.organization_id = ?`).bind(enrollmentMatch[1], context.organizationId).first<{ id: string; employeeUserId: string | null }>();
    if (!assignment) return error("Learning assignment not found.", 404);
    if (!canManage && assignment.employeeUserId !== context.userId) return error("Only HR or the assigned learner may update this course.", 403);
    if (!['assigned','in_progress','completed','waived'].includes(body.status || "") || (!canManage && body.status === "waived")) return error("Choose a valid course progress status.");
    await env.DB.prepare(`UPDATE learning_enrollments SET status = ?, completed_at = CASE WHEN ? = 'completed' THEN CURRENT_TIMESTAMP ELSE completed_at END, notes = COALESCE(?, notes), updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(body.status, body.status, body.notes?.trim() || null, assignment.id, context.organizationId).run();
    await audit(env, context, `learning_${body.status}`, "learning_enrollments", assignment.id);
    return json({ ok: true });
  }
  return error("HR talent endpoint not found.", 404);
}

async function dashboard(env: Env, context: AuthContext) {
  const { organizationId, userId } = context;
  const moduleRows = await env.DB.prepare(`SELECT m.module_key as moduleKey FROM organization_modules m LEFT JOIN module_subscriptions s ON s.organization_id=m.organization_id AND s.module_key=m.module_key WHERE m.organization_id=? AND m.enabled=1 AND (s.id IS NULL OR (s.status='active' AND (s.ends_at IS NULL OR datetime(s.ends_at)>CURRENT_TIMESTAMP)))`).bind(organizationId).all<{ moduleKey: string }>();
  const activeModules = new Set((moduleRows.results || []).map((item) => item.moduleKey));
  const employee = await env.DB.prepare(`SELECT id FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(organizationId, userId).first<{ id: string }>();
  const canManageLeave = hasPermission(context, "employees.manage") || hasPermission(context, "hr.onboarding.approve");
  const canViewAllRequests = hasPermission(context, "requests.manage");
  const [people, leave, visibleLeave, requests, projects, tasks, expenses, departments, recentActivity] = await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active, SUM(CASE WHEN status = 'on_leave' THEN 1 ELSE 0 END) as onLeave FROM employees WHERE organization_id = ? AND deleted_at IS NULL`).bind(organizationId).first<{ total: number; active: number; onLeave: number }>(),
    env.DB.prepare(`SELECT COUNT(*) as pending FROM leave_requests WHERE organization_id = ? AND status = 'pending'`).bind(organizationId).first<{ pending: number }>(),
    env.DB.prepare(`SELECT COUNT(*) as pending FROM leave_requests l JOIN employees e ON e.id = l.employee_id AND e.organization_id = l.organization_id WHERE l.organization_id = ? AND l.status = 'pending' AND (? = 1 OR e.user_id = ? OR e.manager_id = ?)`).bind(organizationId, canManageLeave ? 1 : 0, userId, employee?.id || "").first<{ pending: number }>(),
    env.DB.prepare(`SELECT COUNT(*) as pending FROM approval_requests WHERE organization_id = ? AND status = 'pending' AND (? = 1 OR requester_id = ?)`).bind(organizationId, canViewAllRequests ? 1 : 0, userId).first<{ pending: number }>(),
    env.DB.prepare(`SELECT COUNT(*) as active FROM projects WHERE organization_id = ? AND status IN ('active','at_risk')`).bind(organizationId).first<{ active: number }>(),
    env.DB.prepare(`SELECT COUNT(*) as overdue FROM tasks WHERE organization_id = ? AND status != 'completed' AND due_date < date('now')`).bind(organizationId).first<{ overdue: number }>(),
    env.DB.prepare(`SELECT COALESCE(SUM(amount),0) as total FROM expenses WHERE organization_id = ? AND strftime('%Y-%m', expense_date) = strftime('%Y-%m', 'now')`).bind(organizationId).first<{ total: number }>(),
    env.DB.prepare(`SELECT d.name, COUNT(e.id) as count FROM departments d LEFT JOIN employees e ON e.department_id = d.id AND e.deleted_at IS NULL WHERE d.organization_id = ? GROUP BY d.id ORDER BY count DESC`).bind(organizationId).all(),
    env.DB.prepare(`SELECT action, module, created_at FROM audit_logs WHERE organization_id = ? ORDER BY created_at DESC LIMIT 6`).bind(organizationId).all(),
  ]);
  return {
    people: activeModules.has("hr") ? people || { total: 0, active: 0, onLeave: 0 } : { total: 0, active: 0, onLeave: 0 },
    leave: activeModules.has("hr") ? { pending: leave?.pending || 0, visiblePending: visibleLeave?.pending || 0 } : { pending: 0, visiblePending: 0 },
    requests: activeModules.has("finance") ? requests || { pending: 0 } : { pending: 0 },
    projects: activeModules.has("projects") ? projects || { active: 0 } : { active: 0 },
    tasks: activeModules.has("operations") ? tasks || { overdue: 0 } : { overdue: 0 },
    expenses: activeModules.has("finance") ? expenses || { total: 0 } : { total: 0 },
    departments: activeModules.has("hr") ? departments.results || [] : [],
    recentActivity: recentActivity.results || [],
  };
}

async function handleApi(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const mobilePath = url.pathname.startsWith("/api/mobile/");
  const path = mobilePath ? url.pathname.replace("/api/mobile", "/api") : url.pathname;

  if (request.method === "GET" && path === "/api/health") {
    return json({ ok: true, service: "zyntris-operations", environment: env.ENVIRONMENT, d1: Boolean(env.DB), r2: Boolean(env.FILES), timestamp: new Date().toISOString() });
  }

  if (!mobilePath && ["POST", "PUT", "PATCH", "DELETE"].includes(request.method) && !originAllowed(request, env)) return error("Request origin rejected", 403);

  if (mobilePath && request.method === "POST" && path === "/api/auth/login") {
    if (!(await consumeAuthLimit(env, request, "login", 20, 15))) return error("Too many sign-in attempts. Try again later.", 429);
    const body = await request.json<{ email?: string; password?: string }>();
    const email = body.email?.trim().toLowerCase() || "";
    if (email && !(await consumeAuthLimit(env, request, "login", 8, 15, email))) return error("Too many sign-in attempts. Try again later.", 429);
    const user = await env.DB.prepare(`SELECT id, password_hash as passwordHash, email_verified_at as verifiedAt, status FROM users WHERE email = ?`).bind(email).first<{ id: string; passwordHash: string | null; verifiedAt: string | null; status: string }>();
    if (!user?.passwordHash || user.status !== "active" || !(await verifyPassword(body.password || "", user.passwordHash, env.PASSWORD_PEPPER))) return error("Email or password is incorrect.", 401);
    await upgradeLegacyPassword(env, user.id, body.password || "", user.passwordHash);
    if (!user.verifiedAt) return error("Please verify your email address before signing in.", 403);
    const membership = await env.DB.prepare(`SELECT organization_id as organizationId FROM memberships WHERE user_id = ? AND status = 'active' ORDER BY created_at LIMIT 1`).bind(user.id).first<{ organizationId: string }>();
    if (!membership) return error("No active organization is linked to this account.", 403);
    const accessError = await workspaceAccessError(env, membership.organizationId);
    if (accessError) return error(accessError, 403);
    const factor = await env.DB.prepare(`SELECT enabled_at as enabledAt FROM user_two_factor WHERE user_id = ?`).bind(user.id).first<{ enabledAt: string | null }>();
    if (factor?.enabledAt) return issueTwoFactorChallenge(env, user.id, membership.organizationId, true);
    const accessToken = await createSession(env, user.id, membership.organizationId);
    await env.DB.prepare(`INSERT INTO audit_logs (id, organization_id, actor_user_id, action, module, record_type) VALUES (?, ?, ?, 'signed_in', 'authentication', 'mobile_session')`).bind(`audit-${crypto.randomUUID()}`, membership.organizationId, user.id).run();
    return json({ accessToken, tokenType: "Bearer", expiresIn: 43200 });
  }

  if (mobilePath && request.method === "POST" && path === "/api/auth/logout") {
    const token = request.headers.get("authorization")?.match(/^Bearer\s+([a-f0-9]{64})$/i)?.[1];
    if (token) await env.DB.prepare(`DELETE FROM sessions WHERE token_hash = ?`).bind(await hashToken(token)).run();
    return json({ ok: true });
  }

    const publicAuth = await handlePublicAuth(request, env, path, mobilePath);
  if (publicAuth) return publicAuth;

  if (request.method === "POST" && path === "/api/auth/logout") {
    if (!originAllowed(request, env)) return error("Request origin rejected", 403);
    const token = getCookie(request, "zyntris_session");
    if (token) await env.DB.prepare(`DELETE FROM sessions WHERE token_hash = ?`).bind(await hashToken(decodeURIComponent(token))).run();
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json", "cache-control": "private, no-store", "set-cookie": setCookie("zyntris_session", "", 0) } });
  }

  const secured = await requireAuth(request, env);
  if ("response" in secured && secured.response) return secured.response;
  const context = secured.context;

  if (context.mfaEnrollmentRequired && !mfaEnrollmentAllowed(path, request.method)) return error("Authenticator-based two-factor authentication is required before using this privileged account. Open Account security to complete setup.", 403);

  const requiredModule = requiredTenantModule(path);
  if (requiredModule) {
    const entitlement = await env.DB.prepare(`SELECT m.enabled,s.status,CASE WHEN s.ends_at IS NULL OR datetime(s.ends_at)>CURRENT_TIMESTAMP THEN 1 ELSE 0 END as withinTerm FROM organization_modules m LEFT JOIN module_subscriptions s ON s.organization_id=m.organization_id AND s.module_key=m.module_key WHERE m.organization_id=? AND m.module_key=?`).bind(context.organizationId, requiredModule).first<{ enabled: number; status: string | null; withinTerm: number }>();
    const subscriptionActive = !entitlement?.status || (entitlement.status === "active" && entitlement.withinTerm === 1);
    if (!entitlement || entitlement.enabled !== 1 || !subscriptionActive) return error(`The ${requiredModule.replaceAll("_", " ")} module is not active for this organization. Contact your Zyntris administrator.`, 403);
  }

  if (request.method === "POST" && path === "/api/auth/activity") {
    if (!originAllowed(request, env)) return error("Request origin rejected", 403);
    const token = mobilePath ? request.headers.get("authorization")?.match(/^Bearer\s+([a-f0-9]{64})$/i)?.[1] : getCookie(request, "zyntris_session");
    if (!token) return error("Authentication required", 401);
    const touched = await env.DB.prepare(`UPDATE sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP AND last_seen_at > datetime('now', '-2 minutes')`).bind(await hashToken(decodeURIComponent(token))).run();
    if (touched.meta.changes !== 1) return error("Your session expired after inactivity. Sign in again.", 401);
    return json({ ok: true });
  }

  if (context.isDemo && ["POST", "PUT", "PATCH", "DELETE"].includes(request.method)) return error("The demo sandbox is read-only. Changes are not allowed.", 403);

  if (mobilePath && path === "/api/push-token" && request.method === "POST") {
    const body = await request.json<{ token?: string; platform?: string }>();
    if (!body.token || body.token.length > 250 || !/^(Expo|Exponent)PushToken\[[A-Za-z0-9_-]+\]$/.test(body.token) || !["ios","android"].includes(body.platform || "")) return error("A valid Expo push token and iOS or Android platform are required.");
    await env.DB.prepare(`INSERT INTO mobile_push_tokens (id, organization_id, user_id, token, platform) VALUES (?, ?, ?, ?, ?) ON CONFLICT(token) DO UPDATE SET organization_id = excluded.organization_id, user_id = excluded.user_id, platform = excluded.platform, updated_at = CURRENT_TIMESTAMP`).bind(`push-${crypto.randomUUID()}`, context.organizationId, context.userId, body.token, body.platform).run();
    return json({ ok: true });
  }
  if (mobilePath && path === "/api/push-token" && request.method === "DELETE") {
    const body = await request.json<{ token?: string }>();
    if (body.token) await env.DB.prepare(`DELETE FROM mobile_push_tokens WHERE token = ? AND organization_id = ? AND user_id = ?`).bind(body.token, context.organizationId, context.userId).run();
    else await env.DB.prepare(`DELETE FROM mobile_push_tokens WHERE organization_id = ? AND user_id = ?`).bind(context.organizationId, context.userId).run();
    return json({ ok: true });
  }

  if (path === "/api/calendar/connections" && request.method === "GET") {
    const connections = await env.DB.prepare(`SELECT provider, scopes, last_synced_at as lastSyncedAt, sync_error as syncError, revoked_at as revokedAt FROM calendar_provider_connections WHERE organization_id = ? AND user_id = ? ORDER BY provider`).bind(context.organizationId, context.userId).all();
    return json({ data: connections.results || [], configuredProviders: { google: Boolean(env.GOOGLE_CALENDAR_CLIENT_ID && env.GOOGLE_CALENDAR_CLIENT_SECRET), microsoft: Boolean(env.MICROSOFT_CALENDAR_CLIENT_ID && env.MICROSOFT_CALENDAR_CLIENT_SECRET) } });
  }
  if (path === "/api/calendar/connect" && request.method === "POST") {
    const body = await request.json<{ provider?: string }>(); const provider = body.provider;
    if (!hasPermission(context, "operations.view") || !["google","microsoft"].includes(provider || "")) return error("Calendar access is not enabled or provider is invalid.", 403);
    const google = provider === "google";
    const clientId = google ? env.GOOGLE_CALENDAR_CLIENT_ID : env.MICROSOFT_CALENDAR_CLIENT_ID;
    if (!clientId) return error(`Set the ${google ? "GOOGLE_CALENDAR_CLIENT_ID" : "MICROSOFT_CALENDAR_CLIENT_ID"} Worker variable before connecting this provider.`, 409);
    if (!env.SESSION_SECRET) return error("Calendar integration requires SESSION_SECRET for encrypted token storage.", 409);
    const state = crypto.randomUUID().replaceAll("-", "") + crypto.randomUUID().replaceAll("-", "");
    await env.DB.prepare(`INSERT INTO calendar_oauth_states (token_hash, organization_id, user_id, provider, expires_at) VALUES (?, ?, ?, ?, datetime('now','+10 minutes'))`).bind(await hashToken(state), context.organizationId, context.userId, provider).run();
    const redirectUri = `${env.APP_ORIGIN}/api/calendar/oauth/callback`;
    const authUrl = google ? new URL("https://accounts.google.com/o/oauth2/v2/auth") : new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
    authUrl.search = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: "code", response_mode: "query", scope: google ? "https://www.googleapis.com/auth/calendar.events.owned" : "offline_access https://graph.microsoft.com/Calendars.ReadWrite", state, ...(google ? { access_type: "offline", prompt: "consent" } : { prompt: "select_account" }) }).toString();
    return json({ authUrl: authUrl.toString() });
  }
  const calendarConnectionMatch = path.match(/^\/api\/calendar\/connections\/(google|microsoft)$/);
  if (calendarConnectionMatch && request.method === "DELETE") {
    await env.DB.prepare(`UPDATE calendar_provider_connections SET revoked_at = CURRENT_TIMESTAMP, encrypted_tokens = '', sync_cursor = NULL, updated_at = CURRENT_TIMESTAMP WHERE organization_id = ? AND user_id = ? AND provider = ?`).bind(context.organizationId, context.userId, calendarConnectionMatch[1]).run();
    await audit(env, context, "disconnected", "calendar_provider_connections", calendarConnectionMatch[1]);
    return json({ ok: true });
  }

  if (request.method === "GET" && path === "/api/search") {
    const query = new URL(request.url).searchParams.get("q")?.trim().slice(0, 100) || "";
    if (query.length < 2) return json({ data: [] });
    const like = `%${query}%`; const data: { id: string; title: string; subtitle: string; module: string }[] = [];
    const add = (rows: { results?: unknown[] }) => data.push(...(rows.results || []) as typeof data);
    if (hasPermission(context, "employees.view")) add(await env.DB.prepare(`SELECT e.id, e.first_name || ' ' || e.last_name as title, e.job_title || ' · ' || COALESCE(d.name,'No department') as subtitle, 'employees' as module FROM employees e LEFT JOIN departments d ON d.id = e.department_id AND d.organization_id = e.organization_id WHERE e.organization_id = ? AND e.deleted_at IS NULL AND (e.first_name LIKE ? OR e.last_name LIKE ? OR e.email LIKE ? OR e.job_title LIKE ? OR d.name LIKE ?) ORDER BY e.first_name LIMIT 8`).bind(context.organizationId, like, like, like, like, like).all());
    if (hasPermission(context, "operations.view")) {
      const employee = await env.DB.prepare(`SELECT id FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string }>();
      const canManage = hasPermission(context, "operations.manage");
      add(await env.DB.prepare(`SELECT t.id, t.title, COALESCE(p.name,'Task') || ' · ' || t.status as subtitle, 'tasks' as module FROM tasks t LEFT JOIN projects p ON p.id = t.project_id AND p.organization_id = t.organization_id WHERE t.organization_id = ? AND (? = 1 OR t.assignee_id = ? OR t.creator_id = ?) AND (t.title LIKE ? OR COALESCE(t.description,'') LIKE ?) ORDER BY t.updated_at DESC LIMIT 8`).bind(context.organizationId, canManage ? 1 : 0, employee?.id || "", context.userId, like, like).all());
      add(await env.DB.prepare(`SELECT id, name as title, COALESCE(description,'') || ' · ' || status as subtitle, 'projects' as module FROM projects WHERE organization_id = ? AND (name LIKE ? OR COALESCE(description,'') LIKE ?) ORDER BY updated_at DESC LIMIT 8`).bind(context.organizationId, like, like).all());
      add(await env.DB.prepare(`SELECT id, name as title, category || ' · ' || status as subtitle, 'vendors' as module FROM vendors WHERE organization_id = ? AND (name LIKE ? OR category LIKE ? OR COALESCE(contact_name,'') LIKE ?) ORDER BY updated_at DESC LIMIT 8`).bind(context.organizationId, like, like, like).all());
      add(await env.DB.prepare(`SELECT id, subject as title, ticket_number || ' · ' || status as subtitle, 'helpdesk' as module FROM support_tickets WHERE organization_id = ? AND (subject LIKE ? OR ticket_number LIKE ? OR COALESCE(description,'') LIKE ?) ORDER BY updated_at DESC LIMIT 8`).bind(context.organizationId, like, like, like).all());
      add(await env.DB.prepare(`SELECT id, name as title, category as subtitle, 'documents' as module FROM documents WHERE organization_id = ? AND (name LIKE ? OR category LIKE ?) ORDER BY created_at DESC LIMIT 8`).bind(context.organizationId, like, like).all());
      add(await env.DB.prepare(`SELECT id, COALESCE(company,name) as title, name || ' · ' || stage as subtitle, 'customers' as module FROM customers WHERE organization_id = ? AND (name LIKE ? OR company LIKE ? OR email LIKE ?) ORDER BY updated_at DESC LIMIT 8`).bind(context.organizationId, like, like, like).all());
    }
    if (hasPermission(context, "hr.talent.view") || hasPermission(context, "hr.talent.manage")) add(await env.DB.prepare(`SELECT id, title, category as subtitle, 'talent' as module FROM learning_courses WHERE organization_id = ? AND status = 'active' AND (title LIKE ? OR description LIKE ?) ORDER BY updated_at DESC LIMIT 8`).bind(context.organizationId, like, like).all());
    if (hasPermission(context, "goals.view")) add(await env.DB.prepare(`SELECT id, title, level || ' goal · ' || status as subtitle, 'goals' as module FROM goals WHERE organization_id = ? AND title LIKE ? ORDER BY updated_at DESC LIMIT 8`).bind(context.organizationId, like).all());
    const activeRows = await env.DB.prepare(`SELECT m.module_key as moduleKey FROM organization_modules m LEFT JOIN module_subscriptions s ON s.organization_id=m.organization_id AND s.module_key=m.module_key WHERE m.organization_id=? AND m.enabled=1 AND (s.id IS NULL OR (s.status='active' AND (s.ends_at IS NULL OR datetime(s.ends_at)>CURRENT_TIMESTAMP)))`).bind(context.organizationId).all<{ moduleKey: string }>();
    const activeModules = new Set((activeRows.results || []).map((item) => item.moduleKey));
    const resultModule = (module: string) => ["employees", "talent", "goals"].includes(module) ? "hr" : ["tasks", "vendors", "helpdesk", "documents"].includes(module) ? "operations" : module === "projects" ? "projects" : module === "customers" ? "crm" : null;
    return json({ data: data.filter((item) => { const required = resultModule(item.module); return !required || activeModules.has(required); }).slice(0, 50) });
  }

  const exitManagementResponse = await handleExitManagement(request, env, context, path);
  if (exitManagementResponse) return exitManagementResponse;
  const talentResponse = await handleHRTalent(request, env, context, path);
  if (talentResponse) return talentResponse;
  const appraisalResponse = await handleAppraisals(request, env, context, path);
  if (appraisalResponse) return appraisalResponse;

  if (request.method === "POST" && path === "/api/settings/email/test") {
    if (!hasPermission(context, "settings.manage")) return error("Organization administrator permission is required to test email delivery.", 403);
    if (!env.BREVO_API_KEY) return error("Brevo is not configured. Add the BREVO_API_KEY Worker secret.", 503);
    const sender = brevoSender(env);
    try {
      const response = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: { "api-key": env.BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({
          sender, to: [{ email: context.email }], subject: "Zyntris email delivery test",
          textContent: `This test confirms that Zyntris can submit transactional email through Brevo. Sender: ${sender.email}.`,
          htmlContent: `<p>This test confirms that Zyntris can submit transactional email through Brevo.</p><p>Sender: ${sender.email}.</p>`,
        }),
      });
      const result = await response.json().catch(() => ({})) as { messageId?: string; code?: string; message?: string };
      if (!response.ok) {
        console.error("Brevo test email was rejected", { status: response.status, code: result.code || "unknown", message: result.message?.slice(0, 240) || "No provider detail" });
        if (response.status === 401 || response.status === 403) return error("Brevo rejected its API key. Update the BREVO_API_KEY Worker secret.", 502);
        if (response.status === 400) return error("Brevo rejected this message. Verify the sender identity and recipient address in Brevo.", 502);
        return error(`Brevo did not accept the test email (HTTP ${response.status}). Check the sender setup and retry.`, 502);
      }
      return json({ accepted: true, recipient: context.email, sender: sender.email, messageId: result.messageId || null });
    } catch (cause) {
      console.error("Brevo test email request failed", cause instanceof Error ? cause.name : "Unknown network error");
      return error("Zyntris could not reach Brevo. Check connectivity and retry.", 502);
    }
  }

  if (request.method === "GET" && path === "/api/auth/2fa/status") {
    const [factor, recovery] = await Promise.all([
      env.DB.prepare(`SELECT enabled_at as enabledAt FROM user_two_factor WHERE user_id = ?`).bind(context.userId).first<{ enabledAt: string | null }>(),
      env.DB.prepare(`SELECT COUNT(*) as remaining FROM two_factor_recovery_codes WHERE user_id = ? AND used_at IS NULL`).bind(context.userId).first<{ remaining: number }>(),
    ]);
    return json({ enabled: Boolean(factor?.enabledAt), enabledAt: factor?.enabledAt || null, recoveryCodesRemaining: recovery?.remaining || 0 });
  }

  if (request.method === "POST" && path === "/api/auth/2fa/setup") {
    if (!(await consumeAuthLimit(env, request, "2fa-setup", 10, 15, context.userId))) return error("Too many authenticator setup attempts. Try again later.", 429);
    const body = await request.json<{ password?: string }>();
    if (!body.password || body.password.length > 128) return error("Enter your current password to set up two-factor authentication.");
    const user = await env.DB.prepare(`SELECT password_hash as passwordHash FROM users WHERE id = ? AND status = 'active'`).bind(context.userId).first<{ passwordHash: string | null }>();
    if (!user?.passwordHash || !(await verifyPassword(body.password, user.passwordHash, env.PASSWORD_PEPPER))) return error("Your current password is incorrect.", 401);
    const current = await env.DB.prepare(`SELECT enabled_at as enabledAt FROM user_two_factor WHERE user_id = ?`).bind(context.userId).first<{ enabledAt: string | null }>();
    if (current?.enabledAt) return error("Two-factor authentication is already enabled.", 409);
    const secret = base32Encode(crypto.getRandomValues(new Uint8Array(20)));
    const encrypted = await encryptTwoFactorSecret(env, secret);
    await env.DB.prepare(`INSERT INTO user_two_factor (user_id, pending_secret_enc, pending_expires_at, pending_attempts) VALUES (?, ?, datetime('now', '+10 minutes'), 0)
      ON CONFLICT(user_id) DO UPDATE SET pending_secret_enc = excluded.pending_secret_enc, pending_expires_at = excluded.pending_expires_at, pending_attempts = 0, updated_at = CURRENT_TIMESTAMP WHERE user_two_factor.enabled_at IS NULL`)
      .bind(context.userId, encrypted).run();
    const account = encodeURIComponent(`${context.email} (Zyntris)`);
    const issuer = encodeURIComponent("Zyntris");
    const provisioningUri = `otpauth://totp/${account}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    await audit(env, context, "two_factor_setup_started", "authentication");
    return json({ secret, provisioningUri, expiresIn: 600 });
  }

  if (request.method === "POST" && path === "/api/auth/2fa/enable") {
    if (!(await consumeAuthLimit(env, request, "2fa-enroll", 10, 15)) || !(await consumeAuthLimit(env, request, "2fa-enroll", 8, 15, context.userId))) return error("Too many authenticator setup attempts. Start setup again later.", 429);
    const body = await request.json<{ code?: string }>();
    const pending = await env.DB.prepare(`SELECT pending_secret_enc as secretEnc, pending_attempts as attempts FROM user_two_factor WHERE user_id = ? AND enabled_at IS NULL AND pending_expires_at > CURRENT_TIMESTAMP`).bind(context.userId).first<{ secretEnc: string | null; attempts: number }>();
    if (!pending?.secretEnc || !body.code) return error("Start setup again; the authenticator setup has expired.", 409);
    if (pending.attempts >= 5) return error("Too many incorrect setup codes. Start authenticator setup again.", 429);
    const counter = await matchTotp(await decryptTwoFactorSecret(env, pending.secretEnc), body.code);
    if (counter === null) {
      const failed = await env.DB.prepare(`UPDATE user_two_factor SET pending_attempts = pending_attempts + 1, pending_secret_enc = CASE WHEN pending_attempts + 1 >= 5 THEN NULL ELSE pending_secret_enc END, pending_expires_at = CASE WHEN pending_attempts + 1 >= 5 THEN NULL ELSE pending_expires_at END, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND enabled_at IS NULL AND pending_secret_enc = ? AND pending_expires_at > CURRENT_TIMESTAMP AND pending_attempts < 5`).bind(context.userId, pending.secretEnc).run();
      return error(failed.meta.changes ? "That code is not valid. Setup expires after five incorrect attempts; start again if necessary." : "Setup expired or was already completed. Start setup again.", failed.meta.changes ? 401 : 409);
    }
    const codes = makeRecoveryCodes();
    const updated = await env.DB.prepare(`UPDATE user_two_factor SET secret_enc = pending_secret_enc, pending_secret_enc = NULL, pending_expires_at = NULL, pending_attempts = 0, enabled_at = CURRENT_TIMESTAMP, last_counter = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND enabled_at IS NULL AND pending_secret_enc = ? AND pending_expires_at > CURRENT_TIMESTAMP AND pending_attempts < 5`)
      .bind(counter - 1, context.userId, pending.secretEnc).run();
    if (!updated.meta.changes) return error("Setup expired or was already completed. Start setup again.", 409);
    const codeHashes = await Promise.all(codes.map((code) => hashToken(code.replace(/-/g, "").toLowerCase())));
    await env.DB.batch(codes.map((_, index) => env.DB.prepare(`INSERT INTO two_factor_recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)`)
      .bind(requestId(), context.userId, codeHashes[index])));
    await audit(env, context, "two_factor_enabled", "authentication");
    return json({ ok: true, recoveryCodes: codes });
  }

  if (request.method === "POST" && path === "/api/auth/2fa/disable") {
    if (context.isPlatformAdmin || ["admin", "organization admin", "hr admin", "finance admin", "ceo"].includes(context.role.trim().toLowerCase()) || context.permissions.has("roles.manage") || context.permissions.has("settings.manage")) return error("Two-factor authentication is mandatory for this privileged account.", 403);
    const body = await request.json<{ password?: string; code?: string }>();
    const user = await env.DB.prepare(`SELECT password_hash as passwordHash FROM users WHERE id = ? AND status = 'active'`).bind(context.userId).first<{ passwordHash: string | null }>();
    if (!user?.passwordHash || !(await verifyPassword(body.password || "", user.passwordHash, env.PASSWORD_PEPPER))) return error("Your current password is incorrect.", 401);
    const factor = await env.DB.prepare(`SELECT secret_enc as secretEnc, enabled_at as enabledAt, last_counter as lastCounter FROM user_two_factor WHERE user_id = ?`).bind(context.userId).first<{ secretEnc: string | null; enabledAt: string | null; lastCounter: number }>();
    if (!factor?.enabledAt || !factor.secretEnc) return error("Two-factor authentication is not enabled.", 409);
    let verified = false;
    if (/^\d{6}$/.test(body.code || "")) {
      const counter = await matchTotp(await decryptTwoFactorSecret(env, factor.secretEnc), body.code || "");
      if (counter !== null && counter > factor.lastCounter) {
        verified = (await env.DB.prepare(`UPDATE user_two_factor SET last_counter = ? WHERE user_id = ? AND last_counter < ?`).bind(counter, context.userId, counter).run()).meta.changes > 0;
      }
    } else {
      const normalized = (body.code || "").replace(/-/g, "").trim().toLowerCase();
      if (/^[a-f0-9]{10}$/.test(normalized)) verified = (await env.DB.prepare(`UPDATE two_factor_recovery_codes SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`).bind(context.userId, await hashToken(normalized)).run()).meta.changes > 0;
    }
    if (!verified) return error("Enter a valid unused authenticator or recovery code.", 401);
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM user_two_factor WHERE user_id = ?`).bind(context.userId),
      env.DB.prepare(`DELETE FROM two_factor_recovery_codes WHERE user_id = ?`).bind(context.userId),
      env.DB.prepare(`DELETE FROM two_factor_challenges WHERE user_id = ?`).bind(context.userId),
    ]);
    await audit(env, context, "two_factor_disabled", "authentication");
    return json({ ok: true });
  }

  if (request.method === "GET" && path === "/api/notifications") {
    const result = await env.DB.prepare(`SELECT id, type, title, body, read_at as readAt, created_at as createdAt FROM notifications WHERE organization_id = ? AND user_id = ? ORDER BY created_at DESC LIMIT 50`).bind(context.organizationId, context.userId).all();
    const unread = await env.DB.prepare(`SELECT COUNT(*) as count FROM notifications WHERE organization_id = ? AND user_id = ? AND read_at IS NULL`).bind(context.organizationId, context.userId).first<{ count: number }>();
    return json({ data: result.results || [], unread: unread?.count || 0 });
  }

  if (request.method === "PATCH" && path === "/api/notifications/read-all") {
    await env.DB.prepare(`UPDATE notifications SET read_at = CURRENT_TIMESTAMP WHERE organization_id = ? AND user_id = ? AND read_at IS NULL`).bind(context.organizationId, context.userId).run();
    return json({ ok: true });
  }

  const notificationMatch = path.match(/^\/api\/notifications\/([^/]+)\/read$/);
  if (request.method === "PATCH" && notificationMatch) {
    await env.DB.prepare(`UPDATE notifications SET read_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND user_id = ? AND read_at IS NULL`).bind(notificationMatch[1], context.organizationId, context.userId).run();
    return json({ ok: true });
  }

  if (path.startsWith("/api/platform/")) {
    if (!context.isPlatformAdmin) return error("Platform administrator access is required.", 403);

    const moduleCatalog = [
      { key: "hr", label: "HR & People", description: "Employee records, leave, attendance, teams, appraisals and exits." },
      { key: "payroll", label: "Payroll", description: "Remuneration records, payroll review and employee payslips." },
      { key: "finance", label: "Expenses & Finance", description: "Expenses, financial requests, approval rules, budgets and purchasing." },
      { key: "operations", label: "Operations", description: "Tasks, assets, vendors, documents, helpdesk and calendar." },
      { key: "projects", label: "Project Management", description: "Project plans, portfolios, Gantt, timesheets, budgets and client portal." },
      { key: "crm", label: "CRM", description: "Customers, contacts, pipeline, quotations and CRM reporting." },
      { key: "reports", label: "Reports & Analytics", description: "Cross-workspace reports and downloadable operational summaries." },
    ];
    const tenantModulesMatch = path.match(/^\/api\/platform\/organizations\/([^/]+)\/modules(?:\/([a-z-]+))?$/);
    if (tenantModulesMatch && request.method === "GET" && !tenantModulesMatch[2]) {
      const org = await env.DB.prepare(`SELECT id FROM organizations WHERE id=?`).bind(tenantModulesMatch[1]).first<{ id: string }>();
      if (!org) return error("Tenant was not found.", 404);
      const [entitlements, subscriptions] = await Promise.all([
        env.DB.prepare(`SELECT module_key as moduleKey,enabled,features_json as featuresJson FROM organization_modules WHERE organization_id=?`).bind(org.id).all<{ moduleKey: string; enabled: number; featuresJson: string }>(),
        env.DB.prepare(`SELECT module_key as moduleKey,plan_code as planCode,status,ends_at as endsAt,notes,CASE WHEN ends_at IS NULL OR datetime(ends_at)>CURRENT_TIMESTAMP THEN 1 ELSE 0 END as withinTerm FROM module_subscriptions WHERE organization_id=?`).bind(org.id).all<{ moduleKey: string; planCode: string; status: string; endsAt: string | null; notes: string | null; withinTerm: number }>(),
      ]);
      const entitlementByKey = new Map((entitlements.results || []).map((item) => [item.moduleKey, item]));
      const subscriptionByKey = new Map((subscriptions.results || []).map((item) => [item.moduleKey, item]));
      return json({ data: moduleCatalog.map((module) => {
        const entitlement = entitlementByKey.get(module.key);
        const subscription = subscriptionByKey.get(module.key);
        const enabled = entitlement?.enabled === 1 && (!subscription || (subscription.status === "active" && subscription.withinTerm === 1));
        return { ...module, enabled, status: subscription?.status || (enabled ? "active" : "paused"), planCode: subscription?.planCode || "manual", endsAt: subscription?.endsAt || null, notes: subscription?.notes || "" };
      }) });
    }
    if (tenantModulesMatch && request.method === "PATCH" && tenantModulesMatch[2]) {
      const module = moduleCatalog.find((item) => item.key === tenantModulesMatch[2]);
      if (!module) return error("Unknown tenant module.", 404);
      const body = await request.json<{ status?: string; planCode?: string; endsAt?: string | null; notes?: string }>();
      if (!body.status || !["active", "paused", "cancelled", "expired"].includes(body.status)) return error("Choose active or inactive module service status.");
      if ((body.planCode || "").trim().length > 80 || (body.notes || "").trim().length > 1000 || (body.endsAt && Number.isNaN(Date.parse(body.endsAt)))) return error("Check the plan name, expiry date and notes.");
      if (body.status === "active" && body.endsAt && new Date(`${body.endsAt.slice(0, 10)}T23:59:59Z`).getTime() <= Date.now()) return error("An active module must have an expiry date in the future.");
      const org = await env.DB.prepare(`SELECT id,is_demo as isDemo FROM organizations WHERE id=?`).bind(tenantModulesMatch[1]).first<{ id: string; isDemo: number }>();
      if (!org) return error("Tenant was not found.", 404);
      if (org.isDemo) return error("The synthetic demo tenant is protected.", 403);
      const before = await env.DB.prepare(`SELECT enabled,features_json as featuresJson FROM organization_modules WHERE organization_id=? AND module_key=?`).bind(org.id, module.key).first<{ enabled: number; featuresJson: string }>();
      let featuresJson = before?.featuresJson || "{}";
      if (module.key === "projects" && !before) featuresJson = '{"portfolios":true,"programmes":true,"gantt":true,"timesheets":true,"budgets":true,"risks":true,"change_control":true,"meetings":true,"templates":true,"client_portal":true,"advanced_reports":true,"ai":false}';
      const enabled = body.status === "active";
      const planCode = body.planCode?.trim() || "manual";
      const endsAt = body.endsAt ? `${body.endsAt.slice(0, 10)} 23:59:59` : null;
      const notes = body.notes?.trim() || null;
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO organization_modules(organization_id,module_key,enabled,features_json) VALUES(?,?,?,?) ON CONFLICT(organization_id,module_key) DO UPDATE SET enabled=excluded.enabled,features_json=excluded.features_json,updated_at=CURRENT_TIMESTAMP`).bind(org.id, module.key, enabled ? 1 : 0, featuresJson),
        env.DB.prepare(`INSERT INTO module_subscriptions(id,organization_id,module_key,plan_code,status,activated_by,starts_at,ends_at,notes) VALUES(?,?,?,?,?,?,CASE WHEN ?='active' THEN CURRENT_TIMESTAMP ELSE NULL END,?,?) ON CONFLICT(organization_id,module_key) DO UPDATE SET plan_code=excluded.plan_code,status=excluded.status,activated_by=excluded.activated_by,starts_at=CASE WHEN excluded.status='active' THEN CURRENT_TIMESTAMP ELSE module_subscriptions.starts_at END,ends_at=excluded.ends_at,notes=excluded.notes,updated_at=CURRENT_TIMESTAMP`).bind(`module-sub-${requestId()}`, org.id, module.key, planCode, body.status, context.userId, body.status, endsAt, notes),
        env.DB.prepare(`INSERT INTO audit_logs(id,organization_id,actor_user_id,action,module,record_type,record_id,previous_value_json,new_value_json) VALUES(?,?,?,?,'platform','module_subscription',?,?,?)`).bind(`audit-${requestId()}`, org.id, context.userId, `module_${module.key}_${body.status}`, module.key, JSON.stringify({ enabled: before?.enabled === 1 }), JSON.stringify({ enabled, status: body.status, planCode, endsAt, notes })),
      ]);
      return json({ ok: true, organizationId: org.id, module: module.key, enabled, status: body.status });
    }

    const serviceMatch = path.match(/^\/api\/platform\/organizations\/([^/]+)\/service$/);
    if (request.method === "PATCH" && serviceMatch) {
      const body = await request.json<{ enabled?: boolean }>();
      if (typeof body.enabled !== "boolean") return error("Choose whether tenant services should be enabled or disabled.");
      const org = await env.DB.prepare(`SELECT o.id, o.name, o.status, o.is_demo as isDemo, s.status as subscriptionStatus, s.trial_ends_at as trialEndsAt FROM organizations o LEFT JOIN subscriptions s ON s.organization_id = o.id WHERE o.id = ?`).bind(serviceMatch[1]).first<{ id: string; name: string; status: string; isDemo: number; subscriptionStatus: string | null; trialEndsAt: string | null }>();
      if (!org) return error("Tenant was not found.", 404);
      if (org.isDemo) return error("The synthetic demo tenant is protected and cannot be toggled.", 403);
      if (body.enabled && !org.subscriptionStatus) return error("This tenant has no subscription record; service cannot be enabled.", 409);

      let subscriptionStatus = org.subscriptionStatus;
      let organizationStatus = "suspended";
      if (body.enabled) {
        const trialValid = org.subscriptionStatus === "trialing" && Boolean(org.trialEndsAt) && new Date(`${org.trialEndsAt!.replace(" ", "T")}Z`).getTime() > Date.now();
        subscriptionStatus = org.subscriptionStatus === "active" || trialValid ? org.subscriptionStatus : "active";
        organizationStatus = subscriptionStatus === "trialing" ? "trial" : "active";
      }
      const platformStatements = [];
      if (body.enabled) platformStatements.push(env.DB.prepare(`UPDATE subscriptions SET status = ? WHERE organization_id = ?`).bind(subscriptionStatus, org.id));
      platformStatements.push(env.DB.prepare(`UPDATE organizations SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(organizationStatus, org.id));
      if (!body.enabled) platformStatements.push(env.DB.prepare(`DELETE FROM sessions WHERE organization_id = ?`).bind(org.id));
      platformStatements.push(env.DB.prepare(`INSERT INTO audit_logs (id, organization_id, actor_user_id, action, module, record_type, record_id, previous_value_json, new_value_json) VALUES (?, ?, ?, ?, 'platform', 'organization', ?, ?, ?)`)
        .bind(`audit-${crypto.randomUUID()}`, org.id, context.userId, body.enabled ? "tenant_services_enabled" : "tenant_services_disabled", org.id, JSON.stringify({ organizationStatus: org.status, subscriptionStatus: org.subscriptionStatus }), JSON.stringify({ organizationStatus, subscriptionStatus })));
      await env.DB.batch(platformStatements);
      return json({ ok: true, organizationId: org.id, enabled: body.enabled, organizationStatus, subscriptionStatus });
    }

    const organizationUsersMatch = path.match(/^\/api\/platform\/organizations\/([^/]+)\/users$/);
    if (request.method === "GET" && organizationUsersMatch) {
      const org = await env.DB.prepare(`SELECT id FROM organizations WHERE id = ?`).bind(organizationUsersMatch[1]).first<{ id: string }>();
      if (!org) return error("Tenant was not found.", 404);
      const users = await env.DB.prepare(`SELECT u.id, u.full_name as fullName, u.email, u.status, u.email_verified_at as emailVerifiedAt, r.name as role, u.created_at as createdAt FROM memberships m JOIN users u ON u.id = m.user_id JOIN roles r ON r.id = m.role_id WHERE m.organization_id = ? ORDER BY CASE WHEN r.name IN ('Organization Admin','CEO') THEN 0 ELSE 1 END, u.full_name LIMIT 250`).bind(org.id).all();
      return json({ data: users.results || [] });
    }

    const userResetMatch = path.match(/^\/api\/platform\/organizations\/([^/]+)\/users\/([^/]+)\/password-reset$/);
    if (request.method === "POST" && userResetMatch) {
      if (!env.PASSWORD_PEPPER) return error("Secure password recovery is not configured. Set PASSWORD_PEPPER before sending reset links.", 503);
      if (!(await consumeAuthLimit(env, request, "platform-password-reset", 15, 60))) return error("The password reset limit has been reached. Wait before sending more reset emails.", 429);
      const target = await env.DB.prepare(`SELECT u.id, u.email, u.full_name as fullName, o.id as organizationId, o.name as organizationName, r.name as role FROM users u JOIN memberships m ON m.user_id = u.id JOIN roles r ON r.id = m.role_id JOIN organizations o ON o.id = m.organization_id WHERE o.id = ? AND u.id = ? AND m.status = 'active' AND u.status = 'active' AND u.email_verified_at IS NOT NULL AND o.is_demo = 0 AND r.name IN ('Organization Admin','CEO') LIMIT 1`).bind(userResetMatch[1], userResetMatch[2]).first<{ id: string; email: string; fullName: string; organizationId: string; organizationName: string; role: string }>();
      if (!target) return error("An active, verified Organization Admin or CEO account for this tenant was not found.", 404);
      await env.DB.prepare(`DELETE FROM password_reset_tokens WHERE user_id = ?`).bind(target.id).run();
      const resetToken = randomToken();
      const resetId = `pwdreset-${crypto.randomUUID()}`;
      await env.DB.prepare(`INSERT INTO password_reset_tokens (id, user_id, organization_id, token_hash, expires_at) VALUES (?, ?, ?, ?, datetime('now', '+30 minutes'))`).bind(resetId, target.id, target.organizationId, await hashToken(resetToken)).run();
      const delivery = await sendPasswordResetEmail(env, target.email, target.fullName, target.organizationName, resetToken);
      if (!delivery.accepted) {
        await env.DB.prepare(`DELETE FROM password_reset_tokens WHERE id = ?`).bind(resetId).run();
        return error(delivery.message, 502);
      }
      await env.DB.batch([
        env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(target.id),
        env.DB.prepare(`DELETE FROM two_factor_challenges WHERE user_id = ?`).bind(target.id),
        env.DB.prepare(`INSERT INTO audit_logs (id, organization_id, actor_user_id, action, module, record_type, record_id, new_value_json) VALUES (?, ?, ?, 'platform_password_reset_requested', 'platform', 'user', ?, ?)`)
          .bind(`audit-${crypto.randomUUID()}`, target.organizationId, context.userId, target.id, JSON.stringify({ email: target.email, role: target.role, resetLinkExpiresInMinutes: 30 })),
      ]);
      return json({ ok: true, recipient: target.email, expiresIn: 1800, sessionsRevoked: true });
    }

    if (request.method === "POST" && /^\/api\/platform\/users\/[^/]+\/password-reset$/.test(path)) {
      return error("Choose an Organization Admin or CEO from the specific tenant workspace.", 404);
    }

    if (request.method !== "GET") return error("Platform console endpoint not found.", 404);

    if (path === "/api/platform/summary") {
      const summary = await env.DB.prepare(`
        SELECT COUNT(*) as organizations,
          SUM(CASE WHEN o.status != 'suspended' AND (s.status = 'active' OR (s.status = 'trialing' AND s.trial_ends_at > CURRENT_TIMESTAMP)) THEN 1 ELSE 0 END) as active,
          SUM(CASE WHEN s.status = 'trialing' AND s.trial_ends_at > CURRENT_TIMESTAMP AND o.status != 'suspended' THEN 1 ELSE 0 END) as trialing,
          SUM(CASE WHEN o.status = 'suspended' OR s.status = 'expired' THEN 1 ELSE 0 END) as suspended,
          (SELECT COUNT(DISTINCT m.user_id) FROM memberships m) as users,
          (SELECT COUNT(*) FROM employees e WHERE e.deleted_at IS NULL) as employees
        FROM organizations o LEFT JOIN subscriptions s ON s.organization_id = o.id
      `).first();
      return json(summary || { organizations: 0, active: 0, trialing: 0, suspended: 0, users: 0, employees: 0 });
    }

    if (path === "/api/platform/organizations") {
      const search = url.searchParams.get("search")?.trim().slice(0, 100) || "";
      const limit = Math.max(1, Math.min(Number(url.searchParams.get("limit")) || 50, 100));
      const offset = Math.max(0, Math.min(Number(url.searchParams.get("offset")) || 0, 1000000));
      const condition = `(? = '' OR o.name LIKE '%' || ? || '%' OR o.slug LIKE '%' || ? || '%' OR COALESCE(o.industry, '') LIKE '%' || ? || '%')`;
      const [total, organizations] = await Promise.all([
        env.DB.prepare(`SELECT COUNT(*) as total FROM organizations o WHERE ${condition}`).bind(search, search, search, search).first<{ total: number }>(),
        env.DB.prepare(`
          SELECT o.id, o.name, o.slug, o.industry, o.status, o.is_demo as isDemo, o.created_at as createdAt,
            s.plan, s.status as subscriptionStatus, s.trial_ends_at as trialEndsAt,
            CASE WHEN o.status != 'suspended' AND s.status IN ('active','trialing') AND (s.status != 'trialing' OR s.trial_ends_at > CURRENT_TIMESTAMP) THEN 1 ELSE 0 END as serviceEnabled,
            (SELECT COUNT(*) FROM memberships m WHERE m.organization_id = o.id AND m.status = 'active') as members,
            (SELECT COUNT(*) FROM employees e WHERE e.organization_id = o.id AND e.deleted_at IS NULL) as employees,
            (SELECT MAX(a.created_at) FROM audit_logs a WHERE a.organization_id = o.id) as lastActivity
          FROM organizations o LEFT JOIN subscriptions s ON s.organization_id = o.id
          WHERE ${condition}
          ORDER BY o.created_at DESC LIMIT ? OFFSET ?
        `).bind(search, search, search, search, limit, offset).all(),
      ]);
      return json({ data: organizations.results || [], total: total?.total || 0, limit, offset });
    }

    if (path === "/api/platform/activity") {
      const organizationId = url.searchParams.get("organizationId")?.trim() || "";
      const limit = Math.max(1, Math.min(Number(url.searchParams.get("limit")) || 50, 100));
      const offset = Math.max(0, Math.min(Number(url.searchParams.get("offset")) || 0, 1000000));
      const condition = `(? = '' OR o.id = ?)`;
      const [total, activity] = await Promise.all([
        env.DB.prepare(`SELECT COUNT(*) as total FROM audit_logs a JOIN organizations o ON o.id = a.organization_id WHERE ${condition}`).bind(organizationId, organizationId).first<{ total: number }>(),
        env.DB.prepare(`
          SELECT a.id, o.name as organizationName, u.full_name as actorName,
            a.action, a.module, a.record_type as recordType, a.created_at as createdAt
          FROM audit_logs a JOIN organizations o ON o.id = a.organization_id
          LEFT JOIN users u ON u.id = a.actor_user_id
          WHERE ${condition}
          ORDER BY a.created_at DESC LIMIT ? OFFSET ?
        `).bind(organizationId, organizationId, limit, offset).all(),
      ]);
      return json({ data: activity.results || [], total: total?.total || 0, limit, offset });
    }

    return error("Platform console endpoint not found.", 404);
  }

  if (request.method === "GET" && path === "/api/me") {
    const user = await env.DB.prepare(`SELECT u.id, u.email, u.full_name as fullName, r.name as role, o.id as organizationId, o.name as organizationName, s.trial_ends_at as trialEndsAt, s.status as subscriptionStatus FROM users u JOIN memberships m ON m.user_id = u.id JOIN roles r ON r.id = m.role_id JOIN organizations o ON o.id = m.organization_id LEFT JOIN subscriptions s ON s.organization_id = o.id WHERE u.id = ? AND o.id = ?`).bind(context.userId, context.organizationId).first();
    const entitlements = await env.DB.prepare(`SELECT m.module_key as moduleKey FROM organization_modules m LEFT JOIN module_subscriptions s ON s.organization_id=m.organization_id AND s.module_key=m.module_key WHERE m.organization_id=? AND m.enabled=1 AND (s.id IS NULL OR (s.status='active' AND (s.ends_at IS NULL OR datetime(s.ends_at)>CURRENT_TIMESTAMP)))`).bind(context.organizationId).all<{ moduleKey: string }>();
    return json({ ...(user || { id: context.userId, role: context.role, organizationId: context.organizationId }), permissions: [...context.permissions], enabledModules: (entitlements.results || []).map((item) => item.moduleKey), isPlatformAdmin: context.isPlatformAdmin, isDemo: context.isDemo, mfaMandatory: context.mfaMandatory, mfaEnrollmentRequired: context.mfaEnrollmentRequired });
  }

  if (path === "/api/settings/organization" && request.method === "GET") {
    const organization = await env.DB.prepare(`SELECT id, name, slug, industry, description, timezone, currency, status, created_at as createdAt FROM organizations WHERE id = ?`).bind(context.organizationId).first();
    const subscription = await env.DB.prepare(`SELECT plan, status, trial_ends_at as trialEndsAt, renews_at as renewsAt, employee_limit as employeeLimit, storage_limit_bytes as storageLimitBytes FROM subscriptions WHERE organization_id = ?`).bind(context.organizationId).first();
    return json({ organization, subscription });
  }

  if (path === "/api/settings/organization" && request.method === "PUT") {
    if (!hasPermission(context, "settings.manage")) return error("Organization administrator permission required.", 403);
    const body = await request.json<{ name?: string; industry?: string; description?: string; timezone?: string; currency?: string }>();
    const name = body.name?.trim();
    if (!name || name.length > 120 || !body.timezone || !body.currency || !/^[A-Z]{3}$/.test(body.currency)) return error("Organization name, time zone and a valid currency code are required.");
    await env.DB.prepare(`UPDATE organizations SET name = ?, industry = ?, description = ?, timezone = ?, currency = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
      .bind(name, body.industry?.trim() || null, body.description?.trim() || null, body.timezone, body.currency, context.organizationId).run();
    await audit(env, context, "updated", "organization_settings", context.organizationId, { name, industry: body.industry || null, timezone: body.timezone, currency: body.currency });
    return json({ ok: true });
  }

  if (path === "/api/settings/backups" && request.method === "GET") {
    if (!hasPermission(context, "settings.manage")) return error("Organization administrator permission is required to manage backups.", 403);
    const backups = await env.DB.prepare(`SELECT id, checksum, size_bytes as sizeBytes, record_count as recordCount, created_at as createdAt FROM tenant_backups WHERE organization_id = ? ORDER BY created_at DESC LIMIT 30`).bind(context.organizationId).all();
    const settings = await env.DB.prepare(`SELECT enabled, frequency, retention_days as retentionDays, alert_email as alertEmail, last_run_at as lastRunAt, last_status as lastStatus, last_error as lastError, last_verified_at as lastVerifiedAt FROM tenant_backup_settings WHERE organization_id = ?`).bind(context.organizationId).first();
    return json({ data: backups.results || [], settings: settings || { enabled: 0, frequency: "daily", retentionDays: 30, alertEmail: null, lastRunAt: null, lastStatus: null, lastError: null, lastVerifiedAt: null } });
  }

  if (path === "/api/settings/backups/schedule" && request.method === "PUT") {
    if (!hasPermission(context, "settings.manage")) return error("Organization administrator permission is required to manage backups.", 403);
    const body = await request.json<{ enabled?: boolean; frequency?: string; retentionDays?: number; alertEmail?: string | null }>();
    if (typeof body.enabled !== "boolean" || !["daily", "weekly"].includes(body.frequency || "") || !Number.isInteger(body.retentionDays) || Number(body.retentionDays) < 7 || Number(body.retentionDays) > 365 || (body.alertEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.alertEmail))) return error("Choose daily or weekly snapshots, 7–365 retention days, and a valid optional alert address.");
    await env.DB.prepare(`INSERT INTO tenant_backup_settings (organization_id, enabled, frequency, retention_days, alert_email, updated_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(organization_id) DO UPDATE SET enabled = excluded.enabled, frequency = excluded.frequency, retention_days = excluded.retention_days, alert_email = excluded.alert_email, updated_at = CURRENT_TIMESTAMP`).bind(context.organizationId, body.enabled ? 1 : 0, body.frequency, body.retentionDays, body.alertEmail?.trim().toLowerCase() || null).run();
    await audit(env, context, "updated", "tenant_backup_settings", context.organizationId, { enabled: body.enabled, frequency: body.frequency, retentionDays: body.retentionDays });
    return json({ ok: true });
  }

  if (path === "/api/settings/backups" && request.method === "POST") {
    if (!hasPermission(context, "settings.manage")) return error("Organization administrator permission is required to manage backups.", 403);
    try {
      const created = await createTenantBackup(env, context.organizationId, context.userId);
      await env.DB.prepare(`INSERT INTO tenant_backup_settings (organization_id, last_run_at, last_status, last_error, last_verified_at, updated_at) VALUES (?, CURRENT_TIMESTAMP, 'success', NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) ON CONFLICT(organization_id) DO UPDATE SET last_run_at = CURRENT_TIMESTAMP, last_status = 'success', last_error = NULL, last_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP`).bind(context.organizationId).run();
      await audit(env, context, "created", "tenant_backups", created.id, { checksum: created.checksum, recordCount: created.recordCount, fileCount: created.fileCount });
      return json(created, { status: 201 });
    } catch (cause) { return error(`Backup was not completed: ${cause instanceof Error ? cause.message : "R2 or D1 snapshot failure"}`, 409); }
  }

  const backupMatch = path.match(/^\/api\/settings\/backups\/([^/]+)(?:\/(download|restore))?$/);
  if (backupMatch && request.method === "GET" && backupMatch[2] === "download") {
    if (!hasPermission(context, "settings.manage")) return error("Organization administrator permission is required to manage backups.", 403);
    const backup = await env.DB.prepare(`SELECT object_key as objectKey, checksum FROM tenant_backups WHERE id = ? AND organization_id = ?`).bind(backupMatch[1], context.organizationId).first<{ objectKey: string; checksum: string }>();
    if (!backup) return error("Backup not found.", 404);
    const object = await getTenantBackupObject(env, context.organizationId, backupMatch[1], backup.objectKey);
    if (!object) return error("Backup file is missing from private storage.", 410);
    const payload = await object.text();
    if (await hashToken(payload) !== backup.checksum) return error("Backup integrity verification failed. Do not use this copy for recovery.", 409);
    await audit(env, context, "downloaded", "tenant_backups", backupMatch[1]);
    return new Response(payload, { headers: { "content-type": "application/json; charset=utf-8", "content-disposition": `attachment; filename=\"zyntris-backup-${backupMatch[1]}.json\"`, "cache-control": "no-store" } });
  }

  if (backupMatch && request.method === "POST" && backupMatch[2] === "restore") {
    if (!hasPermission(context, "settings.manage")) return error("Organization administrator permission is required to manage backups.", 403);
    const body = await request.json<{ dryRun?: boolean; confirmation?: string }>();
    const backup = await env.DB.prepare(`SELECT object_key as objectKey, checksum FROM tenant_backups WHERE id = ? AND organization_id = ?`).bind(backupMatch[1], context.organizationId).first<{ objectKey: string; checksum: string }>();
    if (!backup) return error("Backup not found.", 404);
    const object = await getTenantBackupObject(env, context.organizationId, backupMatch[1], backup.objectKey);
    if (!object) return error("Backup file is missing from private storage.", 410);
    const serialized = await object.text();
    if (await hashToken(serialized) !== backup.checksum) return error("Backup integrity verification failed. Do not use this copy for recovery.", 409);
    let snapshot: { schemaVersion?: number; organizationId?: string; tables?: Record<string, unknown[]>; files?: { originalKey: string; backupKey: string }[] };
    try { snapshot = JSON.parse(serialized); } catch { return error("Backup data is not valid JSON.", 409); }
    if (snapshot.schemaVersion !== 1 || snapshot.organizationId !== context.organizationId || !snapshot.tables || Array.isArray(snapshot.tables) || (snapshot.files !== undefined && (!Array.isArray(snapshot.files) || snapshot.files.some((file) => !file || typeof file.originalKey !== "string" || typeof file.backupKey !== "string")))) return error("Backup version, tenant identity or file manifest is invalid.", 409);
    const counts: Record<string, number> = {};
    for (const [table, rows] of Object.entries(snapshot.tables)) {
      if (!(BACKUP_TABLES as readonly string[]).includes(table) || !Array.isArray(rows)) return error("Backup includes an unsupported table.", 409);
      counts[table] = rows.length;
      if (rows.some((raw) => {
        if (!raw || typeof raw !== "object") return true;
        const row = raw as Record<string, unknown>;
        return row.organization_id !== context.organizationId || Object.keys(row).some((column) => !/^[a-z_]+$/.test(column));
      })) return error("Backup contains an invalid or out-of-tenant record.", 409);
    }
    for (const file of snapshot.files || []) {
      if (!isTenantObjectKey(file.originalKey, context.organizationId) || !isTenantBackupObjectKey(file.backupKey, context.organizationId, backupMatch[1]) || !file.backupKey.includes("/files/") || !await getTenantBackupObject(env, context.organizationId, backupMatch[1], file.backupKey)) return error("Backup file manifest contains a missing or out-of-tenant object.", 409);
    }
    if (body.dryRun) return json({ valid: true, mode: "non-destructive merge", rows: counts, fileCount: snapshot.files?.length || 0, note: "Existing records are never overwritten or deleted. Missing records and files are restored where their references remain valid." });
    if (body.confirmation !== "RESTORE MERGE") return error("Type RESTORE MERGE to confirm recovery. This is a non-destructive merge; current rows will not be overwritten or deleted.");
    let restoredCount = 0;
    try {
      for (const table of BACKUP_TABLES) {
        const rows = snapshot.tables[table] || [];
        for (let offset = 0; offset < rows.length; offset += 100) {
          const statements = rows.slice(offset, offset + 100).map((raw) => {
            const row = raw as Record<string, unknown>;
            const columns = Object.keys(row);
            if (!columns.length || columns.some((column) => !/^[a-z_]+$/.test(column)) || row.organization_id !== context.organizationId) throw new Error("Unsafe backup row.");
            return env.DB.prepare(`INSERT OR IGNORE INTO ${table} (${columns.join(",")}) VALUES (${columns.map(() => "?").join(",")})`).bind(...columns.map((column) => row[column] as string | number | null));
          });
          const results = await env.DB.batch(statements);
          restoredCount += results.reduce((sum, result) => sum + result.meta.changes, 0);
        }
      }
      let restoredFiles = 0;
      for (const file of snapshot.files || []) {
        if (!isTenantObjectKey(file.originalKey, context.organizationId) || !isTenantBackupObjectKey(file.backupKey, context.organizationId, backupMatch[1]) || !file.backupKey.includes("/files/")) continue;
        if (await env.FILES.head(file.originalKey)) continue;
        const archived = await getTenantBackupObject(env, context.organizationId, backupMatch[1], file.backupKey);
        if (archived) { await env.FILES.put(file.originalKey, archived.body, { httpMetadata: archived.httpMetadata }); restoredFiles += 1; }
      }
      await env.DB.prepare(`INSERT INTO tenant_storage_usage (organization_id, used_bytes, updated_at) SELECT ?, (SELECT COALESCE(SUM(size_bytes),0) FROM documents WHERE organization_id = ?) + (SELECT COALESCE(SUM(receipt_size_bytes),0) FROM expenses WHERE organization_id = ?), CURRENT_TIMESTAMP ON CONFLICT(organization_id) DO UPDATE SET used_bytes = excluded.used_bytes, updated_at = CURRENT_TIMESTAMP`).bind(context.organizationId, context.organizationId, context.organizationId).run();
      await audit(env, context, "restored_merge", "tenant_backups", backupMatch[1], { restoredCount, restoredFiles });
      return json({ ok: true, mode: "non-destructive merge", restoredCount, restoredFiles });
    } catch (cause) {
      console.error("Tenant backup merge restore stopped", cause);
      await audit(env, context, "restore_merge_failed", "tenant_backups", backupMatch[1], { restoredCount });
      return error(`Restore stopped after ${restoredCount} records. Existing data was not overwritten or deleted; review the audit log and source backup before retrying.`, 409);
    }
  }

  if (request.method === "GET" && path === "/api/payroll/my-payslips") {
    if (!hasPermission(context, "payroll.self.view")) return error("Employee payslip access is not enabled for this account.", 403);
    const employee = await env.DB.prepare(`SELECT id FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string }>();
    if (!employee) return json({ data: [] });
    const result = await env.DB.prepare(`SELECT i.id, i.employee_number as employeeNumber, i.employee_name as employeeName, i.job_title as jobTitle, r.period_start as periodStart, r.period_end as periodEnd, r.payment_date as payDate, r.currency, r.status as runStatus, i.gross_pay as grossPay, i.paye_tax as payeTax, i.employee_pension as employeePension, i.other_deductions as otherDeductions, i.net_pay as netPay, i.breakdown_json as breakdownJson FROM payroll_run_items i JOIN payroll_runs r ON r.id = i.payroll_run_id AND r.organization_id = i.organization_id JOIN employees e ON e.id = i.employee_id AND e.organization_id = i.organization_id WHERE i.organization_id = ? AND e.id = ? AND r.status IN ('approved','paid') ORDER BY r.period_end DESC LIMIT 100`).bind(context.organizationId, employee.id).all();
    return json({ data: result.results || [] });
  }
  if (path.startsWith("/api/payroll") && !hasPermission(context, "payroll.view") && !hasPermission(context, "payroll.manage")) return error("You do not have permission to access the payroll administration workspace.", 403);

  if (path.startsWith("/api/hr/") && !hasPermission(context, "employees.view")) return error("You do not have permission to access HR records.", 403);
  const taskApiPath=path==="/api/tasks"||path.startsWith("/api/tasks/");
  if(taskApiPath&&!hasPermission(context,"operations.view")&&!hasPermission(context,"projects.view")&&!hasPermission(context,"projects.manage"))return error("Task access is not enabled for this account.",403);
  if(taskApiPath&&!hasPermission(context,"operations.view")&&(hasPermission(context,"projects.view")||hasPermission(context,"projects.manage"))){const entitlement=await env.DB.prepare(`SELECT enabled FROM organization_modules WHERE organization_id=? AND module_key='projects'`).bind(context.organizationId).first<{enabled:number}>();if(!entitlement||entitlement.enabled!==1)return error("The Projects module is not included in this organization's entitlements.",403);}
  const operationsPaths = ["/api/assets", "/api/vendors", "/api/purchases", "/api/tickets", "/api/calendar", "/api/customers", "/api/files", "/api/budgets", "/api/reports", "/api/operations/members"];
  const operationsPath = operationsPaths.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
  if (operationsPath && !hasPermission(context, "operations.view")) return error("You do not have access to operations modules.", 403);
  if (operationsPath && request.method !== "GET" && !(path === "/api/tickets" && request.method === "POST") && path !== "/api/purchases" && !path.startsWith("/api/purchases/") && !hasPermission(context, "operations.manage")) return error("Operations manager permission is required for this change.", 403);

  const projectPath=path==="/api/projects"||path.startsWith("/api/projects/");
  if(projectPath){
    if(!hasPermission(context,"projects.view")&&!hasPermission(context,"projects.manage")&&!hasPermission(context,"operations.view"))return error("Project access is not enabled for this account.",403);
    if(path!=="/api/projects/subscription"){
      const entitlement=await env.DB.prepare(`SELECT enabled FROM organization_modules WHERE organization_id=? AND module_key='projects'`).bind(context.organizationId).first<{enabled:number}>();
      if(!entitlement||entitlement.enabled!==1)return error("The Projects module is not included in this organization's entitlements.",403);
    }
  }

  const crmRoute = path === "/api/crm" || path.startsWith("/api/crm/");
  if (crmRoute && !hasPermission(context, "crm.view") && !hasPermission(context, "crm.manage")) return error("CRM access is not enabled for this account.", 403);
  if (crmRoute) {
    const crmEntitlement=await env.DB.prepare(`SELECT enabled FROM organization_modules WHERE organization_id=? AND module_key='crm'`).bind(context.organizationId).first<{enabled:number}>();
    if(!crmEntitlement||crmEntitlement.enabled!==1)return error("The CRM module is not included in this organization's entitlements.",403);
    const canSeeAll = hasPermission(context, "crm.view.all");
    const canManageCrm = hasPermission(context, "crm.manage");
    const crmUrl = new URL(request.url);
    if (request.method === "GET" && path === "/api/crm/dashboard") {
      const ownerFilter = canSeeAll ? "" : " AND owner_id = ?";
      const params = canSeeAll ? [context.organizationId] : [context.organizationId, context.userId];
      const [leads, opportunities, activities, sources] = await Promise.all([
        env.DB.prepare(`SELECT COUNT(*) total, SUM(CASE WHEN status='new' THEN 1 ELSE 0 END) newCount, SUM(CASE WHEN status='qualified' THEN 1 ELSE 0 END) qualified FROM crm_leads WHERE organization_id = ?${ownerFilter}`).bind(...params).first<{ total: number; newCount: number; qualified: number }>(),
        env.DB.prepare(`SELECT COUNT(*) total, COALESCE(SUM(value_minor),0)/100.0 pipelineValue, COALESCE(SUM(value_minor * probability / 100.0),0)/100.0 weightedValue, SUM(CASE WHEN status='won' THEN 1 ELSE 0 END) wonCount, COALESCE(SUM(CASE WHEN status='won' THEN value_minor ELSE 0 END),0)/100.0 wonValue FROM crm_opportunities WHERE organization_id = ?${ownerFilter}`).bind(...params).first<{ total: number; pipelineValue: number; weightedValue: number; wonCount: number; wonValue: number }>(),
        env.DB.prepare(`SELECT COUNT(*) total, SUM(CASE WHEN status != 'completed' AND due_at < CURRENT_TIMESTAMP THEN 1 ELSE 0 END) overdue FROM crm_activities WHERE organization_id = ? AND owner_id = ?`).bind(context.organizationId, context.userId).first<{ total: number; overdue: number }>(),
        env.DB.prepare(`SELECT source, COUNT(*) total FROM crm_leads WHERE organization_id = ?${ownerFilter} GROUP BY source ORDER BY total DESC LIMIT 8`).bind(...params).all(),
      ]);
      return json({ leads: leads || {}, opportunities: opportunities || {}, activities: activities || {}, leadsBySource: sources.results || [] });
    }
    if (request.method === "GET" && path === "/api/crm/sources") {
      const result = await env.DB.prepare(`SELECT id,name,active FROM crm_lead_sources WHERE organization_id = ? AND active = 1 ORDER BY name`).bind(context.organizationId).all();
      return json({ data: result.results || [] });
    }
    if(request.method==="GET"&&path==="/api/crm/customers"){
      const result=await env.DB.prepare(`SELECT c.id,c.name,c.company,c.email,c.phone,c.website,c.industry,c.country,c.city,c.source,c.customer_status as customerStatus,c.stage,c.value,c.owner_id as ownerId,u.full_name as owner,c.last_activity_at as lastActivity,c.won_at as wonAt FROM customers c LEFT JOIN users u ON u.id=c.owner_id WHERE c.organization_id=? AND (?=1 OR c.owner_id=?) ORDER BY c.updated_at DESC LIMIT 200`).bind(context.organizationId,canSeeAll?1:0,context.userId).all();return json({data:result.results||[]});
    }
    const crmCustomerMatch=path.match(/^\/api\/crm\/customers\/([^/]+)$/);
    if(request.method==="PATCH"&&crmCustomerMatch){
      if(!canManageCrm)return error("CRM customer edit permission is required.",403);
      const current=await env.DB.prepare(`SELECT * FROM customers WHERE id=? AND organization_id=?`).bind(crmCustomerMatch[1],context.organizationId).first<Record<string,any>>();if(!current)return error("Customer not found.",404);if(!canSeeAll&&current.owner_id!==context.userId)return error("You can only edit your own customer records.",403);
      const body=await request.json<{name?:string;company?:string;email?:string;phone?:string;website?:string;industry?:string;country?:string;city?:string;customerStatus?:string;source?:string}>();
      if(body.name!==undefined&&(!body.name.trim()||body.name.length>120)||body.email&& !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)||body.customerStatus&&!['prospect','active','inactive','dormant','former'].includes(body.customerStatus))return error("Customer profile contains invalid details.");
      const next={name:body.name?.trim()??current.name,company:body.company?.trim()??current.company,email:body.email?.trim().toLowerCase()??current.email,phone:body.phone?.trim()??current.phone,website:body.website?.trim()??current.website,industry:body.industry?.trim()??current.industry,country:body.country?.trim()??current.country,city:body.city?.trim()??current.city,customerStatus:body.customerStatus??current.customer_status,source:body.source??current.source};
      await env.DB.prepare(`UPDATE customers SET name=?,company=?,email=?,phone=?,website=?,industry=?,country=?,city=?,customer_status=?,source=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?`).bind(next.name,next.company,next.email,next.phone,next.website,next.industry,next.country,next.city,next.customerStatus,next.source,context.userId,current.id,context.organizationId).run();await audit(env,context,"updated","customers",current.id,next,current);return json({ok:true});
    }
    if (request.method === "GET" && path === "/api/crm/stages") {
      const result = await env.DB.prepare(`SELECT stage_key as stageKey,name,probability,sort_order as sortOrder FROM crm_pipeline_stages WHERE organization_id = ? AND active=1 ORDER BY sort_order`).bind(context.organizationId).all();
      return json({ data: result.results || [] });
    }
    if (request.method === "GET" && path === "/api/crm/leads") {
      const limit = Math.min(100, Math.max(1, Number(crmUrl.searchParams.get("limit") || 50)));
      const offset = Math.max(0, Number(crmUrl.searchParams.get("offset") || 0));
      const search = `%${(crmUrl.searchParams.get("q") || "").trim().slice(0,100)}%`;
      const status = crmUrl.searchParams.get("status") || "";
      const result = await env.DB.prepare(`SELECT l.id,l.lead_number as leadNumber,l.name,l.company,l.email,l.phone,l.website,l.industry,l.country,l.region,l.source,l.interest,l.estimated_value_minor/100.0 as estimatedValue,l.estimated_value_minor as estimatedValueMinor,l.currency,l.owner_id as ownerId,u.full_name as owner,l.status,l.temperature,l.score,l.description,l.tags_json as tagsJson,l.created_at as createdAt,l.updated_at as updatedAt,l.last_activity_at as lastActivityAt,l.next_follow_up_at as nextFollowUpAt FROM crm_leads l LEFT JOIN users u ON u.id=l.owner_id WHERE l.organization_id=? AND (?=1 OR l.owner_id=?) AND (?='' OR l.status=?) AND (?='%%' OR l.name LIKE ? OR l.company LIKE ? OR l.email LIKE ?) ORDER BY l.updated_at DESC LIMIT ? OFFSET ?`).bind(context.organizationId,canSeeAll?1:0,context.userId,status,status,search,search,search,search,limit,offset).all();
      const count = await env.DB.prepare(`SELECT COUNT(*) total FROM crm_leads WHERE organization_id=? AND (?=1 OR owner_id=?) AND (?='' OR status=?) AND (?='%%' OR name LIKE ? OR company LIKE ? OR email LIKE ?)`).bind(context.organizationId,canSeeAll?1:0,context.userId,status,status,search,search,search,search).first<{ total: number }>();
      return json({ data: result.results || [], total: count?.total || 0, limit, offset });
    }
    if (request.method === "POST" && path === "/api/crm/leads") {
      if (!canManageCrm) return error("CRM lead creation permission is required.",403);
      const body = await request.json<{ name?:string; company?:string; email?:string; phone?:string; website?:string; industry?:string; country?:string; region?:string; source?:string; interest?:string; estimatedValue?:number; currency?:string; ownerId?:string; description?:string; nextFollowUpAt?:string; tags?:string[] }>();
      const name=body.name?.trim()||"", email=body.email?.trim().toLowerCase()||"", ownerId=body.ownerId||context.userId, value=Number(body.estimatedValue||0);
      if (!name||name.length>160||email.length>254||(email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))||!Number.isFinite(value)||value<0||value>1_000_000_000_000||body.description&&body.description.length>4000||body.tags&&(!Array.isArray(body.tags)||body.tags.length>30)) return error("Enter a valid lead name, email and non-negative estimated value.");
      if (ownerId!==context.userId&&!hasPermission(context,"crm.assign")) return error("Lead assignment permission is required.",403);
      const owner=await env.DB.prepare(`SELECT 1 FROM memberships WHERE organization_id=? AND user_id=? AND status='active'`).bind(context.organizationId,ownerId).first();
      if (!owner) return error("Lead owner must be an active member of this organization.");
      if (body.source) { const source=await env.DB.prepare(`SELECT 1 FROM crm_lead_sources WHERE organization_id=? AND name=? AND active=1`).bind(context.organizationId,body.source).first(); if(!source)return error("Choose a configured lead source."); }
      if (body.nextFollowUpAt && Number.isNaN(Date.parse(body.nextFollowUpAt))) return error("Enter a valid follow-up date and time.");
      const id=`crm-lead-${requestId()}`, number=`LD-${crypto.randomUUID().slice(0,8).toUpperCase()}`;
      const scored=await evaluateCrmLead(env,context.organizationId,{has_email:email,has_phone:body.phone,has_website:body.website,has_company:body.company,industry:body.industry,country:body.country,source:body.source,interest:body.interest,estimated_value_min:value});
      await env.DB.prepare(`INSERT INTO crm_leads (id,organization_id,lead_number,name,company,email,phone,website,industry,country,region,source,interest,estimated_value,estimated_value_minor,currency,owner_id,status,temperature,score,description,tags_json,created_by,updated_by,next_follow_up_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'new',?,?, ?,?,?,?,?)`).bind(id,context.organizationId,number,name,body.company?.trim()||null,email||null,body.phone?.trim()||null,body.website?.trim()||null,body.industry?.trim()||null,body.country?.trim()||null,body.region?.trim()||null,body.source||null,body.interest?.trim()||null,value,Math.round(value*100),(body.currency||"NGN").toUpperCase(),ownerId,scored.temperature,scored.score,body.description?.trim()||null,JSON.stringify(body.tags||[]),context.userId,context.userId,body.nextFollowUpAt||null).run();
      await audit(env,context,"created","crm_leads",id,body); await recordCrmEvent(env,context,"lead.created","lead",id,{name,ownerId,source:body.source||null});
      if(ownerId!==context.userId) await env.DB.prepare(`INSERT INTO notifications (id,organization_id,user_id,type,title,body) VALUES (?,?,?,'crm_lead_assigned','Lead assigned',?)`).bind(requestId(),context.organizationId,ownerId,`${name} was assigned to you.`).run();
      return json({id,leadNumber:number},{status:201});
    }
    const crmLeadMatch=path.match(/^\/api\/crm\/leads\/([^/]+)$/);
    if (request.method === "PATCH" && crmLeadMatch) {
      if (!canManageCrm) return error("CRM lead edit permission is required.",403);
      const current=await env.DB.prepare(`SELECT * FROM crm_leads WHERE id=? AND organization_id=?`).bind(crmLeadMatch[1],context.organizationId).first<Record<string,any>>();
      if(!current)return error("Lead not found.",404);
      if(!canSeeAll&&current.owner_id!==context.userId)return error("You can only edit your own leads.",403);
      const body=await request.json<{name?:string;company?:string|null;email?:string|null;phone?:string|null;website?:string|null;industry?:string|null;country?:string|null;region?:string|null;source?:string|null;interest?:string|null;estimatedValue?:number;currency?:string;ownerId?:string;status?:string;temperature?:string;description?:string|null;nextFollowUpAt?:string|null;tags?:string[]}>();
      const statuses=["new","contacted","qualified","disqualified"], temperatures=["hot","warm","cold"];
      if(body.name!==undefined&&(!body.name.trim()||body.name.trim().length>160)||body.email&& !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)||body.status&&(!statuses.includes(body.status)||current.status==="converted")||body.temperature&&!temperatures.includes(body.temperature)||body.estimatedValue!==undefined&&(!Number.isFinite(Number(body.estimatedValue))||Number(body.estimatedValue)<0)||body.nextFollowUpAt&&Number.isNaN(Date.parse(body.nextFollowUpAt)))return error("One or more lead fields are invalid. Use the convert action to create a customer and opportunity.");
      const ownerId=body.ownerId??current.owner_id;
      if(ownerId!==current.owner_id&&!hasPermission(context,"crm.assign"))return error("Lead assignment permission is required.",403);
      if(ownerId){const member=await env.DB.prepare(`SELECT 1 FROM memberships WHERE organization_id=? AND user_id=? AND status='active'`).bind(context.organizationId,ownerId).first();if(!member)return error("Lead owner must be an active member of this organization.");}
      const next={name:body.name?.trim()??current.name,company:body.company===undefined?current.company:body.company?.trim()||null,email:body.email===undefined?current.email:body.email?.trim().toLowerCase()||null,phone:body.phone===undefined?current.phone:body.phone?.trim()||null,website:body.website===undefined?current.website:body.website?.trim()||null,industry:body.industry===undefined?current.industry:body.industry?.trim()||null,country:body.country===undefined?current.country:body.country?.trim()||null,region:body.region===undefined?current.region:body.region?.trim()||null,source:body.source===undefined?current.source:body.source,interest:body.interest===undefined?current.interest:body.interest?.trim()||null,estimatedValue:body.estimatedValue===undefined?Number(current.estimated_value_minor)/100:Number(body.estimatedValue),currency:body.currency?.toUpperCase()??current.currency,ownerId,status:body.status??current.status,temperature:body.temperature??current.temperature,description:body.description===undefined?current.description:body.description?.trim()||null,nextFollowUpAt:body.nextFollowUpAt===undefined?current.next_follow_up_at:body.nextFollowUpAt,tagsJson:body.tags===undefined?current.tags_json:JSON.stringify(body.tags)};
      const scored=await evaluateCrmLead(env,context.organizationId,{has_email:next.email,has_phone:next.phone,has_website:next.website,has_company:next.company,industry:next.industry,country:next.country,source:next.source,interest:next.interest,estimated_value_min:next.estimatedValue});if(!body.temperature)next.temperature=scored.temperature;
      await env.DB.prepare(`UPDATE crm_leads SET name=?,company=?,email=?,phone=?,website=?,industry=?,country=?,region=?,source=?,interest=?,estimated_value=?,estimated_value_minor=?,currency=?,owner_id=?,status=?,temperature=?,score=?,description=?,next_follow_up_at=?,tags_json=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?`).bind(next.name,next.company,next.email,next.phone,next.website,next.industry,next.country,next.region,next.source,next.interest,next.estimatedValue,Math.round(next.estimatedValue*100),next.currency,next.ownerId,next.status,next.temperature,scored.score,next.description,next.nextFollowUpAt,next.tagsJson,context.userId,current.id,context.organizationId).run();
      await audit(env,context,body.status&&body.status!==current.status?`status_${body.status}`:body.ownerId&&body.ownerId!==current.owner_id?"reassigned":"updated","crm_leads",current.id,next,current); if(body.status&&body.status!==current.status)await recordCrmEvent(env,context,body.status==="qualified"?"lead.qualified":"lead.status_changed","lead",current.id,{from:current.status,to:body.status});
      return json({ok:true});
    }
    const crmConvertMatch=path.match(/^\/api\/crm\/leads\/([^/]+)\/convert$/);
    if(request.method==="POST"&&crmConvertMatch){
      if(!canManageCrm)return error("CRM lead conversion permission is required.",403);
      const lead=await env.DB.prepare(`SELECT * FROM crm_leads WHERE id=? AND organization_id=?`).bind(crmConvertMatch[1],context.organizationId).first<Record<string,any>>();
      if(!lead)return error("Lead not found.",404); if(!canSeeAll&&lead.owner_id!==context.userId)return error("You can only convert your own leads.",403); if(lead.status==="converted")return error("This lead has already been converted.",409); if(lead.status!=="qualified")return error("Qualify the lead before converting it.",409);
      const body=await request.json<{opportunityName?:string;expectedCloseDate?:string;probability?:number}>();
      if(body.expectedCloseDate&&!isIsoCalendarDate(body.expectedCloseDate)||body.probability!==undefined&&(!Number.isInteger(body.probability)||body.probability<0||body.probability>100))return error("Enter a valid expected close date and probability.");
      const customerId=`customer-${crypto.randomUUID()}`, opportunityId=`crm-opp-${requestId()}`, oppNumber=`OP-${crypto.randomUUID().slice(0,8).toUpperCase()}`;
      const customerName=lead.company||lead.name;
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO customers (id,organization_id,name,company,email,stage,value,owner_id,last_activity_at,customer_status,industry,website,phone,country,source,updated_by) VALUES (?,?,?,?,?,'qualified',?,?,date('now'),'prospect',?,?,?,?,?,?)`).bind(customerId,context.organizationId,lead.name,lead.company,lead.email,lead.estimated_value,lead.owner_id,lead.industry,lead.website,lead.phone,lead.country,lead.source,context.userId),
        env.DB.prepare(`INSERT INTO crm_opportunities (id,organization_id,opportunity_number,name,customer_id,lead_id,owner_id,stage,value,value_minor,currency,probability,expected_close_date,source,product,description,created_by,updated_by) VALUES (?,?,?,?,?,?,?,'qualification',?,?,?,?,?,?,?,?,?,?)`).bind(opportunityId,context.organizationId,oppNumber,body.opportunityName?.trim()||`${customerName} opportunity`,customerId,lead.id,lead.owner_id,lead.estimated_value,lead.estimated_value_minor,lead.currency,body.probability??10,body.expectedCloseDate||null,lead.source,lead.interest,lead.description,context.userId,context.userId),
        env.DB.prepare(`UPDATE crm_leads SET status='converted',converted_customer_id=?,converted_opportunity_id=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?`).bind(customerId,opportunityId,context.userId,lead.id,context.organizationId),
      ]);
      await audit(env,context,"converted","crm_leads",lead.id,{customerId,opportunityId},lead); await recordCrmEvent(env,context,"lead.converted","lead",lead.id,{customerId,opportunityId}); await recordCrmEvent(env,context,"customer.created","customer",customerId,{leadId:lead.id}); await recordCrmEvent(env,context,"opportunity.created","opportunity",opportunityId,{leadId:lead.id,customerId});
      return json({customerId,opportunityId},{status:201});
    }
    if(request.method==="GET"&&path==="/api/crm/opportunities"){
      const result=await env.DB.prepare(`SELECT o.id,o.opportunity_number as opportunityNumber,o.name,o.customer_id as customerId,c.company as company,c.name as contactName,o.lead_id as leadId,o.owner_id as ownerId,u.full_name as owner,o.stage,o.status,o.value_minor/100.0 as value,o.value_minor as valueMinor,o.currency,o.probability,o.expected_close_date as expectedCloseDate,o.source,o.product,o.priority,o.description,o.loss_reason as lossReason,o.created_at as createdAt,o.last_activity_at as lastActivityAt FROM crm_opportunities o LEFT JOIN customers c ON c.id=o.customer_id AND c.organization_id=o.organization_id LEFT JOIN users u ON u.id=o.owner_id WHERE o.organization_id=? AND (?=1 OR o.owner_id=?) ORDER BY CASE o.stage WHEN 'qualification' THEN 1 WHEN 'discovery' THEN 2 WHEN 'proposal' THEN 3 WHEN 'negotiation' THEN 4 WHEN 'won' THEN 5 ELSE 6 END,o.expected_close_date LIMIT 500`).bind(context.organizationId,canSeeAll?1:0,context.userId).all();
      const stages=await env.DB.prepare(`SELECT stage_key as stageKey,name,probability,sort_order as sortOrder FROM crm_pipeline_stages WHERE organization_id=? AND active=1 ORDER BY sort_order`).bind(context.organizationId).all(); return json({data:result.results||[],stages:stages.results||[]});
    }
    if(request.method==="POST"&&path==="/api/crm/opportunities"){
      if(!canManageCrm)return error("CRM opportunity creation permission is required.",403);
      const body=await request.json<{name?:string;customerId?:string;leadId?:string;value?:number;currency?:string;stage?:string;expectedCloseDate?:string;probability?:number;source?:string;product?:string;priority?:string;description?:string}>();
      const value=Number(body.value||0),stage=body.stage||"qualification";
      const stageRow=await env.DB.prepare(`SELECT probability FROM crm_pipeline_stages WHERE organization_id=? AND stage_key=? AND active=1`).bind(context.organizationId,stage).first<{probability:number}>();
      if(!body.name?.trim()||body.name.length>180||!stageRow||!Number.isFinite(value)||value<0||body.expectedCloseDate&&!isIsoCalendarDate(body.expectedCloseDate))return error("Enter a valid opportunity name, stage, value and close date.");
      if(body.customerId){const customer=await env.DB.prepare(`SELECT id FROM customers WHERE id=? AND organization_id=?`).bind(body.customerId,context.organizationId).first();if(!customer)return error("Customer does not exist in this organization.");}
      const id=`crm-opp-${requestId()}`,number=`OP-${crypto.randomUUID().slice(0,8).toUpperCase()}`;
      await env.DB.prepare(`INSERT INTO crm_opportunities (id,organization_id,opportunity_number,name,customer_id,lead_id,owner_id,stage,value,value_minor,currency,probability,expected_close_date,source,product,priority,description,created_by,updated_by) VALUES (?,?,?,?,?,?,?, ?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,context.organizationId,number,body.name.trim(),body.customerId||null,body.leadId||null,context.userId,stage,value,Math.round(value*100),(body.currency||"NGN").toUpperCase(),body.probability??stageRow.probability,body.expectedCloseDate||null,body.source||null,body.product||null,body.priority||"medium",body.description?.trim()||null,context.userId,context.userId).run();
      await audit(env,context,"created","crm_opportunities",id,body);await recordCrmEvent(env,context,"opportunity.created","opportunity",id,{stage,value});return json({id,opportunityNumber:number},{status:201});
    }
    const crmOppMatch=path.match(/^\/api\/crm\/opportunities\/([^/]+)$/);
    if(request.method==="PATCH"&&crmOppMatch){
      if(!canManageCrm)return error("CRM opportunity edit permission is required.",403);
      const current=await env.DB.prepare(`SELECT * FROM crm_opportunities WHERE id=? AND organization_id=?`).bind(crmOppMatch[1],context.organizationId).first<Record<string,any>>(); if(!current)return error("Opportunity not found.",404); if(!canSeeAll&&current.owner_id!==context.userId)return error("You can only edit your own opportunities.",403);
      const body=await request.json<{stage?:string;value?:number;probability?:number;expectedCloseDate?:string|null;lossReason?:string;name?:string;priority?:string}>();
      const stage=body.stage??current.stage,stageRow=await env.DB.prepare(`SELECT probability FROM crm_pipeline_stages WHERE organization_id=? AND stage_key=? AND active=1`).bind(context.organizationId,stage).first<{probability:number}>(); if(!stageRow)return error("Choose a configured pipeline stage.");
      if(body.stage==="lost"&&!body.lossReason?.trim()&&current.stage!=="lost")return error("A loss reason is required before marking an opportunity lost.");
      if(body.value!==undefined&&(!Number.isFinite(Number(body.value))||Number(body.value)<0)||body.probability!==undefined&&(!Number.isInteger(body.probability)||body.probability<0||body.probability>100)||body.expectedCloseDate&& !isIsoCalendarDate(body.expectedCloseDate))return error("Opportunity value, probability or close date is invalid.");
      if(body.stage==="won"&&!current.customer_id)return error("Link this opportunity to a customer before marking it won.");
      const value=body.value===undefined?current.value:Number(body.value),probability=body.probability??(body.stage?stageRow.probability:current.probability),status=stage==="won"?"won":stage==="lost"?"lost":"open";
      await env.DB.prepare(`UPDATE crm_opportunities SET name=?,stage=?,status=?,value=?,value_minor=?,probability=?,expected_close_date=?,loss_reason=?,priority=?,won_at=CASE WHEN ?='won' THEN COALESCE(won_at,CURRENT_TIMESTAMP) ELSE won_at END,lost_at=CASE WHEN ?='lost' THEN COALESCE(lost_at,CURRENT_TIMESTAMP) ELSE lost_at END,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?`).bind(body.name?.trim()||current.name,stage,status,value,Math.round(value*100),probability,body.expectedCloseDate===undefined?current.expected_close_date:body.expectedCloseDate||null,body.lossReason===undefined?current.loss_reason:body.lossReason.trim()||null,body.priority||current.priority,status,status,context.userId,current.id,context.organizationId).run();
      await audit(env,context,body.stage&&body.stage!==current.stage?`stage_${body.stage}`:"updated","crm_opportunities",current.id,{...body,status},current);
      if(body.stage&&body.stage!==current.stage)await recordCrmEvent(env,context,body.stage==="won"?"opportunity.won":body.stage==="lost"?"opportunity.lost":"opportunity.stage_changed","opportunity",current.id,{from:current.stage,to:body.stage,value,lossReason:body.lossReason||null});
      if(body.stage==="won"&&current.customer_id)await env.DB.prepare(`UPDATE customers SET customer_status='active',stage='won',won_at=COALESCE(won_at,CURRENT_TIMESTAMP),updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?`).bind(context.userId,current.customer_id,context.organizationId).run();
      return json({ok:true,status});
    }
    if(request.method==="GET"&&path==="/api/crm/activities"){
      const followup=crmUrl.searchParams.get("view")==="followups";
      const result=await env.DB.prepare(`SELECT a.id,a.activity_type as activityType,a.subject,a.description,a.owner_id as ownerId,u.full_name as owner,a.lead_id as leadId,l.name as leadName,a.customer_id as customerId,c.company as company,a.opportunity_id as opportunityId,o.name as opportunityName,a.starts_at as startsAt,a.due_at as dueAt,a.priority,a.status,a.outcome,a.created_at as createdAt FROM crm_activities a LEFT JOIN users u ON u.id=a.owner_id LEFT JOIN crm_leads l ON l.id=a.lead_id AND l.organization_id=a.organization_id LEFT JOIN customers c ON c.id=a.customer_id AND c.organization_id=a.organization_id LEFT JOIN crm_opportunities o ON o.id=a.opportunity_id AND o.organization_id=a.organization_id WHERE a.organization_id=? AND (?=1 OR a.owner_id=?) AND (?=0 OR a.activity_type='follow_up') ORDER BY CASE WHEN a.status='completed' THEN 1 ELSE 0 END,a.due_at LIMIT 300`).bind(context.organizationId,canSeeAll?1:0,context.userId,followup?1:0).all(); return json({data:result.results||[]});
    }
    if(request.method==="POST"&&path==="/api/crm/activities"){
      if(!canManageCrm)return error("CRM activity creation permission is required.",403);
      const body=await request.json<{activityType?:string;subject?:string;description?:string;leadId?:string;customerId?:string;opportunityId?:string;dueAt?:string;startsAt?:string;priority?:string}>();
      if(!body.subject?.trim()||body.subject.length>180||!['call','email','meeting','task','follow_up','demo','presentation','site_visit','note'].includes(body.activityType||'')||(!body.leadId&&!body.customerId&&!body.opportunityId)||body.dueAt&&Number.isNaN(Date.parse(body.dueAt)))return error("Provide an activity type, subject, related CRM record and valid due date.");
      if(body.leadId){const x=await env.DB.prepare(`SELECT id FROM crm_leads WHERE id=? AND organization_id=? AND (?=1 OR owner_id=?)`).bind(body.leadId,context.organizationId,canSeeAll?1:0,context.userId).first();if(!x)return error("Related lead is unavailable.",404);}
      if(body.customerId){const x=await env.DB.prepare(`SELECT id FROM customers WHERE id=? AND organization_id=?`).bind(body.customerId,context.organizationId).first();if(!x)return error("Related customer is unavailable.",404);}
      if(body.opportunityId){const x=await env.DB.prepare(`SELECT id FROM crm_opportunities WHERE id=? AND organization_id=? AND (?=1 OR owner_id=?)`).bind(body.opportunityId,context.organizationId,canSeeAll?1:0,context.userId).first();if(!x)return error("Related opportunity is unavailable.",404);}
      const id=`crm-act-${requestId()}`; await env.DB.prepare(`INSERT INTO crm_activities (id,organization_id,activity_type,subject,description,owner_id,lead_id,customer_id,opportunity_id,starts_at,due_at,priority,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,context.organizationId,body.activityType,body.subject.trim(),body.description?.trim()||null,context.userId,body.leadId||null,body.customerId||null,body.opportunityId||null,body.startsAt||null,body.dueAt||null,body.priority||"medium",context.userId).run();
      if(body.leadId)await env.DB.prepare(`UPDATE crm_leads SET last_activity_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?`).bind(body.leadId,context.organizationId).run(); if(body.opportunityId)await env.DB.prepare(`UPDATE crm_opportunities SET last_activity_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?`).bind(body.opportunityId,context.organizationId).run();
      await audit(env,context,"created","crm_activities",id,body);await recordCrmEvent(env,context,"activity.created","activity",id,{activityType:body.activityType,subject:body.subject});return json({id},{status:201});
    }
    const crmActivityMatch=path.match(/^\/api\/crm\/activities\/([^/]+)$/);
    if(request.method==="PATCH"&&crmActivityMatch){
      if(!canManageCrm)return error("CRM activity edit permission is required.",403);
      const current=await env.DB.prepare(`SELECT * FROM crm_activities WHERE id=? AND organization_id=?`).bind(crmActivityMatch[1],context.organizationId).first<Record<string,any>>();if(!current)return error("Activity not found.",404);if(!canSeeAll&&current.owner_id!==context.userId)return error("You can only update your own activities.",403);
      const body=await request.json<{status?:string;outcome?:string;subject?:string}>();if(body.status&&!['planned','in_progress','completed','cancelled'].includes(body.status))return error("Choose a valid activity status.");
      await env.DB.prepare(`UPDATE crm_activities SET status=COALESCE(?,status),outcome=CASE WHEN ? IS NULL THEN outcome ELSE ? END,subject=COALESCE(?,subject),updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?`).bind(body.status||null,body.outcome===undefined?null:1,body.outcome??null,body.subject?.trim()||null,current.id,context.organizationId).run();
      await audit(env,context,body.status==="completed"?"completed":"updated","crm_activities",current.id,body,current);if(body.status==="completed"&&current.status!=="completed")await recordCrmEvent(env,context,"activity.completed","activity",current.id,{subject:current.subject});return json({ok:true});
    }
    if(path==="/api/crm/config"&&request.method==="GET"){
      if(!hasPermission(context,"crm.configure"))return error("CRM configuration permission is required.",403);
      const [sources,stages,rules]=await Promise.all([env.DB.prepare(`SELECT id,name,active FROM crm_lead_sources WHERE organization_id=? ORDER BY name`).bind(context.organizationId).all(),env.DB.prepare(`SELECT stage_key as stageKey,name,probability,sort_order as sortOrder,active FROM crm_pipeline_stages WHERE organization_id=? ORDER BY sort_order`).bind(context.organizationId).all(),env.DB.prepare(`SELECT id,factor_key as factorKey,label,points,condition_json as conditionJson,active FROM crm_scoring_rules WHERE organization_id=? ORDER BY label`).bind(context.organizationId).all()]);return json({sources:sources.results||[],stages:stages.results||[],scoringRules:rules.results||[]});
    }
    const sourceMatch=path.match(/^\/api\/crm\/sources\/([^/]+)$/);
    if(request.method==="POST"&&path==="/api/crm/sources"){
      if(!hasPermission(context,"crm.configure"))return error("CRM configuration permission is required.",403);const body=await request.json<{name?:string}>();if(!body.name?.trim()||body.name.length>80)return error("Enter a source name up to 80 characters.");const id=`crm-source-${requestId()}`;await env.DB.prepare(`INSERT INTO crm_lead_sources(id,organization_id,name) VALUES(?,?,?)`).bind(id,context.organizationId,body.name.trim()).run();await audit(env,context,"created","crm_lead_sources",id,{name:body.name.trim()});return json({id},{status:201});
    }
    if(request.method==="PATCH"&&sourceMatch){
      if(!hasPermission(context,"crm.configure"))return error("CRM configuration permission is required.",403);const body=await request.json<{name?:string;active?:boolean}>();if(body.name!==undefined&&(!body.name.trim()||body.name.length>80)||body.active!==undefined&&typeof body.active!=="boolean")return error("Source update is invalid.");const changed=await env.DB.prepare(`UPDATE crm_lead_sources SET name=COALESCE(?,name),active=COALESCE(?,active) WHERE id=? AND organization_id=?`).bind(body.name?.trim()||null,body.active===undefined?null:body.active?1:0,sourceMatch[1],context.organizationId).run();if(!changed.meta.changes)return error("Lead source not found.",404);await audit(env,context,"updated","crm_lead_sources",sourceMatch[1],body);return json({ok:true});
    }
    const stageMatch=path.match(/^\/api\/crm\/stages\/([a-z_]+)$/);
    if(request.method==="PATCH"&&stageMatch){
      if(!hasPermission(context,"crm.configure"))return error("CRM configuration permission is required.",403);const body=await request.json<{name?:string;probability?:number;sortOrder?:number;active?:boolean}>();if(body.name!==undefined&&(!body.name.trim()||body.name.length>80)||body.probability!==undefined&&(!Number.isInteger(body.probability)||body.probability<0||body.probability>100)||body.sortOrder!==undefined&&(!Number.isInteger(body.sortOrder)||body.sortOrder<0||body.sortOrder>100)||body.active!==undefined&&typeof body.active!=="boolean")return error("Pipeline stage update is invalid.");const changed=await env.DB.prepare(`UPDATE crm_pipeline_stages SET name=COALESCE(?,name),probability=COALESCE(?,probability),sort_order=COALESCE(?,sort_order),active=COALESCE(?,active) WHERE organization_id=? AND stage_key=?`).bind(body.name?.trim()||null,body.probability??null,body.sortOrder??null,body.active===undefined?null:body.active?1:0,context.organizationId,stageMatch[1]).run();if(!changed.meta.changes)return error("Pipeline stage not found.",404);await audit(env,context,"updated","crm_pipeline_stages",stageMatch[1],body);return json({ok:true});
    }
    if(path==="/api/crm/scoring"&&(request.method==="GET"||request.method==="PUT")){
      if(!hasPermission(context,"crm.configure"))return error("CRM configuration permission is required.",403);
      if(request.method==="GET"){const rows=await env.DB.prepare(`SELECT id,factor_key as factorKey,label,points,condition_json as conditionJson,active FROM crm_scoring_rules WHERE organization_id=? ORDER BY label`).bind(context.organizationId).all();return json({data:rows.results||[]});}
      const body=await request.json<{rules?:{factorKey:string;label:string;points:number;condition?:Record<string,unknown>;active?:boolean}[]}>();const allowed=new Set(["has_email","has_phone","has_company","has_website","industry","country","source","interest","estimated_value_min"]);if(!Array.isArray(body.rules)||body.rules.length>30||body.rules.some((r)=>!allowed.has(r.factorKey)||!r.label?.trim()||r.label.length>100||!Number.isInteger(r.points)||r.points<0||r.points>100||r.condition&&JSON.stringify(r.condition).length>500||r.active!==undefined&&typeof r.active!=="boolean"))return error("Scoring rules contain unsupported factors or invalid values.");
      const statements=body.rules.map((r)=>env.DB.prepare(`INSERT INTO crm_scoring_rules(id,organization_id,factor_key,label,points,condition_json,active,updated_by) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(organization_id,factor_key) DO UPDATE SET label=excluded.label,points=excluded.points,condition_json=excluded.condition_json,active=excluded.active,updated_by=excluded.updated_by,updated_at=CURRENT_TIMESTAMP`).bind(`score-${requestId()}`,context.organizationId,r.factorKey,r.label.trim(),r.points,JSON.stringify(r.condition||{}),r.active===false?0:1,context.userId));await env.DB.batch(statements);await audit(env,context,"updated","crm_scoring_rules",context.organizationId,{rules:body.rules.length});return json({ok:true});
    }
    if(path==="/api/crm/contacts"&&request.method==="GET"){
      const customerId=crmUrl.searchParams.get("customerId")||"";const rows=await env.DB.prepare(`SELECT x.id,x.customer_id as customerId,c.company as company,x.first_name as firstName,x.last_name as lastName,x.job_title as jobTitle,x.department,x.email,x.phone,x.alternative_phone as alternativePhone,x.linkedin_url as linkedinUrl,x.decision_maker as decisionMaker,x.influence_level as influenceLevel,x.preferred_communication as preferredCommunication,x.notes,x.tags_json as tagsJson FROM crm_contacts x LEFT JOIN customers c ON c.id=x.customer_id AND c.organization_id=x.organization_id WHERE x.organization_id=? AND (?='' OR x.customer_id=?) AND (?=1 OR EXISTS(SELECT 1 FROM customers c2 WHERE c2.id=x.customer_id AND c2.organization_id=x.organization_id AND c2.owner_id=?)) ORDER BY x.last_name,x.first_name LIMIT 500`).bind(context.organizationId,customerId,customerId,canSeeAll?1:0,context.userId).all();return json({data:rows.results||[]});
    }
    if(path==="/api/crm/contacts"&&request.method==="POST"){
      if(!canManageCrm)return error("CRM contact management permission is required.",403);const body=await request.json<{customerId?:string;firstName?:string;lastName?:string;jobTitle?:string;department?:string;email?:string;phone?:string;alternativePhone?:string;linkedinUrl?:string;decisionMaker?:boolean;influenceLevel?:string;preferredCommunication?:string;notes?:string}>();if(!body.firstName?.trim()||!body.lastName?.trim()||body.firstName.length>100||body.lastName.length>100||body.email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)||body.influenceLevel&&!['low','medium','high'].includes(body.influenceLevel))return error("Contact fields are invalid.");if(body.customerId&&!await env.DB.prepare(`SELECT 1 FROM customers WHERE id=? AND organization_id=? AND (?=1 OR owner_id=?)`).bind(body.customerId,context.organizationId,canSeeAll?1:0,context.userId).first())return error("Customer is unavailable in this organization.",404);const id=`contact-${requestId()}`;await env.DB.prepare(`INSERT INTO crm_contacts(id,organization_id,customer_id,first_name,last_name,job_title,department,email,phone,alternative_phone,linkedin_url,decision_maker,influence_level,preferred_communication,notes,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,context.organizationId,body.customerId||null,body.firstName.trim(),body.lastName.trim(),body.jobTitle?.trim()||null,body.department?.trim()||null,body.email?.trim().toLowerCase()||null,body.phone?.trim()||null,body.alternativePhone?.trim()||null,body.linkedinUrl?.trim()||null,body.decisionMaker?1:0,body.influenceLevel||null,body.preferredCommunication||null,body.notes?.trim()||null,context.userId).run();await audit(env,context,"created","crm_contacts",id,body);return json({id},{status:201});
    }
    const crmContactMatch=path.match(/^\/api\/crm\/contacts\/([^/]+)$/);
    if(request.method==="PATCH"&&crmContactMatch){if(!canManageCrm)return error("CRM contact management permission is required.",403);const current=await env.DB.prepare(`SELECT * FROM crm_contacts WHERE id=? AND organization_id=?`).bind(crmContactMatch[1],context.organizationId).first<Record<string,any>>();if(!current)return error("Contact not found.",404);const body=await request.json<{customerId?:string|null;firstName?:string;lastName?:string;jobTitle?:string;department?:string;email?:string;phone?:string;decisionMaker?:boolean;influenceLevel?:string;notes?:string}>();if(body.firstName!==undefined&&!body.firstName.trim()||body.lastName!==undefined&&!body.lastName.trim()||body.email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)||body.influenceLevel&&!['low','medium','high'].includes(body.influenceLevel))return error("Contact fields are invalid.");const customerId=body.customerId===undefined?current.customer_id:body.customerId||null;if(customerId&&!await env.DB.prepare(`SELECT 1 FROM customers WHERE id=? AND organization_id=?`).bind(customerId,context.organizationId).first())return error("Customer is unavailable in this organization.",404);const values={customerId,firstName:body.firstName?.trim()??current.first_name,lastName:body.lastName?.trim()??current.last_name,jobTitle:body.jobTitle?.trim()??current.job_title,department:body.department?.trim()??current.department,email:body.email?.trim().toLowerCase()??current.email,phone:body.phone?.trim()??current.phone,decisionMaker:body.decisionMaker===undefined?current.decision_maker:body.decisionMaker?1:0,influenceLevel:body.influenceLevel??current.influence_level,notes:body.notes?.trim()??current.notes};await env.DB.prepare(`UPDATE crm_contacts SET customer_id=?,first_name=?,last_name=?,job_title=?,department=?,email=?,phone=?,decision_maker=?,influence_level=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?`).bind(values.customerId,values.firstName,values.lastName,values.jobTitle,values.department,values.email,values.phone,values.decisionMaker,values.influenceLevel,values.notes,current.id,context.organizationId).run();await audit(env,context,"updated","crm_contacts",current.id,values,current);return json({ok:true});}
    if(path==="/api/crm/products"&&request.method==="GET"){const rows=await env.DB.prepare(`SELECT id,name,code,description,currency,price_minor as priceMinor,active FROM crm_products WHERE organization_id=? AND (?=1 OR active=1) ORDER BY name`).bind(context.organizationId,canSeeAll?1:0).all();return json({data:rows.results||[]});}
    if(path==="/api/crm/products"&&request.method==="POST"){
      if(!hasPermission(context,"crm.quotes.manage"))return error("CRM quotation/product permission is required.",403);const body=await request.json<{name?:string;code?:string;description?:string;currency?:string;priceMinor?:number}>();if(!body.name?.trim()||body.name.length>120||!Number.isSafeInteger(body.priceMinor)||Number(body.priceMinor)<0||body.currency&&!/^[A-Z]{3}$/i.test(body.currency))return error("Enter a product name, three-letter currency and integer minor-unit price.");const id=`product-${requestId()}`;await env.DB.prepare(`INSERT INTO crm_products(id,organization_id,name,code,description,currency,price_minor) VALUES(?,?,?,?,?,?,?)`).bind(id,context.organizationId,body.name.trim(),body.code?.trim()||null,body.description?.trim()||null,(body.currency||"NGN").toUpperCase(),body.priceMinor).run();await audit(env,context,"created","crm_products",id,{...body,priceMinor:body.priceMinor});return json({id},{status:201});
    }
    if(path==="/api/crm/quotations"&&request.method==="GET"){const rows=await env.DB.prepare(`SELECT q.id,q.quote_number as quoteNumber,q.customer_id as customerId,c.company as company,q.opportunity_id as opportunityId,q.currency,q.subtotal_minor as subtotalMinor,q.tax_minor as taxMinor,q.total_minor as totalMinor,q.status,q.valid_until as validUntil,q.notes,q.created_at as createdAt FROM crm_quotations q LEFT JOIN customers c ON c.id=q.customer_id AND c.organization_id=q.organization_id WHERE q.organization_id=? AND (?=1 OR EXISTS(SELECT 1 FROM crm_opportunities o WHERE o.id=q.opportunity_id AND o.organization_id=q.organization_id AND o.owner_id=?)) ORDER BY q.created_at DESC LIMIT 300`).bind(context.organizationId,canSeeAll?1:0,context.userId).all();return json({data:rows.results||[]});}
    if(path==="/api/crm/quotations"&&request.method==="POST"){
      if(!hasPermission(context,"crm.quotes.manage"))return error("CRM quotation permission is required.",403);const body=await request.json<{customerId?:string;opportunityId?:string;contactId?:string;currency?:string;taxMinor?:number;validUntil?:string;notes?:string;lines?:{productId?:string;description:string;quantityMilli:number;unitPriceMinor:number}[]}>();const lines=body.lines||[];if(!lines.length||lines.length>100||!Number.isSafeInteger(body.taxMinor||0)||(body.taxMinor||0)<0||body.validUntil&&!isoDate(body.validUntil)||!lines.every(l=>l.description?.trim()&&Number.isSafeInteger(l.quantityMilli)&&l.quantityMilli>0&&Number.isSafeInteger(l.unitPriceMinor)&&l.unitPriceMinor>=0))return error("Quotation lines, tax or validity are invalid.");
      if(body.currency&&!/^[A-Z]{3}$/i.test(body.currency))return error("Quotation currency must be a three-letter ISO code.");if(body.customerId&&!await env.DB.prepare(`SELECT 1 FROM customers WHERE id=? AND organization_id=?`).bind(body.customerId,context.organizationId).first())return error("Customer not found.",404);if(body.opportunityId&&!await env.DB.prepare(`SELECT 1 FROM crm_opportunities WHERE id=? AND organization_id=? AND (?=1 OR owner_id=?)`).bind(body.opportunityId,context.organizationId,canSeeAll?1:0,context.userId).first())return error("Opportunity is unavailable.",404);if(body.contactId&&!await env.DB.prepare(`SELECT 1 FROM crm_contacts WHERE id=? AND organization_id=? AND (? IS NULL OR customer_id=? OR customer_id IS NULL)`).bind(body.contactId,context.organizationId,body.customerId||null,body.customerId||null).first())return error("Contact not found or not linked to the selected customer.",404);for(const line of lines)if(line.productId&&!await env.DB.prepare(`SELECT 1 FROM crm_products WHERE id=? AND organization_id=? AND active=1`).bind(line.productId,context.organizationId).first())return error("A quotation product is not active in this organization.",404);
      const lineAmounts=lines.map(l=>Math.round(l.quantityMilli*l.unitPriceMinor/1000));const subtotalMinor=lineAmounts.reduce((a,b)=>a+b,0);if(!Number.isSafeInteger(subtotalMinor+(body.taxMinor||0)))return error("Quotation total exceeds the supported range.");const totalMinor=subtotalMinor+(body.taxMinor||0),id=`quote-${requestId()}`,quoteNumber=`Q-${crypto.randomUUID().slice(0,8).toUpperCase()}`;const statements=[env.DB.prepare(`INSERT INTO crm_quotations(id,organization_id,quote_number,customer_id,opportunity_id,contact_id,currency,subtotal_minor,tax_minor,total_minor,valid_until,notes,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,context.organizationId,quoteNumber,body.customerId||null,body.opportunityId||null,body.contactId||null,(body.currency||"NGN").toUpperCase(),subtotalMinor,body.taxMinor||0,totalMinor,body.validUntil||null,body.notes?.trim()||null,context.userId),...lines.map((l,i)=>env.DB.prepare(`INSERT INTO crm_quotation_lines(id,organization_id,quotation_id,product_id,description,quantity_milli,unit_price_minor,line_total_minor) VALUES(?,?,?,?,?,?,?,?)`).bind(`quote-line-${requestId()}`,context.organizationId,id,l.productId||null,l.description.trim(),l.quantityMilli,l.unitPriceMinor,lineAmounts[i]))];await env.DB.batch(statements);await audit(env,context,"created","crm_quotations",id,{quoteNumber,totalMinor,currency:body.currency||"NGN"});return json({id,quoteNumber,totalMinor},{status:201});
    }
    if(path==="/api/crm/export.csv"&&request.method==="GET"){
      if(!hasPermission(context,"crm.import")&&!hasPermission(context,"crm.report"))return error("CRM export permission is required.",403);const entity=crmUrl.searchParams.get("entity")||"leads";let headers:string[]=[],rows:unknown[][]=[];
      if(entity==="leads"){headers=["Lead number","Name","Company","Email","Phone","Source","Status","Score","Estimated value minor","Currency","Owner"];const r=await env.DB.prepare(`SELECT l.lead_number,l.name,l.company,l.email,l.phone,l.source,l.status,l.score,l.estimated_value_minor,l.currency,u.full_name FROM crm_leads l LEFT JOIN users u ON u.id=l.owner_id WHERE l.organization_id=? AND (?=1 OR l.owner_id=?) ORDER BY l.created_at`).bind(context.organizationId,canSeeAll?1:0,context.userId).all();rows=(r.results||[]).map((x:any)=>Object.values(x));}
      else if(entity==="opportunities"){headers=["Opportunity number","Name","Stage","Status","Value minor","Currency","Probability","Close date","Owner"];const r=await env.DB.prepare(`SELECT o.opportunity_number,o.name,o.stage,o.status,o.value_minor,o.currency,o.probability,o.expected_close_date,u.full_name FROM crm_opportunities o LEFT JOIN users u ON u.id=o.owner_id WHERE o.organization_id=? AND (?=1 OR o.owner_id=?) ORDER BY o.created_at`).bind(context.organizationId,canSeeAll?1:0,context.userId).all();rows=(r.results||[]).map((x:any)=>Object.values(x));}
      else if(entity==="contacts"){headers=["First name","Last name","Job title","Email","Phone","Customer ID"];const r=await env.DB.prepare(`SELECT first_name,last_name,job_title,email,phone,customer_id FROM crm_contacts WHERE organization_id=?`).bind(context.organizationId).all();rows=(r.results||[]).map((x:any)=>Object.values(x));}else return error("Export entity must be leads, opportunities or contacts.");
      const cell=(v:unknown)=>{let s=String(v??"");if(/^[\s]*[=+@-]/.test(s))s="'"+s;return `"${s.replaceAll('"','""').replace(/[\r\n]+/g," ")}"`;};return new Response("\uFEFF"+[headers,...rows].map(r=>r.map(cell).join(",")).join("\r\n"),{headers:{"content-type":"text/csv; charset=utf-8","content-disposition":`attachment; filename=zyntris-crm-${entity}.csv`,"cache-control":"private, no-store","x-content-type-options":"nosniff"}});
    }
    if(path==="/api/crm/import/leads"&&request.method==="POST"){
      if(!hasPermission(context,"crm.import")||!canManageCrm)return error("CRM lead import permission is required.",403);const body=await request.json<{leads?:{name?:string;company?:string;email?:string;phone?:string;source?:string;estimatedValueMinor?:number;currency?:string}[]}>();const leads=body.leads||[];if(!leads.length||leads.length>200)return error("Import between 1 and 200 leads per batch.");
      const valid=leads.every(l=>l.name?.trim()&&l.name.length<=160&&(!l.email||/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(l.email))&&Number.isSafeInteger(l.estimatedValueMinor||0)&&(l.estimatedValueMinor||0)>=0&&(!l.currency||/^[A-Z]{3}$/i.test(l.currency)));if(!valid)return error("Every imported lead needs a name, valid email, three-letter currency and integer minor-unit value.");
      const sourceNames=[...new Set(leads.map(l=>l.source?.trim()).filter((x):x is string=>Boolean(x)))];for(const source of sourceNames)if(!await env.DB.prepare(`SELECT 1 FROM crm_lead_sources WHERE organization_id=? AND name=? AND active=1`).bind(context.organizationId,source).first())return error(`Unknown or inactive CRM source: ${source}. Configure it before importing.`,422);
      const statements=[];for(const l of leads){const id=`crm-lead-${requestId()}`,number=`LD-${crypto.randomUUID().slice(0,8).toUpperCase()}`,minor=l.estimatedValueMinor||0,scored=await evaluateCrmLead(env,context.organizationId,{has_email:l.email,has_phone:l.phone,has_company:l.company,source:l.source,estimated_value_min:minor/100});statements.push(env.DB.prepare(`INSERT INTO crm_leads(id,organization_id,lead_number,name,company,email,phone,source,estimated_value,estimated_value_minor,currency,owner_id,status,temperature,score,created_by,updated_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'new',?,?,?,?)`).bind(id,context.organizationId,number,l.name!.trim(),l.company?.trim()||null,l.email?.trim().toLowerCase()||null,l.phone?.trim()||null,l.source?.trim()||null,minor/100,minor,(l.currency||"NGN").toUpperCase(),context.userId,scored.temperature,scored.score,context.userId,context.userId));}await env.DB.batch(statements);await audit(env,context,"imported","crm_leads",context.organizationId,{count:leads.length});return json({created:leads.length},{status:201});
    }
    if(path==="/api/crm/reports"&&request.method==="GET"){
      if(!hasPermission(context,"crm.report"))return error("CRM reporting permission is required.",403);const [stages,sources,owners,trend]=await Promise.all([env.DB.prepare(`SELECT stage,COUNT(*) count,COALESCE(SUM(value_minor),0)/100.0 value FROM crm_opportunities WHERE organization_id=? AND (?=1 OR owner_id=?) GROUP BY stage ORDER BY stage`).bind(context.organizationId,canSeeAll?1:0,context.userId).all(),env.DB.prepare(`SELECT COALESCE(source,'Unattributed') source,COUNT(*) leads,SUM(CASE WHEN status='converted' THEN 1 ELSE 0 END) converted FROM crm_leads WHERE organization_id=? AND (?=1 OR owner_id=?) GROUP BY source ORDER BY leads DESC`).bind(context.organizationId,canSeeAll?1:0,context.userId).all(),env.DB.prepare(`SELECT u.full_name as owner,COUNT(o.id) opportunities,COALESCE(SUM(CASE WHEN o.status='won' THEN o.value_minor ELSE 0 END),0)/100.0 wonValue FROM crm_opportunities o JOIN users u ON u.id=o.owner_id WHERE o.organization_id=? AND (?=1 OR o.owner_id=?) GROUP BY o.owner_id ORDER BY wonValue DESC`).bind(context.organizationId,canSeeAll?1:0,context.userId).all(),env.DB.prepare(`SELECT substr(created_at,1,7) month,COUNT(*) leads FROM crm_leads WHERE organization_id=? AND (?=1 OR owner_id=?) GROUP BY substr(created_at,1,7) ORDER BY month DESC LIMIT 12`).bind(context.organizationId,canSeeAll?1:0,context.userId).all()]);return json({stages:stages.results||[],sources:sources.results||[],owners:owners.results||[],trend:trend.results||[]});
    }
    return error("CRM endpoint not found.",404);
  }

  if (path === "/api/approval-workflows") {
    if (!hasPermission(context, "requests.manage")) return error("Request administration permission is required to configure approval routing.", 403);
    if (request.method === "GET") {
      const row = await env.DB.prepare(`SELECT approval_workflows_json as workflowsJson, financial_fallback_role as financialFallbackRole, exit_approval_role as exitApprovalRole FROM organization_settings WHERE organization_id = ?`).bind(context.organizationId).first<{ workflowsJson: string; financialFallbackRole: string; exitApprovalRole: string }>();
      let workflows: Record<string, string> = {};
      try { workflows = JSON.parse(row?.workflowsJson || "{}"); } catch { /* use empty settings */ }
      return json({ workflows: { Operational: workflows.Operational || "Manager", Access: workflows.Access || "Manager", HR: workflows.HR || "HR Admin", Leave: workflows.Leave || "HR Admin", Other: workflows.Other || "Manager" }, financialFlow: { primaryRole: "CEO", fallbackRole: row?.financialFallbackRole || "HR Admin", fallbackTrigger: "approver_unavailable" }, exitApprovalRole: row?.exitApprovalRole || "CEO" });
    }
    if (request.method === "PATCH") {
      const body = await request.json<{ workflows?: Record<string, string>; financialFallbackRole?: string; exitApprovalRole?: string }>(); const workflows = body.workflows;
      const categories = ["Operational", "Access", "HR", "Leave", "Other"];
      const allowedRoles = ["Manager", "HR Admin", "CEO"];
      const financialFallbackRole = body.financialFallbackRole || "HR Admin";
      const exitApprovalRole = body.exitApprovalRole || "CEO";
      if (!workflows || categories.some((category) => !allowedRoles.includes(workflows[category])) || !["HR Admin", "Organization Admin"].includes(financialFallbackRole) || !["CEO","HR Admin"].includes(exitApprovalRole)) return error("Choose valid routing roles, a CEO-unavailable fallback, and CEO or HR Admin as the separation sign-off.");
      await env.DB.prepare(`UPDATE organization_settings SET approval_workflows_json = ?, financial_fallback_role = ?, exit_approval_role = ?, updated_at = CURRENT_TIMESTAMP WHERE organization_id = ?`).bind(JSON.stringify(Object.fromEntries(categories.map((category) => [category, workflows[category]]))), financialFallbackRole, exitApprovalRole, context.organizationId).run();
      await audit(env, context, "updated", "approval_workflows", context.organizationId, { workflows, financialFlow: { primaryRole: "CEO", fallbackRole: financialFallbackRole, fallbackTrigger: "approver_unavailable" } });
      return json({ ok: true, workflows, financialFlow: { primaryRole: "CEO", fallbackRole: financialFallbackRole, fallbackTrigger: "approver_unavailable" }, exitApprovalRole });
    }
  }

  if (path === "/api/workflow-admin") {
    if (!hasPermission(context, "requests.manage")) return error("HR or organization administration permission is required to configure workflow automation.", 403);
    if (request.method === "GET") {
      const [sla, templates] = await Promise.all([
        env.DB.prepare(`SELECT request_type as requestType, due_hours as dueHours, reminder_hours as reminderHours, escalation_role as escalationRole FROM workflow_sla_settings WHERE organization_id = ? ORDER BY request_type`).bind(context.organizationId).all(),
        env.DB.prepare(`SELECT id, name, category, steps_json as stepsJson, updated_at as updatedAt FROM workflow_templates WHERE organization_id = ? ORDER BY category,name`).bind(context.organizationId).all(),
      ]);
      return json({ sla: sla.results || [], templates: templates.results || [] });
    }
    if (request.method === "PUT") {
      const body = await request.json<{ sla?: { requestType: string; dueHours: number; reminderHours: number; escalationRole: string }[] }>();
      const allowedTypes = ["Operational","Access","HR","Leave","Expense","Purchase","Budget","Other"];
      if (!Array.isArray(body.sla) || body.sla.length > allowedTypes.length || body.sla.some((s) => !allowedTypes.includes(s.requestType) || !Number.isInteger(s.dueHours) || s.dueHours < 1 || s.dueHours > 8760 || !Number.isInteger(s.reminderHours) || s.reminderHours < 1 || s.reminderHours > 8760 || !["HR Admin","CEO","Organization Admin"].includes(s.escalationRole))) return error("SLA rules must use supported request types, 1–8,760 hours, and an allowed escalation role.");
      await env.DB.batch(body.sla.map((s) => env.DB.prepare(`INSERT INTO workflow_sla_settings (organization_id, request_type, due_hours, reminder_hours, escalation_role, updated_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(organization_id,request_type) DO UPDATE SET due_hours = excluded.due_hours, reminder_hours = excluded.reminder_hours, escalation_role = excluded.escalation_role, updated_at = CURRENT_TIMESTAMP`).bind(context.organizationId, s.requestType, s.dueHours, s.reminderHours, s.escalationRole)));
      await audit(env, context, "updated", "workflow_sla_settings", context.organizationId, { rules: body.sla.length });
      return json({ ok: true });
    }
    if (request.method === "POST") {
      const body = await request.json<{ name?: string; category?: string; steps?: { title: string; details?: string }[] }>();
      const steps = body.steps || [];
      if (!body.name?.trim() || body.name.length > 100 || !["onboarding","offboarding","task"].includes(body.category || "") || steps.length < 1 || steps.length > 50 || steps.some((step) => !step.title?.trim() || step.title.length > 160 || (step.details || "").length > 1000)) return error("Add a template name, supported category, and 1–50 concise steps.");
      const id = `workflow-template-${crypto.randomUUID()}`;
      await env.DB.prepare(`INSERT INTO workflow_templates (id, organization_id, name, category, steps_json, created_by) VALUES (?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, body.name.trim(), body.category, JSON.stringify(steps), context.userId).run();
      await audit(env, context, "created", "workflow_templates", id, { category: body.category, name: body.name.trim() });
      return json({ id }, { status: 201 });
    }
  }
  const workflowTemplateMatch = path.match(/^\/api\/workflow-admin\/templates\/([^/]+)$/);
  const workflowTemplateApplyMatch = path.match(/^\/api\/workflow-admin\/templates\/([^/]+)\/apply$/);
  if (workflowTemplateApplyMatch && request.method === "POST") {
    if (!hasPermission(context, "requests.manage")) return error("HR or organization administration permission is required to apply workflow templates.", 403);
    const body = await request.json<{ assigneeId?: string | null; exitCaseId?: string | null; dueDate?: string | null }>();
    const template = await env.DB.prepare(`SELECT id, name, category, steps_json as stepsJson FROM workflow_templates WHERE id = ? AND organization_id = ?`).bind(workflowTemplateApplyMatch[1], context.organizationId).first<{ id: string; name: string; category: string; stepsJson: string }>();
    if (!template) return error("Workflow template not found.", 404);
    let steps: { title: string; details?: string }[];
    try { steps = JSON.parse(template.stepsJson); } catch { return error("This workflow template is invalid. Edit or recreate it before applying.", 409); }
    if (!Array.isArray(steps) || steps.length === 0 || steps.length > 50) return error("This workflow template has no valid steps.", 409);
    if (body.dueDate && !isIsoCalendarDate(body.dueDate)) return error("Choose a valid task due date.");
    if (body.assigneeId) {
      const assignee = await env.DB.prepare(`SELECT id FROM employees WHERE id = ? AND organization_id = ? AND deleted_at IS NULL AND status = 'active'`).bind(body.assigneeId, context.organizationId).first();
      if (!assignee) return error("Choose an active employee in this organization as the assignee.");
    }
    if (template.category === "offboarding") {
      if (!body.exitCaseId) return error("Choose an exit case to apply this offboarding checklist.");
      const exitCase = await env.DB.prepare(`SELECT id, approval_status as approvalStatus, status FROM employee_exit_cases WHERE id = ? AND organization_id = ?`).bind(body.exitCaseId, context.organizationId).first<{ id: string; approvalStatus: string; status: string }>();
      if (!exitCase || exitCase.status !== "active" || exitCase.approvalStatus === "rejected") return error("Choose an active, non-declined exit case.");
      const existing = await env.DB.prepare(`SELECT COUNT(*) as count FROM employee_exit_tasks WHERE organization_id = ? AND exit_case_id = ? AND title IN (${steps.map(() => "?").join(",")})`).bind(context.organizationId, body.exitCaseId, ...steps.map((step) => step.title.trim())).first<{ count: number }>();
      if ((existing?.count || 0) > 0) return error("One or more template steps already exist on this exit case; no duplicate steps were added.", 409);
      await env.DB.batch(steps.map((step, index) => env.DB.prepare(`INSERT INTO employee_exit_tasks (id, organization_id, exit_case_id, category, title, details, sort_order) VALUES (?, ?, ?, 'hr', ?, ?, (SELECT COALESCE(MAX(sort_order),0) + ? FROM employee_exit_tasks WHERE organization_id = ? AND exit_case_id = ?))`).bind(`exit-task-${crypto.randomUUID()}`, context.organizationId, body.exitCaseId, step.title.trim(), step.details?.trim() || `Added from workflow template: ${template.name}.`, index + 1, context.organizationId, body.exitCaseId)));
      await audit(env, context, "applied", "workflow_templates", template.id, { exitCaseId: body.exitCaseId, stepCount: steps.length });
      return json({ ok: true, created: steps.length, target: "exit_case" }, { status: 201 });
    }
    await env.DB.batch(steps.map((step) => env.DB.prepare(`INSERT INTO tasks (id, organization_id, title, description, assignee_id, creator_id, due_date) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .bind(`task-${crypto.randomUUID()}`, context.organizationId, step.title.trim(), step.details?.trim() || `Created from workflow template: ${template.name}.`, body.assigneeId || null, context.userId, body.dueDate || null)));
    await audit(env, context, "applied", "workflow_templates", template.id, { assigneeId: body.assigneeId || null, stepCount: steps.length });
    return json({ ok: true, created: steps.length, target: "tasks" }, { status: 201 });
  }
  if (workflowTemplateMatch && request.method === "DELETE") {
    if (!hasPermission(context, "requests.manage")) return error("HR or organization administration permission is required.", 403);
    const result = await env.DB.prepare(`DELETE FROM workflow_templates WHERE id = ? AND organization_id = ?`).bind(workflowTemplateMatch[1], context.organizationId).run();
    if (!result.meta.changes) return error("Workflow template not found.", 404);
    await audit(env, context, "deleted", "workflow_templates", workflowTemplateMatch[1]);
    return json({ ok: true });
  }

  if (path === "/api/purchases" && request.method === "GET") {
    const data = await env.DB.prepare(`SELECT p.id, p.title, p.description, p.amount, p.currency, p.status, p.items_json as itemsJson, p.quotes_json as quotesJson, p.receipt_reference as receiptReference, p.invoice_reference as invoiceReference, p.received_amount as receivedAmount, p.created_at as createdAt, u.full_name as requester, v.name as vendor, b.name as budget, po.po_number as poNumber FROM purchase_requests p JOIN users u ON u.id = p.requester_id LEFT JOIN vendors v ON v.id = p.vendor_id AND v.organization_id = p.organization_id LEFT JOIN budgets b ON b.id = p.budget_id AND b.organization_id = p.organization_id LEFT JOIN purchase_orders po ON po.purchase_request_id = p.id AND po.organization_id = p.organization_id WHERE p.organization_id = ? ORDER BY p.created_at DESC LIMIT 100`).bind(context.organizationId).all();
    return json({ data: data.results || [] });
  }
  if (path === "/api/purchases" && request.method === "POST") {
    if (!hasPermission(context, "operations.manage")) return error("Operations manager permission is required to create purchase requests.", 403);
    const body = await request.json<{ title?: string; description?: string; amount?: number; vendorId?: string; budgetId?: string; items?: { description: string; quantity: number; unitPrice: number }[]; quotes?: { vendor: string; amount: number; reference?: string }[] }>();
    const amount = Number(body.amount); const items = body.items || []; const quotes = body.quotes || [];
    if (!body.title?.trim() || body.title.length > 120 || !body.description?.trim() || body.description.length > 2000 || !Number.isFinite(amount) || amount <= 0 || items.length > 100 || quotes.length > 10 || items.some((i) => !i.description?.trim() || i.description.length > 200 || !Number.isFinite(i.quantity) || i.quantity <= 0 || !Number.isFinite(i.unitPrice) || i.unitPrice < 0) || quotes.some((q) => !q.vendor?.trim() || !Number.isFinite(q.amount) || q.amount <= 0)) return error("Provide a title, description, positive total, valid line items and up to ten comparable quotes.");
    if (body.vendorId && !await env.DB.prepare(`SELECT id FROM vendors WHERE id = ? AND organization_id = ?`).bind(body.vendorId, context.organizationId).first()) return error("Vendor not found in this organization.", 404);
    if (body.budgetId && !await env.DB.prepare(`SELECT id FROM budgets WHERE id = ? AND organization_id = ?`).bind(body.budgetId, context.organizationId).first()) return error("Budget not found in this organization.", 404);
    const id = `purchase-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO purchase_requests (id, organization_id, title, description, requester_id, vendor_id, budget_id, amount, currency, items_json, quotes_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, (SELECT currency FROM organizations WHERE id = ?), ?, ?)`)
      .bind(id, context.organizationId, body.title.trim(), body.description.trim(), context.userId, body.vendorId || null, body.budgetId || null, amount, context.organizationId, JSON.stringify(items), JSON.stringify(quotes)).run();
    await audit(env, context, "created", "purchase_requests", id, { amount, vendorId: body.vendorId || null, budgetId: body.budgetId || null });
    return json({ id, status: "draft" }, { status: 201 });
  }
  const purchaseMatch = path.match(/^\/api\/purchases\/([^/]+)(?:\/(submit|receive|match))?$/);
  if (purchaseMatch && request.method === "POST" && purchaseMatch[2] === "submit") {
    const p = await env.DB.prepare(`SELECT id, title, requester_id as requesterId, amount, budget_id as budgetId, quotes_json as quotesJson, status FROM purchase_requests WHERE id = ? AND organization_id = ?`).bind(purchaseMatch[1], context.organizationId).first<{ id: string; title: string; requesterId: string; amount: number; budgetId: string | null; quotesJson: string; status: string }>();
    if (!p) return error("Purchase request not found.", 404);
    if (p.requesterId !== context.userId && !hasPermission(context, "operations.manage")) return error("Only the requester or an operations administrator can submit this purchase.", 403);
    if (p.status !== "draft") return error("Only a draft purchase can be submitted.", 409);
    let quoteRows: { vendor: string; amount: number; reference?: string }[] = [];
    try { quoteRows = JSON.parse(p.quotesJson || "[]") as typeof quoteRows; } catch { return error("Quote comparison data is invalid. Edit the purchase and add valid quotes.", 409); }
    if (!Array.isArray(quoteRows) || quoteRows.length < 2) return error("Add at least two comparable supplier quotes before submitting for CEO approval.", 409);
    if (!quoteRows.some((quote) => Number(quote.amount) === Number(p.amount))) return error("The requested total must match one of the entered supplier quotes so the CEO can compare the selected offer.", 409);
    const quoteSummary = quoteRows.map((quote) => `${quote.vendor}: ${Number(quote.amount).toLocaleString()}${quote.reference ? ` (${quote.reference})` : ""}`).join("; ");
    if (p.budgetId) {
      const budget = await env.DB.prepare(`SELECT allocated, spent, COALESCE((SELECT SUM(amount) FROM budget_reservations r WHERE r.budget_id = budgets.id AND r.organization_id = budgets.organization_id AND r.status = 'reserved'),0) as reserved FROM budgets WHERE id = ? AND organization_id = ?`).bind(p.budgetId, context.organizationId).first<{ allocated: number; spent: number; reserved: number }>();
      if (!budget || Number(budget.allocated) - Number(budget.spent) - Number(budget.reserved) < p.amount) return error("The selected budget does not have enough unreserved funds for this purchase.", 409);
    }
    const purchaseSla = await env.DB.prepare(`SELECT due_hours as dueHours FROM workflow_sla_settings WHERE organization_id = ? AND request_type = 'Purchase'`).bind(context.organizationId).first<{ dueHours: number }>();
    const approvalDueAt = new Date(Date.now() + (purchaseSla?.dueHours || 48) * 3600000).toISOString();
    const approvalId = `request-${crypto.randomUUID()}`;
    const statements = [
      env.DB.prepare(`INSERT INTO approval_requests (id, organization_id, request_type, source_record_id, title, requester_id, amount, currency, required_role, status, current_step, metadata_json, due_at) VALUES (?, ?, 'Purchase', ?, ?, ?, ?, (SELECT currency FROM organizations WHERE id = ?), 'CEO', 'pending', 1, ?, ?)`)
        .bind(approvalId, context.organizationId, p.id, p.title, p.requesterId, p.amount, context.organizationId, JSON.stringify({ details: `Supplier quotes: ${quoteSummary}`, approvalPolicy: ["CEO"], purchaseRequestId: p.id, quotes: quoteRows }), approvalDueAt),
      env.DB.prepare(`UPDATE purchase_requests SET status = 'pending_approval', approval_request_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = 'draft'`).bind(approvalId, p.id, context.organizationId),
      ...(p.budgetId ? [env.DB.prepare(`INSERT INTO budget_reservations (id, organization_id, budget_id, purchase_request_id, amount) VALUES (?, ?, ?, ?, ?)`).bind(`reservation-${crypto.randomUUID()}`, context.organizationId, p.budgetId, p.id, p.amount)] : []),
    ];
    await env.DB.batch(statements);
    await notifyApprovers(env, context, "CEO", p.title, `A purchase request for ${p.amount.toLocaleString()} is pending your approval.`);
    await audit(env, context, "submitted_for_approval", "purchase_requests", p.id, { approvalId, amount: p.amount });
    return json({ ok: true, approvalId, requiredRole: "CEO" });
  }
  if (purchaseMatch && request.method === "POST" && purchaseMatch[2] === "receive") {
    if (!hasPermission(context, "operations.manage") && !hasPermission(context, "expenses.manage")) return error("Finance or operations administrator access is required to record goods receipt and invoice references.", 403);
    const body = await request.json<{ receivedAmount?: number; receiptReference?: string; invoiceReference?: string }>();
    const p = await env.DB.prepare(`SELECT id, amount, status FROM purchase_requests WHERE id = ? AND organization_id = ?`).bind(purchaseMatch[1], context.organizationId).first<{ id: string; amount: number; status: string }>();
    if (!p || !["ordered","partially_received","received"].includes(p.status)) return error("Only an approved purchase order can record receipt and invoice details.", 409);
    const received = Number(body.receivedAmount);
    if (!Number.isFinite(received) || received < 0 || received > p.amount || !body.receiptReference?.trim() || !body.invoiceReference?.trim() || body.receiptReference.length > 120 || body.invoiceReference.length > 120) return error("Record valid received value plus both a receipt reference and supplier invoice reference.");
    const next = received >= p.amount ? "received" : received > 0 ? "partially_received" : p.status;
    await env.DB.batch([
      env.DB.prepare(`UPDATE purchase_requests SET received_amount = ?, receipt_reference = ?, invoice_reference = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(received, body.receiptReference.trim(), body.invoiceReference.trim(), next, p.id, context.organizationId),
      env.DB.prepare(`UPDATE purchase_orders SET status = ? WHERE purchase_request_id = ? AND organization_id = ?`).bind(next, p.id, context.organizationId),
    ]);
    await audit(env, context, "receipt_recorded", "purchase_requests", p.id, { received, receiptReference: body.receiptReference, invoiceReference: body.invoiceReference });
    return json({ ok: true, status: next });
  }
  if (purchaseMatch && request.method === "POST" && purchaseMatch[2] === "match") {
    if (!hasPermission(context, "expenses.manage") && !hasPermission(context, "operations.manage")) return error("Finance administrator access is required to complete a three-way match.", 403);
    const p = await env.DB.prepare(`SELECT id, amount, received_amount as receivedAmount, receipt_reference as receiptReference, invoice_reference as invoiceReference, status FROM purchase_requests WHERE id = ? AND organization_id = ?`).bind(purchaseMatch[1], context.organizationId).first<{ id: string; amount: number; receivedAmount: number; receiptReference: string | null; invoiceReference: string | null; status: string }>();
    if (!p || p.status !== "received" || !p.receiptReference || !p.invoiceReference || Number(p.receivedAmount) !== Number(p.amount)) return error("Three-way match requires an approved PO, full receipt, and recorded supplier invoice and goods-received references.", 409);
    const req = await env.DB.prepare(`SELECT budget_id as budgetId FROM purchase_requests WHERE id = ? AND organization_id = ?`).bind(p.id, context.organizationId).first<{ budgetId: string | null }>();
    await env.DB.batch([
      env.DB.prepare(`UPDATE purchase_requests SET status = 'matched', matched_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(p.id, context.organizationId),
      env.DB.prepare(`UPDATE purchase_orders SET status = 'closed' WHERE purchase_request_id = ? AND organization_id = ?`).bind(p.id, context.organizationId),
      env.DB.prepare(`UPDATE budget_reservations SET status = 'consumed', updated_at = CURRENT_TIMESTAMP WHERE purchase_request_id = ? AND organization_id = ?`).bind(p.id, context.organizationId),
      ...(req?.budgetId ? [env.DB.prepare(`UPDATE budgets SET spent = spent + ? WHERE id = ? AND organization_id = ?`).bind(p.amount, req.budgetId, context.organizationId)] : []),
    ]);
    await audit(env, context, "three_way_matched", "purchase_requests", p.id, { amount: p.amount });
    return json({ ok: true, status: "matched" });
  }

  if (request.method === "GET" && path === "/api/reports/summary") {
    const sixMonthsAgo = new Date(); sixMonthsAgo.setUTCDate(1); sixMonthsAgo.setUTCMonth(sixMonthsAgo.getUTCMonth() - 5);
    const fromDate = sixMonthsAgo.toISOString().slice(0, 10);
    const [people, expenses, leave, tasks, tickets, approvals, appraisals, departments, monthlySpend] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active FROM employees WHERE organization_id = ? AND deleted_at IS NULL`).bind(context.organizationId).first(),
      env.DB.prepare(`SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as total, COALESCE(SUM(CASE WHEN status = 'submitted' THEN amount ELSE 0 END), 0) as pending FROM expenses WHERE organization_id = ? AND expense_date >= ?`).bind(context.organizationId, fromDate).first(),
      env.DB.prepare(`SELECT SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending, SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved, SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected FROM leave_requests WHERE organization_id = ?`).bind(context.organizationId).first(),
      env.DB.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed, SUM(CASE WHEN status != 'completed' AND due_date < date('now') THEN 1 ELSE 0 END) as overdue FROM tasks WHERE organization_id = ?`).bind(context.organizationId).first(),
      env.DB.prepare(`SELECT SUM(CASE WHEN status IN ('open','assigned','in_progress') THEN 1 ELSE 0 END) as open, SUM(CASE WHEN status IN ('resolved','closed') THEN 1 ELSE 0 END) as resolved FROM support_tickets WHERE organization_id = ?`).bind(context.organizationId).first(),
      env.DB.prepare(`SELECT SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending, SUM(CASE WHEN status IN ('approved','paid') THEN 1 ELSE 0 END) as approved, SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected FROM approval_requests WHERE organization_id = ?`).bind(context.organizationId).first(),
      env.DB.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN status = 'complete' THEN 1 ELSE 0 END) as completed, SUM(CASE WHEN status != 'complete' THEN 1 ELSE 0 END) as inProgress FROM appraisals WHERE organization_id = ?`).bind(context.organizationId).first(),
      env.DB.prepare(`SELECT d.name, COUNT(e.id) as count FROM departments d LEFT JOIN employees e ON e.department_id = d.id AND e.organization_id = d.organization_id AND e.deleted_at IS NULL WHERE d.organization_id = ? GROUP BY d.id ORDER BY count DESC`).bind(context.organizationId).all(),
      env.DB.prepare(`SELECT strftime('%Y-%m', expense_date) as month, COALESCE(SUM(amount), 0) as amount FROM expenses WHERE organization_id = ? AND expense_date >= ? GROUP BY strftime('%Y-%m', expense_date) ORDER BY month`).bind(context.organizationId, fromDate).all(),
    ]);
    return json({ people: people || {}, expenses: expenses || {}, leave: leave || {}, tasks: tasks || {}, tickets: tickets || {}, approvals: approvals || {}, appraisals: appraisals || {}, departments: departments.results || [], monthlySpend: monthlySpend.results || [] });
  }

  if (path === "/api/goals" && request.method === "GET") {
    if (!hasPermission(context, "goals.view")) return error("You do not have permission to view goals.", 403);
    const employee = await env.DB.prepare(`SELECT department_id as departmentId, team_id as teamId FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ departmentId: string | null; teamId: string | null }>();
    const canManage = hasPermission(context, "goals.manage");
    const goals = await env.DB.prepare(`SELECT g.id, g.parent_goal_id as parentGoalId, g.level, g.department_id as departmentId, d.name as department, g.team_id as teamId, t.name as team, g.owner_user_id as ownerUserId, u.full_name as owner, g.title, g.description, g.start_date as startDate, g.due_date as dueDate, g.weight, g.progress, g.status, g.created_at as createdAt FROM goals g LEFT JOIN departments d ON d.id = g.department_id AND d.organization_id = g.organization_id LEFT JOIN teams t ON t.id = g.team_id AND t.organization_id = g.organization_id LEFT JOIN users u ON u.id = g.owner_user_id WHERE g.organization_id = ? AND (? = 1 OR g.level = 'company' OR g.owner_user_id = ? OR (g.level = 'department' AND g.department_id = ?) OR (g.level = 'team' AND g.team_id = ?)) ORDER BY CASE g.level WHEN 'company' THEN 0 WHEN 'department' THEN 1 WHEN 'team' THEN 2 ELSE 3 END, g.due_date, g.created_at DESC LIMIT 300`).bind(context.organizationId, canManage ? 1 : 0, context.userId, employee?.departmentId || "", employee?.teamId || "").all();
    const results = await env.DB.prepare(`SELECT kr.id, kr.goal_id as goalId, kr.title, kr.unit, kr.target_value as targetValue, kr.current_value as currentValue, CASE WHEN ? = 1 OR g.owner_user_id = ? THEN 1 ELSE 0 END as canUpdate FROM goal_key_results kr JOIN goals g ON g.id = kr.goal_id AND g.organization_id = kr.organization_id WHERE kr.organization_id = ? ORDER BY kr.created_at`).bind(canManage ? 1 : 0, context.userId, context.organizationId).all();
    const visibleIds = new Set((goals.results || []).map((goal) => (goal as { id: string }).id));
    return json({ data: goals.results || [], keyResults: (results.results || []).filter((item) => visibleIds.has((item as { goalId: string }).goalId)), canManage, departments: (await env.DB.prepare(`SELECT id, name FROM departments WHERE organization_id = ? ORDER BY name`).bind(context.organizationId).all()).results || [], teams: (await env.DB.prepare(`SELECT id, name, department_id as departmentId FROM teams WHERE organization_id = ? ORDER BY name`).bind(context.organizationId).all()).results || [], employees: canManage ? (await env.DB.prepare(`SELECT e.user_id as userId, e.first_name || ' ' || e.last_name as name FROM employees e WHERE e.organization_id = ? AND e.user_id IS NOT NULL AND e.deleted_at IS NULL ORDER BY name`).bind(context.organizationId).all()).results || [] : [] });
  }

  if (path === "/api/goals" && request.method === "POST") {
    if (!hasPermission(context, "goals.manage")) return error("Goal management permission is required.", 403);
    const body = await request.json<{ parentGoalId?: string; level?: string; departmentId?: string; teamId?: string; ownerUserId?: string; title?: string; description?: string; startDate?: string; dueDate?: string; weight?: number; keyResults?: { title: string; unit?: string; targetValue: number }[] }>();
    const level = body.level || "company"; const weight = Number(body.weight || 100);
    if (!body.title?.trim() || body.title.trim().length > 160 || !["company", "department", "team", "individual"].includes(level) || !Number.isInteger(weight) || weight < 1 || weight > 100 || body.startDate && !isoDate(body.startDate) || body.dueDate && !isoDate(body.dueDate) || body.startDate && body.dueDate && body.dueDate < body.startDate || (body.keyResults || []).length > 20 || (body.keyResults || []).some((result) => !result.title?.trim() || result.title.length > 180 || !Number.isFinite(Number(result.targetValue)) || Number(result.targetValue) <= 0)) return error("Enter a valid goal, scope, dates, weight and key results.");
    if (level === "department" && (!body.departmentId || !await env.DB.prepare(`SELECT id FROM departments WHERE id = ? AND organization_id = ?`).bind(body.departmentId, context.organizationId).first())) return error("Choose a department in this organization.");
    if (level === "team" && (!body.teamId || !await env.DB.prepare(`SELECT id FROM teams WHERE id = ? AND organization_id = ?`).bind(body.teamId, context.organizationId).first())) return error("Choose a team in this organization.");
    if (level === "individual" && (!body.ownerUserId || !await env.DB.prepare(`SELECT user_id FROM employees WHERE user_id = ? AND organization_id = ? AND deleted_at IS NULL`).bind(body.ownerUserId, context.organizationId).first())) return error("Choose an employee in this organization.");
    if (body.parentGoalId && !await env.DB.prepare(`SELECT id FROM goals WHERE id = ? AND organization_id = ?`).bind(body.parentGoalId, context.organizationId).first()) return error("Choose a parent goal in this organization.");
    const id = `goal-${crypto.randomUUID()}`;
    const statements = [env.DB.prepare(`INSERT INTO goals (id, organization_id, parent_goal_id, level, department_id, team_id, owner_user_id, title, description, start_date, due_date, weight, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, body.parentGoalId || null, level, level === "department" ? body.departmentId : null, level === "team" ? body.teamId : null, level === "individual" ? body.ownerUserId : null, body.title.trim(), body.description?.trim() || null, body.startDate || null, body.dueDate || null, weight, context.userId)];
    for (const result of body.keyResults || []) statements.push(env.DB.prepare(`INSERT INTO goal_key_results (id, organization_id, goal_id, title, unit, target_value) VALUES (?, ?, ?, ?, ?, ?)`).bind(`kr-${crypto.randomUUID()}`, context.organizationId, id, result.title.trim(), result.unit?.trim().slice(0, 30) || "%", Number(result.targetValue)));
    await env.DB.batch(statements); await audit(env, context, "created", "goals", id, { title: body.title, level, keyResultCount: body.keyResults?.length || 0 });
    return json({ id }, { status: 201 });
  }

  const goalMatch = path.match(/^\/api\/goals\/([^/]+)$/);
  if (request.method === "PATCH" && goalMatch) {
    const body = await request.json<{ progress?: number; status?: string; title?: string; description?: string; dueDate?: string | null }>();
    const current = await env.DB.prepare(`SELECT id, owner_user_id as ownerUserId FROM goals WHERE id = ? AND organization_id = ?`).bind(goalMatch[1], context.organizationId).first<{ id: string; ownerUserId: string | null }>();
    if (!current) return error("Goal not found.", 404);
    const canManage = hasPermission(context, "goals.manage");
    if (!canManage && current.ownerUserId !== context.userId) return error("You can update progress only on a goal assigned to you.", 403);
    if (body.progress !== undefined && (!Number.isInteger(Number(body.progress)) || Number(body.progress) < 0 || Number(body.progress) > 100) || body.status !== undefined && !["not_started", "in_progress", "at_risk", "completed", "cancelled"].includes(body.status) || body.dueDate && !isoDate(body.dueDate) || !canManage && (body.title !== undefined || body.description !== undefined || body.dueDate !== undefined)) return error("Enter valid goal progress or status details.");
    await env.DB.prepare(`UPDATE goals SET title = COALESCE(?, title), description = COALESCE(?, description), due_date = CASE WHEN ? = 1 THEN ? ELSE due_date END, progress = COALESCE(?, progress), status = COALESCE(?, status), updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(body.title?.trim() || null, body.description === undefined ? null : body.description.trim(), body.dueDate === null ? 1 : body.dueDate ? 1 : 0, body.dueDate || null, body.progress ?? null, body.status || null, current.id, context.organizationId).run();
    await audit(env, context, "updated", "goals", current.id, body); return json({ ok: true });
  }

  const keyResultMatch = path.match(/^\/api\/goals\/key-results\/([^/]+)$/);
  if (request.method === "PATCH" && keyResultMatch) {
    const body = await request.json<{ currentValue?: number }>(); const value = Number(body.currentValue);
    if (!Number.isFinite(value) || value < 0 || value > 1_000_000_000_000) return error("Enter a valid key result value.");
    const result = await env.DB.prepare(`SELECT kr.id, kr.goal_id as goalId, g.owner_user_id as ownerUserId FROM goal_key_results kr JOIN goals g ON g.id = kr.goal_id AND g.organization_id = kr.organization_id WHERE kr.id = ? AND kr.organization_id = ?`).bind(keyResultMatch[1], context.organizationId).first<{ id: string; goalId: string; ownerUserId: string | null }>();
    if (!result) return error("Key result not found.", 404);
    if (!hasPermission(context, "goals.manage") && result.ownerUserId !== context.userId) return error("You can update only key results on goals assigned to you.", 403);
    await env.DB.prepare(`UPDATE goal_key_results SET current_value = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(value, result.id, context.organizationId).run();
    const aggregate = await env.DB.prepare(`SELECT CAST(AVG(CASE WHEN target_value > 0 THEN MIN(100, current_value * 100.0 / target_value) ELSE 0 END) AS INTEGER) as progress FROM goal_key_results WHERE organization_id = ? AND goal_id = ?`).bind(context.organizationId, result.goalId).first<{ progress: number }>();
    await env.DB.prepare(`UPDATE goals SET progress = ?, status = CASE WHEN ? >= 100 THEN 'completed' WHEN status = 'not_started' AND ? > 0 THEN 'in_progress' ELSE status END, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(aggregate?.progress || 0, aggregate?.progress || 0, aggregate?.progress || 0, result.goalId, context.organizationId).run();
    await audit(env, context, "key_result_updated", "goals", result.goalId, { keyResultId: result.id, currentValue: value, progress: aggregate?.progress || 0 }); return json({ ok: true, progress: aggregate?.progress || 0 });
  }

  if (path === "/api/announcements" && request.method === "GET") {
    if (!hasPermission(context, "announcements.view")) return error("You do not have permission to view announcements.", 403);
    const employee = await env.DB.prepare(`SELECT id, department_id as departmentId, team_id as teamId FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string; departmentId: string | null; teamId: string | null }>();
    const result = await env.DB.prepare(`SELECT a.id, a.title, a.body, a.target_type as targetType, a.status, a.created_at as createdAt, u.full_name as author, r.read_at as readAt FROM announcements a LEFT JOIN users u ON u.id = a.created_by LEFT JOIN announcement_reads r ON r.announcement_id = a.id AND r.user_id = ? WHERE a.organization_id = ? AND a.status = 'published' AND (a.target_type = 'all' OR (a.target_type = 'department' AND a.target_id = ?) OR (a.target_type = 'team' AND a.target_id = ?) OR (a.target_type = 'employee' AND a.target_id = ?)) ORDER BY a.created_at DESC LIMIT 100`).bind(context.userId, context.organizationId, employee?.departmentId || "", employee?.teamId || "", employee?.id || "").all();
    return json({ data: result.results || [], canManage: hasPermission(context, "announcements.manage"), departments: hasPermission(context, "announcements.manage") ? (await env.DB.prepare(`SELECT id, name FROM departments WHERE organization_id = ? ORDER BY name`).bind(context.organizationId).all()).results || [] : [], teams: hasPermission(context, "announcements.manage") ? (await env.DB.prepare(`SELECT id, name FROM teams WHERE organization_id = ? ORDER BY name`).bind(context.organizationId).all()).results || [] : [], employees: hasPermission(context, "announcements.manage") ? (await env.DB.prepare(`SELECT id, first_name || ' ' || last_name as name FROM employees WHERE organization_id = ? AND deleted_at IS NULL ORDER BY name`).bind(context.organizationId).all()).results || [] : [] });
  }

  if (path === "/api/announcements" && request.method === "POST") {
    if (!hasPermission(context, "announcements.manage")) return error("Announcement management permission is required.", 403);
    const body = await request.json<{ title?: string; body?: string; targetType?: string; targetId?: string }>();
    const targetType = body.targetType || "all";
    if (!body.title?.trim() || body.title.trim().length > 160 || !body.body?.trim() || body.body.trim().length > 5000 || !["all", "department", "team", "employee"].includes(targetType)) return error("Enter a title and message and choose a valid audience.");
    const targetTable = targetType === "department" ? "departments" : targetType === "team" ? "teams" : targetType === "employee" ? "employees" : "";
    if (targetTable && (!body.targetId || !await env.DB.prepare(`SELECT id FROM ${targetTable} WHERE id = ? AND organization_id = ?`).bind(body.targetId, context.organizationId).first())) return error("Choose an audience in this organization.", 404);
    const id = `announcement-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO announcements (id, organization_id, title, body, target_type, target_id, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, body.title.trim(), body.body.trim(), targetType, body.targetId || null, context.userId).run();
    const audienceSql = targetType === "all" ? `SELECT m.user_id FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.organization_id = ? AND m.status = 'active' AND u.status = 'active'` : targetType === "department" ? `SELECT e.user_id FROM employees e JOIN memberships m ON m.user_id = e.user_id AND m.organization_id = e.organization_id AND m.status = 'active' WHERE e.organization_id = ? AND e.department_id = ? AND e.user_id IS NOT NULL AND e.deleted_at IS NULL` : targetType === "team" ? `SELECT e.user_id FROM employees e JOIN memberships m ON m.user_id = e.user_id AND m.organization_id = e.organization_id AND m.status = 'active' WHERE e.organization_id = ? AND e.team_id = ? AND e.user_id IS NOT NULL AND e.deleted_at IS NULL` : `SELECT e.user_id FROM employees e JOIN memberships m ON m.user_id = e.user_id AND m.organization_id = e.organization_id AND m.status = 'active' WHERE e.organization_id = ? AND e.id = ? AND e.user_id IS NOT NULL AND e.deleted_at IS NULL`;
    const notice = await env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) SELECT lower(hex(randomblob(16))), ?, audience.user_id, 'announcement', ?, ? FROM (${audienceSql}) audience WHERE audience.user_id IS NOT NULL`).bind(context.organizationId, body.title.trim(), body.body.trim(), context.organizationId, ...(targetType === "all" ? [] : [body.targetId])).run();
    await audit(env, context, "published", "announcements", id, { title: body.title.trim(), targetType, notificationCount: notice.meta.changes });
    return json({ id, notificationCount: notice.meta.changes }, { status: 201 });
  }

  const announcementReadMatch = path.match(/^\/api\/announcements\/([^/]+)\/read$/);
  if (request.method === "POST" && announcementReadMatch) {
    const employee = await env.DB.prepare(`SELECT id, department_id as departmentId, team_id as teamId FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string; departmentId: string | null; teamId: string | null }>();
    const visible = await env.DB.prepare(`SELECT id FROM announcements WHERE id = ? AND organization_id = ? AND status = 'published' AND (target_type = 'all' OR (target_type = 'department' AND target_id = ?) OR (target_type = 'team' AND target_id = ?) OR (target_type = 'employee' AND target_id = ?))`).bind(announcementReadMatch[1], context.organizationId, employee?.departmentId || "", employee?.teamId || "", employee?.id || "").first();
    if (!visible) return error("Announcement not found.", 404);
    await env.DB.prepare(`INSERT INTO announcement_reads (announcement_id, user_id) VALUES (?, ?) ON CONFLICT(announcement_id, user_id) DO UPDATE SET read_at = CURRENT_TIMESTAMP`).bind(announcementReadMatch[1], context.userId).run();
    return json({ ok: true });
  }

  if (request.method === "GET" && path === "/api/operations/members") {
    const members = await env.DB.prepare(`SELECT u.id, u.full_name as fullName, u.email FROM users u JOIN memberships m ON m.user_id = u.id AND m.organization_id = ? AND m.status = 'active' WHERE u.status = 'active' ORDER BY u.full_name`).bind(context.organizationId).all();
    return json({ data: members.results || [] });
  }

  if (request.method === "GET" && path === "/api/hr/options") {
    if (!hasPermission(context, "employees.manage")) return error("HR administrator permission is required.", 403);
    const [departments, teams] = await Promise.all([
      env.DB.prepare(`SELECT id, name FROM departments WHERE organization_id = ? ORDER BY name`).bind(context.organizationId).all(),
      env.DB.prepare(`SELECT t.id, t.name, t.department_id as departmentId, d.name as department FROM teams t LEFT JOIN departments d ON d.id = t.department_id WHERE t.organization_id = ? ORDER BY t.name`).bind(context.organizationId).all(),
    ]);
    const roleQuery = hasPermission(context, "settings.manage")
      ? env.DB.prepare(`SELECT id, name, description FROM roles WHERE organization_id = ? ORDER BY name`).bind(context.organizationId)
      : env.DB.prepare(`SELECT id, name, description FROM roles WHERE organization_id = ? AND name IN ('Employee','Manager','Finance Admin','HR Admin') ORDER BY name`).bind(context.organizationId);
    const roles = await roleQuery.all();
    return json({ departments: departments.results || [], teams: teams.results || [], roles: roles.results || [] });
  }

  if (request.method === "GET" && path === "/api/hr/org-structure") {
    if (!hasPermission(context, "employees.view")) return error("You do not have permission to view organization structure.", 403);
    const [departments, teams] = await Promise.all([
      env.DB.prepare(`SELECT d.id, d.name, COUNT(DISTINCT e.id) as employeeCount, COUNT(DISTINCT t.id) as teamCount FROM departments d LEFT JOIN employees e ON e.department_id = d.id AND e.organization_id = d.organization_id AND e.deleted_at IS NULL LEFT JOIN teams t ON t.department_id = d.id AND t.organization_id = d.organization_id WHERE d.organization_id = ? GROUP BY d.id ORDER BY d.name`).bind(context.organizationId).all(),
      env.DB.prepare(`SELECT t.id, t.name, t.department_id as departmentId, d.name as department, COUNT(DISTINCT e.id) as employeeCount FROM teams t LEFT JOIN departments d ON d.id = t.department_id AND d.organization_id = t.organization_id LEFT JOIN employees e ON e.team_id = t.id AND e.organization_id = t.organization_id AND e.deleted_at IS NULL WHERE t.organization_id = ? GROUP BY t.id ORDER BY d.name, t.name`).bind(context.organizationId).all(),
    ]);
    return json({ departments: departments.results || [], teams: teams.results || [] });
  }

  if (request.method === "POST" && path === "/api/hr/teams") {
    if (!hasPermission(context, "teams.manage") && !hasPermission(context, "hr.talent.manage")) return error("You do not have permission to manage departments and teams.", 403);
    const body = await request.json<{ name?: string; kind?: string; departmentId?: string }>();
    const name = body.name?.trim();
    if (!name || name.length > 100 || !["department", "team"].includes(body.kind || "")) return error("A valid team or department name is required.");
    let departmentId = body.departmentId || null;
    if (body.kind === "department") {
      departmentId = `dept-${crypto.randomUUID()}`;
      await env.DB.prepare(`INSERT INTO departments (id, organization_id, name) VALUES (?, ?, ?)`).bind(departmentId, context.organizationId, name).run();
    } else {
      if (departmentId && !await env.DB.prepare(`SELECT id FROM departments WHERE id = ? AND organization_id = ?`).bind(departmentId, context.organizationId).first()) return error("Department not found in this organization.");
      await env.DB.prepare(`INSERT INTO teams (id, organization_id, department_id, name) VALUES (?, ?, ?, ?)`).bind(`team-${crypto.randomUUID()}`, context.organizationId, departmentId, name).run();
    }
    await audit(env, context, "created", "teams", departmentId || name, { kind: body.kind, name });
    return json({ ok: true }, { status: 201 });
  }

  if (request.method === "GET" && path === "/api/payroll/settings") {
    const settings = await env.DB.prepare(`SELECT currency, pay_frequency as payFrequency, tax_country as taxCountry, tax_region as taxRegion, tax_year as taxYear, tax_free_allowance as taxFreeAllowance, tax_bands_json as taxBandsJson, employee_pension_rate as employeePensionRate, employer_pension_rate as employerPensionRate, pension_basis as pensionBasis FROM payroll_settings WHERE organization_id = ?`).bind(context.organizationId).first();
    return json(settings || { currency: "NGN", payFrequency: "monthly", taxCountry: "NG", taxRegion: null, taxYear: new Date().getFullYear(), taxFreeAllowance: 0, taxBandsJson: "[]", employeePensionRate: 0, employerPensionRate: 0, pensionBasis: "base_salary" });
  }

  if (request.method === "PUT" && path === "/api/payroll/settings") {
    if (!hasPermission(context, "payroll.manage")) return error("Payroll administrator permission required.", 403);
    const body = await request.json<{ currency?: string; payFrequency?: string; taxCountry?: string; taxRegion?: string; taxYear?: number; taxFreeAllowance?: number; taxBands?: { upTo: number | null; rate: number }[]; employeePensionRate?: number; employerPensionRate?: number; pensionBasis?: string }>();
    if (!body.currency || !/^[A-Z]{3}$/.test(body.currency) || !["weekly", "biweekly", "semimonthly", "monthly"].includes(body.payFrequency || "") || !body.taxCountry || !/^[A-Za-z]{2}$/.test(body.taxCountry) || !validTaxBands(body.taxBands) || !Number.isFinite(body.taxYear) || Number(body.taxYear) < 2000 || Number(body.taxYear) > 2100 || !Number.isFinite(body.taxFreeAllowance) || Number(body.taxFreeAllowance) < 0 || !Number.isFinite(body.employeePensionRate) || Number(body.employeePensionRate) < 0 || Number(body.employeePensionRate) > 1 || !Number.isFinite(body.employerPensionRate) || Number(body.employerPensionRate) < 0 || Number(body.employerPensionRate) > 1 || !["base_salary", "gross"].includes(body.pensionBasis || "")) return error("Payroll settings must include ordered tax bands ending in an unlimited band, a two-letter country code, valid policy year, currency, frequency, allowance and contribution rates.");
    await env.DB.prepare(`INSERT INTO payroll_settings (organization_id, currency, pay_frequency, tax_country, tax_region, tax_year, tax_free_allowance, tax_bands_json, employee_pension_rate, employer_pension_rate, pension_basis) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(organization_id) DO UPDATE SET currency=excluded.currency, pay_frequency=excluded.pay_frequency, tax_country=excluded.tax_country, tax_region=excluded.tax_region, tax_year=excluded.tax_year, tax_free_allowance=excluded.tax_free_allowance, tax_bands_json=excluded.tax_bands_json, employee_pension_rate=excluded.employee_pension_rate, employer_pension_rate=excluded.employer_pension_rate, pension_basis=excluded.pension_basis, updated_at=CURRENT_TIMESTAMP`)
      .bind(context.organizationId, body.currency, body.payFrequency, body.taxCountry.toUpperCase(), body.taxRegion?.trim() || null, Number(body.taxYear) || new Date().getFullYear(), body.taxFreeAllowance, JSON.stringify(body.taxBands), body.employeePensionRate, body.employerPensionRate, body.pensionBasis).run();
    await audit(env, context, "updated", "payroll_settings");
    return json({ ok: true });
  }

  if (request.method === "GET" && path === "/api/payroll/profiles") {
    if (!hasPermission(context, "payroll.view") && !hasPermission(context, "payroll.manage")) return error("Payroll administrator permission is required to view organization remuneration.", 403);
    const employees = await env.DB.prepare(`SELECT e.id as employeeId, e.employee_number as employeeNumber, e.first_name as firstName, e.last_name as lastName, e.job_title as jobTitle, e.email, p.base_salary as baseSalary, p.currency, p.pay_frequency as payFrequency, p.effective_from as effectiveFrom, p.bank_details_enc as bankDetailsEnc, p.tax_reference as taxReference, p.pension_reference as pensionReference, p.status as payStatus FROM employees e LEFT JOIN employee_pay_profiles p ON p.employee_id = e.id AND p.organization_id = e.organization_id WHERE e.organization_id = ? AND e.deleted_at IS NULL ORDER BY e.first_name, e.last_name`).bind(context.organizationId).all<{ bankDetailsEnc: string | null; [key: string]: unknown }>();
    const data = [];
    for (const row of employees.results || []) {
      let masked = { bankName: null as string | null, accountName: null as string | null, accountLast4: null as string | null };
      if (row.bankDetailsEnc) {
        try {
          const details = await decryptBankDetails(env, row.bankDetailsEnc);
          masked = { bankName: details.bankName, accountName: details.accountName, accountLast4: details.accountNumber.slice(-4) };
        } catch (cause) { console.error("Stored remuneration bank record could not be decrypted", cause); }
      }
      const { bankDetailsEnc: _bankDetailsEnc, ...profile } = row;
      data.push({ ...profile, ...masked, bankConfigured: Boolean(row.bankDetailsEnc) });
    }
    return json({ data });
  }

  if (request.method === "PUT" && path === "/api/payroll/profiles") {
    if (!hasPermission(context, "payroll.manage")) return error("Payroll administrator permission required.", 403);
    const body = await request.json<{ employeeId?: string; baseSalary?: number; currency?: string; payFrequency?: string; effectiveFrom?: string; bankName?: string; accountName?: string; accountNumber?: string; taxReference?: string; pensionReference?: string }>();
    const salary = Number(body.baseSalary);
    if (!body.employeeId || !Number.isFinite(salary) || salary < 0 || !body.effectiveFrom || !isoDate(body.effectiveFrom) || !["weekly", "biweekly", "semimonthly", "monthly"].includes(body.payFrequency || "monthly") || !body.currency || !/^[A-Z]{3}$/.test(body.currency)) return error("Employee, valid salary, currency, pay frequency and effective date are required.");
    if (!(await env.DB.prepare(`SELECT id FROM employees WHERE id = ? AND organization_id = ? AND deleted_at IS NULL`).bind(body.employeeId, context.organizationId).first())) return error("Employee not found.", 404);
    const previousProfile = await env.DB.prepare(`SELECT base_salary as baseSalary, currency, pay_frequency as payFrequency, effective_from as effectiveFrom, status FROM employee_pay_profiles WHERE employee_id = ? AND organization_id = ?`).bind(body.employeeId, context.organizationId).first<{ baseSalary: number; currency: string; payFrequency: string; effectiveFrom: string; status: string }>();
    let bankDetails: string | null = null;
    if (body.bankName || body.accountName || body.accountNumber) {
      const bankName = body.bankName?.trim() || ""; const accountName = body.accountName?.trim() || ""; const accountNumber = body.accountNumber?.replace(/[\s-]/g, "") || "";
      if (!bankName || !accountName || !/^[a-zA-Z0-9]{4,34}$/.test(accountNumber)) return error("Enter the bank name, account name and a valid account number (4–34 letters or digits).");
      try { bankDetails = await encryptBankDetails(env, { bankName, accountName, accountNumber }); }
      catch { return error("Encrypted bank-record storage is unavailable. Configure SESSION_SECRET before saving account details.", 503); }
    }
    await env.DB.prepare(`INSERT INTO employee_pay_profiles (id, organization_id, employee_id, base_salary, currency, pay_frequency, effective_from, bank_details_enc, tax_reference, pension_reference) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(organization_id, employee_id) DO UPDATE SET base_salary=excluded.base_salary, currency=excluded.currency, pay_frequency=excluded.pay_frequency, effective_from=excluded.effective_from, bank_details_enc=COALESCE(excluded.bank_details_enc, employee_pay_profiles.bank_details_enc), tax_reference=excluded.tax_reference, pension_reference=excluded.pension_reference, status='active', updated_at=CURRENT_TIMESTAMP`)
      .bind(`pay-${crypto.randomUUID()}`, context.organizationId, body.employeeId, salary, body.currency, body.payFrequency || "monthly", body.effectiveFrom, bankDetails, body.taxReference?.trim() || null, body.pensionReference?.trim() || null).run();
    await audit(env, context, previousProfile ? "compensation_changed" : "compensation_created", "employee_pay_profiles", body.employeeId, { baseSalary: salary, currency: body.currency, payFrequency: body.payFrequency || "monthly", effectiveFrom: body.effectiveFrom, bankDetailsRecorded: Boolean(bankDetails) }, previousProfile || undefined);
    return json({ ok: true });
  }

  if (request.method === "GET" && path === "/api/payroll/components") {
    const components = await env.DB.prepare(`SELECT id, code, name, kind, taxable, pensionable FROM payroll_components WHERE organization_id = ? ORDER BY kind, name`).bind(context.organizationId).all();
    return json({ data: components.results || [] });
  }

  if (request.method === "POST" && path === "/api/payroll/components") {
    if (!hasPermission(context, "payroll.manage")) return error("Payroll administrator permission required.", 403);
    const body = await request.json<{ code?: string; name?: string; kind?: string; taxable?: boolean; pensionable?: boolean }>();
    const code = body.code?.trim().toUpperCase().replace(/[^A-Z0-9_-]/g, "_");
    if (!code || !body.name?.trim() || !["earning", "deduction", "employer_contribution"].includes(body.kind || "")) return error("Code, name and a valid component type are required.");
    const id = `pc-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO payroll_components (id, organization_id, code, name, kind, taxable, pensionable) VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, code, body.name.trim(), body.kind, body.taxable ? 1 : 0, body.pensionable ? 1 : 0).run();
    return json({ id }, { status: 201 });
  }

  if (request.method === "POST" && path === "/api/payroll/employee-components") {
    if (!hasPermission(context, "payroll.manage")) return error("Payroll administrator permission required.", 403);
    const body = await request.json<{ employeeId?: string; componentId?: string; amount?: number; effectiveFrom?: string }>();
    const amount = Number(body.amount);
    const component = body.componentId ? await env.DB.prepare(`SELECT id FROM payroll_components WHERE id = ? AND organization_id = ?`).bind(body.componentId, context.organizationId).first() : null;
    const employee = body.employeeId ? await env.DB.prepare(`SELECT id FROM employees WHERE id = ? AND organization_id = ? AND deleted_at IS NULL`).bind(body.employeeId, context.organizationId).first() : null;
    if (!employee || !component || !Number.isFinite(amount) || amount < 0 || !body.effectiveFrom || !isoDate(body.effectiveFrom)) return error("Employee, pay component, non-negative amount and valid effective date are required.");
    const id = `epc-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO employee_pay_components (id, organization_id, employee_id, component_id, amount, effective_from) VALUES (?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, body.employeeId, body.componentId, amount, body.effectiveFrom).run();
    return json({ id }, { status: 201 });
  }

  if (request.method === "GET" && path === "/api/payroll/employee-components") {
    const data = await env.DB.prepare(`SELECT ec.id, e.first_name || ' ' || e.last_name as employee, c.name as component, ec.amount, ec.effective_from as effectiveFrom FROM employee_pay_components ec JOIN employees e ON e.id = ec.employee_id AND e.organization_id = ec.organization_id JOIN payroll_components c ON c.id = ec.component_id AND c.organization_id = ec.organization_id WHERE ec.organization_id = ? AND (ec.effective_to IS NULL OR ec.effective_to >= date('now')) ORDER BY e.first_name, c.name`).bind(context.organizationId).all();
    return json({ data: data.results || [] });
  }

  if (request.method === "GET" && path === "/api/payroll/runs") {
    if (!hasPermission(context, "payroll.view") && !hasPermission(context, "payroll.manage")) return error("Payroll viewing permission is required.", 403);
    const runs = await env.DB.prepare(`SELECT id, period_start as periodStart, period_end as periodEnd, payment_date as paymentDate, currency, status, employee_count as employeeCount, gross_total as grossTotal, deductions_total as deductionsTotal, employer_cost_total as employerCostTotal, net_total as netTotal, preflight_warnings_json as preflightWarningsJson, created_at as createdAt FROM payroll_runs WHERE organization_id = ? ORDER BY period_start DESC LIMIT 100`).bind(context.organizationId).all();
    return json({ data: runs.results || [] });
  }

  if (request.method === "POST" && path === "/api/payroll/runs") {
    if (!hasPermission(context, "payroll.run")) return error("Payroll run permission required.", 403);
    const body = await request.json<{ periodStart?: string; periodEnd?: string; paymentDate?: string; adjustments?: { employeeId: string; label: string; kind: "earning" | "deduction"; amount: number }[] }>();
    if (!body.periodStart || !body.periodEnd || !body.paymentDate || !isoDate(body.periodStart) || !isoDate(body.periodEnd) || !isoDate(body.paymentDate) || body.periodEnd < body.periodStart || body.paymentDate < body.periodEnd) return error("Enter valid payroll dates. The period end must not precede its start, and the intended pay date must be on or after period end.");
    const periodEnd = body.periodEnd;
    const overlap = await env.DB.prepare(`SELECT id, status FROM payroll_runs WHERE organization_id = ? AND period_start <= ? AND period_end >= ? LIMIT 1`).bind(context.organizationId, body.periodEnd, body.periodStart).first<{ id: string; status: string }>();
    if (overlap) return error(`This payroll period overlaps an existing ${overlap.status} record. Review that record; a period cannot be run twice, even after voiding.`, 409);
    const config = await env.DB.prepare(`SELECT currency, pay_frequency as payFrequency, tax_free_allowance as taxFreeAllowance, tax_bands_json as taxBandsJson, employee_pension_rate as employeePensionRate, employer_pension_rate as employerPensionRate, pension_basis as pensionBasis FROM payroll_settings WHERE organization_id = ?`).bind(context.organizationId).first<{ currency: string; payFrequency: string; taxFreeAllowance: number; taxBandsJson: string; employeePensionRate: number; employerPensionRate: number; pensionBasis: string }>();
    if (!config) return error("Configure payroll settings before running payroll.", 409);
    const activeStaff = await env.DB.prepare(`SELECT e.employee_number as employeeNumber, e.first_name as firstName, e.last_name as lastName, e.start_date as startDate, p.status as payStatus, p.pay_frequency as payFrequency, p.currency as payCurrency, p.effective_from as effectiveFrom FROM employees e LEFT JOIN employee_pay_profiles p ON p.employee_id = e.id AND p.organization_id = e.organization_id WHERE e.organization_id = ? AND e.status = 'active' AND e.deleted_at IS NULL AND e.start_date <= ?`).bind(context.organizationId, body.periodEnd).all<{ employeeNumber: string; firstName: string; lastName: string; startDate: string; payStatus: string | null; payFrequency: string | null; payCurrency: string | null; effectiveFrom: string | null }>();
    const blockers = (activeStaff.results || []).flatMap((person) => {
      const name = `${person.firstName} ${person.lastName} (${person.employeeNumber})`;
      if (person.payStatus !== "active") return [`${name}: missing active pay profile`];
      if (person.payFrequency !== config.payFrequency) return [`${name}: pay frequency does not match organization settings`];
      if (person.payCurrency !== config.currency) return [`${name}: currency does not match organization settings`];
      if (!person.effectiveFrom || !isoDate(person.effectiveFrom) || person.effectiveFrom > periodEnd) return [`${name}: pay profile is not effective for this period`];
      return [];
    });
    const duplicateNumbers = await env.DB.prepare(`SELECT employee_number as employeeNumber, COUNT(*) as count FROM employees WHERE organization_id = ? AND status = 'active' AND deleted_at IS NULL AND start_date <= ? GROUP BY employee_number HAVING COUNT(*) > 1`).bind(context.organizationId, body.periodEnd).all<{ employeeNumber: string; count: number }>();
    blockers.push(...(duplicateNumbers.results || []).map((row) => `Duplicate employee number ${row.employeeNumber} is assigned to ${row.count} active employee records`));
    if (blockers.length) return json({ error: `Payroll preflight found ${blockers.length} blocking issue${blockers.length === 1 ? "" : "s"}. No run was created.`, blockers: blockers.slice(0, 50) }, { status: 409 });
    const employees = await env.DB.prepare(`SELECT e.id as employeeId, e.employee_number as employeeNumber, e.first_name as firstName, e.last_name as lastName, e.job_title as jobTitle, e.start_date as startDate, p.base_salary as baseSalary, p.currency as payCurrency, c.id as componentId, c.code as componentCode, c.name as componentName, c.kind as componentKind, c.taxable, c.pensionable, ec.amount as componentAmount FROM employees e JOIN employee_pay_profiles p ON p.employee_id = e.id AND p.organization_id = e.organization_id AND p.status = 'active' AND p.pay_frequency = (SELECT pay_frequency FROM payroll_settings WHERE organization_id = e.organization_id) LEFT JOIN employee_pay_components ec ON ec.employee_id = e.id AND ec.organization_id = e.organization_id AND ec.effective_from <= ? AND (ec.effective_to IS NULL OR ec.effective_to >= ?) LEFT JOIN payroll_components c ON c.id = ec.component_id AND c.organization_id = e.organization_id WHERE e.organization_id = ? AND e.status = 'active' AND e.deleted_at IS NULL ORDER BY e.employee_number`).bind(body.periodEnd, body.periodStart, context.organizationId).all<Record<string, unknown>>();
    const byEmployee = new Map<string, Record<string, unknown>[]>();
    for (const employee of employees.results || []) { const list = byEmployee.get(String(employee.employeeId)) || []; list.push(employee); byEmployee.set(String(employee.employeeId), list); }
    if (!byEmployee.size) return error("Add active employees and pay profiles before creating a run.", 409);
    const adjustments = body.adjustments || [];
    if (adjustments.length > 1000 || adjustments.some((item) => !item || !byEmployee.has(item.employeeId) || typeof item.label !== "string" || !item.label.trim() || item.label.length > 120 || !["earning", "deduction"].includes(item.kind) || !Number.isFinite(item.amount) || item.amount < 0 || item.amount > 1_000_000_000_000)) return error("Payroll adjustments contain invalid employee, type, label or amount.");
    let taxBands: { upTo: number | null; rate: number }[];
    try { taxBands = JSON.parse(config.taxBandsJson) as { upTo: number | null; rate: number }[]; } catch { return error("Tax bands are invalid. Save payroll settings again.", 409); }
    if (!validTaxBands(taxBands)) return error("Tax bands must have valid rates, strictly ascending positive thresholds, and exactly one final band with no upper limit.", 409);
    const runId = `pr-${crypto.randomUUID()}`;
    const calculated: { id: string; employeeId: string; employeeNumber: string; employeeName: string; jobTitle: string; baseSalary: number; gross: number; taxable: number; tax: number; employeePension: number; employerPension: number; otherDeductions: number; employerContributions: number; net: number; breakdown: Record<string, unknown> }[] = [];
    for (const [employeeId, rows] of byEmployee) {
      const employee = rows[0];
      const baseSalary = Number(employee.baseSalary || 0);
      if (employee.payCurrency !== config.currency) return error(`Pay currency for ${employee.firstName} ${employee.lastName} does not match payroll settings.`, 409);
      let gross = baseSalary;
      let taxableEarnings = baseSalary;
      let pensionableEarnings = baseSalary;
      let otherDeductions = 0;
      let employerContributions = 0;
      const lines: { code: string; name: string; kind: string; amount: number }[] = [{ code: "BASE", name: "Base salary", kind: "earning", amount: baseSalary }];
      for (const row of rows) {
        const amount = Number(row.componentAmount || 0);
        if (!row.componentId || amount === 0) continue;
        const kind = String(row.componentKind);
        lines.push({ code: String(row.componentCode), name: String(row.componentName), kind, amount });
        if (kind === "earning") { gross += amount; if (row.taxable) taxableEarnings += amount; if (row.pensionable) pensionableEarnings += amount; }
        if (kind === "deduction") otherDeductions += amount;
        if (kind === "employer_contribution") employerContributions += amount;
      }
      for (const adj of adjustments.filter((item) => item.employeeId === employeeId)) {
        lines.push({ code: "ADJUSTMENT", name: adj.label.trim(), kind: adj.kind, amount: adj.amount });
        if (adj.kind === "earning") { gross += adj.amount; taxableEarnings += adj.amount; }
        else otherDeductions += adj.amount;
      }
      const pensionBasis = config.pensionBasis === "gross" ? gross : pensionableEarnings;
      const employeePension = Math.round(pensionBasis * config.employeePensionRate * 100) / 100;
      const employerPension = Math.round(pensionBasis * config.employerPensionRate * 100) / 100;
      const taxable = Math.max(0, taxableEarnings - Number(config.taxFreeAllowance || 0) - employeePension);
      let remaining = taxable;
      let lower = 0;
      let tax = 0;
      for (const band of taxBands) {
        const upper = band.upTo === null ? Number.POSITIVE_INFINITY : band.upTo;
        const portion = Math.max(0, Math.min(remaining, upper - lower));
        tax += portion * band.rate;
        remaining -= portion;
        lower = upper;
        if (remaining <= 0) break;
      }
      if (remaining > 0) return error("Tax bands must include a final band with no upper limit.", 409);
      tax = Math.round(tax * 100) / 100;
      const net = gross - otherDeductions - employeePension - tax;
      if (![gross, taxable, tax, employeePension, employerPension, otherDeductions, employerContributions, net].every(Number.isFinite) || net < 0) return error(`Payroll calculation for ${employee.firstName} ${employee.lastName} would produce an invalid or negative net amount. Review deductions and policy settings.`, 409);
      const prorationDays = Math.max(0, Math.min(1, (new Date(body.periodEnd).getTime() - new Date(String(employee.startDate)).getTime() + 86400000) / (new Date(body.periodEnd).getTime() - new Date(body.periodStart).getTime() + 86400000)));
      const factor = String(employee.startDate) > body.periodStart ? prorationDays : 1;
      const prorate = (value: number) => Math.round(value * factor * 100) / 100;
      calculated.push({ id: `pri-${crypto.randomUUID()}`, employeeId, employeeNumber: String(employee.employeeNumber), employeeName: `${employee.firstName} ${employee.lastName}`, jobTitle: String(employee.jobTitle), baseSalary: prorate(baseSalary), gross: prorate(gross), taxable: prorate(taxable), tax: prorate(tax), employeePension: prorate(employeePension), employerPension: prorate(employerPension), otherDeductions: prorate(otherDeductions), employerContributions: prorate(employerContributions), net: prorate(net), breakdown: { currency: config.currency, lines, prorated: factor !== 1, prorationFactor: factor, taxBands } });
    }
    const sum = (key: "gross" | "tax" | "employeePension" | "employerPension" | "otherDeductions" | "employerContributions" | "net") => calculated.reduce((total, item) => total + item[key], 0);
    const preflightWarnings = calculated.filter((item) => item.gross > 0 && item.otherDeductions / item.gross > 0.4).map((item) => `${item.employeeName}: additional deductions exceed 40% of gross earnings; verify authorization and policy.`);
    const statements: D1PreparedStatement[] = [env.DB.prepare(`INSERT INTO payroll_runs (id, organization_id, period_start, period_end, payment_date, currency, status, employee_count, gross_total, deductions_total, employer_cost_total, net_total, created_by, preflight_warnings_json) VALUES (?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?)`)
      .bind(runId, context.organizationId, body.periodStart, body.periodEnd, body.paymentDate, config.currency, calculated.length, sum("gross"), sum("tax") + sum("employeePension") + sum("otherDeductions"), sum("gross") + sum("employerPension") + sum("employerContributions"), sum("net"), context.userId, JSON.stringify(preflightWarnings))];
    for (const item of calculated) statements.push(env.DB.prepare(`INSERT INTO payroll_run_items (id, organization_id, payroll_run_id, employee_id, employee_number, employee_name, job_title, base_salary, gross_pay, taxable_pay, paye_tax, employee_pension, employer_pension, other_deductions, employer_contributions, net_pay, breakdown_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(item.id, context.organizationId, runId, item.employeeId, item.employeeNumber, item.employeeName, item.jobTitle, item.baseSalary, item.gross, item.taxable, item.tax, item.employeePension, item.employerPension, item.otherDeductions, item.employerContributions, item.net, JSON.stringify(item.breakdown)));
    await env.DB.batch(statements);
    await audit(env, context, "created", "payroll_runs", runId, { periodStart: body.periodStart, periodEnd: body.periodEnd, employeeCount: calculated.length });
    await notifyApprovers(env, context, "Finance Admin", `Payroll run · ${body.periodStart} to ${body.periodEnd}`, `A payroll run covering ${calculated.length} employees is ready for finance review.`);
    return json({ id: runId, employeeCount: calculated.length, status: "draft", preflightWarnings }, { status: 201 });
  }

  const payrollRunMatch = path.match(/^\/api\/payroll\/runs\/([^/]+)(?:\/(action|payslips|export|payout))?$/);
  if (payrollRunMatch && request.method === "GET") {
    if (!hasPermission(context, "payroll.view") && !hasPermission(context, "payroll.manage")) return error("Payroll viewing permission is required.", 403);
    const runId = payrollRunMatch[1];
    const run = await env.DB.prepare(`SELECT id, period_start as periodStart, period_end as periodEnd, payment_date as paymentDate, currency, status, employee_count as employeeCount, gross_total as grossTotal, deductions_total as deductionsTotal, employer_cost_total as employerCostTotal, net_total as netTotal, preflight_warnings_json as preflightWarningsJson, created_at as createdAt FROM payroll_runs WHERE id = ? AND organization_id = ?`).bind(runId, context.organizationId).first();
    if (!run) return error("Payroll run not found.", 404);
    const items = await env.DB.prepare(`SELECT id, employee_id as employeeId, employee_number as employeeNumber, employee_name as employeeName, job_title as jobTitle, base_salary as baseSalary, gross_pay as grossPay, taxable_pay as taxablePay, paye_tax as payeTax, employee_pension as employeePension, employer_pension as employerPension, other_deductions as otherDeductions, employer_contributions as employerContributions, net_pay as netPay, breakdown_json as breakdownJson FROM payroll_run_items WHERE payroll_run_id = ? AND organization_id = ? ORDER BY employee_name`).bind(runId, context.organizationId).all();
    if (payrollRunMatch[2] === "export") {
      const headers = ["Employee number", "Employee", "Job title", "Base salary", "Gross pay", "PAYE", "Employee pension", "Other deductions", "Net pay", "Employer pension", "Employer contributions"];
      const values = (items.results || []).map((row: Record<string, unknown>) => [row.employeeNumber, row.employeeName, row.jobTitle, row.baseSalary, row.grossPay, row.payeTax, row.employeePension, row.otherDeductions, row.netPay, row.employerPension, row.employerContributions]);
      const cell = (value: unknown) => { let text = String(value ?? ""); if (/^[\s]*[=+@-]/.test(text)) text = `'${text}`; return `"${text.replaceAll('"', '""').replace(/[\r\n]+/g, " ")}"`; };
      const csv = [headers, ...values].map((row) => row.map(cell).join(",")).join("\r\n");
      return new Response(csv, { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="zyntris-payroll-${runId}.csv"`, "cache-control": "private, no-store", "x-content-type-options": "nosniff" } });
    }
    if (payrollRunMatch[2] === "payout") return error("Zyntris is a remuneration record system and does not generate bank payout files or initiate transfers.", 410);
    return json({ run, items: items.results || [] });
  }

  if (payrollRunMatch && request.method === "POST" && payrollRunMatch[2] === "action") {
    const body = await request.json<{ action?: string }>();
    const transition: Record<string, string> = { review: "draft", approve: "reviewed", pay: "approved", void: "draft" };
    if (!body.action || !transition[body.action]) return error("Choose review, approve, pay or void.");
    const required = body.action === "review" ? "payroll.run" : "payroll.approve";
    if (!hasPermission(context, required)) return error("You do not have permission for this payroll action.", 403);
    if (body.action === "approve" && context.role !== "CEO") return error("Only the CEO can give final approval to a payroll run.", 403);
    if (body.action === "review" || body.action === "approve") {
      const separation = await env.DB.prepare(`SELECT created_by as createdBy, reviewed_by as reviewedBy FROM payroll_runs WHERE id = ? AND organization_id = ?`).bind(payrollRunMatch[1], context.organizationId).first<{ createdBy: string; reviewedBy: string | null }>();
      if (separation?.createdBy === context.userId) return error("The payroll creator cannot review or finally approve the same run.", 403);
      if (body.action === "approve" && separation?.reviewedBy === context.userId) return error("The finance reviewer and final CEO approver must be different people.", 403);
    }
    const actorColumn = body.action === "review" ? "reviewed_by" : body.action === "approve" ? "approved_by" : body.action === "pay" ? "paid_by" : null;
    const next = body.action === "review" ? "reviewed" : body.action === "approve" ? "approved" : body.action === "pay" ? "paid" : "void";
    const result = await env.DB.prepare(`UPDATE payroll_runs SET status = ?, ${actorColumn ? `${actorColumn} = ?,` : ""} updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = ?`)
      .bind(...(actorColumn ? [next, context.userId, payrollRunMatch[1], context.organizationId, transition[body.action]] : [next, payrollRunMatch[1], context.organizationId, transition[body.action]])).run();
    if (!result.meta.changes) return error("That payroll transition is not allowed from the current status.", 409);
    await audit(env, context, body.action, "payroll_runs", payrollRunMatch[1]);
    if (body.action === "review") {
      const payrollRun = await env.DB.prepare(`SELECT period_start as periodStart, period_end as periodEnd FROM payroll_runs WHERE id = ? AND organization_id = ?`).bind(payrollRunMatch[1], context.organizationId).first<{ periodStart: string; periodEnd: string }>();
      if (payrollRun) await notifyApprovers(env, context, "CEO", `Payroll run · ${payrollRun.periodStart} to ${payrollRun.periodEnd}`, "Finance review is complete. Final CEO approval is pending.");
    }
    if (body.action === "approve") {
      const payrollNotice = await env.DB.prepare(`SELECT u.email, u.full_name as fullName, o.name as organizationName, r.period_start as periodStart, r.period_end as periodEnd FROM payroll_runs r JOIN users u ON u.id = r.created_by JOIN organizations o ON o.id = r.organization_id WHERE r.id = ? AND r.organization_id = ?`).bind(payrollRunMatch[1], context.organizationId).first<{ email: string; fullName: string; organizationName: string; periodStart: string; periodEnd: string }>();
      if (payrollNotice) await sendApprovalNotificationEmail(env, payrollNotice.email, payrollNotice.fullName, payrollNotice.organizationName, "Payroll record approved", `Your payroll record for ${payrollNotice.periodStart} to ${payrollNotice.periodEnd} has received final CEO approval.`);
    }
    return json({ ok: true, status: next });
  }

  if (request.method === "GET" && path === "/api/dashboard") {
    return json(await dashboard(env, context));
  }

  if (request.method === "GET" && path === "/api/employees") {
    if (!hasPermission(context, "employees.view")) return error("You do not have permission to view employee records.", 403);
    const query = url.searchParams.get("q")?.trim();
    const result = await env.DB.prepare(`
      SELECT e.id, e.employee_number as employeeNumber, e.first_name as firstName, e.last_name as lastName, e.email, e.job_title as jobTitle, e.status, e.onboarding_status as onboardingStatus, (SELECT i.email_status FROM employee_invites i WHERE i.employee_id = e.id ORDER BY i.created_at DESC LIMIT 1) as invitationEmailStatus, (SELECT i.last_error FROM employee_invites i WHERE i.employee_id = e.id ORDER BY i.created_at DESC LIMIT 1) as invitationEmailError, e.work_location as workLocation, e.start_date as startDate, e.avatar_color as avatarColor, d.name as department, t.name as team, e.manager_id as managerId, manager.first_name || ' ' || manager.last_name as managerName, r.name as accessRole
      FROM employees e LEFT JOIN departments d ON d.id = e.department_id LEFT JOIN teams t ON t.id = e.team_id LEFT JOIN employees manager ON manager.id = e.manager_id AND manager.organization_id = e.organization_id AND manager.deleted_at IS NULL LEFT JOIN memberships m ON m.user_id = e.user_id AND m.organization_id = e.organization_id LEFT JOIN roles r ON r.id = m.role_id
      WHERE e.organization_id = ? AND e.deleted_at IS NULL AND (? IS NULL OR e.first_name || ' ' || e.last_name LIKE '%' || ? || '%' OR e.employee_number LIKE '%' || ? || '%')
      ORDER BY e.first_name ASC
    `).bind(context.organizationId, query || null, query || null, query || null).all();
    return json({ data: result.results || [] });
  }

  const employeeManagerMatch = path.match(/^\/api\/employees\/([^/]+)\/manager$/);
  if (request.method === "PATCH" && employeeManagerMatch) {
    if (!hasPermission(context, "employees.manage")) return error("HR administrator permission is required to assign line managers.", 403);
    const body = await request.json<{ managerId?: string | null }>();
    const employee = await env.DB.prepare(`SELECT id FROM employees WHERE id = ? AND organization_id = ? AND deleted_at IS NULL`).bind(employeeManagerMatch[1], context.organizationId).first<{ id: string }>();
    if (!employee) return error("Employee not found.", 404);
    if (body.managerId) {
      if (body.managerId === employee.id) return error("An employee cannot be their own line manager.");
      const manager = await env.DB.prepare(`SELECT id FROM employees WHERE id = ? AND organization_id = ? AND status = 'active' AND deleted_at IS NULL`).bind(body.managerId, context.organizationId).first();
      if (!manager) return error("Choose an active line manager in this organization.");
    }
    await env.DB.prepare(`UPDATE employees SET manager_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(body.managerId || null, employee.id, context.organizationId).run();
    await audit(env, context, "manager_assigned", "employees", employee.id, { managerId: body.managerId || null });
    return json({ ok: true, managerId: body.managerId || null });
  }

  if (request.method === "POST" && path === "/api/employees") {
    if (!hasPermission(context, "employees.manage")) return error("HR administrator permission is required to onboard employees.", 403);
    const body = await request.json<{ firstName?: string; lastName?: string; email?: string; jobTitle?: string; departmentName?: string; teamName?: string; managerId?: string; roleName?: string; startDate?: string; employmentType?: string; workLocation?: string }>();
    const firstName = body.firstName?.trim(); const lastName = body.lastName?.trim(); const email = body.email?.trim().toLowerCase(); const jobTitle = body.jobTitle?.trim();
    if (!firstName || !lastName || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !jobTitle || !body.startDate || !/^\d{4}-\d{2}-\d{2}$/.test(body.startDate)) return error("Enter a valid name, work email, job title and start date.");
    const roleName = body.roleName?.trim() || "Employee";
    if (body.managerId && !await env.DB.prepare(`SELECT id FROM employees WHERE id = ? AND organization_id = ? AND status = 'active' AND deleted_at IS NULL`).bind(body.managerId, context.organizationId).first()) return error("Choose an active line manager in this organization.");
    const elevatedRole = ["CEO", "Organization Admin"].includes(roleName);
    if (elevatedRole && !hasPermission(context, "settings.manage")) return error("Only an organization administrator can assign executive or administrator access.", 403);
    const role = await env.DB.prepare(`SELECT id FROM roles WHERE organization_id = ? AND name = ?`).bind(context.organizationId, roleName).first<{ id: string }>();
    if (!role) return error("Choose an access role available to this organization.");
    if (await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first() || await env.DB.prepare(`SELECT id FROM employees WHERE organization_id = ? AND email = ? AND deleted_at IS NULL`).bind(context.organizationId, email).first()) return error("That email address already has an account or employee record.", 409);
    let departmentId: string | null = null; let teamId: string | null = null;
    const departmentName = body.departmentName?.trim(); const teamName = body.teamName?.trim();
    if (departmentName) {
      await env.DB.prepare(`INSERT OR IGNORE INTO departments (id, organization_id, name) VALUES (?, ?, ?)`).bind(`dept-${crypto.randomUUID()}`, context.organizationId, departmentName).run();
      departmentId = (await env.DB.prepare(`SELECT id FROM departments WHERE organization_id = ? AND name = ?`).bind(context.organizationId, departmentName).first<{ id: string }>())?.id || null;
    }
    if (teamName) {
      await env.DB.prepare(`INSERT OR IGNORE INTO teams (id, organization_id, department_id, name) VALUES (?, ?, ?, ?)`).bind(`team-${crypto.randomUUID()}`, context.organizationId, departmentId, teamName).run();
      teamId = (await env.DB.prepare(`SELECT id FROM teams WHERE organization_id = ? AND name = ?`).bind(context.organizationId, teamName).first<{ id: string }>())?.id || null;
    }
    const id = `emp-${crypto.randomUUID().slice(0, 8)}`;
    const employeeNumber = `EMP-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
    const userId = `usr-${crypto.randomUUID()}`; const inviteId = `inv-${crypto.randomUUID()}`; const token = randomToken();
    const organization = await env.DB.prepare(`SELECT name FROM organizations WHERE id = ?`).bind(context.organizationId).first<{ name: string }>();
    try {
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO users (id, email, full_name, status) VALUES (?, ?, ?, 'invited')`).bind(userId, email, `${firstName} ${lastName}`),
        env.DB.prepare(`INSERT INTO memberships (id, organization_id, user_id, role_id, status) VALUES (?, ?, ?, ?, 'invited')`).bind(`mem-${crypto.randomUUID()}`, context.organizationId, userId, role.id),
        env.DB.prepare(`INSERT INTO employees (id, organization_id, user_id, employee_number, first_name, last_name, email, job_title, department_id, team_id, manager_id, employment_type, work_location, status, onboarding_status, start_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'inactive', 'invited', ?)`)
          .bind(id, context.organizationId, userId, employeeNumber, firstName, lastName, email, jobTitle, departmentId, teamId, body.managerId || null, body.employmentType || "Full-time", body.workLocation || "Hybrid", body.startDate),
        env.DB.prepare(`INSERT INTO employee_invites (id, organization_id, employee_id, user_id, token_hash, expires_at, email_status) VALUES (?, ?, ?, ?, ?, datetime('now', '+72 hours'), 'pending')`).bind(inviteId, context.organizationId, id, userId, await hashToken(token)),
      ]);
    } catch (cause) {
      console.error("Employee invitation could not be saved", cause);
      return error("We couldn’t prepare the onboarding invitation. Please retry or contact support.", 500);
    }
    const delivery = await sendEmployeeInviteEmail(env, email, `${firstName} ${lastName}`, organization?.name || "your organization", token);
    if (!delivery.accepted) {
      const deliveryError = inviteDeliveryError(delivery);
      await env.DB.prepare(`UPDATE employee_invites SET email_status = 'failed', last_error = ?, last_attempt_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(deliveryError, inviteId).run();
      await audit(env, context, "invitation_email_failed", "employees", id, { employeeNumber, reason: delivery.cause });
      return json({ id, employeeNumber, onboardingStatus: "invited", accessRole: roleName, invitationEmailAccepted: false, invitationEmailStatus: "failed", invitationEmailError: deliveryError }, { status: 201 });
    }
    await env.DB.prepare(`UPDATE employee_invites SET email_status = 'accepted', email_message_id = ?, last_error = NULL, last_attempt_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(delivery.messageId || null, inviteId).run();
    await audit(env, context, "invited", "employees", id, { employeeNumber, role: roleName, department: departmentName || null, team: teamName || null });
    return json({ id, employeeNumber, onboardingStatus: "invited", accessRole: roleName, invitationEmailAccepted: true, invitationEmailStatus: "accepted", emailMessageId: delivery.messageId || null }, { status: 201 });
  }

  const employeeInviteMatch = path.match(/^\/api\/employees\/([^/]+)\/invite$/);
  if (request.method === "POST" && employeeInviteMatch) {
    if (!hasPermission(context, "employees.manage")) return error("HR administrator permission is required.", 403);
    const employee = await env.DB.prepare(`SELECT e.id, e.user_id as userId, e.email, e.first_name as firstName, e.last_name as lastName, o.name as organizationName FROM employees e JOIN organizations o ON o.id = e.organization_id WHERE e.id = ? AND e.organization_id = ? AND e.onboarding_status = 'invited' AND e.deleted_at IS NULL`).bind(employeeInviteMatch[1], context.organizationId).first<{ id: string; userId: string; email: string; firstName: string; lastName: string; organizationName: string }>();
    if (!employee?.userId) return error("No pending employee invitation was found.", 404);
    const token = randomToken(); const inviteId = `inv-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO employee_invites (id, organization_id, employee_id, user_id, token_hash, expires_at, email_status, last_attempt_at) VALUES (?, ?, ?, ?, ?, datetime('now', '+72 hours'), 'pending', CURRENT_TIMESTAMP)`).bind(inviteId, context.organizationId, employee.id, employee.userId, await hashToken(token)).run();
    const delivery = await sendEmployeeInviteEmail(env, employee.email, `${employee.firstName} ${employee.lastName}`, employee.organizationName, token);
    if (!delivery.accepted) {
      const deliveryError = inviteDeliveryError(delivery);
      await env.DB.prepare(`UPDATE employee_invites SET email_status = 'failed', last_error = ?, last_attempt_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(deliveryError, inviteId).run();
      await audit(env, context, "invitation_email_failed", "employees", employee.id, { reason: delivery.cause, resend: true });
      return json({ ok: true, invitationEmailAccepted: false, invitationEmailStatus: "failed", invitationEmailError: deliveryError });
    }
    await env.DB.prepare(`UPDATE employee_invites SET email_status = 'accepted', email_message_id = ?, last_error = NULL, last_attempt_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(delivery.messageId || null, inviteId).run();
    await env.DB.prepare(`UPDATE employee_invites SET expires_at = CURRENT_TIMESTAMP WHERE employee_id = ? AND id != ? AND accepted_at IS NULL`).bind(employee.id, inviteId).run();
    await audit(env, context, "invitation_resent", "employees", employee.id);
    return json({ ok: true, invitationEmailAccepted: true, invitationEmailStatus: "accepted", emailMessageId: delivery.messageId || null });
  }

  if (request.method === "GET" && path === "/api/attendance") {
    if (!hasPermission(context, "employees.view")) return error("You do not have permission to view attendance.", 403);
    const canViewAll = hasPermission(context, "employees.manage") || hasPermission(context, "hr.onboarding.approve") ? 1 : 0;
    const result = await env.DB.prepare(`SELECT a.id, a.work_date as workDate, a.clock_in_at as clockInAt, a.clock_out_at as clockOutAt, a.break_minutes as breakMinutes, a.worked_minutes as workedMinutes, a.overtime_minutes as overtimeMinutes, a.status, a.note, e.id as employeeId, e.first_name || ' ' || e.last_name as employee, u.full_name as reviewer FROM attendance_records a JOIN employees e ON e.id = a.employee_id LEFT JOIN users u ON u.id = a.reviewer_id WHERE a.organization_id = ? AND (? = 1 OR e.user_id = ?) ORDER BY a.work_date DESC, a.clock_in_at DESC LIMIT 200`).bind(context.organizationId, canViewAll, context.userId).all();
    return json({ data: result.results || [], canManage: Boolean(canViewAll) });
  }

  if (request.method === "GET" && path === "/api/attendance/shifts") {
    if (!hasPermission(context, "employees.view")) return error("You do not have permission to view shift schedules.", 403);
    const result = await env.DB.prepare(`SELECT s.id, s.employee_id as employeeId, COALESCE(e.first_name || ' ' || e.last_name, 'All employees') as employee, s.weekday, s.start_time as startTime, s.end_time as endTime, s.break_minutes as breakMinutes, s.effective_from as effectiveFrom, s.effective_to as effectiveTo FROM shift_schedules s LEFT JOIN employees e ON e.id = s.employee_id WHERE s.organization_id = ? ORDER BY s.weekday, s.start_time LIMIT 200`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/attendance/shifts") {
    if (!hasPermission(context, "employees.manage")) return error("HR manager permission is required to create shifts.", 403);
    const body = await request.json<{ employeeId?: string; weekday?: number; startTime?: string; endTime?: string; breakMinutes?: number; effectiveFrom?: string; effectiveTo?: string | null }>();
    const weekday = Number(body.weekday); const breakMinutes = Number(body.breakMinutes || 0); const timePattern = /^([01]\d|2[0-3]):[0-5]\d$/;
    if (!Number.isInteger(weekday) || weekday < 0 || weekday > 6 || !body.startTime || !body.endTime || !timePattern.test(body.startTime) || !timePattern.test(body.endTime) || body.startTime >= body.endTime || !Number.isInteger(breakMinutes) || breakMinutes < 0 || breakMinutes > 240 || !body.effectiveFrom || !isoDate(body.effectiveFrom) || body.effectiveTo && (!isoDate(body.effectiveTo) || body.effectiveTo < body.effectiveFrom)) return error("Enter a valid weekday, same-day shift times, break duration and effective date range.");
    if (body.employeeId && !await env.DB.prepare(`SELECT id FROM employees WHERE id = ? AND organization_id = ? AND deleted_at IS NULL`).bind(body.employeeId, context.organizationId).first()) return error("The selected employee was not found in this organization.", 404);
    const id = `shift-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO shift_schedules (id, organization_id, employee_id, weekday, start_time, end_time, break_minutes, effective_from, effective_to, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, body.employeeId || null, weekday, body.startTime, body.endTime, breakMinutes, body.effectiveFrom, body.effectiveTo || null, context.userId).run();
    await audit(env, context, "created", "shift_schedules", id, body);
    return json({ id }, { status: 201 });
  }

  if (request.method === "POST" && path === "/api/attendance/clock-in") {
    if (!hasPermission(context, "employees.view")) return error("Only organization members can clock in.", 403);
    const employee = await env.DB.prepare(`SELECT id FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string }>();
    if (!employee) return error("Your account must be linked to an active employee profile before clocking in.", 409);
    const parts = new Intl.DateTimeFormat("en-CA", { timeZone: "Africa/Lagos", year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(new Date());
    const workDate = `${parts.find((part) => part.type === "year")?.value}-${parts.find((part) => part.type === "month")?.value}-${parts.find((part) => part.type === "day")?.value}`;
    const existing = await env.DB.prepare(`SELECT id, status FROM attendance_records WHERE organization_id = ? AND employee_id = ? AND work_date = ?`).bind(context.organizationId, employee.id, workDate).first<{ id: string; status: string }>();
    if (existing) return error(existing.status === "in_progress" ? "You are already clocked in today." : "An attendance record already exists for today. Contact HR if it needs correction.", 409);
    const id = `attendance-${crypto.randomUUID()}`; const now = new Date().toISOString();
    await env.DB.prepare(`INSERT INTO attendance_records (id, organization_id, employee_id, work_date, clock_in_at, status) VALUES (?, ?, ?, ?, ?, 'in_progress')`).bind(id, context.organizationId, employee.id, workDate, now).run();
    await audit(env, context, "clocked_in", "attendance", id, { workDate, clockInAt: now });
    return json({ id, workDate, clockInAt: now, status: "in_progress" }, { status: 201 });
  }

  if (request.method === "POST" && path === "/api/attendance/clock-out") {
    if (!hasPermission(context, "employees.view")) return error("Only organization members can clock out.", 403);
    const employee = await env.DB.prepare(`SELECT id FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string }>();
    if (!employee) return error("Your account must be linked to an active employee profile before clocking out.", 409);
    const current = await env.DB.prepare(`SELECT id, clock_in_at as clockInAt, work_date as workDate FROM attendance_records WHERE organization_id = ? AND employee_id = ? AND status = 'in_progress' ORDER BY clock_in_at DESC LIMIT 1`).bind(context.organizationId, employee.id).first<{ id: string; clockInAt: string; workDate: string }>();
    if (!current) return error("You do not have an active clock-in to end.", 409);
    const now = new Date(); const elapsed = Math.floor((now.getTime() - new Date(current.clockInAt).getTime()) / 60000);
    if (!Number.isFinite(elapsed) || elapsed <= 0 || elapsed > 24 * 60) return error("This clock-in duration is invalid. Ask HR to correct the time record.", 409);
    const weekdayParts = new Intl.DateTimeFormat("en-US", { timeZone: "Africa/Lagos", weekday: "short" }).formatToParts(new Date(`${current.workDate}T12:00:00Z`));
    const weekday = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(weekdayParts.find((part) => part.type === "weekday")?.value || "");
    const shift = await env.DB.prepare(`SELECT break_minutes as breakMinutes, start_time as startTime, end_time as endTime FROM shift_schedules WHERE organization_id = ? AND (employee_id = ? OR employee_id IS NULL) AND weekday = ? AND effective_from <= ? AND (effective_to IS NULL OR effective_to >= ?) ORDER BY CASE WHEN employee_id = ? THEN 0 ELSE 1 END LIMIT 1`).bind(context.organizationId, employee.id, weekday, current.workDate, current.workDate, employee.id).first<{ breakMinutes: number; startTime: string; endTime: string }>();
    const breakMinutes = shift?.breakMinutes || 0; const workedMinutes = Math.max(0, elapsed - breakMinutes); const shiftMinutes = shift ? (Number(shift.endTime.slice(0, 2)) * 60 + Number(shift.endTime.slice(3)) - Number(shift.startTime.slice(0, 2)) * 60 - Number(shift.startTime.slice(3)) - breakMinutes) : null; const overtimeMinutes = shiftMinutes === null ? null : Math.max(0, workedMinutes - shiftMinutes);
    const changed = await env.DB.prepare(`UPDATE attendance_records SET clock_out_at = ?, break_minutes = ?, worked_minutes = ?, overtime_minutes = ?, status = 'submitted', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND employee_id = ? AND status = 'in_progress'`).bind(now.toISOString(), breakMinutes, workedMinutes, overtimeMinutes, current.id, context.organizationId, employee.id).run();
    if (!changed.meta.changes) return error("The clock-in record changed. Refresh and try again.", 409);
    await audit(env, context, "clocked_out", "attendance", current.id, { clockOutAt: now.toISOString(), workedMinutes, overtimeMinutes });
    return json({ ok: true, workedMinutes, overtimeMinutes });
  }

  const attendanceReviewMatch = path.match(/^\/api\/attendance\/([^/]+)$/);
  if (request.method === "PATCH" && attendanceReviewMatch) {
    if (!hasPermission(context, "employees.manage") && !hasPermission(context, "hr.onboarding.approve")) return error("HR manager permission is required to review attendance.", 403);
    const body = await request.json<{ status?: string; note?: string }>();
    if (body.status !== "approved" && body.status !== "rejected") return error("Choose approved or rejected.");
    const row = await env.DB.prepare(`SELECT a.id, a.status, e.user_id as userId FROM attendance_records a JOIN employees e ON e.id = a.employee_id WHERE a.id = ? AND a.organization_id = ?`).bind(attendanceReviewMatch[1], context.organizationId).first<{ id: string; status: string; userId: string | null }>();
    if (!row) return error("Attendance record not found.", 404);
    if (row.userId === context.userId) return error("You cannot review your own attendance record.", 403);
    if (row.status !== "submitted") return error("Only submitted attendance records can be reviewed.", 409);
    const changed = await env.DB.prepare(`UPDATE attendance_records SET status = ?, reviewer_id = ?, note = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = 'submitted'`).bind(body.status, context.userId, body.note?.trim().slice(0, 1000) || null, row.id, context.organizationId).run();
    if (!changed.meta.changes) return error("The record changed. Refresh and try again.", 409);
    await audit(env, context, body.status, "attendance", row.id, { note: body.note || null });
    return json({ ok: true, status: body.status });
  }

  if (request.method === "GET" && path === "/api/leave/types") {
    const result = await env.DB.prepare(`SELECT id, name, days_per_year as daysPerYear, requires_approval as requiresApproval FROM leave_types WHERE organization_id = ? ORDER BY name`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (path === "/api/leave" && request.method === "GET") {
    const employee = await env.DB.prepare(`SELECT id FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string }>();
    const canManageLeave = hasPermission(context, "employees.manage") || hasPermission(context, "hr.onboarding.approve");
    const result = await env.DB.prepare(`SELECT l.id, l.employee_id as employeeId, e.user_id as employeeUserId, l.leave_type_id as leaveTypeId, l.start_date as startDate, l.end_date as endDate, l.days, l.reason, l.status, e.first_name || ' ' || e.last_name as employee, lt.name as leaveType, e.manager_id as managerId, (e.manager_id = ?) as isLineManager, (e.user_id = ?) as isRequester FROM leave_requests l JOIN employees e ON e.id = l.employee_id AND e.organization_id = l.organization_id JOIN leave_types lt ON lt.id = l.leave_type_id AND lt.organization_id = l.organization_id WHERE l.organization_id = ? AND (? = 1 OR e.user_id = ? OR e.manager_id = ?) ORDER BY CASE l.status WHEN 'pending' THEN 0 ELSE 1 END, l.start_date DESC LIMIT 200`).bind(employee?.id || "", context.userId, context.organizationId, canManageLeave ? 1 : 0, context.userId, employee?.id || "").all<Record<string, unknown>>();
    return json({ data: (result.results || []).map((row) => ({ ...row, canApprove: canManageLeave || row.isLineManager === 1 || row.isLineManager === true, canCancel: row.isRequester === 1 || row.isRequester === true })) });
  }

  if (path === "/api/leave" && request.method === "POST") {
    if (!hasPermission(context, "employees.view")) return error("Organization membership is required to request leave.", 403);
    const body = await request.json<{ leaveTypeId?: string; startDate?: string; endDate?: string; reason?: string }>();
    if (!body.leaveTypeId || !body.startDate || !body.endDate || !isoDate(body.startDate) || !isoDate(body.endDate) || body.endDate < body.startDate || !body.reason?.trim() || body.reason.trim().length > 1000) return error("Choose a leave type, valid dates and a short reason.");
    const today = new Date().toISOString().slice(0, 10);
    if (body.startDate < today) return error("Leave requests must start today or later.");
    if ((Date.parse(`${body.endDate}T00:00:00Z`) - Date.parse(`${body.startDate}T00:00:00Z`)) / 86400000 > 366) return error("A single leave request cannot exceed one year.");
    const employee = await env.DB.prepare(`SELECT e.id, e.first_name as firstName, e.last_name as lastName, e.manager_id as managerId FROM employees e WHERE e.organization_id = ? AND e.user_id = ? AND e.status = 'active' AND e.deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string; firstName: string; lastName: string; managerId: string | null }>();
    if (!employee) return error("Your account needs an active employee profile before you can request leave. Contact your HR administrator.", 409);
    const leaveType = await env.DB.prepare(`SELECT id, name, days_per_year as daysPerYear, requires_approval as requiresApproval FROM leave_types WHERE id = ? AND organization_id = ?`).bind(body.leaveTypeId, context.organizationId).first<{ id: string; name: string; daysPerYear: number; requiresApproval: number }>();
    if (!leaveType) return error("Choose a leave type available to your organization.", 404);
    const conflict = await env.DB.prepare(`SELECT id FROM leave_requests WHERE organization_id = ? AND employee_id = ? AND status IN ('pending','approved') AND start_date <= ? AND end_date >= ? LIMIT 1`).bind(context.organizationId, employee.id, body.endDate, body.startDate).first();
    if (conflict) return error("These dates overlap an existing pending or approved leave request.", 409);
    const settings = await env.DB.prepare(`SELECT working_days_json as workingDaysJson, public_holidays_json as holidaysJson FROM organization_settings WHERE organization_id = ?`).bind(context.organizationId).first<{ workingDaysJson: string; holidaysJson: string }>();
    let workingDays = [1, 2, 3, 4, 5]; let holidays: string[] = [];
    try { if (settings?.workingDaysJson) workingDays = JSON.parse(settings.workingDaysJson) as number[]; } catch { /* use weekday defaults */ }
    try { if (settings?.holidaysJson) holidays = JSON.parse(settings.holidaysJson) as string[]; } catch { /* use no public holidays */ }
    const workdaySet = new Set(workingDays.filter((day) => Number.isInteger(day) && day >= 0 && day <= 6));
    const holidaySet = new Set(holidays.filter((day) => typeof day === "string"));
    let days = 0;
    for (let stamp = Date.parse(`${body.startDate}T00:00:00Z`); stamp <= Date.parse(`${body.endDate}T00:00:00Z`); stamp += 86400000) {
      const date = new Date(stamp); const iso = date.toISOString().slice(0, 10);
      if (workdaySet.has(date.getUTCDay()) && !holidaySet.has(iso)) days += 1;
    }
    if (!days) return error("The selected dates contain no working days under your organization calendar.");
    const startYear = body.startDate.slice(0, 4);
    const used = await env.DB.prepare(`SELECT COALESCE(SUM(days), 0) as days FROM leave_requests WHERE organization_id = ? AND employee_id = ? AND leave_type_id = ? AND status = 'approved' AND strftime('%Y', start_date) = ?`).bind(context.organizationId, employee.id, leaveType.id, startYear).first<{ days: number }>();
    if (leaveType.daysPerYear > 0 && Number(used?.days || 0) + days > leaveType.daysPerYear) return error(`This request would exceed the ${leaveType.daysPerYear}-day annual allowance for ${leaveType.name}. Contact HR if an exception applies.`, 409);
    const manager = employee.managerId ? await env.DB.prepare(`SELECT user_id as userId FROM employees WHERE id = ? AND organization_id = ? AND deleted_at IS NULL`).bind(employee.managerId, context.organizationId).first<{ userId: string | null }>() : null;
    const id = `leave-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO leave_requests (id, organization_id, employee_id, leave_type_id, start_date, end_date, days, reason, status, approver_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, employee.id, leaveType.id, body.startDate, body.endDate, days, body.reason.trim(), leaveType.requiresApproval ? "pending" : "approved", manager?.userId || null).run();
    await audit(env, context, leaveType.requiresApproval ? "submitted" : "auto_approved", "leave_requests", id, { leaveType: leaveType.name, startDate: body.startDate, endDate: body.endDate, days });
    const approverUserId = manager?.userId;
    if (leaveType.requiresApproval && approverUserId) {
      const approver = await env.DB.prepare(`SELECT email, full_name as fullName FROM users WHERE id = ? AND status = 'active'`).bind(approverUserId).first<{ email: string; fullName: string }>();
      await env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'leave_pending', ?, ?)`).bind(requestId(), context.organizationId, approverUserId, "Leave approval pending", `${employee.firstName} ${employee.lastName} requested ${days} working day(s) of ${leaveType.name} (${body.startDate} to ${body.endDate}).`).run();
      if (approver) await sendApprovalNotificationEmail(env, approver.email, approver.fullName, (await env.DB.prepare(`SELECT name FROM organizations WHERE id = ?`).bind(context.organizationId).first<{ name: string }>())?.name || "your organization", "Leave approval pending", `${employee.firstName} ${employee.lastName} requested ${days} working day(s) of ${leaveType.name} from ${body.startDate} to ${body.endDate}. Sign in to review it.`);
    } else if (leaveType.requiresApproval) {
      await notifyApprovers(env, context, "HR Admin", `Leave request · ${employee.firstName} ${employee.lastName}`, `${days} working day(s) of ${leaveType.name} requested from ${body.startDate} to ${body.endDate}.`);
    } else {
      await env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'leave_approved', ?, ?)`).bind(requestId(), context.organizationId, context.userId, "Leave automatically approved", `Your ${leaveType.name} request for ${days} working day(s) has been approved.`).run();
    }
    return json({ id, status: leaveType.requiresApproval ? "pending" : "approved", days }, { status: 201 });
  }

  const leaveAction = path.match(/^\/api\/leave\/([^/]+)$/);
  if (leaveAction && request.method === "PATCH") {
    const body = await request.json<{ status?: string; reason?: string }>();
    const item = await env.DB.prepare(`SELECT l.id, l.status, l.employee_id as employeeId, l.approver_id as approverId, e.user_id as employeeUserId, e.first_name || ' ' || e.last_name as employeeName, lt.name as leaveType, l.start_date as startDate, l.end_date as endDate FROM leave_requests l JOIN employees e ON e.id = l.employee_id AND e.organization_id = l.organization_id JOIN leave_types lt ON lt.id = l.leave_type_id AND lt.organization_id = l.organization_id WHERE l.id = ? AND l.organization_id = ?`).bind(leaveAction[1], context.organizationId).first<{ id: string; status: string; employeeId: string; approverId: string | null; employeeUserId: string | null; employeeName: string; leaveType: string; startDate: string; endDate: string }>();
    if (!item) return error("Leave request not found.", 404);
    if (body.status === "cancelled") {
      if (item.employeeUserId !== context.userId || item.status !== "pending") return error("Only the requester can cancel a pending leave request.", 403);
      await env.DB.prepare(`UPDATE leave_requests SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = 'pending'`).bind(item.id, context.organizationId).run();
      await audit(env, context, "cancelled", "leave_requests", item.id);
      return json({ ok: true, status: "cancelled" });
    }
    if (!['approved','rejected'].includes(body.status || "") || (body.status === "rejected" && !body.reason?.trim())) return error("Choose approve or reject; a rejection must include a reason.");
    const canManageLeave = hasPermission(context, "employees.manage") || hasPermission(context, "hr.onboarding.approve");
    const directManager = await env.DB.prepare(`SELECT id FROM employees WHERE id = ? AND organization_id = ? AND user_id = ? AND deleted_at IS NULL`).bind(item.employeeId, context.organizationId, context.userId).first();
    const reportsToUser = item.approverId === context.userId;
    if (directManager || (!canManageLeave && !reportsToUser)) return error("You are not authorized to approve this leave request.", 403);
    if (item.status !== "pending") return error("This leave request is no longer pending.", 409);
    const decision = body.status as "approved" | "rejected";
    const changed = await env.DB.prepare(`UPDATE leave_requests SET status = ?, approver_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = 'pending'`).bind(decision, context.userId, item.id, context.organizationId).run();
    if (!changed.meta.changes) return error("This request was already updated. Refresh and try again.", 409);
    await audit(env, context, decision, "leave_requests", item.id, { reason: body.reason?.trim() || null });
    if (item.employeeUserId) {
      const message = `Your ${item.leaveType} request for ${item.startDate} to ${item.endDate} was ${decision}${decision === "rejected" ? `: ${body.reason!.trim()}` : ""}.`;
      await env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'leave_decision', ?, ?)`).bind(requestId(), context.organizationId, item.employeeUserId, `Leave request ${decision}`, message).run();
      const requester = await env.DB.prepare(`SELECT email, full_name as fullName FROM users WHERE id = ?`).bind(item.employeeUserId).first<{ email: string; fullName: string }>();
      const organization = await env.DB.prepare(`SELECT name FROM organizations WHERE id = ?`).bind(context.organizationId).first<{ name: string }>();
      if (requester && organization) await sendApprovalNotificationEmail(env, requester.email, requester.fullName, organization.name, `Leave request ${decision}`, message);
    }
    return json({ ok: true, status: decision });
  }

  if (request.method === "GET" && path === "/api/projects") {
    const canSeeAll=hasPermission(context,"projects.view.all")||hasPermission(context,"projects.manage")||hasPermission(context,"operations.manage");
    const employee=await env.DB.prepare(`SELECT id FROM employees WHERE organization_id=? AND user_id=? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId,context.userId).first<{id:string}>();
    const result = await env.DB.prepare(`SELECT p.id,p.project_code as projectCode,p.name,COALESCE(p.description,'') as description,p.status,p.health,p.priority,p.progress,p.start_date as startDate,p.end_date as endDate,p.budget,p.currency,p.expected_revenue as expectedRevenue,p.project_manager_id as projectManagerId,COALESCE(pm.full_name,owner.full_name) as owner,COUNT(t.id) as taskCount,(SELECT COUNT(*) FROM project_milestones m WHERE m.project_id=p.id AND m.organization_id=p.organization_id AND m.status!='completed') as openMilestones,(SELECT COUNT(*) FROM project_risks r WHERE r.project_id=p.id AND r.organization_id=p.organization_id AND r.status!='closed') as openRisks FROM projects p LEFT JOIN users owner ON owner.id=p.owner_id LEFT JOIN users pm ON pm.id=p.project_manager_id LEFT JOIN tasks t ON t.project_id=p.id AND t.organization_id=p.organization_id WHERE p.organization_id=? AND (?=1 OR p.owner_id=? OR p.project_manager_id=? OR EXISTS(SELECT 1 FROM project_members member WHERE member.project_id=p.id AND member.organization_id=p.organization_id AND member.employee_id=?)) GROUP BY p.id ORDER BY CASE p.status WHEN 'active' THEN 0 WHEN 'at_risk' THEN 1 WHEN 'planning' THEN 2 ELSE 3 END,p.name LIMIT 200`).bind(context.organizationId,canSeeAll?1:0,context.userId,context.userId,employee?.id||"").all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/projects") {
    if (!hasPermission(context, "projects.create")&&!hasPermission(context,"operations.manage")) return error("Project creation permission is required.", 403);
    const body = await request.json<{ name?: string; description?: string; status?: string; startDate?: string; endDate?: string; budget?: number; projectManagerId?:string; sponsorId?:string; departmentId?:string; priority?:string; methodology?:string; currency?:string; expectedRevenue?:number; objectives?:string; scope?:string; outOfScope?:string; expectedOutcomes?:string; successCriteria?:string }>();
    if (!body.name?.trim() || body.name.trim().length > 160 || (body.startDate && !isoDate(body.startDate)) || (body.endDate && !isoDate(body.endDate)) || (body.startDate && body.endDate && body.endDate < body.startDate) || (body.budget !== undefined && (!Number.isFinite(Number(body.budget)) || Number(body.budget) < 0)) || (body.expectedRevenue!==undefined&&(!Number.isFinite(Number(body.expectedRevenue))||Number(body.expectedRevenue)<0))) return error("Enter a project name and valid dates/budget.");
    const status = body.status || "planning";
    if (!['draft','proposed','pending_approval','approved','planning','active','on_hold','at_risk','completed','closed','cancelled','archived'].includes(status)) return error("Choose a valid project status.");
    if(status==="approved"&&!hasPermission(context,"projects.approve"))return error("Project approval permission is required to approve a project.",403);
    if(status==="closed"&&!hasPermission(context,"projects.close"))return error("Project closure permission is required to close a project.",403);
    if(body.priority&&!['low','medium','high','urgent'].includes(body.priority))return error("Choose a valid project priority.");
    if(body.departmentId&&!await env.DB.prepare(`SELECT id FROM departments WHERE id=? AND organization_id=?`).bind(body.departmentId,context.organizationId).first())return error("Department not found in this organization.");
    if(body.projectManagerId&&!await env.DB.prepare(`SELECT id FROM users WHERE id=? AND status='active' AND EXISTS(SELECT 1 FROM memberships WHERE organization_id=? AND user_id=users.id AND status='active')`).bind(body.projectManagerId,context.organizationId).first())return error("Choose an active project manager in this organization.");
    if(body.sponsorId&&!await env.DB.prepare(`SELECT id FROM users WHERE id=? AND status='active' AND EXISTS(SELECT 1 FROM memberships WHERE organization_id=? AND user_id=users.id AND status='active')`).bind(body.sponsorId,context.organizationId).first())return error("Choose an active sponsor in this organization.");
    if(body.currency&&!/^[A-Z]{3}$/i.test(body.currency))return error("Enter a valid three-letter currency code.");
    const id = `project-${crypto.randomUUID()}`;
    const code=`PRJ-${crypto.randomUUID().slice(0,8).toUpperCase()}`;
    const budgetMinor=body.budget===undefined?null:Math.round(Number(body.budget)*100),expectedRevenueMinor=Math.round(Number(body.expectedRevenue||0)*100);
    await env.DB.prepare(`INSERT INTO projects (id,organization_id,project_code,name,description,owner_id,project_manager_id,sponsor_id,department_id,status,priority,health,start_date,end_date,budget,budget_minor,currency,expected_revenue,expected_revenue_minor,methodology,objectives,scope,out_of_scope,expected_outcomes,success_criteria,created_by,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,context.organizationId,code,body.name.trim(),body.description?.trim()||null,context.userId,body.projectManagerId||context.userId,body.sponsorId||null,body.departmentId||null,status,body.priority||"medium","green",body.startDate||null,body.endDate||null,body.budget===undefined?null:Number(body.budget),budgetMinor,(body.currency||"NGN").toUpperCase(),Number(body.expectedRevenue||0),expectedRevenueMinor,body.methodology||null,body.objectives||null,body.scope||null,body.outOfScope||null,body.expectedOutcomes||null,body.successCriteria||null,context.userId,context.userId).run();
    await env.DB.prepare(`INSERT INTO project_health_history (id,organization_id,project_id,health,reason,recorded_by) VALUES (?,?,?,?,?,?)`).bind(`phh-${crypto.randomUUID()}`,context.organizationId,id,"green","Initial project health",context.userId).run();
    await audit(env, context, "created", "projects", id, { projectCode:code,name: body.name.trim(), status });
    return json({ id,projectCode:code }, { status: 201 });
  }

  const projectMatch = path.match(/^\/api\/projects\/([^/]+)$/);
  if (projectMatch && request.method === "PATCH") {
    if (!hasPermission(context, "projects.edit")&&!hasPermission(context,"operations.manage")) return error("Project edit permission is required.", 403);
    const body = await request.json<{ name?: string; description?: string; status?: string; progress?: number; startDate?: string | null; endDate?: string | null; budget?: number | null;projectManagerId?:string;sponsorId?:string;departmentId?:string|null;priority?:string;health?:string;currency?:string;expectedRevenue?:number;methodology?:string;objectives?:string;scope?:string;outOfScope?:string;expectedOutcomes?:string;successCriteria?:string }>();
    if (body.status !== undefined && !['draft','proposed','pending_approval','approved','planning','active','on_hold','at_risk','completed','closed','cancelled','archived'].includes(body.status)) return error("Choose a valid project status.");
    if(body.status==="approved"&&!hasPermission(context,"projects.approve"))return error("Project approval permission is required to approve a project.",403);
    if(body.status==="closed"&&!hasPermission(context,"projects.close"))return error("Project closure permission is required to close a project.",403);
    if (body.progress !== undefined && (!Number.isInteger(Number(body.progress)) || Number(body.progress) < 0 || Number(body.progress) > 100)) return error("Progress must be a whole number from 0 to 100.");
    if (body.startDate && !isoDate(body.startDate) || body.endDate && !isoDate(body.endDate)) return error("Enter valid project dates.");
    if(body.health&&!['green','amber','red'].includes(body.health)||body.priority&&!['low','medium','high','urgent'].includes(body.priority)||body.expectedRevenue!==undefined&&(!Number.isFinite(Number(body.expectedRevenue))||Number(body.expectedRevenue)<0)||body.budget!==undefined&&body.budget!==null&&(!Number.isFinite(Number(body.budget))||Number(body.budget)<0))return error("Project health, priority or financial values are invalid.");
    if(body.currency&&!/^[A-Z]{3}$/i.test(body.currency))return error("Enter a valid three-letter currency code.");
    if(body.projectManagerId&&!await env.DB.prepare(`SELECT id FROM users WHERE id=? AND status='active' AND EXISTS(SELECT 1 FROM memberships WHERE organization_id=? AND user_id=users.id AND status='active')`).bind(body.projectManagerId,context.organizationId).first())return error("Choose an active project manager in this organization.");
    if(body.sponsorId&&!await env.DB.prepare(`SELECT id FROM users WHERE id=? AND status='active' AND EXISTS(SELECT 1 FROM memberships WHERE organization_id=? AND user_id=users.id AND status='active')`).bind(body.sponsorId,context.organizationId).first())return error("Choose an active sponsor in this organization.");
    if(body.departmentId&&!await env.DB.prepare(`SELECT id FROM departments WHERE id=? AND organization_id=?`).bind(body.departmentId,context.organizationId).first())return error("Department not found in this organization.");
    const before=await env.DB.prepare(`SELECT status,health,progress,budget,name,currency FROM projects WHERE id=? AND organization_id=?`).bind(projectMatch[1],context.organizationId).first<{status:string;health:string;progress:number;budget:number|null;name:string;currency:string}>();
    if(body.endDate&&body.startDate&&body.endDate<body.startDate)return error("The project end date must be on or after its start date.");
    if(body.status==="approved"&&before?.status!=="pending_approval")return error("Only projects awaiting approval can be approved.",409);
    const changed = await env.DB.prepare(`UPDATE projects SET name=COALESCE(?,name),description=CASE WHEN ?=1 THEN ? ELSE description END,status=COALESCE(?,status),progress=COALESCE(?,progress),start_date=CASE WHEN ?=1 THEN ? ELSE start_date END,end_date=CASE WHEN ?=1 THEN ? ELSE end_date END,budget=CASE WHEN ?=1 THEN ? ELSE budget END,budget_minor=CASE WHEN ?=1 THEN ? ELSE budget_minor END,project_manager_id=COALESCE(?,project_manager_id),sponsor_id=COALESCE(?,sponsor_id),department_id=CASE WHEN ?=1 THEN ? ELSE department_id END,priority=COALESCE(?,priority),health=COALESCE(?,health),currency=COALESCE(?,currency),expected_revenue=COALESCE(?,expected_revenue),expected_revenue_minor=COALESCE(?,expected_revenue_minor),methodology=COALESCE(?,methodology),objectives=COALESCE(?,objectives),scope=COALESCE(?,scope),out_of_scope=COALESCE(?,out_of_scope),expected_outcomes=COALESCE(?,expected_outcomes),success_criteria=COALESCE(?,success_criteria),updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=?`).bind(body.name?.trim()||null,body.description!==undefined?1:0,body.description||"",body.status||null,body.progress??null,body.startDate!==undefined?1:0,body.startDate||null,body.endDate!==undefined?1:0,body.endDate||null,body.budget!==undefined?1:0,body.budget,body.budget!==undefined?1:0,body.budget===null?null:body.budget===undefined?null:Math.round(Number(body.budget)*100),body.projectManagerId||null,body.sponsorId||null,body.departmentId!==undefined?1:0,body.departmentId||null,body.priority||null,body.health||null,body.currency?.toUpperCase()||null,body.expectedRevenue??null,body.expectedRevenue===undefined?null:Math.round(Number(body.expectedRevenue)*100),body.methodology||null,body.objectives||null,body.scope||null,body.outOfScope||null,body.expectedOutcomes||null,body.successCriteria||null,context.userId,projectMatch[1],context.organizationId).run();
    if (!changed.meta.changes) return error("Project not found.", 404);
    if(body.health&&before?.health!==body.health)await env.DB.prepare(`INSERT INTO project_health_history (id,organization_id,project_id,health,reason,recorded_by) VALUES (?,?,?,?,?,?)`).bind(`phh-${crypto.randomUUID()}`,context.organizationId,projectMatch[1],body.health,"Project health updated",context.userId).run();
    await audit(env, context, body.status&&body.status!==before?.status?`status_${body.status}`:"updated", "projects", projectMatch[1], body,before);
    if(body.status==="pending_approval"&&before?.status!=="pending_approval"){
      const approvalId=`approval-${requestId()}`;const title=`Project proposal: ${before?.name||projectMatch[1]}`;
      await env.DB.prepare(`INSERT INTO approval_requests(id,organization_id,request_type,source_record_id,title,requester_id,currency,required_role,status,current_step,metadata_json,due_at) VALUES(?,?,'Project proposal',?,?,?,?,'CEO','pending',1,?,datetime('now','+72 hours'))`).bind(approvalId,context.organizationId,projectMatch[1],title,context.userId,before?.currency||"NGN",JSON.stringify({projectId:projectMatch[1],approvalPolicy:["CEO","HR Admin"]})).run();
      await notifyApprovers(env,context,"CEO",title,"A project proposal is awaiting your approval.");
    }
    return json({ ok: true });
  }

  const projectMilestonesMatch=path.match(/^\/api\/projects\/([^/]+)\/milestones$/);
  if(projectMilestonesMatch){
    const project=await env.DB.prepare(`SELECT p.id FROM projects p WHERE p.id=? AND p.organization_id=? AND (?=1 OR p.owner_id=? OR p.project_manager_id=? OR EXISTS(SELECT 1 FROM project_members member JOIN employees e ON e.id=member.employee_id AND e.organization_id=member.organization_id WHERE member.project_id=p.id AND member.organization_id=p.organization_id AND e.user_id=?))`).bind(projectMilestonesMatch[1],context.organizationId,(hasPermission(context,"projects.view.all")||hasPermission(context,"projects.manage")||hasPermission(context,"operations.manage"))?1:0,context.userId,context.userId,context.userId).first();
    if(!project)return error("Project not found or access is not enabled.",404);
    if(request.method==="GET"){const result=await env.DB.prepare(`SELECT m.id,m.name,m.description,m.owner_id as ownerId,u.full_name as owner,m.target_date as targetDate,m.completed_at as completedAt,m.status,m.deliverables_json as deliverablesJson,(SELECT COUNT(*) FROM tasks t WHERE t.organization_id=m.organization_id AND t.project_id=m.project_id AND t.due_date=m.target_date) as linkedTasks FROM project_milestones m LEFT JOIN users u ON u.id=m.owner_id WHERE m.organization_id=? AND m.project_id=? ORDER BY m.target_date`).bind(context.organizationId,projectMilestonesMatch[1]).all();return json({data:result.results||[]});}
    if(request.method==="POST"){
      if(!hasPermission(context,"projects.manage")&&!hasPermission(context,"operations.manage"))return error("Project management permission is required to add milestones.",403);
      const body=await request.json<{name?:string;description?:string;ownerId?:string;targetDate?:string}>();if(!body.name?.trim()||body.name.length>160||!body.targetDate||!isoDate(body.targetDate))return error("Provide a milestone name and valid target date.");
      if(body.ownerId&&!await env.DB.prepare(`SELECT 1 FROM memberships WHERE organization_id=? AND user_id=? AND status='active'`).bind(context.organizationId,body.ownerId).first())return error("Milestone owner must be an active organization member.");
      const id=`mile-${requestId()}`;await env.DB.prepare(`INSERT INTO project_milestones (id,organization_id,project_id,name,description,owner_id,target_date,created_by) VALUES (?,?,?,?,?,?,?,?)`).bind(id,context.organizationId,projectMilestonesMatch[1],body.name.trim(),body.description?.trim()||null,body.ownerId||null,body.targetDate,context.userId).run();await audit(env,context,"created","project_milestones",id,body);return json({id},{status:201});
    }
  }
  const projectMilestoneMatch=path.match(/^\/api\/projects\/([^/]+)\/milestones\/([^/]+)$/);
  if(projectMilestoneMatch&&request.method==="PATCH"){
    if(!hasPermission(context,"projects.manage")&&!hasPermission(context,"operations.manage"))return error("Project management permission is required.",403);
    const body=await request.json<{status?:string;name?:string;description?:string;targetDate?:string}>();if(body.status&&!['pending','in_progress','completed','cancelled'].includes(body.status)||body.targetDate&&!isoDate(body.targetDate))return error("Milestone update is invalid.");
    const current=await env.DB.prepare(`SELECT id,status FROM project_milestones WHERE id=? AND project_id=? AND organization_id=?`).bind(projectMilestoneMatch[2],projectMilestoneMatch[1],context.organizationId).first<{id:string;status:string}>();if(!current)return error("Milestone not found.",404);
    await env.DB.prepare(`UPDATE project_milestones SET name=COALESCE(?,name),description=CASE WHEN ?=1 THEN ? ELSE description END,target_date=COALESCE(?,target_date),status=COALESCE(?,status),completed_at=CASE WHEN ?='completed' THEN COALESCE(completed_at,CURRENT_TIMESTAMP) WHEN ? IS NOT NULL THEN NULL ELSE completed_at END,updated_at=CURRENT_TIMESTAMP WHERE id=? AND project_id=? AND organization_id=?`).bind(body.name?.trim()||null,body.description!==undefined?1:0,body.description||"",body.targetDate||null,body.status||null,body.status||current.status,body.status||null,current.id,projectMilestoneMatch[1],context.organizationId).run();await audit(env,context,body.status=== "completed"?"completed":"updated","project_milestones",current.id,body,current);return json({ok:true});
  }

  const projectRegisterMatch=path.match(/^\/api\/projects\/([^/]+)\/(risks|issues)$/);
  if(projectRegisterMatch){
    const [projectId,kind]=[projectRegisterMatch[1],projectRegisterMatch[2] as "risks"|"issues"];
    const project=await env.DB.prepare(`SELECT id FROM projects WHERE id=? AND organization_id=? AND (?=1 OR owner_id=? OR project_manager_id=? OR EXISTS(SELECT 1 FROM project_members member JOIN employees e ON e.id=member.employee_id AND e.organization_id=member.organization_id WHERE member.project_id=projects.id AND member.organization_id=projects.organization_id AND e.user_id=?))`).bind(projectId,context.organizationId,(hasPermission(context,"projects.view.all")||hasPermission(context,"projects.manage")||hasPermission(context,"operations.manage"))?1:0,context.userId,context.userId,context.userId).first();if(!project)return error("Project not found or access is not enabled.",404);
    const table=kind==="risks"?"project_risks":"project_issues";
    if(request.method==="GET"){const result=await env.DB.prepare(`SELECT x.*,u.full_name as owner FROM ${table} x LEFT JOIN users u ON u.id=x.owner_id WHERE x.organization_id=? AND x.project_id=? ORDER BY x.updated_at DESC`).bind(context.organizationId,projectId).all();return json({data:result.results||[]});}
    if(request.method==="POST"){
      if(!hasPermission(context,"risks.manage")&&!hasPermission(context,"projects.manage")&&!hasPermission(context,"operations.manage"))return error("Project risk and issue management permission is required.",403);
      const body=await request.json<{title?:string;description?:string;category?:string;probability?:number;impact?:number;severity?:string;ownerId?:string;mitigation?:string;contingency?:string;resolutionPlan?:string;dueDate?:string;targetDate?:string}>();if(!body.title?.trim()||body.title.length>180)return error("Provide a concise title.");const id=`${kind.slice(0,-1)}-${requestId()}`;
      if(kind==="risks"){
        const probability=Number(body.probability??3),impact=Number(body.impact??3);if(!Number.isInteger(probability)||probability<1||probability>5||!Number.isInteger(impact)||impact<1||impact>5||body.dueDate&&!isoDate(body.dueDate))return error("Risk likelihood, impact or due date is invalid.");
        if(body.ownerId&&!await env.DB.prepare(`SELECT 1 FROM memberships WHERE organization_id=? AND user_id=? AND status='active'`).bind(context.organizationId,body.ownerId).first())return error("Risk owner must be an active organization member.");
        await env.DB.prepare(`INSERT INTO project_risks (id,organization_id,project_id,title,description,category,probability,impact,owner_id,mitigation,contingency,due_date,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,context.organizationId,projectId,body.title.trim(),body.description||null,body.category||"general",probability,impact,body.ownerId||context.userId,body.mitigation||null,body.contingency||null,body.dueDate||null,context.userId).run();
      }else{
        const severity=body.severity||"medium";if(!['low','medium','high','critical'].includes(severity)||body.targetDate&&!isoDate(body.targetDate))return error("Issue severity or target date is invalid.");
        if(body.ownerId&&!await env.DB.prepare(`SELECT 1 FROM memberships WHERE organization_id=? AND user_id=? AND status='active'`).bind(context.organizationId,body.ownerId).first())return error("Issue owner must be an active organization member.");
        await env.DB.prepare(`INSERT INTO project_issues (id,organization_id,project_id,title,description,severity,owner_id,resolution_plan,target_date,created_by) VALUES (?,?,?,?,?,?,?,?,?,?)`).bind(id,context.organizationId,projectId,body.title.trim(),body.description||null,severity,body.ownerId||context.userId,body.resolutionPlan||null,body.targetDate||null,context.userId).run();
      }
      await audit(env,context,"created",table,id,body);return json({id},{status:201});
    }
  }

  if(path==="/api/projects/subscription"){
    if(request.method==="GET"){
      const [module,subscription]=await Promise.all([
        env.DB.prepare(`SELECT enabled,features_json as featuresJson,updated_at as updatedAt FROM organization_modules WHERE organization_id=? AND module_key='projects'`).bind(context.organizationId).first(),
        env.DB.prepare(`SELECT plan_code as planCode,status,billing_contact as billingContact,starts_at as startsAt,ends_at as endsAt,notes,created_at as requestedAt FROM module_subscriptions WHERE organization_id=? AND module_key='projects'`).bind(context.organizationId).first(),
      ]);return json({module:module||{enabled:0,featuresJson:"{}"},subscription:subscription||null});
    }
    if(request.method==="POST"){
      if(!hasPermission(context,"projects.billing.manage"))return error("Organization administrator permission is required to request a Projects subscription.",403);
      const body=await request.json<{billingContact?:string;planCode?:string;notes?:string}>();if(body.billingContact&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.billingContact)||body.notes&&body.notes.length>1000)return error("Enter a valid billing email and a short request note.");
      const existing=await env.DB.prepare(`SELECT status FROM module_subscriptions WHERE organization_id=? AND module_key='projects'`).bind(context.organizationId).first<{status:string}>();if(existing?.status==="active")return error("Projects is already active for this organization.",409);
      const id=`module-sub-${requestId()}`;await env.DB.prepare(`INSERT INTO module_subscriptions(id,organization_id,module_key,plan_code,status,billing_contact,requested_by,notes) VALUES(?,?,'projects',?,'pending',?,?,?) ON CONFLICT(organization_id,module_key) DO UPDATE SET plan_code=excluded.plan_code,status='pending',billing_contact=excluded.billing_contact,requested_by=excluded.requested_by,notes=excluded.notes,updated_at=CURRENT_TIMESTAMP`).bind(id,context.organizationId,body.planCode?.trim()||"manual",body.billingContact?.trim().toLowerCase()||context.email,context.userId,body.notes?.trim()||null).run();await audit(env,context,"requested","module_subscriptions",id,{module:"projects",plan:body.planCode||"manual",billingContact:body.billingContact||context.email});return json({status:"pending",message:"Your request is recorded. The Zyntris Business Development team must confirm commercial terms and activate the module."},{status:201});
    }
  }

  const projectPortfolioPath=path==="/api/projects/portfolios";
  if(projectPortfolioPath){
    const entitlement=await env.DB.prepare(`SELECT enabled,features_json as featuresJson FROM organization_modules WHERE organization_id=? AND module_key='projects'`).bind(context.organizationId).first<{enabled:number;featuresJson:string}>();if(!entitlement||entitlement.enabled!==1)return error("The Projects module is not active for this organization.",403);let portfolioFeatures:Record<string,boolean>={};try{portfolioFeatures=JSON.parse(entitlement.featuresJson||"{}");}catch{}if(portfolioFeatures.portfolios===false)return error("Portfolios are not included in this organization's Projects subscription.",403);
    if(request.method==="GET"){
      const rows=await env.DB.prepare(`SELECT f.id,f.name,f.description,f.status,f.owner_id as ownerId,u.full_name as owner,COUNT(p.id) as projectCount,COALESCE(SUM(p.budget_minor),0) as budgetMinor,COALESCE(AVG(p.progress),0) as progress FROM project_portfolios f LEFT JOIN users u ON u.id=f.owner_id LEFT JOIN projects p ON p.portfolio_id=f.id AND p.organization_id=f.organization_id WHERE f.organization_id=? GROUP BY f.id ORDER BY f.name`).bind(context.organizationId).all();
      return json({data:rows.results||[]});
    }
    if(request.method==="POST"){
      if(!hasPermission(context,"projects.manage"))return error("Project management permission is required.",403);
      const body=await request.json<{name?:string;description?:string;ownerId?:string}>();if(!body.name?.trim()||body.name.trim().length>120)return error("Enter a portfolio name (maximum 120 characters).");
      if(body.ownerId&&!await env.DB.prepare(`SELECT 1 FROM memberships WHERE organization_id=? AND user_id=? AND status='active'`).bind(context.organizationId,body.ownerId).first())return error("Portfolio owner must be an active organization member.");
      const id=`portfolio-${requestId()}`;await env.DB.prepare(`INSERT INTO project_portfolios(id,organization_id,name,description,owner_id,created_by) VALUES(?,?,?,?,?,?)`).bind(id,context.organizationId,body.name.trim(),body.description?.trim()||null,body.ownerId||context.userId,context.userId).run();await audit(env,context,"created","project_portfolios",id,body);return json({id},{status:201});
    }
  }

  const projectFeaturePath=path.match(/^\/api\/projects\/([^/]+)\/(timeline|phases|dependencies|timesheets|budget|changes|meetings|decisions|templates|client-portal|reports)(?:\/([^/]+))?$/);
  if(projectFeaturePath){
    const [,projectId,feature,subId]=projectFeaturePath;
    const featureKey:Record<string,string>={timeline:"gantt",phases:"gantt",dependencies:"gantt",timesheets:"timesheets",budget:"budgets",changes:"change_control",meetings:"meetings",decisions:"meetings",templates:"templates","client-portal":"client_portal",reports:"advanced_reports"};
    const entitlement=await env.DB.prepare(`SELECT enabled,features_json as featuresJson FROM organization_modules WHERE organization_id=? AND module_key='projects'`).bind(context.organizationId).first<{enabled:number;featuresJson:string}>();
    if(!entitlement||entitlement.enabled!==1)return error("The Projects module is not active for this organization.",403);
    if(featureKey[feature]){let features:Record<string,boolean>={};try{features=JSON.parse(entitlement.featuresJson||"{}");}catch{}if(features[featureKey[feature]]===false)return error(`The ${featureKey[feature].replaceAll("_"," ")} feature is not enabled for this organization's Projects subscription.`,403);}
    const canManageProject=hasPermission(context,"projects.manage")||hasPermission(context,"operations.manage");
    const canSeeProjects=hasPermission(context,"projects.view.all")||canManageProject;
    const employee=await env.DB.prepare(`SELECT id FROM employees WHERE organization_id=? AND user_id=? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId,context.userId).first<{id:string}>();
    const project=await env.DB.prepare(`SELECT p.id,p.project_code as projectCode,p.name,p.status,p.budget_minor as budgetMinor,p.currency,p.project_manager_id as projectManagerId FROM projects p WHERE p.id=? AND p.organization_id=? AND (?=1 OR p.owner_id=? OR p.project_manager_id=? OR EXISTS(SELECT 1 FROM project_members pm WHERE pm.project_id=p.id AND pm.organization_id=p.organization_id AND pm.employee_id=?))`).bind(projectId,context.organizationId,canSeeProjects?1:0,context.userId,context.userId,employee?.id||"").first<{id:string;projectCode:string;name:string;status:string;budgetMinor:number|null;currency:string;projectManagerId:string|null}>();
    if(!project)return error("Project not found or access is not enabled.",404);
    if(feature==="timeline"){
      if(request.method!=="GET")return error("Timeline is read-only here. Edit task or phase dates in their respective views.",405);
      const [phases,tasks,milestones]=await Promise.all([
        env.DB.prepare(`SELECT id,name,description,start_date as startDate,end_date as endDate,status,sort_order as sortOrder FROM project_phases WHERE organization_id=? AND project_id=? ORDER BY sort_order,start_date`).bind(context.organizationId,projectId).all(),
        env.DB.prepare(`SELECT t.id,t.title,t.start_date as startDate,t.due_date as endDate,t.progress,t.status,t.blocked_flag as blocked,t.phase_id as phaseId,e.first_name||' '||e.last_name as assignee FROM tasks t LEFT JOIN employees e ON e.id=t.assignee_id AND e.organization_id=t.organization_id WHERE t.organization_id=? AND t.project_id=? ORDER BY t.start_date,t.due_date`).bind(context.organizationId,projectId).all(),
        env.DB.prepare(`SELECT id,name,target_date as targetDate,status FROM project_milestones WHERE organization_id=? AND project_id=? ORDER BY target_date`).bind(context.organizationId,projectId).all(),
      ]);return json({project,phases:phases.results||[],tasks:tasks.results||[],milestones:milestones.results||[]});
    }
    if(feature==="phases"){
      if(request.method==="GET"){const rows=await env.DB.prepare(`SELECT id,name,description,start_date as startDate,end_date as endDate,status,sort_order as sortOrder FROM project_phases WHERE organization_id=? AND project_id=? ORDER BY sort_order`).bind(context.organizationId,projectId).all();return json({data:rows.results||[]});}
      if(request.method==="PATCH"&&subId){if(!canManageProject)return error("Project management permission is required to edit phases.",403);const body=await request.json<{name?:string;description?:string;startDate?:string|null;endDate?:string|null;status?:string;sortOrder?:number}>();if(body.name!==undefined&&(!body.name.trim()||body.name.length>120)||body.startDate&& !isoDate(body.startDate)||body.endDate&&!isoDate(body.endDate)||body.startDate&&body.endDate&&body.startDate>body.endDate||body.status&&!['planned','active','completed','cancelled'].includes(body.status))return error("Phase details are invalid.");const changed=await env.DB.prepare(`UPDATE project_phases SET name=COALESCE(?,name),description=CASE WHEN ?=1 THEN ? ELSE description END,start_date=CASE WHEN ?=1 THEN ? ELSE start_date END,end_date=CASE WHEN ?=1 THEN ? ELSE end_date END,status=COALESCE(?,status),sort_order=COALESCE(?,sort_order),updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=? AND project_id=?`).bind(body.name?.trim()||null,body.description===undefined?0:1,body.description||null,body.startDate===undefined?0:1,body.startDate||null,body.endDate===undefined?0:1,body.endDate||null,body.status||null,body.sortOrder??null,subId,context.organizationId,projectId).run();if(!changed.meta.changes)return error("Project phase not found.",404);await audit(env,context,"updated","project_phases",subId,body);return json({ok:true});}
      if(request.method==="POST"){
        if(!canManageProject)return error("Project management permission is required to add phases.",403);
        const body=await request.json<{name?:string;description?:string;startDate?:string;endDate?:string}>();if(!body.name?.trim()||body.name.length>120||body.startDate&&!isoDate(body.startDate)||body.endDate&&!isoDate(body.endDate)||body.startDate&&body.endDate&&body.startDate>body.endDate)return error("Enter a phase name and valid date range.");
        const id=`phase-${requestId()}`;await env.DB.prepare(`INSERT INTO project_phases(id,organization_id,project_id,name,description,start_date,end_date,sort_order,created_by) VALUES(?,?,?,?,?,?,?,(SELECT COALESCE(MAX(sort_order),0)+1 FROM project_phases WHERE organization_id=? AND project_id=?),?)`).bind(id,context.organizationId,projectId,body.name.trim(),body.description?.trim()||null,body.startDate||null,body.endDate||null,context.organizationId,projectId,context.userId).run();await audit(env,context,"created","project_phases",id,body);return json({id},{status:201});
      }
    }
    if(feature==="dependencies"){
      if(request.method==="GET"){const rows=await env.DB.prepare(`SELECT d.id,d.task_id as taskId,d.depends_on_task_id as dependsOnTaskId,d.dependency_type as dependencyType,a.title as taskTitle,b.title as dependsOnTitle FROM task_dependencies d JOIN tasks a ON a.id=d.task_id AND a.organization_id=d.organization_id JOIN tasks b ON b.id=d.depends_on_task_id AND b.organization_id=d.organization_id WHERE d.organization_id=? AND a.project_id=?`).bind(context.organizationId,projectId).all();return json({data:rows.results||[]});}
      if(request.method==="POST"){
        if(!canManageProject)return error("Project management permission is required to change dependencies.",403);
        const body=await request.json<{taskId?:string;dependsOnTaskId?:string;dependencyType?:string}>();const type=body.dependencyType||"finish_to_start";
        if(!body.taskId||!body.dependsOnTaskId||body.taskId===body.dependsOnTaskId||!['finish_to_start','start_to_start','finish_to_finish','start_to_finish'].includes(type))return error("Choose two different tasks and a valid dependency type.");
        const tasks=await env.DB.prepare(`SELECT COUNT(*) as total FROM tasks WHERE organization_id=? AND project_id=? AND id IN (?,?)`).bind(context.organizationId,projectId,body.taskId,body.dependsOnTaskId).first<{total:number}>();if(tasks?.total!==2)return error("Both tasks must belong to this project.",404);
        const cycle=await env.DB.prepare(`WITH RECURSIVE reachable(id) AS (SELECT ? UNION SELECT d.depends_on_task_id FROM task_dependencies d JOIN reachable r ON d.task_id=r.id JOIN tasks task ON task.id=d.task_id AND task.organization_id=d.organization_id WHERE d.organization_id=? AND task.project_id=?) SELECT 1 FROM reachable WHERE id=? LIMIT 1`).bind(body.dependsOnTaskId,context.organizationId,projectId,body.taskId).first();if(cycle)return error("This dependency would create a circular task chain.",409);
        const id=`dependency-${requestId()}`;await env.DB.prepare(`INSERT INTO task_dependencies(id,organization_id,task_id,depends_on_task_id,dependency_type) VALUES(?,?,?,?,?)`).bind(id,context.organizationId,body.taskId,body.dependsOnTaskId,type).run();await audit(env,context,"created","task_dependencies",id,body);return json({id},{status:201});
      }
    }
    if(feature==="timesheets"){
      if(request.method==="GET"){
        const all=canManageProject||hasPermission(context,"timesheets.approve");const rows=await env.DB.prepare(`SELECT t.id,t.employee_id as employeeId,e.first_name||' '||e.last_name as employee,t.task_id as taskId,k.title as taskTitle,t.work_date as workDate,t.hours,t.billable,t.description,t.status,t.reviewed_at as reviewedAt,u.full_name as reviewer FROM project_timesheets t JOIN employees e ON e.id=t.employee_id AND e.organization_id=t.organization_id LEFT JOIN tasks k ON k.id=t.task_id AND k.organization_id=t.organization_id LEFT JOIN users u ON u.id=t.reviewed_by WHERE t.organization_id=? AND t.project_id=? AND (?=1 OR e.user_id=?) ORDER BY t.work_date DESC LIMIT 300`).bind(context.organizationId,projectId,all?1:0,context.userId).all();return json({data:rows.results||[]});
      }
      if(request.method==="POST"){
        const body=await request.json<{taskId?:string;workDate?:string;hours?:number;billable?:boolean;description?:string}>();if(!employee)return error("A linked employee profile is required to log time.",403);
        const hours=Number(body.hours);if(!body.workDate||!isoDate(body.workDate)||!Number.isFinite(hours)||hours<=0||hours>24||!body.description?.trim()||body.description.length>1000)return error("Enter a valid work date, hours and description.");
        if(body.taskId&&!await env.DB.prepare(`SELECT 1 FROM tasks WHERE id=? AND project_id=? AND organization_id=?`).bind(body.taskId,projectId,context.organizationId).first())return error("Task must belong to this project.",404);
        const id=`timesheet-${requestId()}`;await env.DB.prepare(`INSERT INTO project_timesheets(id,organization_id,project_id,task_id,employee_id,work_date,hours,billable,description,status) VALUES(?,?,?,?,?,?,?,?,?,'submitted')`).bind(id,context.organizationId,projectId,body.taskId||null,employee.id,body.workDate,hours,body.billable?1:0,body.description.trim()).run();await audit(env,context,"submitted","project_timesheets",id,{...body,hours});return json({id,status:"submitted"},{status:201});
      }
      if(request.method==="PATCH"&&subId){if(!hasPermission(context,"timesheets.approve")&&!canManageProject)return error("Timesheet review permission is required.",403);const body=await request.json<{status?:string}>();if(!["approved","rejected"].includes(body.status||""))return error("Choose approved or rejected.");const changed=await env.DB.prepare(`UPDATE project_timesheets SET status=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=? AND project_id=? AND status='submitted'`).bind(body.status,context.userId,subId,context.organizationId,projectId).run();if(!changed.meta.changes)return error("Submitted timesheet not found or already reviewed.",404);await audit(env,context,`timesheet_${body.status}`,"project_timesheets",subId,{status:body.status});return json({ok:true,status:body.status});}
    }
    if(feature==="budget"){
      if(request.method==="GET"){const rows=await env.DB.prepare(`SELECT id,category,description,allocated,committed,actual FROM project_budget_lines WHERE organization_id=? AND project_id=? ORDER BY category`).bind(context.organizationId,projectId).all();const totals=await env.DB.prepare(`SELECT COALESCE(SUM(allocated),0) allocated,COALESCE(SUM(committed),0) committed,COALESCE(SUM(actual),0) actual FROM project_budget_lines WHERE organization_id=? AND project_id=?`).bind(context.organizationId,projectId).first();return json({budgetMinor:project.budgetMinor, currency:project.currency, lines:rows.results||[], totals});}
      if(request.method==="POST"){
        if(!canManageProject)return error("Project management permission is required to edit budgets.",403);
        const body=await request.json<{category?:string;description?:string;allocatedMinor?:number}>();if(!body.category?.trim()||body.category.length>100||!Number.isSafeInteger(body.allocatedMinor)||Number(body.allocatedMinor)<0)return error("Provide a category and non-negative amount in minor currency units.");
        const id=`budget-line-${requestId()}`;await env.DB.prepare(`INSERT INTO project_budget_lines(id,organization_id,project_id,category,description,allocated,committed,actual) VALUES(?,?,?,?,?,?,0,0)`).bind(id,context.organizationId,projectId,body.category.trim(),body.description?.trim()||null,Number(body.allocatedMinor)).run();await audit(env,context,"created","project_budget_lines",id,body);return json({id},{status:201});
      }
    }
    if(feature==="changes"){
      if(request.method==="GET"){const rows=await env.DB.prepare(`SELECT c.id,c.title,c.description,c.reason,c.scope_impact as scopeImpact,c.schedule_impact_days as scheduleImpactDays,c.budget_impact_minor as budgetImpactMinor,c.resource_impact as resourceImpact,c.risk_impact as riskImpact,c.status,c.requested_by as requestedBy,u.full_name as requester,c.approval_request_id as approvalRequestId,c.created_at as createdAt FROM project_change_requests c JOIN users u ON u.id=c.requested_by WHERE c.organization_id=? AND c.project_id=? ORDER BY c.created_at DESC`).bind(context.organizationId,projectId).all();return json({data:rows.results||[]});}
      if(request.method==="POST"){
        const body=await request.json<{title?:string;description?:string;reason?:string;scopeImpact?:string;scheduleImpactDays?:number;budgetImpactMinor?:number;resourceImpact?:string;riskImpact?:string;submit?:boolean}>();if(!body.title?.trim()||!body.description?.trim()||!body.reason?.trim()||!Number.isInteger(body.scheduleImpactDays||0)||Math.abs(Number(body.scheduleImpactDays||0))>3650||!Number.isSafeInteger(body.budgetImpactMinor||0))return error("Provide a title, impact description, reason, and valid impact estimates.");
        const id=`change-${requestId()}`,approvalId=body.submit?`approval-${requestId()}`:null;const requiredRole="CEO";
        const statements=[env.DB.prepare(`INSERT INTO project_change_requests(id,organization_id,project_id,approval_request_id,title,description,reason,scope_impact,schedule_impact_days,budget_impact_minor,resource_impact,risk_impact,status,requested_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,context.organizationId,projectId,approvalId,body.title.trim(),body.description.trim(),body.reason.trim(),body.scopeImpact||null,Number(body.scheduleImpactDays||0),Number(body.budgetImpactMinor||0),body.resourceImpact||null,body.riskImpact||null,body.submit?"submitted":"draft",context.userId)];
        if(body.submit)statements.push(env.DB.prepare(`INSERT INTO approval_requests(id,organization_id,request_type,source_record_id,title,requester_id,amount,currency,required_role,status,current_step,metadata_json,due_at) VALUES(?,?,'Project change',?,?,?,NULL,?,'CEO','pending',1,?,datetime('now','+72 hours'))`).bind(approvalId,context.organizationId,id,body.title.trim(),context.userId,project.currency,JSON.stringify({projectId,changeRequestId:id,approvalPolicy:["CEO","HR Admin"]})));
        await env.DB.batch(statements);await audit(env,context,body.submit?"submitted":"created","project_change_requests",id,body);if(body.submit)await notifyApprovers(env,context,requiredRole,body.title.trim(),`A project change request for ${project.name} is awaiting approval.`);return json({id,approvalRequestId:approvalId,status:body.submit?"submitted":"draft"},{status:201});
      }
    }
    if(feature==="meetings"){
      if(request.method==="GET"){const rows=await env.DB.prepare(`SELECT m.id,m.title,m.starts_at as startsAt,m.ends_at as endsAt,m.location,m.agenda,m.minutes,m.decisions,m.created_by as createdBy,u.full_name as organizer FROM project_meetings m LEFT JOIN users u ON u.id=m.created_by WHERE m.organization_id=? AND m.project_id=? ORDER BY m.starts_at DESC LIMIT 200`).bind(context.organizationId,projectId).all();return json({data:rows.results||[]});}
      if(request.method==="POST"){
        if(!canManageProject)return error("Project management permission is required to schedule project meetings.",403);
        const body=await request.json<{title?:string;startsAt?:string;endsAt?:string;location?:string;agenda?:string;attendeeIds?:string[]}>();const start=Date.parse(body.startsAt||""),end=Date.parse(body.endsAt||"");if(!body.title?.trim()||body.title.length>160||!Number.isFinite(start)||!Number.isFinite(end)||end<=start)return error("Provide a meeting title and valid start/end times.");
        const attendees=[...new Set((body.attendeeIds||[]).slice(0,100))];for(const userId of attendees){if(!await env.DB.prepare(`SELECT 1 FROM memberships WHERE organization_id=? AND user_id=? AND status='active'`).bind(context.organizationId,userId).first())return error("Every attendee must be an active organization member.");}
        const id=`meeting-${requestId()}`;const statements=[env.DB.prepare(`INSERT INTO project_meetings(id,organization_id,project_id,title,starts_at,ends_at,location,agenda,created_by) VALUES(?,?,?,?,?,?,?,?,?)`).bind(id,context.organizationId,projectId,body.title.trim(),new Date(start).toISOString(),new Date(end).toISOString(),body.location?.trim()||null,body.agenda?.trim()||null,context.userId),...attendees.map(userId=>env.DB.prepare(`INSERT INTO project_meeting_attendees(meeting_id,organization_id,user_id) VALUES(?,?,?)`).bind(id,context.organizationId,userId))];await env.DB.batch(statements);await audit(env,context,"created","project_meetings",id,{...body,attendeeIds:attendees});return json({id},{status:201});
      }
    }
    if(feature==="decisions"){
      if(request.method==="GET"){const rows=await env.DB.prepare(`SELECT d.id,d.decision,d.context,d.reason,d.impact,d.decision_maker_id as decisionMakerId,u.full_name as decisionMaker,d.decided_at as decidedAt FROM project_decisions d JOIN users u ON u.id=d.decision_maker_id WHERE d.organization_id=? AND d.project_id=? ORDER BY d.decided_at DESC`).bind(context.organizationId,projectId).all();return json({data:rows.results||[]});}
      if(request.method==="POST"){if(!canManageProject)return error("Project management permission is required to record a decision.",403);const body=await request.json<{decision?:string;context?:string;reason?:string;impact?:string}>();if(!body.decision?.trim()||body.decision.length>2000)return error("Enter the decision (maximum 2,000 characters).");const id=`decision-${requestId()}`;await env.DB.prepare(`INSERT INTO project_decisions(id,organization_id,project_id,decision,context,reason,impact,decision_maker_id) VALUES(?,?,?,?,?,?,?,?)`).bind(id,context.organizationId,projectId,body.decision.trim(),body.context?.trim()||null,body.reason?.trim()||null,body.impact?.trim()||null,context.userId).run();await audit(env,context,"created","project_decisions",id,body);return json({id},{status:201});}
    }
    if(feature==="templates"){
      if(request.method==="GET"){const rows=await env.DB.prepare(`SELECT id,name,description,methodology,template_json as templateJson,created_at as createdAt FROM project_templates WHERE organization_id=? AND active=1 ORDER BY name`).bind(context.organizationId).all();return json({data:rows.results||[]});}
      if(request.method==="POST"){if(!canManageProject)return error("Project management permission is required to manage templates.",403);const body=await request.json<{name?:string;description?:string;methodology?:string;template?:Record<string,unknown>;applyTemplateId?:string}>();if(body.applyTemplateId){const template=await env.DB.prepare(`SELECT template_json as templateJson FROM project_templates WHERE id=? AND organization_id=? AND active=1`).bind(body.applyTemplateId,context.organizationId).first<{templateJson:string}>();if(!template)return error("Project template not found.",404);let model:Record<string,unknown>;try{model=JSON.parse(template.templateJson||"{}");}catch{return error("Stored project template is invalid.",500);}const phases=Array.isArray(model.phases)?model.phases.slice(0,50) as Record<string,unknown>[]:[],milestones=Array.isArray(model.milestones)?model.milestones.slice(0,100) as Record<string,unknown>[]:[];if(phases.some(x=>typeof x.name!=="string"||!x.name.trim())||milestones.some(x=>typeof x.name!=="string"||!x.name.trim()||typeof x.targetDate!=="string"||!isoDate(x.targetDate)))return error("Template contains invalid phase or milestone definitions.",422);const statements=[...phases.map(x=>env.DB.prepare(`INSERT INTO project_phases(id,organization_id,project_id,name,description,start_date,end_date,sort_order,created_by) VALUES(?,?,?,?,?,?,?,?,?)`).bind(`phase-${requestId()}`,context.organizationId,projectId,String(x.name).trim(),typeof x.description==="string"?x.description:null,typeof x.startDate==="string"&&isoDate(x.startDate)?x.startDate:null,typeof x.endDate==="string"&&isoDate(x.endDate)?x.endDate:null,Number.isInteger(x.sortOrder)?Number(x.sortOrder):0,context.userId)),...milestones.map(x=>env.DB.prepare(`INSERT INTO project_milestones(id,organization_id,project_id,name,description,target_date,created_by) VALUES(?,?,?,?,?,?,?)`).bind(`milestone-${requestId()}`,context.organizationId,projectId,String(x.name).trim(),typeof x.description==="string"?x.description:null,String(x.targetDate),context.userId))];if(statements.length)await env.DB.batch(statements);await audit(env,context,"applied","project_templates",body.applyTemplateId,{projectId,phases:phases.length,milestones:milestones.length});return json({applied:true,phases:phases.length,milestones:milestones.length},{status:201});}if(!body.name?.trim()||body.name.length>120)return error("Enter a template name.");const template=body.template||{};if(JSON.stringify(template).length>20000)return error("Template exceeds the 20 KB limit.");const id=`template-${requestId()}`;await env.DB.prepare(`INSERT INTO project_templates(id,organization_id,name,description,methodology,template_json,created_by) VALUES(?,?,?,?,?,?,?)`).bind(id,context.organizationId,body.name.trim(),body.description?.trim()||null,body.methodology||null,JSON.stringify(template),context.userId).run();await audit(env,context,"created","project_templates",id,{name:body.name});return json({id},{status:201});}
    }
    if(feature==="client-portal"){
      if(request.method==="GET"){if(!hasPermission(context,"projects.client_portal.manage"))return error("Client portal management permission is required.",403);const rows=await env.DB.prepare(`SELECT id,label,expires_at as expiresAt,created_at as createdAt,revoked_at as revokedAt FROM project_client_portal_tokens WHERE organization_id=? AND project_id=? ORDER BY created_at DESC`).bind(context.organizationId,projectId).all();return json({data:rows.results||[]});}
      if(request.method==="POST"){if(!hasPermission(context,"projects.client_portal.manage"))return error("Client portal management permission is required.",403);const body=await request.json<{label?:string;expiresAt?:string}>();if(!body.label?.trim()||body.label.length>100||!body.expiresAt||!isoDate(body.expiresAt)||new Date(`${body.expiresAt}T23:59:59Z`).getTime()<=Date.now())return error("Enter a label and a future expiry date.");const token=randomToken(32),id=`portal-${requestId()}`;await env.DB.prepare(`INSERT INTO project_client_portal_tokens(id,organization_id,project_id,token_hash,label,expires_at,created_by) VALUES(?,?,?,?,?,?,?)`).bind(id,context.organizationId,projectId,await hashToken(token),body.label.trim(),new Date(`${body.expiresAt}T23:59:59Z`).toISOString(),context.userId).run();await audit(env,context,"created","project_client_portal_tokens",id,{label:body.label,expiresAt:body.expiresAt,scope:"read-only public project status"});return json({id,url:`${new URL(request.url).origin}/project-portal/${token}`,token},{status:201});}
      if(request.method==="DELETE"&&subId){if(!hasPermission(context,"projects.client_portal.manage"))return error("Client portal management permission is required.",403);const changed=await env.DB.prepare(`UPDATE project_client_portal_tokens SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=? AND project_id=? AND revoked_at IS NULL`).bind(subId,context.organizationId,projectId).run();if(!changed.meta.changes)return error("Active portal link not found.",404);await audit(env,context,"revoked","project_client_portal_tokens",subId,{projectId});return json({ok:true});}
    }
    if(feature==="reports"&&request.method==="GET"){
      const [summary,tasks,milestones,budget,risks]=await Promise.all([
        env.DB.prepare(`SELECT p.id,p.project_code as projectCode,p.name,p.status,p.health,p.progress,p.start_date as startDate,p.end_date as endDate,p.budget_minor as budgetMinor,COUNT(t.id) taskCount,SUM(CASE WHEN t.status='completed' THEN 1 ELSE 0 END) completedTasks,SUM(CASE WHEN t.due_date<date('now') AND t.status!='completed' THEN 1 ELSE 0 END) overdueTasks FROM projects p LEFT JOIN tasks t ON t.organization_id=p.organization_id AND t.project_id=p.id WHERE p.organization_id=? AND p.id=? GROUP BY p.id`).bind(context.organizationId,projectId).first(),
        env.DB.prepare(`SELECT status,COUNT(*) total FROM tasks WHERE organization_id=? AND project_id=? GROUP BY status`).bind(context.organizationId,projectId).all(),
        env.DB.prepare(`SELECT status,COUNT(*) total FROM project_milestones WHERE organization_id=? AND project_id=? GROUP BY status`).bind(context.organizationId,projectId).all(),
        env.DB.prepare(`SELECT COALESCE(SUM(allocated),0) allocatedMinor,COALESCE(SUM(committed),0) committedMinor,COALESCE(SUM(actual),0) actualMinor FROM project_budget_lines WHERE organization_id=? AND project_id=?`).bind(context.organizationId,projectId).first(),
        env.DB.prepare(`SELECT COUNT(*) total,SUM(CASE WHEN probability*impact>=15 THEN 1 ELSE 0 END) critical FROM project_risks WHERE organization_id=? AND project_id=? AND status!='closed'`).bind(context.organizationId,projectId).first(),
      ]);return json({summary,tasks:tasks.results||[],milestones:milestones.results||[],budget,risks});
    }
    return error("Project feature endpoint not found.",404);
  }

  if (request.method === "GET" && path === "/api/tasks") {
    const employee = await env.DB.prepare(`SELECT id FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string }>();
    const canManageTasks = hasPermission(context, "operations.manage");
    const canSeeAllProjects=hasPermission(context,"projects.view.all")||hasPermission(context,"projects.manage");
    const result = await env.DB.prepare(`SELECT t.id,t.project_id as projectId,t.title,COALESCE(t.description,'') as description,t.priority,CASE WHEN t.blocked_flag=1 THEN 'blocked' ELSE t.status END as status,t.due_date as dueDate,t.assignee_id as assigneeId,e.first_name || ' ' || e.last_name as assignee,p.name as project,t.creator_id as creatorId,t.progress,t.blocked_flag as blocked FROM tasks t LEFT JOIN employees e ON e.id=t.assignee_id AND e.organization_id=t.organization_id LEFT JOIN projects p ON p.id=t.project_id AND p.organization_id=t.organization_id WHERE t.organization_id=? AND (?=1 OR (t.project_id IS NULL AND (t.assignee_id=? OR t.creator_id=?)) OR (t.project_id IS NOT NULL AND (?=1 OR p.owner_id=? OR p.project_manager_id=? OR EXISTS(SELECT 1 FROM project_members member WHERE member.organization_id=t.organization_id AND member.project_id=t.project_id AND member.employee_id=?)))) ORDER BY CASE t.priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,t.due_date LIMIT 300`).bind(context.organizationId,canManageTasks?1:0,employee?.id||"",context.userId,canSeeAllProjects?1:0,context.userId,context.userId,employee?.id||"").all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/tasks") {
    const body = await request.json<{ title?: string; description?: string; projectId?: string; assigneeId?: string; priority?: string; dueDate?: string; status?: string }>();
    if (!hasPermission(context, "operations.manage") && !(body.projectId && hasPermission(context,"projects.manage"))) return error("Operations task or project task creation permission is required.", 403);
    if (!body.title?.trim() || body.title.trim().length > 180 || (body.dueDate && !isoDate(body.dueDate))) return error("Enter a task title and valid due date.");
    const priority = body.priority || "medium";
    if (!['low','medium','high','urgent'].includes(priority)) return error("Choose a valid task priority.");
    if(body.status&&!['todo','in_progress','review','completed','blocked'].includes(body.status))return error("Choose a valid task status.");
    if (body.projectId && !await env.DB.prepare(`SELECT id FROM projects WHERE id=? AND organization_id=? AND status!='archived' AND (?=1 OR owner_id=? OR project_manager_id=? OR EXISTS(SELECT 1 FROM project_members pm JOIN employees e ON e.id=pm.employee_id AND e.organization_id=pm.organization_id WHERE pm.project_id=projects.id AND pm.organization_id=projects.organization_id AND e.user_id=?))`).bind(body.projectId,context.organizationId,(hasPermission(context,"projects.view.all")||hasPermission(context,"projects.manage")||hasPermission(context,"operations.manage"))?1:0,context.userId,context.userId,context.userId).first()) return error("Choose an accessible project in this organization.", 404);
    if (body.assigneeId && !await env.DB.prepare(`SELECT id FROM employees WHERE id = ? AND organization_id = ? AND status = 'active' AND deleted_at IS NULL`).bind(body.assigneeId, context.organizationId).first()) return error("Choose an active employee in this organization.", 404);
    const id = `task-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO tasks (id, organization_id, project_id, title, description, assignee_id, creator_id, priority, status, blocked_flag, due_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, body.projectId || null, body.title.trim(), body.description?.trim() || null, body.assigneeId || null, context.userId, priority, body.status === "blocked" ? "todo" : body.status || "todo", body.status === "blocked" ? 1 : 0, body.dueDate || null).run();
    await audit(env, context, "created", "tasks", id, { title: body.title.trim(), assigneeId: body.assigneeId || null, projectId: body.projectId || null });
    if (body.assigneeId) {
      const assignee = await env.DB.prepare(`SELECT user_id as userId FROM employees WHERE id = ? AND organization_id = ?`).bind(body.assigneeId, context.organizationId).first<{ userId: string | null }>();
      if (assignee?.userId) await env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'task_assigned', ?, ?)`).bind(requestId(), context.organizationId, assignee.userId, "Task assigned", `You were assigned “${body.title.trim()}”${body.dueDate ? `, due ${body.dueDate}` : ""}.`).run();
    }
    return json({ id }, { status: 201 });
  }

  const taskMatch = path.match(/^\/api\/tasks\/([^/]+)$/);
  if (taskMatch && request.method === "PATCH") {
    const body = await request.json<{ title?: string; description?: string; projectId?: string | null; assigneeId?: string | null; priority?: string; status?: string; dueDate?: string | null }>();
    const task = await env.DB.prepare(`SELECT t.id,t.project_id as projectId,t.assignee_id as assigneeId,t.creator_id as creatorId,e.user_id as assigneeUserId FROM tasks t LEFT JOIN employees e ON e.id=t.assignee_id AND e.organization_id=t.organization_id WHERE t.id=? AND t.organization_id=?`).bind(taskMatch[1],context.organizationId).first<{id:string;projectId:string|null;assigneeId:string|null;creatorId:string|null;assigneeUserId:string|null}>();
    if (!task) return error("Task not found.", 404);
    const canManageTasks = hasPermission(context, "operations.manage") || (Boolean(task.projectId)&&hasPermission(context,"projects.manage"));
    const isAssignee = task.assigneeUserId === context.userId;
    if (!canManageTasks && !isAssignee) return error("Only the task assignee or an operations manager can update this task.", 403);
    if (!canManageTasks && (body.title !== undefined || body.description !== undefined || body.assigneeId !== undefined || body.projectId !== undefined || body.priority !== undefined || body.dueDate !== undefined)) return error("Only an operations manager can change task details.", 403);
    if (body.status !== undefined && !['todo','in_progress','review','completed','blocked'].includes(body.status)) return error("Choose a valid task status.");
    if (body.priority !== undefined && !['low','medium','high','urgent'].includes(body.priority)) return error("Choose a valid task priority.");
    if (body.dueDate && !isoDate(body.dueDate)) return error("Enter a valid due date.");
    if (body.projectId && !await env.DB.prepare(`SELECT id FROM projects WHERE id = ? AND organization_id = ?`).bind(body.projectId, context.organizationId).first()) return error("Project not found.", 404);
    if (body.assigneeId && !await env.DB.prepare(`SELECT id FROM employees WHERE id = ? AND organization_id = ? AND status = 'active' AND deleted_at IS NULL`).bind(body.assigneeId, context.organizationId).first()) return error("Assignee not found.", 404);
    const changed = await env.DB.prepare(`UPDATE tasks SET title = COALESCE(?, title), description = COALESCE(?, description), project_id = CASE WHEN ? = 1 THEN ? ELSE project_id END, assignee_id = CASE WHEN ? = 1 THEN ? ELSE assignee_id END, priority = COALESCE(?, priority), status = CASE WHEN ?='blocked' THEN 'todo' ELSE COALESCE(?,status) END, blocked_flag = CASE WHEN ? IS NULL THEN blocked_flag WHEN ?='blocked' THEN 1 ELSE 0 END, due_date = CASE WHEN ? = 1 THEN ? ELSE due_date END, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(body.title?.trim() || null, body.description === undefined ? null : body.description.trim(), body.projectId !== undefined ? 1 : 0, body.projectId || null, body.assigneeId !== undefined ? 1 : 0, body.assigneeId || null, body.priority || null, body.status || null, body.status || null, body.status ?? null, body.status || null, body.dueDate !== undefined ? 1 : 0, body.dueDate || null, task.id, context.organizationId).run();
    if (!changed.meta.changes) return error("No task changes were saved.", 409);
    await audit(env, context, body.status ? `status_${body.status}` : "updated", "tasks", task.id, body);
    if (body.assigneeId && body.assigneeId !== task.assigneeId) {
      const assignee = await env.DB.prepare(`SELECT user_id as userId FROM employees WHERE id = ? AND organization_id = ?`).bind(body.assigneeId, context.organizationId).first<{ userId: string | null }>();
      if (assignee?.userId) await env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'task_assigned', ?, ?)`).bind(requestId(), context.organizationId, assignee.userId, "Task assigned", `You were assigned “${body.title?.trim() || "a task"}”.`).run();
    }
    return json({ ok: true });
  }

  if (path === "/api/calendar/feed" && request.method === "GET") {
    const active = await env.DB.prepare(`SELECT id, created_at as createdAt, expires_at as expiresAt FROM calendar_feed_tokens WHERE organization_id = ? AND revoked_at IS NULL AND datetime(expires_at) > CURRENT_TIMESTAMP ORDER BY created_at DESC LIMIT 1`).bind(context.organizationId).first<{ id: string; createdAt: string; expiresAt: string }>();
    return json({ enabled: Boolean(active), createdAt: active?.createdAt || null, expiresAt: active?.expiresAt || null });
  }

  if (path === "/api/calendar/feed" && request.method === "POST") {
    if (!hasPermission(context, "operations.manage")) return error("Operations manager permission is required to manage calendar subscriptions.", 403);
    const token = randomToken(32); const id = `calendar-feed-${crypto.randomUUID()}`;
    const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();
    await env.DB.batch([
      env.DB.prepare(`UPDATE calendar_feed_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE organization_id = ? AND revoked_at IS NULL`).bind(context.organizationId),
      env.DB.prepare(`INSERT INTO calendar_feed_tokens (id, organization_id, token_hash, created_by, expires_at) VALUES (?, ?, ?, ?, ?)`).bind(id, context.organizationId, await hashToken(token), context.userId, expiresAt),
    ]);
    await audit(env, context, "created", "calendar_feed", id, { access: "read-only subscription", expiresAt });
    return json({ enabled: true, expiresAt, url: `${new URL(request.url).origin}/calendar/feed/${token}.ics` }, { status: 201 });
  }

  if (path === "/api/calendar/feed" && request.method === "DELETE") {
    if (!hasPermission(context, "operations.manage")) return error("Operations manager permission is required to manage calendar subscriptions.", 403);
    await env.DB.prepare(`UPDATE calendar_feed_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE organization_id = ? AND revoked_at IS NULL`).bind(context.organizationId).run();
    await audit(env, context, "revoked", "calendar_feed", context.organizationId, {});
    return json({ enabled: false });
  }

  if (request.method === "GET" && path === "/api/calendar") {
    const result = await env.DB.prepare(`SELECT id, title, event_type as eventType, start_at as startAt, end_at as endAt, location, owner_id as ownerId FROM calendar_events WHERE organization_id = ? ORDER BY start_at LIMIT 300`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/calendar") {
    if (!hasPermission(context, "operations.manage")) return error("Operations manager permission is required to add calendar events.", 403);
    const body = await request.json<{ title?: string; eventType?: string; startAt?: string; endAt?: string; location?: string }>();
    const start = body.startAt ? new Date(body.startAt) : null; const end = body.endAt ? new Date(body.endAt) : null;
    if (!body.title?.trim() || body.title.trim().length > 160 || !start || Number.isNaN(start.getTime()) || !end || Number.isNaN(end.getTime()) || end <= start) return error("Enter a title and valid start/end times; the end must be after the start.");
    const eventType = body.eventType || "Meeting";
    if (!['Meeting','Deadline','Training','Company','Leave','Other'].includes(eventType)) return error("Choose a valid calendar event type.");
    const id = `event-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO calendar_events (id, organization_id, title, event_type, start_at, end_at, location, owner_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, body.title.trim(), eventType, start.toISOString(), end.toISOString(), body.location?.trim() || null, context.userId).run();
    await pushCalendarEvent(env, context.organizationId, id);
    await audit(env, context, "created", "calendar_events", id, { title: body.title.trim(), eventType, startAt: start.toISOString(), endAt: end.toISOString() });
    return json({ id }, { status: 201 });
  }

  const calendarMatch = path.match(/^\/api\/calendar\/([^/]+)$/);
  if (calendarMatch && request.method === "PATCH") {
    if (!hasPermission(context, "operations.manage")) return error("Operations manager permission is required to update calendar events.", 403);
    const body = await request.json<{ title?: string; eventType?: string; startAt?: string; endAt?: string; location?: string }>();
    const current = await env.DB.prepare(`SELECT id, start_at as startAt, end_at as endAt FROM calendar_events WHERE id = ? AND organization_id = ?`).bind(calendarMatch[1], context.organizationId).first<{ id: string; startAt: string; endAt: string }>();
    if (!current) return error("Calendar event not found.", 404);
    if (body.startAt && Number.isNaN(new Date(body.startAt).getTime()) || body.endAt && Number.isNaN(new Date(body.endAt).getTime())) return error("Enter valid event dates and times.");
    const startAt = body.startAt ? new Date(body.startAt).toISOString() : current.startAt; const endAt = body.endAt ? new Date(body.endAt).toISOString() : current.endAt;
    if (new Date(endAt) <= new Date(startAt)) return error("The event end must be after its start.");
    if (body.eventType && !['Meeting','Deadline','Training','Company','Leave','Other'].includes(body.eventType)) return error("Choose a valid calendar event type.");
    await env.DB.prepare(`UPDATE calendar_events SET title = COALESCE(?, title), event_type = COALESCE(?, event_type), start_at = ?, end_at = ?, location = COALESCE(?, location) WHERE id = ? AND organization_id = ?`).bind(body.title?.trim() || null, body.eventType || null, startAt, endAt, body.location?.trim() || null, current.id, context.organizationId).run();
    await pushCalendarEvent(env, context.organizationId, current.id);
    await audit(env, context, "updated", "calendar_events", current.id, body);
    return json({ ok: true });
  }

  if (request.method === "GET" && path === "/api/expense-policy") {
    if (!hasPermission(context, "expenses.view")) return error("You do not have permission to view expense policy.", 403);
    const policy = await env.DB.prepare(`SELECT expense_max_amount as maxAmount, expense_receipt_required as receiptRequired FROM organization_settings WHERE organization_id = ?`).bind(context.organizationId).first<{ maxAmount: number | null; receiptRequired: number }>();
    return json({ maxAmount: policy?.maxAmount ?? null, receiptRequired: Boolean(policy?.receiptRequired) });
  }

  if (request.method === "PATCH" && path === "/api/expense-policy") {
    if (!hasPermission(context, "expenses.manage")) return error("Expense manager permission is required to change policy.", 403);
    const body = await request.json<{ maxAmount?: number | null; receiptRequired?: boolean }>();
    const existing = await env.DB.prepare(`SELECT expense_max_amount as maxAmount, expense_receipt_required as receiptRequired FROM organization_settings WHERE organization_id = ?`).bind(context.organizationId).first<{ maxAmount: number | null; receiptRequired: number }>();
    const maxAmount = body.maxAmount === undefined ? (existing?.maxAmount ?? null) : body.maxAmount === null || body.maxAmount === 0 ? null : Number(body.maxAmount);
    if (maxAmount !== null && (!Number.isFinite(maxAmount) || maxAmount < 0 || maxAmount > 1_000_000_000_000)) return error("Enter a valid positive expense limit, or leave it blank.");
    if (body.receiptRequired !== undefined && typeof body.receiptRequired !== "boolean") return error("Receipt requirement must be enabled or disabled.");
    const receiptRequired = body.receiptRequired ?? Boolean(existing?.receiptRequired);
    await env.DB.prepare(`UPDATE organization_settings SET expense_max_amount = ?, expense_receipt_required = ? WHERE organization_id = ?`).bind(maxAmount, receiptRequired ? 1 : 0, context.organizationId).run();
    await audit(env, context, "updated", "expense_policy", context.organizationId, { maxAmount, receiptRequired });
    return json({ maxAmount, receiptRequired });
  }

  if (request.method === "GET" && path === "/api/expenses/export") {
    if (!hasPermission(context, "expenses.view")) return error("You do not have permission to export expenses.", 403);
    const result = await env.DB.prepare(`SELECT x.id, e.first_name || ' ' || e.last_name as employee, x.category, x.amount, x.currency, x.expense_date as expenseDate, x.description, x.status, p.name as project FROM expenses x JOIN employees e ON e.id = x.employee_id LEFT JOIN approval_requests a ON a.source_record_id = x.id AND a.organization_id = x.organization_id LEFT JOIN projects p ON p.id = json_extract(a.metadata_json, '$.project') AND p.organization_id = x.organization_id WHERE x.organization_id = ? AND (? = 1 OR e.user_id = ?) ORDER BY x.created_at DESC`).bind(context.organizationId, hasPermission(context, "expenses.manage") ? 1 : 0, context.userId).all<{ id: string; employee: string; category: string; amount: number; currency: string; expenseDate: string; description: string; status: string; project: string | null }>();
    const cell = (value: unknown) => { let text = String(value ?? ""); if (/^[\s]*[=+@-]/.test(text)) text = `'${text}`; return `"${text.replace(/"/g, '""').replace(/[\r\n]+/g, " ")}"`; };
    const rows = [["Expense ID", "Employee", "Category", "Date", "Amount", "Currency", "Description", "Status", "Project"], ...(result.results || []).map((row) => [row.id, row.employee, row.category, row.expenseDate, row.amount, row.currency, row.description, row.status, row.project || ""])];
    const csv = rows.map((row) => row.map(cell).join(",")).join("\r\n");
    return new Response(`\uFEFF${csv}`, { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": 'attachment; filename="zyntris-expenses.csv"', "cache-control": "private, no-store", "x-content-type-options": "nosniff" } });
  }

  if (request.method === "GET" && path === "/api/expenses") {
    if (!hasPermission(context, "expenses.view")) return error("You do not have permission to view expenses.", 403);
    const result = await env.DB.prepare(`SELECT x.id, e.first_name || ' ' || e.last_name as employee, x.category, x.amount, x.currency, x.expense_date as expenseDate, x.description, x.status, x.receipt_key IS NOT NULL as receiptAvailable, p.name as project FROM expenses x JOIN employees e ON e.id = x.employee_id LEFT JOIN approval_requests a ON a.source_record_id = x.id AND a.organization_id = x.organization_id LEFT JOIN projects p ON p.id = json_extract(a.metadata_json, '$.project') AND p.organization_id = x.organization_id WHERE x.organization_id = ? AND (? = 1 OR e.user_id = ?) ORDER BY x.created_at DESC LIMIT 100`).bind(context.organizationId, hasPermission(context, "expenses.manage") ? 1 : 0, context.userId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/expenses") {
    if (!hasPermission(context, "employees.view")) return error("Only organization members can submit expense records.", 403);
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength > 10 * 1024 * 1024 + 64 * 1024) return error("Receipt uploads must be 10MB or smaller.", 413);
    let body: { category?: string; amount?: number | string; expenseDate?: string; description?: string; project?: string };
    let receipt: File | null = null;
    if ((request.headers.get("content-type") || "").toLowerCase().includes("multipart/form-data")) {
      const form = await request.formData();
      const file = form.get("receipt");
      receipt = file instanceof File && file.size > 0 ? file : null;
      body = { category: String(form.get("category") || ""), amount: String(form.get("amount") || ""), expenseDate: String(form.get("expenseDate") || ""), description: String(form.get("description") || ""), project: String(form.get("project") || "") || undefined };
    } else body = await request.json();
    const amount = Number(body.amount);
    const category = body.category?.trim(); const description = body.description?.trim();
    if (!category || category.length > 80 || !Number.isFinite(amount) || amount <= 0 || amount > 1_000_000_000_000 || !body.expenseDate || !isoDate(body.expenseDate) || !description || description.length > 1000) return error("Enter a valid category, amount, expense date and description. Amounts must be positive and the expense date must be valid.");
    if (body.expenseDate > new Date().toISOString().slice(0, 10)) return error("Expense date cannot be in the future.");
    const policy = await env.DB.prepare(`SELECT expense_max_amount as maxAmount, expense_receipt_required as receiptRequired FROM organization_settings WHERE organization_id = ?`).bind(context.organizationId).first<{ maxAmount: number | null; receiptRequired: number }>();
    if (policy?.maxAmount && amount > policy.maxAmount) return error(`This claim exceeds the organization’s per-claim limit of ₦${policy.maxAmount.toLocaleString("en-NG")}.`, 400);
    if (policy?.receiptRequired && !receipt) return error("A receipt attachment is required by your organization’s expense policy.");
    if (receipt && (receipt.size > 10 * 1024 * 1024 || !(await validUploadContent(receipt, ["image/jpeg", "image/png", "image/webp", "application/pdf"])))) return error("Attach a valid JPEG, PNG, WebP or PDF receipt no larger than 10MB.");
    if (receipt && !env.FILES) return error("Receipt storage is unavailable. Contact your administrator.", 503);
    const employee = await env.DB.prepare(`SELECT id, first_name as firstName, last_name as lastName FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string; firstName: string; lastName: string }>();
    const employeeId = employee?.id;
    if (!employeeId) return error("Your account must be linked to an active employee profile before submitting an expense. Ask your HR administrator to complete your profile.", 409);
    if (body.project && !await env.DB.prepare(`SELECT id FROM projects WHERE id = ? AND organization_id = ?`).bind(body.project, context.organizationId).first()) return error("The selected project was not found in this organization.", 404);
    const duplicate = await env.DB.prepare(`SELECT id FROM expenses WHERE organization_id = ? AND employee_id = ? AND amount = ? AND expense_date = ? AND lower(category) = lower(?) AND lower(trim(COALESCE(description,''))) = lower(trim(?)) AND status != 'rejected' LIMIT 1`).bind(context.organizationId, employeeId, amount, body.expenseDate, category, description).first<{ id: string }>();
    if (duplicate) return error("A matching expense is already on file. Check its status before submitting again.", 409);
    const id = `expense-${crypto.randomUUID()}`;
    const requestIdValue = `request-${crypto.randomUUID()}`;
    const expenseSla = await env.DB.prepare(`SELECT due_hours as dueHours FROM workflow_sla_settings WHERE organization_id = ? AND request_type = 'Expense'`).bind(context.organizationId).first<{ dueHours: number }>();
    const expenseDueAt = new Date(Date.now() + (expenseSla?.dueHours || 48) * 3600000).toISOString();
    const receiptKey = receipt ? tenantReceiptKey(context.organizationId, id, crypto.randomUUID()) : null;
    if (receipt) {
      const reservation = await reserveTenantStorage(env, context.organizationId, receipt.size);
      if (!reservation.available) return error("Organization storage allowance is unavailable. Contact support.", 503);
      if (!reservation.withinLimit) return error("This receipt would exceed the organization’s storage allowance. Remove unused files or contact Zyntris.", 413);
    }
    try {
      if (receipt && receiptKey) await env.FILES.put(receiptKey, receipt.stream(), { httpMetadata: { contentType: receipt.type } });
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO expenses (id, organization_id, employee_id, category, amount, currency, expense_date, description, receipt_key, receipt_size_bytes, status) VALUES (?, ?, ?, ?, ?, 'NGN', ?, ?, ?, ?, 'submitted')`).bind(id, context.organizationId, employeeId, category, amount, body.expenseDate, description, receiptKey, receipt?.size || 0),
        env.DB.prepare(`INSERT INTO approval_requests (id, organization_id, request_type, source_record_id, title, requester_id, amount, currency, required_role, status, current_step, metadata_json, due_at) VALUES (?, ?, 'Expense', ?, ?, ?, ?, 'NGN', 'CEO', 'pending', 1, ?, ?)`).bind(requestIdValue, context.organizationId, id, description, context.userId, amount, JSON.stringify({ category, project: body.project || null, approvalPolicy: ["CEO"] }), expenseDueAt),
      ]);
    } catch (cause) {
      if (receipt && receiptKey) {
        let objectRemoved = false;
        try { await env.FILES.delete(receiptKey); objectRemoved = true; } catch (cleanupError) { console.error("Failed to clean up expense receipt; storage reservation retained", cleanupError); }
        if (objectRemoved) await releaseTenantStorage(env, context.organizationId, receipt.size);
      }
      throw cause;
    }
    await audit(env, context, "submitted", "expenses", id, { category, amount, description });
    await notifyApprovers(env, context, "CEO", description, `A financial request for ₦${amount.toLocaleString("en-NG")} is pending your approval.`);
    return json({ id, requestId: requestIdValue, status: "submitted", employee: `${employee.firstName} ${employee.lastName}` }, { status: 201 });
  }

  const expenseReceiptMatch = path.match(/^\/api\/expenses\/([^/]+)\/receipt$/);
  if (request.method === "GET" && expenseReceiptMatch) {
    const record = await env.DB.prepare(`SELECT x.receipt_key as receiptKey, x.employee_id as employeeId, e.user_id as userId FROM expenses x JOIN employees e ON e.id = x.employee_id WHERE x.id = ? AND x.organization_id = ?`).bind(expenseReceiptMatch[1], context.organizationId).first<{ receiptKey: string | null; employeeId: string; userId: string | null }>();
    if (!record || !record.receiptKey) return error("Receipt not found.", 404);
    if (record.userId !== context.userId && !hasPermission(context, "expenses.manage")) return error("You do not have permission to view this receipt.", 403);
    if (!isTenantObjectKey(record.receiptKey, context.organizationId)) return error("Receipt not found.", 404);
    const object = await env.FILES.get(record.receiptKey);
    if (!object) return error("Receipt file is unavailable.", 404);
    return new Response(object.body, { headers: { "content-type": object.httpMetadata?.contentType || "application/octet-stream", "content-disposition": "attachment; filename=expense-receipt", "cache-control": "private, no-store", "x-content-type-options": "nosniff" } });
  }

  const expenseMatch = path.match(/^\/api\/expenses\/([^/]+)$/);
  if (request.method === "PATCH" && expenseMatch) {
    return error("Expense decisions must be made from the role-checked approval queue.", 409);
  }

  const requestHistoryMatch = path.match(/^\/api\/requests\/([^/]+)\/history$/);
  if (request.method === "GET" && requestHistoryMatch) {
    const requestRow = await env.DB.prepare(`SELECT id, requester_id as requesterId, request_type as requestType, title, created_at as createdAt FROM approval_requests WHERE id = ? AND organization_id = ? AND (? = 1 OR requester_id = ?)`).bind(requestHistoryMatch[1], context.organizationId, hasPermission(context, "requests.manage") ? 1 : 0, context.userId).first<{ id: string; requesterId: string; requestType: string; title: string; createdAt: string }>();
    if (!requestRow) return error("Request not found.", 404);
    const history = await env.DB.prepare(`SELECT a.id, a.action, a.module, a.new_value_json as details, a.created_at as createdAt, u.full_name as actor FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id WHERE a.organization_id = ? AND a.module = 'requests' AND a.record_id = ? ORDER BY a.created_at DESC LIMIT 50`).bind(context.organizationId, requestRow.id).all();
    const initial = { id: `created-${requestRow.id}`, action: "submitted", module: "requests", details: JSON.stringify({ requestType: requestRow.requestType, title: requestRow.title }), createdAt: requestRow.createdAt, actor: null };
    return json({ data: [initial, ...(history.results || [])] });
  }

  if (request.method === "GET" && path === "/api/requests") {
    if (!hasPermission(context, "requests.manage") && !hasPermission(context, "employees.view")) return error("You do not have permission to view requests.", 403);
    const canViewAll = hasPermission(context, "requests.manage") ? 1 : 0;
    const result = await env.DB.prepare(`SELECT a.id, a.request_type as requestType, a.title, json_extract(a.metadata_json, '$.details') as details, u.full_name as requester, a.amount, a.status, a.return_note as returnNote, a.requester_id = ? as canEdit, COALESCE(json_extract(a.metadata_json, '$.fallbackActive'), 0) as fallbackActive, CASE WHEN a.amount IS NOT NULL OR lower(trim(a.request_type)) IN ('expense','purchase','budget','payroll','reimbursement','payment','financial','asset purchase') THEN json_extract(a.metadata_json, '$.fallbackRoles[0]') ELSE 'HR Admin & CEO' END as fallbackRole, (a.requester_id = ? OR a.required_role = ? OR ? = 1) as canEscalate, a.required_role as requiredRole, a.created_at as createdAt FROM approval_requests a JOIN users u ON u.id = a.requester_id WHERE a.organization_id = ? AND (? = 1 OR a.requester_id = ?) ORDER BY CASE a.status WHEN 'pending' THEN 1 WHEN 'returned' THEN 2 ELSE 3 END, a.created_at DESC LIMIT 100`).bind(context.userId, context.userId, context.role, context.role === "Organization Admin" ? 1 : 0, context.organizationId, canViewAll, context.userId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/requests") {
    if (!hasPermission(context, "employees.view")) return error("Only organization members can submit requests.", 403);
    const body = await request.json<{ requestType?: string; title?: string; details?: string; amount?: number | string }>();
    const requestType = body.requestType?.trim() || "Other";
    const title = body.title?.trim();
    const details = body.details?.trim();
    const amount = body.amount === undefined || body.amount === "" ? null : Number(body.amount);
    if (!["Operational", "Access", "HR", "Leave", "Purchase", "Budget", "Other"].includes(requestType) || !title || title.length > 120 || !details || details.length > 2000 || (amount !== null && (!Number.isFinite(amount) || amount <= 0))) return error("Choose a supported request type and provide a valid title, details and optional positive amount.");
    const financialTypes = ["expense", "purchase", "budget", "payroll", "reimbursement", "payment", "financial", "asset purchase"];
    const financial = amount !== null || financialTypes.includes(requestType.toLowerCase());
    if (financial && amount === null) return error("Financial requests must include an amount.");
    const workflowRow = await env.DB.prepare(`SELECT approval_workflows_json as workflowsJson FROM organization_settings WHERE organization_id = ?`).bind(context.organizationId).first<{ workflowsJson: string }>();
    let workflowSettings: Record<string, string> = {};
    try { workflowSettings = JSON.parse(workflowRow?.workflowsJson || "{}"); } catch { /* use defaults */ }
    const requiredRole = financial ? "CEO" : workflowSettings[requestType] || (requestType === "HR" || requestType === "Leave" ? "HR Admin" : "Manager");
    const id = `request-${crypto.randomUUID()}`;
    const sla = await env.DB.prepare(`SELECT due_hours as dueHours FROM workflow_sla_settings WHERE organization_id = ? AND request_type = ?`).bind(context.organizationId, requestType).first<{ dueHours: number }>();
    const dueAt = new Date(Date.now() + (sla?.dueHours || 48) * 3600000).toISOString();
    await env.DB.prepare(`INSERT INTO approval_requests (id, organization_id, request_type, title, requester_id, amount, currency, required_role, status, current_step, metadata_json, due_at) VALUES (?, ?, ?, ?, ?, ?, 'NGN', ?, 'pending', 1, ?, ?)`)
      .bind(id, context.organizationId, requestType, title, context.userId, amount, requiredRole, JSON.stringify({ details, approvalPolicy: [requiredRole] }), dueAt).run();
    await audit(env, context, "submitted", "requests", id, { requestType, title, amount, requiredRole });
    await notifyApprovers(env, context, requiredRole, title, `${financial ? `A financial request for ₦${Number(amount || 0).toLocaleString("en-NG")} is` : "A request is"} pending your approval. Details: ${details}`);
    return json({ id, requestType, title, amount, requiredRole, dueAt, status: "pending" }, { status: 201 });
  }

  const requestMatch = path.match(/^\/api\/requests\/([^/]+)$/);
  const unavailableMatch = path.match(/^\/api\/requests\/([^/]+)\/approver-unavailable$/);
  if (request.method === "POST" && unavailableMatch) {
    const item = await env.DB.prepare(`SELECT a.requester_id as requesterId, a.request_type as requestType, a.title, a.required_role as requiredRole, a.amount, a.status, a.metadata_json as metadataJson, s.financial_fallback_role as financialFallbackRole FROM approval_requests a JOIN organization_settings s ON s.organization_id = a.organization_id WHERE a.id = ? AND a.organization_id = ?`).bind(unavailableMatch[1], context.organizationId).first<{ requesterId: string; requestType: string; title: string; requiredRole: string; amount: number | null; status: string; metadataJson: string; financialFallbackRole: string }>();
    if (!item) return error("Request not found.", 404);
    if (item.requesterId !== context.userId && context.role !== item.requiredRole && context.role !== "Organization Admin") return error("Only the requester, assigned approver, or organization administrator can flag an unavailable approver.", 403);
    if (item.status !== "pending") return error("Only a pending request can be escalated.", 409);
    let metadata: Record<string, unknown> = {}; try { metadata = JSON.parse(item.metadataJson || "{}"); } catch { /* preserve existing metadata via json_set */ }
    if (metadata.fallbackActive) return error("This request has already been escalated to its fallback approver(s).", 409);
    const financialTypes = ["expense", "purchase", "budget", "payroll", "reimbursement", "payment", "financial", "asset purchase"];
    const isFinancialRequest = item.amount !== null || financialTypes.includes(item.requestType.trim().toLowerCase());
    const fallbackRoles = isFinancialRequest ? [item.financialFallbackRole || "HR Admin"] : ["HR Admin", "CEO"];
    const updated = await env.DB.prepare(`UPDATE approval_requests SET metadata_json = json_set(metadata_json, '$.fallbackActive', 1, '$.fallbackRoles', json(?), '$.fallbackAt', ?, '$.fallbackBy', ?), updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = 'pending' AND COALESCE(json_extract(metadata_json, '$.fallbackActive'), 0) = 0`).bind(JSON.stringify(fallbackRoles), new Date().toISOString(), context.userId, unavailableMatch[1], context.organizationId).run();
    if (!updated.meta.changes) return error("This request changed before escalation. Refresh and try again.", 409);
    await audit(env, context, "approver_unavailable_escalated", "requests", unavailableMatch[1], { originalRole: item.requiredRole, fallbackRoles });
    const requesterContext = { ...context, userId: item.requesterId };
    await Promise.all(fallbackRoles.map((role) => notifyApprovers(env, requesterContext, role, item.title, `The assigned ${item.requiredRole} approver is unavailable. This request has moved to its configured fallback approver.`)));
    return json({ ok: true, status: "pending", fallbackActive: true, fallbackRoles });
  }
  if (request.method === "PUT" && requestMatch) {
    const body = await request.json<{ title?: string; details?: string; amount?: number | string | null }>();
    const item = await env.DB.prepare(`SELECT source_record_id as sourceRecordId, requester_id as requesterId, request_type as requestType, required_role as requiredRole, amount, status FROM approval_requests WHERE id = ? AND organization_id = ?`).bind(requestMatch[1], context.organizationId).first<{ sourceRecordId: string | null; requesterId: string; requestType: string; requiredRole: string; amount: number | null; status: string }>();
    if (!item) return error("Request not found.", 404);
    if (item.requesterId !== context.userId) return error("Only the requester can edit this request.", 403);
    if (item.status !== "returned") return error("Only a request returned for edits can be resubmitted.", 409);
    const title = body.title?.trim(); const details = body.details?.trim();
    const amount = body.amount === undefined || body.amount === null || body.amount === "" ? null : Number(body.amount);
    const financialTypes = ["expense", "purchase", "budget", "payroll", "reimbursement", "payment", "financial", "asset purchase"];
    const financial = amount !== null || financialTypes.includes(item.requestType.trim().toLowerCase());
    if (!title || title.length > 120 || !details || details.length > 2000 || (amount !== null && (!Number.isFinite(amount) || amount <= 0)) || (financial && amount === null)) return error("Enter a valid title, details and amount. Financial requests must include a positive amount.");
    const requiredRole = financial ? "CEO" : item.requiredRole;
    const update = await env.DB.prepare(`UPDATE approval_requests SET title = ?, amount = ?, required_role = ?, status = 'pending', return_note = NULL, metadata_json = json_set(json_remove(metadata_json, '$.decisionReason', '$.fallbackActive', '$.fallbackAt', '$.fallbackBy'), '$.details', ?), current_step = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND requester_id = ? AND status = 'returned'`).bind(title, amount, requiredRole, details, requestMatch[1], context.organizationId, context.userId).run();
    if (!update.meta.changes) return error("This request changed before it could be resubmitted. Refresh and try again.", 409);
    if (item.sourceRecordId) await env.DB.prepare(`UPDATE expenses SET description = ?, amount = ?, status = 'submitted', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(title, amount, item.sourceRecordId, context.organizationId).run();
    await audit(env, context, "resubmitted", "requests", requestMatch[1], { title, amount, requiredRole, details });
    await notifyApprovers(env, context, requiredRole, title, `A returned request was edited and resubmitted for approval. Details: ${details}`);
    return json({ ok: true, status: "pending", requiredRole });
  }
  if (request.method === "PATCH" && requestMatch) {
    if (!hasPermission(context, "requests.manage") && !hasPermission(context, "hr.onboarding.approve")) return error("You do not have permission to approve requests.", 403);
    const body = await request.json<{ status?: string; reason?: string; note?: string }>();
    if (!body.status || !["approved", "rejected", "returned", "paid", "cancelled"].includes(body.status)) return error("A valid request status is required");
    const requestIdValue = requestMatch[1];
    const item = await env.DB.prepare(`SELECT source_record_id as sourceRecordId, requester_id as requesterId, title, request_type as requestType, required_role as requiredRole, amount, current_step as currentStep, status, metadata_json as metadataJson FROM approval_requests WHERE id = ? AND organization_id = ?`).bind(requestIdValue, context.organizationId).first<{ sourceRecordId: string | null; requesterId: string; title: string; requestType: string; requiredRole: string; amount: number | null; currentStep: number; status: string; metadataJson: string }>();
    if (!item) return error("Request not found.", 404);
    if (item.status !== "pending" && !(body.status === "paid" && item.status === "approved")) return error("This request has already been decided or is not ready for payment recording.", 409);
    const financialTypes = ["expense", "purchase", "budget", "payroll", "reimbursement", "payment", "financial", "asset purchase"];
    const isFinancialRequest = item.amount !== null || financialTypes.includes(item.requestType.trim().toLowerCase());
    let decisionMetadata: Record<string, unknown> = {}; try { decisionMetadata = JSON.parse(item.metadataJson || "{}"); } catch { /* use role-only authorization */ }
    const fallbackRoles = Array.isArray(decisionMetadata.fallbackRoles) ? decisionMetadata.fallbackRoles : isFinancialRequest ? ["HR Admin"] : ["HR Admin", "CEO"];
    const fallbackApproverMayDecide = Boolean(decisionMetadata.fallbackActive) && fallbackRoles.includes(context.role);
    const requiredRole = isFinancialRequest ? "CEO" : item.requiredRole;
    if ((body.status === "approved" || body.status === "rejected") && item.requesterId === context.userId) return error("You cannot approve or reject a request you submitted.", 403);
    if (body.status === "rejected" && !body.reason?.trim()) return error("A rejection reason is required so the requester has a clear decision record.");
    if (body.status === "returned" && !body.note?.trim()) return error("Add a note explaining what the requester needs to edit.");
    if (body.status === "approved" || body.status === "rejected" || body.status === "returned") {
      const organizationAdminMayDecide = !isFinancialRequest && context.role === "Organization Admin";
      if (context.role !== requiredRole && !organizationAdminMayDecide && !fallbackApproverMayDecide) return error(`This request requires approval from ${requiredRole}${decisionMetadata.fallbackActive ? " or its configured fallback approver" : ""}.`, 403);
    } else if (body.status === "paid" && !hasPermission(context, "expenses.manage")) return error("Finance permission is required to mark a claim as paid.", 403);
    const expectedStatus = body.status === "paid" ? "approved" : "pending";
    const decisionNote = body.status === "returned" ? body.note!.trim().slice(0, 2000) : body.reason?.trim().slice(0, 2000) || "";
    const changes = await env.DB.batch([
      env.DB.prepare(`UPDATE approval_requests SET status = ?, return_note = CASE WHEN ? = 'returned' THEN ? ELSE return_note END, metadata_json = CASE WHEN ? = '' THEN metadata_json ELSE json_set(metadata_json, '$.decisionReason', ?) END, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = ?`).bind(body.status, body.status, decisionNote, decisionNote, decisionNote, requestIdValue, context.organizationId, expectedStatus),
      ...(item.sourceRecordId ? [env.DB.prepare(`UPDATE expenses SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND EXISTS (SELECT 1 FROM approval_requests WHERE id = ? AND organization_id = ? AND status = ?)`).bind(body.status === "returned" ? "submitted" : body.status, item.sourceRecordId, context.organizationId, requestIdValue, context.organizationId, body.status)] : []),
    ]);
    if (!changes[0]?.meta.changes) return error("This request was decided by another approver. Refresh the queue.", 409);
    if (item.requestType.toLowerCase() === "purchase" && typeof decisionMetadata.purchaseRequestId === "string") {
      const purchaseId = decisionMetadata.purchaseRequestId;
      if (body.status === "approved") {
        const poNumber = `PO-${new Date().getUTCFullYear()}-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
        await env.DB.batch([
          env.DB.prepare(`UPDATE purchase_requests SET status = 'ordered', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = 'pending_approval'`).bind(purchaseId, context.organizationId),
          env.DB.prepare(`INSERT OR IGNORE INTO purchase_orders (id, organization_id, purchase_request_id, po_number, issued_by) VALUES (?, ?, ?, ?, ?)`).bind(`po-${crypto.randomUUID()}`, context.organizationId, purchaseId, poNumber, context.userId),
        ]);
      } else if (body.status === "rejected" || body.status === "cancelled") {
        await env.DB.batch([
          env.DB.prepare(`UPDATE purchase_requests SET status = 'rejected', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(purchaseId, context.organizationId),
          env.DB.prepare(`UPDATE budget_reservations SET status = 'released', updated_at = CURRENT_TIMESTAMP WHERE purchase_request_id = ? AND organization_id = ? AND status = 'reserved'`).bind(purchaseId, context.organizationId),
        ]);
      }
    }
    if(item.requestType.toLowerCase()==="project proposal"&&typeof decisionMetadata.projectId==="string"&&(body.status==="approved"||body.status==="rejected"||body.status==="returned")){
      const newStatus=body.status==="approved"?"approved":"proposed";
      await env.DB.prepare(`UPDATE projects SET status=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=? AND status='pending_approval'`).bind(newStatus,context.userId,decisionMetadata.projectId,context.organizationId).run();
      await audit(env,context,`proposal_${body.status}`,"projects",decisionMetadata.projectId,{approvalRequestId:requestIdValue,note:decisionNote||null});
    }
    if(item.requestType.toLowerCase()==="project change"&&typeof decisionMetadata.changeRequestId==="string"&&(body.status==="approved"||body.status==="rejected"||body.status==="returned")){
      const newStatus=body.status==="approved"?"approved":body.status==="returned"?"draft":"rejected";
      await env.DB.prepare(`UPDATE project_change_requests SET status=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=? AND status='submitted'`).bind(newStatus,context.userId,decisionMetadata.changeRequestId,context.organizationId).run();
      await audit(env,context,`change_${body.status}`,"project_change_requests",decisionMetadata.changeRequestId,{approvalRequestId:requestIdValue,note:decisionNote||null});
    }
    await audit(env, context, body.status === "returned" ? "returned_for_edits" : body.status, "requests", requestIdValue, { role: context.role, stage: item.currentStep, note: decisionNote || null });
    if (body.status === "approved" || body.status === "rejected" || body.status === "returned") {
      const requester = await env.DB.prepare(`SELECT u.email, u.full_name as fullName, o.name as organizationName FROM users u JOIN organizations o ON o.id = ? WHERE u.id = ?`).bind(context.organizationId, item.requesterId).first<{ email: string; fullName: string; organizationName: string }>();
      const decisionText = body.status === "approved" ? "approved" : body.status === "returned" ? `returned for edits. Note: ${decisionNote}` : `rejected. Reason: ${decisionNote}`;
      await env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'request_decision', ?, ?)`).bind(requestId(), context.organizationId, item.requesterId, body.status === "returned" ? "Request returned for edits" : `Request ${body.status}`, `Your ${item.requestType.toLowerCase()} request “${item.title}” was ${decisionText}.`).run();
      if (requester) await sendApprovalNotificationEmail(env, requester.email, requester.fullName, requester.organizationName, body.status === "returned" ? "Your Zyntris request needs edits" : `Your Zyntris request was ${body.status}`, `Your ${item.requestType.toLowerCase()} request “${item.title}” was ${decisionText}.`);
    }
    return json({ ok: true, id: requestIdValue, status: body.status });
  }

  if (request.method === "GET" && path === "/api/assets") {
    const result = await env.DB.prepare(`SELECT a.id, a.asset_tag as assetTag, a.name, a.category, COALESCE(a.serial_number, '') as serialNumber, a.status, a.assigned_employee_id as assignedEmployeeId, e.first_name || ' ' || e.last_name as assignee, a.location, a.current_value as value FROM assets a LEFT JOIN employees e ON e.id = a.assigned_employee_id WHERE a.organization_id = ? ORDER BY a.created_at DESC`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "GET" && path === "/api/budgets") {
    const result = await env.DB.prepare(`SELECT id, name, category, period, allocated, spent, status FROM budgets WHERE organization_id = ? ORDER BY created_at DESC`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/budgets") {
    const body = await request.json<{ name?: string; category?: string; period?: string; allocated?: number; spent?: number }>();
    const allocated = Number(body.allocated); const spent = Number(body.spent || 0);
    if (!body.name?.trim() || !body.category?.trim() || !body.period?.trim() || !Number.isFinite(allocated) || allocated <= 0 || !Number.isFinite(spent) || spent < 0 || spent > allocated) return error("Enter a name, category, period, and valid allocation/spend amounts.");
    const id = `budget-${crypto.randomUUID()}`; const status = spent / allocated >= 0.8 ? "watch" : "on_track";
    await env.DB.prepare(`INSERT INTO budgets (id, organization_id, name, category, period, allocated, spent, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, context.organizationId, body.name.trim(), body.category.trim(), body.period.trim(), allocated, spent, status).run();
    await audit(env, context, "created", "budgets", id, { name: body.name.trim(), allocated, spent, status });
    return json({ id }, { status: 201 });
  }

  const budgetMatch = path.match(/^\/api\/budgets\/([^/]+)$/);
  if (request.method === "PATCH" && budgetMatch) {
    const body = await request.json<{ name?: string; category?: string; period?: string; allocated?: number; spent?: number }>();
    const current = await env.DB.prepare(`SELECT id, name, category, period, allocated, spent FROM budgets WHERE id = ? AND organization_id = ?`).bind(budgetMatch[1], context.organizationId).first<{ id: string; name: string; category: string; period: string; allocated: number; spent: number }>();
    if (!current) return error("Budget not found.", 404);
    const allocated = body.allocated === undefined ? current.allocated : Number(body.allocated); const spent = body.spent === undefined ? current.spent : Number(body.spent);
    if (!Number.isFinite(allocated) || allocated <= 0 || !Number.isFinite(spent) || spent < 0 || spent > allocated) return error("Spent amount must be between zero and the allocated amount.");
    const name = body.name?.trim() || current.name; const category = body.category?.trim() || current.category; const period = body.period?.trim() || current.period;
    const status = spent / allocated >= 0.8 ? "watch" : "on_track";
    await env.DB.prepare(`UPDATE budgets SET name = ?, category = ?, period = ?, allocated = ?, spent = ?, status = ? WHERE id = ? AND organization_id = ?`).bind(name, category, period, allocated, spent, status, current.id, context.organizationId).run();
    await audit(env, context, "updated", "budgets", current.id, { name, category, period, allocated, spent, status });
    return json({ ok: true });
  }

  if (request.method === "POST" && path === "/api/assets") {
    const body = await request.json<{ name?: string; category?: string; serialNumber?: string; location?: string; value?: number }>();
    if (!body.name || !body.category) return error("name and category are required");
    const id = `asset-${crypto.randomUUID().slice(0, 8)}`;
    const tag = `AST-${Math.floor(1000 + Math.random() * 8999)}`;
    await env.DB.prepare(`INSERT INTO assets (id, organization_id, asset_tag, name, category, serial_number, location, purchase_price, current_value) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, tag, body.name, body.category, body.serialNumber || null, body.location || null, Number(body.value || 0), Number(body.value || 0)).run();
    await env.DB.prepare(`INSERT INTO asset_history (id, organization_id, asset_id, action, employee_id, notes) VALUES (?, ?, ?, 'created', NULL, ?)`).bind(`asset-history-${crypto.randomUUID()}`, context.organizationId, id, "Asset added to the register.").run();
    await audit(env, context, "created", "assets", id, body);
    return json({ id, assetTag: tag }, { status: 201 });
  }

  const assetHistoryMatch = path.match(/^\/api\/assets\/([^/]+)\/history$/);
  if (request.method === "GET" && assetHistoryMatch) {
    const result = await env.DB.prepare(`SELECT h.id, h.action, h.notes, h.created_at as createdAt, e.first_name || ' ' || e.last_name as employee FROM asset_history h LEFT JOIN employees e ON e.id = h.employee_id AND e.organization_id = h.organization_id WHERE h.asset_id = ? AND h.organization_id = ? ORDER BY h.created_at DESC LIMIT 100`).bind(assetHistoryMatch[1], context.organizationId).all();
    return json({ data: result.results || [] });
  }

  const assetMatch = path.match(/^\/api\/assets\/([^/]+)$/);
  if (request.method === "PATCH" && assetMatch) {
    const body = await request.json<{ name?: string; category?: string; serialNumber?: string | null; location?: string | null; value?: number; status?: string; assignedEmployeeId?: string | null; notes?: string }>();
    const asset = await env.DB.prepare(`SELECT id, name, status, assigned_employee_id as assignedEmployeeId FROM assets WHERE id = ? AND organization_id = ?`).bind(assetMatch[1], context.organizationId).first<{ id: string; name: string; status: string; assignedEmployeeId: string | null }>();
    if (!asset) return error("Asset not found.", 404);
    if (body.status !== undefined && !["available", "assigned", "maintenance", "retired"].includes(body.status)) return error("Choose a valid asset status.");
    const value = body.value === undefined ? null : Number(body.value);
    if (value !== null && (!Number.isFinite(value) || value < 0)) return error("Asset value must be zero or greater.");
    if (body.assignedEmployeeId && !await env.DB.prepare(`SELECT id FROM employees WHERE id = ? AND organization_id = ? AND status = 'active' AND deleted_at IS NULL`).bind(body.assignedEmployeeId, context.organizationId).first()) return error("Choose an active employee in this organization.", 404);
    const status = body.assignedEmployeeId ? "assigned" : body.status || (body.assignedEmployeeId === null ? "available" : asset.status);
    await env.DB.prepare(`UPDATE assets SET name = COALESCE(?, name), category = COALESCE(?, category), serial_number = CASE WHEN ? = 1 THEN ? ELSE serial_number END, location = CASE WHEN ? = 1 THEN ? ELSE location END, current_value = COALESCE(?, current_value), status = ?, assigned_employee_id = CASE WHEN ? = 1 THEN ? ELSE assigned_employee_id END, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`)
      .bind(body.name?.trim() || null, body.category?.trim() || null, body.serialNumber !== undefined ? 1 : 0, body.serialNumber || null, body.location !== undefined ? 1 : 0, body.location || null, value, status, body.assignedEmployeeId !== undefined ? 1 : 0, body.assignedEmployeeId || null, asset.id, context.organizationId).run();
    const changedAssignment = body.assignedEmployeeId !== undefined && body.assignedEmployeeId !== asset.assignedEmployeeId;
    const changedStatus = body.status !== undefined && body.status !== asset.status;
    if (changedAssignment || changedStatus || body.notes?.trim()) {
      const action = changedAssignment ? (body.assignedEmployeeId ? "assigned" : "unassigned") : changedStatus ? `status_${status}` : "updated";
      await env.DB.prepare(`INSERT INTO asset_history (id, organization_id, asset_id, action, employee_id, notes) VALUES (?, ?, ?, ?, ?, ?)`)
        .bind(`asset-history-${crypto.randomUUID()}`, context.organizationId, asset.id, action, body.assignedEmployeeId || null, body.notes?.trim() || null).run();
    }
    await audit(env, context, "updated", "assets", asset.id, body);
    return json({ ok: true, status });
  }

  if (request.method === "GET" && path === "/api/vendors") {
    const result = await env.DB.prepare(`SELECT id, name, category, contact_name as contactName, email, status, contract_end as contractEnd, spend FROM vendors WHERE organization_id = ? ORDER BY name`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/vendors") {
    const body = await request.json<{ name?: string; category?: string; contactName?: string; email?: string; contractEnd?: string }>();
    if (!body.name || !body.category) return error("name and category are required");
    const id = `vendor-${crypto.randomUUID().slice(0, 8)}`;
    await env.DB.prepare(`INSERT INTO vendors (id, organization_id, name, category, contact_name, email, contract_end) VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, body.name, body.category, body.contactName || null, body.email || null, body.contractEnd || null).run();
    await audit(env, context, "created", "vendors", id, body);
    return json({ id }, { status: 201 });
  }

  const vendorMatch = path.match(/^\/api\/vendors\/([^/]+)$/);
  if (request.method === "PATCH" && vendorMatch) {
    const body = await request.json<{ name?: string; category?: string; contactName?: string | null; email?: string | null; status?: string; contractEnd?: string | null; spend?: number }>();
    const current = await env.DB.prepare(`SELECT id, name, category, contact_name as contactName, email, status, contract_end as contractEnd, spend FROM vendors WHERE id = ? AND organization_id = ?`).bind(vendorMatch[1], context.organizationId).first<{ id: string; name: string; category: string; contactName: string | null; email: string | null; status: string; contractEnd: string | null; spend: number }>();
    if (!current) return error("Vendor not found.", 404);
    if (body.status !== undefined && !["active", "review", "expired"].includes(body.status)) return error("Choose a valid vendor status.");
    if (body.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) return error("Enter a valid vendor email address.");
    if (body.contractEnd && !isoDate(body.contractEnd)) return error("Enter a valid contract end date.");
    const spend = body.spend === undefined ? current.spend : Number(body.spend);
    if (!Number.isFinite(spend) || spend < 0) return error("Vendor spend must be a non-negative amount.");
    await env.DB.prepare(`UPDATE vendors SET name = ?, category = ?, contact_name = ?, email = ?, status = ?, contract_end = ?, spend = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(body.name?.trim() || current.name, body.category?.trim() || current.category, body.contactName === undefined ? current.contactName : body.contactName?.trim() || null, body.email === undefined ? current.email : body.email?.trim() || null, body.status || current.status, body.contractEnd === undefined ? current.contractEnd : body.contractEnd || null, spend, current.id, context.organizationId).run();
    await audit(env, context, "updated", "vendors", current.id, body);
    return json({ ok: true });
  }

  if (request.method === "GET" && path === "/api/tickets") {
    const result = await env.DB.prepare(`SELECT t.id, t.ticket_number as ticketNumber, t.subject, t.category, t.priority, t.status, t.description, t.assignee_id as assigneeId, requester.full_name as requester, assignee.full_name as assignee, t.created_at as createdAt FROM support_tickets t JOIN users requester ON requester.id = t.requester_id LEFT JOIN users assignee ON assignee.id = t.assignee_id WHERE t.organization_id = ? ORDER BY t.created_at DESC`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/tickets") {
    const body = await request.json<{ subject?: string; category?: string; priority?: string; description?: string }>();
    if (!body.subject || !body.category) return error("subject and category are required");
    const id = `ticket-${crypto.randomUUID().slice(0, 8)}`;
    const ticketNumber = `ZD-${Math.floor(1000 + Math.random() * 8999)}`;
    await env.DB.prepare(`INSERT INTO support_tickets (id, organization_id, ticket_number, subject, category, priority, requester_id, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, ticketNumber, body.subject, body.category, body.priority || "medium", context.userId, body.description || null).run();
    await audit(env, context, "created", "helpdesk", id, body);
    return json({ id, ticketNumber }, { status: 201 });
  }

  const ticketMatch = path.match(/^\/api\/tickets\/([^/]+)$/);
  if (request.method === "PATCH" && ticketMatch) {
    const body = await request.json<{ status?: string; assigneeId?: string | null; priority?: string; description?: string }>();
    const ticket = await env.DB.prepare(`SELECT id, ticket_number as ticketNumber, subject, requester_id as requesterId, status, assignee_id as assigneeId FROM support_tickets WHERE id = ? AND organization_id = ?`).bind(ticketMatch[1], context.organizationId).first<{ id: string; ticketNumber: string; subject: string; requesterId: string; status: string; assigneeId: string | null }>();
    if (!ticket) return error("Support ticket not found.", 404);
    if (body.status !== undefined && !["open", "assigned", "in_progress", "resolved", "closed"].includes(body.status)) return error("Choose a valid support ticket status.");
    if (body.priority !== undefined && !["low", "medium", "high", "urgent"].includes(body.priority)) return error("Choose a valid priority.");
    if (body.assigneeId && !await env.DB.prepare(`SELECT id FROM users WHERE id = ? AND status = 'active' AND EXISTS (SELECT 1 FROM memberships WHERE user_id = users.id AND organization_id = ? AND status = 'active')`).bind(body.assigneeId, context.organizationId).first()) return error("Choose an active member of this organization.", 404);
    const status = body.status || (body.assigneeId && ticket.status === "open" ? "assigned" : ticket.status);
    await env.DB.prepare(`UPDATE support_tickets SET status = ?, assignee_id = CASE WHEN ? = 1 THEN ? ELSE assignee_id END, priority = COALESCE(?, priority), description = COALESCE(?, description), updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(status, body.assigneeId !== undefined ? 1 : 0, body.assigneeId || null, body.priority || null, body.description?.trim() || null, ticket.id, context.organizationId).run();
    if (body.assigneeId !== undefined && body.assigneeId !== ticket.assigneeId && body.assigneeId) await env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'ticket_assigned', 'Support ticket assigned', ?)`).bind(requestId(), context.organizationId, body.assigneeId, `A support ticket was assigned to you. Status: ${status}.`).run();
    if (body.status && body.status !== ticket.status) {
      const requester = await env.DB.prepare(`SELECT email, full_name as fullName FROM users WHERE id = ?`).bind(ticket.requesterId).first<{ email: string; fullName: string }>();
      const orgName = await env.DB.prepare(`SELECT name FROM organizations WHERE id = ?`).bind(context.organizationId).first<{ name: string }>();
      await env.DB.prepare(`INSERT INTO notifications (id, organization_id, user_id, type, title, body) VALUES (?, ?, ?, 'ticket_status', ?, ?)`).bind(requestId(), context.organizationId, ticket.requesterId, `Ticket ${status.replace("_", " ")}`, `${ticket.ticketNumber} — ${ticket.subject} is now ${status.replace("_", " ")}.`).run();
      if (requester) await sendApprovalNotificationEmail(env, requester.email, requester.fullName, orgName?.name || "your organization", `Support ticket ${ticket.ticketNumber} updated`, `Your ticket “${ticket.subject}” is now ${status.replace("_", " ")}.`);
    }
    await audit(env, context, "updated", "helpdesk", ticket.id, { ...body, status });
    return json({ ok: true, status });
  }

  if (request.method === "GET" && path === "/api/calendar") {
    const result = await env.DB.prepare(`SELECT id, title, event_type as eventType, start_at as startAt, end_at as endAt, location FROM calendar_events WHERE organization_id = ? ORDER BY start_at LIMIT 100`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "GET" && path === "/api/customers") {
    const result = await env.DB.prepare(`SELECT c.id, c.name, c.company, c.email, c.stage, c.value, u.full_name as owner, c.last_activity_at as lastActivity, c.won_at as wonAt FROM customers c LEFT JOIN users u ON u.id = c.owner_id WHERE c.organization_id = ? ORDER BY c.created_at DESC`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/customers") {
    const body = await request.json<{ name?: string; company?: string; email?: string; stage?: string; value?: number }>();
    if (!body.name?.trim() || body.name.trim().length > 120 || !body.email || body.email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email) || body.company && body.company.length > 160 || !["lead", "qualified", "proposal", "negotiation", "won", "lost"].includes(body.stage || "lead") || !Number.isFinite(Number(body.value || 0)) || Number(body.value || 0) < 0) return error("Enter a valid contact name, email, stage, and non-negative deal value.");
    const id = `customer-${crypto.randomUUID().slice(0, 8)}`;
    await env.DB.prepare(`INSERT INTO customers (id, organization_id, name, company, email, stage, value, owner_id, last_activity_at, won_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, date('now'), CASE WHEN ? = 'won' THEN CURRENT_TIMESTAMP ELSE NULL END)`).bind(id, context.organizationId, body.name.trim(), body.company?.trim() || null, body.email.trim().toLowerCase(), body.stage || "lead", Number(body.value || 0), context.userId, body.stage || "lead").run();
    await audit(env, context, "created", "customers", id, body);
    return json({ id }, { status: 201 });
  }

  const customerMatch = path.match(/^\/api\/customers\/([^/]+)$/);
  if (request.method === "PATCH" && customerMatch) {
    if (!hasPermission(context, "operations.manage")) return error("Operations manager permission is required to edit customer profiles.", 403);
    const body = await request.json<{ name?: string; company?: string; email?: string; stage?: string; value?: number }>();
    const current = await env.DB.prepare(`SELECT id, name, company, email, stage, value FROM customers WHERE id = ? AND organization_id = ?`).bind(customerMatch[1], context.organizationId).first<{ id: string; name: string; company: string | null; email: string; stage: string; value: number }>();
    if (!current) return error("Customer not found.", 404);
    const name = body.name?.trim() ?? current.name; const company = body.company === undefined ? current.company : body.company.trim() || null; const email = body.email?.trim().toLowerCase() ?? current.email; const stage = body.stage ?? current.stage; const value = body.value === undefined ? current.value : Number(body.value);
    if (!name || name.length > 120 || company && company.length > 160 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !["lead", "qualified", "proposal", "negotiation", "won", "lost"].includes(stage) || !Number.isFinite(value) || value < 0 || value > 1_000_000_000_000) return error("Enter a valid customer profile and non-negative deal value.");
    await env.DB.prepare(`UPDATE customers SET name = ?, company = ?, email = ?, stage = ?, value = ?, last_activity_at = date('now'), won_at = CASE WHEN ? = 'won' THEN CASE WHEN stage = 'won' AND won_at IS NOT NULL THEN won_at ELSE CURRENT_TIMESTAMP END ELSE NULL END, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(name, company, email, stage, value, stage, current.id, context.organizationId).run();
    await audit(env, context, "updated", "customers", current.id, { name, company, email, stage, value }, current);
    return json({ ok: true });
  }

  if (request.method === "GET" && path === "/api/files") {
    const [result, storage] = await Promise.all([
      env.DB.prepare(`SELECT id, name, category, content_type as contentType, size_bytes as sizeBytes, expires_at as expiresAt, created_at as createdAt FROM documents WHERE organization_id = ? ORDER BY created_at DESC LIMIT 100`).bind(context.organizationId).all(),
      env.DB.prepare(`SELECT s.storage_limit_bytes as storageLimitBytes, COALESCE(u.used_bytes,0) as usedBytes FROM subscriptions s LEFT JOIN tenant_storage_usage u ON u.organization_id=s.organization_id WHERE s.organization_id=?`).bind(context.organizationId).first<{ storageLimitBytes: number; usedBytes: number }>(),
    ]);
    return json({ data: result.results || [], storageLimitBytes: storage?.storageLimitBytes || 0, usedBytes: storage?.usedBytes || 0 });
  }

  const fileMatch = path.match(/^\/api\/files\/([^/]+)$/);
  if (request.method === "GET" && fileMatch) {
    const doc = await env.DB.prepare(`SELECT name, r2_key as r2Key, content_type as contentType FROM documents WHERE id = ? AND organization_id = ?`).bind(fileMatch[1], context.organizationId).first<{ name: string; r2Key: string; contentType: string }>();
    if (!doc) return error("Document not found.", 404);
    if (!isTenantObjectKey(doc.r2Key, context.organizationId)) return error("Document not found.", 404);
    const object = await env.FILES.get(doc.r2Key);
    if (!object) return error("Document contents are unavailable.", 404);
    const safeName = doc.name.replace(/[\r\n"\\]/g, "_");
    return new Response(object.body, { headers: { "content-type": doc.contentType || "application/octet-stream", "content-disposition": `attachment; filename="${safeName}"`, "cache-control": "private, no-store", "x-content-type-options": "nosniff" } });
  }

  if (request.method === "DELETE" && fileMatch) {
    if (!hasPermission(context, "operations.manage")) return error("Operations manager permission is required to delete documents.", 403);
    const doc = await env.DB.prepare(`SELECT r2_key as r2Key, name, size_bytes as sizeBytes FROM documents WHERE id = ? AND organization_id = ?`).bind(fileMatch[1], context.organizationId).first<{ r2Key: string; name: string; sizeBytes: number }>();
    if (!doc) return error("Document not found.", 404);
    if (!isTenantObjectKey(doc.r2Key, context.organizationId)) return error("Document not found.", 404);
    await env.FILES.delete(doc.r2Key);
    const deleted = await env.DB.prepare(`DELETE FROM documents WHERE id = ? AND organization_id = ?`).bind(fileMatch[1], context.organizationId).run();
    if (deleted.meta.changes === 1) await env.DB.prepare(`UPDATE tenant_storage_usage SET used_bytes = MAX(0, used_bytes - ?), updated_at = CURRENT_TIMESTAMP WHERE organization_id = ?`).bind(doc.sizeBytes, context.organizationId).run();
    await audit(env, context, "deleted", "documents", fileMatch[1], { name: doc.name, size: doc.sizeBytes });
    return json({ ok: true });
  }

  if (request.method === "POST" && path === "/api/files") {
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength > 10 * 1024 * 1024 + 64 * 1024) return error("Files must be 10MB or smaller.", 413);
    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return error("A file is required");
    if (file.size > 10 * 1024 * 1024) return error("Files must be 10MB or smaller", 413);
    if (!(await validUploadContent(file, ["application/pdf", "image/jpeg", "image/png", "image/webp", "text/csv", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]))) return error("Unsupported file type or file content. Use a valid PDF, image, CSV, DOCX or XLSX file.", 415);
    const reservation = await reserveTenantStorage(env, context.organizationId, file.size);
    if (!reservation.available) return error("Organization storage allowance is unavailable. Contact support.", 503);
    if (!reservation.withinLimit) return error("This upload would exceed the organization’s storage allowance. Remove unused files or contact Zyntris.", 413);
    const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, "-");
    const key = tenantDocumentKey(context.organizationId, `${crypto.randomUUID()}-${safeName}`);
    const id = `doc-${crypto.randomUUID().slice(0, 8)}`;
    try {
      await env.FILES.put(key, file.stream(), { httpMetadata: { contentType: file.type || "application/octet-stream" } });
      await env.DB.prepare(`INSERT INTO documents (id, organization_id, name, category, r2_key, content_type, size_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .bind(id, context.organizationId, file.name, String(form.get("category") || "General"), key, file.type || "application/octet-stream", file.size).run();
    } catch (cause) {
      let objectRemoved = false;
      try { await env.FILES.delete(key); objectRemoved = true; } catch (cleanupError) { console.error("Failed to clean up document upload object; storage reservation retained", cleanupError); }
      if (objectRemoved) await releaseTenantStorage(env, context.organizationId, file.size);
      throw cause;
    }
    await audit(env, context, "uploaded", "documents", id, { name: file.name, size: file.size });
    return json({ id, name: file.name }, { status: 201 });
  }

  return error("Not found", 404);
}

async function expireTrials(env: Env) {
  const expiredTrials = await env.DB.prepare(`SELECT organization_id as organizationId FROM subscriptions WHERE status = 'trialing' AND trial_ends_at IS NOT NULL AND trial_ends_at <= CURRENT_TIMESTAMP AND organization_id IN (SELECT id FROM organizations WHERE is_demo = 0)`).all<{ organizationId: string }>();
  const due = expiredTrials.results || [];
  for (let offset = 0; offset < due.length; offset += 30) {
    const statements = due.slice(offset, offset + 30).flatMap(({ organizationId }) => [
      env.DB.prepare(`UPDATE subscriptions SET status = 'expired' WHERE organization_id = ? AND status = 'trialing' AND trial_ends_at <= CURRENT_TIMESTAMP`).bind(organizationId),
      env.DB.prepare(`UPDATE organizations SET status = 'suspended', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND is_demo = 0 AND EXISTS (SELECT 1 FROM subscriptions WHERE organization_id = ? AND status = 'expired')`).bind(organizationId, organizationId),
      env.DB.prepare(`DELETE FROM sessions WHERE organization_id = ? AND EXISTS (SELECT 1 FROM organizations o JOIN subscriptions s ON s.organization_id = o.id WHERE o.id = ? AND o.status = 'suspended' AND s.status = 'expired')`).bind(organizationId, organizationId),
      env.DB.prepare(`INSERT INTO audit_logs (id, organization_id, actor_user_id, action, module, record_type, record_id, new_value_json) SELECT ?, ?, NULL, 'trial_expired_services_disabled', 'platform', 'organization', ?, ? FROM organizations o JOIN subscriptions s ON s.organization_id = o.id WHERE o.id = ? AND o.status = 'suspended' AND s.status = 'expired'`)
        .bind(`audit-${crypto.randomUUID()}`, organizationId, organizationId, JSON.stringify({ subscriptionStatus: "expired", serviceEnabled: false }), organizationId),
    ]);
    if (statements.length) await env.DB.batch(statements);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      const calendarFeedMatch = url.pathname.match(/^\/calendar\/feed\/([a-f0-9]{64})(?:\.ics)?$/i);
      if (request.method === "GET" && calendarFeedMatch) return withSecurityHeaders(await publicCalendarFeed(calendarFeedMatch[1], env));
      const projectPortalMatch = url.pathname.match(/^\/api\/public\/project-portal\/([A-Za-z0-9_-]{32,200})$/);
      if (request.method === "GET" && projectPortalMatch) return withSecurityHeaders(await publicProjectPortal(projectPortalMatch[1], env));
      const projectPortalPageMatch = url.pathname.match(/^\/project-portal\/([A-Za-z0-9_-]{32,200})$/);
      if (request.method === "GET" && projectPortalPageMatch) return withSecurityHeaders(await publicProjectPortal(projectPortalPageMatch[1], env, true));
      if (request.method === "GET" && url.pathname === "/api/calendar/oauth/callback") return withSecurityHeaders(await handleCalendarOAuthCallback(request, env));
      if (url.pathname.startsWith("/api/")) return withSecurityHeaders(await handleApi(request, env));
      return withSecurityHeaders(await env.ASSETS.fetch(request));
    } catch (cause) {
      const incidentId = requestId();
      console.error("Unhandled request error", { incidentId, cause });
      const response = error(`Something went wrong. Please try again. Reference: ${incidentId}`, 500);
      response.headers.set("x-zyntris-request-id", incidentId);
      return withSecurityHeaders(response);
    }
  },
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM auth_rate_limits WHERE window_started_at < datetime('now', '-1 day')`),
      env.DB.prepare(`DELETE FROM sessions WHERE expires_at <= CURRENT_TIMESTAMP OR last_seen_at <= datetime('now', '-2 minutes')`),
      env.DB.prepare(`DELETE FROM two_factor_challenges WHERE expires_at <= CURRENT_TIMESTAMP`),
      env.DB.prepare(`DELETE FROM password_reset_tokens WHERE expires_at <= CURRENT_TIMESTAMP OR (used_at IS NOT NULL AND created_at < datetime('now', '-1 day'))`),
      env.DB.prepare(`DELETE FROM email_verification_tokens WHERE expires_at <= CURRENT_TIMESTAMP OR (used_at IS NOT NULL AND created_at < datetime('now', '-1 day'))`),
      env.DB.prepare(`DELETE FROM calendar_oauth_states WHERE expires_at <= CURRENT_TIMESTAMP`),
    ]);
    const legacyReceipts = await env.DB.prepare(`SELECT id, organization_id as organizationId, receipt_key as receiptKey FROM expenses WHERE receipt_key IS NOT NULL AND receipt_size_bytes = 0 ORDER BY created_at LIMIT 200`).all<{ id: string; organizationId: string; receiptKey: string }>();
    for (const receipt of legacyReceipts.results || []) {
      const object = await env.FILES.head(receipt.receiptKey);
      if (!object) continue;
      const updated = await env.DB.prepare(`UPDATE expenses SET receipt_size_bytes = ? WHERE id = ? AND organization_id = ? AND receipt_size_bytes = 0 AND receipt_key = ?`).bind(object.size, receipt.id, receipt.organizationId, receipt.receiptKey).run();
      if (updated.meta.changes === 1) {
        await env.DB.prepare(`INSERT INTO tenant_storage_usage (organization_id, used_bytes, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(organization_id) DO UPDATE SET used_bytes = used_bytes + excluded.used_bytes, updated_at = CURRENT_TIMESTAMP`).bind(receipt.organizationId, object.size).run();
      }
    }
    await expireTrials(env);
    const expiredModules=await env.DB.prepare(`SELECT id,organization_id as organizationId,module_key as moduleKey FROM module_subscriptions WHERE status='active' AND ends_at IS NOT NULL AND ends_at<=CURRENT_TIMESTAMP LIMIT 200`).all<{id:string;organizationId:string;moduleKey:string}>();
    for(const item of expiredModules.results||[]){
      await env.DB.batch([
        env.DB.prepare(`UPDATE module_subscriptions SET status='expired',updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='active'`).bind(item.id),
        env.DB.prepare(`UPDATE organization_modules SET enabled=0,updated_at=CURRENT_TIMESTAMP WHERE organization_id=? AND module_key=?`).bind(item.organizationId,item.moduleKey),
        env.DB.prepare(`INSERT INTO audit_logs(id,organization_id,action,module,record_type,record_id,new_value_json) VALUES(?,?, 'module_expired','billing','module_subscription',?,?)`).bind(`audit-${requestId()}`,item.organizationId,item.moduleKey,JSON.stringify({expiredAt:new Date().toISOString()})),
      ]);
    }
    await syncExternalCalendars(env);
    const pending = await env.DB.prepare(`SELECT a.id, a.organization_id as organizationId, a.requester_id as requesterId, a.request_type as requestType, a.title, a.required_role as requiredRole, a.amount, a.due_at as dueAt, a.reminder_sent_at as reminderSentAt, a.escalated_at as escalatedAt, s.reminder_hours as reminderHours, s.escalation_role as escalationRole, os.financial_fallback_role as financialFallbackRole FROM approval_requests a LEFT JOIN workflow_sla_settings s ON s.organization_id = a.organization_id AND s.request_type = a.request_type LEFT JOIN organization_settings os ON os.organization_id = a.organization_id WHERE a.status = 'pending' AND a.due_at IS NOT NULL ORDER BY a.due_at LIMIT 500`).all<{ id: string; organizationId: string; requesterId: string; requestType: string; title: string; requiredRole: string; amount: number | null; dueAt: string; reminderSentAt: string | null; escalatedAt: string | null; reminderHours: number | null; escalationRole: string | null; financialFallbackRole: string | null }>();
    for (const item of pending.results || []) {
      const systemContext: AuthContext = { userId: item.requesterId, organizationId: item.organizationId, email: "", role: "System", isDemo: false, isPlatformAdmin: false, mfaMandatory: false, mfaEnrollmentRequired: false, permissions: new Set() };
      const overdue = Date.parse(`${item.dueAt.replace(" ", "T")}Z`) <= Date.now();
      const reminderDue = Date.parse(`${item.dueAt.replace(" ", "T")}Z`) - (item.reminderHours || 24) * 3600000 <= Date.now();
      const financial = item.amount !== null || ["expense","purchase","budget","payroll","reimbursement","payment","financial","asset purchase"].includes(item.requestType.toLowerCase());
      if (overdue && !item.escalatedAt) {
        const roles = financial ? [item.financialFallbackRole || "HR Admin"] : [item.escalationRole || "HR Admin", "CEO"];
        const changed = await env.DB.prepare(`UPDATE approval_requests SET escalated_at = CURRENT_TIMESTAMP, metadata_json = json_set(metadata_json, '$.fallbackActive', 1, '$.fallbackRoles', json(?), '$.fallbackAt', ?), updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = 'pending' AND escalated_at IS NULL`).bind(JSON.stringify(roles), new Date().toISOString(), item.id, item.organizationId).run();
        if (changed.meta.changes) for (const role of [...new Set(roles)]) await notifyApprovers(env, systemContext, role, item.title, `This approval is overdue (SLA due ${item.dueAt}). It has been escalated from ${item.requiredRole}.`);
      } else if (reminderDue && !item.reminderSentAt) {
        await env.DB.prepare(`UPDATE approval_requests SET reminder_sent_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND reminder_sent_at IS NULL`).bind(item.id, item.organizationId).run();
        await notifyApprovers(env, systemContext, item.requiredRole, item.title, `Reminder: approval is due by ${item.dueAt}. Please review the pending request.`);
      }
    }

    const dueCrmActivities = await env.DB.prepare(`SELECT id,organization_id as organizationId,owner_id as ownerId,subject,due_at as dueAt,reminder_sent_at as reminderSentAt,overdue_notified_at as overdueNotifiedAt FROM crm_activities WHERE status IN ('planned','in_progress') AND due_at IS NOT NULL AND due_at <= CURRENT_TIMESTAMP AND (reminder_sent_at IS NULL OR overdue_notified_at IS NULL) ORDER BY due_at LIMIT 500`).all<{id:string;organizationId:string;ownerId:string|null;subject:string;dueAt:string;reminderSentAt:string|null;overdueNotifiedAt:string|null}>();
    for(const activity of dueCrmActivities.results||[]){
      if(!activity.ownerId)continue;
      const overdue=Date.parse(`${activity.dueAt.replace(" ","T")}Z`)<Date.now();
      if(!activity.reminderSentAt){
        await env.DB.batch([
          env.DB.prepare(`INSERT INTO notifications (id,organization_id,user_id,type,title,body) VALUES (?,?,?,?,?,?)`).bind(requestId(),activity.organizationId,activity.ownerId,overdue?"crm_followup_overdue":"crm_followup_due",overdue?"CRM follow-up overdue":"CRM follow-up due",`${activity.subject}${overdue?` was due ${activity.dueAt} and is now overdue.`:` is due now (${activity.dueAt}).`}`),
          env.DB.prepare(`UPDATE crm_activities SET reminder_sent_at=CURRENT_TIMESTAMP,overdue_notified_at=CASE WHEN ?=1 THEN CURRENT_TIMESTAMP ELSE overdue_notified_at END WHERE id=? AND organization_id=? AND reminder_sent_at IS NULL`).bind(overdue?1:0,activity.id,activity.organizationId),
        ]);
        if(overdue)await env.DB.prepare(`INSERT INTO crm_events (id,organization_id,event_type,entity_type,entity_id,payload_json,status,processed_at) VALUES (?,?, 'followup.overdue','activity',?,?,'processed',CURRENT_TIMESTAMP)`).bind(requestId(),activity.organizationId,activity.id,JSON.stringify({subject:activity.subject,ownerId:activity.ownerId,dueAt:activity.dueAt})).run();
      }else if(overdue&&!activity.overdueNotifiedAt){
        await env.DB.batch([
          env.DB.prepare(`INSERT INTO notifications (id,organization_id,user_id,type,title,body) VALUES (?,?,?,'crm_followup_overdue','CRM follow-up overdue',?)`).bind(requestId(),activity.organizationId,activity.ownerId,`${activity.subject} is overdue (due ${activity.dueAt}).`),
          env.DB.prepare(`UPDATE crm_activities SET overdue_notified_at=CURRENT_TIMESTAMP WHERE id=? AND organization_id=? AND overdue_notified_at IS NULL`).bind(activity.id,activity.organizationId),
        ]);
        await env.DB.prepare(`INSERT INTO crm_events (id,organization_id,event_type,entity_type,entity_id,payload_json,status,processed_at) VALUES (?,?, 'followup.overdue','activity',?,?,'processed',CURRENT_TIMESTAMP)`).bind(requestId(),activity.organizationId,activity.id,JSON.stringify({subject:activity.subject,ownerId:activity.ownerId,dueAt:activity.dueAt})).run();
      }
    }

    const backupSchedules = await env.DB.prepare(`SELECT b.organization_id as organizationId, b.frequency, b.retention_days as retentionDays, b.alert_email as alertEmail, b.last_run_at as lastRunAt, m.user_id as createdBy FROM tenant_backup_settings b JOIN memberships m ON m.organization_id = b.organization_id AND m.status = 'active' WHERE b.enabled = 1 GROUP BY b.organization_id`).all<{ organizationId: string; frequency: string; retentionDays: number; alertEmail: string | null; lastRunAt: string | null; createdBy: string }>();
    for (const schedule of backupSchedules.results || []) {
      const interval = schedule.frequency === "weekly" ? 7 * 86400000 : 86400000;
      if (schedule.lastRunAt && Date.now() - Date.parse(`${schedule.lastRunAt.replace(" ", "T")}Z`) < interval) continue;
      try {
        const backup = await createTenantBackup(env, schedule.organizationId, schedule.createdBy);
        const stored = await getTenantBackupObject(env, schedule.organizationId, backup.id, backup.objectKey);
        const serialized = stored ? await stored.text() : "";
        let valid = Boolean(stored && await hashToken(serialized) === backup.checksum);
        if (valid) {
          try {
            const snapshot = JSON.parse(serialized) as { schemaVersion?: number; organizationId?: string; tables?: Record<string, unknown[]>; files?: { originalKey: string; backupKey: string }[] };
            valid = snapshot.schemaVersion === 1 && snapshot.organizationId === schedule.organizationId && !!snapshot.tables && !Array.isArray(snapshot.tables)
              && Object.values(snapshot.tables).every((rows) => Array.isArray(rows) && rows.every((row) => !!row && typeof row === "object" && (row as { organization_id?: unknown }).organization_id === schedule.organizationId))
              && Array.isArray(snapshot.files) && snapshot.files.every((file) => file && isTenantObjectKey(file.originalKey, schedule.organizationId) && isTenantBackupObjectKey(file.backupKey, schedule.organizationId, backup.id) && file.backupKey.includes("/files/"));
            if (valid) for (const file of snapshot.files || []) if (!await getTenantBackupObject(env, schedule.organizationId, backup.id, file.backupKey)) { valid = false; break; }
          } catch { valid = false; }
        }
        await env.DB.prepare(`UPDATE tenant_backup_settings SET last_run_at = CURRENT_TIMESTAMP, last_status = ?, last_error = ?, last_verified_at = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE last_verified_at END, updated_at = CURRENT_TIMESTAMP WHERE organization_id = ?`).bind(valid ? "success" : "verification_failed", valid ? null : "Snapshot checksum or restore preflight verification failed", valid ? 1 : 0, schedule.organizationId).run();
        if (!valid) throw new Error("Scheduled snapshot failed its checksum or non-destructive restore preflight verification.");
        const cutoff = new Date(Date.now() - schedule.retentionDays * 86400000).toISOString();
        const expired = await env.DB.prepare(`SELECT id, object_key as objectKey FROM tenant_backups WHERE organization_id = ? AND created_at < ?`).bind(schedule.organizationId, cutoff).all<{ id: string; objectKey: string }>();
        for (const row of expired.results || []) {
          if (isTenantBackupObjectKey(row.objectKey, schedule.organizationId, row.id)) await env.BACKUPS.delete(row.objectKey);
          let cursor: string | undefined;
          do { const prefix = `tenant-backups/${schedule.organizationId}/${row.id}/`; const listed = await env.BACKUPS.list({ prefix, cursor }); if (listed.objects.length) await Promise.all(listed.objects.map((object) => env.BACKUPS.delete(object.key))); cursor = listed.truncated ? listed.cursor : undefined; } while (cursor);
          cursor = undefined;
          do { const prefix = `tenant-backups/${schedule.organizationId}/${row.id}/`; const listed = await env.FILES.list({ prefix, cursor }); if (listed.objects.length) await Promise.all(listed.objects.map((object) => env.FILES.delete(object.key))); cursor = listed.truncated ? listed.cursor : undefined; } while (cursor);
          await env.DB.prepare(`DELETE FROM tenant_backups WHERE id = ? AND organization_id = ?`).bind(row.id, schedule.organizationId).run();
        }
      } catch (cause) {
        const message = cause instanceof Error ? cause.message.slice(0, 300) : "Unknown backup failure";
        await env.DB.prepare(`UPDATE tenant_backup_settings SET last_run_at = CURRENT_TIMESTAMP, last_status = 'failed', last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE organization_id = ?`).bind(message, schedule.organizationId).run();
        if (schedule.alertEmail) {
          const org = await env.DB.prepare(`SELECT name FROM organizations WHERE id = ?`).bind(schedule.organizationId).first<{ name: string }>();
          await sendApprovalNotificationEmail(env, schedule.alertEmail, "Administrator", org?.name || "Zyntris", "Scheduled backup failed", `The scheduled tenant backup failed: ${message}. Review organization settings and storage health.`);
        }
      }
    }
  },
};
