export interface Env {
  DB: D1Database;
  FILES: R2Bucket;
  ASSETS: Fetcher;
  APP_ORIGIN: string;
  ENVIRONMENT: string;
  SESSION_SECRET?: string;
  BREVO_API_KEY?: string;
  EMAIL_SENDER?: string;
  PLATFORM_ADMIN_EMAILS?: string;
  DEMO_ACCESS_PASSWORD?: string;
}

type AuthContext = {
  userId: string;
  organizationId: string;
  email: string;
  role: string;
  isDemo: boolean;
  isPlatformAdmin: boolean;
  permissions: Set<string>;
};

const json = (data: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(data), {
    ...init,
    headers: { "content-type": "application/json; charset=utf-8", ...(init.headers || {}) },
  });

const error = (message: string, status = 400) => json({ error: message }, { status });

const requestId = () => crypto.randomUUID();

function withSecurityHeaders(response: Response) {
  const headers = new Headers(response.headers);
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("referrer-policy", "strict-origin-when-cross-origin");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
  headers.set("content-security-policy", "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self' https://app.zyntris.org");
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

async function auth(request: Request, env: Env): Promise<AuthContext | null> {
  const mobileRequest = new URL(request.url).pathname.startsWith("/api/mobile/");
  const authorization = mobileRequest ? request.headers.get("authorization") : null;
  const token = authorization?.match(/^Bearer\s+([a-f0-9]{64})$/i)?.[1] || getCookie(request, "zyntris_session");
  if (!token) return null;
  const tokenHash = await hashToken(token);
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
  return {
    userId: result.userId,
    organizationId: result.organizationId,
    email: result.email,
    role: result.role,
    isDemo: result.isDemo === 1,
    isPlatformAdmin: platformEmails.includes(result.email.toLowerCase()),
    permissions: new Set((rows.results || []).map((row) => row.code)),
  };
}

function hasPermission(context: AuthContext, permission: string) {
  return context.permissions.has(permission);
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

async function passwordHash(password: string, salt = randomToken(16)) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  // Cloudflare Workers WebCrypto rejects PBKDF2 iteration counts above 100,000.
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: 100000 }, material, 256);
  const digest = [...new Uint8Array(bits)].map((part) => part.toString(16).padStart(2, "0")).join("");
  return `pbkdf2-sha256$100000$${salt}$${digest}`;
}

async function verifyPassword(password: string, encoded: string) {
  const [algorithm, rounds, salt, expected] = encoded.split("$");
  if (algorithm !== "pbkdf2-sha256" || rounds !== "100000" || !salt || !expected) return false;
  const actual = await passwordHash(password, salt);
  return safeEqual(actual.split("$")[3] || "", expected);
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
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "set-cookie": setCookie("zyntris_session", token, maxAge) } });
}

function originAllowed(request: Request, env: Env) {
  const origin = request.headers.get("origin");
  return !origin || origin === env.APP_ORIGIN;
}

async function consumeAuthLimit(env: Env, request: Request, action: string, limit: number, windowMinutes: number) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const key = `${action}:${await hashToken(ip)}`;
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

async function sendEmployeeInviteEmail(env: Env, email: string, fullName: string, organizationName: string, token: string) {
  if (!env.BREVO_API_KEY) return false;
  const url = `${env.APP_ORIGIN}/?invite=${encodeURIComponent(token)}`;
  const safe = (value: string) => value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[char] || char);
  const configuredSender = env.EMAIL_SENDER || "Zyntris <no-reply@zyntris.org>";
  const senderMatch = configuredSender.match(/^\s*(.*?)\s*<([^<>]+)>\s*$/);
  const sender = senderMatch ? { name: senderMatch[1] || "Zyntris", email: senderMatch[2] } : { name: "Zyntris", email: configuredSender.trim() };
  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST", headers: { "api-key": env.BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ sender, to: [{ email, name: fullName }], subject: `You’re invited to ${organizationName} on Zyntris`,
      textContent: `Hello ${fullName}, ${organizationName} invited you to its Zyntris workspace. Set up your account here: ${url}. This link expires in 72 hours.`,
      htmlContent: `<p>Hello ${safe(fullName)},</p><p>${safe(organizationName)} invited you to its Zyntris workspace.</p><p><a href="${url}">Accept invitation and set up your account</a></p><p>This link expires in 72 hours.</p>` }),
  });
  return response.ok;
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
  if (organization) await Promise.all(targets.map((approver) => sendApprovalNotificationEmail(env, approver.email, approver.fullName, organization.name, `Approval pending: ${subjectTitle}`, details)));
}

async function handlePublicAuth(request: Request, env: Env, path: string, mobile = false): Promise<Response | null> {
  if (request.method === "GET" && path === "/api/auth/config") return json({ emailVerificationEnabled: Boolean(env.BREVO_API_KEY), demoEnabled: Boolean(env.DEMO_ACCESS_PASSWORD) });
  if (request.method === "POST" && path === "/api/auth/accept-invite") {
    if (!originAllowed(request, env)) return error("Request origin rejected", 403);
    if (!(await consumeAuthLimit(env, request, "accept-invite", 10, 30))) return error("Too many attempts. Try again later.", 429);
    const body = await request.json<{ token?: string; password?: string }>();
    if (!body.token || body.token.length !== 64 || !body.password || body.password.length < 12 || body.password.length > 128) return error("Use a valid invitation and a password of at least 12 characters.");
    const invite = await env.DB.prepare(`SELECT i.id as inviteId, i.user_id as userId, i.organization_id as organizationId, i.employee_id as employeeId FROM employee_invites i JOIN users u ON u.id = i.user_id AND u.status = 'invited' JOIN employees e ON e.id = i.employee_id AND e.onboarding_status = 'invited' WHERE i.token_hash = ? AND i.accepted_at IS NULL AND i.expires_at > CURRENT_TIMESTAMP LIMIT 1`).bind(await hashToken(body.token)).first<{ inviteId: string; userId: string; organizationId: string; employeeId: string }>();
    if (!invite) return error("This invitation is invalid, expired, or already used.", 400);
    const claimedInvite = await env.DB.prepare(`UPDATE employee_invites SET accepted_at = CURRENT_TIMESTAMP WHERE id = ? AND accepted_at IS NULL AND expires_at > CURRENT_TIMESTAMP`).bind(invite.inviteId).run();
    if (!claimedInvite.meta.changes) return error("This invitation has already been used.", 409);
    await env.DB.batch([
      env.DB.prepare(`UPDATE users SET password_hash = ?, status = 'active', email_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(await passwordHash(body.password), invite.userId),
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
    const slug = `${organizationName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "organization"}-${orgId.slice(-8)}`;
    const token = randomToken();
    const now = new Date();
    try {
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO organizations (id, name, slug, industry, status) VALUES (?, ?, ?, ?, 'trial')`).bind(orgId, organizationName, slug, body.industry?.trim() || null),
        env.DB.prepare(`INSERT INTO organization_settings (organization_id) VALUES (?)`).bind(orgId),
        env.DB.prepare(`INSERT INTO users (id, email, full_name, password_hash, status) VALUES (?, ?, ?, ?, 'active')`).bind(userId, email, fullName, await passwordHash(password)),
        env.DB.prepare(`INSERT INTO roles (id, organization_id, name, description, is_system) VALUES (?, ?, 'Organization Admin', 'Organization owner and administrator', 1)`).bind(roleId, orgId),
        env.DB.prepare(`INSERT INTO roles (id, organization_id, name, description, is_system) VALUES (?, ?, 'HR Admin', 'Manage people, teams and onboarding', 1)`).bind(hrRoleId, orgId),
        env.DB.prepare(`INSERT INTO roles (id, organization_id, name, description, is_system) VALUES (?, ?, 'CEO', 'Executive review and final approvals', 1)`).bind(ceoRoleId, orgId),
        env.DB.prepare(`INSERT INTO roles (id, organization_id, name, description, is_system) VALUES (?, ?, 'Finance Admin', 'Manage finance operations and approvals', 1)`).bind(financeRoleId, orgId),
        env.DB.prepare(`INSERT INTO roles (id, organization_id, name, description, is_system) VALUES (?, ?, 'Manager', 'Manage team work and submit approvals', 1)`).bind(managerRoleId, orgId),
        env.DB.prepare(`INSERT INTO roles (id, organization_id, name, description, is_system) VALUES (?, ?, 'Employee', 'Standard employee workspace access', 1)`).bind(employeeRoleId, orgId),
        env.DB.prepare(`INSERT INTO memberships (id, organization_id, user_id, role_id) VALUES (?, ?, ?, ?)`).bind(`mem-${crypto.randomUUID()}`, orgId, userId, roleId),
        env.DB.prepare(`INSERT INTO subscriptions (id, organization_id, plan, status, employee_limit, trial_ends_at) VALUES (?, ?, 'business', 'trialing', 100, datetime('now', '+30 days'))`).bind(subscriptionId, orgId),
        env.DB.prepare(`INSERT INTO payroll_settings (organization_id, currency, tax_year) VALUES (?, 'NGN', ?)`).bind(orgId, now.getUTCFullYear()),
        env.DB.prepare(`INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now', '+24 hours'))`).bind(`evt-${crypto.randomUUID()}`, userId, await hashToken(token)),
        env.DB.prepare(`INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions`).bind(roleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE code IN ('employees.view','employees.manage','payroll.view','payroll.manage','payroll.run','hr.onboarding.approve','roles.manage','teams.manage','operations.view')`).bind(hrRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE code IN ('employees.view','payroll.view','payroll.approve','requests.manage','hr.onboarding.approve','operations.view','operations.manage','expenses.view','expenses.manage')`).bind(ceoRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE code IN ('payroll.view','payroll.run','payroll.approve','expenses.view','expenses.manage','requests.manage','operations.view','operations.manage')`).bind(financeRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE code IN ('employees.view','operations.view','expenses.view','payroll.self.view')`).bind(employeeRoleId),
        env.DB.prepare(`INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE code IN ('employees.view','operations.view','operations.manage','expenses.view','requests.manage','payroll.self.view')`).bind(managerRoleId),
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
    ]);
    const session = await createSession(env, row.userId, row.organizationId);
    return cookieResponse({ ok: true }, session);
  }
  if (request.method === "POST" && path === "/api/auth/2fa/verify") {
    if (!mobile && !originAllowed(request, env)) return error("Request origin rejected", 403);
    if (!(await consumeAuthLimit(env, request, "2fa-verify", 12, 15))) return error("Too many verification attempts. Try again later.", 429);
    const body = await request.json<{ challengeToken?: string; code?: string }>();
    if (!body.challengeToken || body.challengeToken.length !== 64 || !body.code || body.code.length > 32) return error("Enter your six-digit authenticator code or a recovery code.");
    const challenge = await env.DB.prepare(`SELECT id, user_id as userId, organization_id as organizationId, is_mobile as isMobile, attempts FROM two_factor_challenges WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP LIMIT 1`)
      .bind(await hashToken(body.challengeToken)).first<{ id: string; userId: string; organizationId: string; isMobile: number; attempts: number }>();
    if (!challenge || challenge.isMobile !== (mobile ? 1 : 0)) return error("This sign-in challenge is invalid or expired. Sign in again.", 401);
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
    const user = await env.DB.prepare(`SELECT id, password_hash as passwordHash, email_verified_at as verifiedAt, status FROM users WHERE email = ?`).bind(email).first<{ id: string; passwordHash: string | null; verifiedAt: string | null; status: string }>();
    if (!user?.passwordHash || user.status !== "active" || !(await verifyPassword(body.password || "", user.passwordHash))) return error("Email or password is incorrect.", 401);
    if (!user.verifiedAt) return error("Please verify your email address before signing in.", 403);
    const membership = await env.DB.prepare(`SELECT organization_id as organizationId FROM memberships WHERE user_id = ? AND status = 'active' ORDER BY created_at LIMIT 1`).bind(user.id).first<{ organizationId: string }>();
    if (!membership) return error("No active organization is linked to this account.", 403);
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

async function audit(env: Env, context: AuthContext, action: string, module: string, recordId?: string, newValue?: unknown) {
  await env.DB.prepare(`INSERT INTO audit_logs (id, organization_id, actor_user_id, action, module, record_id, new_value_json) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .bind(requestId(), context.organizationId, context.userId, action, module, recordId || null, newValue ? JSON.stringify(newValue) : null).run();
}

async function dashboard(env: Env, organizationId: string) {
  const [people, leave, projects, tasks, expenses, departments, recentActivity] = await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active, SUM(CASE WHEN status = 'on_leave' THEN 1 ELSE 0 END) as onLeave FROM employees WHERE organization_id = ? AND deleted_at IS NULL`).bind(organizationId).first<{ total: number; active: number; onLeave: number }>(),
    env.DB.prepare(`SELECT COUNT(*) as pending FROM leave_requests WHERE organization_id = ? AND status = 'pending'`).bind(organizationId).first<{ pending: number }>(),
    env.DB.prepare(`SELECT COUNT(*) as active FROM projects WHERE organization_id = ? AND status IN ('active','at_risk')`).bind(organizationId).first<{ active: number }>(),
    env.DB.prepare(`SELECT COUNT(*) as overdue FROM tasks WHERE organization_id = ? AND status != 'completed' AND due_date < date('now')`).bind(organizationId).first<{ overdue: number }>(),
    env.DB.prepare(`SELECT COALESCE(SUM(amount),0) as total FROM expenses WHERE organization_id = ? AND strftime('%Y-%m', expense_date) = strftime('%Y-%m', 'now')`).bind(organizationId).first<{ total: number }>(),
    env.DB.prepare(`SELECT d.name, COUNT(e.id) as count FROM departments d LEFT JOIN employees e ON e.department_id = d.id AND e.deleted_at IS NULL WHERE d.organization_id = ? GROUP BY d.id ORDER BY count DESC`).bind(organizationId).all(),
    env.DB.prepare(`SELECT action, module, created_at FROM audit_logs WHERE organization_id = ? ORDER BY created_at DESC LIMIT 6`).bind(organizationId).all(),
  ]);
  return { people: people || { total: 0, active: 0, onLeave: 0 }, leave: leave || { pending: 0 }, projects: projects || { active: 0 }, tasks: tasks || { overdue: 0 }, expenses: expenses || { total: 0 }, departments: departments.results || [], recentActivity: recentActivity.results || [] };
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
    const user = await env.DB.prepare(`SELECT id, password_hash as passwordHash, email_verified_at as verifiedAt, status FROM users WHERE email = ?`).bind(email).first<{ id: string; passwordHash: string | null; verifiedAt: string | null; status: string }>();
    if (!user?.passwordHash || user.status !== "active" || !(await verifyPassword(body.password || "", user.passwordHash))) return error("Email or password is incorrect.", 401);
    if (!user.verifiedAt) return error("Please verify your email address before signing in.", 403);
    const membership = await env.DB.prepare(`SELECT organization_id as organizationId FROM memberships WHERE user_id = ? AND status = 'active' ORDER BY created_at LIMIT 1`).bind(user.id).first<{ organizationId: string }>();
    if (!membership) return error("No active organization is linked to this account.", 403);
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
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json", "set-cookie": setCookie("zyntris_session", "", 0) } });
  }

  const secured = await requireAuth(request, env);
  if ("response" in secured && secured.response) return secured.response;
  const context = secured.context;

  if (context.isDemo && ["POST", "PUT", "PATCH", "DELETE"].includes(request.method)) return error("The demo sandbox is read-only. Changes are not allowed.", 403);

  if (request.method === "GET" && path === "/api/auth/2fa/status") {
    const [factor, recovery] = await Promise.all([
      env.DB.prepare(`SELECT enabled_at as enabledAt FROM user_two_factor WHERE user_id = ?`).bind(context.userId).first<{ enabledAt: string | null }>(),
      env.DB.prepare(`SELECT COUNT(*) as remaining FROM two_factor_recovery_codes WHERE user_id = ? AND used_at IS NULL`).bind(context.userId).first<{ remaining: number }>(),
    ]);
    return json({ enabled: Boolean(factor?.enabledAt), enabledAt: factor?.enabledAt || null, recoveryCodesRemaining: recovery?.remaining || 0 });
  }

  if (request.method === "POST" && path === "/api/auth/2fa/setup") {
    const body = await request.json<{ password?: string }>();
    if (!body.password || body.password.length > 128) return error("Enter your current password to set up two-factor authentication.");
    const user = await env.DB.prepare(`SELECT password_hash as passwordHash FROM users WHERE id = ? AND status = 'active'`).bind(context.userId).first<{ passwordHash: string | null }>();
    if (!user?.passwordHash || !(await verifyPassword(body.password, user.passwordHash))) return error("Your current password is incorrect.", 401);
    const current = await env.DB.prepare(`SELECT enabled_at as enabledAt FROM user_two_factor WHERE user_id = ?`).bind(context.userId).first<{ enabledAt: string | null }>();
    if (current?.enabledAt) return error("Two-factor authentication is already enabled.", 409);
    const secret = base32Encode(crypto.getRandomValues(new Uint8Array(20)));
    const encrypted = await encryptTwoFactorSecret(env, secret);
    await env.DB.prepare(`INSERT INTO user_two_factor (user_id, pending_secret_enc, pending_expires_at) VALUES (?, ?, datetime('now', '+10 minutes'))
      ON CONFLICT(user_id) DO UPDATE SET pending_secret_enc = excluded.pending_secret_enc, pending_expires_at = excluded.pending_expires_at, updated_at = CURRENT_TIMESTAMP WHERE user_two_factor.enabled_at IS NULL`)
      .bind(context.userId, encrypted).run();
    const account = encodeURIComponent(`${context.email} (Zyntris)`);
    const issuer = encodeURIComponent("Zyntris");
    const provisioningUri = `otpauth://totp/${account}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    await audit(env, context, "two_factor_setup_started", "authentication");
    return json({ secret, provisioningUri, expiresIn: 600 });
  }

  if (request.method === "POST" && path === "/api/auth/2fa/enable") {
    const body = await request.json<{ code?: string }>();
    const pending = await env.DB.prepare(`SELECT pending_secret_enc as secretEnc FROM user_two_factor WHERE user_id = ? AND enabled_at IS NULL AND pending_expires_at > CURRENT_TIMESTAMP`).bind(context.userId).first<{ secretEnc: string | null }>();
    if (!pending?.secretEnc || !body.code) return error("Start setup again; the authenticator setup has expired.", 409);
    const counter = await matchTotp(await decryptTwoFactorSecret(env, pending.secretEnc), body.code);
    if (counter === null) return error("That code is not valid yet. Check your device time and try again.", 401);
    const codes = makeRecoveryCodes();
    const updated = await env.DB.prepare(`UPDATE user_two_factor SET secret_enc = pending_secret_enc, pending_secret_enc = NULL, pending_expires_at = NULL, enabled_at = CURRENT_TIMESTAMP, last_counter = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND enabled_at IS NULL AND pending_secret_enc = ? AND pending_expires_at > CURRENT_TIMESTAMP`)
      .bind(counter - 1, context.userId, pending.secretEnc).run();
    if (!updated.meta.changes) return error("Setup expired or was already completed. Start setup again.", 409);
    const codeHashes = await Promise.all(codes.map((code) => hashToken(code.replace(/-/g, "").toLowerCase())));
    await env.DB.batch(codes.map((_, index) => env.DB.prepare(`INSERT INTO two_factor_recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)`)
      .bind(requestId(), context.userId, codeHashes[index])));
    await audit(env, context, "two_factor_enabled", "authentication");
    return json({ ok: true, recoveryCodes: codes });
  }

  if (request.method === "POST" && path === "/api/auth/2fa/disable") {
    const body = await request.json<{ password?: string; code?: string }>();
    const user = await env.DB.prepare(`SELECT password_hash as passwordHash FROM users WHERE id = ? AND status = 'active'`).bind(context.userId).first<{ passwordHash: string | null }>();
    if (!user?.passwordHash || !(await verifyPassword(body.password || "", user.passwordHash))) return error("Your current password is incorrect.", 401);
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
    if (request.method !== "GET") return error("Platform console endpoints are read-only.", 405);

    if (path === "/api/platform/summary") {
      const summary = await env.DB.prepare(`
        SELECT COUNT(*) as organizations,
          SUM(CASE WHEN o.status = 'active' THEN 1 ELSE 0 END) as active,
          SUM(CASE WHEN o.status = 'trial' OR s.status = 'trialing' THEN 1 ELSE 0 END) as trialing,
          SUM(CASE WHEN o.status = 'suspended' OR s.status = 'suspended' THEN 1 ELSE 0 END) as suspended,
          (SELECT COUNT(*) FROM users u WHERE EXISTS (SELECT 1 FROM memberships m JOIN organizations o2 ON o2.id = m.organization_id WHERE m.user_id = u.id AND o2.is_demo = 0)) as users,
          (SELECT COUNT(*) FROM employees e JOIN organizations o3 ON o3.id = e.organization_id WHERE o3.is_demo = 0 AND e.deleted_at IS NULL) as employees
        FROM organizations o LEFT JOIN subscriptions s ON s.organization_id = o.id
        WHERE o.is_demo = 0
      `).first();
      return json(summary || { organizations: 0, active: 0, trialing: 0, suspended: 0, users: 0, employees: 0 });
    }

    if (path === "/api/platform/organizations") {
      const search = url.searchParams.get("search")?.trim().slice(0, 100) || "";
      const limit = Math.max(1, Math.min(Number(url.searchParams.get("limit")) || 50, 100));
      const offset = Math.max(0, Math.min(Number(url.searchParams.get("offset")) || 0, 1000000));
      const condition = `o.is_demo = 0 AND (? = '' OR o.name LIKE '%' || ? || '%' OR o.slug LIKE '%' || ? || '%' OR COALESCE(o.industry, '') LIKE '%' || ? || '%')`;
      const [total, organizations] = await Promise.all([
        env.DB.prepare(`SELECT COUNT(*) as total FROM organizations o WHERE ${condition}`).bind(search, search, search, search).first<{ total: number }>(),
        env.DB.prepare(`
          SELECT o.id, o.name, o.slug, o.industry, o.status, o.created_at as createdAt,
            s.plan, s.status as subscriptionStatus, s.trial_ends_at as trialEndsAt,
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
      const condition = `o.is_demo = 0 AND (? = '' OR o.id = ?)`;
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
    const user = await env.DB.prepare(`SELECT u.id, u.email, u.full_name as fullName, r.name as role, o.id as organizationId, o.name as organizationName, s.trial_ends_at as trialEndsAt FROM users u JOIN memberships m ON m.user_id = u.id JOIN roles r ON r.id = m.role_id JOIN organizations o ON o.id = m.organization_id LEFT JOIN subscriptions s ON s.organization_id = o.id WHERE u.id = ? AND o.id = ?`).bind(context.userId, context.organizationId).first();
    return json({ ...(user || { id: context.userId, role: context.role, organizationId: context.organizationId }), permissions: [...context.permissions], isPlatformAdmin: context.isPlatformAdmin, isDemo: context.isDemo });
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

  if (request.method === "GET" && path === "/api/payroll/my-payslips") {
    if (!hasPermission(context, "payroll.self.view")) return error("Employee payslip access is not enabled for this account.", 403);
    const employee = await env.DB.prepare(`SELECT id FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string }>();
    if (!employee) return json({ data: [] });
    const result = await env.DB.prepare(`SELECT i.id, i.employee_number as employeeNumber, i.employee_name as employeeName, i.job_title as jobTitle, r.period_start as periodStart, r.period_end as periodEnd, r.payment_date as payDate, r.currency, r.status as runStatus, i.gross_pay as grossPay, i.paye_tax as payeTax, i.employee_pension as employeePension, i.other_deductions as otherDeductions, i.net_pay as netPay, i.breakdown_json as breakdownJson FROM payroll_run_items i JOIN payroll_runs r ON r.id = i.payroll_run_id AND r.organization_id = i.organization_id JOIN employees e ON e.id = i.employee_id AND e.organization_id = i.organization_id WHERE i.organization_id = ? AND e.id = ? AND r.status IN ('approved','paid') ORDER BY r.period_end DESC LIMIT 100`).bind(context.organizationId, employee.id).all();
    return json({ data: result.results || [] });
  }
  if (path.startsWith("/api/payroll") && !hasPermission(context, "payroll.view") && !hasPermission(context, "payroll.manage")) return error("You do not have permission to access the payroll administration workspace.", 403);

  if (path.startsWith("/api/hr/") && !hasPermission(context, "employees.view")) return error("You do not have permission to access HR records.", 403);
  const operationsPaths = ["/api/tasks", "/api/projects", "/api/assets", "/api/vendors", "/api/tickets", "/api/calendar", "/api/customers", "/api/files"];
  const operationsPath = operationsPaths.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
  if (operationsPath && !hasPermission(context, "operations.view")) return error("You do not have access to operations modules.", 403);
  if (operationsPath && request.method !== "GET" && !(path === "/api/tickets" && request.method === "POST") && !hasPermission(context, "operations.manage")) return error("Operations manager permission is required for this change.", 403);

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

  if (request.method === "POST" && path === "/api/hr/teams") {
    if (!hasPermission(context, "teams.manage")) return error("You do not have permission to manage departments and teams.", 403);
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
    const validBands = Array.isArray(body.taxBands) && body.taxBands.length <= 20 && body.taxBands.every((band) => Number.isFinite(band.rate) && band.rate >= 0 && band.rate <= 1 && (band.upTo === null || (Number.isFinite(band.upTo) && band.upTo > 0)));
    if (!body.currency || !/^[A-Z]{3}$/.test(body.currency) || !["weekly", "biweekly", "semimonthly", "monthly"].includes(body.payFrequency || "") || !body.taxCountry || !validBands || !Number.isFinite(body.taxFreeAllowance) || Number(body.taxFreeAllowance) < 0 || !Number.isFinite(body.employeePensionRate) || Number(body.employeePensionRate) < 0 || Number(body.employeePensionRate) > 1 || !Number.isFinite(body.employerPensionRate) || Number(body.employerPensionRate) < 0 || Number(body.employerPensionRate) > 1 || !["base_salary", "gross"].includes(body.pensionBasis || "")) return error("Payroll settings are incomplete or invalid.");
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
    if (!body.employeeId || !Number.isFinite(salary) || salary < 0 || !body.effectiveFrom || !body.currency || !/^[A-Z]{3}$/.test(body.currency)) return error("Employee, valid salary, currency and effective date are required.");
    if (!(await env.DB.prepare(`SELECT id FROM employees WHERE id = ? AND organization_id = ? AND deleted_at IS NULL`).bind(body.employeeId, context.organizationId).first())) return error("Employee not found.", 404);
    let bankDetails: string | null = null;
    if (body.bankName || body.accountName || body.accountNumber) {
      const bankName = body.bankName?.trim() || ""; const accountName = body.accountName?.trim() || ""; const accountNumber = body.accountNumber?.replace(/[\s-]/g, "") || "";
      if (!bankName || !accountName || !/^[a-zA-Z0-9]{4,34}$/.test(accountNumber)) return error("Enter the bank name, account name and a valid account number (4–34 letters or digits).");
      try { bankDetails = await encryptBankDetails(env, { bankName, accountName, accountNumber }); }
      catch { return error("Encrypted bank-record storage is unavailable. Configure SESSION_SECRET before saving account details.", 503); }
    }
    await env.DB.prepare(`INSERT INTO employee_pay_profiles (id, organization_id, employee_id, base_salary, currency, pay_frequency, effective_from, bank_details_enc, tax_reference, pension_reference) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(organization_id, employee_id) DO UPDATE SET base_salary=excluded.base_salary, currency=excluded.currency, pay_frequency=excluded.pay_frequency, effective_from=excluded.effective_from, bank_details_enc=COALESCE(excluded.bank_details_enc, employee_pay_profiles.bank_details_enc), tax_reference=excluded.tax_reference, pension_reference=excluded.pension_reference, status='active', updated_at=CURRENT_TIMESTAMP`)
      .bind(`pay-${crypto.randomUUID()}`, context.organizationId, body.employeeId, salary, body.currency, body.payFrequency || "monthly", body.effectiveFrom, bankDetails, body.taxReference?.trim() || null, body.pensionReference?.trim() || null).run();
    await audit(env, context, "updated", "employee_pay_profiles", body.employeeId, { baseSalary: salary, currency: body.currency, bankDetailsRecorded: Boolean(bankDetails) });
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
    if (!employee || !component || !Number.isFinite(amount) || amount < 0 || !body.effectiveFrom) return error("Employee, pay component, non-negative amount and effective date are required.");
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
    const runs = await env.DB.prepare(`SELECT id, period_start as periodStart, period_end as periodEnd, payment_date as paymentDate, currency, status, employee_count as employeeCount, gross_total as grossTotal, deductions_total as deductionsTotal, employer_cost_total as employerCostTotal, net_total as netTotal, created_at as createdAt FROM payroll_runs WHERE organization_id = ? ORDER BY period_start DESC LIMIT 100`).bind(context.organizationId).all();
    return json({ data: runs.results || [] });
  }

  if (request.method === "POST" && path === "/api/payroll/runs") {
    if (!hasPermission(context, "payroll.run")) return error("Payroll run permission required.", 403);
    const body = await request.json<{ periodStart?: string; periodEnd?: string; paymentDate?: string; adjustments?: { employeeId: string; label: string; kind: "earning" | "deduction"; amount: number }[] }>();
    if (!body.periodStart || !body.periodEnd || !body.paymentDate || body.periodEnd < body.periodStart || !/^\d{4}-\d{2}-\d{2}$/.test(body.periodStart) || !/^\d{4}-\d{2}-\d{2}$/.test(body.periodEnd)) return error("A valid period and payment date are required.");
    const config = await env.DB.prepare(`SELECT currency, tax_free_allowance as taxFreeAllowance, tax_bands_json as taxBandsJson, employee_pension_rate as employeePensionRate, employer_pension_rate as employerPensionRate, pension_basis as pensionBasis FROM payroll_settings WHERE organization_id = ?`).bind(context.organizationId).first<{ currency: string; taxFreeAllowance: number; taxBandsJson: string; employeePensionRate: number; employerPensionRate: number; pensionBasis: string }>();
    if (!config) return error("Configure payroll settings before running payroll.", 409);
    const employees = await env.DB.prepare(`SELECT e.id as employeeId, e.employee_number as employeeNumber, e.first_name as firstName, e.last_name as lastName, e.job_title as jobTitle, e.start_date as startDate, p.base_salary as baseSalary, p.currency as payCurrency, c.id as componentId, c.code as componentCode, c.name as componentName, c.kind as componentKind, c.taxable, c.pensionable, ec.amount as componentAmount FROM employees e JOIN employee_pay_profiles p ON p.employee_id = e.id AND p.organization_id = e.organization_id AND p.status = 'active' AND p.pay_frequency = (SELECT pay_frequency FROM payroll_settings WHERE organization_id = e.organization_id) LEFT JOIN employee_pay_components ec ON ec.employee_id = e.id AND ec.organization_id = e.organization_id AND ec.effective_from <= ? AND (ec.effective_to IS NULL OR ec.effective_to >= ?) LEFT JOIN payroll_components c ON c.id = ec.component_id AND c.organization_id = e.organization_id WHERE e.organization_id = ? AND e.status = 'active' AND e.deleted_at IS NULL ORDER BY e.employee_number`).bind(body.periodEnd, body.periodStart, context.organizationId).all<Record<string, unknown>>();
    const byEmployee = new Map<string, Record<string, unknown>[]>();
    for (const employee of employees.results || []) { const list = byEmployee.get(String(employee.employeeId)) || []; list.push(employee); byEmployee.set(String(employee.employeeId), list); }
    if (!byEmployee.size) return error("Add active employees and pay profiles before creating a run.", 409);
    const adjustments = body.adjustments || [];
    if (adjustments.length > 1000 || adjustments.some((item) => !byEmployee.has(item.employeeId) || !item.label.trim() || !["earning", "deduction"].includes(item.kind) || !Number.isFinite(item.amount) || item.amount < 0)) return error("Payroll adjustments contain invalid employee, type or amount.");
    let taxBands: { upTo: number | null; rate: number }[];
    try { taxBands = JSON.parse(config.taxBandsJson) as { upTo: number | null; rate: number }[]; } catch { return error("Tax bands are invalid. Save payroll settings again.", 409); }
    if (!taxBands.length) return error("Add effective tax bands in Payroll settings before running payroll.", 409);
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
      const prorationDays = Math.max(0, Math.min(1, (new Date(body.periodEnd).getTime() - new Date(String(employee.startDate)).getTime() + 86400000) / (new Date(body.periodEnd).getTime() - new Date(body.periodStart).getTime() + 86400000)));
      const factor = String(employee.startDate) > body.periodStart ? prorationDays : 1;
      const prorate = (value: number) => Math.round(value * factor * 100) / 100;
      calculated.push({ id: `pri-${crypto.randomUUID()}`, employeeId, employeeNumber: String(employee.employeeNumber), employeeName: `${employee.firstName} ${employee.lastName}`, jobTitle: String(employee.jobTitle), baseSalary: prorate(baseSalary), gross: prorate(gross), taxable: prorate(taxable), tax: prorate(tax), employeePension: prorate(employeePension), employerPension: prorate(employerPension), otherDeductions: prorate(otherDeductions), employerContributions: prorate(employerContributions), net: prorate(net), breakdown: { currency: config.currency, lines, prorated: factor !== 1, prorationFactor: factor, taxBands } });
    }
    const sum = (key: "gross" | "tax" | "employeePension" | "employerPension" | "otherDeductions" | "employerContributions" | "net") => calculated.reduce((total, item) => total + item[key], 0);
    const statements: D1PreparedStatement[] = [env.DB.prepare(`INSERT INTO payroll_runs (id, organization_id, period_start, period_end, payment_date, currency, status, employee_count, gross_total, deductions_total, employer_cost_total, net_total, created_by) VALUES (?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?)`)
      .bind(runId, context.organizationId, body.periodStart, body.periodEnd, body.paymentDate, config.currency, calculated.length, sum("gross"), sum("tax") + sum("employeePension") + sum("otherDeductions"), sum("gross") + sum("employerPension") + sum("employerContributions"), sum("net"), context.userId)];
    for (const item of calculated) statements.push(env.DB.prepare(`INSERT INTO payroll_run_items (id, organization_id, payroll_run_id, employee_id, employee_number, employee_name, job_title, base_salary, gross_pay, taxable_pay, paye_tax, employee_pension, employer_pension, other_deductions, employer_contributions, net_pay, breakdown_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(item.id, context.organizationId, runId, item.employeeId, item.employeeNumber, item.employeeName, item.jobTitle, item.baseSalary, item.gross, item.taxable, item.tax, item.employeePension, item.employerPension, item.otherDeductions, item.employerContributions, item.net, JSON.stringify(item.breakdown)));
    await env.DB.batch(statements);
    await audit(env, context, "created", "payroll_runs", runId, { periodStart: body.periodStart, periodEnd: body.periodEnd, employeeCount: calculated.length });
    await notifyApprovers(env, context, "Finance Admin", `Payroll run · ${body.periodStart} to ${body.periodEnd}`, `A payroll run covering ${calculated.length} employees is ready for finance review.`);
    return json({ id: runId, employeeCount: calculated.length, status: "draft" }, { status: 201 });
  }

  const payrollRunMatch = path.match(/^\/api\/payroll\/runs\/([^/]+)(?:\/(action|payslips|export|payout))?$/);
  if (payrollRunMatch && request.method === "GET") {
    if (!hasPermission(context, "payroll.view") && !hasPermission(context, "payroll.manage")) return error("Payroll viewing permission is required.", 403);
    const runId = payrollRunMatch[1];
    const run = await env.DB.prepare(`SELECT id, period_start as periodStart, period_end as periodEnd, payment_date as paymentDate, currency, status, employee_count as employeeCount, gross_total as grossTotal, deductions_total as deductionsTotal, employer_cost_total as employerCostTotal, net_total as netTotal, created_at as createdAt FROM payroll_runs WHERE id = ? AND organization_id = ?`).bind(runId, context.organizationId).first();
    if (!run) return error("Payroll run not found.", 404);
    const items = await env.DB.prepare(`SELECT id, employee_id as employeeId, employee_number as employeeNumber, employee_name as employeeName, job_title as jobTitle, base_salary as baseSalary, gross_pay as grossPay, taxable_pay as taxablePay, paye_tax as payeTax, employee_pension as employeePension, employer_pension as employerPension, other_deductions as otherDeductions, employer_contributions as employerContributions, net_pay as netPay, breakdown_json as breakdownJson FROM payroll_run_items WHERE payroll_run_id = ? AND organization_id = ? ORDER BY employee_name`).bind(runId, context.organizationId).all();
    if (payrollRunMatch[2] === "export") {
      const headers = ["Employee number", "Employee", "Job title", "Base salary", "Gross pay", "PAYE", "Employee pension", "Other deductions", "Net pay", "Employer pension", "Employer contributions"];
      const values = (items.results || []).map((row: Record<string, unknown>) => [row.employeeNumber, row.employeeName, row.jobTitle, row.baseSalary, row.grossPay, row.payeTax, row.employeePension, row.otherDeductions, row.netPay, row.employerPension, row.employerContributions]);
      const csv = [headers, ...values].map((row) => row.map((value) => `"${String(value ?? "").replace(/"/g, '""')}"`).join(",")).join("\r\n");
      return new Response(csv, { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="zyntris-payroll-${runId}.csv"` } });
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
    return json(await dashboard(env, context.organizationId));
  }

  if (request.method === "GET" && path === "/api/employees") {
    if (!hasPermission(context, "employees.view")) return error("You do not have permission to view employee records.", 403);
    const query = url.searchParams.get("q")?.trim();
    const result = await env.DB.prepare(`
      SELECT e.id, e.employee_number as employeeNumber, e.first_name as firstName, e.last_name as lastName, e.email, e.job_title as jobTitle, e.status, e.onboarding_status as onboardingStatus, e.work_location as workLocation, e.start_date as startDate, e.avatar_color as avatarColor, d.name as department, t.name as team, r.name as accessRole
      FROM employees e LEFT JOIN departments d ON d.id = e.department_id LEFT JOIN teams t ON t.id = e.team_id LEFT JOIN memberships m ON m.user_id = e.user_id AND m.organization_id = e.organization_id LEFT JOIN roles r ON r.id = m.role_id
      WHERE e.organization_id = ? AND e.deleted_at IS NULL AND (? IS NULL OR e.first_name || ' ' || e.last_name LIKE '%' || ? || '%' OR e.employee_number LIKE '%' || ? || '%')
      ORDER BY e.first_name ASC
    `).bind(context.organizationId, query || null, query || null, query || null).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/employees") {
    if (!hasPermission(context, "employees.manage")) return error("HR administrator permission is required to onboard employees.", 403);
    if (!env.BREVO_API_KEY) return error("Employee invitations are unavailable until the organization email sender is configured.", 503);
    const body = await request.json<{ firstName?: string; lastName?: string; email?: string; jobTitle?: string; departmentName?: string; teamName?: string; roleName?: string; startDate?: string; employmentType?: string; workLocation?: string }>();
    const firstName = body.firstName?.trim(); const lastName = body.lastName?.trim(); const email = body.email?.trim().toLowerCase(); const jobTitle = body.jobTitle?.trim();
    if (!firstName || !lastName || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !jobTitle || !body.startDate || !/^\d{4}-\d{2}-\d{2}$/.test(body.startDate)) return error("Enter a valid name, work email, job title and start date.");
    const roleName = body.roleName?.trim() || "Employee";
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
        env.DB.prepare(`INSERT INTO employees (id, organization_id, user_id, employee_number, first_name, last_name, email, job_title, department_id, team_id, employment_type, work_location, status, onboarding_status, start_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'inactive', 'invited', ?)`)
          .bind(id, context.organizationId, userId, employeeNumber, firstName, lastName, email, jobTitle, departmentId, teamId, body.employmentType || "Full-time", body.workLocation || "Hybrid", body.startDate),
        env.DB.prepare(`INSERT INTO employee_invites (id, organization_id, employee_id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?, ?, datetime('now', '+72 hours'))`).bind(inviteId, context.organizationId, id, userId, await hashToken(token)),
      ]);
      if (!await sendEmployeeInviteEmail(env, email, `${firstName} ${lastName}`, organization?.name || "your organization", token)) throw new Error("Brevo rejected invitation email");
    } catch (cause) {
      console.error("Employee invitation failed", cause);
      await env.DB.batch([
        env.DB.prepare(`DELETE FROM employee_invites WHERE id = ?`).bind(inviteId),
        env.DB.prepare(`DELETE FROM employees WHERE id = ? AND organization_id = ?`).bind(id, context.organizationId),
        env.DB.prepare(`DELETE FROM memberships WHERE user_id = ? AND organization_id = ?`).bind(userId, context.organizationId),
        env.DB.prepare(`DELETE FROM users WHERE id = ? AND status = 'invited'`).bind(userId),
      ]);
      return error("We couldn’t deliver the onboarding invitation. Confirm the Brevo sender and try again.", 503);
    }
    await audit(env, context, "invited", "employees", id, { employeeNumber, role: roleName, department: departmentName || null, team: teamName || null });
    return json({ id, employeeNumber, onboardingStatus: "invited", accessRole: roleName }, { status: 201 });
  }

  const employeeInviteMatch = path.match(/^\/api\/employees\/([^/]+)\/invite$/);
  if (request.method === "POST" && employeeInviteMatch) {
    if (!hasPermission(context, "employees.manage")) return error("HR administrator permission is required.", 403);
    const employee = await env.DB.prepare(`SELECT e.id, e.user_id as userId, e.email, e.first_name as firstName, e.last_name as lastName, o.name as organizationName FROM employees e JOIN organizations o ON o.id = e.organization_id WHERE e.id = ? AND e.organization_id = ? AND e.onboarding_status = 'invited' AND e.deleted_at IS NULL`).bind(employeeInviteMatch[1], context.organizationId).first<{ id: string; userId: string; email: string; firstName: string; lastName: string; organizationName: string }>();
    if (!employee?.userId) return error("No pending employee invitation was found.", 404);
    const token = randomToken(); const inviteId = `inv-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO employee_invites (id, organization_id, employee_id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?, ?, datetime('now', '+72 hours'))`).bind(inviteId, context.organizationId, employee.id, employee.userId, await hashToken(token)).run();
    if (!await sendEmployeeInviteEmail(env, employee.email, `${employee.firstName} ${employee.lastName}`, employee.organizationName, token)) {
      await env.DB.prepare(`DELETE FROM employee_invites WHERE id = ?`).bind(inviteId).run();
      return error("We couldn’t deliver the invitation. Confirm the Brevo sender and try again.", 503);
    }
    await env.DB.prepare(`UPDATE employee_invites SET accepted_at = CURRENT_TIMESTAMP WHERE employee_id = ? AND id != ? AND accepted_at IS NULL`).bind(employee.id, inviteId).run();
    await audit(env, context, "invitation_resent", "employees", employee.id);
    return json({ ok: true });
  }

  if (request.method === "GET" && path === "/api/leave") {
    const result = await env.DB.prepare(`SELECT l.id, l.start_date as startDate, l.end_date as endDate, l.days, l.reason, l.status, e.first_name || ' ' || e.last_name as employee, lt.name as leaveType FROM leave_requests l JOIN employees e ON e.id = l.employee_id JOIN leave_types lt ON lt.id = l.leave_type_id WHERE l.organization_id = ? ORDER BY l.created_at DESC LIMIT 50`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "GET" && path === "/api/tasks") {
    const result = await env.DB.prepare(`SELECT t.id, t.title, t.priority, t.status, t.due_date as dueDate, e.first_name || ' ' || e.last_name as assignee, p.name as project FROM tasks t LEFT JOIN employees e ON e.id = t.assignee_id LEFT JOIN projects p ON p.id = t.project_id WHERE t.organization_id = ? ORDER BY CASE t.priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, t.due_date LIMIT 100`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "GET" && path === "/api/expenses") {
    if (!hasPermission(context, "expenses.view")) return error("You do not have permission to view expenses.", 403);
    const result = await env.DB.prepare(`SELECT x.id, e.first_name || ' ' || e.last_name as employee, x.category, x.amount, x.currency, x.expense_date as expenseDate, x.description, x.status, p.name as project FROM expenses x JOIN employees e ON e.id = x.employee_id LEFT JOIN projects p ON p.id = (SELECT id FROM projects WHERE organization_id = x.organization_id LIMIT 1) WHERE x.organization_id = ? AND (? = 1 OR e.user_id = ?) ORDER BY x.created_at DESC LIMIT 100`).bind(context.organizationId, hasPermission(context, "expenses.manage") ? 1 : 0, context.userId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/expenses") {
    if (!hasPermission(context, "employees.view")) return error("Only organization members can submit expense records.", 403);
    const body = await request.json<{ category?: string; amount?: number; expenseDate?: string; description?: string; project?: string }>();
    const amount = Number(body.amount);
    if (!body.category || !Number.isFinite(amount) || amount <= 0 || !body.expenseDate || !body.description) return error("category, amount, expenseDate and description are required");
    const employee = await env.DB.prepare(`SELECT id FROM employees WHERE organization_id = ? AND user_id = ? AND deleted_at IS NULL LIMIT 1`).bind(context.organizationId, context.userId).first<{ id: string }>();
    const employeeId = employee?.id || (await env.DB.prepare(`SELECT id FROM employees WHERE organization_id = ? AND deleted_at IS NULL ORDER BY created_at LIMIT 1`).bind(context.organizationId).first<{ id: string }>())?.id;
    if (!employeeId) return error("No active employee profile is available for this request", 409);
    const id = `expense-${crypto.randomUUID().slice(0, 8)}`;
    const requestIdValue = `request-${crypto.randomUUID().slice(0, 8)}`;
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO expenses (id, organization_id, employee_id, category, amount, currency, expense_date, description, status) VALUES (?, ?, ?, ?, ?, 'NGN', ?, ?, 'submitted')`).bind(id, context.organizationId, employeeId, body.category, amount, body.expenseDate, body.description),
      env.DB.prepare(`INSERT INTO approval_requests (id, organization_id, request_type, source_record_id, title, requester_id, amount, currency, required_role, status, current_step, metadata_json) VALUES (?, ?, 'Expense', ?, ?, ?, ?, 'NGN', 'CEO', 'pending', 1, ?)`).bind(requestIdValue, context.organizationId, id, body.description, context.userId, amount, JSON.stringify({ category: body.category, project: body.project || null, approvalPolicy: ["CEO"] })),
    ]);
    await audit(env, context, "submitted", "expenses", id, { category: body.category, amount, description: body.description });
    await notifyApprovers(env, context, "CEO", body.description, `A financial request for ₦${amount.toLocaleString("en-NG")} is pending your approval.`);
    return json({ id, requestId: requestIdValue, status: "submitted" }, { status: 201 });
  }

  const expenseMatch = path.match(/^\/api\/expenses\/([^/]+)$/);
  if (request.method === "PATCH" && expenseMatch) {
    return error("Expense decisions must be made from the role-checked approval queue.", 409);
  }

  if (request.method === "GET" && path === "/api/requests") {
    if (!hasPermission(context, "requests.manage") && !hasPermission(context, "employees.view")) return error("You do not have permission to view requests.", 403);
    const canViewAll = hasPermission(context, "requests.manage") ? 1 : 0;
    const result = await env.DB.prepare(`SELECT a.id, a.request_type as requestType, a.title, json_extract(a.metadata_json, '$.details') as details, u.full_name as requester, a.amount, a.status, a.required_role as requiredRole, a.created_at as createdAt FROM approval_requests a JOIN users u ON u.id = a.requester_id WHERE a.organization_id = ? AND (? = 1 OR a.requester_id = ?) ORDER BY CASE a.status WHEN 'pending' THEN 1 ELSE 2 END, a.created_at DESC LIMIT 100`).bind(context.organizationId, canViewAll, context.userId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/requests") {
    if (!hasPermission(context, "employees.view")) return error("Only organization members can submit requests.", 403);
    const body = await request.json<{ requestType?: string; title?: string; details?: string; amount?: number | string; approverRole?: string }>();
    const requestType = body.requestType?.trim() || "Other";
    const title = body.title?.trim();
    const details = body.details?.trim();
    const amount = body.amount === undefined || body.amount === "" ? null : Number(body.amount);
    if (!["Operational", "Access", "HR", "Leave", "Purchase", "Budget", "Other"].includes(requestType) || !title || title.length > 120 || !details || details.length > 2000 || (amount !== null && (!Number.isFinite(amount) || amount <= 0))) return error("Choose a supported request type and provide a valid title, details and optional positive amount.");
    const financialTypes = ["expense", "purchase", "budget", "payroll", "reimbursement", "payment", "financial", "asset purchase"];
    const financial = amount !== null || financialTypes.includes(requestType.toLowerCase());
    if (financial && amount === null) return error("Financial requests must include an amount.");
    const requiredRole = financial ? "CEO" : body.approverRole?.trim() || "Manager";
    if (!financial && !["Manager", "HR Admin", "CEO"].includes(requiredRole)) return error("Choose a supported approval role.");
    const id = `request-${crypto.randomUUID()}`;
    await env.DB.prepare(`INSERT INTO approval_requests (id, organization_id, request_type, title, requester_id, amount, currency, required_role, status, current_step, metadata_json) VALUES (?, ?, ?, ?, ?, ?, 'NGN', ?, 'pending', 1, ?)`)
      .bind(id, context.organizationId, requestType, title, context.userId, amount, requiredRole, JSON.stringify({ details, approvalPolicy: [requiredRole] })).run();
    await audit(env, context, "submitted", "requests", id, { requestType, title, amount, requiredRole });
    await notifyApprovers(env, context, requiredRole, title, `${financial ? `A financial request for ₦${Number(amount || 0).toLocaleString("en-NG")} is` : "A request is"} pending your approval. Details: ${details}`);
    return json({ id, requestType, title, amount, requiredRole, status: "pending" }, { status: 201 });
  }

  const requestMatch = path.match(/^\/api\/requests\/([^/]+)$/);
  if (request.method === "PATCH" && requestMatch) {
    if (!hasPermission(context, "requests.manage") && !hasPermission(context, "hr.onboarding.approve")) return error("You do not have permission to approve requests.", 403);
    const body = await request.json<{ status?: string }>();
    if (!body.status || !["approved", "rejected", "paid", "cancelled"].includes(body.status)) return error("A valid request status is required");
    const requestIdValue = requestMatch[1];
    const item = await env.DB.prepare(`SELECT source_record_id as sourceRecordId, requester_id as requesterId, title, request_type as requestType, required_role as requiredRole, amount, current_step as currentStep, status FROM approval_requests WHERE id = ? AND organization_id = ?`).bind(requestIdValue, context.organizationId).first<{ sourceRecordId: string | null; requesterId: string; title: string; requestType: string; requiredRole: string; amount: number | null; currentStep: number; status: string }>();
    if (!item) return error("Request not found.", 404);
    if (item.status !== "pending") return error("This request has already been decided.", 409);
    const financialTypes = ["expense", "purchase", "budget", "payroll", "reimbursement", "payment", "financial", "asset purchase"];
    const isFinancialRequest = item.amount !== null || financialTypes.includes(item.requestType.trim().toLowerCase());
    const requiredRole = isFinancialRequest ? "CEO" : item.requiredRole;
    if (body.status === "approved" || body.status === "rejected") {
      const organizationAdminMayDecide = !isFinancialRequest && context.role === "Organization Admin";
      if (context.role !== requiredRole && !organizationAdminMayDecide) return error(`This request requires approval from ${requiredRole}.`, 403);
    } else if (body.status === "paid" && !hasPermission(context, "expenses.manage")) return error("Finance permission is required to mark a claim as paid.", 403);
    await env.DB.batch([
      env.DB.prepare(`UPDATE approval_requests SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND status = 'pending'`).bind(body.status, requestIdValue, context.organizationId),
      ...(item.sourceRecordId ? [env.DB.prepare(`UPDATE expenses SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`).bind(body.status, item.sourceRecordId, context.organizationId)] : []),
    ]);
    await audit(env, context, body.status, "requests", requestIdValue, { role: context.role, stage: item.currentStep });
    if (body.status === "approved") {
      const requester = await env.DB.prepare(`SELECT u.email, u.full_name as fullName, o.name as organizationName FROM users u JOIN organizations o ON o.id = ? WHERE u.id = ?`).bind(context.organizationId, item.requesterId).first<{ email: string; fullName: string; organizationName: string }>();
      if (requester) await sendApprovalNotificationEmail(env, requester.email, requester.fullName, requester.organizationName, "Your Zyntris request was approved", `Your ${item.requestType.toLowerCase()} request “${item.title}” has been approved.`);
    }
    return json({ ok: true, id: requestIdValue, status: body.status });
  }

  if (request.method === "GET" && path === "/api/assets") {
    const result = await env.DB.prepare(`SELECT a.id, a.asset_tag as assetTag, a.name, a.category, COALESCE(a.serial_number, '') as serialNumber, a.status, e.first_name || ' ' || e.last_name as assignee, a.location, a.current_value as value FROM assets a LEFT JOIN employees e ON e.id = a.assigned_employee_id WHERE a.organization_id = ? ORDER BY a.created_at DESC`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/assets") {
    const body = await request.json<{ name?: string; category?: string; serialNumber?: string; location?: string; value?: number }>();
    if (!body.name || !body.category) return error("name and category are required");
    const id = `asset-${crypto.randomUUID().slice(0, 8)}`;
    const tag = `AST-${Math.floor(1000 + Math.random() * 8999)}`;
    await env.DB.prepare(`INSERT INTO assets (id, organization_id, asset_tag, name, category, serial_number, location, purchase_price, current_value) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, context.organizationId, tag, body.name, body.category, body.serialNumber || null, body.location || null, Number(body.value || 0), Number(body.value || 0)).run();
    await audit(env, context, "created", "assets", id, body);
    return json({ id, assetTag: tag }, { status: 201 });
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

  if (request.method === "GET" && path === "/api/tickets") {
    const result = await env.DB.prepare(`SELECT t.id, t.ticket_number as ticketNumber, t.subject, t.category, t.priority, t.status, requester.full_name as requester, assignee.full_name as assignee, t.created_at as createdAt FROM support_tickets t JOIN users requester ON requester.id = t.requester_id LEFT JOIN users assignee ON assignee.id = t.assignee_id WHERE t.organization_id = ? ORDER BY t.created_at DESC`).bind(context.organizationId).all();
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

  if (request.method === "GET" && path === "/api/calendar") {
    const result = await env.DB.prepare(`SELECT id, title, event_type as eventType, start_at as startAt, end_at as endAt, location FROM calendar_events WHERE organization_id = ? ORDER BY start_at LIMIT 100`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "GET" && path === "/api/customers") {
    const result = await env.DB.prepare(`SELECT c.id, c.name, c.company, c.email, c.stage, c.value, u.full_name as owner, c.last_activity_at as lastActivity FROM customers c LEFT JOIN users u ON u.id = c.owner_id WHERE c.organization_id = ? ORDER BY c.created_at DESC`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/customers") {
    const body = await request.json<{ name?: string; company?: string; email?: string; stage?: string; value?: number }>();
    if (!body.name || !body.email) return error("name and email are required");
    const id = `customer-${crypto.randomUUID().slice(0, 8)}`;
    await env.DB.prepare(`INSERT INTO customers (id, organization_id, name, company, email, stage, value, owner_id, last_activity_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, date('now'))`).bind(id, context.organizationId, body.name, body.company || null, body.email, body.stage || "lead", Number(body.value || 0), context.userId).run();
    await audit(env, context, "created", "customers", id, body);
    return json({ id }, { status: 201 });
  }

  if (request.method === "GET" && path === "/api/files") {
    const result = await env.DB.prepare(`SELECT id, name, category, content_type as contentType, size_bytes as sizeBytes, expires_at as expiresAt, created_at as createdAt FROM documents WHERE organization_id = ? ORDER BY created_at DESC LIMIT 100`).bind(context.organizationId).all();
    return json({ data: result.results || [] });
  }

  if (request.method === "POST" && path === "/api/files") {
    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return error("A file is required");
    if (file.size > 10 * 1024 * 1024) return error("Files must be 10MB or smaller");
    const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, "-");
    const key = `${context.organizationId}/${crypto.randomUUID()}-${safeName}`;
    await env.FILES.put(key, file.stream(), { httpMetadata: { contentType: file.type || "application/octet-stream" } });
    const id = `doc-${crypto.randomUUID().slice(0, 8)}`;
    await env.DB.prepare(`INSERT INTO documents (id, organization_id, name, category, r2_key, content_type, size_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, context.organizationId, file.name, String(form.get("category") || "General"), key, file.type || "application/octet-stream", file.size).run();
    await audit(env, context, "uploaded", "documents", id, { name: file.name, size: file.size });
    return json({ id, key, name: file.name }, { status: 201 });
  }

  return error("Not found", 404);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) return withSecurityHeaders(await handleApi(request, env));
      return env.ASSETS.fetch(request);
    } catch (cause) {
      console.error("Unhandled request error", cause);
      return withSecurityHeaders(error("Something went wrong. Please try again.", 500));
    }
  },
};
