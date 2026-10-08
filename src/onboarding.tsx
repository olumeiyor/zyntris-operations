import { useEffect, useState, type FormEvent } from "react";
import { ArrowRight, Building2, CheckCircle2, LockKeyhole, Mail, ShieldCheck } from "lucide-react";

type AuthFlowProps = { onAuthenticated: () => void; initialNotice?: string; adminPortal?: boolean };

async function authRequest(path: string, body: Record<string, string>) {
  const response = await fetch(path, { method: "POST", credentials: "include", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const data = await response.json().catch(() => ({})) as { error?: string; email?: string; twoFactorRequired?: boolean; challengeToken?: string };
  if (!response.ok) throw new Error(data.error || "Something went wrong. Please try again.");
  return data;
}

export function Onboarding({ onAuthenticated, initialNotice, adminPortal = false }: AuthFlowProps) {
  const inviteToken = new URLSearchParams(window.location.search).get("invite") || "";
  const resetToken = new URLSearchParams(window.location.search).get("reset") || "";
  const [mode, setMode] = useState<"signup" | "login" | "demo" | "invite" | "reset" | "forgot">(resetToken ? "reset" : inviteToken ? "invite" : adminPortal ? "login" : "signup");
  const [message, setMessage] = useState(initialNotice || "");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [verificationSent, setVerificationSent] = useState(false);
  const [demoEnabled, setDemoEnabled] = useState(false);
  const [twoFactorChallenge, setTwoFactorChallenge] = useState("");
  const [passwordResetComplete, setPasswordResetComplete] = useState(false);

  useEffect(() => {
    void fetch("/api/auth/config").then((response) => response.json()).then((config: { demoEnabled?: boolean }) => setDemoEnabled(Boolean(config.demoEnabled))).catch(() => setDemoEnabled(false));
  }, []);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError(""); setMessage(""); setBusy(true);
    const fields = Object.fromEntries(new FormData(event.currentTarget).entries());
    const body = Object.fromEntries(Object.entries(fields).map(([key, value]) => [key, String(value)]));
    try {
      if (mode === "reset") {
        if (body.password !== body.confirmPassword) throw new Error("The passwords do not match.");
        await authRequest("/api/auth/reset-password", { token: resetToken, password: body.password || "" });
        setPasswordResetComplete(true);
        window.history.replaceState({}, "", window.location.pathname);
      } else if (mode === "forgot") {
        await authRequest("/api/auth/request-password-reset", { email: body.email || "" });
        setMessage("If an account exists for that email, we’ve sent a secure password reset link. Please check your inbox and spam folder.");
      } else if (mode === "signup") {
        const result = await authRequest("/api/auth/register", body);
        setVerificationSent(true); setMessage(`We sent a verification link to ${result.email}. Your 15-day trial starts as soon as you verify.`);
      } else if (mode === "invite") {
        await authRequest("/api/auth/accept-invite", { token: inviteToken, password: String(body.password || "") });
        window.history.replaceState({}, "", window.location.pathname);
        onAuthenticated();
      } else if (mode === "demo") {
        await authRequest("/api/auth/demo", { password: String(body.password || "") });
        onAuthenticated();
      } else {
        if (twoFactorChallenge) {
          await authRequest("/api/auth/2fa/verify", { challengeToken: twoFactorChallenge, code: String(body.code || "") });
        } else {
          const result = await authRequest("/api/auth/login", body);
          if (result.twoFactorRequired && result.challengeToken) {
            setTwoFactorChallenge(result.challengeToken);
            setMessage("Enter the current code from your authenticator app. You can also use one unused recovery code.");
            setBusy(false);
            return;
          }
        }
        onAuthenticated();
      }
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Something went wrong."); }
    finally { setBusy(false); }
  };

  return <main className="auth-shell">
    <section className="auth-aside">
      <img className="auth-logo" src="/zyntris-logo.png" alt="Zyntris" />
      <div className="auth-aside-copy"><span className="auth-kicker">{adminPortal ? "ZYNTRIS PLATFORM ADMIN" : "ONE SYSTEM. EVERY OPERATION."}</span><h1>{adminPortal ? "Operate the platform with confidence." : "Give your team a calmer way to work."}</h1><p>{adminPortal ? "A restricted control room for tenant oversight, service access and platform maintenance." : "People, finance and day-to-day operations together in one secure workspace."}</p></div>
      <div className="auth-promise"><span><ShieldCheck size={17} /></span><div><strong>{adminPortal ? "Restricted access" : "Private by design"}</strong><small>{adminPortal ? "Only approved platform administrator accounts can enter." : "Your organization gets its own isolated workspace and records."}</small></div></div>
    </section>
    <section className="auth-main"><div className="auth-card">
      <div className="auth-brand-mobile"><img src="/zyntris-logo.png" alt="Zyntris" /></div>
      {passwordResetComplete ? <div className="verify-state"><span className="verify-icon"><CheckCircle2 size={24} /></span><div className="auth-kicker">PASSWORD UPDATED</div><h2>Sign in with your new password.</h2><p>Your password has been changed and existing sessions have been signed out.</p><button className="button secondary" onClick={() => { setPasswordResetComplete(false); setMode("login"); }}>Back to sign in</button></div> : verificationSent ? <div className="verify-state"><span className="verify-icon"><Mail size={24} /></span><div className="auth-kicker">ONE LAST STEP</div><h2>Check your inbox</h2><p>{message}</p><p className="auth-small">The secure link expires in 24 hours. Check your spam folder if it hasn’t arrived.</p><button className="button secondary" onClick={() => { setVerificationSent(false); setMode("login"); }}>Back to sign in</button></div> : <>
        <div className="auth-kicker">{adminPortal && mode === "login" ? "PLATFORM ADMIN ACCESS" : mode === "signup" ? "START YOUR WORKSPACE" : mode === "demo" ? "SANDBOX ACCESS" : mode === "invite" ? "EMPLOYEE ONBOARDING" : mode === "reset" ? "SECURE PASSWORD RESET" : "WELCOME BACK"}</div>
        <h2>{adminPortal && mode === "login" ? "Sign in to the admin dashboard." : mode === "signup" ? "Build better operations." : mode === "demo" ? "Explore the demo workspace." : mode === "invite" ? "Set up your employee access." : mode === "reset" ? "Create a new password." : "Sign in to Zyntris."}</h2>
        <p className="auth-intro">{adminPortal && mode === "login" ? "Use your approved Zyntris administrator account. All access is verified by the platform." : mode === "signup" ? "Create your organization workspace. No card required." : mode === "demo" ? "Fictional organization and payroll records. Demo access is read-only." : mode === "invite" ? "Your HR administrator invited you. Create a password to activate your account." : mode === "reset" ? "Choose a new password of at least 12 characters. This one-time link expires after 30 minutes." : twoFactorChallenge ? "Verify your identity to finish signing in." : "Pick up where your team left off."}</p>
        {message && <div className="auth-message"><CheckCircle2 size={17} />{message}</div>}
        {error && <div className="auth-error" role="alert">{error}</div>}
        <form className="auth-form" onSubmit={submit}>
          {mode === "signup" && <>
            <label><span>Organization name</span><div className="auth-input"><Building2 size={16} /><input name="organizationName" required minLength={2} maxLength={120} placeholder="e.g. Acme Limited" /></div></label>
            <label><span>Your full name</span><input className="plain-auth-input" name="fullName" required minLength={2} maxLength={120} placeholder="e.g. Ada Okafor" /></label>
            <label><span>Industry <small>Optional</small></span><select className="plain-auth-input" name="industry" defaultValue=""><option value="">Choose an industry</option><option>Professional services</option><option>Technology</option><option>Financial services</option><option>Healthcare</option><option>Education</option><option>Retail & commerce</option><option>Manufacturing</option><option>Nonprofit</option><option>Other</option></select></label>
          </>}
          {(mode === "signup" || mode === "login" || mode === "forgot") && <label><span>Work email</span><div className="auth-input"><Mail size={16} /><input name="email" type="email" autoComplete="email" required placeholder="you@company.com" /></div></label>}
          {mode === "demo" && <div className="demo-login-id"><span>Demo sign-in ID</span><strong>demo@demo.zyntris.invalid</strong></div>}
          {mode !== "forgot" && <label><span>{mode === "demo" ? "Demo password" : mode === "login" ? "Password" : "Create password"} {(mode === "signup" || mode === "invite" || mode === "reset") && <small>At least 12 characters</small>}</span><div className="auth-input"><LockKeyhole size={16} /><input name="password" type="password" autoComplete={mode === "signup" || mode === "invite" || mode === "reset" ? "new-password" : "current-password"} minLength={mode === "signup" || mode === "invite" || mode === "reset" ? 12 : 1} required placeholder={mode === "signup" || mode === "invite" || mode === "reset" ? "Create a strong password" : mode === "demo" ? "Enter the shared demo password" : "Your password"} /></div></label>}
          {mode === "reset" && <label><span>Confirm new password</span><div className="auth-input"><LockKeyhole size={16} /><input name="confirmPassword" type="password" autoComplete="new-password" minLength={12} required placeholder="Enter the new password again" /></div></label>}
          {mode === "login" && twoFactorChallenge && <label><span>Authenticator or recovery code</span><div className="auth-input"><ShieldCheck size={16} /><input name="code" inputMode="numeric" autoComplete="one-time-code" autoFocus required placeholder="6-digit code or recovery code" /></div></label>}
          {mode === "signup" && <div className="trial-note"><CheckCircle2 size={16} /><span><strong>15 days free</strong> · Full access during your trial, no card required.</span></div>}
          {mode === "demo" && <div className="trial-note"><ShieldCheck size={16} /><span>Fictional records only. Changes and uploads are disabled.</span></div>}
          <button className="button primary auth-submit" type="submit" disabled={busy}>{busy ? "Please wait…" : mode === "signup" ? "Create organization" : mode === "demo" ? "Enter demo sandbox" : mode === "invite" ? "Accept invitation" : mode === "reset" ? "Set new password" : mode === "forgot" ? "Send reset link" : twoFactorChallenge ? "Verify and sign in" : "Sign in"}<ArrowRight size={16} /></button>
        </form>
        {mode === "login" && !twoFactorChallenge && !adminPortal && <div className="auth-switch">New to Zyntris?<button onClick={() => { setError(""); setMessage(""); setMode("signup"); }}>Start a 15-day trial</button></div>}
        {mode === "login" && !twoFactorChallenge && <button className="demo-entry" type="button" onClick={() => { setError(""); setMessage(""); setMode("forgot"); }}>Forgot password?</button>}
        {mode === "forgot" && <button className="demo-entry" type="button" onClick={() => { setError(""); setMessage(""); setMode("login"); }}>Back to sign in</button>}
        {mode === "signup" && <div className="auth-switch">Already have an account?<button onClick={() => { setError(""); setMessage(""); setMode("login"); }}>Sign in</button></div>}
        {mode === "demo" && <div className="auth-switch">Have a company account?<button onClick={() => { setError(""); setMessage(""); setMode("login"); }}>Sign in</button></div>}
        {mode === "reset" && <button className="demo-entry" type="button" onClick={() => { setError(""); setMessage(""); window.history.replaceState({}, "", window.location.pathname); setMode("login"); }}>Back to sign in</button>}
        {twoFactorChallenge && <button className="demo-entry" type="button" onClick={() => { setTwoFactorChallenge(""); setMessage(""); setError(""); }}>Back to password sign in</button>}
        {!adminPortal && demoEnabled && mode !== "demo" && mode !== "invite" && mode !== "reset" && <button className="demo-entry" type="button" onClick={() => { setError(""); setMessage(""); setMode("demo"); }}>Explore the read-only demo</button>}
      </>}
      <div className="auth-legal">By continuing, you agree to Zyntris’s terms and privacy policy.</div>
    </div></section>
  </main>;
}
