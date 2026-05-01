import { useState } from "react";
import { Shield, Lock, User, AlertTriangle, ArrowRight, Activity, Terminal, KeyRound, QrCode, CheckCircle2 } from "lucide-react";
import { API_BASE, Token } from "../utils/api";

type Step = "login" | "enroll" | "2fa";

export default function LoginScreen({ onLoginSuccess }: { onLoginSuccess: () => void }) {
  const [step,     setStep]     = useState<Step>("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code,     setCode]     = useState("");
  const [tempToken, setTempToken] = useState("");
  const [qrCode,   setQrCode]   = useState("");
  const [error,    setError]    = useState<string | null>(null);
  const [loading,  setLoading]  = useState(false);

  const post = async (path: string, body: object) => {
    const res = await fetch(`${API_BASE}${path}`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body:    JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");
    return data;
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true); setError(null);
    try {
      const data = await post("/api/auth/login", { username, password });
      setTempToken(data.tempToken);
      if (data.step === "enroll") { setQrCode(data.qrCode); setStep("enroll"); }
      else                        { setStep("2fa"); }
    } catch (err: any) { setError(err.message); }
    finally { setLoading(false); }
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true); setError(null);
    try {
      const data = await post("/api/auth/verify-2fa", { tempToken, code });
      Token.setAccess(data.accessToken);
      onLoginSuccess();
    } catch (err: any) { setError(err.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="min-h-screen bg-[#020617] flex items-center justify-center p-4 relative overflow-hidden font-sans">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_0%,_rgba(56,189,248,0.1),_transparent_50%),radial-gradient(circle_at_50%_100%,_rgba(244,63,94,0.05),_transparent_50%)]" />
      <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 h-[400px] w-[400px] bg-sky-500/20 blur-[120px] rounded-full pointer-events-none animate-pulse" />

      <div className="w-full max-w-md relative z-10">
        <div className="rounded-3xl border border-white/10 bg-black/40 backdrop-blur-3xl p-8 shadow-2xl shadow-sky-900/20 ring-1 ring-white/5">

          {/* Logo */}
          <div className="flex flex-col items-center text-center mb-8">
            <div className="relative group mb-4">
              <div className="absolute -inset-1 rounded-2xl bg-gradient-to-r from-sky-500 to-indigo-500 opacity-25 blur transition group-hover:opacity-50" />
              <div className="relative flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-slate-800 to-black ring-1 ring-white/20">
                <Shield className="h-8 w-8 text-sky-400" />
              </div>
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">SentinelGrid</h1>
            <p className="text-xs text-sky-400 font-mono mt-1 tracking-widest uppercase flex items-center gap-2">
              <Activity className="h-3 w-3 animate-pulse" /> Central Command
            </p>
          </div>

          {/* Error */}
          {error && (
            <div className="mb-6 flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 animate-in slide-in-from-top-2">
              <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
              <p className="text-sm font-medium text-rose-200">{error}</p>
            </div>
          )}

          {/* ── Step: Login ── */}
          {step === "login" && (
            <form onSubmit={handleLogin} className="space-y-5">
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                  <User className="h-3.5 w-3.5" /> Operator ID
                </label>
                <input type="text" required value={username} onChange={e => setUsername(e.target.value)}
                  className="w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white placeholder-slate-600 outline-none transition focus:border-sky-500/50 focus:ring-1 focus:ring-sky-500/50"
                  placeholder="Enter operator ID..." />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                  <Lock className="h-3.5 w-3.5" /> Passphrase
                </label>
                <input type="password" required value={password} onChange={e => setPassword(e.target.value)}
                  className="w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white placeholder-slate-600 outline-none transition focus:border-sky-500/50 focus:ring-1 focus:ring-sky-500/50"
                  placeholder="••••••••••••" />
              </div>
              <button type="submit" disabled={loading}
                className="group relative flex w-full items-center justify-center gap-2 overflow-hidden rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 px-4 py-3.5 text-sm font-bold text-white shadow-lg shadow-sky-500/25 transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 mt-2">
                <div className="absolute inset-0 bg-white/20 opacity-0 transition-opacity group-hover:opacity-100" />
                {loading ? <><Activity className="h-5 w-5 animate-spin" /> Verifying...</> : <><Terminal className="h-5 w-5" /> Initiate Secure Uplink <ArrowRight className="absolute right-4 h-4 w-4 opacity-0 transition-all group-hover:opacity-100 group-hover:translate-x-1" /></>}
              </button>
            </form>
          )}

          {/* ── Step: Enroll TOTP ── */}
          {step === "enroll" && (
            <form onSubmit={handleVerify} className="space-y-5">
              <div className="rounded-xl bg-sky-500/10 border border-sky-500/20 p-4 text-center">
                <QrCode className="h-6 w-6 text-sky-400 mx-auto mb-2" />
                <p className="text-sm font-semibold text-sky-200 mb-1">Set up Authenticator</p>
                <p className="text-xs text-slate-400">Scan this QR code with Google Authenticator or Authy, then enter the 6-digit code below.</p>
              </div>
              {qrCode && (
                <div className="flex justify-center">
                  <img src={qrCode} alt="TOTP QR Code" className="w-48 h-48 rounded-xl border border-white/10 bg-white p-2" />
                </div>
              )}
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                  <KeyRound className="h-3.5 w-3.5" /> Verification Code
                </label>
                <input type="text" required autoFocus maxLength={6} value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ""))}
                  className="w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-center text-2xl tracking-[0.5em] font-mono text-white placeholder-slate-600 outline-none transition focus:border-sky-500/50 focus:ring-1 focus:ring-sky-500/50"
                  placeholder="------" />
              </div>
              <button type="submit" disabled={loading || code.length !== 6}
                className="group relative flex w-full items-center justify-center gap-2 overflow-hidden rounded-xl bg-gradient-to-r from-emerald-500 to-sky-600 px-4 py-3.5 text-sm font-bold text-white shadow-lg transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 mt-2">
                {loading ? <><Activity className="h-5 w-5 animate-spin" /> Confirming...</> : <><CheckCircle2 className="h-5 w-5" /> Confirm &amp; Activate</>}
              </button>
            </form>
          )}

          {/* ── Step: 2FA Code ── */}
          {step === "2fa" && (
            <form onSubmit={handleVerify} className="space-y-5">
              <div className="rounded-xl bg-sky-500/10 border border-sky-500/20 p-4 text-center">
                <p className="text-sm text-sky-200">Enter the 6-digit code from your authenticator app.</p>
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                  <KeyRound className="h-3.5 w-3.5" /> 2FA Code
                </label>
                <input type="text" required autoFocus maxLength={6} value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ""))}
                  className="w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-center text-2xl tracking-[0.5em] font-mono text-white placeholder-slate-600 outline-none transition focus:border-sky-500/50 focus:ring-1 focus:ring-sky-500/50"
                  placeholder="------" />
              </div>
              <button type="submit" disabled={loading || code.length !== 6}
                className="group relative flex w-full items-center justify-center gap-2 overflow-hidden rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 px-4 py-3.5 text-sm font-bold text-white shadow-lg shadow-sky-500/25 transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 mt-2">
                {loading ? <><Activity className="h-5 w-5 animate-spin" /> Verifying...</> : <><Shield className="h-5 w-5" /> Verify Identity</>}
              </button>
              <button type="button" onClick={() => { setStep("login"); setCode(""); }} className="w-full text-center text-xs text-slate-500 hover:text-white transition">
                Return to Login
              </button>
            </form>
          )}

          <div className="mt-8 border-t border-white/10 pt-6 text-center">
            <p className="font-mono text-[10px] text-slate-600">
              UNAUTHORIZED ACCESS IS STRICTLY PROHIBITED AND MONITORED.<br />
              YOUR IP HAS BEEN LOGGED AND RATE LIMITED.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
