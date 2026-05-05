import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  Fingerprint,
  KeyRound,
  Loader2,
  Lock,
  Mail,
  ScanLine,
  Shield,
  User,
  UserPlus,
} from "lucide-react";
import { API_BASE, Token } from "../utils/api";

type Step = "identify" | "signup" | "password" | "enroll" | "2fa";

type FieldProps = {
  label: string;
  icon: ReactNode;
  type?: string;
  value: string;
  autoFocus?: boolean;
  maxLength?: number;
  inputMode?: "text" | "numeric" | "email";
  onChange: (value: string) => void;
};

function Field({ label, icon, type = "text", value, autoFocus, maxLength, inputMode, onChange }: FieldProps) {
  return (
    <label className="group block">
      <span className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500 group-focus-within:text-cyan-400 transition-colors">
        {icon}
        {label}
      </span>
      <div className="relative">
        <input
          type={type}
          required
          autoFocus={autoFocus}
          maxLength={maxLength}
          inputMode={inputMode}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          className="h-12 w-full rounded-lg border border-slate-700/80 bg-slate-950/70 px-4 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400 focus:bg-slate-950 focus:ring-4 focus:ring-cyan-400/10"
        />
        {value && (
          <motion.div 
            initial={{ scale: 0 }} 
            animate={{ scale: 1 }} 
            className="absolute right-3 top-1/2 -translate-y-1/2"
          >
            <CheckCircle2 className="h-4 w-4 text-emerald-400/50" />
          </motion.div>
        )}
      </div>
    </label>
  );
}

function PrimaryButton({ children, disabled, loading }: { children: ReactNode; disabled?: boolean; loading?: boolean }) {
  return (
    <button
      type="submit"
      disabled={disabled || loading}
      className="relative overflow-hidden group inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 px-6 text-sm font-bold text-white shadow-lg shadow-cyan-900/20 transition-all hover:scale-[1.02] active:scale-[0.98] disabled:cursor-not-allowed disabled:grayscale disabled:opacity-50"
    >
      <div className="absolute inset-0 bg-white/10 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-500" />
      {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : children}
    </button>
  );
}

function SecondaryButton({ children, onClick }: { children: ReactNode; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex h-10 items-center gap-2 rounded-lg border border-slate-700 px-3 text-sm font-semibold text-slate-300 transition hover:border-cyan-400/60 hover:text-white"
    >
      {children}
    </button>
  );
}

export default function LoginScreen({ onLoginSuccess }: { onLoginSuccess: () => void }) {
  const [step, setStep] = useState<Step>("identify");
  const [isSignup, setIsSignup] = useState(false);

  const [identifier, setIdentifier] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [code, setCode] = useState("");
  const [rememberMe, setRememberMe] = useState(false);

  const [tempToken, setTempToken] = useState("");
  const [qrCode, setQrCode] = useState("");
  const [signupSuccess, setSignupSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => { setError(null); }, [step, isSignup]);

  const passwordScore = (() => {
    let score = 0;
    if (password.length >= 10) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    return score;
  })();

  const post = async (path: string, body: object) => {
    try {
      const res = await fetch(`${API_BASE}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Security challenge failed. Please check your credentials.");
      return data;
    } catch (err: any) {
      if (err.message === "Failed to fetch") {
        throw new Error("Cannot reach Central Command. Check your network connection or server status.");
      }
      throw err;
    }
  };

  const goToPassword = (e: FormEvent) => {
    e.preventDefault();
    if (!identifier.trim()) return;
    setStep("password");
  };

  const handleLogin = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const data = await post("/api/auth/login", { identifier, password, rememberMe });
      setTempToken(data.tempToken);
      if (data.step === "enroll") {
        setQrCode(data.qrCode);
        setStep("enroll");
      } else {
        setStep("2fa");
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSignup = async (e: FormEvent) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      setError("Password and confirm password do not match.");
      return;
    }
    setLoading(true);
    setError(null);
    setSignupSuccess(null);
    try {
      await post("/api/auth/signup", { username, email, password });
      setIsSignup(false);
      setIdentifier(username);
      setStep("identify");
      setSignupSuccess("Account created. Sign in to receive your authenticator QR setup.");
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (e: FormEvent) => {
    e.preventDefault();
    if (code.length !== 6) return;
    setLoading(true);
    setError(null);
    try {
      const data = await post("/api/auth/verify-2fa", { tempToken, code, rememberMe });
      Token.setAccess(data.accessToken);
      Token.setUser(data.user);
      onLoginSuccess();
    } catch (err: any) {
      setError(err.message);
      setCode("");
    } finally {
      setLoading(false);
    }
  };

  const stepTitle = isSignup
    ? "Create analyst access"
    : step === "password"
      ? "Confirm identity"
      : step === "enroll"
        ? "Bind authenticator"
        : step === "2fa"
          ? "Verify session"
          : "Welcome back";

  const slideVariants = {
    enter: { y: 12, opacity: 0 },
    center: { y: 0, opacity: 1 },
    exit: { y: -12, opacity: 0 },
  };

  return (
    <div className="min-h-screen overflow-hidden bg-[#070b10] text-white selection:bg-cyan-400/25">
      <div className="pointer-events-none fixed inset-0 bg-[linear-gradient(rgba(148,163,184,0.08)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.08)_1px,transparent_1px)] bg-[size:48px_48px]" />
      <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(circle_at_50%_0%,rgba(34,211,238,0.12),transparent_34%),linear-gradient(180deg,transparent,rgba(0,0,0,0.52))]" />

      <main className="relative z-10 mx-auto grid min-h-screen w-full max-w-6xl items-center gap-8 px-4 py-8 lg:grid-cols-[1fr_440px] lg:px-8">
        <section className="hidden lg:block">
          <div className="max-w-xl">
            <div className="mb-8 flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-lg border border-cyan-300/30 bg-cyan-300/10">
                <Shield className="h-6 w-6 text-cyan-200" />
              </div>
              <div>
                <p className="text-lg font-bold tracking-tight">SentinelGrid</p>
                <p className="text-xs uppercase tracking-[0.28em] text-slate-500">SOC monitoring command</p>
              </div>
            </div>

            <h1 className="text-5xl font-black leading-[1.02] tracking-tight text-white">
              Secure access for live threat operations.
            </h1>
            <p className="mt-5 max-w-lg text-base leading-7 text-slate-400">
              Sign in with multi-factor verification and continue monitoring telemetry, segments, detections, and response activity from one hardened console.
            </p>

            <div className="mt-10 grid max-w-lg gap-3">
              {[
                { label: "MFA", text: "Authenticator-backed login flow", icon: CheckCircle2 },
                { label: "Cache", text: "Hot telemetry reads stay fast", icon: Activity },
                { label: "Session", text: "HttpOnly refresh with short access tokens", icon: KeyRound },
              ].map(({ label, text, icon: Icon }) => (
                <div key={label} className="flex items-center gap-4 rounded-lg border border-white/10 bg-white/[0.04] p-4">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-950 text-cyan-200">
                    <Icon className="h-5 w-5" />
                  </div>
                  <div>
                    <p className="text-sm font-bold text-white">{label}</p>
                    <p className="text-sm text-slate-400">{text}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="mx-0 w-[358px] max-w-[calc(100vw-2rem)] min-w-0 lg:mx-auto lg:w-[440px]">
          <motion.div
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            className="overflow-hidden rounded-xl border border-white/10 bg-[#0d1219]/95 shadow-2xl shadow-black/50 backdrop-blur-xl"
          >
            <div className="h-1 bg-slate-800">
              {loading && (
                <motion.div
                  className="h-full w-1/2 bg-cyan-300"
                  animate={{ x: ["-100%", "220%"] }}
                  transition={{ duration: 1.1, repeat: Infinity, ease: "easeInOut" }}
                />
              )}
            </div>

            <div className="p-6 sm:p-8">
              <div className="mb-7 flex items-start justify-between gap-4">
                <div>
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-cyan-300 text-slate-950">
                    {isSignup ? <UserPlus className="h-6 w-6" /> : step === "2fa" || step === "enroll" ? <Fingerprint className="h-6 w-6" /> : <Shield className="h-6 w-6" />}
                  </div>
                  <h2 className="text-2xl font-black tracking-tight">{stepTitle}</h2>
                  <p className="mt-1 text-sm text-slate-400">
                    {isSignup ? "Create a protected analyst account." : "Continue to the SentinelGrid dashboard."}
                  </p>
                </div>
                <div className="rounded-lg border border-emerald-400/20 bg-emerald-400/10 px-3 py-2 text-right">
                  <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-emerald-300">Status</p>
                  <p className="text-xs text-emerald-100">Protected</p>
                </div>
              </div>

              {error && (
                <motion.div
                  initial={{ opacity: 0, y: -6 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mb-5 flex items-start gap-3 rounded-lg border border-rose-400/25 bg-rose-500/10 p-3"
                >
                  <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-rose-300" />
                  <p className="text-sm leading-6 text-rose-100">{error}</p>
                </motion.div>
              )}

              {signupSuccess && (
                <motion.div
                  initial={{ opacity: 0, y: -6 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mb-5 flex items-start gap-3 rounded-lg border border-emerald-400/25 bg-emerald-400/10 p-3"
                >
                  <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-300" />
                  <p className="text-sm leading-6 text-emerald-100">{signupSuccess}</p>
                </motion.div>
              )}

              <div className="relative min-h-[265px] overflow-hidden">
                <AnimatePresence mode="wait">
                  {step === "identify" && !isSignup && (
                    <motion.form
                      key="identify"
                      variants={slideVariants}
                      initial="enter"
                      animate="center"
                      exit="exit"
                      onSubmit={goToPassword}
                      className="space-y-5"
                    >
                      <Field label="Email or username" icon={<User className="h-3.5 w-3.5" />} value={identifier} autoFocus onChange={setIdentifier} />
                      
                      <label className="flex items-center gap-2 cursor-pointer group w-fit">
                        <div className="relative flex items-center justify-center h-5 w-5 rounded border border-slate-700 bg-slate-950 group-hover:border-cyan-400 transition-colors">
                          <input 
                            type="checkbox" 
                            checked={rememberMe} 
                            onChange={(e) => setRememberMe(e.target.checked)} 
                            className="peer absolute inset-0 opacity-0 cursor-pointer"
                          />
                          <div className={`h-2.5 w-2.5 rounded-sm bg-cyan-400 transition-transform ${rememberMe ? 'scale-100' : 'scale-0'}`} />
                        </div>
                        <span className="text-xs text-slate-400 group-hover:text-slate-300 transition-colors">Remember my identity</span>
                      </label>

                      <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                        <SecondaryButton onClick={() => setIsSignup(true)}>
                          <UserPlus className="h-4 w-4" />
                          Create account
                        </SecondaryButton>
                        <PrimaryButton loading={loading}>Next</PrimaryButton>
                      </div>
                    </motion.form>
                  )}

                  {isSignup && (
                    <motion.form
                      key="signup"
                      variants={slideVariants}
                      initial="enter"
                      animate="center"
                      exit="exit"
                      onSubmit={handleSignup}
                      className="space-y-4"
                    >
                      <Field label="Username" icon={<User className="h-3.5 w-3.5" />} value={username} autoFocus onChange={setUsername} />
                      <Field label="Email address" icon={<Mail className="h-3.5 w-3.5" />} type="email" inputMode="email" value={email} onChange={setEmail} />
                      <Field label="Password" icon={<Lock className="h-3.5 w-3.5" />} type="password" value={password} onChange={setPassword} />
                      <Field label="Confirm password" icon={<Lock className="h-3.5 w-3.5" />} type="password" value={confirmPassword} onChange={setConfirmPassword} />

                      <div className="rounded-lg border border-white/10 bg-slate-950/60 p-3">
                        <div className="mb-2 flex items-center justify-between text-xs text-slate-400">
                          <span>Password strength</span>
                          <span>{passwordScore}/4</span>
                        </div>
                        <div className="grid grid-cols-4 gap-1.5">
                          {[0, 1, 2, 3].map((i) => (
                            <div key={i} className={`h-1.5 rounded-full ${passwordScore > i ? "bg-cyan-300" : "bg-slate-800"}`} />
                          ))}
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                        <SecondaryButton onClick={() => setIsSignup(false)}>
                          <ChevronLeft className="h-4 w-4" />
                          Sign in
                        </SecondaryButton>
                        <PrimaryButton loading={loading} disabled={passwordScore < 2}>
                          Finish
                        </PrimaryButton>
                      </div>
                    </motion.form>
                  )}

                  {step === "password" && (
                    <motion.form
                      key="password"
                      variants={slideVariants}
                      initial="enter"
                      animate="center"
                      exit="exit"
                      onSubmit={handleLogin}
                      className="space-y-5"
                    >
                      <div className="flex items-center justify-between rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2">
                        <div className="flex min-w-0 items-center gap-2">
                          <User className="h-4 w-4 shrink-0 text-slate-500" />
                          <span className="truncate text-sm font-semibold text-slate-200">{identifier}</span>
                        </div>
                        <button type="button" onClick={() => setStep("identify")} className="text-cyan-300 transition hover:text-cyan-100">
                          <ChevronLeft className="h-4 w-4" />
                        </button>
                      </div>
                      <Field label="Password" icon={<Lock className="h-3.5 w-3.5" />} type="password" value={password} autoFocus onChange={setPassword} />
                      
                      <label className="flex items-center gap-2 cursor-pointer group w-fit">
                        <div className="relative flex items-center justify-center h-5 w-5 rounded border border-slate-700 bg-slate-950 group-hover:border-cyan-400 transition-colors">
                          <input 
                            type="checkbox" 
                            checked={rememberMe} 
                            onChange={(e) => setRememberMe(e.target.checked)} 
                            className="peer absolute inset-0 opacity-0 cursor-pointer"
                          />
                          <div className={`h-2.5 w-2.5 rounded-sm bg-cyan-400 transition-transform ${rememberMe ? 'scale-100' : 'scale-0'}`} />
                        </div>
                        <span className="text-xs text-slate-400 group-hover:text-slate-300 transition-colors">Remember my identity</span>
                      </label>

                      <div className="flex justify-end pt-2">
                        <PrimaryButton loading={loading}>
                          Continue
                        </PrimaryButton>
                      </div>
                    </motion.form>
                  )}

                  {step === "enroll" && (
                    <motion.form
                      key="enroll"
                      variants={slideVariants}
                      initial="enter"
                      animate="center"
                      exit="exit"
                      onSubmit={handleVerify}
                      className="space-y-5"
                    >
                      <div className="text-center">
                        <div className="mx-auto mb-4 inline-flex rounded-xl bg-white p-3 shadow-xl shadow-black/30">
                          <img src={qrCode} alt="2FA setup QR code" className="h-40 w-40" />
                        </div>
                        <p className="text-sm leading-6 text-slate-400">
                          Scan the code with Google Authenticator, Microsoft Authenticator, or any TOTP-compatible app.
                        </p>
                      </div>
                      <Field
                        label="6-digit code"
                        icon={<ScanLine className="h-3.5 w-3.5" />}
                        value={code}
                        maxLength={6}
                        inputMode="numeric"
                        onChange={(value) => setCode(value.replace(/\D/g, ""))}
                      />
                      <PrimaryButton loading={loading} disabled={code.length !== 6}>
                        Verify and continue
                      </PrimaryButton>
                    </motion.form>
                  )}

                  {step === "2fa" && (
                    <motion.form
                      key="2fa"
                      variants={slideVariants}
                      initial="enter"
                      animate="center"
                      exit="exit"
                      onSubmit={handleVerify}
                      className="space-y-5"
                    >
                      <div className="rounded-lg border border-cyan-300/20 bg-cyan-300/10 p-4">
                        <div className="mb-2 flex items-center gap-2 text-cyan-100">
                          <Fingerprint className="h-5 w-5" />
                          <p className="text-sm font-bold">Authenticator challenge</p>
                        </div>
                        <p className="text-sm leading-6 text-slate-400">Enter the current six-digit code from your authenticator app.</p>
                      </div>
                      <Field
                        label="Verification code"
                        icon={<KeyRound className="h-3.5 w-3.5" />}
                        value={code}
                        autoFocus
                        maxLength={6}
                        inputMode="numeric"
                        onChange={(value) => setCode(value.replace(/\D/g, ""))}
                      />
                      <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                        <SecondaryButton onClick={() => setStep("identify")}>
                          <ChevronLeft className="h-4 w-4" />
                          Back
                        </SecondaryButton>
                        <PrimaryButton loading={loading} disabled={code.length !== 6}>
                          Verify
                        </PrimaryButton>
                      </div>
                    </motion.form>
                  )}
                </AnimatePresence>
              </div>
            </div>

            <div className="grid gap-3 border-t border-white/10 bg-slate-950/55 px-6 py-4 text-xs text-slate-500 sm:grid-cols-3 sm:px-8">
              <span>English (US)</span>
              <span className="sm:text-center">Privacy</span>
              <span className="sm:text-right">Terms</span>
            </div>
          </motion.div>
        </section>
      </main>
    </div>
  );
}
