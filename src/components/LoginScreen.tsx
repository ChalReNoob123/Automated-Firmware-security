import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Shield, User, AlertTriangle, 
  ChevronLeft, Fingerprint, 
  Loader2
} from "lucide-react";
import { API_BASE, Token } from "../utils/api";

type Step = "identify" | "signup" | "password" | "enroll" | "2fa";

export default function LoginScreen({ onLoginSuccess }: { onLoginSuccess: () => void }) {
  const [step, setStep] = useState<Step>("identify");
  const [isSignup, setIsSignup] = useState(false);
  
  // Form State
  const [identifier, setIdentifier] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  
  // Auth State
  const [tempToken, setTempToken] = useState("");
  const [qrCode, setQrCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Reset errors when changing steps
  useEffect(() => { setError(null); }, [step]);

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

  const goToPassword = (e: React.FormEvent) => {
    e.preventDefault();
    if (!identifier) return;
    setStep("password");
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const data = await post("/api/auth/login", { identifier, password });
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

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await post("/api/auth/signup", { username, email, password });
      setIsSignup(false);
      setIdentifier(username);
      setStep("identify");
      // Show success state briefly or just go back to login
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (code.length !== 6) return;
    setLoading(true);
    setError(null);
    try {
      const data = await post("/api/auth/verify-2fa", { tempToken, code });
      Token.setAccess(data.accessToken);
      onLoginSuccess();
    } catch (err: any) {
      setError(err.message);
      setCode(""); // Clear failed code
    } finally {
      setLoading(false);
    }
  };

  const slideVariants = {
    enter: (direction: number) => ({ x: direction > 0 ? 300 : -300, opacity: 0 }),
    center: { x: 0, opacity: 1 },
    exit: (direction: number) => ({ x: direction < 0 ? 300 : -300, opacity: 0 }),
  };

  return (
    <div className="min-h-screen bg-[#0a0a0a] flex items-center justify-center p-4 font-sans selection:bg-sky-500/30">
      {/* Background Ambience */}
      <div className="pointer-events-none fixed inset-0">
        <div className="absolute top-0 left-1/4 w-[500px] h-[500px] bg-sky-600/10 blur-[120px] rounded-full" />
        <div className="absolute bottom-0 right-1/4 w-[400px] h-[400px] bg-indigo-600/10 blur-[120px] rounded-full" />
        <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')] opacity-[0.03] mix-blend-overlay" />
      </div>

      <div className="w-full max-w-[440px] relative z-10">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-[#161616] border border-white/5 rounded-[28px] overflow-hidden shadow-[0_20px_50px_rgba(0,0,0,0.5)] ring-1 ring-white/10"
        >
          {/* Progress Bar */}
          <div className="h-1 w-full bg-white/5">
            {loading && (
              <motion.div 
                layoutId="progress"
                className="h-full bg-sky-500"
                animate={{ x: ["-100%", "100%"] }}
                transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
              />
            )}
          </div>

          <div className="p-10 pb-12">
            {/* Header */}
            <div className="flex flex-col items-center mb-8">
              <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-sky-500 shadow-[0_0_20px_rgba(14,165,233,0.4)]">
                <Shield className="h-7 w-7 text-white" />
              </div>
              <h1 className="text-[24px] font-medium text-white tracking-tight">SentinelGrid</h1>
              <div className="mt-1 flex items-center gap-2 text-[#9aa0a6] text-[16px]">
                {step === 'signup' ? 'Create your SOC account' : 'Sign in'}
              </div>
            </div>

            {error && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="mb-6 flex items-start gap-3 rounded-xl border border-rose-500/20 bg-rose-500/5 p-4"
              >
                <AlertTriangle className="h-5 w-5 text-rose-500 shrink-0 mt-0.5" />
                <p className="text-sm text-rose-200 leading-snug">{error}</p>
              </motion.div>
            )}

            <div className="relative overflow-hidden min-h-[220px]">
              <AnimatePresence mode="wait" custom={1}>
                {step === "identify" && !isSignup && (
                  <motion.form 
                    key="identify"
                    custom={1}
                    variants={slideVariants}
                    initial="enter" animate="center" exit="exit"
                    onSubmit={goToPassword}
                    className="space-y-6"
                  >
                    <div className="group relative">
                      <input 
                        type="text" 
                        required 
                        autoFocus
                        value={identifier} 
                        onChange={e => setIdentifier(e.target.value)}
                        placeholder=" "
                        className="peer w-full rounded-lg border border-[#3c4043] bg-transparent px-4 py-4.5 text-white outline-none transition-all focus:border-sky-500 focus:ring-1 focus:ring-sky-500 placeholder:opacity-0"
                      />
                      <label className="pointer-events-none absolute left-4 top-4.5 text-[#9aa0a6] transition-all 
                        peer-focus:-top-2.5 peer-focus:left-2 peer-focus:bg-[#161616] peer-focus:px-1 peer-focus:text-xs peer-focus:text-sky-500 
                        peer-[:not(:placeholder-shown)]:-top-2.5 peer-[:not(:placeholder-shown)]:left-2 peer-[:not(:placeholder-shown)]:bg-[#161616] peer-[:not(:placeholder-shown)]:px-1 peer-[:not(:placeholder-shown)]:text-xs">
                        Email or Username
                      </label>
                    </div>

                    <div className="flex items-center justify-between">
                      <button 
                        type="button" 
                        onClick={() => setIsSignup(true)}
                        className="text-sm font-semibold text-sky-500 hover:text-sky-400 transition"
                      >
                        Create account
                      </button>
                      <button 
                        type="submit"
                        className="rounded-lg bg-sky-500 px-6 py-2.5 text-sm font-semibold text-white shadow-lg shadow-sky-500/20 hover:bg-sky-400 transition-all active:scale-95"
                      >
                        Next
                      </button>
                    </div>
                  </motion.form>
                )}

                {isSignup && (
                  <motion.form 
                    key="signup"
                    custom={1}
                    variants={slideVariants}
                    initial="enter" animate="center" exit="exit"
                    onSubmit={handleSignup}
                    className="space-y-5"
                  >
                    <div className="relative">
                      <input type="text" required value={username} onChange={e => setUsername(e.target.value)} placeholder=" "
                        className="peer w-full rounded-lg border border-[#3c4043] bg-transparent px-4 py-4.5 text-white outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 placeholder:opacity-0" />
                      <label className="pointer-events-none absolute left-4 top-4.5 text-[#9aa0a6] transition-all 
                        peer-focus:-top-2.5 peer-focus:left-2 peer-focus:bg-[#161616] peer-focus:px-1 peer-focus:text-xs peer-focus:text-sky-500 
                        peer-[:not(:placeholder-shown)]:-top-2.5 peer-[:not(:placeholder-shown)]:left-2 peer-[:not(:placeholder-shown)]:bg-[#161616] peer-[:not(:placeholder-shown)]:px-1 peer-[:not(:placeholder-shown)]:text-xs">
                        Username
                      </label>
                    </div>
                    <div className="relative">
                      <input type="email" required value={email} onChange={e => setEmail(e.target.value)} placeholder=" "
                        className="peer w-full rounded-lg border border-[#3c4043] bg-transparent px-4 py-4.5 text-white outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 placeholder:opacity-0" />
                      <label className="pointer-events-none absolute left-4 top-4.5 text-[#9aa0a6] transition-all 
                        peer-focus:-top-2.5 peer-focus:left-2 peer-focus:bg-[#161616] peer-focus:px-1 peer-focus:text-xs peer-focus:text-sky-500 
                        peer-[:not(:placeholder-shown)]:-top-2.5 peer-[:not(:placeholder-shown)]:left-2 peer-[:not(:placeholder-shown)]:bg-[#161616] peer-[:not(:placeholder-shown)]:px-1 peer-[:not(:placeholder-shown)]:text-xs">
                        Email address
                      </label>
                    </div>
                    <div className="relative">
                      <input type="password" required value={password} onChange={e => setPassword(e.target.value)} placeholder=" "
                        className="peer w-full rounded-lg border border-[#3c4043] bg-transparent px-4 py-4.5 text-white outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 placeholder:opacity-0" />
                      <label className="pointer-events-none absolute left-4 top-4.5 text-[#9aa0a6] transition-all 
                        peer-focus:-top-2.5 peer-focus:left-2 peer-focus:bg-[#161616] peer-focus:px-1 peer-focus:text-xs peer-focus:text-sky-500 
                        peer-[:not(:placeholder-shown)]:-top-2.5 peer-[:not(:placeholder-shown)]:left-2 peer-[:not(:placeholder-shown)]:bg-[#161616] peer-[:not(:placeholder-shown)]:px-1 peer-[:not(:placeholder-shown)]:text-xs">
                        Create password
                      </label>
                    </div>

                    <div className="flex items-center justify-between pt-2">
                      <button type="button" onClick={() => setIsSignup(false)} className="text-sm font-semibold text-sky-500">Sign in instead</button>
                      <button type="submit" disabled={loading} className="flex items-center gap-2 rounded-lg bg-sky-500 px-6 py-2.5 text-sm font-semibold text-white shadow-lg shadow-sky-500/20 hover:bg-sky-400">
                        {loading && <Loader2 className="h-4 w-4 animate-spin" />} Finish
                      </button>
                    </div>
                  </motion.form>
                )}

                {step === "password" && (
                  <motion.form 
                    key="password"
                    custom={1}
                    variants={slideVariants}
                    initial="enter" animate="center" exit="exit"
                    onSubmit={handleLogin}
                    className="space-y-6"
                  >
                    <div className="flex flex-col items-center">
                      <div className="flex items-center gap-2 rounded-full border border-[#3c4043] px-3 py-1 text-sm text-white mb-6">
                        <User className="h-4 w-4 text-[#9aa0a6]" />
                        {identifier}
                        <button type="button" onClick={() => setStep("identify")} className="ml-1 text-sky-500 hover:text-sky-400">
                          <ChevronLeft className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                    <div className="relative">
                      <input 
                        type="password" 
                        required 
                        autoFocus
                        value={password} 
                        onChange={e => setPassword(e.target.value)}
                        placeholder=" "
                        className="peer w-full rounded-lg border border-[#3c4043] bg-transparent px-4 py-4.5 text-white outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 placeholder:opacity-0"
                      />
                      <label className="pointer-events-none absolute left-4 top-4.5 text-[#9aa0a6] transition-all 
                        peer-focus:-top-2.5 peer-focus:left-2 peer-focus:bg-[#161616] peer-focus:px-1 peer-focus:text-xs peer-focus:text-sky-500 
                        peer-[:not(:placeholder-shown)]:-top-2.5 peer-[:not(:placeholder-shown)]:left-2 peer-[:not(:placeholder-shown)]:bg-[#161616] peer-[:not(:placeholder-shown)]:px-1 peer-[:not(:placeholder-shown)]:text-xs">
                        Enter your password
                      </label>
                    </div>

                    <div className="flex items-center justify-end">
                      <button 
                        type="submit"
                        disabled={loading}
                        className="flex items-center gap-2 rounded-lg bg-sky-500 px-8 py-2.5 text-sm font-semibold text-white shadow-lg shadow-sky-500/20 hover:bg-sky-400 transition-all active:scale-95"
                      >
                        {loading && <Loader2 className="h-4 w-4 animate-spin" />} Next
                      </button>
                    </div>
                  </motion.form>
                )}

                {step === "enroll" && (
                  <motion.form 
                    key="enroll"
                    custom={1}
                    variants={slideVariants}
                    initial="enter" animate="center" exit="exit"
                    onSubmit={handleVerify}
                    className="space-y-6"
                  >
                    <div className="text-center">
                      <h2 className="text-lg font-medium text-white mb-2">Set up 2-Step Verification</h2>
                      <p className="text-sm text-[#9aa0a6] mb-6">Scan this QR code with Google Authenticator to secure your account.</p>
                      <div className="inline-block rounded-2xl bg-white p-3 mb-6 shadow-xl shadow-sky-500/10">
                        <img src={qrCode} alt="2FA" className="h-40 w-40" />
                      </div>
                    </div>
                    <div className="relative">
                      <input 
                        type="text" 
                        required 
                        maxLength={6}
                        value={code} 
                        onChange={e => setCode(e.target.value.replace(/\D/g, ''))}
                        placeholder=" "
                        className="peer w-full rounded-lg border border-[#3c4043] bg-transparent px-4 py-4.5 text-center text-2xl tracking-[0.5em] font-mono text-white outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 placeholder:opacity-0"
                      />
                      <label className="pointer-events-none absolute left-0 right-0 top-4.5 text-center text-[#9aa0a6] transition-all 
                        peer-focus:-top-2.5 peer-focus:bg-[#161616] peer-focus:text-xs peer-focus:text-sky-500 
                        peer-[:not(:placeholder-shown)]:-top-2.5 peer-[:not(:placeholder-shown)]:bg-[#161616] peer-[:not(:placeholder-shown)]:text-xs">
                        6-digit code
                      </label>
                    </div>
                    <button type="submit" disabled={loading || code.length !== 6} className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-500 py-3 text-sm font-semibold text-white">
                      {loading && <Loader2 className="h-4 w-4 animate-spin" />} Verify & Continue
                    </button>
                  </motion.form>
                )}

                {step === "2fa" && (
                  <motion.form 
                    key="2fa"
                    custom={1}
                    variants={slideVariants}
                    initial="enter" animate="center" exit="exit"
                    onSubmit={handleVerify}
                    className="space-y-6"
                  >
                    <div className="text-center">
                      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-sky-500/10 mx-auto mb-4">
                        <Fingerprint className="h-6 w-6 text-sky-500" />
                      </div>
                      <h2 className="text-lg font-medium text-white mb-1">2-Step Verification</h2>
                      <p className="text-sm text-[#9aa0a6] mb-8">Enter the code from your authenticator app.</p>
                    </div>
                    <div className="relative">
                      <input 
                        type="text" 
                        required 
                        autoFocus
                        maxLength={6}
                        value={code} 
                        onChange={e => setCode(e.target.value.replace(/\D/g, ''))}
                        placeholder=" "
                        className="peer w-full rounded-lg border border-[#3c4043] bg-transparent px-4 py-4.5 text-center text-2xl tracking-[0.5em] font-mono text-white outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 placeholder:opacity-0"
                      />
                      <label className="pointer-events-none absolute left-0 right-0 top-4.5 text-center text-[#9aa0a6] transition-all 
                        peer-focus:-top-2.5 peer-focus:bg-[#161616] peer-focus:text-xs peer-focus:text-sky-500 
                        peer-[:not(:placeholder-shown)]:-top-2.5 peer-[:not(:placeholder-shown)]:bg-[#161616] peer-[:not(:placeholder-shown)]:text-xs">
                        Verification code
                      </label>
                    </div>
                    <div className="flex items-center justify-between">
                      <button type="button" onClick={() => setStep("identify")} className="text-sm font-semibold text-sky-500">More ways to verify</button>
                      <button type="submit" disabled={loading || code.length !== 6} className="flex items-center gap-2 rounded-lg bg-sky-500 px-8 py-2.5 text-sm font-semibold text-white">
                        {loading && <Loader2 className="h-4 w-4 animate-spin" />} Next
                      </button>
                    </div>
                  </motion.form>
                )}
              </AnimatePresence>
            </div>
          </div>

          <div className="px-10 py-6 border-t border-white/5 flex items-center justify-between text-xs text-[#9aa0a6]">
            <div className="flex items-center gap-4">
              <span>English (United States)</span>
            </div>
            <div className="flex items-center gap-4">
              <span className="hover:text-white cursor-pointer">Help</span>
              <span className="hover:text-white cursor-pointer">Privacy</span>
              <span className="hover:text-white cursor-pointer">Terms</span>
            </div>
          </div>
        </motion.div>

        {/* Footer info */}
        <div className="mt-8 text-center">
          <p className="text-[12px] text-[#5f6368] leading-relaxed">
            One account. All of SentinelGrid working for you.<br />
            Secure monitoring and enterprise-grade threat detection.
          </p>
        </div>
      </div>
    </div>
  );
}

