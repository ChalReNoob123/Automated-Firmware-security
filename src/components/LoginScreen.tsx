import { useEffect, useState, useRef, type FormEvent, type ReactNode } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
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
import { API_BASE, Token, apiPost } from "../utils/api";

type Step = "identify" | "signup" | "password" | "enroll" | "2fa";

// --- 3D HTML5 Canvas Threat Globe ---
function ThreatGlobe({ threatLevel, isZooming }: { threatLevel: "none" | "low" | "medium" | "high"; isZooming: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    
    let animationId: number;
    let width = canvas.width = canvas.offsetWidth;
    let height = canvas.height = canvas.offsetHeight;
    
    // Generate 3D points on a sphere
    interface Point3D {
      x: number;
      y: number;
      z: number;
      color: string;
      size: number;
      threat?: boolean;
    }
    
    const points: Point3D[] = [];
    const numPoints = 750;
    
    for (let i = 0; i < numPoints; i++) {
      const y = 1 - (i / (numPoints - 1)) * 2; 
      const radius = Math.sqrt(1 - y * y); 
      const phi = i * 1.618033988749895 * 2 * Math.PI; 
      const x = Math.cos(phi) * radius;
      const z = Math.sin(phi) * radius;
      
      let color = "rgba(34, 211, 238, 0.55)"; // Cyan baseline
      let threat = false;
      let size = Math.random() * 1.2 + 0.8;
      
      if (i % 22 === 0) {
        color = "rgba(244, 63, 94, 0.9)"; // Red threat node
        threat = true;
        size = 2.8;
      } else if (i % 35 === 0) {
        color = "rgba(52, 211, 153, 0.85)"; // Green secure node
        size = 2.0;
      }
      
      points.push({ x, y, z, color, size, threat });
    }
    
    let rotationX = 0.002;
    let rotationY = 0.004;
    let currentRotationX = 0;
    let currentRotationY = 0;
    let baseScale = 120;
    const perspective = 350;
    let scaleMultiplier = 1.0;
    
    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = canvas.offsetWidth;
      height = canvas.height = canvas.offsetHeight;
    };
    window.addEventListener("resize", handleResize);
    
    const render = () => {
      ctx.clearRect(0, 0, width, height);
      
      const centerX = width / 2;
      const centerY = height / 2;
      
      // Zoom fly-through sequence on success
      if (isZooming) {
        scaleMultiplier += 0.35;
      }
      
      // Control rotation and dynamics depending on login threat level
      let speedFactor = 1.0;
      if (threatLevel === "high") speedFactor = 4.0;
      else if (threatLevel === "medium") speedFactor = 2.0;
      
      currentRotationX += rotationX * speedFactor;
      currentRotationY += rotationY * speedFactor;
      
      const cosX = Math.cos(currentRotationX);
      const sinX = Math.sin(currentRotationX);
      const cosY = Math.cos(currentRotationY);
      const sinY = Math.sin(currentRotationY);
      
      const projected = points.map(p => {
        // Rotations
        let y1 = p.y * cosX - p.z * sinX;
        let z1 = p.z * cosX + p.y * sinX;
        let x2 = p.x * cosY - z1 * sinY;
        let z2 = z1 * cosY + p.x * sinY;
        
        const pz = z2 + 2.2; 
        const currentScale = baseScale * scaleMultiplier;
        const px = centerX + x2 * (perspective / (perspective + pz * scaleMultiplier)) * currentScale;
        const py = centerY + y1 * (perspective / (perspective + pz * scaleMultiplier)) * currentScale;
        
        return {
          x: px,
          y: py,
          z: z2,
          color: p.color,
          size: p.size,
          threat: p.threat
        };
      });
      
      // Draw rings background
      ctx.strokeStyle = threatLevel === "high" ? "rgba(244, 63, 94, 0.05)" : "rgba(34, 211, 238, 0.04)";
      ctx.lineWidth = 1;
      
      // Sort back-to-front
      projected.sort((a, b) => b.z - a.z);
      
      for (const p of projected) {
        if (p.x < -100 || p.x > width + 100 || p.y < -100 || p.y > height + 100) continue;
        
        const depthOpacity = Math.max(0.08, Math.min(1.0, (p.z + 1.2) / 2.2));
        
        let drawColor = p.color;
        if (threatLevel === "high") {
          // Flashing red mode
          drawColor = p.threat 
            ? "rgba(244, 63, 94, 0.95)" 
            : `rgba(244, 63, 94, ${0.45 * depthOpacity})`;
        } else {
          // Adjust opacity based on depth
          if (drawColor.startsWith("rgba")) {
            drawColor = drawColor.replace(/[\d\.]+\)$/, `${depthOpacity})`);
          }
        }
        
        ctx.beginPath();
        const r = p.size * (perspective / (perspective + (p.z + 2.2) * scaleMultiplier));
        ctx.arc(p.x, p.y, Math.max(0.4, r), 0, 2 * Math.PI);
        ctx.fillStyle = drawColor;
        ctx.fill();
        
        // Attacker points pulse/glow
        if (p.threat && threatLevel !== "none") {
          ctx.beginPath();
          ctx.arc(p.x, p.y, r * 2.8, 0, 2 * Math.PI);
          ctx.fillStyle = threatLevel === "high" ? "rgba(244, 63, 94, 0.18)" : "rgba(244, 63, 94, 0.1)";
          ctx.fill();
        }
      }
      
      // Grid effect lines
      ctx.fillStyle = "rgba(5, 8, 16, 0.08)";
      for (let y = 0; y < height; y += 5) {
        ctx.fillRect(0, y, width, 2);
      }
      
      animationId = requestAnimationFrame(render);
    };
    
    render();
    
    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener("resize", handleResize);
    };
  }, [threatLevel, isZooming]);
  
  return (
    <div className="relative w-full h-[280px] sm:h-[350px] lg:h-[480px] flex items-center justify-center">
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-25">
        <div className={`w-[260px] h-[260px] rounded-full border border-cyan-500/20 animate-spin ${threatLevel === 'high' ? 'border-rose-500/30' : ''}`} style={{ animationDuration: '40s' }} />
        <div className={`absolute w-[220px] h-[220px] rounded-full border border-dashed border-blue-500/30 animate-spin ${threatLevel === 'high' ? 'border-rose-500/20' : ''}`} style={{ animationDuration: '20s', animationDirection: 'reverse' }} />
        <div className="absolute w-[160px] h-[160px] rounded-full border border-emerald-500/10" />
      </div>
      <canvas ref={canvasRef} className="w-full h-full block" />
    </div>
  );
}

// --- Alphanumeric 6-Digit OTP Grid Component ---
function OTPInputGrid({ value, onChange, length = 6, error }: { value: string; onChange: (val: string) => void; length?: number; error?: boolean }) {
  const inputsRef = useRef<(HTMLInputElement | null)[]>([]);
  
  useEffect(() => {
    // Focus first box
    if (inputsRef.current[0]) {
      inputsRef.current[0].focus();
    }
  }, []);

  const updateVal = (val: string) => {
    onChange(val.slice(0, length));
  };
  
  const handleChange = (val: string, index: number) => {
    const sanitized = val.toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (!sanitized) return;
    
    const char = sanitized[sanitized.length - 1];
    const currentCode = value.split("");
    currentCode[index] = char;
    const newCode = currentCode.join("");
    updateVal(newCode);
    
    // Move to next input box
    if (index < length - 1 && inputsRef.current[index + 1]) {
      inputsRef.current[index + 1]?.focus();
    }
  };
  
  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>, index: number) => {
    if (e.key === "Backspace") {
      const currentCode = value.split("");
      if (!currentCode[index] && index > 0) {
        currentCode[index - 1] = "";
        updateVal(currentCode.join(""));
        inputsRef.current[index - 1]?.focus();
      } else {
        currentCode[index] = "";
        updateVal(currentCode.join(""));
      }
    }
  };
  
  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData("text").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, length);
    updateVal(pasted);
    const targetIdx = Math.min(pasted.length, length - 1);
    inputsRef.current[targetIdx]?.focus();
  };
  
  return (
    <div className="flex justify-between gap-2.5 my-5">
      {Array.from({ length }).map((_, idx) => {
        const char = value[idx] || "";
        return (
          <input
            key={idx}
            ref={(el) => { inputsRef.current[idx] = el; }}
            type="text"
            maxLength={1}
            value={char}
            onChange={(e) => handleChange(e.target.value, idx)}
            onKeyDown={(e) => handleKeyDown(e, idx)}
            onPaste={idx === 0 ? handlePaste : undefined}
            className={`w-full h-14 text-center text-xl font-black font-mono rounded-lg border bg-slate-950/80 text-white outline-none transition focus:ring-4 ${
              error 
                ? "border-rose-500/60 focus:border-rose-400 focus:ring-rose-500/10 text-rose-300" 
                : "border-slate-800 focus:border-cyan-400 focus:ring-cyan-400/10"
            }`}
          />
        );
      })}
    </div>
  );
}

// --- Text Fields ---
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
          className="h-12 w-full rounded-lg border border-slate-800/80 bg-slate-950/70 px-4 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400 focus:bg-slate-950 focus:ring-4 focus:ring-cyan-400/10"
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

// --- Primary and Secondary Buttons ---
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
      className="inline-flex h-10 items-center gap-2 rounded-lg border border-slate-800 px-3 text-sm font-semibold text-slate-300 transition hover:border-cyan-400/60 hover:text-white"
    >
      {children}
    </button>
  );
}

// --- Main LoginScreen Component ---
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
  
  // Animation / Cinematic states
  const [isZooming, setIsZooming] = useState(false);
  const [shakeCard, setShakeCard] = useState(false);

  useEffect(() => { setError(null); }, [step, isSignup]);

  const passwordScore = (() => {
    let score = 0;
    if (password.length >= 10) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score += 1;
    return score;
  })();

  const strengthLabel = ['Very Weak','Weak','Fair','Strong','Very Strong'][passwordScore] || 'None';
  const strengthColor = ['bg-rose-500','bg-orange-400','bg-amber-400','bg-cyan-400','bg-emerald-400'][passwordScore] || 'bg-slate-700';

  const post = async (path: string, body: object) => {
    try {
      return await apiPost(path, body);
    } catch (err: any) {
      if (err.message === "Failed to fetch" || err.message?.includes("NetworkError") || err.message?.includes("fetch")) {
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
      // Trigger card shake & flash globe red
      setShakeCard(true);
      if (navigator.vibrate) navigator.vibrate([100, 50, 100]);
      setTimeout(() => setShakeCard(false), 600);
    } finally {
      setLoading(false);
    }
  };

  const handleSignup = async (e: FormEvent) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      setError("Password and confirm password do not match.");
      setShakeCard(true);
      setTimeout(() => setShakeCard(false), 600);
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
      setShakeCard(true);
      setTimeout(() => setShakeCard(false), 600);
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
      
      // Success Cinematic Sequence (Fly through Threat Globe zoom)
      setIsZooming(true);
      setTimeout(() => {
        onLoginSuccess();
      }, 900);
      
    } catch (err: any) {
      setError(err.message);
      setCode("");
      setShakeCard(true);
      if (navigator.vibrate) navigator.vibrate([80, 80, 80]);
      setTimeout(() => setShakeCard(false), 600);
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

  // Compute active threat level for the globe
  const getActiveThreatLevel = (): "none" | "low" | "medium" | "high" => {
    if (error) return "high";
    if (loading) return "medium";
    if (step === "2fa" || step === "enroll") return "medium";
    return "low";
  };

  return (
    <div className="min-h-screen overflow-hidden bg-[#050810] text-white selection:bg-cyan-400/25 relative flex items-center justify-center">
      {/* Cyber grid */}
      <div className="pointer-events-none fixed inset-0 cyber-grid" />
      {/* Volumetric light */}
      <div className="pointer-events-none fixed inset-0 volumetric-light" />
      {/* Holographic overlay */}
      <div className="pointer-events-none fixed inset-0 holographic opacity-40" />
      
      {/* Floating particles */}
      {[...Array(6)].map((_, i) => (
        <div key={i} className="pointer-events-none fixed rounded-full bg-cyan-400/20 blur-sm float-particle" style={{ width: 4 + i * 2, height: 4 + i * 2, left: `${15 + i * 14}%`, top: `${20 + (i % 3) * 25}%`, animationDelay: `${i * 0.8}s` }} />
      ))}

      <main className="relative z-10 mx-auto grid min-h-screen w-full max-w-6xl items-center gap-8 px-4 py-8 lg:grid-cols-[1fr_460px] lg:px-8">
        
        {/* Globe Visualization Column */}
        <section className="flex flex-col items-center justify-center text-center lg:text-left">
          <motion.div 
            className="w-full max-w-xl"
            animate={isZooming ? { scale: 1.15, opacity: 0.1, y: -20 } : { scale: 1, opacity: 1, y: 0 }}
            transition={{ duration: 0.8, ease: "easeInOut" }}
          >
            {/* Animated Shield + Brand */}
            <div className="mb-4 flex flex-col lg:flex-row items-center gap-4 justify-center lg:justify-start">
              <div className="relative">
                <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-2xl shadow-cyan-500/30 breathe-glow">
                  <Shield className="h-7 w-7 text-white" />
                </div>
                <div className="absolute -inset-2 rounded-2xl border border-cyan-400/20" style={{ animation: 'pulse-ring-expand 3s cubic-bezier(0,0,0.2,1) infinite' }} />
              </div>
              <div className="text-center lg:text-left">
                <p className="text-xl font-black tracking-tight">SentinelGrid<span className="text-cyan-400 ml-1 text-xs font-mono align-super">v21.0</span></p>
                <p className="text-[10px] uppercase tracking-[0.3em] text-cyan-300/50">Chrono-Defensive Operations Command</p>
              </div>
            </div>

            <div className="my-2">
              <ThreatGlobe threatLevel={getActiveThreatLevel()} isZooming={isZooming} />
            </div>

            <div className="hidden lg:block">
              <h1 className="text-4xl font-black leading-[1.05] tracking-tight mt-4">
                <span className="bg-gradient-to-r from-white via-cyan-100 to-white bg-clip-text text-transparent">Hypervisor Inversion</span> and Real-Time Sandboxing.
              </h1>
              <p className="mt-4 text-sm leading-relaxed text-slate-400 max-w-lg">
                Enter your security credentials to manage active VM detonation, configure QCOW2 temporal backups, and investigate real-time intrusion forensics.
              </p>
            </div>
          </motion.div>
        </section>

        {/* Credentials Form Column */}
        <section className="login-card-shell mx-auto min-w-0 flex items-center justify-center">
          <motion.div
            initial={{ opacity: 0, y: 18 }}
            animate={isZooming 
              ? { scale: 0.85, opacity: 0, y: -30 } 
              : shakeCard 
                ? { x: [-10, 10, -10, 10, -5, 5, -2, 2, 0], opacity: 1, y: 0 } 
                : { opacity: 1, y: 0 }
            }
            transition={isZooming ? { duration: 0.6 } : (shakeCard ? { duration: 0.6 } : { duration: 0.3 })}
            className="login-card-panel overflow-hidden rounded-2xl glass-v2 neon-border shadow-2xl shadow-black/60 w-full"
          >
            <div className="h-1 bg-slate-900">
              {loading && (
                <motion.div
                  className="h-full w-1/2 bg-cyan-400"
                  animate={{ x: ["-100%", "220%"] }}
                  transition={{ duration: 1.1, repeat: Infinity, ease: "easeInOut" }}
                />
              )}
            </div>

            <div className="p-6 sm:p-8">
              <div className="mb-6 flex items-start justify-between gap-4">
                <div>
                  <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-400 to-blue-600 text-white shadow-lg shadow-cyan-500/30 breathe-glow">
                    {isSignup ? <UserPlus className="h-7 w-7" /> : step === "2fa" || step === "enroll" ? <Fingerprint className="h-7 w-7" /> : <Shield className="h-7 w-7" />}
                  </div>
                  <h2 className="text-2xl font-black tracking-tight">{stepTitle}</h2>
                  <p className="mt-1 text-xs text-slate-400">
                    {isSignup ? "Create a protected analyst account." : "Access the Sentinel V-Axiom dashboard."}
                  </p>
                </div>
                <div className="rounded-lg border border-emerald-400/20 bg-emerald-400/10 px-3 py-2 text-right">
                  <p className="text-[9px] font-bold uppercase tracking-[0.2em] text-emerald-300">System</p>
                  <p className="text-xs text-emerald-100 font-mono">SEC-SECURE</p>
                </div>
              </div>

              {error && (
                <motion.div
                  initial={{ opacity: 0, y: -6 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mb-5 flex items-start gap-3 rounded-lg border border-rose-400/25 bg-rose-500/10 p-3 animate-pulse"
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

              <div className="relative min-h-[250px] overflow-hidden">
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
                        <div className="relative flex items-center justify-center h-5 w-5 rounded border border-slate-800 bg-slate-950 group-hover:border-cyan-400 transition-colors">
                          <input 
                            type="checkbox" 
                            checked={rememberMe} 
                            onChange={(e) => setRememberMe(e.target.checked)} 
                            className="peer absolute inset-0 opacity-0 cursor-pointer"
                          />
                          <div className={`h-2.5 w-2.5 rounded-sm bg-cyan-400 transition-transform ${rememberMe ? 'scale-100' : 'scale-0'}`} />
                        </div>
                        <span className="text-xs text-slate-400 group-hover:text-slate-300 transition-colors">Remember identity context</span>
                      </label>

                      <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                        <SecondaryButton onClick={() => setIsSignup(true)}>
                          <UserPlus className="h-4 w-4" />
                          Create node
                        </SecondaryButton>
                        <PrimaryButton loading={loading}>Next Step</PrimaryButton>
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

                      <div className="rounded-xl border border-white/10 bg-slate-950/60 p-3">
                        <div className="mb-2 flex items-center justify-between text-xs">
                          <span className="text-slate-400 font-mono text-[10px]">COHERENCE</span>
                          <span className={passwordScore >= 4 ? 'text-emerald-400 font-bold' : passwordScore >= 3 ? 'text-cyan-400' : 'text-slate-400'}>{strengthLabel} ({passwordScore}/5)</span>
                        </div>
                        <div className="grid grid-cols-5 gap-1.5">
                          {[0, 1, 2, 3, 4].map((i) => (
                            <div key={i} className={`h-2 rounded-full transition-all duration-300 ${passwordScore > i ? strengthColor : "bg-slate-800"}`} />
                          ))}
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                        <SecondaryButton onClick={() => setIsSignup(false)}>
                          <ChevronLeft className="h-4 w-4" />
                          Return
                        </SecondaryButton>
                        <PrimaryButton loading={loading} disabled={passwordScore < 5}>
                          Register
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
                      <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2">
                        <div className="flex min-w-0 items-center gap-2">
                          <User className="h-4 w-4 shrink-0 text-slate-500" />
                          <span className="truncate text-xs font-mono font-semibold text-slate-200">{identifier}</span>
                        </div>
                        <button type="button" onClick={() => setStep("identify")} className="text-cyan-300 transition hover:text-cyan-100">
                          <ChevronLeft className="h-4 w-4" />
                        </button>
                      </div>
                      <Field label="Password" icon={<Lock className="h-3.5 w-3.5" />} type="password" value={password} autoFocus onChange={setPassword} />
                      
                      <label className="flex items-center gap-2 cursor-pointer group w-fit">
                        <div className="relative flex items-center justify-center h-5 w-5 rounded border border-slate-800 bg-slate-950 group-hover:border-cyan-400 transition-colors">
                          <input 
                            type="checkbox" 
                            checked={rememberMe} 
                            onChange={(e) => setRememberMe(e.target.checked)} 
                            className="peer absolute inset-0 opacity-0 cursor-pointer"
                          />
                          <div className={`h-2.5 w-2.5 rounded-sm bg-cyan-400 transition-transform ${rememberMe ? 'scale-100' : 'scale-0'}`} />
                        </div>
                        <span className="text-xs text-slate-400 group-hover:text-slate-300 transition-colors">Remember identity context</span>
                      </label>

                      <div className="flex justify-end pt-2">
                        <PrimaryButton loading={loading}>
                          Authenticate
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
                          <img src={qrCode} alt="2FA setup QR code" className="h-36 w-36" />
                        </div>
                        <p className="text-xs leading-5 text-slate-400 max-w-sm mx-auto">
                          Scan with your Google or Microsoft Authenticator app to bind your analyst profile to the grid.
                        </p>
                      </div>
                      
                      <div>
                        <span className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                          <ScanLine className="h-3.5 w-3.5" />
                          6-Digit Alphanumeric Grid
                        </span>
                        <OTPInputGrid value={code} onChange={setCode} error={!!error} />
                      </div>
                      
                      <PrimaryButton loading={loading} disabled={code.length !== 6}>
                        Complete binding
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
                      <div className="rounded-lg border border-cyan-300/10 bg-cyan-300/5 p-4">
                        <div className="mb-1 flex items-center gap-2 text-cyan-200">
                          <Fingerprint className="h-4 w-4" />
                          <p className="text-xs font-bold font-mono">OTP CHALLENGE REQUIRED</p>
                        </div>
                        <p className="text-xs leading-relaxed text-slate-400">Please enter the current alphanumeric OTP from your authenticator app.</p>
                      </div>

                      <div>
                        <span className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                          <KeyRound className="h-3.5 w-3.5" />
                          OTP validation grid
                        </span>
                        <OTPInputGrid value={code} onChange={setCode} error={!!error} />
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                        <SecondaryButton onClick={() => setStep("identify")}>
                          <ChevronLeft className="h-4 w-4" />
                          Return
                        </SecondaryButton>
                        <PrimaryButton loading={loading} disabled={code.length !== 6}>
                          Verify Session
                        </PrimaryButton>
                      </div>
                    </motion.form>
                  )}
                </AnimatePresence>
              </div>
            </div>

            <div className="grid gap-3 border-t border-white/5 bg-black/30 px-6 py-4 text-[10px] text-slate-500 sm:grid-cols-3 sm:px-8 font-mono">
              <span className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span> SECURE-LINK</span>
              <span className="sm:text-center">AES-256-GCM</span>
              <span className="sm:text-right">AXIOM v21.0</span>
            </div>
          </motion.div>
        </section>
      </main>
    </div>
  );
}
