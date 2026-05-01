import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Monitor, Shield, AlertTriangle, CheckCircle, XCircle,
  RefreshCw, ChevronRight, Info, Zap, Lock, Eye,
  Globe, Cpu, HardDrive, Wifi,
} from "lucide-react";
import {
  detectOSSecurityProfile,
  type OSSecurityProfile,
  type RiskFactor,
} from "../utils/osDetector";
import { API_BASE, Token } from "../utils/api";

/* ─── helpers ─────────────────────────────────────────────────────── */
function severityColor(s: RiskFactor["severity"]) {
  return {
    info:     "border-sky-400/30 bg-sky-400/10 text-sky-300",
    low:      "border-emerald-400/30 bg-emerald-400/10 text-emerald-300",
    medium:   "border-amber-400/30 bg-amber-400/10 text-amber-300",
    high:     "border-orange-400/30 bg-orange-400/10 text-orange-300",
    critical: "border-rose-500/30 bg-rose-500/10 text-rose-300",
  }[s];
}

function scoreColor(score: number) {
  if (score >= 80) return "text-emerald-400";
  if (score >= 60) return "text-amber-400";
  if (score >= 40) return "text-orange-400";
  return "text-rose-400";
}

function scoreBarColor(score: number) {
  if (score >= 80) return "bg-emerald-500";
  if (score >= 60) return "bg-amber-500";
  if (score >= 40) return "bg-orange-500";
  return "bg-rose-500";
}

function complianceBadge(status: string) {
  if (status === "compliant")     return "border-emerald-400/30 bg-emerald-400/10 text-emerald-300";
  if (status === "partial")       return "border-amber-400/30 bg-amber-400/10 text-amber-300";
  if (status === "non-compliant") return "border-rose-500/30 bg-rose-500/10 text-rose-300";
  return "border-slate-500/30 bg-slate-500/10 text-slate-300";
}

function osPlatformIcon(platform: string) {
  switch (platform) {
    case "win32":  return "🪟";
    case "darwin": return "🍎";
    case "linux":  return "🐧";
    default:       return "💻";
  }
}

function securityLevelBadge(level: string) {
  if (level === "high")     return "border-emerald-400/30 bg-emerald-400/10 text-emerald-300";
  if (level === "medium")   return "border-amber-400/30 bg-amber-400/10 text-amber-300";
  if (level === "low")      return "border-orange-400/30 bg-orange-400/10 text-orange-300";
  if (level === "critical") return "border-rose-500/30 bg-rose-500/10 text-rose-300 animate-pulse";
  return "border-slate-500/30 bg-slate-500/10 text-slate-300";
}

/* ─── server-side OS telemetry from /api/analyze ─────────────────── */
type ServerOsTelemetry = {
  platform: string;
  cpu: string;
  cores: number;
  totalMem: string;
  freeMem: string;
  uptime: string;
  localIp: string;
  macAddress: string;
  subnet: string;
  networkAdapter: string;
};

/* ─── component ───────────────────────────────────────────────────── */
export default function OSSecurityPanel() {
  const [profile, setProfile]       = useState<OSSecurityProfile | null>(null);
  const [serverOs, setServerOs]     = useState<ServerOsTelemetry | null>(null);
  const [loading, setLoading]       = useState(true);
  const [serverLoading, setServerLoading] = useState(true);
  const [activeRisk, setActiveRisk] = useState<string | null>(null);
  const [showRecs, setShowRecs]     = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  /* Client-side detection */
  useEffect(() => {
    setLoading(true);
    const detected = detectOSSecurityProfile();
    setProfile(detected);
    setLoading(false);
  }, [refreshKey]);

  /* Server-side OS telemetry */
  const fetchServerTelemetry = useCallback(async () => {
    const token = Token.getAccess();
    if (!token) { setServerLoading(false); return; }

    try {
      setServerLoading(true);
      const res = await fetch(`${API_BASE}/api/analyze`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error("Backend unavailable");
      const raw = await res.json();

      // Decrypt payload (AES-256-CBC via backend)
      // If already plain JSON (dev mode), use directly; otherwise handle encrypted
      let data: any = raw;
      if (raw.iv && raw.encryptedData) {
        // Backend encryption is handled server-side; we receive decrypted via /api/analyze
        // Actually the backend returns encrypted — fetch unencrypted system info via second endpoint
        // For now, use the system key from the response metadata
        setServerLoading(false);
        return;
      }
      if (data.system) setServerOs(data.system);
    } catch {
      // Backend may be offline; gracefully degrade
    } finally {
      setServerLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchServerTelemetry();
  }, [fetchServerTelemetry, refreshKey]);

  /* ── /api/os-info endpoint (we'll add this) ── */
  useEffect(() => {
    const token = Token.getAccess();
    if (!token) { setServerLoading(false); return; }

    fetch(`${API_BASE}/api/os-info`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(r => r.json())
      .then(d => { if (d && d.platform) setServerOs(d); })
      .catch(() => {})
      .finally(() => setServerLoading(false));
  }, [refreshKey]);

  if (loading || !profile) {
    return (
      <div className="flex items-center justify-center h-48">
        <div className="flex items-center gap-3 text-slate-400">
          <RefreshCw className="h-5 w-5 animate-spin text-sky-400" />
          <span className="text-sm">Scanning system environment…</span>
        </div>
      </div>
    );
  }

  const { os, browserInfo, securityScore, riskFactors, complianceStatus } = profile;
  const criticalRisks  = riskFactors.filter(r => r.severity === "critical");
  const highRisks      = riskFactors.filter(r => r.severity === "high");

  return (
    <div className="space-y-6">

      {/* ── Header banner ── */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="rounded-3xl border border-white/10 bg-gradient-to-br from-slate-900/80 to-black/60 p-6 backdrop-blur-xl"
      >
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-4">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-white/10 bg-white/5 text-3xl">
              {osPlatformIcon(os.platform)}
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-xl font-bold text-white">{os.name}</h2>
                <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${securityLevelBadge(os.securityLevel)}`}>
                  {os.securityLevel} security
                </span>
                {os.isEOL && (
                  <span className="rounded-full border border-rose-500/40 bg-rose-500/20 px-2.5 py-0.5 text-xs font-bold text-rose-300 animate-pulse">
                    ⚠ END-OF-LIFE
                  </span>
                )}
              </div>
              <p className="mt-0.5 text-sm text-slate-400">
                Version {os.version} · {os.architecture}
                {os.eolDate && (
                  <span className={`ml-2 ${os.isEOL ? "text-rose-400" : "text-slate-500"}`}>
                    · EOL: {os.eolDate}
                  </span>
                )}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Security Score Ring */}
            <div className="flex flex-col items-center">
              <div className={`text-4xl font-black ${scoreColor(securityScore)}`}>
                {securityScore}
              </div>
              <div className="text-xs text-slate-500 uppercase tracking-widest">OS Score</div>
            </div>

            <button
              onClick={() => setRefreshKey(k => k + 1)}
              className="flex items-center gap-1.5 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-xs text-slate-300 transition hover:bg-white/10 hover:text-white"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Rescan
            </button>
          </div>
        </div>

        {/* Score bar */}
        <div className="mt-4">
          <div className="mb-1.5 flex justify-between text-xs text-slate-500">
            <span>Security Posture Score</span>
            <span className={scoreColor(securityScore)}>{securityScore}/100</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-white/10">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${securityScore}%` }}
              transition={{ duration: 1.2, ease: "easeOut" }}
              className={`h-full rounded-full ${scoreBarColor(securityScore)}`}
            />
          </div>
        </div>
      </motion.div>

      {/* ── Main grid ── */}
      <div className="grid gap-6 lg:grid-cols-3">

        {/* ── Left: OS & Browser details ── */}
        <div className="space-y-4 lg:col-span-1">

          {/* OS Info card */}
          <motion.div
            initial={{ opacity: 0, x: -15 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 }}
            className="rounded-2xl border border-white/10 bg-white/5 p-4 backdrop-blur-xl"
          >
            <div className="mb-3 flex items-center gap-2">
              <Monitor className="h-4 w-4 text-sky-400" />
              <h3 className="text-sm font-semibold text-white">OS Details</h3>
            </div>
            <div className="space-y-2.5">
              {[
                { label: "Operating System", value: os.name, icon: <Monitor className="h-3 w-3" /> },
                { label: "Version",          value: os.version, icon: <Info className="h-3 w-3" /> },
                { label: "Architecture",     value: os.architecture, icon: <Cpu className="h-3 w-3" /> },
                { label: "Patch Status",     value: os.patchStatus.replace(/-/g, " ").toUpperCase(), icon: <Shield className="h-3 w-3" /> },
                { label: "EOL Status",       value: os.isEOL ? "⚠ End-of-Life" : "✓ Supported", icon: <CheckCircle className="h-3 w-3" /> },
              ].map(row => (
                <div key={row.label} className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 text-slate-500">
                    <span className="text-slate-600">{row.icon}</span>
                    {row.label}
                  </span>
                  <span className={`font-medium ${row.label === "EOL Status" ? (os.isEOL ? "text-rose-300" : "text-emerald-300") : "text-slate-300"}`}>
                    {row.value}
                  </span>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Browser card */}
          <motion.div
            initial={{ opacity: 0, x: -15 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
            className="rounded-2xl border border-white/10 bg-white/5 p-4 backdrop-blur-xl"
          >
            <div className="mb-3 flex items-center gap-2">
              <Globe className="h-4 w-4 text-purple-400" />
              <h3 className="text-sm font-semibold text-white">Browser Environment</h3>
            </div>
            <div className="space-y-2.5">
              {[
                { label: "Browser",      value: browserInfo.name },
                { label: "Version",      value: browserInfo.version },
                { label: "Engine",       value: browserInfo.engine },
                { label: "Secure Context", value: browserInfo.isSecure ? "✓ HTTPS / Localhost" : "⚠ Insecure" },
              ].map(row => (
                <div key={row.label} className="flex items-center justify-between text-xs">
                  <span className="text-slate-500">{row.label}</span>
                  <span className={`font-medium ${row.label === "Secure Context" ? (browserInfo.isSecure ? "text-emerald-300" : "text-rose-300") : "text-slate-300"}`}>
                    {row.value}
                  </span>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Server-side OS telemetry card */}
          <motion.div
            initial={{ opacity: 0, x: -15 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3 }}
            className="rounded-2xl border border-white/10 bg-white/5 p-4 backdrop-blur-xl"
          >
            <div className="mb-3 flex items-center gap-2">
              <HardDrive className="h-4 w-4 text-amber-400" />
              <h3 className="text-sm font-semibold text-white">Server Telemetry</h3>
              {serverLoading && <RefreshCw className="ml-auto h-3 w-3 animate-spin text-slate-500" />}
            </div>
            {serverOs ? (
              <div className="space-y-2.5">
                {[
                  { label: "Platform",    value: serverOs.platform },
                  { label: "CPU",         value: serverOs.cpu },
                  { label: "Cores",       value: String(serverOs.cores) },
                  { label: "Total RAM",   value: serverOs.totalMem },
                  { label: "Free RAM",    value: serverOs.freeMem },
                  { label: "Uptime",      value: serverOs.uptime },
                  { label: "Local IP",    value: serverOs.localIp },
                  { label: "MAC Addr",    value: serverOs.macAddress },
                  { label: "Subnet",      value: serverOs.subnet },
                  { label: "Adapter",     value: serverOs.networkAdapter },
                ].map(row => (
                  <div key={row.label} className="flex items-center justify-between gap-2 text-xs">
                    <span className="shrink-0 text-slate-500">{row.label}</span>
                    <span className="truncate text-right font-medium text-slate-300">{row.value}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <Wifi className="h-3.5 w-3.5 text-slate-600" />
                {serverLoading ? "Connecting to SentinelGrid agent…" : "Agent offline — start backend server"}
              </div>
            )}
          </motion.div>
        </div>

        {/* ── Middle: Risk factors ── */}
        <div className="space-y-4 lg:col-span-2">

          {/* Alert banners for critical/high */}
          {criticalRisks.length > 0 && (
            <motion.div
              initial={{ opacity: 0, scale: 0.97 }}
              animate={{ opacity: 1, scale: 1 }}
              className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-4"
            >
              <div className="flex items-center gap-2 mb-2">
                <XCircle className="h-4 w-4 text-rose-400" />
                <span className="text-sm font-bold text-rose-300">
                  {criticalRisks.length} Critical Security Risk{criticalRisks.length > 1 ? "s" : ""} Detected
                </span>
              </div>
              <p className="text-xs text-rose-200/70">
                Immediate remediation required. This OS posture may violate NIST SP 800-40 patch management compliance.
              </p>
            </motion.div>
          )}

          {highRisks.length > 0 && criticalRisks.length === 0 && (
            <motion.div
              initial={{ opacity: 0, scale: 0.97 }}
              animate={{ opacity: 1, scale: 1 }}
              className="rounded-2xl border border-orange-400/30 bg-orange-400/10 p-4"
            >
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-orange-400" />
                <span className="text-sm font-bold text-orange-300">
                  {highRisks.length} High Severity Risk{highRisks.length > 1 ? "s" : ""} — Review Required
                </span>
              </div>
            </motion.div>
          )}

          {/* Risk Factors List */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.15 }}
            className="rounded-2xl border border-white/10 bg-white/5 p-4 backdrop-blur-xl"
          >
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-400" />
                <h3 className="text-sm font-semibold text-white">OS Risk Factors</h3>
                <span className="rounded-full border border-white/10 bg-black/20 px-2 py-0.5 text-xs text-slate-400">
                  {riskFactors.length}
                </span>
              </div>
            </div>
            <div className="space-y-2">
              <AnimatePresence>
                {riskFactors.map(risk => (
                  <motion.div
                    key={risk.id}
                    layout
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -8 }}
                    className={`cursor-pointer rounded-xl border p-3 transition hover:opacity-90 ${severityColor(risk.severity)}`}
                    onClick={() => setActiveRisk(activeRisk === risk.id ? null : risk.id)}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="text-xs font-semibold text-white">{risk.title}</p>
                        {risk.mitreId && (
                          <span className="mt-0.5 inline-block rounded border border-white/10 bg-black/20 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                            {risk.mitreId}
                          </span>
                        )}
                      </div>
                      <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase ${severityColor(risk.severity)}`}>
                        {risk.severity}
                      </span>
                    </div>

                    <AnimatePresence>
                      {activeRisk === risk.id && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: "auto" }}
                          exit={{ opacity: 0, height: 0 }}
                          className="overflow-hidden"
                        >
                          <p className="mt-2 text-xs leading-relaxed text-slate-300">{risk.description}</p>
                          {risk.cve && (
                            <p className="mt-1.5 font-mono text-[10px] text-rose-300">CVE Ref: {risk.cve}</p>
                          )}
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          </motion.div>

          {/* Compliance Status */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.25 }}
            className="rounded-2xl border border-white/10 bg-white/5 p-4 backdrop-blur-xl"
          >
            <div className="mb-4 flex items-center gap-2">
              <Lock className="h-4 w-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white">Compliance Posture</h3>
            </div>
            <div className="mb-4 grid grid-cols-2 gap-3">
              <div className="rounded-xl border border-white/10 bg-black/20 p-3 text-center">
                <p className="text-xs text-slate-500 mb-1">NIST SP 800-40</p>
                <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${complianceBadge(complianceStatus.nist)}`}>
                  {complianceStatus.nist}
                </span>
              </div>
              <div className="rounded-xl border border-white/10 bg-black/20 p-3 text-center">
                <p className="text-xs text-slate-500 mb-1">CIS Controls v8</p>
                <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${complianceBadge(complianceStatus.cis)}`}>
                  {complianceStatus.cis}
                </span>
              </div>
            </div>
            <div className="space-y-1.5">
              {complianceStatus.details.map((d, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-slate-400">
                  <ChevronRight className="mt-0.5 h-3 w-3 shrink-0 text-slate-600" />
                  <span>{d}</span>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Recommendations */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.35 }}
            className="rounded-2xl border border-white/10 bg-white/5 p-4 backdrop-blur-xl"
          >
            <button
              onClick={() => setShowRecs(r => !r)}
              className="flex w-full items-center justify-between"
            >
              <div className="flex items-center gap-2">
                <Eye className="h-4 w-4 text-sky-400" />
                <h3 className="text-sm font-semibold text-white">Security Hardening Recommendations</h3>
                <span className="rounded-full border border-white/10 bg-black/20 px-2 py-0.5 text-xs text-slate-400">
                  {os.recommendations.length}
                </span>
              </div>
              <ChevronRight className={`h-4 w-4 text-slate-500 transition-transform ${showRecs ? "rotate-90" : ""}`} />
            </button>

            <AnimatePresence>
              {showRecs && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  className="overflow-hidden"
                >
                  <div className="mt-3 space-y-2">
                    {os.recommendations.map((rec, i) => (
                      <div key={i} className="flex items-start gap-2 rounded-xl border border-sky-400/10 bg-sky-400/5 p-3">
                        <Zap className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sky-400" />
                        <p className="text-xs text-slate-300 leading-relaxed">{rec}</p>
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>

          {/* Vulnerabilities Summary */}
          {os.vulnerabilities.length > 0 && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
              className="rounded-2xl border border-white/10 bg-white/5 p-4 backdrop-blur-xl"
            >
              <div className="mb-3 flex items-center gap-2">
                <Shield className="h-4 w-4 text-rose-400" />
                <h3 className="text-sm font-semibold text-white">Vulnerability Summary</h3>
              </div>
              <div className="space-y-2">
                {os.vulnerabilities.map((v, i) => {
                  const isCrit   = v.toLowerCase().startsWith("critical");
                  const isHigh   = v.toLowerCase().startsWith("high");
                  const isMedium = v.toLowerCase().startsWith("medium");
                  const color = isCrit ? "text-rose-300" : isHigh ? "text-orange-300" : isMedium ? "text-amber-300" : "text-sky-300";
                  return (
                    <div key={i} className="flex items-start gap-2 text-xs">
                      <AlertTriangle className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${color}`} />
                      <span className={color}>{v}</span>
                    </div>
                  );
                })}
              </div>
            </motion.div>
          )}
        </div>
      </div>

      {/* ── Footer: detected-at ── */}
      <div className="text-center text-xs text-slate-600">
        Last scanned: {new Date(profile.os.detectedAt).toLocaleString()} · SentinelGrid OS Security Monitor v1.0
      </div>
    </div>
  );
}
