import { useState, useEffect, useRef, useMemo, memo, lazy, Suspense } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell, Legend,
} from "recharts";
import {
  Shield, AlertTriangle, Activity, Network, Eye, Zap,
  Terminal, Database, Globe, RefreshCw, ChevronRight, X,
  CheckCircle, Clock, Cpu, FileText, Server, Flame, Monitor, LogOut, HardDrive, Wifi,
} from "lucide-react";
import HyperbolicTopology from "./components/HyperbolicTopology";
import ChronoMonitor from "./components/ChronoMonitor";
import LabEngineInterface from "./components/LabEngineInterface";
import AkashicHorizon from "./components/AkashicHorizon";
import EgoLockStatus from "./components/EgoLockStatus";
import TelemetryIntegrityPanel from "./components/TelemetryIntegrityPanel";
import { Token, logout, refreshAccessToken, fetchMe } from "./utils/api";
import { useSOCStore, selectActiveCnt, selectBlockedCnt, selectCriticalCnt, selectContainedCnt, selectThreatPressure, selectTotalPps, selectTotalBytes, type Severity, type TabId, type ConnStatus } from "./stores/socStore";
import { useWebSocket } from "./hooks/useWebSocket";
import { useSystemStats, usePermissions, usePluginData } from "./hooks/useSOCQueries";

const MitreMatrix = lazy(() => import("./components/MitreMatrix"));
const NistCompliance = lazy(() => import("./components/NistCompliance"));
const VirusTotalScanner = lazy(() => import("./components/VirusTotalScanner"));
const WindowsLogViewer = lazy(() => import("./components/WindowsLogViewer"));
const ThreatIntelligence = lazy(() => import("./components/ThreatIntelligence"));
const MalwareSandbox = lazy(() => import("./components/MalwareSandbox"));
const VulnPentestManager = lazy(() => import("./components/VulnPentestManager"));
const CrossPlatformFim = lazy(() => import("./components/CrossPlatformFim"));
const AdvancedVirtualBox = lazy(() => import("./components/AdvancedVirtualBox"));
const AIAgent = lazy(() => import("./components/AIAgent"));
const LoginScreen = lazy(() => import("./components/LoginScreen"));
const OSSecurityPanel = lazy(() => import("./components/OSSecurityPanel"));
const SystemScanner = lazy(() => import("./components/SystemScanner"));
const GlobalAnalytics = lazy(() => import("./components/GlobalAnalytics"));
const InteractiveVM = lazy(() => import("./components/InteractiveVM"));

type Protocol = "HTTPS" | "SSH" | "RDP" | "DNS" | "TLS" | "MQTT" | "SMB" | "FTP" | "LDAP" | "SYSTEM";

/* ── constants ── */
const ZONES = ["Perimeter", "Identity", "Payments", "Remote Access", "Data Core", "OT Segment", "Cloud", "DMZ"];
const PORT_MAP: Record<Protocol, number> = { HTTPS: 443, SSH: 22, RDP: 3389, DNS: 53, TLS: 8443, MQTT: 1883, SMB: 445, FTP: 21, LDAP: 389, SYSTEM: 0 };


// Scenarios and simulated constants removed for real system data integration.

/* ── helpers ── */
function clock(ts: number) {
  return new Intl.DateTimeFormat("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(ts);
}
function relative(ts: number, now: number) {
  const s = Math.max(0, Math.floor((now - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ago`;
}

const SEV_BADGE: Record<Severity, string> = {
  low: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200",
  medium: "border-amber-400/30 bg-amber-400/10 text-amber-200",
  high: "border-orange-400/30 bg-orange-400/10 text-orange-200",
  critical: "border-rose-500/30 bg-rose-500/10 text-rose-200 animate-pulse",
};
const SEV_BAR: Record<Severity, string> = {
  low: "bg-emerald-400", medium: "bg-amber-400", high: "bg-orange-400", critical: "bg-rose-500"
};
const CONN_BADGE: Record<ConnStatus, string> = {
  active: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200",
  observing: "border-sky-400/30 bg-sky-400/10 text-sky-200",
  dropped: "border-orange-400/30 bg-orange-400/10 text-orange-200",
  quarantined: "border-rose-500/30 bg-rose-500/10 text-rose-200",
  blocked: "border-red-600/30 bg-red-600/10 text-red-200",
};
const PIE_COLORS = ["#f43f5e", "#fb923c", "#f59e0b", "#34d399"];


/* ── sub-components ── */
function Badge({ children, cls }: { children: React.ReactNode; cls: string }) {
  return <span className={`rounded-full border px-2.5 py-1 text-xs font-medium uppercase tracking-wide ${cls}`}>{children}</span>;
}

function PermissionBadge({ label, enabled, value, icon }: { label: string; enabled: boolean; value?: string; icon?: React.ReactNode }) {
  return (
    <div className={`rounded-lg border px-2 py-1.5 flex items-center gap-2 ${enabled ? 'border-emerald-400/30 bg-emerald-500/10' : 'border-rose-400/30 bg-rose-500/10'}`}>
      {icon && <span className={enabled ? 'text-emerald-400' : 'text-rose-400'}>{icon}</span>}
      <div className="flex-1 min-w-0">
        <span className="text-[10px] text-slate-400 block truncate">{label}</span>
        <span className={`text-xs font-semibold block truncate ${enabled ? 'text-emerald-300' : 'text-rose-300'}`}>
          {value || (enabled ? 'Yes' : 'No')}
        </span>
      </div>
    </div>
  );
}

const Panel = memo(function Panel({ title, sub, action, children, className = "" }: {
  title: string; sub?: string; action?: React.ReactNode; children: React.ReactNode; className?: string;
}) {
  return (
    <motion.section 
      initial={{ opacity: 0, y: 15 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-50px" }}
      transition={{ duration: 0.5, ease: "easeOut" }}
      className={`rounded-3xl glass-v2 p-5 shadow-2xl shadow-slate-950/30 transition-all duration-300 hover:border-white/20 hover:shadow-cyan-500/5 relative overflow-hidden ${className}`}
    >
      {/* Holographic scan line */}
      <div className="absolute inset-0 pointer-events-none scan-line opacity-30" />
      <div className="relative z-10">
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-white">{title}</h2>
            {sub && <p className="mt-0.5 text-sm text-slate-400">{sub}</p>}
          </div>
          {action}
        </div>
        {children}
      </div>
    </motion.section>
  );
});

const StatCard = memo(function StatCard({ label, value, sub, tone, icon }: {
  label: string; value: string | number; sub: string;
  tone: "rose" | "emerald" | "sky" | "amber" | "purple" | "orange"; icon: React.ReactNode;
}) {
  const t: Record<string, string> = {
    rose: "from-rose-500/20 to-transparent ring-rose-500/20 text-rose-300 shadow-rose-500/10",
    emerald: "from-emerald-500/20 to-transparent ring-emerald-500/20 text-emerald-300 shadow-emerald-500/10",
    sky: "from-sky-500/20 to-transparent ring-sky-500/20 text-sky-300 shadow-sky-500/10",
    amber: "from-amber-500/20 to-transparent ring-amber-500/20 text-amber-300 shadow-amber-500/10",
    purple: "from-purple-500/20 to-transparent ring-purple-500/20 text-purple-300 shadow-purple-500/10",
    orange: "from-orange-500/20 to-transparent ring-orange-500/20 text-orange-300 shadow-orange-500/10",
  };
  return (
    <motion.div 
      whileHover={{ scale: 1.05, translateY: -8, rotateX: 5, rotateY: -3 }}
      whileTap={{ scale: 0.97 }}
      transition={{ type: "spring", stiffness: 300, damping: 20 }}
      className={`stat-card-3d rounded-3xl border border-white/10 bg-gradient-to-br p-5 ring-1 shadow-xl transform-gpu cursor-pointer relative overflow-hidden ${t[tone]}`}
    >
      {/* Neon edge glow on hover */}
      <div className="absolute inset-0 rounded-3xl opacity-0 hover:opacity-100 transition-opacity duration-500 pointer-events-none" style={{ boxShadow: 'inset 0 0 30px rgba(34, 211, 238, 0.05)' }} />
      <div className="relative z-10">
        <div className="flex items-center justify-between">
          <p className="text-xs font-medium uppercase tracking-widest text-slate-400">{label}</p>
          <div className={`rounded-xl border border-white/10 bg-black/30 p-2.5 ${t[tone].split(" ").find(c => c.startsWith("text-"))}`}>
            {icon}
          </div>
        </div>
        <p className="mt-3 text-3xl font-bold text-white drop-shadow-md">{value}</p>
        <p className="mt-1 text-sm text-slate-400">{sub}</p>
      </div>
    </motion.div>
  );
});

const TABS: { id: TabId; label: string; icon: React.ReactNode }[] = [
  { id: "dashboard",   label: "SOC Dashboard",      icon: <Activity className="h-4 w-4" /> },
  { id: "analytics",   label: "Global Analytics",   icon: <Activity className="h-4 w-4 text-sky-400" /> },
  { id: "ossec",       label: "OS Security",         icon: <Monitor className="h-4 w-4 text-sky-400" /> },
  { id: "ai_agent",   label: "AI Analyst",           icon: <Cpu className="h-4 w-4 text-purple-400" /> },
  { id: "winlogs",    label: "Live Event Logs",      icon: <FileText className="h-4 w-4 text-amber-400" /> },
  { id: "sandbox",    label: "Malware Sandbox",      icon: <Server className="h-4 w-4" /> },
  { id: "crossplat",  label: "Cross-Platform FIM",  icon: <Activity className="h-4 w-4" /> },
  { id: "vulnpentest", label: "Vuln & Pentest",      icon: <Flame className="h-4 w-4" /> },
  { id: "advancedvb", label: "VirtualBox Gov",       icon: <Shield className="h-4 w-4" /> },
  { id: "mitre",      label: "MITRE ATT&CK",         icon: <Shield className="h-4 w-4" /> },
  { id: "nist",       label: "NIST CSF 2.0",         icon: <CheckCircle className="h-4 w-4" /> },
  { id: "virustotal", label: "VirusTotal",           icon: <Globe className="h-4 w-4" /> },
  { id: "intel",      label: "Threat Intel",         icon: <Cpu className="h-4 w-4" /> },
  { id: "scanner",    label: "System Scanner",       icon: <HardDrive className="h-4 w-4 text-indigo-400" /> },
  { id: "vm",         label: "Interactive VM",       icon: <Terminal className="h-4 w-4 text-cyan-400" /> },
];

/* ── MAIN ── */
export default function App() {
  const [now, setNow] = useState(Date.now);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Zustand store bindings (subscription-based, only rerenders on change)
  const tab = useSOCStore((s) => s.tab);
  const setTab = useSOCStore((s) => s.setTab);
  const authReady = useSOCStore((s) => s.authReady);
  const isAuthenticated = useSOCStore((s) => s.isAuthenticated);
  const user = useSOCStore((s) => s.user);
  const connections = useSOCStore((s) => s.connections);
  const alerts = useSOCStore((s) => s.alerts);
  const traffic = useSOCStore((s) => s.traffic);
  const systemStats = useSOCStore((s) => s.systemStats);
  const statsHistory = useSOCStore((s) => s.statsHistory);
  const segmentData = useSOCStore((s) => s.segmentData);
  const permissions = useSOCStore((s) => s.permissions);
  const wsStatus = useSOCStore((s) => s.wsStatus);
  const wsLatency = useSOCStore((s) => s.wsLatency);
  const responseLog = useSOCStore((s) => s.responseLog);
  const telemetryMeta = useSOCStore((s) => s.telemetryMeta);

  // Derived selectors (memoized in store)
  const activeCnt = useSOCStore(selectActiveCnt);
  const blockedCnt = useSOCStore(selectBlockedCnt);
  const criticalCnt = useSOCStore(selectCriticalCnt);
  const containedCnt = useSOCStore(selectContainedCnt);
  const threatPressure = useSOCStore(selectThreatPressure);
  const totalPps = useSOCStore(selectTotalPps);
  const totalBytes = useSOCStore(selectTotalBytes);
  const malAlerts = useMemo(() => alerts.filter((alert) => alert.malicious), [alerts]);
  const containRate = malAlerts.length ? Math.round((containedCnt / malAlerts.length) * 100) : 100;
  const avgRisk = connections.length > 0 ? Math.round(connections.reduce((s, c) => s + c.risk, 0) / connections.length) : 0;

  // --- Poincaré & HUD Deep Segments States ---
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [activeSegmentTab, setActiveSegmentTab] = useState<string>("W");
  const [threatLevel, setThreatLevel] = useState<"green" | "yellow" | "red">("green");
  const overrideThreatLevel = useRef<boolean>(false);

  useEffect(() => {
    if (!overrideThreatLevel.current) {
      const level = threatPressure >= 70 ? "red" : threatPressure >= 40 ? "yellow" : "green";
      setThreatLevel(level);
    }
  }, [threatPressure]);

  const handleThreatLevelChange = (level: "green" | "yellow" | "red") => {
    overrideThreatLevel.current = true;
    setThreatLevel(level);
  };

  const handleRollbackSuccess = () => {
    overrideThreatLevel.current = false;
    setThreatLevel("green");
  };

  const selectedNode = useMemo(() => {
    if (!selectedNodeId) return null;
    const nodesList = [
      { id: "gateway", name: "Core Firewall / Gateway", ip: "10.0.2.1", type: "gateway" },
      { id: "win2025", name: "Windows Server 2025 AD", ip: "10.0.2.15", type: "server" },
      { id: "kali", name: "Kali Attack Platform", ip: "10.0.2.16", type: "external" },
      { id: "android", name: "Android Test Container", ip: "10.0.2.20", type: "mobile" },
      { id: "ios", name: "iOS Core Sandbox", ip: "10.0.2.21", type: "mobile" },
      { id: "db_shard", name: "Database Shard Core", ip: "10.0.2.5", type: "server" },
      { id: "siem_hub", name: "SIEM Telemetry Collector", ip: "10.0.2.8", type: "server" },
      { id: "analyst_ws", name: "Analyst Workstation", ip: "10.0.2.100", type: "workstation" }
    ];
    return nodesList.find(n => n.id === selectedNodeId) || null;
  }, [selectedNodeId]);

  useEffect(() => {
    if (selectedNodeId) {
      setActiveSegmentTab("W");
    }
  }, [selectedNodeId]);

  // --- 3D Spatial Web Audio Setup ---
  const audioCtxRef = useRef<AudioContext | null>(null);
  const pannerNodeRef = useRef<PannerNode | null>(null);

  const initAudio = () => {
    if (audioCtxRef.current) return;
    try {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      const ctx = new AudioCtx();
      const panner = ctx.createPanner();
      panner.panningModel = "HRTF";
      panner.distanceModel = "inverse";
      panner.refDistance = 1;
      panner.maxDistance = 10000;
      panner.rolloffFactor = 1;
      panner.coneInnerAngle = 360;
      panner.coneOuterAngle = 0;
      panner.coneOuterGain = 0;
      
      panner.connect(ctx.destination);
      
      audioCtxRef.current = ctx;
      pannerNodeRef.current = panner;
      console.log("3D Audio Context initialized successfully!");
    } catch (e) {
      console.error("Failed to initialize Web Audio API", e);
    }
  };

  useEffect(() => {
    const handleInteraction = () => {
      initAudio();
      window.removeEventListener("click", handleInteraction);
      window.removeEventListener("keydown", handleInteraction);
    };
    window.addEventListener("click", handleInteraction);
    window.addEventListener("keydown", handleInteraction);
    return () => {
      window.removeEventListener("click", handleInteraction);
      window.removeEventListener("keydown", handleInteraction);
    };
  }, []);

  const prevAlertsLength = useRef(alerts.length);
  useEffect(() => {
    if (alerts.length > prevAlertsLength.current) {
      const newAlert = alerts[alerts.length - 1];
      if (newAlert && audioCtxRef.current && pannerNodeRef.current) {
        const zoneIdx = ZONES.indexOf(newAlert.zone);
        let x = 0;
        if (zoneIdx !== -1) {
          x = (zoneIdx / (ZONES.length - 1)) * 2 - 1;
        } else {
          let hash = 0;
          for (let i = 0; i < newAlert.srcIp.length; i++) {
            hash = newAlert.srcIp.charCodeAt(i) + ((hash << 5) - hash);
          }
          x = (hash % 100) / 100;
        }
        const y = 0;
        const z = 1 - Math.abs(x);
        
        const panner = pannerNodeRef.current;
        const ctx = audioCtxRef.current;
        
        if (panner.positionX) {
          panner.positionX.setValueAtTime(x, ctx.currentTime);
          panner.positionY.setValueAtTime(y, ctx.currentTime);
          panner.positionZ.setValueAtTime(z, ctx.currentTime);
        } else {
          panner.setPosition(x, y, z);
        }
        
        let freq = 160;
        let duration = 0.5;
        let type: OscillatorType = "sine";
        
        if (newAlert.severity === "critical") {
          freq = 380;
          duration = 1.0;
          type = "sawtooth";
        } else if (newAlert.severity === "high") {
          freq = 280;
          duration = 0.7;
          type = "triangle";
        } else if (newAlert.severity === "medium") {
          freq = 210;
          duration = 0.5;
          type = "triangle";
        }
        
        try {
          const osc = ctx.createOscillator();
          const gainNode = ctx.createGain();
          const filter = ctx.createBiquadFilter();
          
          osc.type = type;
          osc.frequency.setValueAtTime(freq, ctx.currentTime);
          
          filter.type = "lowpass";
          filter.frequency.setValueAtTime(800, ctx.currentTime);
          
          osc.connect(filter);
          filter.connect(gainNode);
          gainNode.connect(panner);
          
          gainNode.gain.setValueAtTime(0, ctx.currentTime);
          gainNode.gain.linearRampToValueAtTime(newAlert.severity === "critical" ? 0.35 : 0.25, ctx.currentTime + 0.05);
          gainNode.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + duration);
          
          osc.start(ctx.currentTime);
          osc.stop(ctx.currentTime + duration);
        } catch (e) {
          console.warn("Could not play spatialized warning hum:", e);
        }
      }
    }
    prevAlertsLength.current = alerts.length;
  }, [alerts]);

  // Hooks: WebSocket + React Query
  useWebSocket();
  useSystemStats();
  usePermissions();
  usePluginData();

  // Drag-to-scroll Nav State
  const navRef = useRef<HTMLElement>(null);
  const [isDraggingNav, setIsDraggingNav] = useState(false);
  const [navStartX, setNavStartX] = useState(0);
  const [navScrollLeft, setNavScrollLeft] = useState(0);

  const handleNavMouseDown = (e: React.MouseEvent) => {
    if (!navRef.current) return;
    setIsDraggingNav(true);
    setNavStartX(e.pageX - navRef.current.offsetLeft);
    setNavScrollLeft(navRef.current.scrollLeft);
  };

  const handleNavMouseMove = (e: React.MouseEvent) => {
    if (!isDraggingNav || !navRef.current) return;
    e.preventDefault();
    const x = e.pageX - navRef.current.offsetLeft;
    const walk = (x - navStartX) * 1.5;
    navRef.current.scrollLeft = navScrollLeft - walk;
  };

  /* Session bootstrap: recover from the HttpOnly refresh cookie after a reload. */
  useEffect(() => {
    let cancelled = false;
    const store = useSOCStore.getState();
    (async () => {
      if (Token.isLoggedIn()) {
        const u = await fetchMe();
        if (u && !cancelled) {
          store.setAuth(true, true, u);
          return;
        }
      }
      const refreshed = await refreshAccessToken();
      if (!cancelled) {
        store.setAuth(true, refreshed, Token.getUser());
      }
    })();
    return () => { cancelled = true; };
  }, []);

  /* Clock */
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const sevDist = useMemo(
    () =>
      alerts.reduce(
        (acc, alert) => {
          acc[alert.severity] += 1;
          return acc;
        },
        { low: 0, medium: 0, high: 0, critical: 0 } as Record<Severity, number>
      ),
    [alerts]
  );

  const catDist = useMemo(() => {
    const map = new Map<string, number>();
    alerts.forEach((alert) => map.set(alert.category, (map.get(alert.category) ?? 0) + 1));
    return [...map.entries()].map(([name, value]) => ({ name, value }));
  }, [alerts]);

  const pieData = useMemo(() => [
    { name: "Critical", value: sevDist.critical },
    { name: "High", value: sevDist.high },
    { name: "Medium", value: sevDist.medium },
    { name: "Low", value: sevDist.low },
  ].filter(d => d.value > 0), [sevDist]);

  const timelineStats = useMemo(() => {
    const latest = traffic[traffic.length - 1];
    const prev = traffic[traffic.length - 2] ?? latest;
    const first = traffic[0];
    const avgTraffic = traffic.length ? Math.round(traffic.reduce((s, p) => s + p.traffic, 0) / traffic.length) : 0;
    const threatSum = traffic.reduce((s, p) => s + p.threats, 0);
    const blockSum = traffic.reduce((s, p) => s + p.blocked, 0);
    const direction = latest && prev ? latest.traffic - prev.traffic : 0;
    return {
      latest,
      avgTraffic,
      threatSum,
      blockSum,
      direction,
      window: first && latest ? `${first.t} - ${latest.t}` : "Waiting for live samples",
    };
  }, [traffic]);

  const telemetryAgeMs = telemetryMeta.lastUpdateAt ? now - telemetryMeta.lastUpdateAt : null;
  const telemetryPulseLabel = telemetryAgeMs === null ? "Waiting" : telemetryAgeMs < 1000 ? "Live" : `${(telemetryAgeMs / 1000).toFixed(1)}s`;

  if (!authReady) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-[#020617] gap-6">
        <div className="pointer-events-none fixed inset-0 cyber-grid opacity-20" />
        <div className="relative">
          <div className="h-20 w-20 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-2xl shadow-cyan-500/30 breathe-glow">
            <Shield className="h-10 w-10 text-white" />
          </div>
          <div className="absolute -inset-3 rounded-2xl border border-cyan-400/30 animate-pulse" />
          <div className="absolute -inset-6 rounded-3xl border border-cyan-400/10" style={{ animation: 'pulse-ring-expand 2s cubic-bezier(0,0,0.2,1) infinite' }} />
        </div>
        <div className="text-center">
          <p className="text-lg font-bold text-white tracking-tight">SentinelGrid</p>
          <p className="text-xs text-cyan-300/60 uppercase tracking-[0.3em] mt-1">Restoring Secure Session</p>
        </div>
        <div className="w-48 h-1 bg-slate-800 rounded-full overflow-hidden">
          <motion.div className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full" animate={{ x: ['-100%', '200%'] }} transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }} />
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <LoginScreen onLoginSuccess={() => {
        useSOCStore.getState().setAuth(true, true, Token.getUser());
        useSOCStore.getState().setTab('dashboard');
      }} />
    );
  }

  // If authenticated, we are here.
  // The LoginScreen is not rendered.

  return (
    <div className="min-h-screen overflow-x-hidden bg-[#020617] text-slate-100 font-sans perspective-container">
      {/* Immersive background layers */}
      <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(56,189,248,0.12),_transparent_30%),radial-gradient(circle_at_bottom_right,_rgba(244,63,94,0.12),_transparent_26%)]" />
      <div className="pointer-events-none fixed inset-0 cyber-grid opacity-40" />
      {/* Floating ambient particles */}
      {[...Array(8)].map((_, i) => (
        <div key={`p-${i}`} className="pointer-events-none fixed rounded-full blur-sm float-particle" style={{ width: 3 + (i % 3) * 2, height: 3 + (i % 3) * 2, background: i % 2 === 0 ? 'rgba(34,211,238,0.15)' : 'rgba(168,85,247,0.12)', left: `${10 + i * 11}%`, top: `${15 + (i % 4) * 20}%`, animationDelay: `${i * 1.2}s` }} />
      ))}

      {/* Top nav */}
      <header className="sticky top-0 z-50 bg-black/70 backdrop-blur-2xl">
        <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-cyan-500/30 to-transparent" />
        <div className="mx-auto w-full max-w-screen-2xl px-4 sm:px-6 lg:px-8">
          <div className="flex h-16 min-w-0 items-center justify-between gap-4">
            {/* Logo */}
            <div className="flex items-center gap-3 shrink-0 group">
              <div className="relative">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-600 shadow-lg shadow-cyan-500/30 transition-transform group-hover:scale-110">
                  <Shield className="h-5 w-5 text-white" />
                </div>
                <div className="absolute -inset-1 rounded-xl border border-cyan-400/20 opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>
              <div>
                <p className="text-sm font-bold text-white leading-tight tracking-tight">SentinelGrid<span className="text-cyan-400 ml-1 text-[10px] font-mono align-super">v5</span></p>
                <p className="text-[10px] text-slate-500 leading-tight uppercase tracking-[0.2em]">Enterprise SOC</p>
              </div>
            </div>

            {/* Desktop tabs */}
            <nav 
              ref={navRef}
              onMouseDown={handleNavMouseDown}
              onMouseLeave={() => setIsDraggingNav(false)}
              onMouseUp={() => setIsDraggingNav(false)}
              onMouseMove={handleNavMouseMove}
              className={`hidden min-w-0 flex-1 justify-start gap-1 overflow-x-auto px-2 xl:flex [scrollbar-width:none] [&::-webkit-scrollbar]:hidden ${isDraggingNav ? 'cursor-grabbing select-none' : 'cursor-grab'}`}
            >
              {TABS.map(t => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setTab(t.id)}
                  className={`relative flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl px-2.5 py-2 text-xs font-medium transition 2xl:text-sm ${tab === t.id ? "bg-white/10 text-white shadow-lg shadow-cyan-500/5 tab-active-glow" : "text-slate-400 hover:text-slate-200 hover:bg-white/5"}`}
                >
                  {t.icon}
                  {t.label}
                </button>
              ))}
            </nav>

            {/* Status indicators */}
            <div className="hidden shrink-0 items-center gap-3 2xl:flex">
              <div className="flex items-center gap-4 border-l border-white/10 pl-4">
                <div className={`flex items-center gap-2 rounded-full border px-3 py-1.5 backdrop-blur-md pulse-ring ${
                  wsStatus === 'connected' ? 'border-emerald-400/30 bg-emerald-500/10' : 
                  wsStatus === 'connecting' ? 'border-amber-400/30 bg-amber-500/10' : 
                  'border-rose-400/30 bg-rose-500/10'
                }`}>
                  <div className={`h-2 w-2 rounded-full ${
                    wsStatus === 'connected' ? 'bg-emerald-400 heartbeat' : 
                    wsStatus === 'connecting' ? 'bg-amber-400 animate-pulse' : 
                    'bg-rose-400'
                  }`} />
                  <span className={`text-xs font-semibold ${
                    wsStatus === 'connected' ? 'text-emerald-200' : 
                    wsStatus === 'connecting' ? 'text-amber-200' : 
                    'text-rose-200'
                  }`}>
                    {wsStatus === 'connected' ? 'LIVE' : wsStatus === 'connecting' ? 'SYNC' : 'OFFLINE'}
                  </span>
                  {wsStatus === 'connected' && wsLatency > 0 && (
                    <span className="text-[10px] text-emerald-300/70 font-mono">{wsLatency}ms</span>
                  )}
                </div>
                <div className="flex items-center gap-2 rounded-full border border-sky-400/30 bg-sky-500/10 px-3 py-1.5 backdrop-blur-md">
                  <Wifi className="h-3 w-3 text-sky-400 electric" />
                  <span className="text-xs font-semibold text-sky-200">TELEMETRY</span>
                </div>
                <div className="flex items-center gap-2 rounded-full border border-rose-500/20 bg-rose-500/10 px-3 py-1.5">
                  <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />
                  <span className="text-xs font-semibold text-rose-200">{criticalCnt} Critical</span>
                </div>
                {segmentData.alerts.length > 0 && (
                  <div className="flex items-center gap-2 rounded-full border border-orange-500/20 bg-orange-500/10 px-3 py-1.5">
                    <Activity className="h-3.5 w-3.5 text-orange-400" />
                    <span className="text-xs font-semibold text-orange-200">{segmentData.alerts.length} Seg Alerts</span>
                  </div>
                )}
                <div className="text-right">
                  <p className="font-mono text-xs font-bold text-slate-300">{clock(now)}</p>
                  <p className="font-mono text-[10px] text-slate-500">LOCAL</p>
                </div>
                {user && (
                  <div className="flex items-center gap-3 border-l border-white/10 pl-4">
                    <div className="text-right hidden sm:block">
                      <p className="text-xs font-bold text-white leading-tight">{user.username}</p>
                      <p className="text-[10px] text-slate-500 uppercase tracking-wider leading-tight">{user.role}</p>
                    </div>
                    <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-xs font-bold text-white shadow-lg shadow-cyan-500/20">
                      {user.username.slice(0, 2).toUpperCase()}
                    </div>
                  </div>
                )}
                <button
                  onClick={async () => {
                    await logout();
                  }}
                  className="flex h-8 w-8 items-center justify-center rounded-full hover:bg-rose-500/10 transition text-slate-400 hover:text-rose-400 border border-white/10"
                  title="Log Out"
                >
                  <LogOut className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>

            {/* Mobile menu */}
            <button
              type="button"
              className="rounded-xl border border-white/10 bg-white/5 p-2 lg:hidden"
              onClick={() => setMobileMenuOpen(prev => !prev)}
            >
              {mobileMenuOpen ? <X className="h-5 w-5 text-slate-300" /> : <Terminal className="h-5 w-5 text-slate-300" />}
            </button>
          </div>
        </div>

        {/* Mobile nav */}
        {mobileMenuOpen && (
          <div className="border-t border-white/10 bg-black/80 px-4 py-3 lg:hidden overflow-y-auto max-h-[70vh]">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {TABS.map(t => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => { setTab(t.id); setMobileMenuOpen(false); }}
                  className={`flex min-w-0 items-center gap-2 rounded-xl px-3 py-3 text-sm font-medium transition ${tab === t.id ? "bg-white/10 text-white" : "text-slate-400 hover:text-white"}`}
                >
                  {t.icon}{t.label}
                </button>
              ))}
            </div>
          </div>
        )}
      </header>

      <Suspense fallback={<div className="flex h-[50vh] items-center justify-center text-white"><RefreshCw className="h-8 w-8 animate-spin text-sky-500" /></div>}>
        <AnimatePresence mode="wait">
        <motion.main 
          key={tab}
          initial={{ opacity: 0, y: 40, filter: "blur(12px)", scale: 0.96, rotateX: 3 }}
          animate={{ opacity: 1, y: 0, filter: "blur(0px)", scale: 1, rotateX: 0 }}
          exit={{ opacity: 0, y: -30, filter: "blur(12px)", scale: 0.96, rotateX: -2 }}
          transition={{ duration: 0.5, ease: [0.23, 1, 0.32, 1] }}
          className="mx-auto max-w-screen-2xl px-4 py-6 sm:px-6 lg:px-8 space-y-6"
        >
        {/* Framework banner */}
        <div className="rounded-3xl glass-v2 neon-border px-5 py-4 relative overflow-hidden">
          <div className="absolute inset-0 holographic opacity-20 pointer-events-none" />
          <div className="relative z-10 flex flex-wrap items-center gap-3">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-widest">Active Frameworks:</span>
            {[
              { label: "MITRE ATT&CK v15", cls: "border-rose-400/30 bg-rose-400/10 text-rose-200" },
              { label: "NIST CSF 2.0", cls: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200" },
              { label: "VirusTotal API", cls: "border-sky-400/30 bg-sky-400/10 text-sky-200" },
              { label: "Event Telemetry", cls: "border-amber-400/30 bg-amber-400/10 text-amber-200" },
              { label: "FIM Engine", cls: "border-purple-400/30 bg-purple-400/10 text-purple-200" },
              { label: "YARA Signatures", cls: "border-orange-400/30 bg-orange-400/10 text-orange-200" },
              { label: "AI Heuristic", cls: "border-cyan-400/30 bg-cyan-400/10 text-cyan-200" },
            ].map(f => (
              <motion.span key={f.label} whileHover={{ scale: 1.08 }} className={`rounded-full border px-3 py-1 text-xs font-medium cursor-default transition-shadow hover:shadow-lg ${f.cls}`}>
                {f.label}
              </motion.span>
            ))}
            <div className="ml-auto flex items-center gap-4">
              <div className="flex items-center gap-2">
                <div className="relative h-2 w-2">
                  <div className="absolute inset-0 rounded-full bg-emerald-400 heartbeat" />
                  <div className="absolute -inset-1 rounded-full border border-emerald-400/30 animate-ping" />
                </div>
                <span className="text-xs text-emerald-300 font-semibold">Live</span>
              </div>
              {wsLatency > 0 && <span className="text-[10px] text-slate-500 font-mono">{wsLatency}ms RTT</span>}
            </div>
          </div>
        </div>

        {/* Dashboard tab */}
        {tab === "dashboard" && (
          <div className="space-y-6">
            {/* Poincaré Hyperbolic Topology + Stat cards */}
            <div className="grid gap-6 xl:grid-cols-12 mb-2">
              <div className="xl:col-span-8 h-[450px]">
                <HyperbolicTopology
                  threatLevel={threatLevel}
                  selectedNodeId={selectedNodeId}
                  onSelectNode={(nodeId) => setSelectedNodeId(nodeId)}
                />
              </div>
              
              {/* Stat Cards Grid */}
              <div className="xl:col-span-4 grid gap-4 grid-cols-2">
                <StatCard
                  label="Threat Pressure"
                  value={`${threatPressure}/100`}
                  sub={`${criticalCnt} critical events correlated`}
                  tone="rose"
                  icon={<AlertTriangle className="h-4 w-4" />}
                />
                <StatCard
                  label="Protected Sessions"
                  value={activeCnt}
                  sub={`${blockedCnt} connections auto-killed`}
                  tone="emerald"
                  icon={<Shield className="h-4 w-4" />}
                />
                <StatCard
                  label="Detections Total"
                  value={alerts.length}
                  sub={`${containRate}% auto-contained by inline policy`}
                  tone="sky"
                  icon={<Eye className="h-4 w-4" />}
                />
                <StatCard
                  label="Network Throughput"
                  value={`${(totalPps / 1000).toFixed(1)}k pps`}
                  sub={`${(totalBytes / 1_000_000).toFixed(0)} MB aggregate`}
                  tone="amber"
                  icon={<Network className="h-4 w-4" />}
                />
              </div>
            </div>

            {/* Hardware Telemetry Advancement */}
            <div className="grid gap-6 lg:grid-cols-12">
              <div className="lg:col-span-8 glass-panel rounded-3xl border border-white/10 p-6">
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/20 border border-indigo-500/30">
                      <Cpu className="h-5 w-5 text-indigo-400" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white uppercase tracking-wider">Host Resource Metrics</h3>
                      <p className="text-xs text-slate-500">Live CPU and Memory utilization from local agent</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-xs font-mono">
                    {systemStats.plugins !== undefined && (
                      <div className="flex items-center gap-2 mr-2">
                        <div className="h-3 w-3 rounded-sm bg-purple-500 animate-pulse" />
                        <span className="text-slate-300 font-bold">{systemStats.plugins} Enterprise Plugin(s) Active</span>
                      </div>
                    )}
                    <div className="flex items-center gap-2">
                      <div className="h-3 w-3 rounded-sm bg-indigo-500" />
                      <span className="text-slate-300">CPU: {systemStats.cpu}%</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="h-3 w-3 rounded-sm bg-sky-500" />
                      <span className="text-slate-300">MEM: {systemStats.memory}%</span>
                    </div>
                  </div>
                </div>
                <div className="h-48 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={statsHistory}>
                      <defs>
                        <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3}/>
                          <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                        </linearGradient>
                        <linearGradient id="colorMem" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.3}/>
                          <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                      <XAxis hide dataKey="ts" />
                      <YAxis hide domain={[0, 100]} />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px' }}
                        itemStyle={{ fontSize: '12px' }}
                      />
                      <Area type="monotone" dataKey="cpu" stroke="#6366f1" fillOpacity={1} fill="url(#colorCpu)" isAnimationActive={false} />
                      <Area type="monotone" dataKey="mem" stroke="#0ea5e9" fillOpacity={1} fill="url(#colorMem)" isAnimationActive={false} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="lg:col-span-4 space-y-4">
                <div className="glass-panel rounded-3xl border border-white/10 p-5 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/20 border border-emerald-500/30">
                      <HardDrive className="h-5 w-5 text-emerald-400" />
                    </div>
                    <div>
                      <p className="text-[10px] uppercase tracking-widest text-slate-500">System Uptime</p>
                      <p className="text-lg font-bold text-white">{(systemStats.uptime / 3600).toFixed(1)} Hours</p>
                    </div>
                  </div>
                </div>
                <div className="glass-panel rounded-3xl border border-white/10 p-5 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/20 border border-sky-500/30">
                      <Zap className="h-5 w-5 text-sky-400" />
                    </div>
                    <div>
                      <p className="text-[10px] uppercase tracking-widest text-slate-500">Telemetry Pulse</p>
                      <p className="text-lg font-bold text-white">{telemetryPulseLabel}</p>
                    </div>
                  </div>
                  <div className={`flex h-2 w-2 rounded-full ${wsStatus === "connected" ? "bg-emerald-400 animate-ping" : "bg-amber-400 animate-pulse"}`} />
                </div>
                <TelemetryIntegrityPanel
                  meta={telemetryMeta}
                  wsStatus={wsStatus}
                  wsLatency={wsLatency}
                  now={now}
                />
              </div>
            </div>

            {/* Secondary stats */}
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <StatCard
                label="Critical Alerts"
                value={criticalCnt}
                sub="MITRE-mapped critical severity"
                tone="rose"
                icon={<Zap className="h-4 w-4" />}
              />
              <StatCard
                label="Avg Risk Score"
                value={`${avgRisk}%`}
                sub="Across all monitored sessions"
                tone="orange"
                icon={<Activity className="h-4 w-4" />}
              />
              <StatCard
                label="Simulated Containment"
                value={containedCnt}
                sub="Demo sessions dropped or quarantined"
                tone="purple"
                icon={<RefreshCw className="h-4 w-4" />}
              />
              <StatCard
                label="Malicious IOCs"
                value={malAlerts.length}
                sub="Active threats in watchlist"
                tone="sky"
                icon={<Database className="h-4 w-4" />}
              />
            </div>

            {/* Charts row */}
            <div className="grid gap-6 xl:grid-cols-3">
              {/* Traffic chart */}
              <Panel title="Live Traffic & Threat Timeline" sub={`Current 60s rolling window: ${timelineStats.window}`} className="xl:col-span-2">
                <div className="mb-4 grid gap-2 sm:grid-cols-4">
                  <div className="rounded-2xl border border-white/10 bg-black/20 px-3 py-2">
                    <p className="text-[10px] uppercase tracking-widest text-slate-500">Current Traffic</p>
                    <p className="text-lg font-bold text-sky-300">{timelineStats.latest?.traffic ?? 0}%</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-black/20 px-3 py-2">
                    <p className="text-[10px] uppercase tracking-widest text-slate-500">Trend</p>
                    <p className={`text-lg font-bold ${timelineStats.direction > 0 ? "text-rose-300" : timelineStats.direction < 0 ? "text-emerald-300" : "text-slate-300"}`}>
                      {timelineStats.direction > 0 ? "+" : ""}{timelineStats.direction}%
                    </p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-black/20 px-3 py-2">
                    <p className="text-[10px] uppercase tracking-widest text-slate-500">Threat Pulses</p>
                    <p className="text-lg font-bold text-rose-300">{timelineStats.threatSum}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-black/20 px-3 py-2">
                    <p className="text-[10px] uppercase tracking-widest text-slate-500">Analysis</p>
                    <p className="truncate text-sm font-semibold text-amber-200">{timelineStats.latest?.analysis ?? "Collecting"}</p>
                  </div>
                </div>
                <div className="h-56">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={traffic}>
                      <defs>
                        <linearGradient id="trafficGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.02} />
                        </linearGradient>
                        <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.02} />
                        </linearGradient>
                        <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#fb923c" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#fb923c" stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid stroke="rgba(255,255,255,0.04)" />
                      <XAxis dataKey="t" tick={{ fill: "#475569", fontSize: 10 }} />
                      <YAxis tick={{ fill: "#475569", fontSize: 10 }} />
                      <Tooltip
                        contentStyle={{ background: "#0f172a", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "12px", fontSize: 12 }}
                        labelStyle={{ color: "#94a3b8" }}
                        formatter={(value, name) => [value, name]}
                      />
                      <Area type="monotone" dataKey="traffic" name="Traffic %" stroke="#38bdf8" fill="url(#trafficGrad)" strokeWidth={2} />
                      <Area type="monotone" dataKey="threats" name="Threats" stroke="#f43f5e" fill="url(#threatGrad)" strokeWidth={2} />
                      <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#fb923c" fill="url(#blockedGrad)" strokeWidth={2} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </Panel>

              {/* Severity pie */}
              <Panel title="Alert Severity Distribution" sub="Categorised detection breakdown">
                {pieData.length > 0 ? (
                  <div className="h-56">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={85} dataKey="value" paddingAngle={3}>
                          {pieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i]} />)}
                        </Pie>
                        <Tooltip
                          contentStyle={{ background: "#0f172a", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "12px", fontSize: 12 }}
                        />
                        <Legend formatter={(v) => <span className="text-xs text-slate-300">{v}</span>} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                  <div className="h-56 flex items-center justify-center">
                    <p className="text-sm text-slate-500">Accumulating detection data…</p>
                  </div>
                )}
              </Panel>
            </div>

            {/* Category bar + quick simulation */}
            <div className="grid gap-6 xl:grid-cols-3">
              <Panel title="Detection Category Breakdown" sub="Threats by sensor category" className="xl:col-span-2">
                <div className="h-44">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={catDist} layout="vertical">
                      <CartesianGrid stroke="rgba(255,255,255,0.04)" horizontal={false} />
                      <XAxis type="number" tick={{ fill: "#475569", fontSize: 10 }} />
                      <YAxis dataKey="name" type="category" tick={{ fill: "#94a3b8", fontSize: 11 }} width={130} />
                      <Tooltip
                        contentStyle={{ background: "#0f172a", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "12px", fontSize: 12 }}
                      />
                      <Bar dataKey="value" name="Detections" radius={[0, 6, 6, 0]}>
                        {catDist.map((_, i) => <Cell key={i} fill={["#f43f5e", "#fb923c", "#f59e0b", "#34d399", "#38bdf8", "#a855f7", "#ec4899"][i % 7]} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </Panel>

               <Panel title="Real-Time System Insights" sub="Live analysis from host telemetry and heuristic engine">
                 <div className="space-y-4">
                   <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                     <p className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-2">System Analysis</p>
                     <p className="text-sm text-slate-200 leading-relaxed italic">
                       {timelineStats.latest?.analysis || "Collecting system telemetry..."}
                     </p>
                   </div>
                   <div className="grid grid-cols-2 gap-3">
                     <div className="rounded-2xl border border-white/10 bg-black/20 p-3 text-center">
                       <p className="text-[10px] text-slate-500 uppercase">Host Risk</p>
                       <p className="text-lg font-bold text-white">{threatPressure}%</p>
                     </div>
                     <div className="rounded-2xl border border-white/10 bg-black/20 p-3 text-center">
                       <p className="text-[10px] text-slate-500 uppercase">Active Sessions</p>
                       <p className="text-lg font-bold text-white">{activeCnt}</p>
                     </div>
                   </div>
                 </div>
               </Panel>

               {/* System Permissions Panel */}
               <Panel title="System Permissions" sub={permissions ? `${permissions.isAdmin ? 'Admin' : 'Standard'} access` : 'Detecting...'}>
                 <div className="space-y-3">
                   {!permissions ? (
                     <p className="text-sm text-slate-500 text-center py-4">Detecting permissions...</p>
                   ) : (
                     <>
                       <div className={`rounded-xl border p-3 ${permissions.isAdmin ? 'border-emerald-400/30 bg-emerald-500/10' : 'border-amber-400/30 bg-amber-500/10'}`}>
                         <div className="flex items-center gap-2 mb-2">
                           <Shield className={`h-4 w-4 ${permissions.isAdmin ? 'text-emerald-400' : 'text-amber-400'}`} />
                           <span className="text-xs font-semibold text-slate-200">
                             {permissions.isAdmin ? 'Administrator Access' : 'Standard User'}
                           </span>
                         </div>
                         <p className="text-[10px] text-slate-400">
                           {permissions.isAdmin 
                             ? 'Full system monitoring enabled' 
                             : 'Limited monitoring - Security log access restricted'}
                         </p>
                       </div>
                       
                       {/* Permission Status Grid */}
                       <div className="grid grid-cols-2 gap-2">
                         <PermissionBadge 
                           label="Security Log" 
                           enabled={permissions.canAccessSecurityLog}
                           icon={<FileText className="h-3 w-3" />}
                         />
                         <PermissionBadge 
                           label="Process Memory" 
                           enabled={permissions.canAccessProcessMemory}
                           icon={<Cpu className="h-3 w-3" />}
                         />
                         <PermissionBadge 
                           label="USB Monitor" 
                           enabled={permissions.canMonitorUSB}
                           icon={<HardDrive className="h-3 w-3" />}
                         />
                         <PermissionBadge 
                           label="Platform" 
                           enabled={true}
                           value={permissions.platform}
                           icon={<Monitor className="h-3 w-3" />}
                         />
                       </div>
                       
                       {/* Recommendations */}
                       {permissions.recommendations?.length > 0 && (
                         <div className="mt-3 pt-3 border-t border-white/10">
                           <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Recommendations</p>
                           {permissions.recommendations.slice(0, 2).map((rec: any, i: number) => (
                             <div key={i} className={`text-xs py-1 ${rec.priority === 'high' ? 'text-rose-400' : 'text-amber-400'}`}>
                               • {rec.message}
                             </div>
                           ))}
                         </div>
                       )}
                     </>
                   )}
                 </div>
               </Panel>

               {/* Segment Health Monitoring - 6 Core Segments */}
               <Panel title="6-Core Segment Monitor" sub="Identity, Network, System, Endpoints, Apps, Data">
                 <div className="space-y-3 max-h-72 overflow-y-auto">
                   {Object.keys(segmentData.metrics).length === 0 ? (
                     <p className="text-sm text-slate-500 text-center py-4">Collecting segment data...</p>
                   ) : (
                     <>
                       {/* 6 Core Segments */}
                       {['identity', 'network', 'system', 'endpoints', 'applications', 'data'].map((segName) => {
                         const metrics = segmentData.metrics[segName] || {};
                         const hasData = (metrics.connections ?? 0) > 0 || (metrics.authEvents ?? 0) > 0 || (metrics.totalProcesses ?? 0) > 0;
                         const status = (metrics.suspiciousProcesses ?? 0) > 0 ? 'warning' : (metrics.highRiskProcesses ?? 0) > 0 ? 'critical' : hasData ? 'healthy' : 'idle';
                         
                         return (
                           <div key={segName} className="rounded-xl border border-white/10 bg-black/20 p-3">
                             <div className="flex items-center justify-between mb-2">
                               <div className="flex items-center gap-2">
                                 <div className={`h-2 w-2 rounded-full ${
                                   status === 'healthy' ? 'bg-emerald-400' : 
                                   status === 'warning' ? 'bg-amber-400' : 
                                   status === 'critical' ? 'bg-rose-400' : 'bg-slate-600'
                                 } ${hasData ? 'animate-pulse' : ''}`} />
                                 <span className="text-xs font-semibold text-slate-200 capitalize">{segName}</span>
                               </div>
                               {(metrics.risk ?? 0) > 0 && (
                                 <span className="text-[10px] text-rose-400">Risk: {metrics.risk}</span>
                               )}
                             </div>
                             
                             {/* Segment-specific metrics */}
                             <div className="grid grid-cols-2 gap-2 text-[10px]">
                               {segName === 'identity' && (
                                 <>
                                   <span className="text-slate-400">Auth: {metrics.authEvents || 0}</span>
                                   <span className={(metrics.failedLogons ?? 0) > 0 ? 'text-rose-400' : 'text-slate-400'}>
                                     Failed: {metrics.failedLogons || 0}
                                   </span>
                                 </>
                               )}
                               {segName === 'system' && (
                                 <>
                                   <span className="text-slate-400">Procs: {metrics.totalProcesses || 0}</span>
                                   {(metrics.suspiciousProcesses ?? 0) > 0 && (
                                     <span className="text-rose-400">Susp: {metrics.suspiciousProcesses}</span>
                                   )}
                                 </>
                               )}
                               {(segName === 'network' || segName === 'endpoints' || segName === 'applications' || segName === 'data') && (
                                 <>
                                   <span className="text-slate-400">Conns: {metrics.connections || 0}</span>
                                   <span className="text-slate-400">Active: {metrics.active || 0}</span>
                                 </>
                               )}
                             </div>
                           </div>
                         );
                       })}
                       
                       {/* Advanced Monitoring Summary */}
                       {segmentData.advancedMonitoring && (
                         <div className="mt-3 pt-3 border-t border-white/10">
                           <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Advanced Monitoring</p>
                           <div className="space-y-1 text-[10px]">
                             {segmentData.advancedMonitoring.defender && (
                               <div className="flex items-center gap-2">
                                 <Shield className={`h-3 w-3 ${segmentData.advancedMonitoring.defender.Enabled ? 'text-emerald-400' : 'text-rose-400'}`} />
                                 <span className={segmentData.advancedMonitoring.defender.Enabled ? 'text-emerald-300' : 'text-rose-300'}>
                                   Defender: {segmentData.advancedMonitoring.defender.Enabled ? 'Active' : 'Disabled'}
                                 </span>
                               </div>
                             )}
                             {(segmentData.advancedMonitoring.fimChanges?.length ?? 0) > 0 && (
                               <div className="text-rose-400">
                                 ⚠️ {segmentData.advancedMonitoring.fimChanges?.length} file integrity violations
                               </div>
                             )}
                             {(segmentData.advancedMonitoring.usbDevices?.connected?.length ?? 0) > 0 && (
                               <div className="text-slate-400">
                                 USB: {segmentData.advancedMonitoring.usbDevices?.connected?.length} devices
                               </div>
                             )}
                           </div>
                         </div>
                       )}
                     </>
                   )}
                 </div>
               </Panel>
            </div>

            {/* Main content */}
            <div className="grid gap-6 xl:grid-cols-12">
              <div className="xl:col-span-8 space-y-6">
                {/* Alert stream */}
                <Panel
                  title="Real-Time Threat Alert Stream"
                  sub="MITRE-mapped detections with automated containment actions"
                  action={
                    <span className="rounded-full border border-white/10 bg-black/20 px-3 py-1 text-xs text-slate-400">
                      {alerts.length} events
                    </span>
                  }
                >
                  {alerts.length === 0 ? (
                    <div className="py-12 text-center text-slate-500 text-sm">
                      Monitoring active — alerts will appear as threats are detected…
                    </div>
                  ) : (
                    <div className="space-y-3 max-h-[640px] overflow-y-auto pr-1">
                      {alerts.map(a => (
                        <div key={a.id} className={`rounded-2xl border p-4 transition hover:opacity-90 ${SEV_BADGE[a.severity]}`}>
                          <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                            <div className="space-y-2 min-w-0">
                              <div className="flex flex-wrap items-center gap-2">
                                <Badge cls={SEV_BADGE[a.severity]}>{a.severity}</Badge>
                                <span className="rounded-full border border-white/10 bg-black/20 px-2.5 py-1 text-xs text-slate-300">{a.category}</span>
                                <span className="rounded-lg border border-rose-500/20 bg-rose-500/10 px-2 py-0.5 text-xs font-mono text-rose-300">{a.mitreId}</span>
                                <span className="text-xs text-slate-500">{a.protocol}:{PORT_MAP[a.protocol]}</span>
                              </div>
                              <div>
                                <p className="text-sm font-semibold text-white">{a.mitreName}</p>
                                <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">{a.signature}</p>
                              </div>
                              <p className="text-xs text-slate-500">
                                <span className="text-slate-300 font-medium">{a.srcIp}</span> → <span className="text-slate-300 font-medium">{a.dstHost}</span> · {a.zone}
                              </p>
                              <div className="h-1.5 w-full rounded-full bg-black/30 overflow-hidden">
                                <div className={`h-full rounded-full ${SEV_BAR[a.severity]}`} style={{ width: `${a.score}%` }} />
                              </div>
                            </div>
                            <div className="shrink-0 space-y-2 text-right min-w-[140px]">
                              <p className={`text-sm font-semibold ${a.malicious ? "text-rose-300" : "text-emerald-300"}`}>
                                {a.killed ? "🔴 Dropped" : a.malicious ? "🟠 Observed" : "🟢 Allowed"}
                              </p>
                              <p className="text-xs text-slate-500">{relative(a.ts, now)}</p>
                              <p className="text-xs text-slate-400">Score: {a.score}/100</p>
                              <Badge cls={a.status === "auto-contained" ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-200" : "border-sky-400/30 bg-sky-400/10 text-sky-200"}>
                                {a.status}
                              </Badge>
                            </div>
                          </div>
                          {a.malicious && (
                            <div className="mt-3 rounded-xl border border-white/10 bg-black/20 px-3 py-2">
                              <p className="text-xs text-slate-400">
                                <span className="text-emerald-400 font-medium">Response: </span>{a.action}
                              </p>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>

                {/* Network connections */}
                <Panel
                  title="Live Network Session Monitor"
                  sub="All monitored connections with risk scoring, protocol analysis, and auto-drop enforcement"
                  action={<span className="text-xs text-slate-500">{(totalPps / 1000).toFixed(1)}k pps</span>}
                >
                  <div className="space-y-3">
                    {connections.map(c => (
                      <div key={c.id} className={`rounded-2xl border p-4 transition ${["dropped", "quarantined", "blocked"].includes(c.status) ? "border-rose-500/20 bg-rose-500/5" : "border-white/10 bg-black/20 hover:border-white/20"}`}>
                        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                          <div>
                            <div className="flex flex-wrap items-center gap-2 mb-1">
                              <p className="text-sm font-bold text-white">{c.srcIp}</p>
                              <Badge cls={CONN_BADGE[c.status]}>{c.status}</Badge>
                            </div>
                            <p className="text-xs text-slate-500">{c.geo} · {c.zone}</p>
                            <p className="text-xs text-slate-300 mt-1">→ <span className="font-medium">{c.dstHost}</span></p>
                            {c.mitreId && (
                              <span className="mt-1 inline-block rounded-lg border border-rose-500/20 bg-rose-500/10 px-2 py-0.5 text-xs font-mono text-rose-300">{c.mitreId}</span>
                            )}
                          </div>
                          <div>
                            <p className="text-xs text-slate-500 uppercase tracking-widest mb-1">Protocol</p>
                            <p className="text-sm font-semibold text-slate-200">{c.protocol}:{c.port}</p>
                            <p className="text-xs text-slate-500 mt-1">{relative(c.lastSeen, now)}</p>
                          </div>
                          <div>
                            <p className="text-xs text-slate-500 uppercase tracking-widest mb-1">Throughput</p>
                            <p className="text-lg font-bold text-white">{c.pps.toLocaleString()}</p>
                            <p className="text-xs text-slate-500">pps · {c.latency}ms · {(c.bytes / 1_000_000).toFixed(1)} MB</p>
                          </div>
                          <div>
                            <div className="flex justify-between text-xs text-slate-500 mb-1">
                              <span>Risk</span><span className={c.risk >= 70 ? "text-rose-300" : c.risk >= 45 ? "text-amber-300" : "text-emerald-300"}>{c.risk}%</span>
                            </div>
                            <div className="h-2 rounded-full bg-white/10 overflow-hidden">
                              <div className={`h-full rounded-full ${c.risk >= 70 ? "bg-rose-500" : c.risk >= 45 ? "bg-amber-400" : "bg-emerald-400"}`} style={{ width: `${c.risk}%` }} />
                            </div>
                            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                              {c.status === "active" && "Session within baseline — continuous monitoring active."}
                              {c.status === "observing" && "Elevated risk — deep packet inspection enabled."}
                              {c.status === "dropped" && "Malicious activity confirmed — session terminated."}
                              {c.status === "quarantined" && "Critical threat — host isolated from all segments."}
                              {c.status === "blocked" && "Source blocked by automated ACL enforcement."}
                            </p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </Panel>
              </div>

              {/* Right column */}
              <div className="xl:col-span-4 space-y-6">
                {/* Severity summary */}
                <Panel title="Severity Matrix" sub="Live severity distribution across all detections">
                  <div className="space-y-3">
                    {(["critical", "high", "medium", "low"] as Severity[]).map(sev => (
                      <div key={sev}>
                        <div className="flex justify-between text-xs mb-1">
                          <span className="capitalize text-slate-300">{sev}</span>
                          <span className={sev === "critical" ? "text-rose-300" : sev === "high" ? "text-orange-300" : sev === "medium" ? "text-amber-300" : "text-emerald-300"}>
                            {sevDist[sev]}
                          </span>
                        </div>
                        <div className="h-2 rounded-full bg-white/5 overflow-hidden">
                          <div className={`h-full rounded-full ${SEV_BAR[sev]} transition-all duration-500`} style={{ width: `${alerts.length ? (sevDist[sev] / alerts.length) * 100 : 0}%` }} />
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="mt-4 grid grid-cols-2 gap-3">
                    <div className="rounded-2xl border border-white/10 bg-black/20 p-3 text-center">
                      <p className="text-xl font-bold text-emerald-300">{containRate}%</p>
                      <p className="text-xs text-slate-500">Containment rate</p>
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-black/20 p-3 text-center">
                      <p className="text-xl font-bold text-rose-300">{blockedCnt}</p>
                      <p className="text-xs text-slate-500">Connections killed</p>
                    </div>
                  </div>
                </Panel>

                {/* Zone risk */}
                <Panel title="Zone Risk Heatmap" sub="Network segment posture summary">
                  <div className="space-y-2">
                    {ZONES.map(zone => {
                      const zoneConns = connections.filter(c => c.zone === zone);
                      const zRisk = zoneConns.length ? Math.round(zoneConns.reduce((s, c) => s + c.risk, 0) / zoneConns.length) : 0;
                      const hasKilled = zoneConns.some(c => ["dropped", "quarantined"].includes(c.status));
                      return (
                        <div key={zone} className={`rounded-2xl border p-3 flex items-center justify-between gap-3 ${hasKilled ? "border-rose-500/20 bg-rose-500/5" : "border-white/10 bg-black/20"}`}>
                          <div className="min-w-0">
                            <p className="text-sm font-medium text-slate-200">{zone}</p>
                            <div className="mt-1 h-1.5 w-full rounded-full bg-white/5 overflow-hidden">
                              <div className={`h-full rounded-full ${zRisk >= 70 ? "bg-rose-500" : zRisk >= 45 ? "bg-amber-400" : "bg-emerald-400"}`} style={{ width: `${zRisk}%` }} />
                            </div>
                          </div>
                          <div className="shrink-0 text-right">
                            <p className={`text-sm font-bold ${zRisk >= 70 ? "text-rose-300" : zRisk >= 45 ? "text-amber-300" : "text-emerald-300"}`}>{zRisk}%</p>
                            {hasKilled && <p className="text-xs text-rose-400">Threat Active</p>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </Panel>

                {/* Response ledger */}
                <Panel title="Response Ledger" sub="Backend events plus dashboard simulation actions">
                  <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                    {responseLog.map((entry, i) => (
                      <div key={`${i}-${entry.slice(0, 10)}`} className="rounded-xl border border-white/8 bg-black/20 p-3">
                        <div className="flex gap-2">
                          <ChevronRight className="h-3.5 w-3.5 shrink-0 mt-0.5 text-emerald-400" />
                          <p className="text-xs text-slate-300 leading-relaxed">{entry}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </Panel>

                 {/* Contained Connections List */}
                 <Panel title="Contained Connections" sub="Active dropped or quarantined sessions">
                   {connections.filter(c => ["dropped", "quarantined", "blocked"].includes(c.status)).length === 0 ? (
                     <div className="py-6 text-center">
                       <CheckCircle className="h-8 w-8 text-emerald-400 mx-auto mb-2" />
                       <p className="text-sm text-slate-400">No contained sessions - all current connections are within policy.</p>
                     </div>
                   ) : (
                     <div className="space-y-2">
                       {connections.filter(c => ["dropped", "quarantined", "blocked"].includes(c.status)).map(c => (
                         <div key={c.id} className="flex items-center justify-between rounded-2xl border border-rose-500/20 bg-rose-500/5 px-3 py-3">
                           <div>
                             <p className="text-sm font-mono text-rose-200">{c.srcIp}</p>
                             <p className="text-xs text-slate-500">{c.dstHost} · {c.zone}</p>
                           </div>
                          <div className="text-right">
                            <Badge cls={CONN_BADGE[c.status]}>{c.status}</Badge>
                            <p className="text-xs text-slate-500 mt-1">{c.protocol}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>

                {/* Live clock / status */}
                <div className="rounded-3xl border border-white/10 bg-white/5 p-5">
                  <div className="flex items-center gap-3 mb-3">
                    <Clock className="h-4 w-4 text-slate-400" />
                    <p className="text-sm font-semibold text-white">SOC Status</p>
                  </div>
                  <div className="space-y-3">
                    {[
                      { label: "Engine", value: "SentinelGrid v4.2", ok: true },
                      { label: "Inline drop policy", value: "STRICT", ok: true },
                      { label: "MITRE ATT&CK", value: "v15 (202 techniques)", ok: true },
                      { label: "NIST CSF", value: "2.0 (Feb 2024)", ok: true },
                      { label: "VT Engine Pool", value: "72 AV engines", ok: true },
                      { label: "Event ingestion", value: "Live stream", ok: true },
                      { label: "YARA rules", value: "5 active signatures", ok: true },
                    ].map(row => (
                      <div key={row.label} className="flex items-center justify-between text-sm">
                        <span className="text-slate-500">{row.label}</span>
                        <div className="flex items-center gap-1.5">
                          <div className={`h-1.5 w-1.5 rounded-full ${row.ok ? "bg-emerald-400" : "bg-rose-400"}`} />
                          <span className="text-slate-300 text-xs">{row.value}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {tab === "analytics" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <GlobalAnalytics />
          </div>
        )}

        {tab === "ossec" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <div className="mb-6 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-sky-500 to-indigo-600 shadow-lg shadow-sky-500/30">
                <Monitor className="h-5 w-5 text-white" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">OS Security Monitor</h2>
                <p className="text-xs text-slate-400">Real-time operating system type, version, EOL status and security posture analysis</p>
              </div>
            </div>
            <OSSecurityPanel />
          </div>
        )}

        {tab === "sandbox" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <MalwareSandbox />
          </div>
        )}

        {tab === "crossplat" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <CrossPlatformFim />
          </div>
        )}

        {tab === "vulnpentest" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <VulnPentestManager />
          </div>
        )}

        {tab === "advancedvb" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <AdvancedVirtualBox />
          </div>
        )}

        {tab === "mitre" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <MitreMatrix />
          </div>
        )}

        {tab === "nist" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <NistCompliance />
          </div>
        )}

        {tab === "virustotal" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <VirusTotalScanner />
          </div>
        )}

        {tab === "winlogs" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <WindowsLogViewer />
          </div>
        )}

        {tab === "ai_agent" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <AIAgent />
          </div>
        )}

        {tab === "intel" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <ThreatIntelligence />
          </div>
        )}

        {tab === "scanner" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <SystemScanner />
          </div>
        )}

        {tab === "vm" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <InteractiveVM />
          </div>
        )}

        {/* Slide-over HUD panel */}
        <AnimatePresence>
          {selectedNode && (
            <motion.div
              initial={{ y: "100%", opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              exit={{ y: "100%", opacity: 0 }}
              transition={{ type: "spring", damping: 25, stiffness: 200 }}
              className="fixed bottom-0 left-0 right-0 z-50 h-[80vh] md:h-[65vh] bg-[#030712]/95 border-t border-cyan-500/20 backdrop-blur-3xl p-6 rounded-t-3xl shadow-2xl flex flex-col font-mono"
            >
              {/* Header */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4 border-b border-white/10 pb-3">
                <div className="flex items-center gap-4">
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                    <Terminal className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                      Forensic HUD Node Monitor: <span className="text-cyan-400 font-mono font-black">{selectedNode.name}</span>
                    </h3>
                    <div className="flex items-center gap-1.5 text-xs text-slate-400 mt-0.5">
                      <span>IP: <span className="text-slate-300 font-mono">{selectedNode.ip}</span></span>
                      <span className="text-slate-600">•</span>
                      <span>Type: <span className="text-slate-300 font-mono uppercase">{selectedNode.type}</span></span>
                    </div>
                  </div>
                </div>
                
                {/* HUD segment tabs */}
                <div className="flex flex-wrap items-center gap-2">
                  {[
                    { id: "W", label: "Segment W: Chrono" },
                    { id: "X", label: "Segment X: Lab Engine" },
                    { id: "Y", label: "Segment Y: Akashic" },
                    { id: "Z", label: "Segment Z: Ego-Lock" },
                  ].map((sTab) => (
                    <button
                      key={sTab.id}
                      onClick={() => setActiveSegmentTab(sTab.id)}
                      className={`px-3 py-1.5 rounded-lg border text-xs font-bold transition-all duration-200 ${
                        activeSegmentTab === sTab.id
                          ? "border-cyan-500/50 bg-cyan-500/20 text-cyan-200 shadow-[0_0_10px_rgba(6,182,212,0.15)]"
                          : "border-white/5 bg-white/5 text-slate-400 hover:text-white hover:border-white/10"
                      }`}
                    >
                      {sTab.label}
                    </button>
                  ))}
                  <button
                    onClick={() => setSelectedNodeId(null)}
                    className="ml-2 md:ml-4 p-2 rounded-full border border-white/10 bg-white/5 text-slate-400 hover:text-white hover:bg-rose-950/30 hover:border-rose-500/30 transition-all duration-200"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {/* Content box */}
              <div className="flex-1 min-h-0 overflow-y-auto">
                {activeSegmentTab === "W" && (
                  <ChronoMonitor
                    vmId={selectedNode.id}
                    vmName={selectedNode.name}
                    onRollbackSuccess={handleRollbackSuccess}
                  />
                )}
                {activeSegmentTab === "X" && (
                  <LabEngineInterface
                    vmId={selectedNode.id}
                    vmName={selectedNode.name}
                    onThreatChange={handleThreatLevelChange}
                  />
                )}
                {activeSegmentTab === "Y" && <AkashicHorizon />}
                {activeSegmentTab === "Z" && <EgoLockStatus />}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        </motion.main>
      </AnimatePresence>
      </Suspense>

      {/* Footer */}
      <footer className="border-t border-white/8 py-5 px-6 text-center relative">
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-500/20 to-transparent" />
        <div className="flex items-center justify-center gap-3">
          <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 heartbeat" />
          <p className="text-xs text-slate-500">
            SentinelGrid SOC v5.0 — Real-time telemetry • AI-powered analysis • Enterprise security
          </p>
          <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 heartbeat" style={{ animationDelay: '0.5s' }} />
        </div>
      </footer>
    </div>
  );
}
