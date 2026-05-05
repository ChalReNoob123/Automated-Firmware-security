import { useState, useEffect, useRef, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell, Legend,
} from "recharts";
import {
  Shield, AlertTriangle, Activity, Network, Eye, Zap,
  Terminal, Database, Globe, RefreshCw, ChevronRight, X,
  CheckCircle, Clock, Cpu, FileText, Server, Flame, Monitor, LogOut, HardDrive,
} from "lucide-react";
import MitreMatrix from "./components/MitreMatrix";
import NistCompliance from "./components/NistCompliance";
import VirusTotalScanner from "./components/VirusTotalScanner";
import WindowsLogViewer from "./components/WindowsLogViewer";
import ThreatIntelligence from "./components/ThreatIntelligence";
import MalwareSandbox from "./components/MalwareSandbox";
import VulnPentestManager from "./components/VulnPentestManager";
import CrossPlatformFim from "./components/CrossPlatformFim";
import AdvancedVirtualBox from "./components/AdvancedVirtualBox";
import AIAgent from "./components/AIAgent";
import LoginScreen from "./components/LoginScreen";
import OSSecurityPanel from "./components/OSSecurityPanel";
import SystemScanner from "./components/SystemScanner";
import GlobalAnalytics from "./components/GlobalAnalytics";
import { Token, WS_BASE, logout, refreshAccessToken, apiGet, fetchMe, type User as ApiUser } from "./utils/api";


/* ── types ── */
type User = ApiUser;
type Severity = "low" | "medium" | "high" | "critical";
type Protocol = "HTTPS" | "SSH" | "RDP" | "DNS" | "TLS" | "MQTT" | "SMB" | "FTP" | "LDAP" | "SYSTEM";
type ConnStatus = "active" | "observing" | "dropped" | "quarantined" | "blocked";
type TabId = "dashboard" | "analytics" | "mitre" | "nist" | "virustotal" | "winlogs" | "intel" | "sandbox" | "vulnpentest" | "crossplat" | "advancedvb" | "ai_agent" | "ossec" | "scanner";

type Connection = {
  id: string;
  srcIp: string;
  dstIp: string;
  dstHost: string;
  protocol: Protocol;
  port: number;
  pps: number;
  latency: number;
  risk: number;
  status: ConnStatus;
  zone: string;
  geo: string;
  bytes: number;
  lastSeen: number;
  mitreId?: string;
};

type Alert = {
  id: string;
  ts: number;
  srcIp: string;
  dstHost: string;
  protocol: Protocol;
  category: "Threat Detection" | "Intrusion Detection" | "Network Monitoring" | "Malware" | "Ransomware" | "Lateral Movement" | "Exfiltration";
  severity: Severity;
  mitreId: string;
  mitreName: string;
  signature: string;
  score: number;
  action: string;
  status: "auto-contained" | "investigating" | "false-positive";
  malicious: boolean;
  zone: string;
  killed: boolean;
};

type TrafficPoint = { ts: number; t: string; traffic: number; threats: number; blocked: number; analysis: string };

type SystemStats = {
  cpu: number;
  memory: number;
  uptime: number;
  timestamp: number;
  plugins?: number;
};

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

function timelineLabel(ts: number) {
  return new Intl.DateTimeFormat("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(ts);
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

/* ── initial state ── */
const INIT_CONNS: Connection[] = [];
const INIT_TRAFFIC: TrafficPoint[] = [];

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

function Panel({ title, sub, action, children, className = "" }: {
  title: string; sub?: string; action?: React.ReactNode; children: React.ReactNode; className?: string;
}) {
  return (
    <motion.section 
      initial={{ opacity: 0, y: 15 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-50px" }}
      transition={{ duration: 0.5, ease: "easeOut" }}
      className={`rounded-3xl border border-white/10 bg-white/5 p-5 shadow-2xl shadow-slate-950/30 backdrop-blur-xl transition-all duration-300 hover:border-white/20 hover:shadow-sky-500/10 ${className}`}
    >
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          {sub && <p className="mt-0.5 text-sm text-slate-400">{sub}</p>}
        </div>
        {action}
      </div>
      {children}
    </motion.section>
  );
}

function StatCard({ label, value, sub, tone, icon }: {
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
      whileHover={{ scale: 1.05, translateY: -8, rotateX: 5, rotateY: 5 }}
      whileTap={{ scale: 0.95 }}
      transition={{ type: "spring", stiffness: 300, damping: 20 }}
      className={`rounded-3xl border border-white/10 bg-gradient-to-br p-5 ring-1 shadow-xl transform-gpu cursor-pointer transition-colors duration-300 hover:bg-black/40 ${t[tone]}`}
    >
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium uppercase tracking-widest text-slate-400">{label}</p>
        <div className={`rounded-xl border border-white/10 bg-black/20 p-2 ${t[tone].split(" ").find(c => c.startsWith("text-"))}`}>
          {icon}
        </div>
      </div>
      <p className="mt-3 text-3xl font-bold text-white drop-shadow-md">{value}</p>
      <p className="mt-1 text-sm text-slate-400">{sub}</p>
    </motion.div>
  );
}

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
];

/* ── MAIN ── */
export default function App() {
  const [now, setNow] = useState(Date.now);
  const [tab, setTab] = useState<TabId>("dashboard");
  const [authReady, setAuthReady] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(() => Token.isLoggedIn());
  const [user, setUser] = useState<User | null>(() => Token.getUser());
  const [connections, setConnections] = useState<Connection[]>(INIT_CONNS);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [traffic, setTraffic] = useState<TrafficPoint[]>(INIT_TRAFFIC);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [systemStats, setSystemStats] = useState<SystemStats>({ cpu: 0, memory: 0, uptime: 0, timestamp: Date.now() });
  const [statsHistory, setStatsHistory] = useState<{ts: number, cpu: number, mem: number}[]>([]);

   const [responseLog, setResponseLog] = useState<string[]>([
     `System monitoring initialized at ${clock(Date.now())}`,
   ]);

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
    (async () => {
      // 1. Try recovery from memory/localstorage first
      if (Token.isLoggedIn()) {
        const u = await fetchMe();
        if (u && !cancelled) {
          setUser(u);
          setIsAuthenticated(true);
          setAuthReady(true);
          return;
        }
      }
      
      // 2. Try recovery from refresh cookie
      const refreshed = await refreshAccessToken();
      if (!cancelled) {
        setIsAuthenticated(refreshed);
        setUser(Token.getUser());
        setAuthReady(true);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  /* Backend event stream with auto-reconnection and segment data handling */
  const [segmentData, setSegmentData] = useState<{
    segments: any[];
    health: any[];
    summary: any[];
    metrics: Record<string, any>;
    alerts: any[];
    advancedMonitoring: any;
  }>({ segments: [], health: [], summary: [], metrics: {}, alerts: [], advancedMonitoring: null });
  const [permissions, setPermissions] = useState<{
    isAdmin: boolean;
    isElevated: boolean;
    canAccessSecurityLog: boolean;
    canAccessProcessMemory: boolean;
    canMonitorUSB: boolean;
    platform: string;
    recommendations: any[];
  } | null>(null);
  const [wsStatus, setWsStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected');
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number>(1000);
  const maxReconnectTimeout = 30000;

  // Fetch initial permissions
  useEffect(() => {
    if (!isAuthenticated) return;
    const fetchPermissions = async () => {
      try {
        const perms: any = await apiGet('/api/system/permissions');
        setPermissions(perms);
      } catch (e) { /* silent fail */ }
    };
    fetchPermissions();
    const interval = setInterval(fetchPermissions, 30000);
    return () => clearInterval(interval);
  }, [isAuthenticated]);

  useEffect(() => {
    if (!isAuthenticated || !Token.getAccess()) return;
    
    let isActive = true;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    
    const connect = () => {
      if (!isActive) return;
      setWsStatus('connecting');
      
      const ws = new WebSocket(WS_BASE);
      wsRef.current = ws;
      
      ws.onopen = () => {
        setWsStatus('connected');
        reconnectTimeoutRef.current = 1000;
        ws.send(JSON.stringify({ event: "auth", token: Token.getAccess() }));
      };
      
      ws.onclose = () => {
        setWsStatus('disconnected');
        wsRef.current = null;
        if (!isActive) return;
        reconnectTimer = setTimeout(() => {
          reconnectTimeoutRef.current = Math.min(reconnectTimeoutRef.current * 1.5, maxReconnectTimeout);
          connect();
        }, reconnectTimeoutRef.current);
      };
      
      ws.onerror = () => {
        // Connection failed, will trigger onclose
      };
      
      ws.onmessage = event => {
        try {
          const msg = JSON.parse(event.data);
          
          if (msg.event === "new_logs") {
            setResponseLog(prev => [`${clock(msg.ts)} Host log stored (${msg.data?.[0]?.id ?? "event"})`, ...prev].slice(0, 10));
          }
          if (msg.event === "process_killed") {
            setResponseLog(prev => [`${clock(msg.ts)} Admin action: process ${msg.data?.pid} terminated`, ...prev].slice(0, 10));
          }
          if (msg.event === "segment_alert") {
            setResponseLog(prev => [`${clock(msg.ts)} SEGMENT ALERT: ${msg.data.segment}/${msg.data.zone} - ${msg.data.message}`, ...prev].slice(0, 10));
          }
          if (msg.event === "segment_alerts") {
            setSegmentData(prev => ({ ...prev, alerts: msg.data || [] }));
          }
          
          if (msg.event === "permission_status") {
            setPermissions(msg.data);
          }
          
          if (msg.event === "telemetry_update") {
            const data = msg.data;
            
            // Update segment data if included
            if (data.segments) {
              setSegmentData(prev => ({
                ...prev,
                health: data.segments.segmentHealth || [],
                summary: data.segments.segmentSummary || [],
                metrics: data.segments.segmentMetrics || {},
                advancedMonitoring: data.segments.advancedMonitoring || null
              }));
            }
            
            // Map network traffic to Connections with segment info
            const realConns: Connection[] = (data.network || []).map((c: any, i: number) => {
              const localParts = (c.local || '').split(':');
              const port = parseInt(localParts[localParts.length - 1]) || 0;
              let risk = 0;
              const state = c.state || '';
              
              if (state === 'LISTENING') risk = 30;
              else if (state === 'ESTABLISHED') risk = 10;
              
              const suspiciousPorts: Record<number, number> = {
                21: 20, 22: 10, 23: 30, 25: 25, 53: 15, 80: 10, 135: 30, 139: 30,
                443: 10, 445: 40, 1433: 35, 1521: 35, 3306: 35, 3389: 40, 5432: 30,
                5900: 25, 5901: 25, 6379: 30, 8080: 20, 8443: 15, 9200: 25, 9300: 25
              };
              
              if (suspiciousPorts[port]) risk = Math.max(risk, suspiciousPorts[port]);
              if (state === 'LISTENING' && suspiciousPorts[port] && suspiciousPorts[port] >= 30) risk = Math.min(100, risk + 20);
              
              // Infer zone from port
              let zone = 'System';
              if ([443,80,8080,8443].includes(port)) zone = 'DMZ';
              else if ([22,3389].includes(port)) zone = 'Remote Access';
              else if ([445,139].includes(port)) zone = 'Internal';
              else if ([3306,5432,1433,1521].includes(port)) zone = 'Data Core';
              
              return {
                id: `real-conn-${i}`,
                srcIp: c.local || 'Unknown',
                dstIp: c.foreign || 'Unknown',
                dstHost: c.foreign || 'Unknown',
                protocol: "SYSTEM",
                port: port,
                pps: state === 'ESTABLISHED' ? 25 : state === 'LISTENING' ? 0 : 5,
                latency: state === 'ESTABLISHED' ? 20 : 0,
                risk: risk,
                status: state === 'LISTENING' ? 'observing' : state === 'ESTABLISHED' ? 'active' : 'observing',
                zone: zone,
                geo: 'Local',
                bytes: state === 'ESTABLISHED' ? 250000 : 0,
                lastSeen: Date.now(),
              };
            });
            setConnections(realConns);

            // Map logs to Alerts with segment info
            const realAlerts: Alert[] = (data.logs || []).map((l: any, i: number) => ({
              id: `real-alert-${i}`,
              ts: new Date(l.Date || Date.now()).getTime(),
              srcIp: l.Computer || 'Local',
              dstHost: l.ProviderName || l.Source || 'System',
              protocol: 'SYSTEM',
              category: 'Threat Detection',
              severity: l.Suspicious ? 'high' : 'low',
              mitreId: l.Mitre?.id || 'N/A',
              mitreName: l.Mitre?.name || 'System Event',
              signature: l.Description || l.description || l.Message || 'No description',
              score: l.Suspicious ? 80 : 10,
              action: 'Logged',
              status: 'investigating',
              malicious: !!l.Suspicious,
              zone: l.Zone || l.zone || 'System',
              killed: false,
            }));
            setAlerts(realAlerts);

            // Update traffic timeline
            const ts = Date.now();
            const threatCount = realAlerts.filter(a => a.malicious).length;
            const blockedCount = realAlerts.filter(a => a.killed || a.status === "auto-contained").length;
            const activeConns = realConns.filter(c => c.status === 'active' || c.status === 'observing').length;
            const totalConns = realConns.length;
            const trafficPercentage = totalConns > 0 ? Math.min(100, Math.round((activeConns / totalConns) * 100)) : 0;
            
            const newPoint: TrafficPoint = {
              ts,
              t: timelineLabel(ts),
              traffic: trafficPercentage,
              threats: threatCount,
              blocked: blockedCount,
              analysis: data.analysis?.summary || 'Analyzing system telemetry...',
            };
            setTraffic(prev => [...prev.slice(-119), newPoint]); // Keep 10 minutes of history
          }
        } catch {
          // Ignore malformed messages
        }
      };
    };
    
    connect();
    
    return () => {
      isActive = false;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef.current) wsRef.current.close();
    };
  }, [isAuthenticated]);

  /* Clock */
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  /* Timeline updates are fed by backend telemetry_update messages only. */



  /* Live System Performance Polling (lightweight fallback beside websocket telemetry) */
  useEffect(() => {
    if (!isAuthenticated) return;
    let pluginPollTick = 0;
    const pollStats = async () => {
      try {
        const stats: any = await apiGet('/api/system/stats');
        setSystemStats(stats);
        setStatsHistory(prev => [...prev.slice(-29), { ts: stats.timestamp, cpu: parseFloat(stats.cpu), mem: parseFloat(stats.memory) }]);
        pluginPollTick += 1;
        if (pluginPollTick % 3 === 0) {
          try {
            const pluginData: any = await apiGet('/api/plugins');
            if (pluginData && pluginData.plugins) {
               setSystemStats(prev => ({...prev, plugins: pluginData.plugins.length}));
            }
          } catch (e) {}
        }

      } catch (e) { /* silent fail */ }
    };
    const t = setInterval(pollStats, 10000);
    pollStats();
    return () => clearInterval(t);
  }, [isAuthenticated]);

  /* Recycle blocked conns removed for real data integration */
  useEffect(() => {
    // No longer needed
  }, []);

   /* Derived */
   const activeCnt = useMemo(() => connections.filter(c => c.status === "active" || c.status === "observing").length, [connections]);
   const blockedCnt = useMemo(() => connections.filter(c => ["dropped", "quarantined", "blocked"].includes(c.status)).length, [connections]);
   const malAlerts = useMemo(() => alerts.filter(a => a.malicious), [alerts]);
   const criticalCnt = useMemo(() => alerts.filter(a => a.severity === "critical").length, [alerts]);
   const containedCnt = useMemo(() => alerts.filter(a => a.status === "auto-contained").length, [alerts]);
   const containRate = malAlerts.length ? Math.round((containedCnt / malAlerts.length) * 100) : 100;
   const avgRisk = connections.length > 0 ? Math.round(connections.reduce((s, c) => s + c.risk, 0) / connections.length) : 0;
   const threatPressure = Math.min(100, Math.round((avgRisk + Math.min(100, malAlerts.length * 5)) / 2));
   const totalPps = connections.reduce((s, c) => s + c.pps, 0);
   const totalBytes = connections.reduce((s, c) => s + c.bytes, 0);

  const sevDist = useMemo<Record<Severity, number>>(() =>
    alerts.reduce((a, al) => { a[al.severity]++; return a; }, { low: 0, medium: 0, high: 0, critical: 0 } as Record<Severity, number>),
    [alerts]);

  const catDist = useMemo(() => {
    const map = new Map<string, number>();
    alerts.forEach(a => map.set(a.category, (map.get(a.category) ?? 0) + 1));
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

  if (!authReady) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#020617] text-sm text-slate-300">
        Restoring secure session...
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <LoginScreen onLoginSuccess={() => {
        setIsAuthenticated(true);
        setUser(Token.getUser());
        setTab("dashboard"); // Ensure we start at dashboard
      }} />
    );
  }

  // If authenticated, we are here.
  // The LoginScreen is not rendered.

  return (
    <div className="min-h-screen overflow-x-hidden bg-[#020617] text-slate-100 font-sans">
      {/* Background */}
      <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(56,189,248,0.12),_transparent_30%),radial-gradient(circle_at_bottom_right,_rgba(244,63,94,0.12),_transparent_26%)]" />

      {/* Top nav */}
      <header className="sticky top-0 z-50 border-b border-white/10 bg-black/60 backdrop-blur-2xl">
        <div className="mx-auto w-full max-w-screen-2xl px-4 sm:px-6 lg:px-8">
          <div className="flex h-16 min-w-0 items-center justify-between gap-4">
            {/* Logo */}
            <div className="flex items-center gap-3 shrink-0">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-rose-500 to-orange-600 shadow-lg shadow-rose-500/30">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <div>
                <p className="text-sm font-bold text-white leading-tight">SentinelGrid</p>
                <p className="text-xs text-slate-500 leading-tight">Enterprise SOC Platform</p>
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
                  className={`flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-xl px-2.5 py-2 text-xs font-medium transition 2xl:text-sm ${tab === t.id ? "bg-white/10 text-white" : "text-slate-400 hover:text-slate-200 hover:bg-white/5"}`}
                >
                  {t.icon}
                  {t.label}
                </button>
              ))}
            </nav>

            {/* Status indicators */}
            <div className="hidden shrink-0 items-center gap-3 2xl:flex">
              <div className="flex items-center gap-4 border-l border-white/10 pl-4">
                <div className={`flex items-center gap-2 rounded-full border px-3 py-1.5 backdrop-blur-md ${
                  wsStatus === 'connected' ? 'border-emerald-400/30 bg-emerald-500/10' : 
                  wsStatus === 'connecting' ? 'border-amber-400/30 bg-amber-500/10' : 
                  'border-rose-400/30 bg-rose-500/10'
                }`}>
                  <div className={`h-2 w-2 rounded-full animate-pulse ${
                    wsStatus === 'connected' ? 'bg-emerald-400' : 
                    wsStatus === 'connecting' ? 'bg-amber-400' : 
                    'bg-rose-400'
                  }`} />
                  <span className={`text-xs font-semibold ${
                    wsStatus === 'connected' ? 'text-emerald-200' : 
                    wsStatus === 'connecting' ? 'text-amber-200' : 
                    'text-rose-200'
                  }`}>
                    {wsStatus === 'connected' ? 'LIVE' : wsStatus === 'connecting' ? 'CONNECTING' : 'OFFLINE'}
                  </span>
                </div>
                <div className="flex items-center gap-2 rounded-full border border-sky-400/30 bg-sky-500/10 px-3 py-1.5 backdrop-blur-md">
                  <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-xs font-semibold text-sky-200">LOCAL TELEMETRY</span>
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

      <AnimatePresence mode="wait">
        <motion.main 
          key={tab}
          initial={{ opacity: 0, y: 30, filter: "blur(10px)", scale: 0.98 }}
          animate={{ opacity: 1, y: 0, filter: "blur(0px)", scale: 1 }}
          exit={{ opacity: 0, y: -30, filter: "blur(10px)", scale: 0.98 }}
          transition={{ duration: 0.4, ease: "easeOut" }}
          className="mx-auto max-w-screen-2xl px-4 py-6 sm:px-6 lg:px-8 space-y-6"
        >
        {/* Framework banner */}
        <div className="rounded-3xl border border-white/10 bg-white/5 px-5 py-4 backdrop-blur-xl">
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-widest">Reference Data:</span>
            {[
              { label: "MITRE ATT&CK v15", cls: "border-rose-400/30 bg-rose-400/10 text-rose-200" },
              { label: "NIST CSF 2.0", cls: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200" },
              { label: "VirusTotal API-ready", cls: "border-sky-400/30 bg-sky-400/10 text-sky-200" },
              { label: "Host Event Logs", cls: "border-amber-400/30 bg-amber-400/10 text-amber-200" },
              { label: "Registry/FIM Demo", cls: "border-purple-400/30 bg-purple-400/10 text-purple-200" },
              { label: "YARA References", cls: "border-orange-400/30 bg-orange-400/10 text-orange-200" },
            ].map(f => (
              <span key={f.label} className={`rounded-full border px-3 py-1 text-xs font-medium ${f.cls}`}>
                {f.label}
              </span>
            ))}
            <div className="ml-auto flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs text-emerald-300 font-medium">Live Telemetry Active</span>
            </div>

          </div>
        </div>

        {/* Dashboard tab */}
        {tab === "dashboard" && (
          <div className="space-y-6">
            {/* Stat cards */}
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
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
                      <p className="text-lg font-bold text-white">10.0s</p>
                    </div>
                  </div>
                  <div className="flex h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
                </div>
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
                         const hasData = metrics.connections > 0 || metrics.authEvents > 0 || metrics.totalProcesses > 0;
                         const status = metrics.suspiciousProcesses > 0 ? 'warning' : metrics.highRiskProcesses > 0 ? 'critical' : hasData ? 'healthy' : 'idle';
                         
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
                               {metrics.risk > 0 && (
                                 <span className="text-[10px] text-rose-400">Risk: {metrics.risk}</span>
                               )}
                             </div>
                             
                             {/* Segment-specific metrics */}
                             <div className="grid grid-cols-2 gap-2 text-[10px]">
                               {segName === 'identity' && (
                                 <>
                                   <span className="text-slate-400">Auth: {metrics.authEvents || 0}</span>
                                   <span className={metrics.failedLogons > 0 ? 'text-rose-400' : 'text-slate-400'}>
                                     Failed: {metrics.failedLogons || 0}
                                   </span>
                                 </>
                               )}
                               {segName === 'system' && (
                                 <>
                                   <span className="text-slate-400">Procs: {metrics.totalProcesses || 0}</span>
                                   {metrics.suspiciousProcesses > 0 && (
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
                             {segmentData.advancedMonitoring.fimChanges?.length > 0 && (
                               <div className="text-rose-400">
                                 ⚠️ {segmentData.advancedMonitoring.fimChanges.length} file integrity violations
                               </div>
                             )}
                             {segmentData.advancedMonitoring.usbDevices?.connected?.length > 0 && (
                               <div className="text-slate-400">
                                 USB: {segmentData.advancedMonitoring.usbDevices.connected.length} devices
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
        </motion.main>
      </AnimatePresence>

      {/* Footer */}
      <footer className="border-t border-white/8 py-4 px-6 text-center">
        <p className="text-xs text-slate-600">
          SentinelGrid SOC Monitor - local host telemetry, reference frameworks, and clearly labeled simulation modules
        </p>
      </footer>
    </div>
  );
}
