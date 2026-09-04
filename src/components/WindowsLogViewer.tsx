import { useState, useEffect, useCallback, useRef, useMemo, type ReactNode } from "react";

import { 
  FileText, AlertTriangle, ChevronDown, ChevronRight, 
  Filter, HardDrive, Activity, Shield, Cpu, Zap, 
  Terminal, Monitor, CheckCircle2, Info, AlertOctagon, Database,
  Eye, EyeOff, RefreshCw, Wifi, WifiOff
} from "lucide-react";

import { API_BASE, WS_BASE, Token, refreshAccessToken } from "../utils/api";

// ── Utilities ────────────────────────────────────────────────────

/** Generate a stable unique ID deterministically from log content */
function stableLogId(log: any): string {
  const raw = `${log.Id || log.id || ''}-${log.TimeCreated || log.timestamp || ''}-${log.Message?.slice(0, 50) || ''}-${log.ProviderName || log.source || ''}`;
  let h = 0;
  for (let i = 0; i < raw.length; i++) h = (h << 5) - h + raw.charCodeAt(i);
  return `log-${Math.abs(h).toString(36)}`;
}

/** Parse a timestamp from various backend formats defensively */
function parseTimestamp(val: any): number {
  if (!val) return Date.now();
  if (typeof val === 'number') return isNaN(val) ? Date.now() : val;
  if (typeof val === 'string') {
    if (val.startsWith('/Date(')) {
      const n = parseInt(val.replace(/[^0-9]/g, ''), 10);
      return isNaN(n) ? Date.now() : n;
    }
    const d = new Date(val).getTime();
    return isNaN(d) ? Date.now() : d;
  }
  return Date.now();
}

/** Format timestamp safely */
function formatTime(ts: number): string {
  try {
    return new Intl.DateTimeFormat("en-US", {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit"
    }).format(!isNaN(ts) ? ts : Date.now());
  } catch {
    return "Unknown Date";
  }
}

// Local Badge component for severity labels
function Badge({ cls, children }: { cls: string; children: ReactNode }) {
  return (
    <span className={`rounded-lg border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider ${cls}`}>
      {children}
    </span>
  );
}

type WindowsEventLog = {
  id: string;
  eventId: number | string;
  timestamp: number;
  level: string;
  source: string;
  category: string;
  logName: string;
  message: string;
  computer: string;
  user?: string;
  suspicious: boolean;
  mitre?: {
    id: string;
    name: string;
    tactic: string;
  } | null;
  isNew?: boolean;
};

type FileEntry = {
  name: string;
  path: string;
  size: number;
  modified: string;
};

const levelColor: Record<string, string> = {
  Critical: "border-rose-500/30 bg-rose-500/10 text-rose-200",
  Error: "border-orange-400/30 bg-orange-500/10 text-orange-200",
  Warning: "border-amber-400/30 bg-amber-500/10 text-amber-200",
  Information: "border-sky-400/30 bg-sky-500/10 text-sky-200",
  Verbose: "border-slate-500/30 bg-slate-500/10 text-slate-400",
};

const levelIcon: Record<string, any> = {
  Critical: AlertOctagon,
  Error: AlertTriangle,
  Warning: Info,
  Information: CheckCircle2,
  Verbose: Activity,
};

const channelBadge: Record<string, string> = {
  Security: "bg-rose-500/20 text-rose-300 border-rose-500/20",
  System: "bg-sky-500/20 text-sky-300 border-sky-500/20",
  Application: "bg-indigo-500/20 text-indigo-300 border-indigo-500/20",
};

/** Single-event row with expand/collapse. Uses ref-based expansion to avoid per-row React state */
function EventRow({ event }: { event: WindowsEventLog }) {
  const [expanded, setExpanded] = useState(false);
  const [isNewLocal, setIsNewLocal] = useState(event.isNew);

  // CRITICAL FIX: Clear the "new" animation after 3 seconds to prevent permanent memory leak
  useEffect(() => {
    if (!event.isNew) return;
    const t = setTimeout(() => setIsNewLocal(false), 3000);
    return () => clearTimeout(t);
  }, [event.isNew]);

  const timeStr = formatTime(event.timestamp);
  const Icon = levelIcon[event.level] || Info;
  const lColor = levelColor[event.level] || levelColor.Information;
  
  return (
    <div className={`group rounded-2xl border transition-all duration-300 ${isNewLocal ? 'ring-1 ring-sky-500/30' : ''} ${event.suspicious ? 'border-rose-500/30 bg-rose-500/5 hover:bg-rose-500/10' : 'border-white/5 bg-white/3 hover:bg-white/5'}`}>
      <button
        type="button"
        className="w-full p-4 text-left flex items-start gap-4"
        onClick={() => setExpanded(prev => !prev)}
      >
        <div className={`mt-1 h-8 w-8 shrink-0 rounded-xl flex items-center justify-center border ${lColor}`}>
          <Icon className="h-4 w-4" />
        </div>
        
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span className={`rounded-lg border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${lColor}`}>{event.level}</span>
            <span className={`rounded-lg border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${channelBadge[event.logName] || "bg-slate-500/20 text-slate-300 border-slate-500/20"}`}>{event.logName}</span>
            <span className="font-mono text-xs text-slate-500 bg-white/5 px-1.5 py-0.5 rounded">ID: {event.eventId}</span>
            <span className="text-xs text-slate-400 font-medium truncate max-w-[150px]">{event.source}</span>
            {isNewLocal && <span className="text-[10px] text-sky-400 font-bold animate-pulse">NEW</span>}
          </div>
          
          <p className={`text-sm leading-relaxed transition-all ${expanded ? 'text-slate-200' : 'text-slate-300 line-clamp-1'}`}>{event.message}</p>
          
          <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-[11px] text-slate-500 font-medium">
            <span className="flex items-center gap-1"><Zap className="h-3 w-3" /> {timeStr}</span>
            <span className="flex items-center gap-1"><Monitor className="h-3 w-3" /> {event.computer}</span>
            {event.mitre && (
              <span className="flex items-center gap-1 text-amber-400/80 bg-amber-400/10 px-1.5 py-0.5 rounded border border-amber-400/20">
                <Shield className="h-3 w-3" /> {event.mitre.id}: {event.mitre.name}
              </span>
            )}
          </div>
        </div>
        
        <div className="shrink-0 text-slate-500 mt-2">
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-white/5 p-4 bg-black/20 space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-4">
              <div className="rounded-xl border border-white/5 bg-black/40 p-4">
                <p className="text-[10px] text-slate-500 font-bold uppercase tracking-[0.2em] mb-3 flex items-center gap-2">
                  <Terminal className="h-3 w-3 text-sky-400" /> Full System Event Details
                </p>
                <p className="text-sm text-slate-300 leading-relaxed font-mono whitespace-pre-wrap selection:bg-sky-500/30">{event.message}</p>
              </div>
            </div>
            
            <div className="space-y-4">
              <div className="rounded-xl border border-white/5 bg-black/40 p-4">
                <p className="text-[10px] text-slate-500 font-bold uppercase tracking-[0.2em] mb-3 flex items-center gap-2">
                  <Shield className="h-3 w-3 text-rose-400" /> Event Metadata
                </p>
                <div className="space-y-2.5 text-xs">
                  {[
                    { label: "Log Channel", value: event.logName },
                    { label: "Event ID", value: event.eventId, mono: true },
                    { label: "Source", value: event.source },
                    { label: "Category", value: event.category },
                    { label: "Target Machine", value: event.computer, mono: true },
                    { label: "Exact Timestamp", value: new Date(event.timestamp).toLocaleString(), mono: true },
                  ].map((item) => (
                    <div key={item.label} className="flex justify-between items-center border-b border-white/5 pb-2 last:border-0 last:pb-0">
                      <span className="text-slate-500">{item.label}</span>
                      <span className={`text-slate-300 ${item.mono ? 'font-mono' : ''}`}>{item.value}</span>
                    </div>
                  ))}
                </div>
              </div>

              {event.mitre && (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4">
                  <p className="text-[10px] text-amber-400 font-bold uppercase tracking-[0.2em] mb-2">MITRE ATT&CK Alignment</p>
                  <p className="text-sm font-semibold text-amber-200">{event.mitre.id} - {event.mitre.name}</p>
                  <p className="text-xs text-amber-400/70 mt-1">Tactic: {event.mitre.tactic}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function FileRow({ file }: { file: FileEntry }) {
  let timeStr = "Invalid Date";
  try {
    const d = new Date(file.modified);
    timeStr = new Intl.DateTimeFormat("en-US", {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit"
    }).format(!isNaN(d.getTime()) ? d : Date.now());
  } catch (e) {
    timeStr = "Unknown Date";
  }

  return (
    <div className="rounded-2xl border border-white/5 bg-white/3 p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/5 transition group">
      <div className="flex items-start gap-4 min-w-0">
        <div className="mt-1 h-10 w-10 shrink-0 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center group-hover:scale-110 transition">
          <HardDrive className="h-5 w-5 text-amber-400" />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-semibold text-slate-200 truncate">{file.name}</p>
          <p className="text-xs font-mono text-slate-500 truncate group-hover:text-slate-400 transition">{file.path}</p>
        </div>
      </div>
      <div className="flex items-center gap-4 text-[11px] text-slate-400 shrink-0 font-medium">
        <span className="font-mono bg-black/40 px-2 py-1 rounded border border-white/5">{(file.size / 1024).toFixed(1)} KB</span>
        <span className="bg-black/40 px-2 py-1 rounded border border-white/5 flex items-center gap-1.5">
          <Activity className="h-3 w-3 text-sky-400" /> {timeStr}
        </span>
      </div>
    </div>
  );
}

export default function WindowsLogViewer() {
  const [activeTab, setActiveTab] = useState<"events" | "files" | "vulnerabilities" | "registry">("events");
  const [viewMode, setViewMode] = useState<"live" | "historical">("live");
  const [autoPoll, setAutoPoll] = useState(true);
  const [events, setEvents] = useState<WindowsEventLog[]>([]);
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [computerInfo, setComputerInfo] = useState<string>("Local Machine");

  const [filterLevel, setFilterLevel] = useState<string>("All");
  const [filterSuspicious, setFilterSuspicious] = useState(false);
  const [searchText, setSearchText] = useState("");
  const [toast, setToast] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [wsStatus, setWsStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected');
  const EVENTS_PER_PAGE = 50;
  const MAX_EVENTS_BUFFER = 500; // Hard cap to prevent memory exhaustion

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectDelayRef = useRef(1000);
  const isMountedRef = useRef(true);
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showToast = useCallback((message: string) => {
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    setToast(message);
    toastTimerRef.current = setTimeout(() => {
      if (isMountedRef.current) setToast(null);
    }, 3000);
  }, []);

  // Map raw backend log to typed frontend event — centralized to avoid duplication
  const mapRawLog = useCallback((l: any, isNew = false): WindowsEventLog => {
    const ts = parseTimestamp(l.TimeCreated);
    const mitreData = l.Mitre || l.mitre || null;
    const mitre = mitreData && typeof mitreData === 'object' ? {
      id: mitreData.id || mitreData.Id || '',
      name: mitreData.name || mitreData.Name || '',
      tactic: mitreData.tactic || mitreData.Tactic || ''
    } : null;
    return {
      id: stableLogId(l),
      eventId: l.Id || l.eventId || '0',
      timestamp: ts,
      level: l.LevelDisplayName || l.level || 'Information',
      source: l.ProviderName || l.source || 'System',
      category: l.TaskDisplayName || l.category || 'System',
      logName: l.LogName || l.logName || 'System',
      message: l.Message || l.message || l.description || '',
      computer: l.MachineName || l.Computer || l.computer || 'Local',
      suspicious: !!l.Suspicious || !!l.suspicious,
      mitre,
      isNew
    };
  }, []);

  const fetchLiveLogs = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setError(null);
    try {
      const token = Token.getAccess();
      if (!token) throw new Error("No access token. Please re-login.");

      const res = await fetch(`${API_BASE}/api/logs?channel=all&max=100`, {
        headers: { "Authorization": `Bearer ${token}` }
      });
      if (res.status === 401) {
        // Try to refresh token once
        const refreshed = await refreshAccessToken();
        if (!refreshed) throw new Error("Session expired. Please re-login.");
        // Retry with new token
        const retryRes = await fetch(`${API_BASE}/api/logs?channel=all&max=100`, {
          headers: { "Authorization": `Bearer ${Token.getAccess()}` }
        });
        if (!retryRes.ok) throw new Error("Log agent unreachable after token refresh.");
        const json = await retryRes.json();
        if (json.logs) {
          const mapped = json.logs.map((l: any) => mapRawLog(l, false));
          setEvents(mapped);
          if (json.computer) setComputerInfo(json.computer);
          if (!silent) showToast(`Loaded ${mapped.length} device logs`);
        }
        return;
      }
      if (!res.ok) throw new Error(`Log agent unreachable (${res.status}).`);

      const json = await res.json();
      if (json.logs) {
        const mapped = json.logs.map((l: any) => mapRawLog(l, false));
        setEvents(mapped);
        if (json.computer) setComputerInfo(json.computer);
        if (!silent) showToast(`Loaded ${mapped.length} device logs`);
      }
    } catch (e: any) {
      setError(e.message || "Failed to fetch device logs.");
    } finally {
      if (!silent) setLoading(false);
    }
  }, [mapRawLog, showToast]);

  const fetchHistoricalLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/database/logs`, {
        headers: { "Authorization": `Bearer ${Token.getAccess()}` }
      });
      if (!res.ok) throw new Error(`Historical database unreachable (${res.status}).`);
      const json = await res.json();

      const parsedEvents: WindowsEventLog[] = (json.databaseLogs || []).map((log: any) => {
        let mitre = null;
        if (log.mitre) {
          try {
            const m = typeof log.mitre === 'string' ? JSON.parse(log.mitre) : log.mitre;
            if (m && typeof m === 'object') {
              mitre = { id: m.id || '', name: m.name || '', tactic: m.tactic || '' };
            }
          } catch {
            mitre = null; // Gracefully ignore malformed mitre JSON
          }
        }
        return {
          id: log.hash || stableLogId(log),
          eventId: log.eventId || '0',
          timestamp: new Date(log.date).getTime() || Date.now(),
          level: log.level || 'Information',
          source: log.source || 'System',
          category: log.task || 'System',
          logName: log.logName || "Historical",
          message: log.description || 'No description.',
          computer: 'Local Host',
          suspicious: !!log.suspicious,
          mitre,
          isNew: false
        };
      });

      setEvents(parsedEvents);
      setCurrentPage(1);
    } catch (e: any) {
      setError(e.message || "Failed to fetch database records.");
    } finally {
      setLoading(false);
    }
  }, []);

  // ── WebSocket with exponential backoff and proper cleanup ──
  const connectWebSocket = useCallback(() => {
    if (!isMountedRef.current) return;
    if (viewMode !== "live" || !autoPoll) return;

    const token = Token.getAccess();
    if (!token) { setWsStatus('disconnected'); return; }

    setWsStatus('connecting');

    try {
      const ws = new WebSocket(WS_BASE);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!isMountedRef.current) { ws.close(); return; }
        reconnectDelayRef.current = 1000;
        setWsStatus('connected');
        ws.send(JSON.stringify({ event: "auth", token }));
      };

      ws.onmessage = (event) => {
        if (!isMountedRef.current) return;
        try {
          const data = JSON.parse(event.data);
          if (data.event === "telemetry_update") {
            const snapshot = data.data || data;
            if (snapshot.logs && Array.isArray(snapshot.logs)) {
              const newLogs = snapshot.logs.map((logItem: any) => mapRawLog(logItem, true));
              setEvents(prev => {
                // Build a set of existing IDs for deduplication
                const existingIds = new Set(prev.map(e => e.id));
                const uniqueNew = newLogs.filter((logItem: WindowsEventLog) => !existingIds.has(logItem.id));
                if (uniqueNew.length === 0) return prev;
                const combined = [...uniqueNew, ...prev];
                // Hard memory cap: keep newest MAX_EVENTS_BUFFER
                return combined.slice(0, MAX_EVENTS_BUFFER);
              });
            }
            if (snapshot.files) setFiles(snapshot.files);
            if (snapshot.analysis?.threats) {
              setVulnerabilities(snapshot.analysis.threats.map((t: string, i: number) => ({
                id: `vuln-${i}`,
                title: t,
                severity: t.includes('CRITICAL') ? 'Critical' : t.includes('WARNING') ? 'Warning' : 'Information',
                ts: Date.now()
              })));
            }
          }
          if (data.event === "new_logs" && Array.isArray(data.data)) {
            const newLogs = data.data.map((logItem: any) => mapRawLog(logItem, true));
            setEvents(prev => {
              const existingIds = new Set(prev.map(e => e.id));
              const uniqueNew = newLogs.filter((logItem: WindowsEventLog) => !existingIds.has(logItem.id));
              if (uniqueNew.length === 0) return prev;
              return [...uniqueNew, ...prev].slice(0, MAX_EVENTS_BUFFER);
            });
          }
        } catch (err) {
          // Silently ignore malformed WebSocket messages — prevents UI crashes
          if (process.env.NODE_ENV === 'development') {
            console.warn("WS parse warning (suppressed in production):", err);
          }
        }
      };

      ws.onerror = () => {
        if (!isMountedRef.current) return;
        setWsStatus('disconnected');
      };

      ws.onclose = () => {
        if (!isMountedRef.current) return;
        setWsStatus('disconnected');
        wsRef.current = null;
        if (viewMode === "live" && autoPoll) {
          const delay = Math.min(reconnectDelayRef.current, 30000);
          reconnectDelayRef.current = Math.min(reconnectDelayRef.current * 1.5, 30000);
          reconnectTimerRef.current = setTimeout(() => {
            if (isMountedRef.current) connectWebSocket();
          }, delay);
        }
      };
    } catch (err) {
      setWsStatus('disconnected');
    }
  }, [viewMode, autoPoll, mapRawLog]);

  useEffect(() => {
    isMountedRef.current = true;
    if (viewMode === "live" && autoPoll) {
      connectWebSocket();
    } else {
      if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
      if (reconnectTimerRef.current) { clearTimeout(reconnectTimerRef.current); reconnectTimerRef.current = null; }
    }
    return () => {
      isMountedRef.current = false;
      if (wsRef.current) { wsRef.current.close(); wsRef.current = null; }
      if (reconnectTimerRef.current) { clearTimeout(reconnectTimerRef.current); reconnectTimerRef.current = null; }
    };
  }, [viewMode, autoPoll, connectWebSocket]);

  // Fetch logs when view mode changes
  useEffect(() => {
    if (viewMode === "live") fetchLiveLogs();
    else fetchHistoricalLogs();
  }, [viewMode, fetchLiveLogs, fetchHistoricalLogs]);

  // Reset pagination when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [filterLevel, filterSuspicious, searchText]);

  // ── Memoized filtered events (prevents O(n) recompute on every render) ──
  const filteredEvents = useMemo(() => {
    const q = searchText.trim().toLowerCase();
    return events.filter(e => {
      if (filterLevel !== "All" && e.level !== filterLevel) return false;
      if (filterSuspicious && !e.suspicious) return false;
      const msg = e.message || "";
      const src = e.source || "";
      const comp = e.computer || "";
      const cat = e.category || "";
      // Noise filtering — only when not searching and not showing suspicious-only
      const isNoise = msg.includes("ApiSet Function") || src.includes("AppModel");
      if (isNoise && !filterSuspicious && !q) return false;
      if (q) {
        if (!msg.toLowerCase().includes(q) &&
            !src.toLowerCase().includes(q) &&
            !comp.toLowerCase().includes(q) &&
            !cat.toLowerCase().includes(q) &&
            !String(e.eventId).includes(q)) {
          return false;
        }
      }
      return true;
    });
  }, [events, filterLevel, filterSuspicious, searchText]);

  const totalLogs = events.length;
  const totalPages = Math.max(1, Math.ceil(filteredEvents.length / EVENTS_PER_PAGE));
  const safePage = Math.min(currentPage, totalPages);
  const paginatedEvents = filteredEvents.slice((safePage - 1) * EVENTS_PER_PAGE, safePage * EVENTS_PER_PAGE);

  return (
    <div className="space-y-6 relative pb-20">
      {/* ... (toast and header) ... */}
      {toast && (
        <div className="fixed bottom-10 right-10 z-[100] animate-in slide-in-from-bottom-10 fade-in duration-500">
          <div className="flex items-center gap-3 rounded-2xl border border-sky-500/30 bg-sky-500/10 px-6 py-4 shadow-2xl shadow-sky-500/20 backdrop-blur-xl">
            <div className="h-2 w-2 rounded-full bg-sky-400 animate-ping" />
            <p className="text-sm font-semibold text-sky-100">{toast}</p>
          </div>
        </div>
      )}

      {/* Futuristic Header Section */}
      <div className="relative flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between glass-v2 border border-cyan-500/20 rounded-[2.5rem] p-6 lg:p-8 overflow-hidden group shadow-[0_0_30px_rgba(34,211,238,0.1)]">
        <div className="absolute inset-0 pointer-events-none holo-threat-field opacity-10 group-hover:opacity-20 transition-opacity duration-700" />
        <div className="absolute inset-0 pointer-events-none scan-line opacity-20" />
        <div className="relative z-10 flex items-center gap-5">
          <div className="relative">
            <div className="h-14 w-14 rounded-2xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/30 breathe-glow">
              <Cpu className="h-8 w-8 text-white" />
            </div>
            <div className="absolute -inset-1 rounded-2xl border border-cyan-400/30 animate-pulse" />
          </div>
          <div>
            <h2 className="text-3xl font-black text-white flex items-center gap-4 tracking-tight drop-shadow-md">
              MULTI-OS TELEMETRY HUB
              <span className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-[10px] text-cyan-400 font-bold uppercase tracking-widest drop-shadow-[0_0_8px_rgba(34,211,238,0.5)]">
                <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />
                NEURAL AGENT ACTIVE
              </span>
            </h2>
            <div className="flex items-center gap-4 mt-2 text-cyan-100/60 text-xs font-mono uppercase tracking-widest">
              <span className="flex items-center gap-1.5"><Monitor className="h-4 w-4" /> {computerInfo}</span>
              <span className="h-1 w-1 rounded-full bg-cyan-800" />
              <span className="flex items-center gap-1.5"><Shield className="h-4 w-4" /> CROSS-PLATFORM LIVE SYNC</span>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* WebSocket Status Indicator */}
          <div className="flex items-center gap-2 rounded-2xl border px-4 py-2.5 text-xs font-bold transition-all duration-300"
            style={{
              borderColor: wsStatus === 'connected' ? 'rgba(16,185,129,0.3)' : wsStatus === 'connecting' ? 'rgba(245,158,11,0.3)' : 'rgba(244,63,94,0.3)',
              backgroundColor: wsStatus === 'connected' ? 'rgba(16,185,129,0.1)' : wsStatus === 'connecting' ? 'rgba(245,158,11,0.1)' : 'rgba(244,63,94,0.1)',
              color: wsStatus === 'connected' ? 'rgb(52,211,153)' : wsStatus === 'connecting' ? 'rgb(251,191,36)' : 'rgb(251,113,133)'
            }}
          >
            {wsStatus === 'connected' ? <Wifi className="h-4 w-4" /> : wsStatus === 'connecting' ? <RefreshCw className="h-4 w-4 animate-spin" /> : <WifiOff className="h-4 w-4" />}
            {wsStatus === 'connected' ? 'LIVE' : wsStatus === 'connecting' ? 'CONNECTING' : 'OFFLINE'}
          </div>

          <div className="flex bg-black/40 rounded-2xl border border-white/5 p-1.5">
            <button
              onClick={() => setViewMode("live")}
              className={`px-5 py-2.5 text-xs font-bold rounded-xl transition-all duration-300 ${viewMode === "live" ? "bg-sky-500 text-white shadow-lg shadow-sky-500/30" : "text-slate-500 hover:text-slate-300"}`}
            >
              LIVE STREAM
            </button>
            <button
              onClick={() => setViewMode("historical")}
              className={`px-5 py-2.5 text-xs font-bold rounded-xl transition-all duration-300 flex items-center gap-2 ${viewMode === "historical" ? "bg-indigo-600 text-white shadow-lg shadow-indigo-600/30" : "text-slate-500 hover:text-slate-300"}`}
            >
              <Database className="h-3.5 w-3.5" /> ARCHIVE
            </button>
          </div>
          
          <button
            onClick={() => setAutoPoll(!autoPoll)}
            className={`flex items-center gap-2 rounded-2xl border px-5 py-2.5 text-xs font-bold transition-all duration-300 ${autoPoll ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400" : "border-white/10 bg-white/5 text-slate-500"}`}
          >
            <Activity className={`h-4 w-4 ${autoPoll ? "animate-pulse" : ""}`} />
            {autoPoll ? "MONITORING" : "PAUSED"}
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="rounded-2xl border border-rose-500/30 bg-rose-500/5 p-4 flex items-center gap-4">
          <div className="h-10 w-10 shrink-0 rounded-xl bg-rose-500/10 flex items-center justify-center border border-rose-500/20">
            <AlertOctagon className="h-6 w-6 text-rose-400" />
          </div>
          <div className="flex-1">
            <p className="text-sm font-bold text-rose-200">Connectivity Warning</p>
            <p className="text-xs text-rose-400/80">{error}</p>
          </div>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200 transition">
            <ChevronRight className="h-5 w-5 rotate-90" />
          </button>
        </div>
      )}

      {/* Futuristic Stats Grid */}
      <div className="grid gap-6 md:grid-cols-4">
        {[
          { label: "EVENT STREAMS", value: totalLogs, cls: "text-cyan-400", bg: "bg-cyan-500/10", border: "border-cyan-500/20", icon: FileText, desc: "Global ingestion rate" },
          { label: "VULN MATRICES", value: vulnerabilities.length, cls: "text-rose-400", bg: "bg-rose-500/10", border: "border-rose-500/20", icon: AlertOctagon, desc: "Active heuristic matches" },
          { label: "FILE INTEGRITY", value: files.length, cls: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/20", icon: Shield, desc: "Critical path monitoring" },
          { label: "NEURAL PULSE", value: wsStatus === 'connected' ? 'LIVE' : wsStatus === 'connecting' ? 'SYNC' : 'HALT', cls: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/20", icon: Activity, desc: "Real-time socket status" },
        ].map((stat) => (
          <div key={stat.label} className="relative overflow-hidden group glass-v2 border border-cyan-500/20 rounded-[2rem] p-6 hover:bg-cyan-500/5 hover:border-cyan-400/40 transition-all duration-500 hover:-translate-y-2 shadow-xl shadow-cyan-900/10">
            <div className="absolute inset-0 cyber-grid opacity-10 pointer-events-none group-hover:opacity-20 transition-opacity" />
            <div className="absolute top-0 right-0 p-8 opacity-[0.05] group-hover:opacity-[0.15] group-hover:scale-125 transition-all duration-700 text-cyan-500">
              <stat.icon size={120} />
            </div>
            <p className="relative z-10 text-[10px] font-black text-cyan-200/60 uppercase tracking-widest mb-4">{stat.label}</p>
            <div className="relative z-10 flex items-baseline gap-2">
              <span className={`text-4xl font-black drop-shadow-[0_0_8px_rgba(255,255,255,0.4)] ${stat.cls}`}>{stat.value}</span>
            </div>
            <p className="relative z-10 mt-3 text-[11px] text-cyan-100/50 font-mono">{stat.desc}</p>
          </div>
        ))}
      </div>

      {/* Main Navigation Tabs */}
      <div className="flex flex-col gap-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex gap-2 p-1.5 bg-black/60 rounded-[1.5rem] border border-cyan-500/20 backdrop-blur-md">
            <button
              onClick={() => setActiveTab("events")}
              className={`flex items-center gap-2.5 px-6 py-3 text-[11px] font-black tracking-widest rounded-2xl transition-all duration-300 ${activeTab === "events" ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_15px_rgba(34,211,238,0.3)]" : "text-cyan-200/50 hover:text-cyan-200/80"}`}
            >
              <Terminal className="h-4 w-4" />
              NEURAL LOGS
            </button>
            <button
              onClick={() => setActiveTab("vulnerabilities")}
              className={`flex items-center gap-2.5 px-6 py-3 text-[11px] font-black tracking-widest rounded-2xl transition-all duration-300 ${activeTab === "vulnerabilities" ? "bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-[0_0_15px_rgba(244,63,94,0.3)]" : "text-cyan-200/50 hover:text-cyan-200/80"}`}
            >
              <AlertTriangle className="h-4 w-4" />
              THREAT MATRICES
            </button>
            <button
              onClick={() => setActiveTab("files")}
              className={`flex items-center gap-2.5 px-6 py-3 text-[11px] font-black tracking-widest rounded-2xl transition-all duration-300 ${activeTab === "files" ? "bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-[0_0_15px_rgba(245,158,11,0.3)]" : "text-cyan-200/50 hover:text-cyan-200/80"}`}
            >
              <HardDrive className="h-4 w-4" />
              INTEGRITY CORE
            </button>
          </div>
        </div>

        {activeTab === "events" && (
          <div className="space-y-6">
            {/* Filters & Search */}
            <div className="flex flex-col lg:flex-row gap-4 items-stretch lg:items-center">
              <div className="relative flex-1 group">
                <Filter className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500 group-focus-within:text-sky-400 transition-colors" />
                <input
                  type="text"
                  value={searchText}
                  onChange={e => { setSearchText(e.target.value); }}
                  placeholder="Search live event stream (Windows, Linux, Android)..."
                  className="w-full rounded-2xl border border-white/5 bg-black/40 py-4 pl-12 pr-6 text-sm text-white placeholder-slate-600 outline-none focus:border-sky-500/40 focus:ring-4 focus:ring-sky-500/5 transition-all"
                />
              </div>

              {/* Level Filter */}
              <select
                value={filterLevel}
                onChange={e => setFilterLevel(e.target.value)}
                className="rounded-2xl border border-white/5 bg-black/40 py-4 px-5 text-sm text-white outline-none focus:border-sky-500/40 min-w-[140px]"
              >
                <option value="All">All Levels</option>
                <option value="Critical">Critical</option>
                <option value="Error">Error</option>
                <option value="Warning">Warning</option>
                <option value="Information">Information</option>
              </select>

              {/* Suspicious Toggle */}
              <button
                onClick={() => setFilterSuspicious(v => !v)}
                className={`flex items-center gap-2 rounded-2xl border px-5 py-3.5 text-xs font-bold transition-all ${filterSuspicious ? 'border-rose-500/30 bg-rose-500/10 text-rose-400' : 'border-white/10 bg-white/5 text-slate-500'}`}
              >
                {filterSuspicious ? <Eye className="h-4 w-4" /> : <EyeOff className="h-4 w-4" />}
                SUSPICIOUS ONLY
              </button>
            </div>

            {/* Loading State */}
            {loading && events.length === 0 && (
              <div className="flex flex-col items-center justify-center py-20 bg-white/2 border border-white/5 rounded-[2.5rem]">
                <RefreshCw className="h-8 w-8 text-sky-400 animate-spin mb-4" />
                <p className="text-sm text-slate-400">Loading events...</p>
              </div>
            )}

            {/* Event List */}
            <div className="space-y-3 min-h-[400px]">
              {!loading && filteredEvents.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-20 bg-white/2 border border-dashed border-white/10 rounded-[2.5rem] text-center">
                  <h3 className="text-xl font-bold text-slate-300 mb-2">No events matched</h3>
                  <button onClick={() => { setSearchText(""); setFilterLevel("All"); setFilterSuspicious(false); }} className="mt-4 text-sky-400 font-bold">CLEAR FILTERS</button>
                </div>
              ) : (
                <div className="rounded-[2.5rem] border border-white/5 bg-black/20 overflow-hidden">
                  <div className="overflow-y-auto max-h-[600px] space-y-2 p-4">
                    {paginatedEvents.map((event: WindowsEventLog) => (
                      <EventRow key={event.id} event={event} />
                    ))}
                  </div>

                  {/* Pagination */}
                  {filteredEvents.length > EVENTS_PER_PAGE && (
                    <div className="border-t border-white/5 bg-black/40 px-6 py-4 flex items-center justify-between">
                      <p className="text-xs text-slate-500 font-medium">
                        Page {safePage} of {totalPages} • {(safePage - 1) * EVENTS_PER_PAGE + 1}–{Math.min(safePage * EVENTS_PER_PAGE, filteredEvents.length)} of {filteredEvents.length}
                      </p>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                          disabled={safePage === 1}
                          className="px-4 py-2 text-xs font-bold bg-white/5 hover:bg-white/10 disabled:opacity-30 disabled:hover:bg-white/5 rounded-xl transition"
                        >
                          PREV
                        </button>
                        <button
                          onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                          disabled={safePage === totalPages}
                          className="px-4 py-2 text-xs font-bold bg-white/5 hover:bg-white/10 disabled:opacity-30 disabled:hover:bg-white/5 rounded-xl transition"
                        >
                          NEXT
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "vulnerabilities" && (
          <div className="space-y-4">
             {vulnerabilities.length > 0 ? vulnerabilities.map((v) => (
               <div key={v.id} className={`p-5 rounded-2xl border flex items-center gap-4 ${v.severity === 'Critical' ? 'border-rose-500/30 bg-rose-500/10' : 'border-amber-500/30 bg-amber-500/10'}`}>
                 <div className={`h-10 w-10 rounded-xl flex items-center justify-center ${v.severity === 'Critical' ? 'bg-rose-500 text-white' : 'bg-amber-500 text-white'}`}>
                   <AlertTriangle className="h-5 w-5" />
                 </div>
                 <div className="flex-1">
                   <p className="text-sm font-bold text-white">{v.title}</p>
                   <p className="text-xs text-slate-400 mt-1">{new Date(v.ts).toLocaleString()} • Detected via Live Heuristics</p>
                 </div>
                 <Badge cls={v.severity === 'Critical' ? levelColor.Critical : levelColor.Warning}>{v.severity}</Badge>
               </div>
             )) : (
               <div className="py-20 text-center text-slate-500">No vulnerabilities detected in current window.</div>
             )}
          </div>
        )}

        {/* ... (existing files tab) ... */}
        {activeTab === "files" && (
          <div className="space-y-6">
            <div className="rounded-[2.5rem] border border-amber-500/20 bg-amber-500/5 p-8 relative overflow-hidden">
              <div className="absolute top-0 right-0 p-8 opacity-[0.03] rotate-12">
                <HardDrive size={180} />
              </div>
              <div className="relative z-10">
                <h3 className="text-xl font-bold text-amber-200 mb-3 flex items-center gap-3">
                  <Shield className="h-6 w-6 text-amber-400" /> 
                  Cross-Platform FIM
                </h3>
                <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
                  Watching sensitive paths across Windows (%WINDIR%), Linux (/etc), and Android system configurations.
                </p>
              </div>
            </div>
            <div className="space-y-3">
              {files.length > 0 ? files.map((file, i) => <FileRow key={i} file={file} />) : <div className="text-center py-20 text-slate-500">No changes detected.</div>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
