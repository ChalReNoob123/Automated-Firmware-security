import { useState, useEffect, useCallback, useRef, type ReactNode } from "react";

import { 
  FileText, AlertTriangle, ChevronDown, ChevronRight, 
  Filter, HardDrive, Activity, Shield, Cpu, Zap, 
  Terminal, Monitor, CheckCircle2, Info, AlertOctagon, Database
} from "lucide-react";

import { API_BASE, WS_BASE, Token } from "../utils/api";

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

function EventRow({ event }: { event: WindowsEventLog }) {
  const [expanded, setExpanded] = useState(false);

  let timeStr = "Invalid Date";
  try {
    timeStr = new Intl.DateTimeFormat("en-US", {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit"
    }).format(event.timestamp && !isNaN(event.timestamp) ? event.timestamp : Date.now());
  } catch (e) {
    timeStr = "Unknown Date";
  }

  const Icon = levelIcon[event.level] || Info;
  const lColor = levelColor[event.level] || levelColor.Information;
  
  return (
    <div className={`group rounded-2xl border transition-all duration-500 ${event.isNew ? 'animate-pulse ring-1 ring-sky-500/50 shadow-[0_0_15px_rgba(14,165,233,0.2)]' : ''} ${event.suspicious ? 'border-rose-500/30 bg-rose-500/5 hover:bg-rose-500/10' : 'border-white/5 bg-white/3 hover:bg-white/5'}`}>
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
        <div className="border-t border-white/5 p-4 bg-black/20 space-y-4 animate-in slide-in-from-top-2 duration-300">
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
  const logChannel = "all";
  const [autoPoll, setAutoPoll] = useState(true);
  const [events, setEvents] = useState<WindowsEventLog[]>([]);
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
  const [_loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [computerInfo, setComputerInfo] = useState<string>("Local Machine");

  const [filterLevel, setFilterLevel] = useState<string>("All");
  const filterSuspicious = false;
  const [searchText, setSearchText] = useState("");
  const [toast, setToast] = useState<string | null>(null);
  const [wsRetryNonce, setWsRetryNonce] = useState(0);

  const wsRef = useRef<WebSocket | null>(null);

  const showToast = (message: string) => {
    setToast(message);
    setTimeout(() => setToast(null), 3000);
  };

  const fetchLiveLogs = useCallback(async (channel: string = "all", silent = false) => {
    if (!silent) setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/logs?channel=${channel}&max=100`, {
        headers: { "Authorization": `Bearer ${Token.getAccess()}` }
      });
      if (res.status === 401) throw new Error("Unauthorized. Please re-login.");
      if (!res.ok) throw new Error("Log agent unreachable.");

      const json = await res.json();
      if (json.logs) {
        setEvents(json.logs);
        if (json.computer) setComputerInfo(json.computer);
        if (!silent) showToast(`Loaded ${json.logs.length} actual device logs`);
      }
    } catch (e: any) {
      setError(e.message || "Failed to fetch device logs.");
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  const fetchHistoricalLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/database/logs`, {
        headers: { "Authorization": `Bearer ${Token.getAccess()}` }
      });
      if (!res.ok) throw new Error("Historical database unreachable.");
      const json = await res.json();

      const parsedEvents: WindowsEventLog[] = json.databaseLogs.map((log: any, i: number) => ({
        id: log.hash || `db-${i}`,
        eventId: log.eventId,
        timestamp: new Date(log.date).getTime() || Date.now(),
        level: log.level,
        source: log.source,
        category: log.task,
        logName: log.logName || "Historical",
        message: log.description || 'No description.',
        computer: 'Local Host',
        suspicious: log.suspicious,
        mitre: log.mitre ? JSON.parse(log.mitre) : null,
      }));

      setEvents(parsedEvents);
    } catch (e: any) {
      setError(e.message || "Failed to fetch database records.");
    } finally {
      setLoading(false);
    }
  }, []);

  // WebSocket Setup for Real-time Streaming
  useEffect(() => {
    if (viewMode !== "live" || !autoPoll) {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      return;
    }

    const token = Token.getAccess();
    if (!token) return;

    const ws = new WebSocket(WS_BASE);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ event: "auth", token }));
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.event === "telemetry_update") {
          const snapshot = data.data || data;
          
          if (snapshot.logs) {
             const newLogs: WindowsEventLog[] = snapshot.logs.map((l: any) => {
              let ts = Date.now();
              if (l.TimeCreated) {
                if (typeof l.TimeCreated === 'string' && l.TimeCreated.startsWith('/Date(')) {
                  ts = parseInt(l.TimeCreated.replace(/[^0-9]/g, ''), 10);
                } else {
                  ts = new Date(l.TimeCreated).getTime();
                }
              }
              if (isNaN(ts)) ts = Date.now();

              return {
                ...l,
                id: l.Id || Math.random().toString(),
                eventId: l.Id || '0',
                timestamp: ts,
                level: l.LevelDisplayName || 'Information',
                source: l.ProviderName || 'System',
                category: l.TaskDisplayName || 'System',
                logName: l.LogName || 'System',
                message: l.Message || '',
                computer: l.MachineName || l.Computer || 'Local',
                suspicious: !!l.Suspicious,
                isNew: true
              };
            });
            
            setEvents(prev => {
              const existingIds = new Set(prev.slice(0, 50).map(e => `${e.eventId}-${e.timestamp}`));
              const uniqueNew = newLogs.filter(l => !existingIds.has(`${l.eventId}-${l.timestamp}`));
              if (uniqueNew.length === 0) return prev;
              const updated = [...uniqueNew, ...prev].slice(0, 200);
              setTimeout(() => setEvents(current => current.map(e => ({ ...e, isNew: false }))), 3000);
              return updated;
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
      } catch (err) {
        console.error("WS parse error:", err);
      }
    };

    ws.onclose = () => {
      if (viewMode === "live" && autoPoll) {
        setTimeout(() => setWsRetryNonce(prev => prev + 1), 5000);
      }
    };

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [viewMode, autoPoll, wsRetryNonce]);

  useEffect(() => {
    if (viewMode === "live") fetchLiveLogs(logChannel);
    else fetchHistoricalLogs();
  }, [viewMode, logChannel, fetchLiveLogs, fetchHistoricalLogs]);

  // Initial data fetch
  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/analyze`, {
          headers: { "Authorization": `Bearer ${Token.getAccess()}` }
        });
        const json = await res.json();
        if (json.files) setFiles(json.files);
        if (json.analysis?.threats) {
          setVulnerabilities(json.analysis.threats.map((t: string, i: number) => ({
            id: `vuln-init-${i}`,
            title: t,
            severity: t.includes('CRITICAL') ? 'Critical' : t.includes('WARNING') ? 'Warning' : 'Information',
            ts: Date.now()
          })));
        }
      } catch {}
    };
    fetchData();
  }, []);

  const filteredEvents = events.filter(e => {
    if (filterLevel !== "All" && e.level !== filterLevel) return false;
    if (filterSuspicious && !e.suspicious) return false;
    const isNoise = e.message.includes("ApiSet Function") || e.source.includes("AppModel");
    if (isNoise && !filterSuspicious) return false;
    if (searchText && !e.message.toLowerCase().includes(searchText.toLowerCase()) &&
      !e.source.toLowerCase().includes(searchText.toLowerCase()) &&
      !String(e.eventId).includes(searchText)) return false;
    return true;
  });

  const totalLogs = events.length;

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

      {/* Header Section */}
      <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between bg-white/3 border border-white/5 rounded-[2.5rem] p-6 lg:p-8 backdrop-blur-md">
        <div className="flex items-center gap-5">
          <div className="h-14 w-14 rounded-2xl bg-gradient-to-br from-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-sky-500/20">
            <Cpu className="h-8 w-8 text-white" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-3">
              Multi-OS Telemetry Hub
              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-[10px] text-emerald-400 font-bold uppercase tracking-wider">
                <div className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                Cross-Platform Agent Active
              </span>
            </h2>
            <div className="flex items-center gap-4 mt-1 text-slate-400 text-sm">
              <span className="flex items-center gap-1.5"><Monitor className="h-4 w-4" /> {computerInfo}</span>
              <span className="h-1 w-1 rounded-full bg-slate-700" />
              <span className="flex items-center gap-1.5"><Shield className="h-4 w-4" /> Windows/Linux/Android</span>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
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

      {/* ... (error and stats) ... */}
      {error && (
        <div className="rounded-2xl border border-rose-500/30 bg-rose-500/5 p-4 flex items-center gap-4 animate-in fade-in zoom-in duration-300">
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

      {/* Modern Stats Grid */}
      <div className="grid gap-6 md:grid-cols-4">
        {[
          { label: "Total Events", value: totalLogs, color: "sky", icon: FileText, desc: "Cross-OS event stream" },
          { label: "Vulnerabilities", value: vulnerabilities.length, color: "rose", icon: AlertOctagon, desc: "Live threat & vuln matches" },
          { label: "File Changes", value: files.length, color: "amber", icon: Shield, desc: "Integrity monitoring" },
          { label: "Agent Pulse", value: "Active", color: "emerald", icon: Activity, desc: "Real-time telemetry heartbeat" },
        ].map((stat) => (
          <div key={stat.label} className="relative overflow-hidden group bg-white/3 border border-white/5 rounded-[2rem] p-6 hover:bg-white/5 transition-all duration-500 hover:-translate-y-1">
            <div className={`absolute top-0 right-0 p-8 opacity-[0.03] group-hover:opacity-[0.08] group-hover:scale-150 transition-all duration-700 text-${stat.color}-500`}>
              <stat.icon size={120} />
            </div>
            <p className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-4">{stat.label}</p>
            <div className="flex items-baseline gap-2">
              <span className={`text-4xl font-black text-${stat.color}-400`}>{stat.value}</span>
            </div>
            <p className="mt-2 text-xs text-slate-500 font-medium">{stat.desc}</p>
          </div>
        ))}
      </div>

      {/* Main Navigation Tabs */}
      <div className="flex flex-col gap-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex gap-2 p-1.5 bg-black/40 rounded-[1.5rem] border border-white/5">
            <button
              onClick={() => setActiveTab("events")}
              className={`flex items-center gap-2.5 px-6 py-3 text-xs font-bold rounded-2xl transition-all duration-300 ${activeTab === "events" ? "bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-lg shadow-sky-500/5" : "text-slate-500 hover:text-slate-300"}`}
            >
              <Terminal className="h-4 w-4" />
              EVENT LOGS
            </button>
            <button
              onClick={() => setActiveTab("vulnerabilities")}
              className={`flex items-center gap-2.5 px-6 py-3 text-xs font-bold rounded-2xl transition-all duration-300 ${activeTab === "vulnerabilities" ? "bg-rose-500/10 text-rose-400 border border-rose-500/20 shadow-lg shadow-rose-500/5" : "text-slate-500 hover:text-slate-300"}`}
            >
              <AlertTriangle className="h-4 w-4" />
              VULNERABILITIES
            </button>
            <button
              onClick={() => setActiveTab("files")}
              className={`flex items-center gap-2.5 px-6 py-3 text-xs font-bold rounded-2xl transition-all duration-300 ${activeTab === "files" ? "bg-amber-500/10 text-amber-400 border border-amber-500/20 shadow-lg shadow-amber-500/5" : "text-slate-500 hover:text-slate-300"}`}
            >
              <HardDrive className="h-4 w-4" />
              FILE INTEGRITY
            </button>
          </div>
        </div>

        {activeTab === "events" && (
          <div className="space-y-6">
            {/* ... (existing event filter and list) ... */}
            <div className="flex flex-col lg:flex-row gap-4 items-stretch lg:items-center">
              <div className="relative flex-1 group">
                <Filter className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500 group-focus-within:text-sky-400 transition-colors" />
                <input
                  type="text"
                  value={searchText}
                  onChange={e => setSearchText(e.target.value)}
                  placeholder="Search live event stream (Windows, Linux, Android)..."
                  className="w-full rounded-2xl border border-white/5 bg-black/40 py-4 pl-12 pr-6 text-sm text-white placeholder-slate-600 outline-none focus:border-sky-500/40 focus:ring-4 focus:ring-sky-500/5 transition-all"
                />
              </div>
            </div>

            <div className="space-y-3 min-h-[400px]">
              {filteredEvents.length > 0 ? (
                <div className="rounded-[2.5rem] border border-white/5 bg-black/20 overflow-hidden">
                  <div 
                    className="overflow-y-auto max-h-[600px] space-y-2 p-4 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent"
                  >
                    {filteredEvents.slice(0, 200).map((event) => (
                      <EventRow key={event.id} event={event} />
                    ))}
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-20 bg-white/2 border border-dashed border-white/10 rounded-[2.5rem] text-center">
                  <h3 className="text-xl font-bold text-slate-300 mb-2">No events matched</h3>
                  <button onClick={() => {setSearchText(""); setFilterLevel("All");}} className="mt-4 text-sky-400 font-bold">CLEAR FILTERS</button>
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
