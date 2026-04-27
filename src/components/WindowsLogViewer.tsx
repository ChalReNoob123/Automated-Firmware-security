import { useState, useEffect, useCallback } from "react";
import { FileText, Database, AlertTriangle, ChevronDown, ChevronRight, RefreshCw, Filter, HardDrive, Activity } from "lucide-react";
import CryptoJS from "crypto-js";

type WindowsEventLog = {
  id: string;
  eventId: number | string;
  timestamp: number;
  level: string;
  source: string;
  category: string;
  message: string;
  computer: string;
  user: string;
  suspicious: boolean;
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

const levelDot: Record<string, string> = {
  Critical: "bg-rose-400",
  Error: "bg-orange-400",
  Warning: "bg-amber-400",
  Information: "bg-sky-400",
  Verbose: "bg-slate-500",
};

function EventRow({ event }: { event: WindowsEventLog }) {
  const [expanded, setExpanded] = useState(false);

  const time = new Intl.DateTimeFormat("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit"
  }).format(event.timestamp);

  const lColor = levelColor[event.level] || levelColor.Information;
  const lDot = levelDot[event.level] || levelDot.Information;

  return (
    <div className={`rounded-2xl border transition-all ${event.suspicious ? lColor : "border-white/10 bg-white/3 hover:bg-white/5"}`}>
      <button
        type="button"
        className="w-full p-4 text-left flex items-start gap-3"
        onClick={() => setExpanded(prev => !prev)}
      >
        <div className={`mt-1 h-2 w-2 shrink-0 rounded-full ${lDot}`} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${lColor}`}>{event.level}</span>
            <span className="font-mono text-xs text-slate-400">ID:{event.eventId}</span>
            <span className="text-xs text-slate-500">{event.source}</span>
            {event.suspicious && <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />}
          </div>
          <p className="text-sm text-slate-200 leading-relaxed line-clamp-2">{event.message}</p>
          <div className="flex flex-wrap gap-x-4 gap-y-1 mt-1 text-xs text-slate-500">
            <span>{time}</span>
            <span>{event.computer}</span>
            <span>{event.category}</span>
          </div>
        </div>
        <div className="shrink-0 text-slate-500">
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-white/10 p-4 space-y-4">
          <div className="grid gap-3 md:grid-cols-2">
            <div className="rounded-xl border border-white/10 bg-black/20 p-3">
              <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">Full Message</p>
              <p className="text-sm text-slate-300 leading-relaxed">{event.message}</p>
            </div>
            <div className="rounded-xl border border-white/10 bg-black/20 p-3">
              <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">Event Properties</p>
              <div className="space-y-1 text-sm">
                <div className="flex justify-between text-slate-300">
                  <span className="text-slate-500">Event ID</span><span className="font-mono">{event.eventId}</span>
                </div>
                <div className="flex justify-between text-slate-300">
                  <span className="text-slate-500">Level</span><span>{event.level}</span>
                </div>
                <div className="flex justify-between text-slate-300">
                  <span className="text-slate-500">Task Category</span><span>{event.category}</span>
                </div>
                <div className="flex justify-between text-slate-300">
                  <span className="text-slate-500">Computer</span><span className="font-mono">{event.computer}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function FileRow({ file }: { file: FileEntry }) {
  const time = new Intl.DateTimeFormat("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit"
  }).format(new Date(file.modified));

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/10 transition">
      <div className="flex items-start gap-3 min-w-0">
        <HardDrive className="h-5 w-5 text-sky-400 mt-0.5 shrink-0" />
        <div className="min-w-0">
          <p className="text-sm font-semibold text-slate-200 truncate">{file.name}</p>
          <p className="text-xs font-mono text-slate-500 truncate">{file.path}</p>
        </div>
      </div>
      <div className="flex items-center gap-4 text-xs text-slate-400 shrink-0">
        <span className="font-mono bg-black/30 px-2 py-1 rounded">{(file.size / 1024).toFixed(1)} KB</span>
        <span>Modified: {time}</span>
      </div>
    </div>
  );
}

export default function WindowsLogViewer() {
  const [activeTab, setActiveTab] = useState<"events" | "files">("events");
  const [viewMode, setViewMode] = useState<"live" | "historical">("live");
  const [autoPoll, setAutoPoll] = useState(true);
  const [events, setEvents] = useState<WindowsEventLog[]>([]);
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [filterLevel, setFilterLevel] = useState<string>("All");
  const [filterSuspicious, setFilterSuspicious] = useState(false);
  const [searchText, setSearchText] = useState("");
  const [toast, setToast] = useState<string | null>(null);

  const showToast = (message: string) => {
    setToast(message);
    setTimeout(() => setToast(null), 3000);
  };

  const fetchRealLogs = useCallback(async (silent = false) => {
    setViewMode("live");
    if (!silent) setLoading(true);
    setError(null);
    try {
      const res = await fetch("http://localhost:3001/api/analyze", {
        headers: { "Authorization": `Bearer ${import.meta.env.VITE_ADMIN_TOKEN || 'SG-ADMIN-TOKEN-9081'}` }
      });
      if (res.status === 401) throw new Error("Authentication failed. Unauthorized connection.");
      if (!res.ok) throw new Error("Local agent server not responding.");

      const encResponse = await res.json();
      const E2E_SECRET = CryptoJS.SHA256(import.meta.env.VITE_ENCRYPTION_KEY || "sentinel-grid-enterprise-key-2026");
      const iv = CryptoJS.enc.Hex.parse(encResponse.iv);
      const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Hex.parse(encResponse.encryptedData) });
      const decrypted = CryptoJS.AES.decrypt(cipherParams, E2E_SECRET, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
      const rawJson = decrypted.toString(CryptoJS.enc.Utf8);
      const json = JSON.parse(rawJson);

      if (json.files) setFiles(json.files);
      if (typeof json.logs === 'string') throw new Error(json.logs);

      const parsedEvents: WindowsEventLog[] = Array.isArray(json.logs) ? json.logs.map((log: any, i: number) => {
        const id = log.Id ? log.Id.toString() : 'Unknown';
        const isSuspicious = ['4625', '1102', '4688', '4720', '4698'].includes(id);
        let level = log.LevelDisplayName || 'Information';
        if (isSuspicious) level = 'Critical';

        return {
          id: `live-${i}`,
          eventId: id,
          timestamp: new Date(log.Date || Date.now()).getTime(),
          level: level,
          source: log.ProviderName || 'Windows Event Log',
          category: log.TaskDisplayName || 'System Event',
          message: log.Message || 'No description provided by the OS.',
          computer: 'Local Host',
          user: 'N/A',
          suspicious: isSuspicious,
        };
      }) : [];

      setEvents(parsedEvents);
      if (!silent) showToast("Live Telemetry Synchronized");
    } catch (e: any) {
      setError(e.message || "Failed to fetch live logs.");
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  const fetchHistoricalLogs = useCallback(async () => {
    setViewMode("historical");
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("http://localhost:3001/api/database/logs", {
        headers: { "Authorization": `Bearer ${import.meta.env.VITE_ADMIN_TOKEN || 'SG-ADMIN-TOKEN-9081'}` }
      });
      if (!res.ok) throw new Error("Database not responding.");
      const encResponse = await res.json();
      const E2E_SECRET = CryptoJS.SHA256(import.meta.env.VITE_ENCRYPTION_KEY || "sentinel-grid-enterprise-key-2026");
      const iv = CryptoJS.enc.Hex.parse(encResponse.iv);
      const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Hex.parse(encResponse.encryptedData) });
      const decrypted = CryptoJS.AES.decrypt(cipherParams, E2E_SECRET, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
      const rawJson = decrypted.toString(CryptoJS.enc.Utf8);
      const json = JSON.parse(rawJson);

      const parsedEvents: WindowsEventLog[] = json.databaseLogs.map((log: any, i: number) => ({
        id: log.hash || `db-${i}`,
        eventId: log.eventId,
        timestamp: new Date(log.date).getTime() || Date.now(),
        level: log.level,
        source: log.source,
        category: log.task,
        message: log.description || 'No description.',
        computer: 'Local Host',
        user: 'N/A',
        suspicious: log.suspicious,
      }));

      setEvents(parsedEvents);
    } catch (e: any) {
      setError(e.message || "Failed to fetch database logs.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (viewMode === "live") fetchRealLogs();
    else fetchHistoricalLogs();

    if (!autoPoll) return;
    const interval = setInterval(() => {
      if (viewMode === "live") fetchRealLogs(true);
      else fetchHistoricalLogs();
    }, 5000);
    return () => clearInterval(interval);
  }, [viewMode, autoPoll, fetchRealLogs, fetchHistoricalLogs]);

  const filteredEvents = events.filter(e => {
    if (filterLevel !== "All" && e.level !== filterLevel) return false;
    if (filterSuspicious && !e.suspicious) return false;
    if (searchText && !e.message.toLowerCase().includes(searchText.toLowerCase()) &&
      !e.source.toLowerCase().includes(searchText.toLowerCase()) &&
      !String(e.eventId).includes(searchText)) return false;
    return true;
  });

  const totalLogs = events.length;
  const criticalCount = events.filter(e => e.level === "Critical").length;
  const suspiciousCount = events.filter(e => e.suspicious).length;

  return (
    <div className="space-y-6 relative">
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 animate-in slide-in-from-bottom-5 fade-in duration-300">
          <div className="flex items-center gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 shadow-lg shadow-emerald-500/10 backdrop-blur-md">
            <Activity className="h-4 w-4 text-emerald-400" />
            <p className="text-sm font-medium text-emerald-200">{toast}</p>
          </div>
        </div>
      )}

      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <FileText className="h-5 w-5 text-sky-400 drop-shadow-[0_0_8px_rgba(56,189,248,0.8)]" />
            Live System Telemetry Explorer
          </h2>
          <p className="text-sm text-slate-400">
            Securely importing and decrypting actual logs and file modifications from the local machine.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex bg-white/5 rounded-xl border border-white/10 p-1">
            <button
              onClick={() => setViewMode("live")}
              className={`px-4 py-2 text-sm font-semibold rounded-lg transition ${viewMode === "live" ? "bg-sky-500 text-white shadow-[0_0_15px_rgba(14,165,233,0.3)]" : "text-slate-400 hover:text-white"}`}
            >
              Live Memory
            </button>
            <button
              onClick={() => setViewMode("historical")}
              className={`px-4 py-2 text-sm font-semibold rounded-lg transition flex items-center gap-1.5 ${viewMode === "historical" ? "bg-indigo-500 text-white shadow-[0_0_15px_rgba(99,102,241,0.3)]" : "text-slate-400 hover:text-white"}`}
            >
              <Database className="h-4 w-4" /> Historical DB
            </button>
          </div>
          
          <button
            onClick={() => setAutoPoll(!autoPoll)}
            className={`flex items-center gap-2 rounded-xl border px-4 py-2 text-sm font-semibold transition hover:scale-105 ${autoPoll ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.2)]" : "border-white/10 bg-white/5 text-slate-400 hover:text-white"}`}
          >
            <Activity className={`h-4 w-4 ${autoPoll ? "animate-pulse" : ""}`} />
            {autoPoll ? "Live Sync Active" : "Auto-Sync Paused"}
          </button>
          <button
            onClick={() => viewMode === "live" ? fetchRealLogs(false) : fetchHistoricalLogs()}
            disabled={loading}
            className="flex items-center gap-2 rounded-xl border border-sky-400/30 bg-sky-500/10 px-4 py-2 text-sm font-semibold text-sky-200 hover:bg-sky-500/20 hover:scale-105 transition disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            {loading ? "Syncing..." : "Force Sync"}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-4 flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0" />
          <p className="text-sm text-rose-200">{error}</p>
        </div>
      )}

      {/* Stats row */}
      <div className="grid gap-4 md:grid-cols-3">
        {[
          { label: "Total Events", value: totalLogs, color: "sky" },
          { label: "Critical", value: criticalCount, color: "rose" },
          { label: "Warnings", value: suspiciousCount, color: "amber" },
        ].map((stat) => (
          <div key={stat.label} className={`glass-panel rounded-2xl p-5 transition-all duration-300 hover:scale-[1.02] hover:glow-${stat.color} group`}>
            <p className="text-sm font-semibold text-slate-400 uppercase tracking-widest">{stat.label}</p>
            <p className={`mt-2 text-4xl font-bold text-${stat.color}-400 group-hover:text-glow`}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-white/10 pb-4">
        <button
          type="button"
          onClick={() => setActiveTab("events")}
          className={`flex items-center gap-2 rounded-2xl border px-5 py-3 text-sm font-medium transition ${activeTab === "events" ? "border-sky-400/30 bg-sky-500/10 text-sky-200" : "border-white/10 bg-white/5 text-slate-400 hover:text-slate-200"}`}
        >
          <FileText className="h-4 w-4" />
          Windows Event Logs
          <span className="rounded-full bg-black/30 px-2 py-0.5 text-xs">{events.length}</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("files")}
          className={`flex items-center gap-2 rounded-2xl border px-5 py-3 text-sm font-medium transition ${activeTab === "files" ? "border-amber-400/30 bg-amber-500/10 text-amber-200" : "border-white/10 bg-white/5 text-slate-400 hover:text-slate-200"}`}
        >
          <HardDrive className="h-4 w-4" />
          File Integrity Monitor
          {files.length > 0 && <span className="rounded-full bg-black/30 px-2 py-0.5 text-xs">{files.length}</span>}
        </button>
      </div>

      {activeTab === "events" && (
        <>
          <div className="flex flex-wrap gap-3 items-center">
            <div className="relative flex-1 min-w-[200px]">
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
              <input
                type="text"
                value={searchText}
                onChange={e => setSearchText(e.target.value)}
                placeholder="Filter events by message, source, or ID…"
                className="w-full rounded-2xl border border-white/10 bg-black/30 py-2.5 pl-9 pr-4 text-sm text-white placeholder-slate-600 outline-none focus:border-sky-500/50 transition"
              />
            </div>
            {["All", "Critical", "Error", "Warning", "Information"].map(level => (
              <button
                key={level}
                onClick={() => setFilterLevel(level)}
                className={`rounded-xl border px-3 py-2 text-xs font-medium transition ${filterLevel === level ? "border-sky-400/30 bg-sky-500/10 text-sky-200" : "border-white/10 bg-white/5 text-slate-400 hover:text-slate-200"}`}
              >
                {level}
              </button>
            ))}
            <button
              onClick={() => setFilterSuspicious(prev => !prev)}
              className={`flex items-center gap-1.5 rounded-xl border px-3 py-2 text-xs font-medium transition ${filterSuspicious ? "border-amber-400/30 bg-amber-500/10 text-amber-200" : "border-white/10 bg-white/5 text-slate-400"}`}
            >
              <AlertTriangle className="h-3.5 w-3.5" />
              Suspicious only
            </button>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>Showing {filteredEvents.length} of {events.length} real events</span>
            </div>
            {filteredEvents.map((event) => <EventRow key={event.id} event={event} />)}
            {filteredEvents.length === 0 && !loading && (
              <div className="text-center p-8 text-slate-500 border border-white/5 rounded-2xl bg-white/5">
                No events matched the current filter.
              </div>
            )}
          </div>
        </>
      )}

      {activeTab === "files" && (
        <div className="space-y-4">
          <div className="rounded-2xl border border-amber-400/20 bg-amber-500/5 p-4">
            <h3 className="text-sm font-semibold text-amber-200 mb-1 flex items-center gap-2">
              <HardDrive className="h-4 w-4" /> Live File Integrity Tracking
            </h3>
            <p className="text-xs text-slate-400">
              Actively monitoring the local filesystem for recent modifications. Sudden changes to system files or unfamiliar executables in the user directory may indicate a breach.
            </p>
          </div>
          <div className="space-y-2">
            {files.map((file, i) => <FileRow key={i} file={file} />)}
            {files.length === 0 && !loading && (
              <div className="text-center p-8 text-slate-500 border border-white/5 rounded-2xl bg-white/5">
                No recent file modifications detected in the scan area.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
