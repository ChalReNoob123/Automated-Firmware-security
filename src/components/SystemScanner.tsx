import { useState, useEffect, useCallback, useRef } from "react";
import {
  Shield, AlertTriangle, Activity, HardDrive, FileText,
  Search, Download, Play, Square, ChevronDown, ChevronRight,
  CheckCircle2, AlertOctagon, Monitor, Cpu, Lock, Unlock, Eye,
} from "lucide-react";
import { API_BASE, WS_BASE, Token } from "../utils/api";

type ScanTarget = {
  id: string; label: string; category: string; criticality: string;
  resolvedPath: string | null; exists: boolean; maxDepth: number;
  extensions: string[] | null; mitre: string[];
};
type ScanSession = {
  id: string; started_at: number; completed_at: number | null;
  status: string; risk_score: number; total_files: number;
  scanned_files: number; findings: number;
  summary: { totalFiles: number; scannedFiles: number; findings: number; critical: number; suspicious: number; avgRiskScore: number; duration: number } | null;
  config: { targets: string[] } | null;
};
type Finding = {
  id: string; file_path: string; file_name: string; file_size: number;
  sha256: string | null; entropy: number | null; is_signed: number;
  signature_status: string; signer: string | null; has_ads: number;
  ads_streams: string[]; risk_score: number; risk_factors: string[];
  mitre_techniques: string[]; directory_category: string;
  directory_criticality: string; target_label: string; status: string;
  created_at: number;
};
type ScanProgress = {
  sessionId: string; totalFiles: number; scannedFiles: number;
  findings: number; currentDir: string; elapsed: number;
};

const STATUS_COLORS: Record<string, string> = {
  critical: "border-rose-500/30 bg-rose-500/10 text-rose-300",
  suspicious: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  warning: "border-orange-400/30 bg-orange-400/10 text-orange-300",
  clean: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
};
const CRIT_COLORS: Record<string, string> = {
  critical: "bg-rose-500/20 text-rose-300 border-rose-500/20",
  high: "bg-amber-500/20 text-amber-300 border-amber-500/20",
  medium: "bg-sky-500/20 text-sky-300 border-sky-500/20",
  low: "bg-slate-500/20 text-slate-400 border-slate-500/20",
};

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? "#f43f5e" : score >= 40 ? "#f59e0b" : score >= 20 ? "#fb923c" : "#34d399";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 rounded-full bg-white/5 overflow-hidden">
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className="text-xs font-mono font-bold" style={{ color }}>{score}</span>
    </div>
  );
}

export default function SystemScanner() {
  const [targets, setTargets] = useState<ScanTarget[]>([]);
  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set());
  const [sessions, setSessions] = useState<ScanSession[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [scanning, setScanning] = useState(false);
  const [viewSession, setViewSession] = useState<string | null>(null);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [filterStatus, setFilterStatus] = useState("all");
  const [searchText, setSearchText] = useState("");
  const [sortBy, setSortBy] = useState<"risk" | "name" | "size">("risk");
  const [configOpen, setConfigOpen] = useState(true);
  const [checkSigs, setCheckSigs] = useState(true);
  const [checkADS, setCheckADS] = useState(true);
  const [maxDepth, setMaxDepth] = useState(2);
  const wsRef = useRef<WebSocket | null>(null);

  const authHeaders = useCallback(() => ({ Authorization: `Bearer ${Token.getAccess()}` }), []);

  // Load targets
  useEffect(() => {
    fetch(`${API_BASE}/api/scanner/targets`, { headers: authHeaders() })
      .then(r => r.json())
      .then(d => {
        if (d.targets) {
          setTargets(d.targets);
          setSelectedTargets(new Set(d.targets.filter((t: ScanTarget) => t.exists).map((t: ScanTarget) => t.id)));
        }
      }).catch(() => {});
  }, [authHeaders]);

  // Load sessions
  const loadSessions = useCallback(() => {
    fetch(`${API_BASE}/api/scanner/sessions?limit=10`, { headers: authHeaders() })
      .then(r => r.json())
      .then(d => { if (d.sessions) setSessions(d.sessions); })
      .catch(() => {});
  }, [authHeaders]);
  useEffect(() => { loadSessions(); }, [loadSessions]);

  // WebSocket for progress
  useEffect(() => {
    if (!scanning) return;
    const token = Token.getAccess();
    if (!token) return;
    const ws = new WebSocket(WS_BASE);
    wsRef.current = ws;
    ws.onopen = () => ws.send(JSON.stringify({ event: "auth", token }));
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.event === "scanner_progress") setProgress(msg.data);
        if (msg.event === "scanner_complete") {
          setScanning(false);
          setProgress(null);
          loadSessions();
          if (msg.data?.sessionId) loadFindings(msg.data.sessionId);
        }
      } catch {}
    };
    ws.onclose = () => { wsRef.current = null; };
    return () => { ws.close(); wsRef.current = null; };
  }, [scanning, loadSessions]);

  const loadFindings = useCallback((sessionId: string) => {
    setViewSession(sessionId);
    const params = new URLSearchParams();
    if (filterStatus !== "all") params.set("status", filterStatus);
    if (sortBy === "name") params.set("sort", "name");
    fetch(`${API_BASE}/api/scanner/sessions/${sessionId}/findings?${params}`, { headers: authHeaders() })
      .then(r => r.json())
      .then(d => { if (d.findings) setFindings(d.findings); })
      .catch(() => {});
  }, [authHeaders, filterStatus, sortBy]);

  const startScan = async () => {
    setScanning(true); setFindings([]); setProgress(null);
    try {
      await fetch(`${API_BASE}/api/scanner/start`, {
        method: "POST", headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({
          targets: [...selectedTargets], maxDepth, checkSignatures: checkSigs, checkADS,
        }),
      });
    } catch { setScanning(false); }
  };

  const stopScan = async () => {
    await fetch(`${API_BASE}/api/scanner/stop`, { method: "POST", headers: authHeaders() }).catch(() => {});
    setScanning(false); setProgress(null); loadSessions();
  };

  const toggleTarget = (id: string) => {
    setSelectedTargets(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const filteredFindings = findings.filter(f => {
    if (filterStatus !== "all" && f.status !== filterStatus) return false;
    if (searchText) {
      const q = searchText.toLowerCase();
      return f.file_name.toLowerCase().includes(q) || f.file_path.toLowerCase().includes(q) ||
        (f.sha256 || "").includes(q) || f.mitre_techniques.some(t => t.toLowerCase().includes(q));
    }
    return true;
  });

  const currentSession = sessions.find(s => s.id === viewSession);
  const pct = progress ? (progress.totalFiles > 0 ? Math.round((progress.scannedFiles / progress.totalFiles) * 100) : 0) : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row gap-6 lg:items-center lg:justify-between bg-white/3 border border-white/5 rounded-[2rem] p-6 backdrop-blur-md">
        <div className="flex items-center gap-4">
          <div className="h-14 w-14 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
            <Search className="h-7 w-7 text-white" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-3">
              System Scanner
              <span className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${scanning ? "bg-amber-500/10 border border-amber-500/20 text-amber-400" : "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400"}`}>
                <div className={`h-1.5 w-1.5 rounded-full ${scanning ? "bg-amber-500 animate-pulse" : "bg-emerald-500"}`} />
                {scanning ? "Scanning" : "Idle"}
              </span>
            </h2>
            <p className="text-sm text-slate-400 mt-0.5">Multi-threaded OS directory analysis with MITRE ATT&CK mapping</p>
          </div>
        </div>
        <div className="flex gap-3">
          {!scanning ? (
            <button onClick={startScan} disabled={selectedTargets.size === 0}
              className="flex items-center gap-2 rounded-2xl bg-gradient-to-r from-indigo-500 to-purple-600 px-6 py-3 text-sm font-bold text-white shadow-lg shadow-indigo-500/20 transition hover:scale-105 active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed">
              <Play className="h-4 w-4" /> Start Scan
            </button>
          ) : (
            <button onClick={stopScan}
              className="flex items-center gap-2 rounded-2xl bg-rose-500/20 border border-rose-500/30 px-6 py-3 text-sm font-bold text-rose-300 transition hover:bg-rose-500/30">
              <Square className="h-4 w-4" /> Stop
            </button>
          )}
        </div>
      </div>

      {/* Progress Bar */}
      {scanning && progress && (
        <div className="rounded-2xl border border-indigo-500/20 bg-indigo-500/5 p-5 space-y-3 animate-in fade-in">
          <div className="flex justify-between text-sm">
            <span className="text-indigo-300 font-bold">Scanning: {progress.currentDir?.split("\\").slice(-2).join("\\")}</span>
            <span className="text-slate-400 font-mono">{progress.scannedFiles}/{progress.totalFiles} files • {Math.round(progress.elapsed / 1000)}s</span>
          </div>
          <div className="h-2 rounded-full bg-black/40 overflow-hidden">
            <div className="h-full rounded-full bg-gradient-to-r from-indigo-500 to-purple-500 transition-all duration-300" style={{ width: `${pct}%` }} />
          </div>
          <div className="flex gap-6 text-xs text-slate-400">
            <span className="flex items-center gap-1.5"><Activity className="h-3 w-3 text-indigo-400" /> {pct}%</span>
            <span className="flex items-center gap-1.5"><AlertTriangle className="h-3 w-3 text-amber-400" /> {progress.findings} findings</span>
          </div>
        </div>
      )}

      {/* Config + Targets */}
      <div className="rounded-[2rem] border border-white/5 bg-white/3 overflow-hidden">
        <button onClick={() => setConfigOpen(!configOpen)}
          className="w-full flex items-center justify-between p-5 text-left hover:bg-white/3 transition">
          <span className="text-sm font-bold text-white flex items-center gap-2"><HardDrive className="h-4 w-4 text-indigo-400" /> Scan Configuration</span>
          {configOpen ? <ChevronDown className="h-4 w-4 text-slate-500" /> : <ChevronRight className="h-4 w-4 text-slate-500" />}
        </button>
        {configOpen && (
          <div className="border-t border-white/5 p-5 space-y-5">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {targets.map(t => (
                <label key={t.id} className={`group flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-all duration-200 ${selectedTargets.has(t.id) ? "border-indigo-500/30 bg-indigo-500/5" : "border-white/5 bg-black/20 opacity-60"} ${!t.exists ? "opacity-30 cursor-not-allowed" : "hover:border-indigo-500/20"}`}>
                  <input type="checkbox" checked={selectedTargets.has(t.id)} onChange={() => t.exists && toggleTarget(t.id)} disabled={!t.exists} className="mt-1 accent-indigo-500" />
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-bold text-white truncate">{t.label}</p>
                    <p className="text-[10px] text-slate-500 font-mono truncate mt-0.5">{t.resolvedPath || "N/A"}</p>
                    <div className="flex gap-1.5 mt-1.5 flex-wrap">
                      <span className={`rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase ${CRIT_COLORS[t.criticality] || CRIT_COLORS.low}`}>{t.criticality}</span>
                      {t.mitre.slice(0, 2).map(m => <span key={m} className="rounded border border-indigo-500/20 bg-indigo-500/10 px-1.5 py-0.5 text-[9px] text-indigo-300">{m}</span>)}
                    </div>
                  </div>
                </label>
              ))}
            </div>
            <div className="flex flex-wrap gap-6 items-center pt-2 border-t border-white/5">
              <label className="flex items-center gap-2 text-xs text-slate-300">
                <Monitor className="h-3.5 w-3.5 text-slate-500" /> Depth:
                <select value={maxDepth} onChange={e => setMaxDepth(Number(e.target.value))} className="bg-black/40 border border-white/10 rounded-lg px-2 py-1 text-xs text-white">
                  {[1, 2, 3, 4, 5].map(d => <option key={d} value={d}>{d}</option>)}
                </select>
              </label>
              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input type="checkbox" checked={checkSigs} onChange={e => setCheckSigs(e.target.checked)} className="accent-indigo-500" />
                {checkSigs ? <Lock className="h-3.5 w-3.5 text-emerald-400" /> : <Unlock className="h-3.5 w-3.5 text-slate-500" />} Verify Signatures
              </label>
              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input type="checkbox" checked={checkADS} onChange={e => setCheckADS(e.target.checked)} className="accent-indigo-500" />
                <Eye className="h-3.5 w-3.5 text-sky-400" /> Detect ADS
              </label>
            </div>
          </div>
        )}
      </div>

      {/* Session History */}
      {sessions.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-bold text-slate-300 flex items-center gap-2"><FileText className="h-4 w-4 text-indigo-400" /> Scan History</h3>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {sessions.slice(0, 6).map(s => (
              <button key={s.id} onClick={() => loadFindings(s.id)}
                className={`text-left p-4 rounded-2xl border transition-all duration-200 hover:-translate-y-0.5 ${viewSession === s.id ? "border-indigo-500/30 bg-indigo-500/5 ring-1 ring-indigo-500/20" : "border-white/5 bg-white/3 hover:border-white/10"}`}>
                <div className="flex justify-between items-start mb-2">
                  <span className={`rounded-lg border px-2 py-0.5 text-[10px] font-bold uppercase ${s.status === "completed" ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : s.status === "failed" ? "border-rose-500/30 bg-rose-500/10 text-rose-300" : "border-amber-500/30 bg-amber-500/10 text-amber-300"}`}>{s.status}</span>
                  <RiskBar score={Math.round(s.risk_score || 0)} />
                </div>
                <p className="text-[11px] text-slate-500 font-mono">{new Date(s.started_at).toLocaleString()}</p>
                {s.summary && (
                  <div className="flex gap-3 mt-2 text-[10px] text-slate-400">
                    <span>{s.summary.totalFiles} files</span>
                    <span className="text-rose-400">{s.summary.critical} critical</span>
                    <span className="text-amber-400">{s.summary.suspicious} suspicious</span>
                    <span>{((s.summary.duration || 0) / 1000).toFixed(1)}s</span>
                  </div>
                )}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Results */}
      {viewSession && (
        <div className="space-y-4">
          {/* Summary Stats */}
          {currentSession?.summary && (
            <div className="grid gap-4 md:grid-cols-5">
              {[
                { label: "Total Scanned", value: currentSession.summary.totalFiles, color: "sky", icon: <HardDrive className="h-5 w-5" /> },
                { label: "Critical", value: currentSession.summary.critical, color: "rose", icon: <AlertOctagon className="h-5 w-5" /> },
                { label: "Suspicious", value: currentSession.summary.suspicious, color: "amber", icon: <AlertTriangle className="h-5 w-5" /> },
                { label: "Clean", value: currentSession.summary.totalFiles - (currentSession.summary.critical + currentSession.summary.suspicious), color: "emerald", icon: <CheckCircle2 className="h-5 w-5" /> },
                { label: "Risk Score", value: currentSession.summary.avgRiskScore.toFixed(1), color: "indigo", icon: <Shield className="h-5 w-5" /> },
              ].map(s => (
                <div key={s.label} className={`p-4 rounded-2xl border border-white/5 bg-white/3 hover:bg-white/5 transition group`}>
                  <div className={`h-9 w-9 rounded-xl bg-${s.color}-500/10 flex items-center justify-center text-${s.color}-400 mb-2`}>{s.icon}</div>
                  <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">{s.label}</p>
                  <p className={`text-2xl font-black text-${s.color}-400 mt-1`}>{s.value}</p>
                </div>
              ))}
            </div>
          )}

          {/* Filters + Export */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex gap-2 items-center">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
                <input value={searchText} onChange={e => setSearchText(e.target.value)} placeholder="Search files, hashes, MITRE..."
                  className="pl-9 pr-4 py-2 rounded-xl border border-white/5 bg-black/40 text-sm text-white placeholder-slate-600 outline-none focus:border-indigo-500/40 w-64" />
              </div>
              <select value={filterStatus} onChange={e => { setFilterStatus(e.target.value); if (viewSession) loadFindings(viewSession); }}
                className="bg-black/40 border border-white/10 rounded-xl px-3 py-2 text-xs text-white">
                <option value="all">All Status</option>
                <option value="critical">Critical</option>
                <option value="suspicious">Suspicious</option>
                <option value="warning">Warning</option>
                <option value="clean">Clean</option>
              </select>
            </div>
            <div className="flex gap-2">
              {["json", "csv", "html", "stix", "splunk"].map(fmt => (
                <a key={fmt} href={`${API_BASE}/api/scanner/export/${viewSession}/${fmt}`}
                  className="flex items-center gap-1.5 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-[10px] font-bold text-slate-300 uppercase hover:bg-white/10 transition">
                  <Download className="h-3 w-3" /> {fmt}
                </a>
              ))}
            </div>
          </div>

          {/* Findings Table */}
          <div className="rounded-[2rem] border border-white/5 bg-black/20 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-white/5">
                    {[
                      { key: "risk" as const, label: "Risk" },
                      { key: "name" as const, label: "File" },
                      { key: "size" as const, label: "Size" },
                    ].map(col => (
                      <th key={col.key} onClick={() => setSortBy(col.key)}
                        className={`p-3 text-left text-[10px] font-bold uppercase tracking-wider cursor-pointer transition ${sortBy === col.key ? "text-indigo-400" : "text-slate-500 hover:text-slate-300"}`}>
                        {col.label}
                      </th>
                    ))}
                    <th className="p-3 text-left text-[10px] font-bold uppercase tracking-wider text-slate-500">Entropy</th>
                    <th className="p-3 text-left text-[10px] font-bold uppercase tracking-wider text-slate-500">Signed</th>
                    <th className="p-3 text-left text-[10px] font-bold uppercase tracking-wider text-slate-500">ADS</th>
                    <th className="p-3 text-left text-[10px] font-bold uppercase tracking-wider text-slate-500">MITRE</th>
                    <th className="p-3 text-left text-[10px] font-bold uppercase tracking-wider text-slate-500">Category</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.slice(0, 200).map(f => (
                    <tr key={f.id} className="border-b border-white/3 hover:bg-white/3 cursor-pointer transition" onClick={() => setExpandedRow(expandedRow === f.id ? null : f.id)}>
                      <td className="p-3"><RiskBar score={f.risk_score} /></td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <span className={`rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase ${STATUS_COLORS[f.status] || STATUS_COLORS.clean}`}>{f.status}</span>
                          <div className="min-w-0">
                            <p className="text-xs font-semibold text-slate-200 truncate max-w-[250px]">{f.file_name}</p>
                            <p className="text-[10px] text-slate-600 truncate max-w-[250px] font-mono">{f.file_path}</p>
                          </div>
                        </div>
                      </td>
                      <td className="p-3 text-slate-400 font-mono">{(f.file_size / 1024).toFixed(1)}K</td>
                      <td className="p-3 font-mono" style={{ color: f.entropy && f.entropy > 7 ? "#f43f5e" : f.entropy && f.entropy > 5.5 ? "#f59e0b" : "#94a3b8" }}>{f.entropy?.toFixed(2) || "-"}</td>
                      <td className="p-3">{f.is_signed ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <AlertTriangle className="h-4 w-4 text-rose-400/50" />}</td>
                      <td className="p-3">{f.has_ads ? <span className="text-rose-400 font-bold text-[10px]">ADS!</span> : <span className="text-slate-600">-</span>}</td>
                      <td className="p-3">
                        <div className="flex gap-1 flex-wrap">{f.mitre_techniques.slice(0, 2).map(t => <span key={t} className="rounded border border-indigo-500/20 bg-indigo-500/10 px-1 py-0.5 text-[9px] text-indigo-300">{t}</span>)}</div>
                      </td>
                      <td className="p-3"><span className={`rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase ${CRIT_COLORS[f.directory_criticality] || CRIT_COLORS.low}`}>{f.target_label}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {filteredFindings.length === 0 && (
              <div className="py-16 text-center text-slate-500">
                <Cpu className="h-8 w-8 mx-auto mb-3 opacity-30" />
                <p className="font-bold">No findings match current filters</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
