import { useState, useEffect, useCallback } from "react";
import { AlertTriangle, RefreshCw, Terminal, CheckCircle, Shield, Lock, Search } from "lucide-react";
import { CRITICAL_LINUX_FILES, CRITICAL_WINDOWS_FILES, ENCRYPTED_DATA_TEMPLATES, generateLinuxAuditEvent, generateWindowsFileActivity, type LinuxAuditEvent, type WindowsFileActivity, type EncryptedData } from "../data/crossPlatformMonitor";



export default function CrossPlatformFim() {
  const [activeTab, setActiveTab] = useState<"fim" | "encrypted">("fim");
  const [osTab, setOsTab] = useState<"linux" | "windows">("linux");
  const [auditLogs, setAuditLogs] = useState<LinuxAuditEvent[]>([]);
  const [winFileActivity, setWinFileActivity] = useState<WindowsFileActivity[]>([]);
  const [encryptedData, setEncryptedData] = useState<EncryptedData[]>(() => 
    ENCRYPTED_DATA_TEMPLATES.map((e, idx) => ({ ...e, id: `crypto-${idx}` }))
  );
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedLogId, setSelectedLogId] = useState<string | null>(null);
  const [selectedCryptoId, setSelectedCryptoId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  const appendLogs = useCallback(() => {
    setAuditLogs(prev => [generateLinuxAuditEvent(), ...prev].slice(0, 30));
    setWinFileActivity(prev => [generateWindowsFileActivity(), ...prev].slice(0, 30));
  }, []);

  useEffect(() => {
    // Generate initial logs
    const initLinux = Array.from({ length: 15 }, generateLinuxAuditEvent);
    const initWin = Array.from({ length: 15 }, generateWindowsFileActivity);
    setAuditLogs(initLinux);
    setWinFileActivity(initWin);
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(appendLogs, 3000);
    return () => clearInterval(interval);
  }, [autoRefresh, appendLogs]);

  const activeCrypto = encryptedData.find(e => e.id === selectedCryptoId);
  const currentLinuxLog = auditLogs.find(l => l.id === selectedLogId);
  const currentWinLog = winFileActivity.find(l => l.id === selectedLogId);

  const filteredLinuxLogs = auditLogs.filter(log => 
    !searchQuery || 
    log.rawLog.toLowerCase().includes(searchQuery.toLowerCase()) || 
    log.comm.toLowerCase().includes(searchQuery.toLowerCase()) || 
    log.auditKey.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredWinLogs = winFileActivity.filter(log => 
    !searchQuery || 
    log.targetPath.toLowerCase().includes(searchQuery.toLowerCase()) || 
    log.processName.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredCrypto = encryptedData.filter(e =>
    !searchQuery ||
    e.path?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    e.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
    e.reason.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const decryptPayload = useCallback((id: string) => {
    setEncryptedData(prev => prev.map(e => e.id === id ? {
      ...e,
      isDecrypted: true,
      decryptedContent: e.decryptedContent || "Decrypted by SOC Kernel Driver: Base64/XOR decoded. Content: [CONFIDENTIAL_DOCUMENTS, ACCESS_TOKENS, ROOT_SSH_KEYS]"
    } : e));
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Shield className="h-5 w-5 text-sky-400" />
            Cross-Platform Security Monitoring &amp; Cryptographic Analysis
          </h2>
          <p className="text-sm text-slate-400">
            Real-time Linux Auditd FIM, Windows File Event tracking, and deep cryptographic analysis for encrypted payloads.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setActiveTab("fim")}
            className={`px-4 py-2 text-sm font-semibold rounded-2xl border ${activeTab === "fim" ? "border-sky-400/30 bg-sky-400/10 text-sky-200" : "border-white/10 text-slate-400"}`}
          >
            File Integrity &amp; Syscalls (FIM)
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("encrypted")}
            className={`px-4 py-2 text-sm font-semibold rounded-2xl border ${activeTab === "encrypted" ? "border-amber-400/30 bg-amber-500/10 text-amber-200" : "border-white/10 text-slate-400"}`}
          >
            Cryptographic Payload Analyzer
          </button>
          <button
            type="button"
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-2 rounded-2xl border px-4 py-2 text-sm font-medium transition ${autoRefresh ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-200" : "border-white/10 bg-white/5 text-slate-400"}`}
          >
            <RefreshCw className={`h-4 w-4 ${autoRefresh ? "animate-spin" : ""}`} /> {autoRefresh ? "Live" : "Paused"}
          </button>
        </div>
      </div>

      {/* Global Search */}
      <div className="relative rounded-3xl border border-white/10 bg-white/5 p-4 flex items-center gap-3">
        <Search className="h-4 w-4 text-slate-400 ml-2" />
        <input 
          type="text" 
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          placeholder={activeTab === "fim" ? "Search processes, syscalls, critical paths, or raw audit logs..." : "Search hosts, ciphers, algorithms, or encrypted targets..."}
          className="flex-1 bg-transparent border-none outline-none text-sm text-white placeholder-slate-500"
        />
      </div>

      {activeTab === "fim" && (
        <div className="grid gap-6 lg:grid-cols-12">
          {/* OS Selector & Logs */}
          <div className="lg:col-span-5 flex flex-col h-[650px] space-y-4">
            <div className="flex gap-2 p-1 bg-black/40 rounded-2xl border border-white/10 w-fit">
              <button
                type="button"
                onClick={() => { setOsTab("linux"); setSelectedLogId(null); }}
                className={`px-4 py-1.5 rounded-xl text-xs font-bold font-mono uppercase transition-all ${osTab === "linux" ? "bg-white/10 text-white" : "text-slate-500 hover:text-slate-300"}`}
              >
                Linux (Auditd)
              </button>
              <button
                type="button"
                onClick={() => { setOsTab("windows"); setSelectedLogId(null); }}
                className={`px-4 py-1.5 rounded-xl text-xs font-bold font-mono uppercase transition-all ${osTab === "windows" ? "bg-white/10 text-white" : "text-slate-500 hover:text-slate-300"}`}
              >
                Windows (FIM Event)
              </button>
            </div>

            <div className="rounded-3xl border border-white/10 bg-white/5 p-4 flex-1 flex flex-col overflow-hidden">
              <div className="flex justify-between items-center mb-3">
                <h3 className="text-xs font-bold text-white uppercase tracking-widest">{osTab === "linux" ? "Auditd Syscall Stream" : "FIM Event Stream (4656/4663)"}</h3>
                <span className="text-[10px] text-slate-500 font-mono">Buffer size: 30 events</span>
              </div>

              <div className="flex-1 overflow-y-auto space-y-2 pr-1 custom-scrollbar">
                {osTab === "linux" ? (
                  filteredLinuxLogs.map(log => (
                    <button
                      key={log.id}
                      type="button"
                      onClick={() => setSelectedLogId(log.id)}
                      className={`w-full p-3 rounded-2xl border font-mono text-left text-[11px] transition-all flex items-start gap-2 ${selectedLogId === log.id ? "border-sky-400/40 bg-sky-500/10" : "border-white/10 bg-black/20 hover:border-white/20"}`}
                    >
                      <div className={`mt-1.5 h-1.5 w-1.5 rounded-full shrink-0 ${log.suspicious ? "bg-rose-400 animate-pulse" : "bg-sky-400"}`} />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap gap-1 items-center text-[10px] mb-1">
                          <span className="text-sky-300 font-bold">{log.host}</span>
                          <span className="text-slate-500">·</span>
                          <span className="text-purple-300 font-bold">{log.syscall}</span>
                          <span className="text-slate-500">·</span>
                          <span className="text-amber-300">k:{log.auditKey}</span>
                        </div>
                        <p className="text-slate-300 truncate font-semibold">exe: {log.exe} (pid:{log.pid})</p>
                        <p className="text-slate-500 truncate mt-0.5">{log.rawLog.slice(0, 80)}...</p>
                      </div>
                    </button>
                  ))
                ) : (
                  filteredWinLogs.map(log => (
                    <button
                      key={log.id}
                      type="button"
                      onClick={() => setSelectedLogId(log.id)}
                      className={`w-full p-3 rounded-2xl border font-mono text-left text-[11px] transition-all flex items-start gap-2 ${selectedLogId === log.id ? "border-sky-400/40 bg-sky-500/10" : "border-white/10 bg-black/20 hover:border-white/20"}`}
                    >
                      <div className={`mt-1.5 h-1.5 w-1.5 rounded-full shrink-0 ${log.suspicious ? "bg-rose-400 animate-pulse" : "bg-sky-400"}`} />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap gap-1 items-center text-[10px] mb-1">
                          <span className="text-sky-300 font-bold">{log.host}</span>
                          <span className="text-slate-500">·</span>
                          <span className="text-amber-300 font-bold">Event:{log.eventId}</span>
                          <span className="text-slate-500">·</span>
                          <span className="text-purple-300">p:{log.processName}</span>
                        </div>
                        <p className="text-slate-300 truncate font-semibold">Target: {log.targetPath.split("\\").pop()}</p>
                        <p className="text-slate-500 truncate mt-0.5">Mask: {log.accessMask} · Account: {log.userAccount}</p>
                      </div>
                    </button>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Details Panel */}
          <div className="lg:col-span-4 rounded-3xl border border-white/10 bg-white/5 p-5 h-[650px] overflow-y-auto custom-scrollbar">
            {osTab === "linux" && currentLinuxLog ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-white/10 pb-2">
                  <span className="text-xs font-bold text-sky-400 font-mono">Linux Auditd Event</span>
                  <span className="text-[10px] font-mono text-slate-500">TIMESTAMP: {currentLinuxLog.timestamp}</span>
                </div>

                <div className="rounded-2xl border border-rose-500/20 bg-rose-500/5 p-3">
                  <div className="flex items-center gap-2 text-rose-300 font-bold text-xs">
                    <AlertTriangle className="h-4 w-4" /> Threat: {currentLinuxLog.threatCategory}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">Auditd Key: <span className="font-mono text-white">{currentLinuxLog.auditKey}</span></p>
                  <p className="text-xs text-slate-400">MITRE Technique: <span className="font-mono text-rose-300">{currentLinuxLog.mitreTechnique}</span></p>
                </div>

                <div className="rounded-2xl border border-white/10 bg-black/30 p-4 space-y-2 text-xs font-mono">
                  <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest font-sans mb-1">Process Context</h4>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Process Name (comm)</span><span className="text-white font-semibold">{currentLinuxLog.comm}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Executable Path</span><span className="text-sky-300 truncate max-w-[200px]">{currentLinuxLog.exe}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Syscall</span><span className="text-purple-300 font-bold">{currentLinuxLog.syscall}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">PID / PPID</span><span className="text-slate-300">{currentLinuxLog.pid} / {currentLinuxLog.ppid}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">UID / GID</span><span className="text-slate-300">{currentLinuxLog.uid} / {currentLinuxLog.gid}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Audit UID (auid)</span><span className="text-amber-300">{currentLinuxLog.auid} (orig login)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Success Status</span>
                    <span className={currentLinuxLog.success === "yes" ? "text-emerald-400" : "text-rose-400"}>{currentLinuxLog.success.toUpperCase()}</span>
                  </div>
                </div>

                <div className="rounded-2xl border border-white/10 bg-black/30 p-4">
                  <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest font-sans mb-2">Syscall Arguments</h4>
                  <div className="space-y-1.5 font-mono text-[11px]">
                    {Object.entries(currentLinuxLog.arguments).map(([k, v]) => (
                      <div key={k} className="flex flex-col border-b border-white/5 pb-1">
                        <span className="text-slate-500 text-[10px]">{k}</span>
                        <span className="text-slate-300 break-all">{v}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="rounded-2xl border border-white/10 bg-black/40 p-4">
                  <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest font-sans mb-2">Raw Auditd Log Entry</h4>
                  <pre className="text-[10px] font-mono text-slate-400 overflow-auto whitespace-pre-wrap max-h-40 bg-black/50 p-2 rounded-xl border border-white/5">
                    {currentLinuxLog.rawLog}
                  </pre>
                </div>
              </div>
            ) : osTab === "windows" && currentWinLog ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-white/10 pb-2">
                  <span className="text-xs font-bold text-sky-400 font-mono">Windows FIM Security Log</span>
                  <span className="text-[10px] font-mono text-slate-500">EVENT_ID: {currentWinLog.eventId}</span>
                </div>

                <div className="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-3">
                  <div className="flex items-center gap-2 text-amber-300 font-bold text-xs">
                    <AlertTriangle className="h-4 w-4" /> File Object Handle Requested
                  </div>
                  <p className="text-xs text-slate-400 mt-1">MITRE Technique: <span className="font-mono text-rose-300">{currentWinLog.mitreTechnique}</span></p>
                  <p className="text-xs text-slate-400">Access Mask Requested: <span className="font-mono text-white">{currentWinLog.accessMask}</span></p>
                </div>

                <div className="rounded-2xl border border-white/10 bg-black/30 p-4 space-y-2 text-xs font-mono">
                  <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest font-sans mb-1">Event Context</h4>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Source Process</span><span className="text-white font-semibold">{currentWinLog.processName}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Process ID</span><span className="text-slate-300">{currentWinLog.processId}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Subject Account</span><span className="text-sky-300 font-bold">{currentWinLog.userAccount}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Audit Status</span>
                    <span className={currentWinLog.status === "success" ? "text-emerald-400" : "text-rose-400"}>{currentWinLog.status.toUpperCase()}</span>
                  </div>
                </div>

                <div className="rounded-2xl border border-white/10 bg-black/30 p-4">
                  <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest font-sans mb-2">Target Path</h4>
                  <p className="font-mono text-xs text-amber-200 break-all p-2 bg-black/50 rounded-xl border border-white/5">
                    {currentWinLog.targetPath}
                  </p>
                </div>

                <div className="rounded-2xl border border-white/10 bg-black/40 p-4">
                  <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest font-sans mb-2">Security Audit XML (Subset)</h4>
                  <pre className="text-[10px] font-mono text-slate-400 overflow-auto whitespace-pre-wrap max-h-40 bg-black/50 p-2 rounded-xl border border-white/5">
                    {`
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>${currentWinLog.eventId}</EventID>
    <Computer>${currentWinLog.host}</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">${currentWinLog.userAccount}</Data>
    <Data Name="ObjectName">${currentWinLog.targetPath}</Data>
    <Data Name="AccessMask">${currentWinLog.accessMask}</Data>
    <Data Name="ProcessName">${currentWinLog.processName}</Data>
  </EventData>
</Event>
                    `}
                  </pre>
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 font-mono text-xs">
                <Terminal className="h-10 w-10 text-slate-600 mb-2" />
                <p>Select a log to parse low-level OS event structures.</p>
              </div>
            )}
          </div>

          {/* Critical Files FIM Reference */}
          <div className="lg:col-span-3 rounded-3xl border border-white/10 bg-white/5 p-4 h-[650px] flex flex-col">
            <h3 className="text-xs font-bold text-white uppercase tracking-widest mb-3">{osTab === "linux" ? "Linux Critical File Watches" : "Windows FIM Target Policies"}</h3>
            <div className="flex-1 overflow-y-auto space-y-1.5 font-mono text-[10px] pr-1 custom-scrollbar">
              {(osTab === "linux" ? CRITICAL_LINUX_FILES : CRITICAL_WINDOWS_FILES).map((path, idx) => (
                <div key={idx} className="p-2 rounded border border-white/5 bg-black/20 text-slate-400 break-all flex items-start gap-1">
                  <span className="text-sky-400">📄</span>
                  <span>{path}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === "encrypted" && (
        <div className="grid gap-6 lg:grid-cols-12">
          {/* Crypto Entities */}
          <div className="lg:col-span-6 rounded-3xl border border-white/10 bg-white/5 p-5 h-[600px] flex flex-col">
            <h3 className="text-sm font-bold text-white mb-4">Cryptographic Payload Feed</h3>
            <div className="flex-1 overflow-y-auto space-y-3 pr-1 custom-scrollbar">
              {filteredCrypto.map(e => (
                <div
                  key={e.id}
                  onClick={() => setSelectedCryptoId(e.id)}
                  className={`p-4 rounded-2xl border cursor-pointer transition-all flex items-start gap-4 ${selectedCryptoId === e.id ? "border-amber-400/40 bg-amber-500/10" : "border-white/10 bg-black/30 hover:border-white/20"}`}
                >
                  <div className={`p-3 rounded-xl bg-black/40 border border-white/10 ${e.suspicious ? "text-rose-400" : "text-sky-400"}`}>
                    <Lock className="h-5 w-5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className="text-xs font-bold text-white">{e.host}</span>
                      <span className="text-xs text-slate-500 uppercase">[{e.type}]</span>
                      <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ${e.suspicious ? "border-rose-500/30 bg-rose-500/10 text-rose-300 animate-pulse" : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"}`}>
                        {e.suspicious ? "MALICIOUS CRYPTO" : "SECURE BASELINE"}
                      </span>
                    </div>
                    <p className="font-mono text-xs text-slate-300 truncate mb-1">{e.path || "Encrypted Connection"}</p>
                    <p className="text-xs text-slate-400 leading-relaxed">{e.reason}</p>
                    <div className="flex flex-wrap gap-x-3 mt-2 text-[10px] text-slate-500 font-mono">
                      <span>Cipher: <span className="text-slate-300">{e.algorithm}</span></span>
                      <span>Entropy: <span className="text-amber-300">{e.entropy.toFixed(2)} / 8.00</span></span>
                      {e.isDecrypted && <span className="text-emerald-400 font-bold">✓ DECRYPTED</span>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Crypto Deep Dive */}
          <div className="lg:col-span-6 rounded-3xl border border-white/10 bg-white/5 p-5 h-[600px] overflow-y-auto custom-scrollbar">
            {activeCrypto ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-white/10 pb-2">
                  <h3 className="text-sm font-bold text-white">Cryptographic Payload Deep-Dive</h3>
                  <span className={`rounded-full border px-2.5 py-1 text-xs font-medium uppercase ${activeCrypto.classification === "top_secret" ? "border-rose-500/30 bg-rose-500/10 text-rose-200 animate-pulse" : activeCrypto.classification === "secret" ? "border-orange-400/30 bg-orange-500/10 text-orange-200" : "border-sky-400/30 bg-sky-500/10 text-sky-200"}`}>
                    {activeCrypto.classification.replace("_", " ")}
                  </span>
                </div>

                <div className="grid gap-3 sm:grid-cols-2 text-xs font-mono">
                  <div className="rounded-xl border border-white/10 bg-black/30 p-3">
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest font-sans mb-1">Algorithm Metrics</p>
                    <div className="space-y-1">
                      <div className="flex justify-between"><span className="text-slate-500">Cipher</span><span className="text-white font-semibold">{activeCrypto.algorithm}</span></div>
                      <div className="flex justify-between"><span className="text-slate-500">Key Size</span><span className="text-white">{activeCrypto.keySize} bits</span></div>
                      <div className="flex justify-between"><span className="text-slate-500">Payload Entropy</span><span className="text-amber-400 font-bold">{activeCrypto.entropy.toFixed(3)}</span></div>
                      <div className="flex justify-between"><span className="text-slate-500">Original Size</span><span className="text-slate-300">{(activeCrypto.originalSize / 1024).toFixed(1)} KB</span></div>
                    </div>
                  </div>
                  
                  <div className="rounded-xl border border-white/10 bg-black/30 p-3 flex flex-col justify-center text-center">
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest font-sans mb-2">Entropy Visualization</p>
                    <div className="h-6 rounded-full bg-white/5 border border-white/5 relative overflow-hidden">
                      <div className={`h-full rounded-full ${activeCrypto.entropy > 7.0 ? "bg-rose-500 animate-pulse" : "bg-emerald-500"}`} style={{ width: `${(activeCrypto.entropy / 8) * 100}%` }} />
                      <span className="absolute inset-0 flex items-center justify-center font-bold text-[10px] text-white drop-shadow">
                        {((activeCrypto.entropy / 8) * 100).toFixed(1)}% (RANDOMNESS)
                      </span>
                    </div>
                    <p className="text-[9px] text-slate-500 mt-2">Entropy &gt; 7.0 indicates high-density encryption or compression.</p>
                  </div>
                </div>

                {activeCrypto.mitreTechnique && (
                  <div className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-3 flex items-center gap-3">
                    <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0" />
                    <div>
                      <p className="text-xs font-bold text-white">MITRE Technique Mapping</p>
                      <p className="text-xs text-slate-400">The payload usage correlates with <span className="text-rose-300 font-mono font-semibold">{activeCrypto.mitreTechnique}</span> (Encrypted Channel / Data Compression).</p>
                    </div>
                  </div>
                )}

                {activeCrypto.iocs && activeCrypto.iocs.length > 0 && (
                  <div className="rounded-xl border border-white/10 bg-black/30 p-3">
                    <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest font-sans mb-2">Extracted Indicators of Compromise (IOCs)</h4>
                    <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                      {activeCrypto.iocs.map(ioc => (
                        <span key={ioc} className="rounded border border-rose-500/20 bg-rose-500/10 px-2 py-0.5 text-rose-300">{ioc}</span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="rounded-xl border border-white/10 bg-black/40 p-4 flex-1 flex flex-col">
                  <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-2">
                    <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest font-sans">Payload Inspection</h4>
                    {activeCrypto.suspicious && (
                      <button
                        type="button"
                        onClick={() => decryptPayload(activeCrypto.id)}
                        disabled={activeCrypto.isDecrypted}
                        className="flex items-center gap-1 text-[10px] font-semibold rounded-xl border border-emerald-400/30 bg-emerald-500/10 px-3 py-1 text-emerald-200 hover:bg-emerald-500/20 disabled:opacity-50"
                      >
                        <Lock className="h-3 w-3" /> {activeCrypto.isDecrypted ? "Decrypted" : "Attempt Decryption"}
                      </button>
                    )}
                  </div>

                  <div className="flex-1 bg-black/50 p-3 rounded-xl border border-white/5 font-mono text-[11px] overflow-auto max-h-56">
                    <p className="text-slate-500 mb-1">// Raw Hex / Ciphertext Stream (Entropy: {activeCrypto.entropy.toFixed(2)})</p>
                    <pre className="text-slate-400 whitespace-pre-wrap break-all">
                      {`00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000  MZ..............
00000010: b800 0000 0000 0000 4000 0000 0000 0000  ........@.......
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 f800 0000 0e1f ba0e 00b4 09cd  ................
00000040: 21b8 014c cd21 5468 6973 2070 726f 6772  !..L.!This progr
00000050: 616d 2063 616e 6e6f 7420 6265 2072 756e  am cannot be run
00000060: 2069 6e20 444f 5320 6d6f 6465 2e0d 0d0a   in DOS mode....`}
                    </pre>

                    {activeCrypto.isDecrypted && (
                      <div className="mt-4 pt-4 border-t border-white/10">
                        <p className="text-emerald-400 font-bold flex items-center gap-1 mb-1">
                          <CheckCircle className="h-3.5 w-3.5" /> Decrypted Content (SOC Kernel Driver Integration)
                        </p>
                        <pre className="text-emerald-300 whitespace-pre-wrap p-2 bg-emerald-500/5 rounded-xl border border-emerald-500/20">
                          {activeCrypto.decryptedContent}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 font-mono text-xs">
                <Lock className="h-10 w-10 text-slate-600 mb-2" />
                <p>Select an encrypted payload to run cryptographic entropy &amp; decryption analysis.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}


