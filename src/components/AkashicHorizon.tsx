import { useState } from "react";
import { Globe, FileCode, Database, Trash2 } from "lucide-react";

export default function AkashicHorizon() {
  // File states
  const [fileDetails, setFileDetails] = useState<{
    name: string;
    size: string;
    hash: string;
    signature: string;
    risk: "safe" | "warning" | "malicious";
  } | null>(null);
  const [fileLoading, setFileLoading] = useState(false);

  // URL States
  const [urlInput, setUrlInput] = useState("");
  const [urlResult, setUrlResult] = useState<{
    url: string;
    reputation: string;
    vtScore: string;
    ipOwner: string;
    status: "clean" | "suspicious" | "malicious";
  } | null>(null);
  const [urlLoading, setUrlLoading] = useState(false);

  // Local storage telemetry mock
  const [storageItems, setStorageItems] = useState([
    { key: "sentinel_session_jti", val: "a3f89e21-0012-bcd8", origin: "Session Storage", integrity: "secure" },
    { key: "threat_recon_cache", val: "3 hits active", origin: "Local Storage", integrity: "secure" },
    { key: "totp_enrollment_state", val: "1 (bound)", origin: "IndexedDB config", integrity: "secure" },
    { key: "temp_reputation_cookie", val: "vt_checked_ok", origin: "Cookie Jar", integrity: "secure" }
  ]);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileLoading(true);
    setFileDetails(null);

    // Simulate hashing and telemetry carving
    setTimeout(() => {
      // Mock SHA-256 hashes based on file type
      const isExe = file.name.endsWith(".exe") || file.name.endsWith(".ps1") || file.name.endsWith(".bat");
      const mockHash = Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
      
      setFileDetails({
        name: file.name,
        size: `${(file.size / 1024).toFixed(2)} KB`,
        hash: mockHash,
        signature: isExe ? "Unverified Publisher (Suspicious PE headers)" : "Validated Microsoft Authenticode Signature",
        risk: isExe ? "malicious" : "safe"
      });
      setFileLoading(false);
    }, 1200);
  };

  const handleUrlScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) return;

    setUrlLoading(true);
    setUrlResult(null);

    setTimeout(() => {
      const lowerUrl = urlInput.toLowerCase();
      let status: "clean" | "suspicious" | "malicious" = "clean";
      let reputation = "Unrated / Safe Domain";
      let vtScore = "0 / 92 engines flagged";
      let ipOwner = "Cloudflare Global DNS IP Network";

      if (lowerUrl.includes("malicious") || lowerUrl.includes("c2") || lowerUrl.includes("185.220.")) {
        status = "malicious";
        reputation = "Known Command-and-Control Server (C2) / Active Threat";
        vtScore = "74 / 92 engines flagged";
        ipOwner = "M247 Ltd (Tor Exit Subnet / Host)";
      } else if (lowerUrl.includes("github") || lowerUrl.includes("google")) {
        reputation = "High Reputation Core Whitelisted Site";
        vtScore = "0 / 92 engines flagged";
        ipOwner = "Google LLC / Github Systems Inc";
      } else {
        status = "suspicious";
        reputation = "Newly Registered Domain (NRD) / Missing SSL flags";
        vtScore = "4 / 92 engines flagged";
        ipOwner = "NameCheap Hosting Networks";
      }

      setUrlResult({
        url: urlInput,
        reputation,
        vtScore,
        ipOwner,
        status
      });
      setUrlLoading(false);
    }, 1000);
  };

  const deleteStorageItem = (keyToDelete: string) => {
    setStorageItems(prev => prev.filter(item => item.key !== keyToDelete));
  };

  return (
    <div className="flex flex-col h-full bg-slate-950/70 border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-300 glass-panel">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-cyan-400" />
          <span className="text-xs font-black uppercase tracking-wider text-slate-200">Segment Y: Akashic Horizon</span>
        </div>
        <span className="text-[10px] text-slate-500 uppercase">Integrity Monitor</span>
      </div>

      <div className="flex-1 space-y-4 overflow-y-auto pr-1">
        
        {/* File Analyzer Card */}
        <div className="border border-slate-800 bg-slate-950/40 rounded-lg p-3 space-y-3">
          <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1.5 border-b border-slate-900 pb-1.5">
            <FileCode className="h-3.5 w-3.5 text-cyan-400" />
            Volatile File threat analyzer
          </div>

          <label className="flex flex-col items-center justify-center border border-dashed border-slate-800 bg-slate-950 hover:bg-slate-950/90 rounded-lg h-20 cursor-pointer transition-colors text-center p-2">
            <input type="file" onChange={handleFileUpload} className="hidden" />
            <span className="text-[10px] text-slate-400">Click to upload files for sandboxed analysis</span>
            <span className="text-[8px] text-slate-600 mt-1">Carves headers & SHA-256 instantly</span>
          </label>

          {fileLoading && (
            <div className="text-[10px] text-cyan-400 animate-pulse text-center py-2">
              Calculating hash and validating digital signatures...
            </div>
          )}

          {fileDetails && (
            <div className="bg-black/40 border border-slate-850 p-2.5 rounded space-y-1.5">
              <div className="flex justify-between items-center">
                <span className="text-slate-300 font-bold truncate pr-3">{fileDetails.name}</span>
                <span className={`text-[8px] uppercase font-bold px-1.5 py-0.5 rounded border ${
                  fileDetails.risk === 'malicious'
                    ? 'border-rose-500/30 bg-rose-500/10 text-rose-300'
                    : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                }`}>
                  {fileDetails.risk}
                </span>
              </div>
              <div className="text-[9px] text-slate-500 break-all select-all font-mono">SHA-256: {fileDetails.hash}</div>
              <div className="text-[9px] text-slate-400">Size: {fileDetails.size}</div>
              <div className="text-[9px] text-slate-500">{fileDetails.signature}</div>
            </div>
          )}
        </div>

        {/* Reputation URL Link Analyzer */}
        <div className="border border-slate-800 bg-slate-950/40 rounded-lg p-3 space-y-3">
          <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1.5 border-b border-slate-900 pb-1.5">
            <Globe className="h-3.5 w-3.5 text-cyan-400" />
            Malicious Link Reputation Checker
          </div>

          <form onSubmit={handleUrlScan} className="flex gap-2">
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter suspect URL (e.g. http://185.220...)"
              className="flex-1 h-8 rounded bg-slate-950 border border-slate-800 px-2 text-[10px] text-white focus:outline-none focus:border-cyan-400 placeholder:text-slate-700"
            />
            <button
              type="submit"
              disabled={urlLoading}
              className="h-8 px-3 rounded bg-cyan-600/30 border border-cyan-500/40 hover:bg-cyan-600/50 text-cyan-300 text-[10px] uppercase font-bold"
            >
              Scan
            </button>
          </form>

          {urlLoading && (
            <div className="text-[10px] text-cyan-400 animate-pulse text-center py-1">
              Querying central reputation server...
            </div>
          )}

          {urlResult && (
            <div className="bg-black/40 border border-slate-850 p-2.5 rounded space-y-1.5">
              <div className="flex justify-between items-center">
                <span className="text-[9px] text-slate-300 font-bold truncate pr-3">{urlResult.url}</span>
                <span className={`text-[8px] uppercase font-bold px-1.5 py-0.5 rounded border ${
                  urlResult.status === 'malicious'
                    ? 'border-rose-500/30 bg-rose-500/10 text-rose-300'
                    : urlResult.status === 'suspicious'
                      ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                      : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                }`}>
                  {urlResult.status}
                </span>
              </div>
              <div className="text-[9px] text-slate-400">{urlResult.reputation}</div>
              <div className="text-[9px] text-slate-500">Volatile Scan: {urlResult.vtScore}</div>
              <div className="text-[9px] text-slate-600 font-mono">Netblock: {urlResult.ipOwner}</div>
            </div>
          )}
        </div>

        {/* Local Storage Inspector */}
        <div className="border border-slate-800 bg-slate-950/40 rounded-lg p-3 space-y-2">
          <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1.5 border-b border-slate-900 pb-1.5">
            <Database className="h-3.5 w-3.5 text-cyan-400" />
            Client Storage & Cookie Monitors
          </div>

          <ul className="space-y-1.5">
            {storageItems.map((item) => (
              <li key={item.key} className="flex justify-between items-center bg-black/20 p-2 rounded border border-slate-900 text-[10px]">
                <div className="flex flex-col min-w-0 pr-3">
                  <span className="text-slate-300 font-bold font-mono">{item.key}</span>
                  <span className="text-slate-500 text-[8px] truncate mt-0.5">{item.val}</span>
                  <span className="text-slate-600 text-[7px] mt-0.5">{item.origin} · {item.integrity}</span>
                </div>
                <button
                  onClick={() => deleteStorageItem(item.key)}
                  className="text-rose-400 hover:text-rose-300 p-1 hover:bg-rose-950/20 rounded transition-colors"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </li>
            ))}
          </ul>
        </div>

      </div>
    </div>
  );
}
