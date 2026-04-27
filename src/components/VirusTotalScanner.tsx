import { useState, useCallback } from "react";
import { MALWARE_SIGNATURES, LIVE_IOCS, type MalwareSignature, type IOC } from "../data/threatEngine";
import { Search, Shield, AlertTriangle, CheckCircle, ExternalLink, Clock, Hash, Globe, Mail } from "lucide-react";

type ScanResult = {
  query: string;
  type: "hash" | "ip" | "domain" | "url" | "email" | "unknown";
  found: boolean;
  malware?: MalwareSignature;
  ioc?: IOC;
  vtDetections?: number;
  vtTotal?: number;
  reputation?: number;
  categories?: string[];
  scanTime: number;
  verdict: "malicious" | "suspicious" | "clean" | "unknown";
  engines: Array<{ name: string; result: string | null; detected: boolean }>;
};

const KNOWN_CLEAN = [
  "8.8.8.8", "1.1.1.1", "google.com", "microsoft.com", "github.com",
  "d41d8cd98f00b204e9800998ecf8427e", "0"
];

const MOCK_ENGINES = [
  "Kaspersky", "Symantec", "Malwarebytes", "ESET-NOD32", "Sophos", "CrowdStrike Falcon",
  "Microsoft Defender", "Bitdefender", "McAfee", "Trend Micro", "Avast", "AVG",
  "F-Secure", "Emsisoft", "DrWeb", "Cylance", "SentinelOne", "Panda", "NANO-Antivirus", "Fortinet",
  "VBA32", "K7AntiVirus", "Ikarus", "Alibaba", "AhnLab-V3", "Avira", "Rising", "Baidu",
  "ZoneAlarm", "TrendMicro-HouseCall", "Comodo", "ByteHero", "CAT-QuickHeal", "Ad-Aware", "Jiangmin",
  "CMC", "Zillya", "SUPERAntiSpyware", "Antiy-AVL", "Tencent",
  "ViRobot", "MAX", "Yandex", "ALYac", "TheHacker", "APEX", "Arcabit", "ClamAV", "Invincea",
  "TotalDefense", "GData", "VIPRE", "K7GW", "MicroWorld-eScan", "Kingsoft", "Gridinsoft",
  "Cynet", "QuickHeal", "Zoner", "eGambit", "TalosSecurity", "Webroot", "Cylance", "Cybereason",
  "DeepInstinct", "BlackBerry", "Carbon Black", "Elastic", "Palo Alto WildFire", "Recorded Future",
  "ReversingLabs", "Lastline", "CrowdStrike"
];

function detectQueryType(q: string): ScanResult["type"] {
  const clean = q.trim();
  if (/^[a-f0-9]{32}$/i.test(clean)) return "hash";  // MD5
  if (/^[a-f0-9]{40}$/i.test(clean)) return "hash";  // SHA1
  if (/^[a-f0-9]{64}$/i.test(clean)) return "hash";  // SHA256
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(clean)) return "ip";
  if (/^https?:\/\//i.test(clean)) return "url";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) return "email";
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(clean)) return "domain";
  return "unknown";
}

function buildEngineResults(detected: number, total: number, malwareName?: string): ScanResult["engines"] {
  const shuffled = [...MOCK_ENGINES].sort(() => Math.random() - 0.5).slice(0, total);
  return shuffled.map((name, i) => ({
    name,
    detected: i < detected,
    result: i < detected ? (malwareName ?? "Generic.Malware") : null,
  }));
}

function scanQuery(query: string): ScanResult {
  const type = detectQueryType(query);
  const lower = query.toLowerCase().trim();
  const isClean = KNOWN_CLEAN.some(c => lower.includes(c.toLowerCase()));
  const scanTime = 800 + Math.floor(Math.random() * 2400);

  if (isClean) {
    return {
      query, type, found: false, verdict: "clean", scanTime,
      vtDetections: 0, vtTotal: 72, reputation: 85,
      categories: ["Safe", "Known good"],
      engines: buildEngineResults(0, 72),
    };
  }

  // Check against known malware hashes
  const malwareMatch = MALWARE_SIGNATURES.find(m =>
    lower === m.md5.toLowerCase() ||
    lower === m.sha256.toLowerCase() ||
    lower === m.sha1.toLowerCase() ||
    lower.includes(m.family.toLowerCase())
  );

  if (malwareMatch) {
    return {
      query, type, found: true, malware: malwareMatch,
      verdict: "malicious", scanTime,
      vtDetections: malwareMatch.vtDetections,
      vtTotal: malwareMatch.vtTotal,
      vtRatio: malwareMatch.vtRatio,
      reputation: -90,
      categories: [malwareMatch.type, malwareMatch.family],
      engines: buildEngineResults(malwareMatch.vtDetections, malwareMatch.vtTotal, malwareMatch.name),
    } as ScanResult;
  }

  // Check against IOCs
  const iocMatch = LIVE_IOCS.find(ioc =>
    lower === ioc.value.toLowerCase() ||
    lower.replace(/\[|\]/g, "") === ioc.value.replace(/\[|\]/g, "").toLowerCase()
  );

  if (iocMatch) {
    const detections = Math.round(iocMatch.confidence * 0.6);
    return {
      query, type, found: true, ioc: iocMatch,
      verdict: iocMatch.severity === "critical" || iocMatch.severity === "high" ? "malicious" : "suspicious",
      scanTime, vtDetections: detections, vtTotal: 72,
      reputation: -iocMatch.confidence,
      categories: iocMatch.tags,
      engines: buildEngineResults(detections, 72, iocMatch.malwareFamily),
    };
  }

  // Heuristic – suspicious patterns
  const suspiciousTerms = ["exe", "payload", "miner", "xmr", "darkweb", "185.220", "91.223", "update-microsoft", "winupdate"];
  const isSuspicious = suspiciousTerms.some(t => lower.includes(t));

  if (isSuspicious) {
    const detections = 12 + Math.floor(Math.random() * 25);
    return {
      query, type, found: true, verdict: "suspicious", scanTime,
      vtDetections: detections, vtTotal: 72,
      reputation: -30,
      categories: ["Suspicious", "Heuristic"],
      engines: buildEngineResults(detections, 72, "Heuristic.Suspicious"),
    };
  }

  // Unknown
  return {
    query, type, found: false, verdict: "unknown", scanTime,
    vtDetections: 0, vtTotal: 72,
    reputation: 0,
    categories: ["Unclassified"],
    engines: buildEngineResults(0, 72),
  };
}

const verdictStyle: Record<string, string> = {
  malicious: "border-rose-500/30 bg-rose-500/10 text-rose-200",
  suspicious: "border-amber-400/30 bg-amber-500/10 text-amber-200",
  clean: "border-emerald-400/30 bg-emerald-500/10 text-emerald-200",
  unknown: "border-white/10 bg-white/5 text-slate-400",
};

const verdictIcon: Record<string, React.ReactNode> = {
  malicious: <AlertTriangle className="h-6 w-6 text-rose-400" />,
  suspicious: <AlertTriangle className="h-6 w-6 text-amber-400" />,
  clean: <CheckCircle className="h-6 w-6 text-emerald-400" />,
  unknown: <Shield className="h-6 w-6 text-slate-400" />,
};

const typeIcon: Record<string, React.ReactNode> = {
  hash: <Hash className="h-4 w-4 text-slate-400" />,
  ip: <Globe className="h-4 w-4 text-slate-400" />,
  domain: <Globe className="h-4 w-4 text-slate-400" />,
  url: <ExternalLink className="h-4 w-4 text-slate-400" />,
  email: <Mail className="h-4 w-4 text-slate-400" />,
  unknown: <Search className="h-4 w-4 text-slate-400" />,
};

const QUICK_SAMPLES = [
  { label: "Mimikatz MD5", value: "e4b60e87e1d3a520a8e8b8d66c7d0ade" },
  { label: "C2 Server IP", value: "185.220.101.47" },
  { label: "Phishing Domain", value: "update-microsoft-sync[.]com" },
  { label: "LockBit SHA256", value: "e1f3a5b7c9d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4" },
  { label: "Clean Domain", value: "google.com" },
  { label: "Phishing Email", value: "invoice-urgent@secureupd8.ru" },
];

export default function VirusTotalScanner() {
  const [query, setQuery] = useState("");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [showAllEngines, setShowAllEngines] = useState(false);

  const runScan = useCallback((q: string) => {
    if (!q.trim()) return;
    setScanning(true);
    setProgress(0);
    setResult(null);
    setShowAllEngines(false);

    let p = 0;
    const timer = setInterval(() => {
      p += 4 + Math.random() * 8;
      setProgress(Math.min(p, 95));
      if (p >= 95) clearInterval(timer);
    }, 80);

    setTimeout(() => {
      clearInterval(timer);
      setProgress(100);
      const r = scanQuery(q.trim());
      setResult(r);
      setHistory(prev => [r, ...prev].slice(0, 8));
      setTimeout(() => setScanning(false), 200);
    }, 1800 + Math.random() * 1200);
  }, []);

  const detectedEngines = result?.engines.filter(e => e.detected) ?? [];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <img
          src="https://www.virustotal.com/gui/images/favicon.png"
          alt="VT"
          className="h-8 w-8 rounded-lg"
          onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
        />
        <div>
          <h2 className="text-xl font-bold text-white">VirusTotal Intelligence Scanner</h2>
          <p className="text-sm text-slate-400">
            Scan IPs, domains, URLs, file hashes, and emails against 70+ AV engines and threat intel feeds
          </p>
        </div>
      </div>

      {/* Input */}
      <div className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur-xl">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === "Enter" && runScan(query)}
              placeholder="Enter IP, domain, URL, file hash (MD5/SHA1/SHA256), or email address..."
              className="w-full rounded-2xl border border-white/10 bg-black/30 py-3 pl-11 pr-4 text-sm text-white placeholder-slate-500 outline-none focus:border-sky-500/50 focus:ring-1 focus:ring-sky-500/20 transition"
            />
          </div>
          <button
            type="button"
            disabled={scanning || !query.trim()}
            onClick={() => runScan(query)}
            className="shrink-0 rounded-2xl border border-sky-400/30 bg-sky-500/10 px-6 py-3 text-sm font-semibold text-sky-200 transition hover:bg-sky-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {scanning ? "Scanning…" : "Analyze"}
          </button>
        </div>

        {/* Progress */}
        {scanning && (
          <div className="mt-4">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span>Querying {Math.round(progress * 0.72)} / 72 engines…</span>
              <span>{Math.round(progress)}%</span>
            </div>
            <div className="h-2 rounded-full bg-white/5 overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-sky-500 to-emerald-400 transition-all duration-150"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

        {/* Quick samples */}
        <div className="mt-4">
          <p className="text-xs text-slate-500 mb-2">Quick samples:</p>
          <div className="flex flex-wrap gap-2">
            {QUICK_SAMPLES.map(s => (
              <button
                key={s.value}
                type="button"
                onClick={() => { setQuery(s.value); runScan(s.value); }}
                className="rounded-xl border border-white/10 bg-black/20 px-3 py-1.5 text-xs text-slate-300 hover:border-sky-400/30 hover:text-sky-300 transition"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Result */}
      {result && !scanning && (
        <div className="space-y-5">
          {/* Verdict header */}
          <div className={`rounded-3xl border p-6 ${verdictStyle[result.verdict]}`}>
            <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
              <div className="flex items-start gap-4">
                <div className="p-3 rounded-2xl border border-white/10 bg-black/20">
                  {verdictIcon[result.verdict]}
                </div>
                <div>
                  <div className="flex flex-wrap items-center gap-2 mb-1">
                    {typeIcon[result.type]}
                    <span className="text-xs text-slate-400 uppercase tracking-widest">{result.type}</span>
                    <span className={`rounded-full border px-2.5 py-1 text-xs font-bold uppercase tracking-wide ${verdictStyle[result.verdict]}`}>
                      {result.verdict}
                    </span>
                  </div>
                  <p className="font-mono text-sm text-white break-all">{result.query}</p>
                  {result.categories && (
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {result.categories.map(c => (
                        <span key={c} className="rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-xs text-slate-300">{c}</span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
              <div className="text-right space-y-2">
                <div>
                  <p className={`text-4xl font-black ${result.verdict === "malicious" ? "text-rose-300" : result.verdict === "suspicious" ? "text-amber-300" : "text-emerald-300"}`}>
                    {result.vtDetections}/{result.vtTotal}
                  </p>
                  <p className="text-sm text-slate-400">engine detections</p>
                </div>
                <div className="flex items-center gap-2 justify-end text-xs text-slate-500">
                  <Clock className="h-3.5 w-3.5" />
                  <span>Scanned in {result.scanTime}ms</span>
                </div>
              </div>
            </div>

            {/* Detection bar */}
            <div className="mt-5 h-3 rounded-full bg-black/30 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-700 ${result.verdict === "malicious" ? "bg-rose-500" : result.verdict === "suspicious" ? "bg-amber-400" : "bg-emerald-400"}`}
                style={{ width: `${((result.vtDetections ?? 0) / (result.vtTotal ?? 72)) * 100}%` }}
              />
            </div>
          </div>

          {/* Malware detail */}
          {result.malware && (
            <div className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur-xl">
              <h3 className="text-base font-bold text-white mb-4">Malware Intelligence</h3>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-3">
                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <p className="text-xs text-slate-500 uppercase tracking-widest mb-1">Family</p>
                    <p className="text-base font-bold text-rose-200">{result.malware.family}</p>
                    <p className="text-sm text-slate-400 mt-1">{result.malware.type}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">File Hashes</p>
                    <div className="space-y-2 font-mono text-xs text-slate-300 break-all">
                      <div><span className="text-slate-500">MD5  </span>{result.malware.md5}</div>
                      <div><span className="text-slate-500">SHA1 </span>{result.malware.sha1}</div>
                      <div><span className="text-slate-500">SHA256 </span>{result.malware.sha256}</div>
                    </div>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">MITRE ATT&amp;CK</p>
                    <div className="flex flex-wrap gap-1.5">
                      {result.malware.mitreIds.map(id => (
                        <span key={id} className="rounded-lg border border-rose-500/20 bg-rose-500/10 px-2 py-0.5 text-xs font-mono text-rose-200">{id}</span>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="space-y-3">
                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">Description</p>
                    <p className="text-sm text-slate-300 leading-relaxed">{result.malware.description}</p>
                    <div className="mt-3 flex gap-4 text-xs text-slate-500">
                      <span>First seen: {result.malware.firstSeen}</span>
                      <span>Last seen: {result.malware.lastSeen}</span>
                    </div>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">IOC Patterns</p>
                    {result.malware.iocs.map(ioc => (
                      <div key={ioc} className="text-xs font-mono text-amber-300 py-0.5">• {ioc}</div>
                    ))}
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">YARA Rule</p>
                    <pre className="text-xs font-mono text-emerald-300 overflow-auto max-h-36 whitespace-pre-wrap">{result.malware.yara}</pre>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Engine breakdown */}
          <div className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur-xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-white">Engine Breakdown</h3>
              <button
                type="button"
                onClick={() => setShowAllEngines(prev => !prev)}
                className="text-xs text-sky-400 hover:text-sky-300 transition"
              >
                {showAllEngines ? "Show detected only" : "Show all engines"}
              </button>
            </div>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {(showAllEngines ? result.engines : detectedEngines).slice(0, showAllEngines ? 72 : 20).map(engine => (
                <div
                  key={engine.name}
                  className={`rounded-xl border p-3 flex items-center gap-2 ${engine.detected
                    ? "border-rose-500/20 bg-rose-500/8"
                    : "border-white/8 bg-white/3"
                    }`}
                >
                  <div className={`h-2 w-2 rounded-full shrink-0 ${engine.detected ? "bg-rose-400" : "bg-emerald-400/40"}`} />
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-slate-300 truncate">{engine.name}</p>
                    {engine.result && <p className="text-xs text-rose-300 truncate">{engine.result}</p>}
                  </div>
                </div>
              ))}
            </div>
            {!showAllEngines && detectedEngines.length === 0 && (
              <p className="text-center text-sm text-emerald-400 py-4">✓ No engines detected this indicator as malicious</p>
            )}
          </div>
        </div>
      )}

      {/* Scan history */}
      {history.length > 0 && (
        <div className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur-xl">
          <h3 className="text-sm font-bold text-white mb-4">Scan History</h3>
          <div className="space-y-2">
            {history.map((h, i) => (
              <div
                key={`${h.query}-${i}`}
                className="flex items-center justify-between gap-4 rounded-2xl border border-white/10 bg-black/20 px-4 py-3 cursor-pointer hover:border-white/20 transition"
                onClick={() => { setQuery(h.query); setResult(h); setShowAllEngines(false); }}
              >
                <div className="flex items-center gap-3 min-w-0">
                  {typeIcon[h.type]}
                  <p className="text-sm font-mono text-slate-300 truncate">{h.query}</p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className={`text-sm font-semibold ${h.verdict === "malicious" ? "text-rose-300" : h.verdict === "suspicious" ? "text-amber-300" : "text-emerald-300"}`}>
                    {h.vtDetections}/{h.vtTotal}
                  </span>
                  <span className={`rounded-full border px-2.5 py-1 text-xs font-medium uppercase ${verdictStyle[h.verdict]}`}>
                    {h.verdict}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Live IOC feed */}
      <div className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur-xl">
        <h3 className="text-base font-bold text-white mb-4">Live IOC Intelligence Feed</h3>
        <div className="space-y-3">
          {LIVE_IOCS.map(ioc => (
            <div
              key={ioc.id}
              className="grid gap-4 rounded-2xl border border-white/10 bg-black/20 p-4 cursor-pointer hover:border-amber-400/20 transition xl:grid-cols-[1fr_auto]"
              onClick={() => { setQuery(ioc.value.replace(/\[|\]/g, "")); runScan(ioc.value.replace(/\[|\]/g, "")); }}
            >
              <div>
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  <span className={`rounded-full border px-2 py-0.5 text-xs font-medium uppercase ${
                    ioc.severity === "critical" ? "border-rose-500/30 bg-rose-500/10 text-rose-200" :
                    ioc.severity === "high" ? "border-orange-400/30 bg-orange-500/10 text-orange-200" :
                    "border-amber-400/30 bg-amber-500/10 text-amber-200"
                  }`}>{ioc.severity}</span>
                  <span className="text-xs text-slate-500 uppercase tracking-widest">{ioc.type}</span>
                  <span className="text-xs text-slate-500">{ioc.source}</span>
                </div>
                <p className="font-mono text-sm text-white">{ioc.value}</p>
                {ioc.malwareFamily && (
                  <p className="text-xs text-amber-300 mt-1">Family: {ioc.malwareFamily}</p>
                )}
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {ioc.tags.map(tag => (
                    <span key={tag} className="rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-xs text-slate-400">{tag}</span>
                  ))}
                </div>
              </div>
              <div className="text-right space-y-2">
                <div>
                  <p className="text-xl font-bold text-white">{ioc.confidence}%</p>
                  <p className="text-xs text-slate-500">confidence</p>
                </div>
                <div>
                  <p className="text-sm text-slate-300">{ioc.hits} hits</p>
                  <span className={`rounded-full border px-2 py-0.5 text-xs font-medium uppercase ${
                    ioc.action === "block" ? "border-rose-500/30 bg-rose-500/10 text-rose-200" : "border-amber-400/30 bg-amber-500/10 text-amber-200"
                  }`}>{ioc.action}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
