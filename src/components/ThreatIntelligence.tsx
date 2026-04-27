import { useState } from "react";
import { THREAT_ACTORS, MALWARE_SIGNATURES } from "../data/threatEngine";
import { Globe, Cpu, ChevronDown, ChevronRight } from "lucide-react";

const sophisticationColor: Record<string, string> = {
  "Nation-State": "border-rose-500/30 bg-rose-500/10 text-rose-200",
  "Criminal": "border-amber-400/30 bg-amber-500/10 text-amber-200",
  "Hacktivist": "border-sky-400/30 bg-sky-500/10 text-sky-200",
  "Insider": "border-purple-400/30 bg-purple-500/10 text-purple-200",
};

const malwareTypeColor: Record<string, string> = {
  Ransomware: "border-rose-500/30 bg-rose-500/10 text-rose-200",
  RAT: "border-orange-400/30 bg-orange-500/10 text-orange-200",
  Infostealer: "border-amber-400/30 bg-amber-500/10 text-amber-200",
  Rootkit: "border-purple-400/30 bg-purple-500/10 text-purple-200",
  Wiper: "border-rose-600/30 bg-rose-600/10 text-rose-100",
  Dropper: "border-sky-400/30 bg-sky-500/10 text-sky-200",
  Botnet: "border-cyan-400/30 bg-cyan-500/10 text-cyan-200",
  Cryptominer: "border-emerald-400/30 bg-emerald-500/10 text-emerald-200",
};

const severityBg: Record<string, string> = {
  low: "bg-emerald-400",
  medium: "bg-amber-400",
  high: "bg-orange-400",
  critical: "bg-rose-500",
};

export default function ThreatIntelligence() {
  const [expandedActor, setExpandedActor] = useState<string | null>(null);
  const [expandedMalware, setExpandedMalware] = useState<string | null>(null);

  return (
    <div className="space-y-8">
      {/* Threat Actors */}
      <div>
        <h3 className="text-lg font-bold text-white flex items-center gap-2 mb-4">
          <Globe className="h-5 w-5 text-rose-400" />
          Active Threat Actors &amp; APT Groups
        </h3>
        <div className="space-y-3">
          {THREAT_ACTORS.map(actor => (
            <div key={actor.name} className="rounded-3xl border border-white/10 bg-white/5 overflow-hidden">
              <button
                type="button"
                className="w-full p-5 text-left flex items-start gap-4"
                onClick={() => setExpandedActor(expandedActor === actor.name ? null : actor.name)}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <h4 className="text-base font-bold text-white">{actor.name}</h4>
                    <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${sophisticationColor[actor.sophistication]}`}>
                      {actor.sophistication}
                    </span>
                    <span className="text-xs text-slate-500">📍 {actor.origin}</span>
                  </div>
                  <p className="text-sm text-slate-400">{actor.motivation}</p>
                </div>
                <div className="shrink-0 flex gap-2 items-center">
                  <div className="flex flex-wrap gap-1 justify-end">
                    {actor.targetSectors.slice(0, 2).map(s => (
                      <span key={s} className="rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-xs text-slate-300">{s}</span>
                    ))}
                  </div>
                  {expandedActor === actor.name ? <ChevronDown className="h-4 w-4 text-slate-500" /> : <ChevronRight className="h-4 w-4 text-slate-500" />}
                </div>
              </button>

              {expandedActor === actor.name && (
                <div className="border-t border-white/10 p-5 grid gap-4 md:grid-cols-3">
                  <div>
                    <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">Target Sectors</p>
                    <div className="space-y-1">
                      {actor.targetSectors.map(s => (
                        <div key={s} className="text-sm text-slate-300">{s}</div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">Primary TTPs (MITRE)</p>
                    <div className="flex flex-wrap gap-1.5">
                      {actor.ttps.map(t => (
                        <span key={t} className="rounded-lg border border-rose-500/20 bg-rose-500/10 px-2 py-0.5 text-xs font-mono text-rose-300">{t}</span>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">Threat Profile</p>
                    <div className="space-y-2 text-sm text-slate-300">
                      <div className="flex justify-between">
                        <span className="text-slate-500">Sophistication</span>
                        <span>{actor.sophistication}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Origin</span>
                        <span>{actor.origin}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">TTP Count</span>
                        <span>{actor.ttps.length}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Malware Signatures */}
      <div>
        <h3 className="text-lg font-bold text-white flex items-center gap-2 mb-4">
          <Cpu className="h-5 w-5 text-amber-400" />
          Known Malware Signatures &amp; YARA Rules
        </h3>
        <div className="space-y-3">
          {MALWARE_SIGNATURES.map(mal => (
            <div key={mal.id} className="rounded-3xl border border-white/10 bg-white/5 overflow-hidden">
              <button
                type="button"
                className="w-full p-5 text-left flex items-start gap-4"
                onClick={() => setExpandedMalware(expandedMalware === mal.id ? null : mal.id)}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <h4 className="text-base font-bold text-white">{mal.name}</h4>
                    <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${malwareTypeColor[mal.type]}`}>
                      {mal.type}
                    </span>
                    <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${
                      mal.severity === "critical" ? "border-rose-500/30 bg-rose-500/10 text-rose-200" :
                      mal.severity === "high" ? "border-orange-400/30 bg-orange-500/10 text-orange-200" :
                      "border-amber-400/30 bg-amber-500/10 text-amber-200"
                    }`}>{mal.severity}</span>
                  </div>
                  <p className="text-sm text-slate-400 line-clamp-1">{mal.description}</p>
                </div>
                <div className="shrink-0 text-right flex items-center gap-3">
                  <div>
                    <p className={`text-xl font-bold ${mal.vtDetections > 50 ? "text-rose-300" : mal.vtDetections > 30 ? "text-amber-300" : "text-emerald-300"}`}>
                      {mal.vtRatio}
                    </p>
                    <p className="text-xs text-slate-500">VT detections</p>
                  </div>
                  {expandedMalware === mal.id ? <ChevronDown className="h-4 w-4 text-slate-500" /> : <ChevronRight className="h-4 w-4 text-slate-500" />}
                </div>
              </button>

              {expandedMalware === mal.id && (
                <div className="border-t border-white/10 p-5 space-y-4">
                  {/* VT bar */}
                  <div>
                    <div className="flex justify-between text-xs text-slate-400 mb-1">
                      <span>VirusTotal Detection Rate</span>
                      <span>{Math.round((mal.vtDetections / mal.vtTotal) * 100)}%</span>
                    </div>
                    <div className="h-3 rounded-full bg-white/5 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${severityBg[mal.severity]}`}
                        style={{ width: `${(mal.vtDetections / mal.vtTotal) * 100}%` }}
                      />
                    </div>
                  </div>

                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-3">
                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">File Hashes</p>
                        <div className="space-y-1 font-mono text-xs text-slate-300 break-all">
                          <div><span className="text-slate-500">MD5   </span>{mal.md5}</div>
                          <div><span className="text-slate-500">SHA1  </span>{mal.sha1}</div>
                          <div><span className="text-slate-500">SHA256 </span>{mal.sha256}</div>
                        </div>
                      </div>
                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">IOC Patterns</p>
                        {mal.iocs.map(ioc => (
                          <div key={ioc} className="text-xs font-mono text-amber-300 py-0.5">• {ioc}</div>
                        ))}
                      </div>
                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">MITRE IDs</p>
                        <div className="flex flex-wrap gap-1.5">
                          {mal.mitreIds.map(id => (
                            <span key={id} className="rounded-lg border border-rose-500/20 bg-rose-500/10 px-2 py-0.5 text-xs font-mono text-rose-300">{id}</span>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="space-y-3">
                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">Description</p>
                        <p className="text-sm text-slate-300 leading-relaxed">{mal.description}</p>
                        <div className="flex gap-4 mt-3 text-xs text-slate-500">
                          <span>First: {mal.firstSeen}</span>
                          <span>Last: {mal.lastSeen}</span>
                        </div>
                      </div>
                      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">YARA Detection Rule</p>
                        <pre className="text-xs font-mono text-emerald-300 overflow-auto max-h-40 whitespace-pre-wrap">{mal.yara}</pre>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
