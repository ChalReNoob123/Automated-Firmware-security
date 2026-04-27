import { useState } from "react";
import { MITRE_TACTICS, type MitreTechnique } from "../data/mitreData";
import { Shield, ChevronDown, ChevronRight, AlertTriangle, Eye, Lock } from "lucide-react";

const severityColor: Record<string, string> = {
  low: "border-emerald-400/30 bg-emerald-500/10 text-emerald-200",
  medium: "border-amber-400/30 bg-amber-500/10 text-amber-200",
  high: "border-orange-400/30 bg-orange-500/10 text-orange-200",
  critical: "border-rose-500/30 bg-rose-500/10 text-rose-200",
};

const severityBar: Record<string, string> = {
  low: "bg-emerald-400",
  medium: "bg-amber-400",
  high: "bg-orange-400",
  critical: "bg-rose-500",
};

function TechniqueCard({ technique }: { technique: MitreTechnique }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`rounded-2xl border transition-all duration-200 ${severityColor[technique.severity]} ${expanded ? "shadow-lg" : ""}`}>
      <button
        type="button"
        className="flex w-full items-center justify-between gap-3 p-4 text-left"
        onClick={() => setExpanded(prev => !prev)}
      >
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-slate-400">{technique.id}</span>
            <span className="text-sm font-semibold text-white">{technique.name}</span>
            <span className={`rounded-full border px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${severityColor[technique.severity]}`}>
              {technique.severity}
            </span>
          </div>
          <p className="mt-1 truncate text-xs text-slate-400">{technique.description}</p>
        </div>
        <div className="shrink-0 text-slate-500">
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-white/10 p-4 space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-3">
              <div className="rounded-xl border border-white/10 bg-black/30 p-3">
                <div className="flex items-center gap-2 mb-2">
                  <Eye className="h-3.5 w-3.5 text-sky-400" />
                  <p className="text-xs font-semibold uppercase tracking-widest text-sky-300">Detection Logic</p>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed">{technique.detectionLogic}</p>
              </div>
              <div className="rounded-xl border border-white/10 bg-black/30 p-3">
                <p className="text-xs font-semibold uppercase tracking-widest text-amber-300 mb-2">IOC Patterns</p>
                <div className="space-y-1">
                  {technique.iocPatterns.map(ioc => (
                    <div key={ioc} className="flex items-start gap-2">
                      <span className="text-amber-400 text-xs mt-0.5">›</span>
                      <span className="font-mono text-xs text-slate-300 break-all">{ioc}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <div className="space-y-3">
              <div className="rounded-xl border border-white/10 bg-black/30 p-3">
                <div className="flex items-center gap-2 mb-2">
                  <Lock className="h-3.5 w-3.5 text-emerald-400" />
                  <p className="text-xs font-semibold uppercase tracking-widest text-emerald-300">Mitigation</p>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed">{technique.mitigation}</p>
              </div>
              <div className="rounded-xl border border-white/10 bg-black/30 p-3">
                <p className="text-xs font-semibold uppercase tracking-widest text-purple-300 mb-2">Data Source</p>
                <p className="text-sm text-slate-300">{technique.dataSource}</p>
              </div>
              {technique.subTechniques && technique.subTechniques.length > 0 && (
                <div className="rounded-xl border border-white/10 bg-black/30 p-3">
                  <p className="text-xs font-semibold uppercase tracking-widest text-slate-400 mb-2">Sub-Techniques</p>
                  {technique.subTechniques.map(sub => (
                    <div key={sub} className="text-xs text-slate-300 py-0.5">{sub}</div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function MitreMatrix() {
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid");

  const filteredTactics = selectedTactic
    ? MITRE_TACTICS.filter(t => t.id === selectedTactic)
    : MITRE_TACTICS;

  const totalTechniques = MITRE_TACTICS.flatMap(t => t.techniques).length;
  const criticalCount = MITRE_TACTICS.flatMap(t => t.techniques).filter(t => t.severity === "critical").length;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Shield className="h-5 w-5 text-rose-400" />
            MITRE ATT&amp;CK Enterprise Matrix v15
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            {MITRE_TACTICS.length} tactics · {totalTechniques} techniques mapped · {criticalCount} critical severity
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <button
            type="button"
            onClick={() => setViewMode(v => v === "grid" ? "list" : "grid")}
            className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-xs font-medium text-slate-300 hover:border-sky-400/40 hover:text-sky-300 transition"
          >
            {viewMode === "grid" ? "Switch to List" : "Switch to Grid"}
          </button>
          <button
            type="button"
            onClick={() => setSelectedTactic(null)}
            className={`rounded-xl border px-3 py-2 text-xs font-medium transition ${!selectedTactic ? "border-sky-400/40 bg-sky-500/10 text-sky-200" : "border-white/10 bg-white/5 text-slate-400 hover:text-slate-200"}`}
          >
            All Tactics
          </button>
        </div>
      </div>

      {/* Tactic selector row */}
      <div className="flex flex-wrap gap-2">
        {MITRE_TACTICS.map(tactic => {
          const critCount = tactic.techniques.filter(t => t.severity === "critical").length;
          const highCount = tactic.techniques.filter(t => t.severity === "high").length;
          return (
            <button
              key={tactic.id}
              type="button"
              onClick={() => setSelectedTactic(selectedTactic === tactic.id ? null : tactic.id)}
              className={`group rounded-2xl border px-4 py-3 text-left transition-all ${selectedTactic === tactic.id
                ? "border-sky-400/40 bg-sky-500/10 ring-1 ring-sky-500/20"
                : "border-white/10 bg-white/5 hover:border-white/20 hover:bg-white/8"
                }`}
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-slate-500">{tactic.id}</span>
                {critCount > 0 && (
                  <AlertTriangle className="h-3 w-3 text-rose-400" />
                )}
              </div>
              <p className="mt-1 text-sm font-semibold text-white">{tactic.shortName}</p>
              <div className="mt-1 flex gap-2">
                {critCount > 0 && <span className="text-xs text-rose-300">{critCount}C</span>}
                {highCount > 0 && <span className="text-xs text-orange-300">{highCount}H</span>}
              </div>
            </button>
          );
        })}
      </div>

      {/* Tactic sections */}
      <div className={viewMode === "grid" ? "grid gap-6 xl:grid-cols-2" : "space-y-6"}>
        {filteredTactics.map(tactic => (
          <div key={tactic.id} className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur-xl">
            <div className="mb-4 flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-xs text-slate-500 border border-white/10 rounded-lg px-2 py-0.5">{tactic.id}</span>
                  <h3 className="text-base font-bold text-white">{tactic.name}</h3>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{tactic.description}</p>
              </div>
              <span className="shrink-0 rounded-full border border-white/10 bg-black/20 px-2 py-1 text-xs text-slate-400">
                {tactic.techniques.length} techs
              </span>
            </div>

            {/* Severity mini bar */}
            <div className="mb-4 h-1.5 rounded-full bg-white/5 flex overflow-hidden">
              {["critical", "high", "medium", "low"].map(sev => {
                const count = tactic.techniques.filter(t => t.severity === sev).length;
                const pct = (count / tactic.techniques.length) * 100;
                return pct > 0 ? (
                  <div key={sev} className={`h-full ${severityBar[sev]}`} style={{ width: `${pct}%` }} />
                ) : null;
              })}
            </div>

            <div className="space-y-3">
              {tactic.techniques.map(technique => (
                <TechniqueCard key={technique.id} technique={technique} />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
