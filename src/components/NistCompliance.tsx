import { useState } from "react";
import { NIST_FUNCTIONS, type NistFunction, type NistCategory } from "../data/nistData";
import { CheckCircle, AlertCircle, XCircle, HelpCircle, TrendingUp } from "lucide-react";
import { RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer, Tooltip } from "recharts";

const statusIcon: Record<string, React.ReactNode> = {
  compliant: <CheckCircle className="h-4 w-4 text-emerald-400" />,
  partial: <AlertCircle className="h-4 w-4 text-amber-400" />,
  "non-compliant": <XCircle className="h-4 w-4 text-rose-400" />,
  "not-assessed": <HelpCircle className="h-4 w-4 text-slate-500" />,
};

const statusStyle: Record<string, string> = {
  compliant: "border-emerald-400/20 bg-emerald-500/10 text-emerald-200",
  partial: "border-amber-400/20 bg-amber-500/10 text-amber-200",
  "non-compliant": "border-rose-500/20 bg-rose-500/10 text-rose-200",
  "not-assessed": "border-white/10 bg-white/5 text-slate-400",
};

const functionColor: Record<string, string> = {
  GV: "purple", ID: "blue", PR: "emerald", DE: "amber", RS: "orange", RC: "cyan"
};

const colorMap: Record<string, { ring: string; bar: string; glow: string; text: string }> = {
  purple: { ring: "ring-purple-500/30", bar: "bg-purple-500", glow: "from-purple-500/20", text: "text-purple-300" },
  blue: { ring: "ring-blue-500/30", bar: "bg-blue-500", glow: "from-blue-500/20", text: "text-blue-300" },
  emerald: { ring: "ring-emerald-500/30", bar: "bg-emerald-500", glow: "from-emerald-500/20", text: "text-emerald-300" },
  amber: { ring: "ring-amber-500/30", bar: "bg-amber-500", glow: "from-amber-500/20", text: "text-amber-300" },
  orange: { ring: "ring-orange-500/30", bar: "bg-orange-500", glow: "from-orange-500/20", text: "text-orange-300" },
  cyan: { ring: "ring-cyan-500/30", bar: "bg-cyan-500", glow: "from-cyan-500/20", text: "text-cyan-300" },
};

function CategoryPanel({ category, funcId }: { category: NistCategory; funcId: string }) {
  const [expanded, setExpanded] = useState(false);
  const color = colorMap[functionColor[funcId]];

  return (
    <div className="rounded-2xl border border-white/10 bg-black/20 overflow-hidden">
      <button
        type="button"
        className="w-full p-4 text-left"
        onClick={() => setExpanded(prev => !prev)}
      >
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <span className={`font-mono text-xs ${color.text}`}>{category.id}</span>
              <span className="text-sm font-semibold text-white">{category.name}</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed truncate">{category.description}</p>
          </div>
          <div className="shrink-0 text-right">
            <p className={`text-2xl font-bold ${color.text}`}>{category.complianceScore}%</p>
            <p className="text-xs text-slate-500">compliance</p>
          </div>
        </div>
        <div className="mt-3 h-1.5 rounded-full bg-white/5 overflow-hidden">
          <div
            className={`h-full rounded-full ${color.bar} transition-all duration-700`}
            style={{ width: `${category.complianceScore}%` }}
          />
        </div>
      </button>

      {expanded && (
        <div className="border-t border-white/10 p-4 space-y-2">
          {category.subcategories.map(sub => (
            <div key={sub.id} className={`flex items-center justify-between gap-4 rounded-xl border p-3 ${statusStyle[sub.status]}`}>
              <div className="flex items-center gap-3 min-w-0">
                {statusIcon[sub.status]}
                <div className="min-w-0">
                  <p className="font-mono text-xs text-slate-500">{sub.id}</p>
                  <p className="text-sm text-slate-200 leading-relaxed">{sub.name}</p>
                </div>
              </div>
              <div className="shrink-0 text-right">
                <span className={`rounded-full border px-2.5 py-1 text-xs font-medium capitalize ${statusStyle[sub.status]}`}>
                  {sub.status.replace("-", " ")}
                </span>
                <p className="mt-1 text-xs text-slate-500">{sub.lastAssessed}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function FunctionCard({ func, selected, onClick }: { func: NistFunction; selected: boolean; onClick: () => void }) {
  const color = colorMap[functionColor[func.id]];
  const avgScore = Math.round(func.categories.reduce((s, c) => s + c.complianceScore, 0) / func.categories.length);

  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-3xl border p-5 text-left transition-all ${selected
        ? `border-white/20 bg-gradient-to-br ${color.glow} to-transparent ring-1 ${color.ring}`
        : "border-white/10 bg-white/5 hover:border-white/15"
        }`}
    >
      <div className="flex items-start justify-between">
        <div>
          <span className={`font-mono text-xs font-bold ${color.text}`}>{func.id}</span>
          <h3 className="mt-1 text-base font-bold text-white">{func.name}</h3>
        </div>
        <div className="text-right">
          <p className={`text-2xl font-bold ${color.text}`}>{avgScore}%</p>
          <p className="text-xs text-slate-500">avg compliance</p>
        </div>
      </div>
      <p className="mt-2 text-xs text-slate-400 leading-relaxed line-clamp-2">{func.description}</p>
      <div className="mt-3 h-1.5 rounded-full bg-white/5 overflow-hidden">
        <div className={`h-full rounded-full ${color.bar}`} style={{ width: `${avgScore}%` }} />
      </div>
      <p className="mt-2 text-xs text-slate-500">{func.categories.length} categories</p>
    </button>
  );
}

export default function NistCompliance() {
  const [selectedFunc, setSelectedFunc] = useState<string>("GV");

  const activeFunc = NIST_FUNCTIONS.find(f => f.id === selectedFunc)!;

  const radarData = NIST_FUNCTIONS.map(f => ({
    subject: f.id,
    score: Math.round(f.categories.reduce((s, c) => s + c.complianceScore, 0) / f.categories.length),
    fullMark: 100,
  }));

  const overallScore = Math.round(
    NIST_FUNCTIONS.flatMap(f => f.categories).reduce((s, c) => s + c.complianceScore, 0) /
    NIST_FUNCTIONS.flatMap(f => f.categories).length
  );

  const totalSubcats = NIST_FUNCTIONS.flatMap(f => f.categories.flatMap(c => c.subcategories));
  const compliantCount = totalSubcats.filter(s => s.status === "compliant").length;
  const partialCount = totalSubcats.filter(s => s.status === "partial").length;
  const nonCompliantCount = totalSubcats.filter(s => s.status === "non-compliant").length;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-emerald-400" />
            NIST Cybersecurity Framework 2.0 Compliance
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            6 core functions · {NIST_FUNCTIONS.flatMap(f => f.categories).length} categories · {totalSubcats.length} subcategories tracked
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <div className="rounded-2xl border border-emerald-400/20 bg-emerald-500/10 px-4 py-3">
            <p className="text-xs uppercase tracking-widest text-emerald-300">Compliant</p>
            <p className="text-2xl font-bold text-emerald-200">{compliantCount}</p>
          </div>
          <div className="rounded-2xl border border-amber-400/20 bg-amber-500/10 px-4 py-3">
            <p className="text-xs uppercase tracking-widest text-amber-300">Partial</p>
            <p className="text-2xl font-bold text-amber-200">{partialCount}</p>
          </div>
          <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3">
            <p className="text-xs uppercase tracking-widest text-rose-300">Non-Compliant</p>
            <p className="text-2xl font-bold text-rose-200">{nonCompliantCount}</p>
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Radar + Overall */}
        <div className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur-xl">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-white">Overall Posture</h3>
            <div className="text-right">
              <p className="text-3xl font-bold text-emerald-300">{overallScore}%</p>
              <p className="text-xs text-slate-500">NIST CSF 2.0 Score</p>
            </div>
          </div>
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={radarData}>
                <PolarGrid stroke="rgba(255,255,255,0.08)" />
                <PolarAngleAxis dataKey="subject" tick={{ fill: "#94a3b8", fontSize: 11 }} />
                <Radar
                  name="Compliance"
                  dataKey="score"
                  stroke="#34d399"
                  fill="#34d399"
                  fillOpacity={0.18}
                  strokeWidth={2}
                />
                <Tooltip
                  contentStyle={{ background: "#0f172a", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "12px" }}
                  labelStyle={{ color: "#94a3b8" }}
                  itemStyle={{ color: "#34d399" }}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>

          <div className="mt-4 space-y-2">
            {[
              { label: "Tier 4 Adaptive", check: overallScore >= 90 },
              { label: "Tier 3 Repeatable", check: overallScore >= 75 },
              { label: "Tier 2 Risk Informed", check: overallScore >= 60 },
              { label: "Tier 1 Partial", check: overallScore >= 40 },
            ].map(tier => (
              <div key={tier.label} className="flex items-center gap-2">
                {tier.check
                  ? <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
                  : <XCircle className="h-3.5 w-3.5 text-slate-600" />
                }
                <span className={`text-xs ${tier.check ? "text-slate-300" : "text-slate-600"}`}>{tier.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Function grid */}
        <div className="lg:col-span-2 grid gap-4 sm:grid-cols-2 xl:grid-cols-3 content-start">
          {NIST_FUNCTIONS.map(func => (
            <FunctionCard
              key={func.id}
              func={func}
              selected={selectedFunc === func.id}
              onClick={() => setSelectedFunc(func.id)}
            />
          ))}
        </div>
      </div>

      {/* Active function detail */}
      <div className="rounded-3xl border border-white/10 bg-white/5 p-5 backdrop-blur-xl">
        <div className="mb-5 flex items-center gap-3">
          <div className={`rounded-2xl border border-white/10 px-4 py-2 bg-gradient-to-br ${colorMap[functionColor[activeFunc.id]].glow} to-transparent`}>
            <span className={`text-lg font-bold ${colorMap[functionColor[activeFunc.id]].text}`}>{activeFunc.id}</span>
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">{activeFunc.name} Function — Categories &amp; Subcategories</h3>
            <p className="text-sm text-slate-400">{activeFunc.description}</p>
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          {activeFunc.categories.map(category => (
            <CategoryPanel key={category.id} category={category} funcId={activeFunc.id} />
          ))}
        </div>
      </div>
    </div>
  );
}
