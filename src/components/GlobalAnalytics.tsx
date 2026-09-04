import { useState, useEffect } from "react";
import { Activity, Clock, AlertTriangle, XCircle, TrendingUp, TrendingDown, Loader2 } from "lucide-react";
import { apiGet } from "../utils/api";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer } from "recharts";

// ── Types ─────────────────────────────────────────────────────────────
interface GlobalKPIs {
  summary: {
    total_requests: number;
    total_errors: number;
    error_rate_pct: number;
    avg_response_ms: number;
    bytes_transferred: number;
    active_alerts: number;
    segments_tracked: number;
  };
  top_segments: any[];
  slowest_segments: any[];
  timeline: { bucket: number; requests: number; errors: number; avg_ms: number }[];
  computed_at: number;
}

interface SegmentRanking {
  id: string;
  label: string;
  icon: string;
  category: string;
  health_score: number;
  kpi: {
    requests: number;
    errors: number;
    avg_duration_ms: number;
    error_rate_pct: number;
    availability_pct: number;
    threat_events: number;
    alert_count: number;
  };
}

// ── Sub-Components ────────────────────────────────────────────────────
function MetricCard({ title, value, unit = "", icon: Icon, trend = 0, status = "neutral" }: any) {
  const statusColors = {
    neutral: "text-sky-400 bg-sky-500/10 border-sky-500/20",
    good: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    warning: "text-amber-400 bg-amber-500/10 border-amber-500/20",
    critical: "text-rose-400 bg-rose-500/10 border-rose-500/20",
  };

  return (
    <div className="relative rounded-[2rem] border border-cyan-500/20 glass-v2 p-6 overflow-hidden group">
      <div className="absolute inset-0 holographic opacity-10 pointer-events-none group-hover:opacity-20 transition-opacity" />
      <div className="relative z-10 flex items-center justify-between mb-4">
        <h3 className="text-[10px] font-bold text-cyan-200/70 tracking-widest uppercase">{title}</h3>
        <div className={`p-2.5 rounded-xl border backdrop-blur-md shadow-[0_0_15px_rgba(0,0,0,0.2)] ${statusColors[status as keyof typeof statusColors]}`}>
          <Icon className="h-4 w-4" />
        </div>
      </div>
      <div className="relative z-10 flex items-baseline gap-1.5">
        <span className="text-4xl font-black text-white drop-shadow-[0_0_8px_rgba(255,255,255,0.4)] tracking-tighter">{value}</span>
        {unit && <span className="text-sm font-mono text-cyan-400">{unit}</span>}
      </div>
      {trend !== 0 && (
        <div className="relative z-10 mt-5 flex items-center gap-1.5 text-xs font-mono">
          {trend > 0 ? (
            <TrendingUp className={`h-3.5 w-3.5 ${status === "good" ? "text-cyan-400 drop-shadow-[0_0_5px_rgba(34,211,238,0.8)]" : "text-rose-400 drop-shadow-[0_0_5px_rgba(244,63,94,0.8)]"}`} />
          ) : (
            <TrendingDown className={`h-3.5 w-3.5 ${status === "good" ? "text-cyan-400" : "text-cyan-400"}`} />
          )}
          <span className={status === "good" ? "text-cyan-300" : "text-rose-300"}>
            {Math.abs(trend).toFixed(1)}% VS PREVIOUS
          </span>
        </div>
      )}
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────
export default function GlobalAnalytics() {
  const [activeTab, setActiveTab] = useState<"overview" | "segments" | "alerts">("overview");
  const [globalData, setGlobalData] = useState<GlobalKPIs | null>(null);
  const [segments, setSegments] = useState<SegmentRanking[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const [globalRes, segRes] = await Promise.all([
        apiGet("/api/analytics/global"),
        apiGet("/api/analytics/segments")
      ]);
      if (globalRes) setGlobalData(globalRes as GlobalKPIs);
      if (segRes && (segRes as any).segments) setSegments((segRes as any).segments as SegmentRanking[]);
    } catch (err) {
      console.error("Failed to load analytics:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const timer = setInterval(fetchData, 60000); // refresh every minute
    return () => clearInterval(timer);
  }, []);

  if (loading && !globalData) {
    return (
      <div className="flex h-[400px] items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-sky-500" />
      </div>
    );
  }

  if (!loading && !globalData) {
    return (
      <div className="flex flex-col h-[400px] items-center justify-center text-slate-400 space-y-4">
        <AlertTriangle className="h-10 w-10 text-rose-500/80" />
        <p className="text-lg font-medium text-slate-300">Backend API Unreachable</p>
        <p className="text-sm max-w-md text-center">
          The analytics engine could not be reached. Please ensure the backend server has been <b>restarted</b> so it can serve the newly added analytics endpoints.
        </p>
        <button onClick={fetchData} className="mt-4 rounded-xl bg-sky-500/20 text-sky-400 px-4 py-2 hover:bg-sky-500/30 transition">
          Retry Connection
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-20">
      {/* Header */}
      <div className="relative glass-v2 rounded-[2rem] p-6 border border-cyan-500/20 shadow-[0_0_30px_rgba(34,211,238,0.1)] overflow-hidden">
        <div className="absolute inset-0 pointer-events-none holo-threat-field opacity-10" />
        <div className="relative z-10 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 className="text-3xl font-black text-white flex items-center gap-4 tracking-tight drop-shadow-md">
              <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/30 breathe-glow">
                <Activity className="h-6 w-6 text-white" />
              </div>
              GLOBAL COMMAND ANALYTICS
            </h2>
            <p className="mt-2 text-sm text-cyan-200/60 font-mono uppercase tracking-widest">
              Real-time telemetry, segment health monitoring, and KPI tracking
            </p>
          </div>
          <div className="flex gap-3">
            <button onClick={fetchData} className="group relative flex items-center gap-2 rounded-xl bg-black/40 border border-cyan-500/40 px-6 py-3 text-xs font-bold text-cyan-300 shadow-lg hover:bg-cyan-500/20 hover:text-white transition-all duration-300 overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-cyan-400/10 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700 ease-in-out" />
              <Activity className="h-4 w-4" /> RE-SYNC TELEMETRY
            </button>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-white/10 pb-4">
        {["overview", "segments", "alerts"].map((t) => (
          <button
            key={t}
            onClick={() => setActiveTab(t as any)}
            className={`px-4 py-2 text-sm font-medium rounded-xl transition ${
              activeTab === t ? "bg-sky-500/20 text-sky-300 border border-sky-500/30" : "text-slate-400 hover:bg-white/5 hover:text-slate-200"
            }`}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {/* Content */}
      {activeTab === "overview" && globalData && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <MetricCard 
              title="Total Requests (1h)" 
              value={globalData.summary.total_requests.toLocaleString()} 
              icon={Activity} 
              status="neutral" 
            />
            <MetricCard 
              title="Global Error Rate" 
              value={globalData.summary.error_rate_pct.toFixed(2)} 
              unit="%" 
              icon={XCircle} 
              status={globalData.summary.error_rate_pct > 5 ? "critical" : globalData.summary.error_rate_pct > 1 ? "warning" : "good"} 
            />
            <MetricCard 
              title="Avg Response Time" 
              value={globalData.summary.avg_response_ms} 
              unit="ms" 
              icon={Clock} 
              status={globalData.summary.avg_response_ms > 1000 ? "critical" : globalData.summary.avg_response_ms > 500 ? "warning" : "good"} 
            />
            <MetricCard 
              title="Active Alerts" 
              value={globalData.summary.active_alerts} 
              icon={AlertTriangle} 
              status={globalData.summary.active_alerts > 0 ? "warning" : "good"} 
            />
          </div>

          {/* Traffic Chart */}
          <div className="relative rounded-[2rem] border border-cyan-500/20 glass-v2 p-6 shadow-2xl overflow-hidden">
            <div className="absolute inset-0 cyber-grid opacity-10 pointer-events-none" />
            <h3 className="relative z-10 text-sm font-bold text-cyan-300 mb-6 tracking-widest uppercase">Traffic & Latency Timeline (Last Hour)</h3>
            <div className="relative z-10 h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={globalData.timeline}>
                  <defs>
                    <linearGradient id="colorReq" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#22d3ee" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorLat" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#818cf8" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#818cf8" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(34,211,238,0.1)" vertical={false} />
                  <XAxis dataKey="bucket" tickFormatter={(v) => new Date(v).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} stroke="#67e8f9" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis yAxisId="left" stroke="#67e8f9" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis yAxisId="right" orientation="right" stroke="#818cf8" fontSize={10} tickLine={false} axisLine={false} />
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#083344', borderColor: 'rgba(34,211,238,0.3)', borderRadius: '1rem', backdropFilter: 'blur(10px)', color: '#cffafe' }}
                    labelFormatter={(v) => new Date(v).toLocaleTimeString()}
                  />
                  <Area yAxisId="left" type="monotone" dataKey="requests" name="Requests" stroke="#22d3ee" strokeWidth={3} fillOpacity={1} fill="url(#colorReq)" activeDot={{ r: 6, fill: '#22d3ee', stroke: '#fff', strokeWidth: 2 }} />
                  <Area yAxisId="right" type="monotone" dataKey="avg_ms" name="Avg Latency (ms)" stroke="#818cf8" strokeWidth={3} fillOpacity={1} fill="url(#colorLat)" activeDot={{ r: 6, fill: '#818cf8', stroke: '#fff', strokeWidth: 2 }} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {activeTab === "segments" && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
            {segments.map((seg) => (
              <div key={seg.id} className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{seg.icon}</span>
                    <div>
                      <h3 className="font-semibold text-white">{seg.label}</h3>
                      <span className="text-xs text-slate-400 capitalize">{seg.category}</span>
                    </div>
                  </div>
                  <div className={`flex items-center justify-center h-10 w-10 rounded-full border ${
                    seg.health_score > 90 ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400" :
                    seg.health_score > 70 ? "border-amber-500/30 bg-amber-500/10 text-amber-400" :
                    "border-rose-500/30 bg-rose-500/10 text-rose-400"
                  }`}>
                    <span className="text-sm font-bold">{seg.health_score}</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 mt-6">
                  <div>
                    <p className="text-xs text-slate-500 mb-1">Response Time</p>
                    <p className="text-lg font-medium text-slate-200">{seg.kpi.avg_duration_ms} ms</p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 mb-1">Error Rate</p>
                    <p className={`text-lg font-medium ${seg.kpi.error_rate_pct > 5 ? 'text-rose-400' : 'text-slate-200'}`}>
                      {seg.kpi.error_rate_pct}%
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 mb-1">Availability</p>
                    <p className="text-lg font-medium text-slate-200">{seg.kpi.availability_pct}%</p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 mb-1">Requests (1h)</p>
                    <p className="text-lg font-medium text-slate-200">{seg.kpi.requests}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === "alerts" && (
        <div className="rounded-2xl border border-white/10 bg-white/5 p-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
           <h3 className="text-base font-semibold text-white mb-6">Performance & Health Alerts</h3>
           <p className="text-slate-400 text-sm">Alerts module integrated with global alerts system. Check dashboard for active thresholds.</p>
        </div>
      )}
    </div>
  );
}
