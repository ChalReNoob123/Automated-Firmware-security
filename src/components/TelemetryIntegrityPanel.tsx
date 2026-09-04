import { Activity, AlertTriangle, CheckCircle, Clock, Database, Shield } from "lucide-react";
import type { CSSProperties } from "react";
import type { TelemetryMeta, WsStatus } from "../stores/socStore";

type TelemetryIntegrityPanelProps = {
  meta: TelemetryMeta;
  wsStatus: WsStatus;
  wsLatency: number;
  now: number;
};

function formatAge(ageMs: number | null) {
  if (ageMs === null) return "Waiting";
  if (ageMs < 1000) return "Live";
  return `${(ageMs / 1000).toFixed(1)}s`;
}

function confidenceFrom(meta: TelemetryMeta, wsStatus: WsStatus, wsLatency: number, now: number) {
  const ageMs = meta.lastUpdateAt ? now - meta.lastUpdateAt : null;
  const freshnessScore = ageMs === null ? 0 : Math.max(0, 35 - Math.min(35, ageMs / 600));
  const socketScore = wsStatus === "connected" ? 25 : wsStatus === "connecting" ? 10 : 0;
  const latencyScore = wsLatency > 0 ? Math.max(0, 15 - Math.min(15, wsLatency / 40)) : 6;
  const activeSources = Object.values(meta.sourceCounts).filter((count) => count > 0).length;
  const sourceScore = Math.min(20, activeSources * 4);
  const validationPenalty = Math.min(20, meta.malformedMessages * 4);
  return Math.max(0, Math.min(99, Math.round(freshnessScore + socketScore + latencyScore + sourceScore - validationPenalty)));
}

export default function TelemetryIntegrityPanel({ meta, wsStatus, wsLatency, now }: TelemetryIntegrityPanelProps) {
  const ageMs = meta.lastUpdateAt ? now - meta.lastUpdateAt : null;
  const confidence = confidenceFrom(meta, wsStatus, wsLatency, now);
  const healthy = confidence >= 80 && wsStatus === "connected";
  const activeSources = Object.entries(meta.sourceCounts).filter(([, count]) => count > 0);

  return (
    <section className="telemetry-integrity rounded-3xl border border-white/10 bg-black/20 p-5">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.24em] text-slate-500">Realtime Accuracy Guard</p>
          <h3 className="mt-1 text-sm font-bold text-white">Telemetry integrity</h3>
        </div>
        <div className={`rounded-2xl border px-3 py-2 text-right ${healthy ? "border-emerald-400/30 bg-emerald-400/10" : "border-amber-400/30 bg-amber-400/10"}`}>
          <p className={`text-2xl font-black ${healthy ? "text-emerald-200" : "text-amber-200"}`}>{confidence}%</p>
          <p className="text-[9px] uppercase tracking-widest text-slate-500">confidence</p>
        </div>
      </div>

      <div className="telemetry-ring-wrap">
        <div className="telemetry-ring" style={{ "--integrity": `${confidence * 3.6}deg` } as CSSProperties}>
          {healthy ? <CheckCircle className="h-7 w-7 text-emerald-200" /> : <AlertTriangle className="h-7 w-7 text-amber-200" />}
        </div>
      </div>

      <div className="mt-4 grid gap-2">
        <div className="telemetry-row">
          <Activity className="h-3.5 w-3.5 text-emerald-300" />
          <span>Stream</span>
          <strong>{wsStatus}</strong>
        </div>
        <div className="telemetry-row">
          <Clock className="h-3.5 w-3.5 text-cyan-300" />
          <span>Freshness</span>
          <strong>{formatAge(ageMs)}</strong>
        </div>
        <div className="telemetry-row">
          <Shield className="h-3.5 w-3.5 text-indigo-300" />
          <span>Validation</span>
          <strong>{meta.malformedMessages === 0 ? "Clean" : `${meta.malformedMessages} rejected`}</strong>
        </div>
        <div className="telemetry-row">
          <Database className="h-3.5 w-3.5 text-amber-300" />
          <span>Samples</span>
          <strong>{meta.samplesReceived}</strong>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        {activeSources.length === 0 ? (
          <span className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-[10px] uppercase tracking-wider text-slate-500">Awaiting source data</span>
        ) : (
          activeSources.map(([source, count]) => (
            <span key={source} className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-2.5 py-1 text-[10px] uppercase tracking-wider text-cyan-100">
              {source}: {count}
            </span>
          ))
        )}
      </div>
    </section>
  );
}
