import { motion } from "framer-motion";
import { Activity, AlertTriangle, Network, Shield } from "lucide-react";
import type { CSSProperties } from "react";

type HoloThreatFieldProps = {
  threatPressure: number;
  maliciousCount: number;
  activeCount: number;
  blockedCount: number;
  containRate: number;
  wsOnline: boolean;
};

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

export default function HoloThreatField({
  threatPressure,
  maliciousCount,
  activeCount,
  blockedCount,
  containRate,
  wsOnline,
}: HoloThreatFieldProps) {
  const nodeCount = clamp(maliciousCount + activeCount, 5, 14);
  const threatTone =
    threatPressure >= 70
      ? "text-rose-300"
      : threatPressure >= 40
        ? "text-amber-300"
        : "text-emerald-300";

  return (
    <section className="holo-threat-field glass-v2 rounded-3xl p-5">
      <div className="relative z-10 flex w-full items-center justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.24em] text-slate-500">3D Threat Field</p>
          <p className="mt-1 text-sm font-bold text-white">Live spatial posture</p>
        </div>
        <div className={`flex items-center gap-2 rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider ${wsOnline ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-200" : "border-rose-400/30 bg-rose-400/10 text-rose-200"}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${wsOnline ? "bg-emerald-400 heartbeat" : "bg-rose-400"}`} />
          {wsOnline ? "Live" : "Offline"}
        </div>
      </div>

      <div className="holo-stage" aria-hidden="true">
        <div className="holo-orbit-stack">
          <div className="holo-shell holo-shell-a" />
          <div className="holo-shell holo-shell-b" />
          <div className="holo-shell holo-shell-c" />
          <div className="holo-core">
            <Shield className="h-8 w-8 text-cyan-100" />
          </div>
          {Array.from({ length: nodeCount }).map((_, index) => {
            const isThreat = index < maliciousCount;
            const isBlocked = index < blockedCount;
            const angle = Math.round((360 / nodeCount) * index);
            const radius = 58 + (index % 3) * 18;
            const depth = (index % 5) * 18 - 36;
            const style = {
              "--node-angle": `${angle}deg`,
              "--node-radius": `${radius}px`,
              "--node-depth": `${depth}px`,
              animationDelay: `${index * 0.2}s`,
            } as CSSProperties;

            return (
              <span
                key={`${angle}-${radius}`}
                className={`holo-node ${isThreat ? "holo-node-threat" : isBlocked ? "holo-node-blocked" : "holo-node-safe"}`}
                style={style}
              />
            );
          })}
        </div>
      </div>

      <div className="relative z-10 grid w-full grid-cols-3 gap-3">
        <motion.div whileHover={{ y: -3 }} className="rounded-2xl border border-white/10 bg-black/25 p-3 text-center">
          <AlertTriangle className="mx-auto mb-1 h-4 w-4 text-rose-300" />
          <p className={`text-lg font-black ${threatTone}`}>{threatPressure}</p>
          <p className="text-[9px] uppercase tracking-widest text-slate-500">Risk</p>
        </motion.div>
        <motion.div whileHover={{ y: -3 }} className="rounded-2xl border border-white/10 bg-black/25 p-3 text-center">
          <Network className="mx-auto mb-1 h-4 w-4 text-cyan-300" />
          <p className="text-lg font-black text-cyan-200">{activeCount}</p>
          <p className="text-[9px] uppercase tracking-widest text-slate-500">Active</p>
        </motion.div>
        <motion.div whileHover={{ y: -3 }} className="rounded-2xl border border-white/10 bg-black/25 p-3 text-center">
          <Activity className="mx-auto mb-1 h-4 w-4 text-emerald-300" />
          <p className="text-lg font-black text-emerald-200">{containRate}%</p>
          <p className="text-[9px] uppercase tracking-widest text-slate-500">Held</p>
        </motion.div>
      </div>
    </section>
  );
}
