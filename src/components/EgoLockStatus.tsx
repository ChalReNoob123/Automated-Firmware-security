import { useEffect, useState, useRef } from "react";
import { Fingerprint, Activity, Cpu } from "lucide-react";

export default function EgoLockStatus() {
  const containerRef = useRef<HTMLDivElement>(null);
  
  // Real-time tracking metrics
  const [mouseMetrics, setMouseMetrics] = useState({
    velocity: 0,
    acceleration: 0,
    curvature: 0.00
  });

  const [keystrokeProfile, setKeystrokeProfile] = useState({
    dwellTime: 82, // ms
    flightTime: 118, // ms
    rhythmCoherence: 98.4
  });

  const [identityStatus, setIdentityStatus] = useState({
    coherenceScore: 98.9,
    duressStatus: "CONTAINED",
    anomaliesDetected: 0
  });

  const lastPos = useRef({ x: 0, y: 0, time: Date.now() });
  const lastVelocity = useRef(0);

  // Mouse acceleration tracking hook
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      const currentTime = Date.now();
      const dt = (currentTime - lastPos.current.time) / 1000; // in seconds
      if (dt <= 0) return;

      const dx = e.clientX - lastPos.current.x;
      const dy = e.clientY - lastPos.current.y;
      const dist = Math.hypot(dx, dy);

      // Velocity in px/sec
      const velocity = dist / dt;
      
      // Acceleration in px/sec^2
      const dv = velocity - lastVelocity.current;
      const acceleration = dv / dt;

      // Curvature calculation approximation (angle change relative to path length)
      const angle = Math.atan2(dy, dx);
      const curvature = dist > 0 ? Math.abs(angle / dist) : 0;

      // Smooth metrics
      setMouseMetrics(prev => ({
        velocity: Math.round(prev.velocity * 0.8 + velocity * 0.2),
        acceleration: Math.round(prev.acceleration * 0.8 + acceleration * 0.2),
        curvature: parseFloat((prev.curvature * 0.8 + curvature * 0.2).toFixed(4))
      }));

      // Cache position and velocities
      lastPos.current = { x: e.clientX, y: e.clientY, time: currentTime };
      lastVelocity.current = velocity;

      // Periodically trigger a small mock threat coherence shift
      if (velocity > 1200) {
        setIdentityStatus(prev => {
          const score = Math.max(88, prev.coherenceScore - 0.05);
          return {
            coherenceScore: parseFloat(score.toFixed(1)),
            duressStatus: score < 92 ? "ELEVATED DURESS" : "CONTAINED",
            anomaliesDetected: score < 92 ? 1 : 0
          };
        });
      } else {
        setIdentityStatus(prev => {
          const score = Math.min(99.5, prev.coherenceScore + 0.02);
          return {
            ...prev,
            coherenceScore: parseFloat(score.toFixed(1)),
            duressStatus: score >= 95 ? "CONTAINED" : prev.duressStatus
          };
        });
      }
    };

    window.addEventListener("mousemove", handleMouseMove);
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
    };
  }, []);

  // Track keyboard metrics locally
  useEffect(() => {
    const handleKeyDown = () => {
      // Simulate keystroke rhythm calculations
      setKeystrokeProfile(() => {
        const dwell = Math.round(75 + Math.random() * 20);
        const flight = Math.round(105 + Math.random() * 30);
        const coherence = parseFloat((95 + Math.random() * 4.5).toFixed(1));
        return {
          dwellTime: dwell,
          flightTime: flight,
          rhythmCoherence: coherence
        };
      });
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, []);

  return (
    <div ref={containerRef} className="flex flex-col h-full bg-slate-950/70 border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-300 glass-panel">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Fingerprint className="h-4 w-4 text-cyan-400" />
          <span className="text-xs font-black uppercase tracking-wider text-slate-200">Segment Z: Ego-Lock Status</span>
        </div>
        <span className="text-[10px] text-cyan-400 font-bold bg-cyan-950/40 px-2 py-0.5 border border-cyan-800/50 rounded animate-pulse">
          IDENTITY IMMUTABLE
        </span>
      </div>

      <div className="flex-1 space-y-4 overflow-y-auto pr-1">
        
        {/* Core Identity coherence score */}
        <div className="border border-slate-800 bg-slate-950/40 rounded-lg p-3 space-y-3">
          <div className="flex justify-between items-center">
            <span className="text-[10px] text-slate-500 uppercase">Cognitive Coherence Engine</span>
            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${
              identityStatus.duressStatus !== 'CONTAINED'
                ? 'border-rose-500/30 bg-rose-500/10 text-rose-300 animate-pulse'
                : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
            }`}>
              {identityStatus.duressStatus}
            </span>
          </div>

          <div className="flex items-center gap-4">
            <div className="h-16 w-16 rounded-full border border-slate-800 flex items-center justify-center relative bg-slate-950">
              {/* Radial percentage glow circle */}
              <div 
                className="absolute inset-0.5 rounded-full border border-cyan-500/30" 
                style={{ clipPath: `polygon(50% 50%, -50% -50%, ${identityStatus.coherenceScore}% -50%)` }}
              />
              <span className="text-xs font-bold text-white">{identityStatus.coherenceScore}%</span>
            </div>
            <div className="flex-1 space-y-1">
              <div className="text-[10px] text-slate-400">Identity State: <strong className="text-emerald-400">COHERENT</strong></div>
              <div className="text-[9px] text-slate-500">Biometric signals match active analyst token footprint. Duress triggers set to silent containment.</div>
            </div>
          </div>
        </div>

        {/* Real-time Cursor Dynamics */}
        <div className="border border-slate-800 bg-slate-950/40 rounded-lg p-3 space-y-2.5">
          <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1.5 border-b border-slate-900 pb-1.5">
            <Activity className="h-3.5 w-3.5 text-cyan-400" />
            Real-time Cursor Acceleration Dynamics
          </div>
          
          <div className="space-y-1.5">
            <div className="flex justify-between">
              <span className="text-slate-500">VELOCITY:</span>
              <span className="text-white font-mono">{mouseMetrics.velocity} px/s</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">ACCEL:</span>
              <span className="text-white font-mono">{mouseMetrics.acceleration} px/s²</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">CURVATURE:</span>
              <span className="text-cyan-400 font-mono">{mouseMetrics.curvature.toFixed(4)} rad/px</span>
            </div>
          </div>
          
          <div className="text-[8px] text-slate-600 mt-1 leading-relaxed">
            * Move your cursor over the window to calculate real-time geometric curves, speed, and cognitive curvature index.
          </div>
        </div>

        {/* Keyboard Biometrics */}
        <div className="border border-slate-800 bg-slate-950/40 rounded-lg p-3 space-y-2.5">
          <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1.5 border-b border-slate-900 pb-1.5">
            <Cpu className="h-3.5 w-3.5 text-cyan-400" />
            Keystroke Rhythm Profile
          </div>
          
          <div className="grid grid-cols-2 gap-3 text-[10px]">
            <div className="bg-black/20 p-2 rounded border border-slate-900">
              <div className="text-slate-500 text-[8px] uppercase">Dwell Time</div>
              <div className="text-white font-bold text-sm mt-0.5">{keystrokeProfile.dwellTime} ms</div>
            </div>
            <div className="bg-black/20 p-2 rounded border border-slate-900">
              <div className="text-slate-500 text-[8px] uppercase">Flight Time</div>
              <div className="text-white font-bold text-sm mt-0.5">{keystrokeProfile.flightTime} ms</div>
            </div>
          </div>

          <div className="flex justify-between items-center text-[10px]">
            <span className="text-slate-500">Rhythm Coherence:</span>
            <span className="text-emerald-400 font-bold">{keystrokeProfile.rhythmCoherence}%</span>
          </div>
          <div className="text-[8px] text-slate-600 leading-relaxed">
            * Measures interval dynamics of raw typing patterns in focus fields.
          </div>
        </div>

      </div>
    </div>
  );
}
