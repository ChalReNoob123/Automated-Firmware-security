import { useState } from "react";
import { Clock, History, AlertTriangle, ArrowLeftRight } from "lucide-react";

interface ChronoMonitorProps {
  vmId: string;
  vmName: string;
  onRollbackSuccess?: () => void;
}

interface Checkpoint {
  id: string;
  timestamp: string;
  label: string;
  description: string;
  size: string;
  type: "clean" | "malicious" | "intermediate";
}

export default function ChronoMonitor({ vmId, vmName, onRollbackSuccess }: ChronoMonitorProps) {
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const [checkpoints] = useState<Checkpoint[]>([
    { id: "cp_0", timestamp: "10:15:00", label: "0x00FF8E12 (Baseline)", description: "Initial clean installation guest OS baseline config", size: "1.4 GB", type: "clean" },
    { id: "cp_1", timestamp: "10:35:12", label: "0x011A89FB (Patch Applied)", description: "Microsoft KB5039212 security patch applied", size: "280 MB", type: "clean" },
    { id: "cp_2", timestamp: "11:02:44", label: "0x028FA4B0 (Service Active)", description: "SOC telemetry agents & auditd rules initialized", size: "84 MB", type: "clean" },
    { id: "cp_3", timestamp: "11:22:15", label: "0x03FF00A2 (Exploited)", description: "Pre-detonation marker prior to malware payload delivery", size: "12 MB", type: "malicious" }
  ]);

  const handleRollback = async () => {
    setLoading(true);
    setStatusMsg("Initiating Time-Inversion transaction...");
    try {
      const response = await fetch("http://localhost:3002/api/vm/rollback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: vmId })
      });
      const data = await response.json();
      if (response.ok) {
        setStatusMsg("State reverted! Cleared QCOW2 memory overlays.");
        if (onRollbackSuccess) onRollbackSuccess();
      } else {
        setStatusMsg(`Rollback failed: ${data.detail || "Server error"}`);
      }
    } catch (err) {
      setStatusMsg("Error connecting to virtualization server.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-950/70 border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-300 glass-panel">
      {/* HUD Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Clock className="h-4 w-4 text-cyan-400" />
          <span className="text-xs font-black uppercase tracking-wider text-slate-200">Segment W: Chrono Monitor</span>
        </div>
        <span className="text-[10px] text-cyan-400 font-bold bg-cyan-950/40 px-2 py-0.5 border border-cyan-800/50 rounded">
          TISET ACTIVE
        </span>
      </div>

      <div className="flex-1 space-y-4 overflow-y-auto pr-1">
        {/* Info panel */}
        <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 space-y-1.5">
          <div className="text-[10px] text-slate-500 uppercase">Target Node Context</div>
          <div className="text-white font-bold">{vmName} ({vmId})</div>
          <div className="text-slate-400 leading-relaxed text-[11px]">
            The Time-Inversion State Engine (TISET) maintains a transaction log of differential disk writes in QCOW2 overlays. You can invert time to discard modifications instantly.
          </div>
        </div>

        {/* Delta Metrics */}
        <div className="grid grid-cols-2 gap-2.5">
          <div className="border border-slate-800 bg-slate-950/40 rounded p-2.5">
            <div className="text-slate-500 text-[9px] uppercase">Dirty Disk Blocks</div>
            <div className="text-cyan-400 font-bold text-sm mt-1">42,810 blocks</div>
            <div className="text-[9px] text-slate-600 mt-0.5">Approx 167 MB delta</div>
          </div>
          <div className="border border-slate-800 bg-slate-950/40 rounded p-2.5">
            <div className="text-slate-500 text-[9px] uppercase">RAM Commit Delta</div>
            <div className="text-amber-400 font-bold text-sm mt-1">394 MB</div>
            <div className="text-[9px] text-slate-600 mt-0.5">Volatile memory changes</div>
          </div>
        </div>

        {/* Timeline of snapshots */}
        <div className="space-y-2">
          <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1.5 mb-2">
            <History className="h-3 w-3" />
            Historical State Snapshots
          </div>
          
          <div className="space-y-2 border-l border-slate-800 pl-4 ml-2">
            {checkpoints.map((cp) => (
              <div key={cp.id} className="relative group">
                {/* Timeline node */}
                <div className={`absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full border ${
                  cp.type === "malicious"
                    ? "bg-rose-500 border-rose-400 shadow-[0_0_8px_rgba(244,63,94,0.4)]"
                    : "bg-slate-950 border-slate-700 group-hover:border-cyan-400"
                }`} />

                <div className="flex justify-between items-start">
                  <div className="font-bold text-[10px] text-slate-200">{cp.label}</div>
                  <div className="text-slate-600 text-[9px]">{cp.timestamp}</div>
                </div>
                <div className="text-slate-400 text-[9px] mt-0.5">{cp.description}</div>
                <div className="text-slate-500 text-[8px] mt-0.5">Sector Size: {cp.size}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Control Box */}
      <div className="border-t border-slate-800/80 pt-4 mt-3 space-y-3">
        {statusMsg && (
          <div className="p-2 border border-cyan-800/50 bg-cyan-950/30 rounded text-cyan-200 text-[10px] leading-relaxed flex items-start gap-1.5 animate-pulse">
            <AlertTriangle className="h-3.5 w-3.5 text-cyan-400 shrink-0 mt-0.5" />
            <span>{statusMsg}</span>
          </div>
        )}

        <button
          onClick={handleRollback}
          disabled={loading}
          className="w-full flex items-center justify-center gap-2 h-10 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-bold tracking-wider hover:scale-[1.01] active:scale-[0.99] disabled:opacity-50 disabled:cursor-not-allowed text-[11px] uppercase shadow-lg shadow-cyan-950/30"
        >
          {loading ? (
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-white animate-ping" />
              INVERTING STATE...
            </span>
          ) : (
            <>
              <ArrowLeftRight className="h-3.5 w-3.5" />
              Reverse Target Time (Rollback)
            </>
          )}
        </button>
        <div className="text-center text-[9px] text-slate-600">
          WARNING: Instantly reverts guest OS and drops uncommitted volatile memories.
        </div>
      </div>
    </div>
  );
}
