import { useEffect, useRef, useState } from "react";
import { Terminal, ShieldAlert, Cpu, Eye, Database, FileText, RefreshCw, ZapOff } from "lucide-react";

interface LabEngineInterfaceProps {
  vmId: string;
  vmName: string;
  onThreatChange?: (newThreat: "green" | "yellow" | "red") => void;
}

interface ProcessItem {
  pid: number;
  name: string;
  integrity: string;
  command_line?: string;
  suspicious?: boolean;
}

interface RamDumpData {
  dump_file: string;
  size_bytes: number;
  analyzed_processes: ProcessItem[];
  carved_strings: string[];
}

export default function LabEngineInterface({ vmId, vmName, onThreatChange }: LabEngineInterfaceProps) {
  const [, setVmStatus] = useState<string>("running");
  const [metrics, setMetrics] = useState({
    cpu: 12,
    ram: "1512MB",
    disk_read: "0.2 MB/s",
    disk_write: "0.1 MB/s",
    network_tx: "12 KB/s",
    network_rx: "105 KB/s"
  });

  const [logs, setLogs] = useState<{ time: string; source: string; event_id: number; desc: string }[]>([]);
  const [payloadType, setPayloadType] = useState<string>("ransomware_wanna_cry");
  const [injectStatus, setInjectStatus] = useState<string | null>(null);
  
  // Terminal state
  const [cmdHistory, setCmdHistory] = useState<string[]>([
    "System security terminal online...",
    "establishing TLS secure session to guest supervisor...",
    "Connection active. Type help for commands."
  ]);
  const [currentCmd, setCurrentCmd] = useState<string>("");
  
  // Forensic RAM Dump states
  const [ramDump, setRamDump] = useState<RamDumpData | null>(null);
  const [dumpLoading, setDumpLoading] = useState(false);
  
  // Network isolation state
  const [networkShattered, setNetworkShattered] = useState(false);

  const socketRef = useRef<WebSocket | null>(null);
  const consoleBottomRef = useRef<HTMLDivElement>(null);

  // Auto scroll console
  useEffect(() => {
    if (consoleBottomRef.current) {
      consoleBottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [cmdHistory, logs]);

  // Connect to Python virtualization websocket stream
  useEffect(() => {
    // Connect to port 3002
    const wsUrl = `ws://localhost:3002/ws/vm-stream`;
    const socket = new WebSocket(wsUrl);
    socketRef.current = socket;

    socket.onopen = () => {
      // Send VM ID selection init
      socket.send(JSON.stringify({ vm_id: vmId }));
    };

    socket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "init") {
        setVmStatus(data.vm.status);
        setMetrics(prev => ({ ...prev, ram: data.vm.ram_usage }));
        if (data.vm.logs) {
          setLogs(data.vm.logs);
        }
      } else if (data.type === "telemetry") {
        if (!networkShattered) {
          setMetrics(data.metrics);
        }
      } else if (data.type === "new_log") {
        setLogs(prev => [...prev.slice(-15), data.log]);
      } else if (data.type === "terminal_output") {
        setCmdHistory(prev => [...prev, data.output]);
      }
    };

    socket.onerror = (err) => {
      console.warn("FastAPI WebSocket connection error:", err);
    };

    return () => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.close();
      }
    };
  }, [vmId, networkShattered]);

  const runCommand = () => {
    if (!currentCmd.trim()) return;
    setCmdHistory(prev => [...prev, `GuestOS@localhost:~$ ${currentCmd}`]);
    
    // Send to websocket if open
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      socketRef.current.send(JSON.stringify({
        type: "command",
        command: currentCmd
      }));
    } else {
      // Mock command locally
      const cmd = currentCmd.toLowerCase();
      setTimeout(() => {
        let resp = "Command output unavailable (virtualization core offline)";
        if (cmd === "help") {
          resp = "Supported: whoami, ipconfig, ls, clear";
        } else if (cmd === "whoami") {
          resp = "guest_analyst";
        } else if (cmd === "clear") {
          setCmdHistory([]);
          setCurrentCmd("");
          return;
        }
        setCmdHistory(prev => [...prev, resp]);
      }, 200);
    }
    setCurrentCmd("");
  };

  const handleInject = async () => {
    setInjectStatus("Delivering payload package...");
    try {
      const response = await fetch("http://localhost:3002/api/vm/inject", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: vmId, payload: payloadType })
      });
      const data = await response.json();
      if (response.ok) {
        setInjectStatus("Payload detonated! Active process monitored.");
        if (onThreatChange) onThreatChange("red");
        // Force refresh state or append logs
        if (data.triggered_logs) {
          setLogs(prev => [...prev, ...data.triggered_logs]);
        }
      } else {
        setInjectStatus(`Detonation failed: ${data.detail || "Server error"}`);
      }
    } catch (err) {
      setInjectStatus("Error communicating with detonator server.");
    }
  };

  const handleRamDump = async () => {
    setDumpLoading(true);
    setRamDump(null);
    try {
      const response = await fetch("http://localhost:3002/api/vm/ramdump", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: vmId })
      });
      const data = await response.json();
      if (response.ok) {
        setRamDump(data);
      } else {
        alert(data.detail || "Failed to parse RAM telemetry");
      }
    } catch (err) {
      alert("Error dumping RAM. Ensure virtualization server is active.");
    } finally {
      setDumpLoading(false);
    }
  };

  const toggleNetworkShatter = () => {
    const nextState = !networkShattered;
    setNetworkShattered(nextState);
    if (nextState) {
      setMetrics({
        cpu: 1,
        ram: "1024MB",
        disk_read: "0.0 MB/s",
        disk_write: "0.0 MB/s",
        network_tx: "0.0 KB/s",
        network_rx: "0.0 KB/s"
      });
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-950/70 border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-300 glass-panel">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-cyan-400" />
          <span className="text-xs font-black uppercase tracking-wider text-slate-200">Segment X: Lab Engine Interface</span>
        </div>
        <div className="flex items-center gap-2.5">
          <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-[10px] text-emerald-400 uppercase">QCOW2 Dynamic Swapping</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 flex-1 min-h-0">
        {/* Live console display screen */}
        <div className="lg:col-span-2 flex flex-col border border-slate-800 rounded-lg bg-black/60 overflow-hidden min-h-[220px]">
          <div className="flex items-center justify-between bg-slate-950/80 border-b border-slate-800/80 px-3 py-2 text-[10px]">
            <span className="text-slate-400 uppercase">Interactive Guest Console ({vmName})</span>
            <span className="text-slate-600">Baudrate: 115200 bps</span>
          </div>
          
          <div className="flex-1 p-3 overflow-y-auto font-mono text-[11px] leading-relaxed text-cyan-300/90 space-y-1 bg-[#010307]">
            {cmdHistory.map((line, idx) => (
              <div key={idx} className="whitespace-pre-wrap">{line}</div>
            ))}
            <div ref={consoleBottomRef} />
          </div>

          <div className="flex border-t border-slate-800 bg-slate-950/90 h-9 items-center px-2.5">
            <span className="text-slate-500 mr-2">$</span>
            <input
              type="text"
              value={currentCmd}
              onChange={(e) => setCurrentCmd(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && runCommand()}
              placeholder="Enter console commands..."
              className="flex-1 bg-transparent text-white outline-none border-none text-[11px] placeholder:text-slate-700"
            />
            <button onClick={runCommand} className="text-cyan-400 hover:text-white px-2 py-1 text-[9px] uppercase font-bold">
              Run
            </button>
          </div>
        </div>

        {/* Controls Sidebar */}
        <div className="flex flex-col gap-3 min-h-0 overflow-y-auto">
          
          {/* Telemetry metrics display */}
          <div className="border border-slate-800/80 bg-slate-950/40 rounded-lg p-3 space-y-2">
            <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1.5">
              <Cpu className="h-3 w-3" />
              Live Telemetry Stream
            </div>
            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div>CPU: <strong className="text-white font-mono">{metrics.cpu}%</strong></div>
              <div>RAM: <strong className="text-white font-mono">{metrics.ram}</strong></div>
              <div>Disk W: <strong className="text-white font-mono">{metrics.disk_write}</strong></div>
              <div>Net Rx: <strong className="text-white font-mono">{metrics.network_rx}</strong></div>
            </div>
          </div>

          {/* Payload Detonation Block */}
          <div className="border border-slate-800/80 bg-slate-950/40 rounded-lg p-3 space-y-3">
            <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1.5">
              <ShieldAlert className="h-3 w-3 text-rose-400" />
              Payload Detonation Core
            </div>
            
            <select
              value={payloadType}
              onChange={(e) => setPayloadType(e.target.value)}
              className="w-full h-8 px-2 rounded bg-slate-950 border border-slate-800 text-[11px] text-white focus:outline-none focus:border-cyan-400"
            >
              <option value="ransomware_wanna_cry">WannaCry Ransomware Simulator</option>
              <option value="spyware_agent">Pegasus Keylogger/Spyware Agent</option>
              <option value="reverse_shell_listener">Netcat Reverse Shell Exploit</option>
              <option value="kernel_rootkit">LVM-DTC Ring0 Privilege Rootkit</option>
            </select>

            <button
              onClick={handleInject}
              className="w-full h-8 rounded bg-rose-600/30 border border-rose-500/50 hover:bg-rose-600/60 text-rose-100 font-bold hover:scale-[1.01] active:scale-[0.99] transition-transform text-[10px] uppercase tracking-wider"
            >
              Detonate Payload
            </button>
            {injectStatus && (
              <div className="text-[9px] text-amber-400 animate-pulse leading-snug">{injectStatus}</div>
            )}
          </div>

          {/* Forensics controls */}
          <div className="flex gap-2">
            <button
              onClick={handleRamDump}
              disabled={dumpLoading}
              className="flex-1 h-8 rounded bg-cyan-600/20 border border-cyan-500/30 hover:bg-cyan-600/40 text-cyan-200 font-bold text-[9px] uppercase tracking-wider flex items-center justify-center gap-1.5"
            >
              <Eye className="h-3 w-3" />
              {dumpLoading ? "Dumping..." : "RAM Forensics"}
            </button>
            
            <button
              onClick={toggleNetworkShatter}
              className={`flex-1 h-8 rounded font-bold text-[9px] uppercase tracking-wider flex items-center justify-center gap-1.5 border transition-colors ${
                networkShattered
                  ? "bg-emerald-600/20 border-emerald-500/40 text-emerald-200"
                  : "bg-slate-800/40 border-slate-700 text-slate-400 hover:bg-rose-950/20 hover:border-rose-800"
              }`}
            >
              {networkShattered ? (
                <>
                  <RefreshCw className="h-3 w-3 animate-spin" />
                  Restore Link
                </>
              ) : (
                <>
                  <ZapOff className="h-3 w-3" />
                  Shatter Net
                </>
              )}
            </button>
          </div>

        </div>
      </div>

      {/* Volatile RAM dump outputs */}
      {ramDump && (
        <div className="border border-slate-800 bg-slate-950/90 rounded-lg p-3 mt-3 space-y-2 animate-fade-in max-h-[160px] overflow-y-auto">
          <div className="flex items-center justify-between border-b border-slate-800 pb-1.5">
            <span className="text-[10px] text-cyan-400 font-bold uppercase">RAM Dump Carving Analysis</span>
            <span className="text-[9px] text-slate-600 font-mono">Dump: {ramDump.dump_file}</span>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-[10px]">
            {/* Suspicious Processes */}
            <div>
              <div className="text-slate-500 font-bold uppercase mb-1 flex items-center gap-1"><Database className="h-3 w-3" /> Running Processes</div>
              <ul className="space-y-1">
                {ramDump.analyzed_processes.map((proc, i) => (
                  <li key={i} className={`flex flex-col p-1 rounded ${proc.suspicious ? 'bg-rose-950/30 border border-rose-800/50' : 'bg-black/20'}`}>
                    <div className="flex justify-between font-bold">
                      <span className={proc.suspicious ? 'text-rose-400' : 'text-slate-300'}>PID {proc.pid}: {proc.name}</span>
                      <span className="text-slate-500 text-[8px]">{proc.integrity}</span>
                    </div>
                    {proc.command_line && (
                      <span className="text-slate-500 text-[8px] break-all truncate font-mono mt-0.5">{proc.command_line}</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
            
            {/* Carved Indicator Strings */}
            <div>
              <div className="text-slate-500 font-bold uppercase mb-1 flex items-center gap-1"><FileText className="h-3 w-3" /> Decrypted Carved Strings</div>
              <ul className="space-y-1 list-disc list-inside">
                {ramDump.carved_strings.map((str, i) => (
                  <li key={i} className="text-slate-400 font-mono text-[9px] break-all select-all hover:text-white cursor-pointer">{str}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Ingress Live Logs Stream */}
      <div className="border border-slate-800/80 bg-slate-950/40 rounded-lg p-2.5 mt-3 max-h-[110px] overflow-y-auto">
        <div className="text-[9px] text-slate-500 uppercase tracking-wider mb-1 flex items-center gap-1"><Eye className="h-3 w-3" /> Kernel Call telemetry logs</div>
        <div className="space-y-1 font-mono text-[9px]">
          {logs.map((log, i) => (
            <div key={i} className="flex justify-between items-start leading-relaxed text-slate-400 py-0.5 border-b border-slate-900 last:border-0">
              <span className="text-slate-600 shrink-0">{log.time}</span>
              <span className="text-cyan-400/80 px-2 shrink-0">{log.source}</span>
              <span className="text-slate-500 font-bold shrink-0">{log.event_id}</span>
              <span className="text-slate-300 text-left flex-1 pl-3 break-words">{log.desc}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
