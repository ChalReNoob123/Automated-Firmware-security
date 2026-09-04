import { useEffect, useRef, useState } from "react";
import { Terminal as TerminalIcon, Monitor, Activity, ShieldAlert, Cpu } from "lucide-react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { WS_BASE, Token } from "../utils/api";

export default function InteractiveVM() {
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<Terminal | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [status, setStatus] = useState<"disconnected" | "connecting" | "connected">("disconnected");

  useEffect(() => {
    if (!terminalRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      theme: {
        background: "#0f172a", // slate-900
        foreground: "#38bdf8", // sky-400
        cursor: "#38bdf8",
        selectionBackground: "rgba(56, 189, 248, 0.3)"
      },
      fontFamily: "'Fira Code', 'JetBrains Mono', monospace",
      fontSize: 14,
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalRef.current);
    fitAddon.fit();
    xtermRef.current = term;

    term.writeln("\x1b[1;36m[SentinelGrid] Neural VM Console Initialized.\x1b[0m");
    term.writeln("\x1b[1;30mAwaiting connection to Hypervisor...\x1b[0m");

    const connectWs = () => {
      setStatus("connecting");
      const token = Token.getAccess();
      if (!token) {
        term.writeln("\x1b[1;31m[ERROR] No authentication token found. Please re-login.\x1b[0m");
        setStatus("disconnected");
        return;
      }

      const ws = new WebSocket(WS_BASE);
      wsRef.current = ws;

      ws.onopen = () => {
        ws.send(JSON.stringify({ event: "auth", token }));
      };

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.event === "auth_ok") {
            setStatus("connected");
            term.writeln("\x1b[1;32m[OK] Authenticated. Spawning container shell...\x1b[0m");
            ws.send(JSON.stringify({ event: "terminal_start" }));
          } else if (msg.event === "terminal_output") {
            // Replace newlines with CRLF for xterm
            const formatted = String(msg.data).replace(/\r?\n/g, "\r\n");
            term.write(formatted);
          } else if (msg.event === "terminal_exit") {
            term.writeln(`\r\n\x1b[1;31m[WARN] Process exited with code ${msg.code}\x1b[0m`);
            setStatus("disconnected");
          }
        } catch (err) {
          // ignore
        }
      };

      ws.onclose = () => {
        setStatus("disconnected");
        term.writeln("\r\n\x1b[1;31m[DISCONNECTED] Hypervisor socket closed.\x1b[0m");
      };

      ws.onerror = () => {
        term.writeln("\r\n\x1b[1;31m[ERROR] Connection failure.\x1b[0m");
      };

      term.onData((data) => {
        if (ws.readyState === WebSocket.OPEN && status === "connected") {
          ws.send(JSON.stringify({ event: "terminal_input", data }));
        }
      });
    };

    connectWs();

    const resizeObserver = new ResizeObserver(() => {
      try {
        fitAddon.fit();
      } catch (e) {}
    });
    resizeObserver.observe(terminalRef.current);

    return () => {
      resizeObserver.disconnect();
      if (wsRef.current) {
        wsRef.current.send(JSON.stringify({ event: "terminal_stop" }));
        wsRef.current.close();
      }
      term.dispose();
    };
  }, []); // Run once on mount

  const handleReconnect = () => {
    if (wsRef.current) {
      wsRef.current.close();
    }
    // Effect will not re-run, so we manually reload the page or we could extract connect logic.
    // For simplicity, a page reload works best for terminal reset.
    window.location.reload();
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500 pb-20">
      <div className="relative glass-v2 rounded-[2rem] border border-cyan-500/20 p-6 shadow-2xl overflow-hidden group">
        <div className="absolute inset-0 holo-threat-field opacity-10 pointer-events-none group-hover:opacity-20 transition-opacity duration-700" />
        <div className="relative z-10 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-5">
            <div className="relative">
              <div className="h-14 w-14 rounded-2xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/30 breathe-glow">
                <TerminalIcon className="h-8 w-8 text-white" />
              </div>
              <div className="absolute -inset-1 rounded-2xl border border-cyan-400/30 animate-pulse" />
            </div>
            <div>
              <h2 className="text-3xl font-black text-white flex items-center gap-4 tracking-tight drop-shadow-md">
                INTERACTIVE VM CONSOLE
                <span className={`flex items-center gap-1.5 px-3 py-1 rounded-full border text-[10px] font-bold uppercase tracking-widest drop-shadow-[0_0_8px_rgba(34,211,238,0.5)] ${
                  status === "connected" ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400" :
                  status === "connecting" ? "bg-amber-500/10 border-amber-500/30 text-amber-400" :
                  "bg-rose-500/10 border-rose-500/30 text-rose-400"
                }`}>
                  <div className={`h-1.5 w-1.5 rounded-full ${status === "connected" ? "bg-cyan-400 animate-ping" : status === "connecting" ? "bg-amber-400 animate-pulse" : "bg-rose-400"}`} />
                  {status === "connected" ? "SESSION ACTIVE" : status === "connecting" ? "CONNECTING..." : "DISCONNECTED"}
                </span>
              </h2>
              <div className="flex items-center gap-4 mt-2 text-cyan-100/60 text-xs font-mono uppercase tracking-widest">
                <span className="flex items-center gap-1.5"><Monitor className="h-4 w-4" /> HOST_ACCESS</span>
                <span className="h-1 w-1 rounded-full bg-cyan-800" />
                <span className="flex items-center gap-1.5"><ShieldAlert className="h-4 w-4 text-rose-400" /> TRYHACKME STYLE SANDBOX</span>
              </div>
            </div>
          </div>
          <button
            onClick={handleReconnect}
            className="group relative flex items-center gap-3 rounded-2xl bg-black/40 border border-cyan-500/40 px-6 py-3 text-xs font-black tracking-widest text-cyan-300 shadow-lg hover:bg-cyan-500/20 hover:text-white transition-all duration-300 overflow-hidden shrink-0"
          >
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-cyan-400/10 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700 ease-in-out" />
            <Activity className="h-4 w-4" /> REBOOT INSTANCE
          </button>
        </div>
      </div>

      <div className="relative glass-v2 rounded-[2rem] border border-cyan-500/20 shadow-2xl overflow-hidden p-1 flex flex-col h-[650px]">
        <div className="absolute inset-0 cyber-grid opacity-10 pointer-events-none" />
        {/* Terminal Header */}
        <div className="relative z-10 flex items-center justify-between px-4 py-3 border-b border-cyan-500/20 bg-black/40 rounded-t-[1.5rem]">
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-cyan-400" />
            <span className="text-[10px] font-black tracking-widest text-cyan-200 uppercase">root@sentinel-vm:~</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-3 w-3 rounded-full bg-rose-500/80" />
            <div className="h-3 w-3 rounded-full bg-amber-500/80" />
            <div className="h-3 w-3 rounded-full bg-emerald-500/80" />
          </div>
        </div>
        
        {/* xterm container */}
        <div className="relative z-10 flex-1 bg-[#0f172a] rounded-b-[1.5rem] overflow-hidden p-2">
          <div ref={terminalRef} className="w-full h-full" />
        </div>
      </div>
    </div>
  );
}
