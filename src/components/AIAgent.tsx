import { useState, useEffect, useRef } from "react";
import { Cpu, Server, Activity, RefreshCw, Key, Send, Zap, Network, ShieldAlert, Fingerprint } from "lucide-react";
import { API_BASE, WS_BASE, Token, apiGet } from "../utils/api";

type AnalysisResult = {
  summary: string;
  score: number;
  threats: string[];
  mitreMappings: string[];
};

type SystemData = {
  platform: string;
  cpu: string;
  cores: number;
  totalMem: string;
  freeMem: string;
  uptime: string;
  localIp: string;
  macAddress: string;
  subnet: string;
  gateway: string;
  dns: string;
  networkAdapter: string;
};

type TelemetryData = {
  system: SystemData;
  logs: any[];
  network: any[];
  rawNetwork: string;
  analysis: AnalysisResult;
};

type ChatMessage = {
  role: "user" | "model";
  text: string;
};

export default function AIAgent() {
  const [data, setData] = useState<TelemetryData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [liveStreamEnabled, setLiveStreamEnabled] = useState(true);

  const [apiKey, setApiKey] = useState("");
  const [showKeyInput, setShowKeyInput] = useState(false);

  // Copilot State
  const [chatInput, setChatInput] = useState("");
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>([]);
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatHistory]);

  const fetchTelemetry = async (silent = false) => {
    if (!silent) setLoading(true);
    setError(null);
    try {
      const json: TelemetryData = await apiGet('/api/analyze');
      
      if (apiKey && !silent) {
        try {
          const monitoredHost = json.system?.localIp || "the monitored host";
          const prompt = `You are a Tier 3 SOC Analyst AI trained on MITRE ATT&CK, NIST CSF, and advanced threat hunting. 
Your primary assigned system has the following Network Profile:
- Host IP: ${monitoredHost}
- MAC Address: ${json.system?.macAddress}

Analyze the following real Windows Event Logs and Network connections.
Return ONLY a valid JSON object with this exact structure: {"summary": "A detailed 2-3 sentence analysis string", "score": <integer from 0 to 100>, "threats": ["array of specific threat descriptions"], "mitreMappings": ["array of strings like 'TXXXX - Name'"]}. Do not include markdown formatting.\n\nLogs:\n${typeof json.logs === 'string' ? json.logs : JSON.stringify(json.logs, null, 2)}\n\nNetwork:\n${json.rawNetwork}`;
          
          const geminiRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
          });
          
          if (!geminiRes.ok) throw new Error("Gemini API request failed.");
          const geminiData = await geminiRes.json();
          let text = geminiData.candidates[0].content.parts[0].text;
          text = text.replace(/```json/g, '').replace(/```/g, '');
          const aiAnalysis = JSON.parse(text);
          json.analysis = aiAnalysis;
        } catch (aiErr: any) {
          console.error("AI Analysis failed, falling back to heuristic:", aiErr);
          json.analysis.summary = "[Gemini API Error - Using Heuristic Fallback] " + json.analysis.summary;
        }
      }

      setData(json);

    } catch (err: any) {
      setError("Failed to connect to Telemetry Agent. Ensure backend is running.");
    } finally {
      if (!silent) setLoading(false);
    }
  };

  // Real-time WebSocket connection for live telemetry tracking
  useEffect(() => {
    fetchTelemetry();
    let ws: WebSocket;
    let autoRefresh: NodeJS.Timeout;

    if (liveStreamEnabled) {
      ws = new WebSocket(WS_BASE);
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.event === 'telemetry_update' || msg.type === 'log') {
            // Silently refresh data to keep the dashboard "alive"
            fetchTelemetry(true);
          }
        } catch(err) {}
      };

      // Also setup a silent polling interval as a fallback backup for real-time tracking
      autoRefresh = setInterval(() => {
        fetchTelemetry(true);
      }, 10000); // every 10 seconds
    }

    return () => {
      if (ws) ws.close();
      if (autoRefresh) clearInterval(autoRefresh);
    };
  }, [liveStreamEnabled]);

  const sendChatMessage = async (msgText?: string) => {
    const text = msgText || chatInput;
    if (!text.trim()) return;
    
    setChatInput("");
    setChatHistory(prev => [...prev, { role: "user", text }]);
    setChatLoading(true);

    try {
      if (!apiKey) {
        setTimeout(() => {
          setChatHistory(prev => [...prev, { role: "model", text: "I am operating in offline heuristic mode. For conversational Co-pilot analysis, please provide a Google Gemini API Key." }]);
          setChatLoading(false);
        }, 800);
        return;
      }

      const contents = chatHistory.map(m => ({
        role: m.role,
        parts: [{ text: m.text }]
      }));
      contents.push({ role: "user", parts: [{ text: text }] });

      const systemInstruction = `You are Sentinel Copilot, an omniscient Tier 3 SOC Analyst AI inside a futuristic cyberpunk dashboard. Answer queries about the network and logs. Be hyper-analytical and concise.`;
      
      const geminiRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          systemInstruction: { parts: [{ text: systemInstruction }] },
          contents: contents 
        })
      });

      if (!geminiRes.ok) throw new Error("API Request Failed");
      const geminiData = await geminiRes.json();
      const reply = geminiData.candidates[0].content.parts[0].text;
      
      setChatHistory(prev => [...prev, { role: "model", text: reply }]);

    } catch (e) {
      setChatHistory(prev => [...prev, { role: "model", text: "Neural link severed. AI offline." }]);
    } finally {
      setChatLoading(false);
    }
  };

  const killProcess = async (pid: string) => {
    if (!confirm(`WARNING: Are you sure you want to forcefully terminate Process ID ${pid}?`)) return;
    try {
      const res = await fetch(`${API_BASE}/api/admin/kill-process`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${Token.getAccess()}`
        },
        body: JSON.stringify({ pid })
      });
      const resData = await res.json();
      if (resData.success) {
        alert(resData.message);
        fetchTelemetry();
      } else {
        alert("Failed to kill process: " + resData.error);
      }
    } catch (err) {
      alert("Error reaching Central Command: " + err);
    }
  };

  const saveKey = (val: string) => {
    setApiKey(val);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* Futuristic Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between glass-v2 p-5 rounded-3xl neon-border relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-50 scan-line" />
        <div className="relative z-10">
          <h2 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-indigo-400 to-purple-400 flex items-center gap-3 drop-shadow-[0_0_15px_rgba(34,211,238,0.5)]">
            <Cpu className="h-8 w-8 text-cyan-400 animate-pulse" />
            OMNISCIENT AI LIMIT
          </h2>
          <p className="text-sm text-cyan-200/60 font-mono mt-1 tracking-widest uppercase">
            Real-Time Neural Telemetry &amp; Threat Intelligence Engine
          </p>
        </div>
        <div className="flex items-center gap-3 relative z-10">
          <button
            onClick={() => setLiveStreamEnabled(!liveStreamEnabled)}
            className={`flex items-center gap-2 rounded-xl border px-4 py-2 text-sm font-bold font-mono transition-all duration-300 ${liveStreamEnabled ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-400 shadow-[0_0_15px_rgba(52,211,153,0.3)]' : 'bg-rose-500/20 border-rose-500/50 text-rose-400'}`}
          >
            <Activity className={`h-4 w-4 ${liveStreamEnabled ? 'animate-pulse' : ''}`} />
            {liveStreamEnabled ? "LIVE STREAM ACTIVE" : "STREAM PAUSED"}
          </button>
          <button
            onClick={() => setShowKeyInput(!showKeyInput)}
            className="flex items-center gap-2 rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 hover:bg-cyan-500/20 hover:shadow-[0_0_15px_rgba(34,211,238,0.3)] transition-all"
          >
            <Key className="h-4 w-4" />
            {apiKey ? "NEURAL KEY SYNCED" : "SYNC KEY"}
          </button>
          <button
            onClick={() => fetchTelemetry(false)}
            disabled={loading}
            className="flex items-center gap-2 rounded-xl border border-indigo-400/30 bg-indigo-500/10 px-4 py-2 text-sm font-medium text-indigo-200 transition hover:bg-indigo-500/20 disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            PULSE
          </button>
        </div>
      </div>

      {showKeyInput && (
        <div className="rounded-2xl border border-cyan-500/50 bg-cyan-900/20 p-5 flex items-center gap-4 shadow-[0_0_20px_rgba(34,211,238,0.15)] page-enter-3d">
          <Fingerprint className="h-8 w-8 text-cyan-400 shrink-0" />
          <div className="flex-1">
            <p className="text-sm font-bold text-cyan-300 mb-1 uppercase tracking-widest">Neural Link Authorization</p>
            <p className="text-xs text-cyan-200/60 mb-3 font-mono">Input Google Gemini API key to bypass heuristic limitations and enable full AI sentience.</p>
            <input 
              type="password" 
              placeholder="AIzaSy..." 
              value={apiKey}
              onChange={(e) => saveKey(e.target.value)}
              className="w-full max-w-xl rounded-xl border border-cyan-500/30 bg-black/60 px-4 py-3 text-sm text-cyan-100 placeholder-cyan-800 outline-none focus:border-cyan-400 focus:shadow-[0_0_15px_rgba(34,211,238,0.4)] transition-all font-mono"
            />
          </div>
        </div>
      )}

      {error && (
        <div className="glass-v2 border-rose-500/50 p-6 flex items-start gap-4 rounded-3xl shadow-[0_0_30px_rgba(244,63,94,0.2)]">
          <ShieldAlert className="h-8 w-8 text-rose-500 shrink-0 animate-pulse" />
          <div>
            <p className="text-lg font-black text-rose-400 uppercase tracking-widest">CRITICAL LINK FAILURE</p>
            <p className="text-rose-200 mt-1">{error}</p>
          </div>
        </div>
      )}

      {data && (
        <div className="grid gap-6 lg:grid-cols-12 items-start">
          
          {/* Main Cybernetic Panel */}
          <div className="lg:col-span-7 space-y-6">
            
            {/* Holographic 3D Assessment & Health Panel */}
            <div className={`glass-v2 rounded-3xl border p-6 relative overflow-hidden transition-all duration-500 ${(data.analysis?.score ?? 100) < 100 ? "border-rose-500/50 shadow-[0_0_40px_-5px_rgba(244,63,94,0.25)]" : "border-emerald-500/50 shadow-[0_0_40px_-5px_rgba(16,185,129,0.25)]"}`}>
              {/* Animated Background Mesh */}
              <div className="absolute inset-0 cyber-grid opacity-30 pointer-events-none" />
              
              <div className="flex flex-col md:flex-row items-center gap-6 relative z-10">
                {/* 3D Holo Sphere Core */}
                <div className="holo-threat-field w-48 h-48 shrink-0 rounded-2xl bg-black/40 border border-white/5 flex items-center justify-center">
                  <div className="holo-stage">
                    <div className="holo-orbit-stack">
                      <div className="holo-shell holo-shell-a" />
                      <div className="holo-shell holo-shell-b" />
                      <div className="holo-shell holo-shell-c" />
                      <div className="holo-core">
                        <span className="text-2xl font-black text-white text-glow">{data.analysis?.score ?? '100'}</span>
                      </div>
                      <div className="holo-node holo-node-safe" style={{ '--node-angle': '45deg', '--node-radius': '80px', '--node-depth': '20px' } as any} />
                      <div className="holo-node holo-node-threat" style={{ '--node-angle': '180deg', '--node-radius': '60px', '--node-depth': '-30px' } as any} />
                      <div className="holo-node holo-node-blocked" style={{ '--node-angle': '280deg', '--node-radius': '90px', '--node-depth': '10px' } as any} />
                    </div>
                  </div>
                </div>

                <div className="flex-1 space-y-4">
                  <h3 className="text-sm font-bold text-slate-400 uppercase tracking-[0.2em]">Live Neural Synthesis</h3>
                  <div className="rounded-2xl bg-black/60 p-4 border border-white/10 text-cyan-50 font-mono text-sm leading-relaxed holographic">
                    <span className="text-cyan-400 font-bold mr-2">&gt;_</span>
                    {data.analysis?.summary ?? "Awaiting neural matrix resolution..."}
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                    <div className="rounded-xl border border-sky-500/20 bg-sky-500/10 p-3">
                      <span className="text-sky-500 block mb-1">LOCAL_IP</span>
                      <span className="text-sky-200 font-bold text-sm">{data.system?.localIp || "---.---.---.---"}</span>
                    </div>
                    <div className="rounded-xl border border-purple-500/20 bg-purple-500/10 p-3">
                      <span className="text-purple-500 block mb-1">GATEWAY</span>
                      <span className="text-purple-200 font-bold text-sm">{data.system?.gateway || "---.---.---.---"}</span>
                    </div>
                  </div>
                </div>
              </div>

              {Array.isArray(data.analysis?.threats) && data.analysis.threats.length > 0 && (
                <div className="space-y-3 relative z-10 mt-6">
                  <p className="text-xs font-black text-rose-500 uppercase tracking-[0.3em] flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4" /> THREAT VECTORS DETECTED
                  </p>
                  {data.analysis.threats.map((threat, i) => (
                    <div key={i} className="flex items-center gap-4 rounded-2xl border border-rose-500/30 bg-gradient-to-r from-rose-500/10 to-transparent p-4 stat-card-3d">
                      <div className="h-2 w-2 rounded-full bg-rose-500 animate-ping" />
                      <p className="text-sm font-medium text-rose-100">{typeof threat === 'string' ? threat : JSON.stringify(threat)}</p>
                    </div>
                  ))}
                </div>
              )}

              {Array.isArray(data.analysis?.mitreMappings) && data.analysis.mitreMappings.length > 0 && (
                <div className="mt-6 space-y-3 relative z-10">
                  <p className="text-xs font-black text-indigo-400 uppercase tracking-[0.3em]">MITRE ATT&CK ALIGNMENT</p>
                  <div className="flex flex-wrap gap-2">
                    {data.analysis.mitreMappings.map((mitre, i) => (
                      <span key={i} className="rounded-lg border border-indigo-500/50 bg-indigo-500/20 px-3 py-1.5 text-xs font-mono font-bold text-indigo-200 shadow-[0_0_10px_rgba(99,102,241,0.2)]">
                        {typeof mitre === 'string' ? mitre : JSON.stringify(mitre)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Futuristic Telemetry Tables */}
            <div className="grid gap-6 md:grid-cols-2">
              {/* Network Matrix */}
              <div className="glass-v2 rounded-3xl border border-cyan-500/20 overflow-hidden flex flex-col h-[400px]">
                <div className="border-b border-cyan-500/20 bg-cyan-900/30 p-4 flex items-center justify-between">
                  <h3 className="flex items-center gap-2 text-sm font-black text-cyan-400 tracking-wider">
                    <Network className="h-4 w-4" /> NETWORK MATRIX
                  </h3>
                  <span className="flex h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
                </div>
                <div className="flex-1 overflow-auto custom-scrollbar">
                  <table className="w-full text-left text-xs font-mono text-cyan-100/70">
                    <thead className="sticky top-0 bg-black/80 backdrop-blur text-cyan-500">
                      <tr>
                        <th className="px-4 py-3 font-bold border-b border-cyan-500/20">TARGET</th>
                        <th className="px-4 py-3 font-bold border-b border-cyan-500/20">STATE</th>
                        <th className="px-4 py-3 font-bold border-b border-cyan-500/20 text-right">ACTION</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-cyan-500/10">
                      {(Array.isArray(data.network) ? data.network : []).map((conn: any, i: number) => {
                        const foreign = conn.foreign || '0.0.0.0';
                        const state = conn.state || '';
                        const pid = conn.pid || '0';
                        const isDanger = state === "ESTABLISHED" && !foreign.includes("192.168") && !foreign.includes("127.0");
                        
                        return (
                          <tr key={i} className={`hover:bg-cyan-500/10 transition-colors ${isDanger ? 'bg-rose-500/10' : ''}`}>
                            <td className="px-4 py-3 truncate max-w-[120px]" title={foreign}>{foreign}</td>
                            <td className="px-4 py-3">
                              {state && (
                                <span className={`px-1.5 py-0.5 rounded text-[9px] border ${state === 'LISTENING' ? 'bg-emerald-500/20 border-emerald-500/30 text-emerald-400' : 'bg-cyan-500/20 border-cyan-500/30 text-cyan-400'}`}>
                                  {state}
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-3 text-right">
                              {pid && pid !== "0" && pid !== "-" && (
                                <button
                                  onClick={() => killProcess(pid)}
                                  className="px-2 py-1 bg-rose-500/20 text-rose-400 border border-rose-500/50 rounded font-bold hover:bg-rose-500 hover:text-white transition-all shadow-[0_0_10px_rgba(244,63,94,0.3)] hover:shadow-[0_0_20px_rgba(244,63,94,0.6)]"
                                >
                                  TERM
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Event Log Stream */}
              <div className="glass-v2 rounded-3xl border border-purple-500/20 overflow-hidden flex flex-col h-[400px]">
                <div className="border-b border-purple-500/20 bg-purple-900/30 p-4 flex items-center justify-between">
                  <h3 className="flex items-center gap-2 text-sm font-black text-purple-400 tracking-wider">
                    <Server className="h-4 w-4" /> EVENT STREAM
                  </h3>
                  <div className="flex gap-1">
                    <div className="h-2 w-1 bg-purple-400 animate-pulse" />
                    <div className="h-2 w-1 bg-purple-400 animate-pulse" style={{ animationDelay: '100ms'}} />
                    <div className="h-2 w-1 bg-purple-400 animate-pulse" style={{ animationDelay: '200ms'}} />
                  </div>
                </div>
                <div className="flex-1 overflow-auto custom-scrollbar p-3 space-y-2 relative">
                  <div className="absolute inset-0 bg-gradient-to-b from-transparent to-black/80 pointer-events-none z-10" />
                  {(Array.isArray(data.logs) ? data.logs : []).slice(0, 50).map((log: any, i: number) => {
                    const id = log.Id ? log.Id.toString() : '?';
                    const level = log.LevelDisplayName || 'Info';
                    const desc = log.Message || '';
                    const isHighRisk = ['4625', '1102', '4688'].includes(id);

                    return (
                      <div key={i} className={`p-3 rounded-xl border flex flex-col gap-1.5 transition-all hover:translate-x-1 ${isHighRisk ? 'border-amber-500/40 bg-amber-500/10' : 'border-white/5 bg-black/40'}`}>
                        <div className="flex items-center gap-2">
                          <span className={`px-1.5 py-0.5 rounded-sm text-[10px] font-mono font-bold ${isHighRisk ? 'bg-amber-500 text-black' : 'bg-purple-500/20 text-purple-300'}`}>
                            ID:{id}
                          </span>
                          <span className={`text-xs font-bold ${isHighRisk ? 'text-amber-400' : 'text-slate-400'}`}>{level}</span>
                        </div>
                        <p className="text-[10px] text-slate-300 font-mono truncate">{desc}</p>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

          </div>

          {/* AI Copilot Chat Interface (Cyberpunk Edition) */}
          <div className="glass-v2 lg:col-span-5 h-[850px] flex flex-col rounded-3xl border border-cyan-500/40 glow-sky overflow-hidden relative">
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-cyan-900/20 via-transparent to-transparent pointer-events-none" />
            
            <div className="border-b border-cyan-500/30 bg-black/40 p-5 flex items-center justify-between relative z-10">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 rounded-full border-2 border-cyan-400 flex items-center justify-center bg-cyan-400/10 shadow-[0_0_15px_rgba(34,211,238,0.5)]">
                  <Cpu className="h-5 w-5 text-cyan-300" />
                </div>
                <div>
                  <h3 className="font-black text-cyan-300 tracking-widest text-lg">SENTINEL AI</h3>
                  <p className="text-[10px] text-cyan-500 font-mono uppercase">Tier 3 Cognitive Engine</p>
                </div>
              </div>
              <div className="flex gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" style={{ animationDelay: "150ms" }}></span>
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" style={{ animationDelay: "300ms" }}></span>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-5 space-y-6 custom-scrollbar relative z-10">
              {chatHistory.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center px-4">
                  <div className="relative mb-8">
                    <div className="absolute inset-0 bg-cyan-500/20 blur-2xl rounded-full" />
                    <Activity className="h-24 w-24 text-cyan-400 relative z-10 drop-shadow-[0_0_20px_rgba(34,211,238,0.8)] heartbeat" />
                  </div>
                  <p className="text-lg font-black text-cyan-100 tracking-wider">NEURAL LINK ESTABLISHED</p>
                  <p className="text-xs text-cyan-400/60 mt-2 font-mono max-w-[80%]">
                    Awaiting operator input. System is tracking live telemetry.
                  </p>
                  
                  <div className="mt-12 flex flex-col gap-3 w-full max-w-sm">
                    <button onClick={() => sendChatMessage("Analyze all external ESTABLISHED connections for C2 activity.")} className="rounded-xl border border-cyan-500/30 bg-black/50 py-3 px-4 text-xs font-mono text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400 transition-all text-left shadow-[0_0_15px_rgba(34,211,238,0.1)]">
                      <Zap className="inline h-4 w-4 mr-2 text-rose-400"/> Analyze external connections for C2
                    </button>
                    <button onClick={() => sendChatMessage("Correlate the Windows event logs with network traffic anomalies.")} className="rounded-xl border border-cyan-500/30 bg-black/50 py-3 px-4 text-xs font-mono text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400 transition-all text-left shadow-[0_0_15px_rgba(34,211,238,0.1)]">
                      <Zap className="inline h-4 w-4 mr-2 text-amber-400"/> Correlate logs with network traffic
                    </button>
                    <button onClick={() => sendChatMessage("Summarize system health and recommend immediate mitigations.")} className="rounded-xl border border-cyan-500/30 bg-black/50 py-3 px-4 text-xs font-mono text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400 transition-all text-left shadow-[0_0_15px_rgba(34,211,238,0.1)]">
                      <Zap className="inline h-4 w-4 mr-2 text-emerald-400"/> Recommend immediate mitigations
                    </button>
                  </div>
                </div>
              ) : (
                chatHistory.map((msg, i) => (
                  <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"} animate-in slide-in-from-bottom-2 duration-300`}>
                    <div className={`max-w-[85%] rounded-2xl p-4 text-sm leading-relaxed font-mono shadow-lg ${
                      msg.role === "user" 
                        ? "bg-gradient-to-br from-cyan-600 to-blue-700 text-white rounded-br-sm border border-cyan-400/50" 
                        : "bg-black/60 text-cyan-100 border border-cyan-500/30 rounded-bl-sm holographic"
                    }`}>
                      {msg.role === "model" && <span className="block text-[10px] text-cyan-400 mb-2 uppercase tracking-widest border-b border-cyan-500/30 pb-1">AI Output //</span>}
                      {msg.text}
                    </div>
                  </div>
                ))
              )}
              {chatLoading && (
                <div className="flex justify-start">
                  <div className="max-w-[85%] rounded-2xl bg-black/60 border border-cyan-500/30 p-5 rounded-bl-sm">
                    <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono">
                      <span>SYNTHESIZING</span>
                      <div className="flex gap-1 mt-0.5">
                        <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: "0ms" }}></div>
                        <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: "150ms" }}></div>
                        <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: "300ms" }}></div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            <div className="p-5 border-t border-cyan-500/30 bg-black/60 relative z-10 backdrop-blur-md">
              <form 
                onSubmit={(e) => { e.preventDefault(); sendChatMessage(); }}
                className="flex items-center gap-3 relative"
              >
                <div className="absolute left-4 top-1/2 -translate-y-1/2 text-cyan-500 font-mono text-sm">&gt;</div>
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  placeholder="Input command query..."
                  className="flex-1 rounded-xl border border-cyan-500/40 bg-black/50 pl-8 pr-4 py-3.5 text-sm font-mono text-cyan-100 placeholder-cyan-800 outline-none focus:border-cyan-400 focus:bg-cyan-900/20 focus:shadow-[0_0_15px_rgba(34,211,238,0.3)] transition-all"
                  disabled={chatLoading}
                />
                <button
                  type="submit"
                  disabled={!chatInput.trim() || chatLoading}
                  className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-cyan-500 text-black font-black transition hover:bg-cyan-400 hover:shadow-[0_0_20px_rgba(34,211,238,0.6)] disabled:opacity-50 disabled:hover:shadow-none"
                >
                  <Send className="h-5 w-5" />
                </button>
              </form>
            </div>
          </div>

        </div>
      )}
    </div>
  );
}

