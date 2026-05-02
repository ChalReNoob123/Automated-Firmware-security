import { useState, useEffect, useRef } from "react";
import { Cpu, Server, Activity, AlertTriangle, RefreshCw, CheckCircle, Key, Send, MessageSquare, Zap, Network, Wifi } from "lucide-react";

import { API_BASE, Token, apiGet } from "../utils/api";

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

  const fetchTelemetry = async () => {
    setLoading(true);
    setError(null);
    try {
      const json: TelemetryData = await apiGet('/api/analyze');

      
      if (apiKey) {
        try {
          const monitoredHost = json.system?.localIp || "the monitored host";
          const prompt = `You are a Tier 3 SOC Analyst AI trained on MITRE ATT&CK, NIST CSF, and advanced threat hunting. 
Your primary assigned system has the following Network Profile:
- Host IP: ${monitoredHost}
- MAC Address: ${json.system?.macAddress}
- Subnet Mask: ${json.system?.subnet}
- Default Gateway: ${json.system?.gateway}
- Authorized DNS Servers: ${json.system?.dns}
- Network Adapter: ${json.system?.networkAdapter}

Analyze the following real Windows Event Logs and Network connections.

CRITICAL TRAINING INSTRUCTIONS:
1. Cross-reference the Host IP (${monitoredHost}) with the netstat connections to distinguish internal loopback traffic from external connections.
2. Be vigilant for strange ports, lateral movement, or unauthorized external connections to/from ${monitoredHost}, but do not claim malicious activity unless the supplied telemetry supports it.
3. Verify that outbound traffic is routing properly and flag any potential rogue DNS queries or connections attempting to bypass the gateway (${json.system?.gateway}).
4. Look for failed logons, cleared audit logs, or privilege escalation in the event logs.

Return ONLY a valid JSON object with this exact structure: {"summary": "A detailed 2-3 sentence analysis string", "score": <integer from 0 to 100 representing security health>, "threats": ["array of specific threat descriptions"], "mitreMappings": ["array of strings like 'TXXXX - Name'"]}. Do not include markdown formatting.\n\nLogs:\n${typeof json.logs === 'string' ? json.logs : JSON.stringify(json.logs, null, 2)}\n\nNetwork:\n${json.rawNetwork}`;
          
          const geminiRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
          });
          
          if (!geminiRes.ok) throw new Error("Gemini API request failed. Check your API key.");
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
      setError("Failed to connect to Local Telemetry Agent. Ensure 'node backend.js' is running in a separate terminal.");
    } finally {
      setLoading(false);
    }
  };

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

      const systemInstruction = `You are Sentinel Copilot, a Tier 3 SOC Analyst AI. You are assisting a security operator. You have access to telemetry from the host:\nHost IP Address: ${data?.system?.localIp || "unknown"}\nGateway: ${data?.system?.gateway}\nAuthorized DNS: ${data?.system?.dns}\nLogs: ${typeof data?.logs === 'string' ? data?.logs : JSON.stringify(data?.logs)}\nNetwork: ${data?.network}\nAnalyze questions using only this context. Cross-reference the host IP and network profile when analyzing connections. Flag DNS hijacking or lateral movement only when telemetry supports it. Be concise, technical, and explicit about uncertainty.`;
      
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
      setChatHistory(prev => [...prev, { role: "model", text: "Failed to connect to AI engine. Check your API key or network connection." }]);
    } finally {
      setChatLoading(false);
    }
  };

  const killProcess = async (pid: string) => {
    if (!confirm(`WARNING: Are you sure you want to forcefully terminate Process ID ${pid}?`)) return;
    try {
      const res = await fetch(`${API_BASE}/api/kill-process`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${Token.getAccess()}`
        },
        body: JSON.stringify({ pid })
      });
      const data = await res.json();
      if (data.success) {
        alert(data.message);
        fetchTelemetry(); // Refresh the table
      } else {
        alert("Failed to kill process: " + data.error);
      }
    } catch (err) {
      alert("Error reaching Central Command: " + err);
    }
  };

  const saveKey = (val: string) => {
    setApiKey(val);
  };

  useEffect(() => {
    fetchTelemetry();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Cpu className="h-5 w-5 text-indigo-400" />
            Sentinel AI: Real-Time Host Telemetry & Copilot
          </h2>
          <p className="text-sm text-slate-400">
            Ingesting live Windows Security Logs and Network Connections for interactive AI analysis.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowKeyInput(!showKeyInput)}
            className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-medium text-slate-300 transition hover:bg-white/10"
          >
            <Key className="h-4 w-4" />
            {apiKey ? "API Key Active" : "Connect AI"}
          </button>
          <button
            onClick={fetchTelemetry}
            disabled={loading}
            className="flex items-center gap-2 rounded-xl border border-indigo-400/30 bg-indigo-500/10 px-4 py-2 text-sm font-medium text-indigo-200 transition hover:bg-indigo-500/20 disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            {loading ? "Scanning..." : "Re-Scan Host"}
          </button>
        </div>
      </div>

      {showKeyInput && (
        <div className="rounded-2xl border border-indigo-500/30 bg-indigo-500/5 p-4 flex items-center gap-4">
          <Key className="h-5 w-5 text-indigo-400 shrink-0" />
          <div className="flex-1">
            <p className="text-sm font-semibold text-indigo-200 mb-1">Unlock Copilot Features</p>
            <p className="text-xs text-slate-400 mb-3">Provide a Google Gemini API key for this browser session to enable Copilot. If left blank, the system uses a local heuristic fallback engine.</p>
            <input 
              type="password" 
              placeholder="AIzaSy..." 
              value={apiKey}
              onChange={(e) => saveKey(e.target.value)}
              className="w-full max-w-md rounded-xl border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder-slate-600 outline-none focus:border-indigo-500/50"
            />
          </div>
        </div>
      )}

      {error && (
        <div className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-5 flex items-start gap-4">
          <AlertTriangle className="h-6 w-6 text-rose-400 shrink-0" />
          <div>
            <p className="font-bold text-rose-200">Agent Disconnected</p>
            <p className="text-sm text-rose-300/80 mt-1">{error}</p>
            <div className="mt-3 rounded border border-rose-500/20 bg-black/40 p-3 font-mono text-xs text-slate-300">
              node backend.js
            </div>
          </div>
        </div>
      )}

      {data && (
        <div className="grid gap-6 lg:grid-cols-12 items-start">
          
          {/* Main Health Panel */}
          <div className="lg:col-span-7 space-y-6">
            {/* System Backend Data Widget */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="rounded-2xl border border-white/10 bg-black/20 p-3 flex flex-col justify-between col-span-2 md:col-span-1">
                <Wifi className="h-4 w-4 text-slate-500 mb-2" />
                <p className="text-[10px] uppercase tracking-widest text-slate-500">Adapter</p>
                <p className="text-sm font-semibold text-slate-200 truncate" title={data.system?.networkAdapter}>{data.system?.networkAdapter || "Unknown"}</p>
              </div>
              <div className="rounded-2xl border border-sky-500/30 bg-sky-500/10 p-3 flex flex-col justify-between">
                <Activity className="h-4 w-4 text-sky-400 mb-2" />
                <p className="text-[10px] uppercase tracking-widest text-sky-400/70">Assigned IPv4</p>
                <p className="text-sm font-semibold text-sky-300 truncate">{data.system?.localIp || "192.168.1.34"}</p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/20 p-3 flex flex-col justify-between">
                <Network className="h-4 w-4 text-slate-500 mb-2" />
                <p className="text-[10px] uppercase tracking-widest text-slate-500">Gateway</p>
                <p className="text-sm font-semibold text-slate-200 truncate">{data.system?.gateway || "Unknown"}</p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/20 p-3 flex flex-col justify-between">
                <Server className="h-4 w-4 text-slate-500 mb-2" />
                <p className="text-[10px] uppercase tracking-widest text-slate-500">DNS Servers</p>
                <p className="text-sm font-semibold text-slate-200 truncate" title={data.system?.dns}>{data.system?.dns || "Unknown"}</p>
              </div>
            </div>

            <div className={`glass-panel rounded-3xl border p-6 transition-all duration-300 hover:scale-[1.01] ${(data.analysis?.score ?? 100) < 100 ? "border-amber-500/50 bg-gradient-to-br from-amber-500/20 to-transparent shadow-[0_0_30px_-5px_rgba(245,158,11,0.3)]" : "border-emerald-500/50 bg-gradient-to-br from-emerald-500/20 to-transparent shadow-[0_0_30px_-5px_rgba(16,185,129,0.3)]"}`}>
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div className={`flex h-12 w-12 items-center justify-center rounded-xl bg-black/40 border shadow-inner ${(data.analysis?.score ?? 100) < 100 ? "border-amber-500/50" : "border-emerald-500/50"}`}>
                    {(data.analysis?.score ?? 100) < 100 ? <AlertTriangle className="h-6 w-6 text-amber-400 drop-shadow-[0_0_8px_rgba(251,191,36,0.8)]" /> : <CheckCircle className="h-6 w-6 text-emerald-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.8)]" />}
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-slate-400 uppercase tracking-widest">System Posture</p>
                    <p className="text-2xl font-bold text-white text-glow">Score: {data.analysis?.score ?? 'N/A'} / 100</p>
                  </div>
                </div>
              </div>

              <div className="mb-6 rounded-2xl bg-black/40 p-4 border border-white/5 text-slate-200 leading-relaxed">
                <span className="text-indigo-400 font-bold mr-2">Auto-Analysis:</span>
                {data.analysis?.summary ?? "Analysis missing."}
              </div>

              {Array.isArray(data.analysis?.threats) && data.analysis.threats.length > 0 && (
                <div className="space-y-3">
                  <p className="text-xs font-semibold text-rose-400 uppercase tracking-widest">Detected Anomalies</p>
                  {data.analysis.threats.map((threat, i) => (
                    <div key={i} className="flex items-start gap-3 rounded-xl border border-rose-500/20 bg-rose-500/5 p-3">
                      <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
                      <div>
                        <p className="text-sm font-medium text-rose-200">{typeof threat === 'string' ? threat : JSON.stringify(threat)}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {Array.isArray(data.analysis?.mitreMappings) && data.analysis.mitreMappings.length > 0 && (
                <div className="mt-4 space-y-2">
                  <p className="text-xs font-semibold text-indigo-400 uppercase tracking-widest">MITRE ATT&CK Context</p>
                  <div className="flex flex-wrap gap-2">
                    {data.analysis.mitreMappings.map((mitre, i) => (
                      <span key={i} className="rounded-lg border border-indigo-500/30 bg-indigo-500/10 px-3 py-1 text-xs font-mono text-indigo-300">
                        {typeof mitre === 'string' ? mitre : JSON.stringify(mitre)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Interactive Telemetry Data Panels */}
            <div className="space-y-6">
              {/* Active Connections Table */}
              <div className="glass-panel rounded-2xl border border-white/10 overflow-hidden transition-all duration-300 hover:border-sky-500/30">
                <div className="border-b border-white/10 bg-white/5 p-4 flex items-center justify-between">
                  <h3 className="flex items-center gap-2 text-sm font-semibold text-sky-400">
                    <Activity className="h-4 w-4" />
                    Active Network Connections (netstat)
                  </h3>
                  <span className="text-xs text-slate-500 font-mono bg-black/30 px-2 py-1 rounded">Parsed Live</span>
                </div>
                <div className="h-64 overflow-auto custom-scrollbar">
                  <table className="w-full text-left text-xs text-slate-300">
                    <thead className="sticky top-0 bg-slate-900/90 backdrop-blur-sm text-slate-400">
                      <tr>
                        <th className="px-4 py-2 font-medium">Proto</th>
                        <th className="px-4 py-2 font-medium">Local Address</th>
                        <th className="px-4 py-2 font-medium">Foreign Address</th>
                        <th className="px-4 py-2 font-medium">State</th>
                        <th className="px-4 py-2 font-medium">PID</th>
                        <th className="px-4 py-2 font-medium">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 font-mono">
                      {(Array.isArray(data.network) ? data.network : []).map((conn: any, i: number) => {
                        const proto = conn.protocol || 'TCP';
                        const local = conn.local || '0.0.0.0';
                        const foreign = conn.foreign || '0.0.0.0';
                        const state = conn.state || '';
                        const pid = conn.pid || '0';
                        
                        const isAnomalous = state === "LISTENING" && (local.includes(":3389") || local.includes(":22"));
                        
                        return (
                          <tr key={i} className={`hover:bg-white/5 transition-colors ${isAnomalous ? 'bg-amber-500/10' : ''}`}>
                            <td className={`px-4 py-2 ${proto === 'TCP' ? 'text-sky-300' : 'text-emerald-300'}`}>{proto}</td>
                            <td className="px-4 py-2">{local}</td>
                            <td className="px-4 py-2 text-slate-400">{foreign}</td>
                            <td className="px-4 py-2">
                              {state && (
                                <span className={`px-1.5 py-0.5 rounded ${state === 'LISTENING' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : state === 'ESTABLISHED' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30' : 'text-slate-500'}`}>
                                  {state}
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-2 font-bold text-slate-200">{pid}</td>
                            <td className="px-4 py-2">
                              {pid && pid !== "0" && pid !== "-" && (
                                <button
                                  onClick={() => killProcess(pid)}
                                  className="px-2 py-1 bg-rose-500/10 text-rose-400 border border-rose-500/30 rounded flex items-center gap-1 text-[10px] uppercase font-bold hover:bg-rose-500 hover:text-white transition shadow-sm shadow-rose-500/20"
                                >
                                  KILL
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

              {/* Windows Security Logs List */}
              <div className="glass-panel rounded-2xl border border-white/10 overflow-hidden transition-all duration-300 hover:border-emerald-500/30">
                <div className="border-b border-white/10 bg-white/5 p-4 flex items-center justify-between">
                  <h3 className="flex items-center gap-2 text-sm font-semibold text-emerald-400">
                    <Server className="h-4 w-4" />
                    Security Event Logs (wevtutil)
                  </h3>
                  <span className="text-xs text-slate-500 font-mono bg-black/30 px-2 py-1 rounded">Parsed Live</span>
                </div>
                <div className="h-80 overflow-auto custom-scrollbar p-2 space-y-2">
                  {(Array.isArray(data.logs) ? data.logs : []).map((log: any, i: number) => {
                    const id = log.Id ? log.Id.toString() : 'Unknown';
                    const date = log.Date ? new Date(log.Date).toLocaleString() : 'N/A';
                    const level = log.LevelDisplayName || 'Information';
                    const task = log.TaskDisplayName || 'Unknown Task';
                    let desc = log.Message || '';
                    if (desc.length > 100) desc = desc.substring(0, 100) + '...';

                    const isHighRisk = ['4625', '1102', '4688'].includes(id);

                    return (
                      <div key={i} className={`p-3 rounded-xl border flex flex-col gap-2 ${isHighRisk ? 'border-amber-500/30 bg-amber-500/5' : 'border-white/5 bg-white/5'}`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${isHighRisk ? 'bg-amber-500/20 text-amber-300' : 'bg-slate-700 text-slate-300'}`}>
                              ID: {id || 'N/A'}
                            </span>
                            <span className="text-xs font-medium text-slate-300">
                              {level && <span className="text-slate-500 mr-1.5 font-normal">[{level}]</span>}
                              {task || 'Unknown Task'}
                            </span>
                          </div>
                          <span className="text-[10px] text-slate-500 font-mono">{date}</span>
                        </div>
                        <p className="text-xs text-slate-400 break-words">{desc}</p>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>

          {/* Copilot Chat Interface */}
          <div className="glass-panel lg:col-span-5 h-[800px] flex flex-col rounded-3xl border border-indigo-500/30 glow-sky overflow-hidden transition-all duration-300">
            <div className="border-b border-indigo-500/20 bg-indigo-500/10 p-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <MessageSquare className="h-5 w-5 text-indigo-400" />
                <h3 className="font-semibold text-indigo-100">Sentinel Copilot</h3>
              </div>
              <span className="flex h-2 w-2 rounded-full bg-indigo-400 animate-pulse"></span>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
              {chatHistory.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center p-6 opacity-60">
                  <Cpu className="h-12 w-12 text-indigo-400 mb-4" />
                  <p className="text-sm text-indigo-200">I am connected to your live telemetry.</p>
                  <p className="text-xs text-slate-400 mt-2">Ask me to investigate IP addresses, summarize log activity, or correlate threats.</p>
                  
                  <div className="mt-8 flex flex-col gap-2 w-full">
                    <button onClick={() => sendChatMessage("Are there any suspicious external connections?")} className="rounded-xl border border-white/10 bg-white/5 py-2 px-3 text-xs text-slate-300 hover:bg-white/10 text-left">
                      <Zap className="inline h-3 w-3 mr-2 text-amber-400"/> Are there any suspicious external connections?
                    </button>
                    <button onClick={() => sendChatMessage("Summarize the recent Windows Event Logs.")} className="rounded-xl border border-white/10 bg-white/5 py-2 px-3 text-xs text-slate-300 hover:bg-white/10 text-left">
                      <Zap className="inline h-3 w-3 mr-2 text-sky-400"/> Summarize the recent Windows Event Logs.
                    </button>
                    <button onClick={() => sendChatMessage("Draft an executive incident report based on this scan.")} className="rounded-xl border border-white/10 bg-white/5 py-2 px-3 text-xs text-slate-300 hover:bg-white/10 text-left">
                      <Zap className="inline h-3 w-3 mr-2 text-emerald-400"/> Draft an executive incident report based on this scan.
                    </button>
                  </div>
                </div>
              ) : (
                chatHistory.map((msg, i) => (
                  <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                    <div className={`max-w-[85%] rounded-2xl p-3 text-sm leading-relaxed ${
                      msg.role === "user" 
                        ? "bg-indigo-600 text-white rounded-br-sm" 
                        : "bg-white/10 text-slate-200 border border-white/5 rounded-bl-sm"
                    }`}>
                      {msg.text}
                    </div>
                  </div>
                ))
              )}
              {chatLoading && (
                <div className="flex justify-start">
                  <div className="max-w-[85%] rounded-2xl bg-white/5 border border-white/5 p-4 rounded-bl-sm">
                    <div className="flex gap-1.5">
                      <div className="h-2 w-2 rounded-full bg-indigo-400 animate-bounce" style={{ animationDelay: "0ms" }}></div>
                      <div className="h-2 w-2 rounded-full bg-indigo-400 animate-bounce" style={{ animationDelay: "150ms" }}></div>
                      <div className="h-2 w-2 rounded-full bg-indigo-400 animate-bounce" style={{ animationDelay: "300ms" }}></div>
                    </div>
                  </div>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            <div className="p-4 border-t border-indigo-500/20 bg-black/40">
              <form 
                onSubmit={(e) => { e.preventDefault(); sendChatMessage(); }}
                className="flex items-center gap-2"
              >
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  placeholder="Ask Copilot about the telemetry..."
                  className="flex-1 rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-sm text-white placeholder-slate-500 outline-none focus:border-indigo-500/50 focus:bg-white/10 transition"
                  disabled={chatLoading}
                />
                <button
                  type="submit"
                  disabled={!chatInput.trim() || chatLoading}
                  className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-indigo-500 text-white transition hover:bg-indigo-600 disabled:opacity-50"
                >
                  <Send className="h-4 w-4" />
                </button>
              </form>
            </div>
          </div>

        </div>
      )}
    </div>
  );
}
