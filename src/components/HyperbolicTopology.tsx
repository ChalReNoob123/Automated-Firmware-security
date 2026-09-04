import { useEffect, useRef, useState } from "react";
import { Network, Zap } from "lucide-react";

interface NetworkNode {
  id: string;
  name: string;
  ip: string;
  type: "server" | "workstation" | "gateway" | "mobile" | "external";
  status: "secure" | "warning" | "compromised";
  re: number; // Hyperbolic real coordinate (magnitude < 1)
  im: number; // Hyperbolic imaginary coordinate (magnitude < 1)
}

interface Connection {
  from: string;
  to: string;
}

interface Particle {
  fromNode: NetworkNode;
  toNode: NetworkNode;
  progress: number; // 0 to 1
  speed: number;
  color: string;
}

interface HyperbolicTopologyProps {
  threatLevel: "green" | "yellow" | "red";
  selectedNodeId: string | null;
  onSelectNode: (nodeId: string) => void;
}

export default function HyperbolicTopology({
  threatLevel,
  selectedNodeId,
  onSelectNode
}: HyperbolicTopologyProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  
  // Translation center in the Poincaré disk (complex number a where |a| < 1)
  const [targetCenter, setTargetCenter] = useState({ re: 0.0, im: 0.0 });
  const currentCenter = useRef({ re: 0.0, im: 0.0 });
  
  const [nodes, setNodes] = useState<NetworkNode[]>([
    { id: "gateway", name: "Core Firewall / Gateway", ip: "10.0.2.1", type: "gateway", status: "secure", re: 0.0, im: 0.0 },
    { id: "win2025", name: "Windows Server 2025 AD", ip: "10.0.2.15", type: "server", status: "secure", re: 0.35, im: 0.2 },
    { id: "kali", name: "Kali Attack Platform", ip: "10.0.2.16", type: "external", status: "secure", re: -0.4, im: -0.4 },
    { id: "android", name: "Android Test Container", ip: "10.0.2.20", type: "mobile", status: "warning", re: 0.5, im: -0.3 },
    { id: "ios", name: "iOS Core Sandbox", ip: "10.0.2.21", type: "mobile", status: "compromised", re: 0.2, im: -0.55 },
    { id: "db_shard", name: "Database Shard Core", ip: "10.0.2.5", type: "server", status: "secure", re: -0.3, im: 0.4 },
    { id: "siem_hub", name: "SIEM Telemetry Collector", ip: "10.0.2.8", type: "server", status: "secure", re: 0.5, im: 0.4 },
    { id: "analyst_ws", name: "Analyst Workstation", ip: "10.0.2.100", type: "workstation", status: "secure", re: -0.5, im: 0.1 }
  ]);

  const connections: Connection[] = [
    { from: "gateway", to: "win2025" },
    { from: "gateway", to: "db_shard" },
    { from: "gateway", to: "android" },
    { from: "gateway", to: "ios" },
    { from: "gateway", to: "siem_hub" },
    { from: "gateway", to: "analyst_ws" },
    { from: "win2025", to: "db_shard" },
    { from: "kali", to: "gateway" },
    { from: "ios", to: "siem_hub" },
    { from: "android", to: "siem_hub" }
  ];

  // Sync selected node with centering target
  useEffect(() => {
    if (selectedNodeId) {
      const node = nodes.find(n => n.id === selectedNodeId);
      if (node) {
        // Center on the negative of node coordinates to slide it to center (0,0)
        setTargetCenter({ re: node.re * 0.9, im: node.im * 0.9 });
      }
    } else {
      setTargetCenter({ re: 0.0, im: 0.0 });
    }
  }, [selectedNodeId, nodes]);

  // Dynamic threat level coloring for nodes
  useEffect(() => {
    setNodes(prev => prev.map(node => {
      if (node.id === "ios") {
        return { ...node, status: threatLevel === "red" ? "compromised" : "warning" };
      }
      if (node.id === "android") {
        return { ...node, status: threatLevel === "green" ? "secure" : "warning" };
      }
      if (node.id === "win2025") {
        return { ...node, status: threatLevel === "red" ? "warning" : "secure" };
      }
      return node;
    }));
  }, [threatLevel]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationId: number;
    let width = canvas.width = canvas.offsetWidth;
    let height = canvas.height = canvas.offsetHeight;

    // Active telemetry flows particles
    const particles: Particle[] = [];
    
    // Spawn particles on connections periodically
    const spawnParticle = () => {
      if (connections.length === 0) return;
      const conn = connections[Math.floor(Math.random() * connections.length)];
      const fromNode = nodes.find(n => n.id === conn.from);
      const toNode = nodes.find(n => n.id === conn.to);
      if (fromNode && toNode) {
        let pColor = "rgba(34, 211, 238, 0.8)"; // Cyan
        if (fromNode.status === "compromised" || toNode.status === "compromised") {
          pColor = "rgba(244, 63, 94, 0.9)"; // Red
        } else if (fromNode.status === "warning" || toNode.status === "warning") {
          pColor = "rgba(245, 158, 11, 0.85)"; // Amber
        }
        
        particles.push({
          fromNode,
          toNode,
          progress: 0.0,
          speed: 0.008 + Math.random() * 0.012,
          color: pColor
        });
      }
    };

    // Moebius transformation to translate points in Poincaré disk
    // z' = (z - a) / (1 - conj(a)*z)
    const hyperbolicTranslate = (zRe: number, zIm: number, aRe: number, aIm: number) => {
      // Numerator: z - a
      const numRe = zRe - aRe;
      const numIm = zIm - aIm;
      
      // Denominator: 1 - conj(a) * z
      // conj(a) = aRe - i*aIm
      // conj(a)*z = (aRe*zRe + aIm*zIm) + i*(aRe*zIm - aIm*zRe)
      const denRe = 1 - (aRe * zRe + aIm * zIm);
      const denIm = -(aRe * zIm - aIm * zRe);
      
      // Division
      const denSq = denRe * denRe + denIm * denIm;
      if (denSq === 0) return { re: zRe, im: zIm };
      
      const resRe = (numRe * denRe + numIm * denIm) / denSq;
      const resIm = (numIm * denRe - numRe * denIm) / denSq;
      
      return { re: resRe, im: resIm };
    };

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = canvas.offsetWidth;
      height = canvas.height = canvas.offsetHeight;
    };
    window.addEventListener("resize", handleResize);

    // Track user mouse drag
    let isDragging = false;
    let dragStart = { x: 0, y: 0 };
    let centerStart = { re: 0, im: 0 };

    const getMousePos = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      return {
        x: e.clientX - rect.left,
        y: e.clientY - rect.top
      };
    };

    const onMouseDown = (e: MouseEvent) => {
      isDragging = true;
      const pos = getMousePos(e);
      dragStart = pos;
      centerStart = { ...targetCenter };
    };

    const onMouseMove = (e: MouseEvent) => {
      if (!isDragging) return;
      const pos = getMousePos(e);
      const dx = pos.x - dragStart.x;
      const dy = pos.y - dragStart.y;
      
      // Map drag distance in pixels to hyperbolic space coordinates
      const diskRadius = Math.min(width, height) * 0.4;
      const factor = 0.8 / diskRadius;
      
      let nextRe = centerStart.re - dx * factor;
      let nextIm = centerStart.im - dy * factor;
      
      // Clamping to avoid shifting past disk boundaries
      const mag = Math.sqrt(nextRe * nextRe + nextIm * nextIm);
      if (mag >= 0.95) {
        nextRe = (nextRe / mag) * 0.95;
        nextIm = (nextIm / mag) * 0.95;
      }
      
      setTargetCenter({ re: nextRe, im: nextIm });
    };

    const onMouseUp = () => {
      isDragging = false;
    };

    // Click handler for node selection
    const onCanvasClick = (e: MouseEvent) => {
      if (isDragging && Math.abs(e.clientX - dragStart.x) > 3) return; // it was a drag, not click
      
      const pos = getMousePos(e);
      const centerX = width / 2;
      const centerY = height / 2;
      const diskRadius = Math.min(width, height) * 0.4;
      
      // Check if clicked any node
      for (const node of nodes) {
        // Get translated hyperbolic coordinate
        const trans = hyperbolicTranslate(node.re, node.im, currentCenter.current.re, currentCenter.current.im);
        
        // Map to screen pixel coordinates
        const sx = centerX + trans.re * diskRadius;
        const sy = centerY + trans.im * diskRadius;
        
        const dist = Math.hypot(pos.x - sx, pos.y - sy);
        if (dist <= 18) {
          onSelectNode(node.id);
          return;
        }
      }
    };

    canvas.addEventListener("mousedown", onMouseDown);
    canvas.addEventListener("mousemove", onMouseMove);
    canvas.addEventListener("mouseup", onMouseUp);
    canvas.addEventListener("click", onCanvasClick);

    // Frame ticks tracker for rendering wave ripples
    let frame = 0;

    const render = () => {
      frame++;
      
      // Periodically spawn data flows
      if (frame % 15 === 0) {
        spawnParticle();
      }

      ctx.clearRect(0, 0, width, height);
      
      const centerX = width / 2;
      const centerY = height / 2;
      const diskRadius = Math.min(width, height) * 0.42;

      // Smoothly interpolate current hyperbolic panning center towards target
      currentCenter.current.re += (targetCenter.re - currentCenter.current.re) * 0.08;
      currentCenter.current.im += (targetCenter.im - currentCenter.current.im) * 0.08;

      // --- 1. Draw Global Lighting / Background Glow (DEFCON waves) ---
      let glowColor = "rgba(34, 211, 238, 0.02)"; // Cool teal baseline
      if (threatLevel === "red") {
        // Aggressive red wave pulsing
        const pulse = 0.04 + Math.sin(frame * 0.08) * 0.03;
        glowColor = `rgba(244, 63, 94, ${pulse})`;
        
        // Draw red flash boundary overlay
        ctx.fillStyle = `rgba(244, 63, 94, ${0.015 + Math.sin(frame * 0.05) * 0.01})`;
        ctx.fillRect(0, 0, width, height);
      } else if (threatLevel === "yellow") {
        glowColor = "rgba(245, 158, 11, 0.03)";
      }
      
      const radialGlow = ctx.createRadialGradient(centerX, centerY, diskRadius * 0.1, centerX, centerY, diskRadius * 1.5);
      radialGlow.addColorStop(0, "transparent");
      radialGlow.addColorStop(0.6, glowColor);
      radialGlow.addColorStop(1, "transparent");
      ctx.fillStyle = radialGlow;
      ctx.fillRect(0, 0, width, height);

      // --- 2. Draw Poincaré Disk Border Circle ---
      ctx.strokeStyle = "rgba(255, 255, 255, 0.08)";
      if (threatLevel === "red") ctx.strokeStyle = "rgba(244, 63, 94, 0.18)";
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(centerX, centerY, diskRadius, 0, 2 * Math.PI);
      ctx.stroke();

      // Outer rings showing geometric division
      ctx.strokeStyle = "rgba(255, 255, 255, 0.02)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(centerX, centerY, diskRadius * 0.95, 0, 2 * Math.PI);
      ctx.arc(centerX, centerY, diskRadius * 0.85, 0, 2 * Math.PI);
      ctx.stroke();

      // --- 3. Draw Network Connections (Hyperbolic Geodesics / Curved Lines) ---
      for (const conn of connections) {
        const fromNode = nodes.find(n => n.id === conn.from);
        const toNode = nodes.find(n => n.id === conn.to);
        if (!fromNode || !toNode) continue;
        
        // Get translated hyperbolic coordinates
        const tFrom = hyperbolicTranslate(fromNode.re, fromNode.im, currentCenter.current.re, currentCenter.current.im);
        const tTo = hyperbolicTranslate(toNode.re, toNode.im, currentCenter.current.re, currentCenter.current.im);
        
        const fx = centerX + tFrom.re * diskRadius;
        const fy = centerY + tFrom.im * diskRadius;
        const tx = centerX + tTo.re * diskRadius;
        const ty = centerY + tTo.im * diskRadius;
        
        // Dynamic connection line style
        let strokeColor = "rgba(255, 255, 255, 0.07)";
        if (fromNode.status === "compromised" || toNode.status === "compromised") {
          strokeColor = "rgba(244, 63, 94, 0.28)";
        } else if (fromNode.status === "warning" || toNode.status === "warning") {
          strokeColor = "rgba(245, 158, 11, 0.2)";
        }
        
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = 1.5;
        
        // Draw connection curved towards center (Hyperbolic projection approximation)
        ctx.beginPath();
        ctx.moveTo(fx, fy);
        
        // Calculate control point pulled towards Poincaré origin
        const midX = (fx + tx) / 2;
        const midY = (fy + ty) / 2;
        const ctrlX = midX * 0.75 + centerX * 0.25;
        const ctrlY = midY * 0.75 + centerY * 0.25;
        
        ctx.quadraticCurveTo(ctrlX, ctrlY, tx, ty);
        ctx.stroke();
      }

      // --- 4. Update and Draw Volumetric Particles ---
      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        p.progress += p.speed;
        
        if (p.progress >= 1.0) {
          particles.splice(i, 1);
          continue;
        }
        
        const tFrom = hyperbolicTranslate(p.fromNode.re, p.fromNode.im, currentCenter.current.re, currentCenter.current.im);
        const tTo = hyperbolicTranslate(p.toNode.re, p.toNode.im, currentCenter.current.re, currentCenter.current.im);
        
        const fx = centerX + tFrom.re * diskRadius;
        const fy = centerY + tFrom.im * diskRadius;
        const tx = centerX + tTo.re * diskRadius;
        const ty = centerY + tTo.im * diskRadius;
        
        // Calculate mid/control point
        const midX = (fx + tx) / 2;
        const midY = (fy + ty) / 2;
        const ctrlX = midX * 0.75 + centerX * 0.25;
        const ctrlY = midY * 0.75 + centerY * 0.25;
        
        // Interpolate along quadratic bezier curve
        const t = p.progress;
        const px = (1 - t) * (1 - t) * fx + 2 * (1 - t) * t * ctrlX + t * t * tx;
        const py = (1 - t) * (1 - t) * fy + 2 * (1 - t) * t * ctrlY + t * t * ty;
        
        // Draw particle glow
        ctx.beginPath();
        ctx.arc(px, py, 2.5, 0, 2 * Math.PI);
        ctx.fillStyle = p.color;
        ctx.fill();
      }

      // --- 5. Draw Nodes (Projected Poincaré coordinates) ---
      for (const node of nodes) {
        const trans = hyperbolicTranslate(node.re, node.im, currentCenter.current.re, currentCenter.current.im);
        
        // Map disk coordinate to screen pixels
        const sx = centerX + trans.re * diskRadius;
        const sy = centerY + trans.im * diskRadius;
        
        // Distance from disk center (used for scaling / compressing near edges)
        const distFromCenter = Math.hypot(trans.re, trans.im);
        
        // Compression scaling factor: nodes compress as they approach disk boundary
        const compressionScale = Math.max(0.2, 1.0 - distFromCenter * 0.75);
        const nodeSize = 14 * compressionScale;
        
        const isSelected = node.id === selectedNodeId;
        
        // Determine coloring based on security status
        let baseColor = "rgba(34, 211, 238, 0.35)"; // Cyan
        let ringColor = "rgba(34, 211, 238, 0.7)";
        
        if (node.status === "compromised") {
          baseColor = "rgba(244, 63, 94, 0.4)"; // Red
          ringColor = "rgba(244, 63, 94, 0.9)";
        } else if (node.status === "warning") {
          baseColor = "rgba(245, 158, 11, 0.35)"; // Amber
          ringColor = "rgba(245, 158, 11, 0.8)";
        }
        
        // Active target pulsing circle
        if (node.status === "compromised") {
          ctx.beginPath();
          ctx.arc(sx, sy, nodeSize * (1.5 + Math.sin(frame * 0.1) * 0.2), 0, 2 * Math.PI);
          ctx.strokeStyle = "rgba(244, 63, 94, 0.15)";
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        // Draw node selection highlight ring
        if (isSelected) {
          ctx.beginPath();
          ctx.arc(sx, sy, nodeSize * 2.0, 0, 2 * Math.PI);
          ctx.strokeStyle = "rgba(34, 211, 238, 0.4)";
          ctx.lineWidth = 1.5;
          ctx.stroke();
          
          // Crosshair lines
          ctx.strokeStyle = "rgba(34, 211, 238, 0.2)";
          ctx.beginPath();
          ctx.moveTo(sx - nodeSize * 2.5, sy);
          ctx.lineTo(sx + nodeSize * 2.5, sy);
          ctx.moveTo(sx, sy - nodeSize * 2.5);
          ctx.lineTo(sx, sy + nodeSize * 2.5);
          ctx.stroke();
        }

        // Base circular node
        ctx.beginPath();
        ctx.arc(sx, sy, nodeSize, 0, 2 * Math.PI);
        ctx.fillStyle = baseColor;
        ctx.fill();
        ctx.strokeStyle = ringColor;
        ctx.lineWidth = isSelected ? 2.5 : 1.5;
        ctx.stroke();
        
        // Inner core point
        ctx.beginPath();
        ctx.arc(sx, sy, nodeSize * 0.35, 0, 2 * Math.PI);
        ctx.fillStyle = "#ffffff";
        ctx.fill();

        // Node labels (fade out if compressed near boundary)
        if (compressionScale > 0.45) {
          ctx.font = `bold ${Math.max(9, Math.round(11 * compressionScale))}px JetBrains Mono`;
          ctx.fillStyle = isSelected ? "#ffffff" : "rgba(226, 232, 240, 0.8)";
          ctx.textAlign = "center";
          ctx.fillText(node.name, sx, sy - nodeSize - 8);
          
          ctx.font = `${Math.max(8, Math.round(9 * compressionScale))}px JetBrains Mono`;
          ctx.fillStyle = isSelected ? "rgba(34, 211, 238, 0.9)" : "rgba(148, 163, 184, 0.6)";
          ctx.fillText(node.ip, sx, sy - nodeSize - 22);
        }
      }

      // --- 6. Chromatic Aberration Screen Warning Effect (if threat Red) ---
      if (threatLevel === "red" && frame % 4 !== 0) {
        // Draws copy of critical warning indicators offset by 2px to simulate aberration
        ctx.font = "bold 13px JetBrains Mono";
        ctx.textAlign = "left";
        
        // Red channel offset
        ctx.fillStyle = "rgba(239, 68, 68, 0.75)";
        ctx.fillText("STATUS: CRITICAL EXPLOIT DETECTED", 27, 30);
        ctx.fillText("TISET TEMPORAL SWAP ACTIVE", 27, 48);
        
        // Cyan channel offset
        ctx.fillStyle = "rgba(6, 182, 212, 0.75)";
        ctx.fillText("STATUS: CRITICAL EXPLOIT DETECTED", 23, 30);
        ctx.fillText("TISET TEMPORAL SWAP ACTIVE", 23, 48);
        
        // Green baseline
        ctx.fillStyle = "#ffffff";
        ctx.fillText("STATUS: CRITICAL EXPLOIT DETECTED", 25, 30);
        ctx.fillText("TISET TEMPORAL SWAP ACTIVE", 25, 48);
      }

      animationId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener("resize", handleResize);
      canvas.removeEventListener("mousedown", onMouseDown);
      canvas.removeEventListener("mousemove", onMouseMove);
      canvas.removeEventListener("mouseup", onMouseUp);
      canvas.removeEventListener("click", onCanvasClick);
    };
  }, [nodes, targetCenter, threatLevel, selectedNodeId]);

  return (
    <div className="relative w-full h-full flex flex-col bg-slate-950/20 border border-slate-800 rounded-xl overflow-hidden glass-panel">
      {/* HUD Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 bg-slate-950/60 px-4 py-3 font-mono">
        <div className="flex items-center gap-2.5">
          <Network className="h-4 w-4 text-cyan-400" />
          <span className="text-xs font-black uppercase tracking-wider text-slate-300">Poincaré Disk Subnet Topology</span>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <Zap className="h-3 w-3 text-cyan-400" />
            <span className="text-[10px] text-slate-500 uppercase">Interactive Projection</span>
          </div>
          <div className={`flex items-center gap-1.5 rounded border px-2 py-0.5 text-[9px] font-bold uppercase ${
            threatLevel === 'red' 
              ? 'border-rose-500/30 bg-rose-500/10 text-rose-300 animate-pulse' 
              : threatLevel === 'yellow' 
                ? 'border-amber-500/30 bg-amber-500/10 text-amber-300' 
                : 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300'
          }`}>
            DEFCON: {threatLevel === 'red' ? 'CRITICAL (1)' : threatLevel === 'yellow' ? 'WARNING (2)' : 'NORMAL (5)'}
          </div>
        </div>
      </div>

      {/* Grid HUD Overlay Info */}
      <div className="absolute top-14 left-4 pointer-events-none font-mono text-[9px] text-slate-500 z-10 space-y-1 select-none">
        <div>GEOM: NON-EUCLIDEAN POINCARÉ</div>
        <div>METRIC: ds² = 4(dx² + dy²) / (1 - (x² + y²))²</div>
        <div>RENDER_LOAD: Locked 60 FPS (WebGPU accelerated fallback)</div>
        <div>MOEBIUS_SHIFT: re {targetCenter.re.toFixed(4)}, im {targetCenter.im.toFixed(4)}</div>
      </div>

      <div className="flex-1 w-full relative min-h-[300px]">
        <canvas ref={canvasRef} className="w-full h-full block cursor-move" />
      </div>

      {/* Footer / Controls */}
      <div className="flex justify-between items-center bg-slate-950/60 border-t border-slate-800/80 px-4 py-2 font-mono text-[10px] text-slate-500">
        <div>Click node to translate/focus · Drag to explore Poincaré infinity boundaries</div>
        <button 
          onClick={() => setTargetCenter({ re: 0, im: 0 })}
          className="px-2 py-0.5 border border-slate-700 rounded hover:border-cyan-400 hover:text-white transition-colors"
        >
          Reset Horizon
        </button>
      </div>
    </div>
  );
}
