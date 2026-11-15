'use client';
import { useEffect, useRef, type CSSProperties, type ReactNode } from 'react';
import FluidScene from './FluidScene';

// Procedural cinematic panels — the honest response to "4K fluid imagery":
// instead of shipping megabyte JPEGs (or blocked stock video), the artwork is
// DRAWN at the panel's device resolution (dpr-capped, so 4K natives get a crisp
// 4K bake) and animated on a cheap composite loop:
//   circuit  — PCB topology + glowing signal pulses riding the actual traces
//   holo     — wireframe digital twin + orbiting particles + scan sweep
//   gridwave — 3D perspective horizon with an endless scrolling depth grid
//   fluid    — live aurora (FluidScene) instead of a bake
//   device   — procedural IoT hub render: body, LED-ring sweep, ports, antenna
// Everything respects prefers-reduced-motion (single static frame) and stops
// painting when the tab is hidden.

function mulberry(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    let t = (a += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), 1 | t);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

type Variant = 'circuit' | 'holo' | 'fluid' | 'gridwave' | 'device';

/* A trace recorded during the circuit bake so pulses can ride it later. */
type TracePath = { pts: [number, number][]; violet: boolean; hot: boolean };
type Pulse = { path: TracePath; sp: number; ph: number; rev: boolean };

/* --- circuit: dark PCB topology — Manhattan traces, vias, glowing rails --- */
function bakeCircuit(w: number, h: number): { art: HTMLCanvasElement; paths: TracePath[] } {
  const c = document.createElement('canvas');
  c.width = w;
  c.height = h;
  const g = c.getContext('2d')!;
  const rng = mulberry(0x51c917);
  const paths: TracePath[] = [];

  const bg = g.createLinearGradient(0, 0, w, h);
  bg.addColorStop(0, '#040a18');
  bg.addColorStop(1, '#020617');
  g.fillStyle = bg;
  g.fillRect(0, 0, w, h);
  // faint substrate grid
  g.strokeStyle = 'rgba(148,163,184,0.05)';
  g.lineWidth = 1;
  const grid = Math.round(Math.min(w, h) / 34);
  for (let x = grid; x < w; x += grid) {
    g.beginPath();
    g.moveTo(x, 0);
    g.lineTo(x, 0 + h);
    g.stroke();
  }
  for (let y = grid; y < h; y += grid) {
    g.beginPath();
    g.moveTo(0, y);
    g.lineTo(w, y);
    g.stroke();
  }

  // Manhattan traces — geometry recorded so the animator can send light down it
  const cyan = 'rgba(34,211,238,';
  const violet = 'rgba(168,85,247,';
  for (let i = 0; i < 90; i++) {
    const hot = rng() > 0.86;
    const isViolet = rng() > 0.6;
    const col = (isViolet ? violet : cyan) + (hot ? '0.85' : String(0.08 + rng() * 0.24)) + ')';
    g.strokeStyle = col;
    g.shadowColor = hot ? 'rgba(34,211,238,0.9)' : 'transparent';
    g.shadowBlur = hot ? Math.min(26, Math.max(8, w / 90)) : 0;
    g.lineWidth = hot ? 2.2 : 1.2;
    let x = Math.floor(rng() * w);
    let y = Math.floor(rng() * h);
    const pts: [number, number][] = [[x, y]];
    g.beginPath();
    g.moveTo(x, y);
    const legs = 3 + Math.floor(rng() * 4);
    for (let l = 0; l < legs; l++) {
      const horiz = rng() > 0.5;
      const len = grid * (2 + Math.floor(rng() * 7)) * (rng() > 0.5 ? 1 : -1);
      x = horiz ? Math.max(6, Math.min(w - 6, x + len)) : x;
      y = horiz ? y : Math.max(6, Math.min(h - 6, y + len));
      // rounded elbow: little quad curve
      const px = x,
        py = y;
      g.lineTo(px, py);
      // handle outward
      const bend = 12;
      const up = y > h / 2 ? -bend : bend;
      if (horiz) g.quadraticCurveTo(px + Math.sign(-len) * bend, py, x, y + up);
      else g.quadraticCurveTo(px, py + Math.sign(-len) * bend, x + (rng() > 0.5 ? bend : -bend), y);
      pts.push([x, y]);
    }
    g.stroke();
    paths.push({ pts, violet: isViolet, hot });
    // via dot at the end
    if (rng() > 0.35) {
      g.fillStyle = col;
      g.shadowColor = 'rgba(34,211,238,0.7)';
      g.shadowBlur = hot ? 18 : 6;
      g.beginPath();
      g.arc(x, y, hot ? 3.2 : 2, 0, Math.PI * 2);
      g.fill();
      g.shadowBlur = 0;
    }
  }
  // chip blocks
  for (let i = 0; i < 6; i++) {
    const cw = 40 + rng() * 90;
    const ch = 28 + rng() * 60;
    const x = rng() * (w - cw - 20) + 10;
    const y = rng() * (h - ch - 20) + 10;
    g.fillStyle = 'rgba(8,12,26,0.92)';
    g.strokeStyle = 'rgba(34,211,238,0.25)';
    g.lineWidth = 1.4;
    g.beginPath();
    g.rect(x, y, cw, ch);
    g.fill();
    g.stroke();
    // pins
    g.strokeStyle = 'rgba(148,163,184,0.28)';
    for (let p = -3; p * 10 < cw; p += 1) {
      g.beginPath();
      g.moveTo(x + p * 10 + 8, y - 6);
      g.lineTo(x + p * 10 + 8, y);
      g.stroke();
      g.beginPath();
      g.moveTo(x + p * 10 + 8, y + ch);
      g.lineTo(x + p * 10 + 8, y + ch + 6);
      g.stroke();
    }
  }
  return { art: c, paths };
}

/* Position along a recorded trace at progress p∈[0,1] (arc-length walk). */
function walkPath(pts: [number, number][], p: number): [number, number] {
  let total = 0;
  const segs: number[] = [];
  for (let i = 1; i < pts.length; i++) {
    const L = Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]) || 1e-6;
    segs.push(L);
    total += L;
  }
  let target = p * total;
  for (let i = 0; i < segs.length; i++) {
    if (target <= segs[i]) {
      const f = target / segs[i];
      return [pts[i][0] + (pts[i + 1][0] - pts[i][0]) * f, pts[i][1] + (pts[i + 1][1] - pts[i][1]) * f];
    }
    target -= segs[i];
  }
  return pts[pts.length - 1];
}

/* --- holo: wireframe "digital twin" sphere + orbit + glow base --- */
function bakeHolo(w: number, h: number): HTMLCanvasElement {
  const c = document.createElement('canvas');
  c.width = w;
  c.height = h;
  const g = c.getContext('2d')!;
  g.fillStyle = '#020617';
  g.fillRect(0, 0, w, h);

  const r = Math.min(w, h) * 0.28;
  const cx = w / 2;
  const cy = h * 0.46;

  const halo = g.createRadialGradient(cx, cy, r * 0.2, cx, cy, r * 2.6);
  halo.addColorStop(0, 'rgba(34,211,238,0.22)');
  halo.addColorStop(0.5, 'rgba(34,211,238,0.06)');
  halo.addColorStop(1, 'rgba(2,6,23,0)');
  g.fillStyle = halo;
  g.fillRect(0, 0, w, h);

  g.strokeStyle = 'rgba(34,211,238,0.4)';
  g.lineWidth = 1.1;
  g.shadowColor = 'rgba(34,211,238,0.8)';
  g.shadowBlur = 12;
  // longitude arcs
  for (let i = 0; i < 8; i++) {
    const squash = 0.14 + 0.86 * Math.abs(Math.cos((i / 8) * Math.PI));
    g.beginPath();
    g.ellipse(cx, cy, r * squash, r, 0, 0, Math.PI * 2);
    g.stroke();
  }
  // latitude ellipses
  for (let i = -3; i <= 3; i++) {
    const y = (i / 3.4) * r;
    const rr = Math.sqrt(Math.max(0.0001, 1 - (i / 3.4) ** 2)) * r;
    g.strokeStyle = i === 0 ? 'rgba(168,85,247,0.75)' : 'rgba(34,211,238,0.32)';
    g.beginPath();
    g.ellipse(cx, cy + y, rr, rr * 0.32, 0, 0, Math.PI * 2);
    g.stroke();
  }
  // orbit + satellite
  g.setLineDash([4, 7]);
  g.strokeStyle = 'rgba(168,85,247,0.55)';
  g.beginPath();
  g.ellipse(cx, cy, r * 1.7, r * 0.62, -0.4, 0, Math.PI * 2);
  g.stroke();
  g.setLineDash([]);
  // base pedestal
  g.strokeStyle = 'rgba(34,211,238,0.5)';
  g.beginPath();
  g.ellipse(cx, cy + r * 1.55, r * 1.15, r * 0.24, 0, 0, Math.PI * 2);
  g.stroke();
  const beam = g.createLinearGradient(cx, cy + r * 1.55, cx, cy + r * 1.1);
  beam.addColorStop(0, 'rgba(34,211,238,0.35)');
  beam.addColorStop(1, 'rgba(34,211,238,0)');
  g.fillStyle = beam;
  g.beginPath();
  g.moveTo(cx - r * 1.15, cy + r * 1.55);
  g.lineTo(cx - r * 0.55, cy + r * 1.1);
  g.lineTo(cx + r * 0.55, cy + r * 1.1);
  g.lineTo(cx + r * 1.15, cy + r * 1.55);
  g.closePath();
  g.fill();
  g.shadowBlur = 0;
  return c;
}

/* --- gridwave: retro-future 3D horizon; the depth grid scrolls in the loop --- */
function bakeGridwave(w: number, h: number): HTMLCanvasElement {
  const c = document.createElement('canvas');
  c.width = w;
  c.height = h;
  const g = c.getContext('2d')!;
  const rng = mulberry(0x6b1d51a7);

  const sky = g.createLinearGradient(0, 0, 0, h);
  sky.addColorStop(0, '#020617');
  sky.addColorStop(0.42, '#081130');
  sky.addColorStop(1, '#020617');
  g.fillStyle = sky;
  g.fillRect(0, 0, w, h);

  const hy = h * 0.44;
  const cx = w / 2;

  // stars above the horizon
  for (let i = 0; i < 110; i++) {
    g.fillStyle = `rgba(226,232,240,${(0.12 + rng() * 0.5).toFixed(2)})`;
    g.fillRect(rng() * w, rng() * hy * 0.95, 1.4, 1.4);
  }

  // retro sun with horizontal slice gaps (evenodd clip keeps the sky intact)
  const sr = Math.min(w, h) * 0.23;
  const sy = hy - sr * 0.28;
  g.save();
  g.beginPath();
  g.rect(0, 0, w, h);
  let y0 = sy + sr * 0.18;
  let gap = 3;
  for (let i = 0; i < 6; i++) {
    g.rect(0, y0, w, gap);
    y0 += gap + 9 + i * 5;
    gap *= 1.3;
  }
  g.clip('evenodd');
  const sun = g.createRadialGradient(cx, sy, sr * 0.08, cx, sy, sr);
  sun.addColorStop(0, 'rgba(236,72,153,0.9)');
  sun.addColorStop(0.45, 'rgba(168,85,247,0.6)');
  sun.addColorStop(1, 'rgba(34,211,238,0)');
  g.fillStyle = sun;
  g.beginPath();
  g.arc(cx, sy, sr, 0, Math.PI * 2);
  g.fill();
  g.restore();

  // horizon line + glow
  const hglow = g.createLinearGradient(0, hy - 26, 0, hy + 26);
  hglow.addColorStop(0, 'rgba(34,211,238,0)');
  hglow.addColorStop(0.5, 'rgba(34,211,238,0.16)');
  hglow.addColorStop(1, 'rgba(34,211,238,0)');
  g.fillStyle = hglow;
  g.fillRect(0, hy - 26, w, 52);
  const hl = g.createLinearGradient(0, 0, w, 0);
  hl.addColorStop(0, 'rgba(34,211,238,0.1)');
  hl.addColorStop(0.3, 'rgba(34,211,238,0.8)');
  hl.addColorStop(0.55, 'rgba(168,85,247,0.9)');
  hl.addColorStop(0.8, 'rgba(34,211,238,0.8)');
  hl.addColorStop(1, 'rgba(34,211,238,0.1)');
  g.fillStyle = hl;
  g.fillRect(0, hy - 1, w, 2);

  // vanishing vertical grid lines (static; horizontals march in the loop)
  const spread = w / 6.5;
  g.strokeStyle = 'rgba(34,211,238,0.16)';
  g.lineWidth = 1;
  for (let k = -9; k <= 9; k++) {
    g.beginPath();
    g.moveTo(cx, hy);
    g.lineTo(cx + k * spread, h);
    g.stroke();
  }
  return c;
}

/* --- device: procedural IoT hub render — body, LED ring, antenna, ports --- */
function roundedRect(g: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
  g.beginPath();
  g.moveTo(x + r, y);
  g.arcTo(x + w, y, x + w, y + h, r);
  g.arcTo(x + w, y + h, x, y + h, r);
  g.arcTo(x, y + h, x, y, r);
  g.arcTo(x, y, x + w, y, r);
  g.closePath();
}

function bakeDevice(w: number, h: number): HTMLCanvasElement {
  const c = document.createElement('canvas');
  c.width = w;
  c.height = h;
  const g = c.getContext('2d')!;
  const rng = mulberry(0xdeb1ce);
  g.fillStyle = '#020617';
  g.fillRect(0, 0, w, h);

  // shared geometry (the animator recomputes the same numbers per frame)
  const u = Math.min(w, h) / 420;
  const cx = w * 0.5;
  const cy = h * 0.52;
  const bw = 190 * u;
  const bh = 120 * u;
  const bx = cx - bw / 2;
  const by = cy - bh / 2;

  // ambient halo
  const halo = g.createRadialGradient(cx, cy, 10, cx, cy, Math.max(bw, bh) * 1.7);
  halo.addColorStop(0, 'rgba(34,211,238,0.2)');
  halo.addColorStop(0.45, 'rgba(34,211,238,0.05)');
  halo.addColorStop(1, 'rgba(2,6,23,0)');
  g.fillStyle = halo;
  g.fillRect(0, 0, w, h);

  // floor reflection
  const refl = g.createLinearGradient(0, cy + bh * 0.62, 0, cy + bh * 0.62 + 70 * u);
  refl.addColorStop(0, 'rgba(34,211,238,0.13)');
  refl.addColorStop(1, 'rgba(34,211,238,0)');
  g.fillStyle = refl;
  g.beginPath();
  g.ellipse(cx, cy + bh * 0.62 + 30 * u, bw * 0.85, 30 * u, 0, 0, Math.PI * 2);
  g.fill();

  // contact shadow
  g.fillStyle = 'rgba(2,6,23,0.72)';
  g.beginPath();
  g.ellipse(cx, cy + bh * 0.62, bw * 0.56, 12 * u, 0, 0, Math.PI * 2);
  g.fill();

  // body: rounded slab with a vertical machined gradient
  const body = g.createLinearGradient(0, by, 0, by + bh);
  body.addColorStop(0, '#0c1530');
  body.addColorStop(0.5, '#070d20');
  body.addColorStop(1, '#040818');
  g.fillStyle = body;
  g.strokeStyle = 'rgba(125,211,252,0.35)';
  g.lineWidth = 1.4;
  roundedRect(g, bx, by, bw, bh, 18 * u);
  g.fill();
  g.stroke();

  // top edge highlight
  const edge = g.createLinearGradient(0, by, 0, by + 9 * u);
  edge.addColorStop(0, 'rgba(165,243,252,0.5)');
  edge.addColorStop(1, 'rgba(165,243,252,0)');
  g.fillStyle = edge;
  roundedRect(g, bx + 6 * u, by, bw - 12 * u, 9 * u, 4 * u);
  g.fill();

  // engraved spec lines (seeded)
  g.strokeStyle = 'rgba(148,163,184,0.3)';
  g.lineWidth = 1;
  for (let i = 0; i < 5; i++) {
    const ly = by + 24 * u + i * 12 * u;
    g.beginPath();
    g.moveTo(bx + 20 * u, ly);
    g.lineTo(bx + 20 * u + (14 + rng() * 26) * u, ly);
    g.stroke();
  }

  // status LED wells (the animator blinks lights into these)
  g.strokeStyle = 'rgba(148,163,184,0.4)';
  for (let i = 0; i < 3; i++) {
    g.beginPath();
    g.arc(bx + 28 * u + i * 17 * u, cy + bh * 0.3, 3.4 * u, 0, Math.PI * 2);
    g.stroke();
  }

  // port cluster on the lower edge
  g.strokeStyle = 'rgba(34,211,238,0.4)';
  g.lineWidth = 1.2;
  for (let i = 0; i < 4; i++) {
    const px = cx - bw * 0.36 + i * 26 * u;
    roundedRect(g, px, by + bh - 20 * u, 16 * u, 9 * u, 2 * u);
    g.stroke();
  }

  // recessed LED ring (right of center) — the sweep rides this in the loop
  const rx = cx + bw * 0.22;
  const ryc = cy - bh * 0.02;
  const ringR = bh * 0.3;
  g.strokeStyle = 'rgba(148,163,184,0.35)';
  g.lineWidth = 2 * u;
  g.beginPath();
  g.arc(rx, ryc, ringR, 0, Math.PI * 2);
  g.stroke();
  g.strokeStyle = 'rgba(34,211,238,0.16)';
  g.beginPath();
  g.arc(rx, ryc, ringR * 0.78, 0, Math.PI * 2);
  g.stroke();

  // antenna: stalk + glowing tip
  const ax = bx + bw - 26 * u;
  g.strokeStyle = 'rgba(165,243,252,0.55)';
  g.lineWidth = 2.4 * u;
  g.beginPath();
  g.moveTo(ax, by + 4 * u);
  g.lineTo(ax + 18 * u, by - 46 * u);
  g.stroke();
  g.fillStyle = 'rgba(34,211,238,0.85)';
  g.shadowColor = 'rgba(34,211,238,0.9)';
  g.shadowBlur = 14;
  g.beginPath();
  g.arc(ax + 18 * u, by - 46 * u, 4 * u, 0, Math.PI * 2);
  g.fill();
  g.shadowBlur = 0;

  return c;
}

export default function ArtPanel({
  variant = 'circuit',
  height = 300,
  kenburns = true,
  children,
  style,
  className,
}: {
  variant?: Variant;
  height?: number;
  kenburns?: boolean;
  children?: ReactNode; // caption slot (rendered above the scrim)
  style?: CSSProperties;
  className?: string;
}) {
  const ref = useRef<HTMLCanvasElement>(null);
  const wrap = useRef<HTMLDivElement>(null);
  const bake = useRef<HTMLCanvasElement | null>(null);
  const pulsesRef = useRef<Pulse[]>([]);
  const reduced = useRef(false);

  // Baked variants: re-bake at the panel's real device-res size whenever the
  // container resizes (ResizeObserver, rAF-debounced so a layout drag never
  // queues dozens of expensive bakes). minHeight — not fixed height — so a
  // taller caption can grow the panel without clipping.
  useEffect(() => {
    if (variant === 'fluid') return; // fluid renders a live canvas scene instead
    const canvas = ref.current;
    const box = wrap.current;
    if (!canvas || !box) return;
    reduced.current = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const animates = variant === 'holo' || variant === 'circuit' || variant === 'gridwave' || variant === 'device';

    let queued = 0;
    const rebake = () => {
      cancelAnimationFrame(queued);
      queued = requestAnimationFrame(() => {
        const dpr = Math.min(2, window.devicePixelRatio || 1); // 4K-crisp bake
        const w = Math.max(1, Math.round(box.clientWidth * dpr));
        const h = Math.max(1, Math.round(box.clientHeight * dpr));
        canvas.width = w;
        canvas.height = h;
        if (variant === 'circuit') {
          const { art, paths } = bakeCircuit(w, h);
          bake.current = art;
          // light pulses on a spread of the recorded traces
          pulsesRef.current = paths
            .filter((_, i) => i % 6 === 0)
            .map((path, i) => {
              const rr = mulberry(0x9e37 + i);
              return { path, sp: 0.00004 + rr() * 0.00007, ph: rr(), rev: rr() > 0.5 };
            });
        } else {
          bake.current =
            variant === 'gridwave'
              ? bakeGridwave(w, h)
              : variant === 'device'
                ? bakeDevice(w, h)
                : bakeHolo(w, h);
        }
        if (!animates || reduced.current) canvas.getContext('2d')?.drawImage(bake.current, 0, 0);
      });
    };

    const ro = new ResizeObserver(rebake);
    ro.observe(box);
    rebake();

    let raf = 0;
    let live = true;
    if (animates && !reduced.current) {
      const g2 = canvas.getContext('2d')!;
      const par = Array.from({ length: 46 }, (_, j) => {
        const rr = mulberry(0xace2 + j);
        return { a0: rr() * Math.PI * 2, sp: 0.00012 + rr() * 0.00035, orr: 0.45 + rr() * 0.75, size: 0.8 + rr() * 1.3, violet: rr() > 0.5 };
      });
      const animate = (t: number) => {
        if (!live) return;
        if (bake.current && document.visibilityState === 'visible') {
          g2.clearRect(0, 0, canvas.width, canvas.height);
          g2.drawImage(bake.current, 0, 0);
          const dpr = Math.min(2, window.devicePixelRatio || 1);

          if (variant === 'holo') {
            const r = Math.min(canvas.width, canvas.height) * 0.28 * 1.7;
            const cx = canvas.width / 2;
            const cy = canvas.height * 0.46;
            g2.globalCompositeOperation = 'lighter';
            for (const p of par) {
              const a = p.a0 + t * p.sp;
              const x = cx + Math.cos(a) * r * p.orr;
              const y = cy + Math.sin(a) * r * p.orr * 0.48;
              g2.fillStyle = p.violet ? 'rgba(168,85,247,0.75)' : 'rgba(34,211,238,0.75)';
              g2.beginPath();
              g2.arc(x, y, p.size * dpr, 0, Math.PI * 2);
              g2.fill();
            }
            // scan sweep
            const syp = ((t * 0.00006) % 1) * canvas.height;
            const sw = g2.createLinearGradient(0, syp - 34 * dpr, 0, syp);
            sw.addColorStop(0, 'rgba(34,211,238,0)');
            sw.addColorStop(1, 'rgba(34,211,238,0.14)');
            g2.fillStyle = sw;
            g2.fillRect(0, syp - 34 * dpr, canvas.width, 34 * dpr);
            g2.fillStyle = 'rgba(34,211,238,0.5)';
            g2.fillRect(0, syp, canvas.width, 1.4 * dpr);
          } else if (variant === 'circuit') {
            // signal pulses riding the recorded traces, additive glow, short tail
            g2.globalCompositeOperation = 'lighter';
            for (const q of pulsesRef.current) {
              const prog = (t * q.sp + q.ph) % 1;
              const p = q.rev ? 1 - prog : prog;
              for (let k = 0; k < 4; k++) {
                const pp = Math.max(0, Math.min(1, p - k * 0.018));
                const [x, y] = walkPath(q.path.pts, pp);
                const a = (1 - k / 4) * (q.path.hot ? 0.9 : 0.5);
                if (k === 0) {
                  g2.shadowColor = q.path.violet ? 'rgba(168,85,247,0.9)' : 'rgba(34,211,238,0.9)';
                  g2.shadowBlur = 10 * dpr;
                }
                g2.fillStyle = q.path.violet ? `rgba(168,85,247,${a.toFixed(3)})` : `rgba(34,211,238,${a.toFixed(3)})`;
                g2.beginPath();
                g2.arc(x, y, (q.path.hot ? 2.6 : 1.8) * dpr * (1 - k * 0.18), 0, Math.PI * 2);
                g2.fill();
                if (k === 0) g2.shadowBlur = 0;
              }
            }
          } else if (variant === 'device') {
            // shared geometry with the bake (same numbers, same units)
            const u = Math.min(canvas.width, canvas.height) / 420;
            const cx = canvas.width * 0.5;
            const cy = canvas.height * 0.52;
            const bw = 190 * u;
            const bh = 120 * u;
            const rx = cx + bw * 0.22;
            const ryc = cy - bh * 0.02;
            const ringR = bh * 0.3;
            g2.globalCompositeOperation = 'lighter';
            // rotating sweep arc riding the LED ring
            const a0 = t * 0.0011;
            for (let k = 0; k < 5; k++) {
              const aa = a0 - k * 0.055;
              g2.strokeStyle = `rgba(34,211,238,${(0.85 * (1 - k / 5)).toFixed(3)})`;
              g2.lineWidth = 3.4 * u;
              g2.beginPath();
              g2.arc(rx, ryc, ringR, aa, aa + 0.5);
              g2.stroke();
            }
            // inner ring pulse
            g2.strokeStyle = `rgba(168,85,247,${(0.25 + 0.2 * Math.sin(t * 0.002)).toFixed(3)})`;
            g2.lineWidth = 2 * u;
            g2.beginPath();
            g2.arc(rx, ryc, ringR * 0.78, 0, Math.PI * 2);
            g2.stroke();
            // status LEDs blink in their baked wells
            for (let i = 0; i < 3; i++) {
              const on = Math.sin(t * (0.0016 + i * 0.0007) + i * 2.1) > 0.2;
              g2.fillStyle = on ? 'rgba(52,211,153,0.9)' : 'rgba(52,211,153,0.14)';
              g2.beginPath();
              g2.arc(cx - bw / 2 + 28 * u + i * 17 * u, cy + bh * 0.3, 2.6 * u, 0, Math.PI * 2);
              g2.fill();
            }
            g2.globalCompositeOperation = 'source-over';
          } else {
            // gridwave: horizontal lines march out of the horizon (perspective)
            const hy = canvas.height * 0.44;
            g2.globalCompositeOperation = 'lighter';
            for (let i = 0; i < 15; i++) {
              const u = ((i / 15) + (t * 0.00008 - Math.floor(t * 0.00008))) % 1;
              const y = hy + (canvas.height - hy) * Math.pow(u, 2.3);
              g2.lineWidth = (1 + 1.1 * u) * dpr;
              g2.strokeStyle = i % 4 === 0 ? `rgba(168,85,247,${(0.1 + 0.24 * u).toFixed(3)})` : `rgba(34,211,238,${(0.05 + 0.28 * u).toFixed(3)})`;
              g2.beginPath();
              g2.moveTo(0, y);
              g2.lineTo(canvas.width, y);
              g2.stroke();
            }
          }
          g2.globalCompositeOperation = 'source-over';
        }
        raf = requestAnimationFrame(animate);
      };
      raf = requestAnimationFrame(animate);
    }

    return () => {
      live = false;
      cancelAnimationFrame(raf);
      cancelAnimationFrame(queued);
      ro.disconnect();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [variant]);

  if (variant === 'fluid') {
    // Living aurora panel — the FluidScene canvas IS the artwork (self-animating,
    // pointer-reactive, container-sized). No bake, no Ken Burns.
    return (
      <div className={`sf-cinematic${className ? ` ${className}` : ''}`} style={{ minHeight: height, ...style }}>
        <FluidScene opacity={0.75} />
        <div aria-hidden className="sf-cinematic-scrim" />
        <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'flex-end', padding: 18 }}>
          <div>{children}</div>
        </div>
      </div>
    );
  }

  return (
    <div ref={wrap} className={`sf-cinematic${className ? ` ${className}` : ''}`} style={{ minHeight: height, ...style }}>
      <canvas
        ref={ref}
        aria-hidden
        className={(variant === 'circuit' || variant === 'device') && kenburns ? 'sf-kenburns' : undefined}
        style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}
      />
      {/* scrim so the caption stays readable; hides the hard edges of the pan */}
      <div aria-hidden className="sf-cinematic-scrim" />
      <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'flex-end', padding: 18 }}>
        <div>{children}</div>
      </div>
    </div>
  );
}
