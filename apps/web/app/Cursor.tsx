'use client';
import { useEffect, useRef, useState } from 'react';
import { useStory } from './storyStore';

// Lusion-style cursor: instant dot + lagging ring that swells over interactive
// targets. Round 10 adds a deepest-layer halo that trails furthest behind —
// three stacked latencies read as fluid inertia. Round 17 turns it into a
// contextual state machine: elements can declare a cursor intent via a
// `data-cursor` attribute (the WebGL stage declares "drag", the device reel
// "view"), the ring grows and a small mono tip names the affordance, and
// while the ensemble is being dragged the tip flips to ORBIT (read straight
// from the story store's dragging flag — no per-frame React renders).
// Desktop pointers only (hover:hover + pointer:fine); skipped for
// reduced-motion; the native cursor is hidden via an <html> class so a JS
// failure never leaves the site cursorless.
export default function Cursor() {
  const dot = useRef<HTMLDivElement>(null);
  const ring = useRef<HTMLDivElement>(null);
  const halo = useRef<HTMLDivElement>(null);
  const tip = useRef<HTMLDivElement>(null);
  const [enabled, setEnabled] = useState(false);
  const [label, setLabel] = useState<string | null>(null);
  const dragging = useStory((s) => s.dragging);
  const hoverRef = useRef(false);
  const labelRef = useRef<string | null>(null);

  useEffect(() => {
    const fine = window.matchMedia('(hover: hover) and (pointer: fine)').matches;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (!fine || reduced) return;
    document.documentElement.classList.add('sf-cursor-on');
    setEnabled(true);

    let x = window.innerWidth / 2;
    let y = window.innerHeight / 2;
    let rx = x;
    let ry = y;
    let hx = x;
    let hy = y;
    let tx = x;
    let ty = y;
    let s = 1;
    let h = 1;
    let raf = 0;

    const move = (e: PointerEvent) => {
      x = e.clientX;
      y = e.clientY;
      if (dot.current) dot.current.style.transform = `translate(${x}px, ${y}px)`;
    };
    const over = (e: PointerEvent) => {
      const t = e.target as Element | null;
      hoverRef.current = !!t?.closest?.('a, button, input, select, textarea, .sf-card-hover, [role="button"]');
      const lab = t?.closest?.('[data-cursor]')?.getAttribute('data-cursor') ?? null;
      if (lab !== labelRef.current) {
        labelRef.current = lab;
        setLabel(lab); // rare — only on hover transitions between regions
      }
    };
    const loop = () => {
      rx += (x - rx) * 0.16;
      ry += (y - ry) * 0.16;
      const isDragging = useStory.getState().dragging;
      const target = isDragging ? 2.4 : labelRef.current ? 2.1 : hoverRef.current ? 1.9 : 1;
      s += (target - s) * 0.14;
      if (ring.current) ring.current.style.transform = `translate(${rx}px, ${ry}px) scale(${s.toFixed(3)})`;
      hx += (x - hx) * 0.055;
      hy += (y - hy) * 0.055;
      h += ((hoverRef.current || labelRef.current ? 1.45 : 1) - h) * 0.07;
      if (halo.current) halo.current.style.transform = `translate(${hx}px, ${hy}px) scale(${h.toFixed(3)})`;
      // the tip follows with its own latency, offset down-right of the pointer
      tx += (x + 20 - tx) * 0.24;
      ty += (y + 22 - ty) * 0.24;
      if (tip.current) tip.current.style.transform = `translate(${tx.toFixed(1)}px, ${ty.toFixed(1)}px)`;
      raf = requestAnimationFrame(loop);
    };
    window.addEventListener('pointermove', move, { passive: true });
    window.addEventListener('pointerover', over, { passive: true });
    raf = requestAnimationFrame(loop);
    return () => {
      document.documentElement.classList.remove('sf-cursor-on');
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerover', over);
      cancelAnimationFrame(raf);
    };
  }, []);

  if (!enabled) return null;
  const text = dragging ? 'ORBIT' : label ? label.toUpperCase() : null;
  return (
    <>
      <div ref={halo} className="sf-cur-halo" aria-hidden />
      <div ref={dot} className="sf-cur-dot" aria-hidden />
      <div ref={ring} className={`sf-cur-ring${text ? ' labeled' : ''}`} aria-hidden />
      <div ref={tip} className={`sf-cur-tip${text ? ' on' : ''}`} aria-hidden>
        {text}
      </div>
    </>
  );
}
