'use client';
import { useEffect, useRef } from 'react';

// Fluid aurora: additive light "blobs" drifting on a 2D canvas. Sized to its
// CONTAINER (ResizeObserver) so it works as a fullscreen backdrop and inside
// cards alike. Soft radial gradients at a 0.6× dpr raster stay visually
// identical after GPU upscaling while costing a fraction of 4K fill — on a 4K
// monitor the result is still pixel-perfect because gradients have no detail to
// lose. Pointer pulls the blobs toward the cursor. Reduced-motion users get one
// static painted frame; hidden tabs stop scheduling.
export default function FluidScene({ opacity = 0.5 }: { opacity?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return;

    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const blobs = [
      { x: 0.22, y: 0.3, r: 0.42, hue: 190, dx: 0.00013, dy: 0.00009, ph: 0.0, a: 0.55 },
      { x: 0.78, y: 0.22, r: 0.36, hue: 275, dx: -0.00011, dy: 0.00012, ph: 1.7, a: 0.5 },
      { x: 0.6, y: 0.72, r: 0.5, hue: 210, dx: 0.00009, dy: -0.00008, ph: 3.1, a: 0.42 },
      { x: 0.15, y: 0.78, r: 0.34, hue: 262, dx: -0.00013, dy: -0.00006, ph: 4.4, a: 0.44 },
      { x: 0.88, y: 0.62, r: 0.3, hue: 185, dx: 0.0001, dy: 0.00011, ph: 5.2, a: 0.4 },
      { x: 0.45, y: 0.12, r: 0.26, hue: 250, dx: -0.00008, dy: 0.0001, ph: 2.6, a: 0.36 },
    ] as const;

    let px = 0.5;
    let py = 0.5;
    let tx = 0.5;
    let ty = 0.5;
    const onPointer = (e: PointerEvent) => {
      const r = canvas.getBoundingClientRect();
      if (!r.width || !r.height) return;
      tx = (e.clientX - r.left) / r.width;
      ty = (e.clientY - r.top) / r.height;
    };

    let dprEff = 1;
    const resize = () => {
      dprEff = Math.min(2, window.devicePixelRatio || 1) * 0.6;
      const w = Math.max(1, canvas.clientWidth);
      const h = Math.max(1, canvas.clientHeight);
      canvas.width = Math.round(w * dprEff);
      canvas.height = Math.round(h * dprEff);
      ctx.setTransform(dprEff, 0, 0, dprEff, 0, 0);
    };
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    resize();

    const paint = (t: number) => {
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      if (!w || !h) return;
      ctx.clearRect(0, 0, w, h);
      ctx.globalCompositeOperation = 'lighter';
      px += (tx - px) * 0.02;
      py += (ty - py) * 0.02;
      for (const b of blobs) {
        const wob = reduced ? 0 : Math.sin(t * b.dx + b.ph) * 0.08;
        const wob2 = reduced ? 0 : Math.cos(t * b.dy + b.ph) * 0.06;
        const cx = (b.x + wob + (px - 0.5) * 0.05) * w;
        const cy = (b.y + wob2 + (py - 0.5) * 0.05) * h;
        const rad = b.r * Math.min(w, h) * (reduced ? 1 : 0.9 + Math.sin(t * b.dy + b.ph) * 0.05);
        const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, rad);
        g.addColorStop(0, `hsla(${b.hue}, 84%, 60%, ${(b.a * (reduced ? 0.6 : 0.5 + 0.18 * Math.sin(t * b.dx + b.ph))).toFixed(3)})`);
        g.addColorStop(0.55, `hsla(${b.hue}, 84%, 50%, ${(b.a * 0.32).toFixed(3)})`);
        g.addColorStop(1, 'hsla(230, 80%, 30%, 0)');
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(cx, cy, rad, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.globalCompositeOperation = 'source-over';
    };

    if (reduced) {
      paint(0); // single frame, no loop
      return () => ro.disconnect();
    }

    let raf = 0;
    let live = true;
    const loop = (t: number) => {
      if (!live) return;
      if (document.visibilityState === 'visible') paint(t);
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    window.addEventListener('pointermove', onPointer, { passive: true });

    return () => {
      live = false;
      cancelAnimationFrame(raf);
      ro.disconnect();
      window.removeEventListener('pointermove', onPointer);
    };
  }, []);

  return (
    <canvas
      ref={ref}
      aria-hidden
      style={{
        position: 'absolute',
        inset: 0,
        width: '100%',
        height: '100%',
        opacity,
        mixBlendMode: 'screen',
        pointerEvents: 'none',
      }}
    />
  );
}
