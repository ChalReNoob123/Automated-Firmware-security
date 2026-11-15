'use client';
import { motion } from 'framer-motion';
import type { CSSProperties, ReactNode } from 'react';

// Round 15: the site-wide glass spotlight rides React's own delegated events.
// The old round-9 design used a document-level listener (PointerGlow.tsx) that
// fired as soon as the layout hydrated and could then write --gx/--gy into
// .sf-glass elements of NOT-YET-HYDRATED components (streamed boundaries,
// late chunks) — React then saw mutated server HTML and logged a hydration
// mismatch (user-reported). React synthetic handlers only dispatch through
// hydrated fibers, so this whole failure class is gone. Perf profile is the
// same: one native pointermove listener total (React root delegation), zero
// per-card listeners, no re-renders.
export function glassGlow(e: React.PointerEvent<HTMLElement>) {
  const el = e.currentTarget;
  const r = el.getBoundingClientRect();
  el.style.setProperty('--gx', `${e.clientX - r.left}px`);
  el.style.setProperty('--gy', `${e.clientY - r.top}px`);
}

// Shared rich kit — one visual language for every operations page.
export function Card({ children, style }: { children: ReactNode; style?: CSSProperties }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 22 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
      className="sf-glass"
      onPointerMove={glassGlow}
      style={{ borderRadius: 18, padding: 22, ...style }}
    >
      {children}
    </motion.div>
  );
}

export function Eyebrow({ children }: { children: ReactNode }) {
  return <p className="sf-eyebrow">{children}</p>;
}

export function Badge({ tone, children }: { tone: 'cyan' | 'rose' | 'amber' | 'green' | 'violet' | 'gray'; children: ReactNode }) {
  const map: Record<string, string> = {
    cyan: 'rgba(34,211,238,0.12)|rgba(34,211,238,0.35)|#a5f3fc',
    rose: 'rgba(244,63,94,0.12)|rgba(244,63,94,0.4)|#fca5a5',
    amber: 'rgba(245,158,11,0.12)|rgba(245,158,11,0.4)|#fcd34d',
    green: 'rgba(52,211,153,0.12)|rgba(52,211,153,0.4)|#6ee7b7',
    violet: 'rgba(168,85,247,0.14)|rgba(168,85,247,0.4)|#d8b4fe',
    gray: 'rgba(148,163,184,0.12)|rgba(148,163,184,0.35)|#cbd5e1',
  };
  const [bg, border, color] = map[tone].split('|');
  return (
    <span style={{ background: bg, border: `1px solid ${border}`, color, borderRadius: 999, padding: '4px 12px', fontSize: 12, fontWeight: 700, whiteSpace: 'nowrap' }}>
      {children}
    </span>
  );
}

export function Stat({ label, value, sub }: { label: string; value: ReactNode; sub?: string }) {
  return (
    <div className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 16, padding: '16px 18px 14px', minWidth: 150, flex: '1 1 150px', position: 'relative', overflow: 'hidden' }}>
      <div style={{ position: 'absolute', top: 0, left: 18, right: 18, height: 2, borderRadius: 2, background: 'linear-gradient(90deg,#22d3ee,#a855f7)', opacity: 0.85 }} />
      <div style={{ position: 'absolute', top: -30, right: -30, width: 90, height: 90, borderRadius: '50%', background: 'radial-gradient(circle, rgba(34,211,238,0.14), transparent 70%)', pointerEvents: 'none' }} />
      <div style={{ fontSize: 11, letterSpacing: 2, color: '#64748b' }}>{label}</div>
      <div className="sf-gradient-text" style={{ fontSize: 27, fontWeight: 800, marginTop: 3, letterSpacing: -0.5 }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

export function Empty({ title, hint }: { title: string; hint: string }) {
  return (
    <div style={{ border: '1px dashed rgba(255,255,255,0.16)', borderRadius: 14, padding: 26, textAlign: 'center' }}>
      <div style={{ color: '#e2e8f0', fontWeight: 700 }}>{title}</div>
      <div style={{ color: '#64748b', fontSize: 13, marginTop: 4 }}>{hint}</div>
    </div>
  );
}

export function Code({ children }: { children: ReactNode }) {
  return (
    <code style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, padding: '1px 7px', fontSize: 12.5, color: '#a5f3fc', fontFamily: 'ui-monospace, Menlo, Consolas, monospace' }}>
      {children}
    </code>
  );
}
