'use client';
import { motion } from 'framer-motion';
import type { ReactNode } from 'react';

// Shared rich kit — one visual language for every operations page.
export function Card({ children, style }: { children: ReactNode; style?: React.CSSProperties }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 22 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
      className="sf-glass"
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

export function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="sf-glass" style={{ borderRadius: 14, padding: '14px 16px', minWidth: 140, flex: '1 1 140px' }}>
      <div style={{ fontSize: 11, letterSpacing: 2, color: '#64748b' }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 800, color: '#fff', marginTop: 2 }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 2 }}>{sub}</div>}
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
