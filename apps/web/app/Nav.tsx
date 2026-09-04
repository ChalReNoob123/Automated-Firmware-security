'use client';
import { useEffect, useState } from 'react';
import { usePathname } from 'next/navigation';

// Global glass nav: brand + section links + live API status dot.
const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
const LINKS: [string, string][] = [
  ['Forge', '/'],
  ['Devices', '/devices'],
  ['Device Lab', '/lab'],
  ['Emulator', '/emulator'],
  ['Attack Sim', '/attacks'],
  ['Radar', '/radar'],
  ['Copilot', '/copilot'],
  ['Login', '/login'],
];

function ApiDot() {
  const [up, setUp] = useState<boolean | null>(null);
  useEffect(() => {
    let live = true;
    const ping = async () => {
      try {
        const r = await fetch(`${API}/health`);
        if (live) setUp(r.ok);
      } catch {
        if (live) setUp(false);
      }
    };
    void ping();
    const t = setInterval(ping, 15000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, []);
  const color = up === null ? '#64748b' : up ? '#34d399' : '#f43f5e';
  const label = up === null ? '…' : up ? 'API LIVE' : 'API DOWN';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontSize: 11, letterSpacing: 2, color }}>
      <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, boxShadow: `0 0 10px ${color}` }} />
      {label}
    </span>
  );
}

export default function Nav() {
  const path = usePathname();
  return (
    <nav className="sf-nav">
      <a href="/" className="sf-brand">
        <span className="sf-brand-mark">◈</span> SENTINELFORGE
      </a>
      <div className="sf-nav-links">
        {LINKS.map(([label, href]) => (
          <a key={href} href={href} className={path === href ? 'sf-nav-link sf-nav-active' : 'sf-nav-link'}>
            {label}
          </a>
        ))}
      </div>
      <ApiDot />
    </nav>
  );
}
