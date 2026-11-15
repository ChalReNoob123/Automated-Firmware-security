'use client';
import { useEffect, useRef, useState } from 'react';
import { usePathname } from 'next/navigation';
import { motion, useReducedMotion, type Variants } from 'framer-motion';
import { API_URL, getMe, logoutEverywhere } from './lib/auth';
import MenuOverlay from './MenuOverlay';
import SoundToggle from './audio/SoundToggle';

// Global glass nav. Round 6: richer glass, pill links with an active glow,
// breathing brand sigil + text sheen, a real status chip, a styled login
// button, a proper 3-bar burger, and a staggered entrance cascade — all
// gated for reduced motion.

const LINKS: [string, string][] = [
  ['Forge', '/'],
  ['Dashboard', '/dashboard'],
  ['Devices', '/devices'],
  ['Device Lab', '/lab'],
  ['Emulator', '/emulator'],
  ['Attack Sim', '/attacks'],
  ['Radar', '/radar'],
  ['Reports', '/reports'],
  ['Copilot', '/copilot'],
];

function ApiDot() {
  const [up, setUp] = useState<boolean | null>(null);
  useEffect(() => {
    let live = true;
    const ping = async () => {
      try {
        const r = await fetch(`${API_URL}/health`);
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
  const label = up === null ? 'API …' : up ? 'API LIVE' : 'API DOWN';
  return (
    <span className="sf-api-chip" style={{ color, borderColor: `${color}44`, background: `${color}12` }}>
      <span
        className={`sf-api-dot${up ? ' live' : ''}`}
        style={{ width: 7, height: 7, borderRadius: '50%', background: color, boxShadow: `0 0 9px ${color}` }}
      />
      {label}
    </span>
  );
}

function Clock() {
  // Live UTC console clock — the chrome itself should feel like a running system.
  const [t, setT] = useState('');
  useEffect(() => {
    const fmt = () => setT(new Date().toISOString().slice(11, 19) + ' UTC');
    fmt();
    const iv = setInterval(fmt, 1000);
    return () => clearInterval(iv);
  }, []);
  return (
    <span className="sf-clock" suppressHydrationWarning>
      {t || '--:--:-- UTC'}
    </span>
  );
}

function SessionChip() {
  const [me, setMe] = useState<{ username: string; role: string } | null | undefined>(undefined);
  const check = async () => {
    const u = await getMe();
    setMe(u ? { username: u.username, role: u.role } : null);
  };
  useEffect(() => {
    void check();
    // Silent refresh can mint a session while the tab is hidden (login in
    // another window) — re-check when the tab becomes visible again.
    const onVis = () => {
      if (document.visibilityState === 'visible') void check();
    };
    document.addEventListener('visibilitychange', onVis);
    return () => document.removeEventListener('visibilitychange', onVis);
  }, []);
  if (me === undefined) return null;
  if (me === null) {
    return (
      <a href="/login" className="sf-login-btn">
        Login
      </a>
    );
  }
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
      <span
        title={me.username}
        style={{
          fontSize: 11,
          letterSpacing: 0.5,
          color: '#a5f3fc',
          border: '1px solid rgba(34,211,238,0.35)',
          borderRadius: 999,
          padding: '5px 11px',
          background: 'rgba(34,211,238,0.08)',
          whiteSpace: 'nowrap',
        }}
      >
        {me.username} · {me.role.toUpperCase()}
      </span>
      <button
        className="sf-btn"
        style={{ fontSize: 11, padding: '5px 11px' }}
        onClick={async () => {
          await logoutEverywhere();
          setMe(null);
          location.href = '/';
        }}
      >
        Sign out
      </button>
    </span>
  );
}

const navItem: Variants = {
  hidden: { opacity: 0, y: -10, filter: 'blur(6px)' },
  show: { opacity: 1, y: 0, filter: 'blur(0px)', transition: { duration: 0.45, ease: [0.22, 1, 0.36, 1] } },
};

const navStill: Variants = {
  hidden: { opacity: 1 },
  show: { opacity: 1, transition: { duration: 0 } },
};

export default function Nav() {
  const path = usePathname();
  // The glass intensifies once the page scrolls — the bar "notices" movement.
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const on = () => setScrolled(window.scrollY > 8);
    on();
    window.addEventListener('scroll', on, { passive: true });
    return () => window.removeEventListener('scroll', on);
  }, []);
  const [menu, setMenu] = useState(false);
  const reduced = useReducedMotion() ?? false;
  const item = reduced ? navStill : navItem;

  // spotlight: each pill glows around the pointer (CSS vars, delegated)
  const linksRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = linksRef.current;
    if (!el) return;
    const move = (e: PointerEvent) => {
      const link = (e.target as Element | null)?.closest?.('.sf-nav-link') as HTMLElement | null;
      if (!link) return;
      const r = link.getBoundingClientRect();
      link.style.setProperty('--nx', `${e.clientX - r.left}px`);
      link.style.setProperty('--ny', `${e.clientY - r.top}px`);
    };
    el.addEventListener('pointermove', move, { passive: true });
    return () => el.removeEventListener('pointermove', move);
  }, []);
  return (
    <motion.nav
      className={`sf-nav${scrolled ? ' sf-nav-scrolled' : ''}`}
      initial={reduced ? false : 'hidden'}
      animate="show"
      variants={{ hidden: {}, show: { transition: { staggerChildren: reduced ? 0 : 0.04, delayChildren: reduced ? 0 : 0.05 } } }}
    >
      <motion.a variants={item} href="/" className="sf-brand" aria-label="SentinelForge home">
        <span className="sf-brand-mark" aria-hidden>
          ◈
        </span>
        <span className="sf-brand-text">SENTINELFORGE</span>
      </motion.a>
      <div ref={linksRef} className="sf-nav-links">
        {LINKS.map(([label, href]) => (
          <motion.a
            key={href}
            variants={item}
            href={href}
            aria-current={path === href ? 'page' : undefined}
            className={path === href ? 'sf-nav-link sf-nav-active' : 'sf-nav-link'}
          >
            {path === href && <i className="sf-reticle" aria-hidden />}
            {label}
          </motion.a>
        ))}
      </div>
      <motion.div
        variants={item}
        style={{ marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: 14 }}
      >
        <SoundToggle />
        <button
          className="sf-kbtn"
          aria-label="Open command palette (Ctrl+K)"
          title="Command palette — Ctrl+K"
          onClick={() => window.dispatchEvent(new CustomEvent('sf:palette:open'))}
        >
          <span aria-hidden>⌘</span>K
        </button>
        <button className="sf-burger" aria-label="Open menu" aria-expanded={menu} onClick={() => setMenu(true)}>
          <span className="sf-burger-icon" aria-hidden>
            <span />
            <span />
            <span />
          </span>
          MENU
        </button>
        <SessionChip />
        <Clock />
        <ApiDot />
      </motion.div>
      <MenuOverlay open={menu} onClose={() => setMenu(false)} />
    </motion.nav>
  );
}
