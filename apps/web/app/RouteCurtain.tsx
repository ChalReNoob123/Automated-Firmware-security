'use client';
import { useEffect, useRef, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';

// Lusion-style route curtain: internal navigation is intercepted, a two-tone
// skewed wipe covers the viewport, the route swaps underneath, then the wipe
// continues out the other side — hard cuts become a fluid transit.
//
// Decoupling: anything can request a choreographed trip by dispatching the
// `sf:transit` CustomEvent with { href } (the command palette does); plain
// internal <a> clicks are intercepted at document level (capture) with the
// usual escape hatches respected (modifier keys, new tabs, external links).
// Reduced motion: the curtain never mounts and clicks pass through untouched.

const COVER_MS = 360;
const SETTLE_MS = 90; // let the new route paint before the wipe leaves
const REVEAL_MS = 560;
const SAFETY_MS = 1600; // never trap the user behind a stalled push

// canonical nav order — the wipe direction follows it: moving "forward" in
// the nav sweeps left→right, moving "back" sweeps right→left (round-18).
const ROUTE_ORDER = ['/', '/dashboard', '/devices', '/lab', '/emulator', '/attacks', '/radar', '/reports', '/copilot'];

export default function RouteCurtain() {
  const router = useRouter();
  const pathname = usePathname();
  const [phase, setPhase] = useState<'idle' | 'cover' | 'reveal'>('idle');
  const [dir, setDir] = useState<'fwd' | 'back'>('fwd');
  const [dest, setDest] = useState('TRANSIT');
  const pendingRef = useRef<string | null>(null);
  const timersRef = useRef<number[]>([]);
  const reducedRef = useRef(false);

  useEffect(() => {
    reducedRef.current = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }, []);

  const clearTimers = () => {
    timersRef.current.forEach((t) => clearTimeout(t));
    timersRef.current = [];
  };
  const later = (fn: () => void, ms: number) => {
    timersRef.current.push(window.setTimeout(fn, ms));
  };

  const startTransit = (href: string) => {
    if (reducedRef.current) {
      router.push(href);
      return;
    }
    clearTimers();
    // direction follows canonical route order; the curtain names the destination
    const from = ROUTE_ORDER.indexOf(pathname);
    const to = ROUTE_ORDER.indexOf(href);
    setDir(from === -1 || to === -1 || to >= from ? 'fwd' : 'back');
    setDest((href.replace(/^\//, '').replace(/-/g, ' ').toUpperCase()) || 'FORGE');
    pendingRef.current = href;
    setPhase('cover');
    later(() => router.push(href), COVER_MS);
    later(() => {
      // safety: if the route never changes (auth guard, same-path push),
      // never leave the page covered
      setPhase((p) => (p === 'cover' ? 'reveal' : p));
    }, SAFETY_MS);
  };

  // internal <a> interception
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
      const a = (e.target as Element | null)?.closest?.('a') as HTMLAnchorElement | null;
      if (!a) return;
      const href = a.getAttribute('href');
      if (!href || !href.startsWith('/') || href.startsWith('//') || a.target === '_blank' || a.hasAttribute('download')) return;
      if (href === pathname) return; // same path: let the router no-op
      e.preventDefault();
      startTransit(href);
    };
    document.addEventListener('click', onClick, true);
    return () => document.removeEventListener('click', onClick, true);
  }, [pathname, router]);

  // palette / programmatic trips — pathname is a dep so the direction calc
  // always sees the current route
  useEffect(() => {
    const onTransit = (e: Event) => {
      const href = (e as CustomEvent<{ href?: string }>).detail?.href;
      if (typeof href === 'string' && href.startsWith('/')) startTransit(href);
    };
    window.addEventListener('sf:transit', onTransit);
    return () => window.removeEventListener('sf:transit', onTransit);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router, pathname]);

  // pathname landed → sweep out
  useEffect(() => {
    if (phase === 'idle') return;
    if (pendingRef.current && pathname === pendingRef.current) {
      later(() => setPhase('reveal'), SETTLE_MS);
      later(() => setPhase('idle'), SETTLE_MS + REVEAL_MS);
      pendingRef.current = null;
    }
  }, [pathname, phase]);

  // unmount cleanup
  useEffect(() => clearTimers, []);

  if (phase === 'idle') return null;
  return (
    <div className={`sf-curtain${dir === 'back' ? ' sf-curtain--back' : ''}${phase === 'reveal' ? ' out' : ''}`} aria-hidden>
      <div className="sf-curtain-panel a" />
      <div className="sf-curtain-panel b" />
      <div className="sf-curtain-center">
        <span className="sf-curtain-glyph">◈</span>
        <span className="sf-curtain-word">SF://{dest}</span>
        <span className="sf-curtain-line" />
      </div>
    </div>
  );
}
