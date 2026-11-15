'use client';
import { useCallback, useEffect, useRef, useState } from 'react';

// Command palette — Ctrl/Cmd+K. Award-site staple, real utility: one modal to
// reach every surface. Keyboard-first (arrows/enter/escape), pointer-friendly,
// reduced-motion safe (CSS gates the animations), and navigation goes through
// the `sf:transit` event so the route curtain choreographs the trip.

type Item = { eyebrow: string; label: string; hint: string; href: string };

const ITEMS: Item[] = [
  { eyebrow: 'PAGES', label: 'Forge', hint: 'Landing story', href: '/' },
  { eyebrow: 'PAGES', label: 'Dashboard', hint: 'Whole fleet at a glance', href: '/dashboard' },
  { eyebrow: 'PAGES', label: 'Devices', hint: 'Connect real hardware', href: '/devices' },
  { eyebrow: 'PAGES', label: 'Device Lab', hint: 'Virtual bench hardware', href: '/lab' },
  { eyebrow: 'PAGES', label: 'Emulator', hint: 'Boot. Break. Replay.', href: '/emulator' },
  { eyebrow: 'PAGES', label: 'Attack Sim', hint: 'Mirai-style takeover', href: '/attacks' },
  { eyebrow: 'PAGES', label: 'Radar', hint: 'N-day disclosure tracking', href: '/radar' },
  { eyebrow: 'PAGES', label: 'Reports', hint: 'Export the verdict', href: '/reports' },
  { eyebrow: 'PAGES', label: 'Copilot', hint: 'Ask the engines', href: '/copilot' },
  { eyebrow: 'ACCOUNT', label: 'Login', hint: 'Back to the bench', href: '/login' },
  { eyebrow: 'ACCOUNT', label: 'Sign up', hint: 'Claim a workspace', href: '/signup' },
];

export default function Palette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const restoreRef = useRef<HTMLElement | null>(null);

  const filtered = ITEMS.map((it) => {
    const q = query.trim().toLowerCase();
    if (!q) return { it, rank: 0 };
    const l = it.label.toLowerCase();
    const h = it.hint.toLowerCase();
    const rank = l.startsWith(q) ? 0 : l.includes(q) ? 1 : h.includes(q) ? 2 : -1;
    return { it, rank };
  })
    .filter((x) => x.rank >= 0)
    .sort((a, b) => a.rank - b.rank)
    .map((x) => x.it);

  const close = useCallback(() => {
    setOpen(false);
    setQuery('');
    setActive(0);
    restoreRef.current?.focus?.();
    restoreRef.current = null;
  }, []);

  const go = useCallback((href: string) => {
    close();
    // the route curtain owns the transition choreography
    window.dispatchEvent(new CustomEvent('sf:transit', { detail: { href } }));
  }, [close]);

  // global keys: open/toggle, escape
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (open) close();
        else {
          restoreRef.current = document.activeElement as HTMLElement | null;
          setOpen(true);
        }
      } else if (e.key === 'Escape' && open) {
        close();
      }
    };
    window.addEventListener('keydown', onKey);
    const onOpen = () => {
      restoreRef.current = document.activeElement as HTMLElement | null;
      setOpen(true);
    };
    window.addEventListener('sf:palette:open', onOpen);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('sf:palette:open', onOpen);
    };
  }, [open, close]);

  // focus + scroll lock while open
  useEffect(() => {
    if (!open) return;
    const t = setTimeout(() => inputRef.current?.focus(), 30);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      clearTimeout(t);
      document.body.style.overflow = prev;
    };
  }, [open]);

  // keep the active option in view
  useEffect(() => {
    if (!open) return;
    listRef.current?.querySelector(`#sf-palette-opt-${active}`)?.scrollIntoView({ block: 'nearest' });
  }, [active, open]);

  if (!open) return null;

  return (
    <>
      <div className="sf-palette-scrim" onPointerDown={close} aria-hidden />
      <div className="sf-palette" role="dialog" aria-modal="true" aria-label="Command palette">
        <div className="sf-palette-head">
          <span className="sf-palette-glyph" aria-hidden>
            ◈
          </span>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setActive((a) => (filtered.length ? (a + 1) % filtered.length : 0));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActive((a) => (filtered.length ? (a - 1 + filtered.length) % filtered.length : 0));
              } else if (e.key === 'Enter') {
                e.preventDefault();
                const it = filtered[Math.min(active, filtered.length - 1)];
                if (it) go(it.href);
              }
            }}
            placeholder="Type a destination — forge, radar, copilot…"
            aria-label="Search destinations"
            aria-controls="sf-palette-list"
            aria-activedescendant={filtered.length ? `sf-palette-opt-${active}` : undefined}
            autoComplete="off"
            spellCheck={false}
          />
          <kbd className="sf-palette-kbd">ESC</kbd>
        </div>
        <ul id="sf-palette-list" role="listbox" aria-label="Destinations" ref={listRef}>
          {filtered.map((it, i) => (
            <li
              key={it.href}
              id={`sf-palette-opt-${i}`}
              role="option"
              aria-selected={i === active}
              className={`sf-palette-row${i === active ? ' on' : ''}`}
              onPointerEnter={() => setActive(i)}
              onPointerDown={(e) => {
                e.preventDefault();
                go(it.href);
              }}
            >
              <span className="sf-palette-eyebrow">{it.eyebrow}</span>
              <span className="sf-palette-label">{it.label}</span>
              <span className="sf-palette-hint">{it.hint}</span>
              <span className="sf-palette-go" aria-hidden>
                ↵
              </span>
            </li>
          ))}
          {!filtered.length && <li className="sf-palette-empty">No match — try “radar” or “copilot”.</li>}
        </ul>
        <div className="sf-palette-foot" aria-hidden>
          <span>
            <kbd>↑↓</kbd> navigate
          </span>
          <span>
            <kbd>↵</kbd> open
          </span>
          <span>
            <kbd>esc</kbd> close
          </span>
          <span className="sf-palette-brand">SF://NAV</span>
        </div>
      </div>
    </>
  );
}
