'use client';
import { useEffect, useRef, useState } from 'react';
import ArtPanel from './ArtPanel';
import { Tilt } from './motionKit';

// Cinematic device reel — behaves like a monitoring video wall: slides
// crossfade with a slow Ken Burns drift, a progress rail tracks the loop, and
// the whole stage sits on a pointer-tracked 3D tilt with true depth (HUD,
// brackets and rail float at translateZ above the clipped glass).
//
// Photographic plates are AUTO-DETECTED: drop reel-1/2/3.(jpg|png|webp) into
// apps/web/public/devices/ and they lead the reel with zero code changes
// (HEAD-probed on mount). Until then the reel runs fully procedural — the
// generation quota is exhausted today (see SECURITY.md round 11).
// Reduced motion: static first slide, no loop, no sweep.

type Slide =
  | { kind: 'photo'; src: string; eyebrow: string; title: string; sub: string }
  | { kind: 'art'; variant: 'device' | 'holo' | 'circuit' | 'gridwave' | 'fluid'; eyebrow: string; title: string; sub: string };

const PHOTO_CANDIDATES = ['/devices/reel-1', '/devices/reel-2', '/devices/reel-3'];
const PHOTO_META = [
  ['HARDWARE INTAKE', 'Real fleet hardware, staged for acquisition', 'Photographic plates drop into public/devices and are picked up automatically — no code change.'],
  ['DEVICE FARM', 'DUT bench, isolated per run', 'Every device boots inside a logged, attestation-gated acquisition window.'],
  ['RADIO LAB', 'USB · BLE · Zigbee · Z-Wave harnesses', 'Radio surfaces are probed read-only until an authorization is on file.'],
] as const;

const ART_SLIDES: Slide[] = [
  { kind: 'art', variant: 'device', eyebrow: 'DIGITAL TWIN · HUB', title: 'Smart hub, rendered by math', sub: 'LED-ring sweep, port cluster, antenna — drawn at native resolution, never a JPEG.' },
  { kind: 'art', variant: 'holo', eyebrow: 'WIREFRAME TWIN', title: 'The twin, orbit-scanned', sub: 'Orbiting particles and a scan sweep boot the twin in this light.' },
  { kind: 'art', variant: 'circuit', eyebrow: 'MACRO FIRMWARE', title: 'PCB macro, signals alive', sub: 'Seeded topology with pulses riding the real recorded traces.' },
  { kind: 'art', variant: 'gridwave', eyebrow: 'DEPTH GRID', title: 'Perspective horizon, endless', sub: 'A scrolling depth grid carries the eye to the acquisition floor.' },
  { kind: 'art', variant: 'fluid', eyebrow: 'LIVE FLUID', title: 'Aurora, simulated in real time', sub: 'A Navier–Stokes-style field painted at native resolution, never a video.' },
];

const HOLD = 7000; // ms per slide

export default function DeviceReel() {
  const [slides, setSlides] = useState<Slide[]>(ART_SLIDES);
  const [idx, setIdx] = useState(0);
  const [paused, setPaused] = useState(false);
  const [static_, setStatic] = useState(false);
  const timer = useRef(0);

  useEffect(() => {
    setStatic(window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }, []);

  // discover photographic plates once per mount: ONE clean request to the
  // /api/reel-photos route handler (round-16a: the old HEAD-probe loop logged
  // six expected-but-noisy 404s per page load). HEAD probing remains only as a
  // fallback if the handler itself is unavailable.
  useEffect(() => {
    let live = true;
    void (async () => {
      let found: Slide[] = [];
      let handlerOk = false;
      try {
        const r = await fetch('/api/reel-photos');
        if (r.ok) {
          // NOTE: an empty photos list is a VALID answer (no plates dropped
          // yet) — only a failed/!ok request falls back to probing.
          handlerOk = true;
          const { photos } = (await r.json()) as { photos: string[] };
          found = photos.map((src) => {
            const i = Math.max(0, Number(/reel-(\d+)/.exec(src)?.[1] ?? 1) - 1);
            const [eyebrow, title, sub] = PHOTO_META[i] ?? PHOTO_META[0];
            return { kind: 'photo', src, eyebrow, title, sub } as Slide;
          });
        }
      } catch {
        /* handler unavailable — fall back to probing below */
      }
      if (!handlerOk) {
        const exts = ['.jpg', '.png', '.webp'];
        for (let i = 0; i < PHOTO_CANDIDATES.length; i++) {
          for (const ext of exts) {
            try {
              const r = await fetch(PHOTO_CANDIDATES[i] + ext, { method: 'HEAD' });
              if (r.ok) {
                const [eyebrow, title, sub] = PHOTO_META[i];
                found.push({ kind: 'photo', src: PHOTO_CANDIDATES[i] + ext, eyebrow, title, sub });
                break;
              }
            } catch {
              // offline probe failure → treat as absent
            }
          }
        }
      }
      if (live && found.length) setSlides([...found, ...ART_SLIDES]);
    })();
    return () => {
      live = false;
    };
  }, []);

  // the loop (paused on hover, off for reduced motion)
  useEffect(() => {
    if (static_ || paused || slides.length < 2) return;
    timer.current = window.setInterval(() => setIdx((i) => (i + 1) % slides.length), HOLD);
    return () => clearInterval(timer.current);
  }, [static_, paused, slides.length]);

  const cur = slides[Math.min(idx, slides.length - 1)];
  // mount only the current slide and its two neighbors — keeps at most two
  // procedural canvases animating at once
  const keep = (i: number) => {
    const d = (i - idx + slides.length) % slides.length;
    return d === 0 || d === 1 || d === slides.length - 1;
  };

  return (
    <div className="sf-reel-wrap" data-cursor="view" onPointerEnter={() => setPaused(true)} onPointerLeave={() => setPaused(false)}>
      <Tilt max={4} glare={false} className="sf-reel-tilt">
        <div className="sf-reel-stage" role="img" aria-label={`Device reel: ${cur.title}`}>
          <div className="sf-reel">
            {slides.map((s, i) =>
              keep(i) ? (
                <div key={s.kind === 'photo' ? s.src : s.variant} className={`sf-reel-slide${i === idx ? ' on' : ''}`} aria-hidden={i !== idx}>
                  {s.kind === 'photo' ? (
                    <>
                      {/* eslint-disable-next-line @next/next/no-img-element */}
                      <img src={s.src} alt="" className="sf-reel-img" draggable={false} />
                      <div className="sf-reel-scrim" aria-hidden />
                      <div className="sf-reel-photo-caption">
                        <div className="sf-caption-eyebrow">{s.eyebrow}</div>
                        <div className="sf-caption-title">{s.title}</div>
                        <div className="sf-caption-sub">{s.sub}</div>
                      </div>
                    </>
                  ) : (
                    <ArtPanel variant={s.variant} height={0} kenburns={s.variant === 'circuit' || s.variant === 'device'}>
                      <div className="sf-caption-eyebrow">{s.eyebrow}</div>
                      <div className="sf-caption-title">{s.title}</div>
                      <div className="sf-caption-sub">{s.sub}</div>
                    </ArtPanel>
                  )}
                </div>
              ) : null,
            )}
            <div className="sf-reel-scan" aria-hidden />
          </div>
          {/* HUD chrome floats in true 3D above the clipped glass */}
          <div className="sf-reel-hud" aria-hidden>
            <div>SF://FEED · HARDWARE REEL</div>
            <div>
              {String(Math.min(idx, slides.length - 1) + 1).padStart(2, '0')} / {String(slides.length).padStart(2, '0')}
              {paused ? ' · HOLD' : ''}
            </div>
          </div>
          <div className="sf-reel-brackets" aria-hidden />
          <div className="sf-reel-rail" aria-hidden>
            {slides.map((s, i) => (
              <span key={s.kind === 'photo' ? s.src : s.variant} className={`sf-reel-seg${i === idx ? ' on' : ''}`} />
            ))}
          </div>
        </div>
      </Tilt>
    </div>
  );
}
