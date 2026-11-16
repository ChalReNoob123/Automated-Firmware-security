# SentinelForge Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| v3.x    | :white_check_mark: |
| v2.x    | :x:                |

## Reporting a Vulnerability

Please report security vulnerabilities to security@sentinelforge.io or use the GitHub Security Advisories tab. We aim to acknowledge reports within 3 business days and provide a fix or mitigation plan within 14 days.

## Security Architecture

### Authentication & Authorization

- **JWT Access Tokens**: 15-minute expiry, HS256 algorithm enforced, issuer + audience claims verified
- **Refresh Tokens**: 7-day expiry (30 days with "remember me"), rotating on each use, refresh-reuse detection revokes entire token family
- **TOTP 2FA**: Required on first login, speakeasy-based TOTP with window=1
- **RBAC**: 5 roles — Owner, Admin, Analyst, Viewer, Auditor — with fine-grained permissions
- **Rate Limiting**: Auth endpoints 60 req/15min per IP (+ per-identifier login limiter, 10 req/60s to stop distributed brute force on one account), Copilot 30 req/min, mutation endpoints 100 req/min, read endpoints 100 req/min
- **Account Lockout**: 5 failed login attempts triggers 15-minute lockout

### Authorization (RBAC Matrix)

| Role | Permissions |
|------|-------------|
| Owner | * (all permissions) |
| Admin | read:all, write:all, manage:users, attest:sign, scan:run, read:audit |
| Analyst | read:all, scan:run, attest:sign, triage:write |
| Viewer | read:telemetry, read:findings |
| Auditor | read:all, read:audit |

### Data Protection

- **Encryption at Rest**: PostgreSQL with `pgcrypto` extension; all sensitive fields encrypted
- **Encryption in Transit**: TLS 1.2+ required; `__Host-` cookie prefix in production
- **Input Validation**: Zod schemas on all endpoints, prototype-pollution protection, nested depth limit (16), dangerous character stripping
- **Audit Trail**: All auth events, device registrations, attestations, findings creation/deletion logged with user ID, org ID, IP, and timestamp

### Network Security

- CORS allowlist: only configured origins may access the API
- Content Security Policy: strict CSP with no inline scripts, no unsafe-eval
- Referrer-Policy: `strict-origin-when-cross-origin`
- Permissions-Policy: geolocation, microphone, camera disabled
- Rate Limiting: Per-IP rate limits on all API endpoints

## Known Limitations

- **SAML SSO**: Stub implementation only; no actual IdP integration
- **Org membership**: Single-user per org; no invite flow yet
- **Emulator**: QEMU-based emulation is a dry-run simulation unless QEMU binaries are installed on the host
- **Firmware analysis**: Heuristic-based (binwalk magic bytes, regex-based secret scanning); not a replacement for full binary analysis
- **Federated learning**: Not yet implemented (v4 stretch goal)
- **Web-tier CSP (dev)**: The Next.js dev CSP allows `unsafe-eval` (Turbopack) and `ws://localhost:3005` (HMR). Tighten
  `apps/web/next.config.js` for a hardened production build — the API tier CSP stays strict already.
- **Persistence (dev)**: Without Supabase credentials the API runs with `persistence: memory (dev fallback)`; all
  accounts, devices, attestations and emulator sessions are wiped on API restart. Production requires the Postgres
  schema in `packages/db/schema.sql`.
- **Shared IP auth budget (dev)**: All local traffic shares one IP for the 60 req/15min auth limiter. Simultaneous
  heavy API testing on `localhost` can throttle the web session's silent refresh (the UI degrades gracefully to the
  signed-out state). In production, per-IP limits distribute naturally across real client IPs.
- **Login UX**: After a completed login the auth chip can take ~1s to appear (memory-only access token + silent
  refresh cycle on first paint); no functional impact.
- **Native USB detection**: `GET /v1/system/usb-devices` enumerates the host's USB bus via a read-only Windows
  PnP/WMI query (PowerShell child process, −-auth-scoped, 15s cache, 30/min limiter). Truths it cannot escape:
  presence in Windows' device tree is NOT ownership — attestation remains the legal gate; and detection is
  Windows-only in this build (other hosts get an explicit note, manual registration covers non-Windows targets).

## Live-Adversarial Verification (2026-11-08)

Full battery executed against the running app (routes, auth E2E, pentest, stress, UI/UX, Lighthouse):

- Token forgery (`alg:none`, tampered payload, garbage signature, wrong audience) → all 401.
- Cross-org IDOR (read + write with valid foreign attestation) → 404, org-fenced.
- Attestation gate (missing / forged / foreign id) → 403 in all three cases.
- Prototype-pollution, `constructor`, 20-level nesting → 400. 13MB body → 413 (was 500 — fixed).
- CORS evil origin → 403, no `Access-Control-Allow-Origin` echoed.
- Lockout: progressive lockout messages → 15-min lock even with correct password; per-identifier limiter fires 429 by
  the 10th call in 60s; isolation between identifiers confirmed.
- Stress: 50×`/health` p50 12ms; 25 concurrent gated emulator boots all 201 p50 8ms. `/v1/capabilities` under 40-way
  concurrency serialized the event loop (~650ms/request, 26s burst) because toolchain probing spawned subprocesses per
  request — fixed with a 60s process cache (40-burst: 641ms cold → 20ms warm).
- UI: signup + login + TOTP enroll/verify proven end-to-end in the real browser; session chip, gate states
  (SIGNED IN / NOT ATTESTED), disabled CTAs, empty states, sign-out, 404 page, footer anchoring all verified with
  screenshots; Lighthouse a11y 100 (/login) / 96 (/), best-practices 100, SEO 100; console clean.
- Native USB auto-detection (`GET /v1/system/usb-devices`): unauthenticated → 401; authed → live Windows device tree
  (11 real devices incl. picker-hidden webcam/BT/HID), `win32-cim` source, 15s cache dedupe confirmed; UI E2E:
  auto-listed → selected → attested → registered device + `sf_att` unlock verified in the real browser.

## UI Enhancement Round 2 (2026-11-13) — verification notes

Second UI/UX animation pass (3D tilt, scroll progress, fluid aurora panels, dashboard chart choreography).
Honest verification status for this round:

- **No browser this round**: the in-app browser integration is unavailable, so NOTHING below was screenshot-verified.
  Evidence is TypeScript-clean build + HTTP smoke checks against the live dev servers (both were relaunched after a
  machine restart; API `:4000/health` → 200, web `:3005` → 200). Screenshots/axe runs should be re-run next time a
  browser is available.
- **Verified via HTTP**: all 10 routes + `/` return 200 and include the ambient-starfield markup; `/login` renders the
  split-screen grid (`sf-auth-split`) with the live fluid aurora panel; `/signup` renders the holo digital-twin panel;
  the scroll-progress bar is present in the SSR payload; unknown routes still return a real 404 status.
- **Accessibility unchanged in intent, re-verify pending**: every new motion (tilt cards, count-ups, chart draw-ins,
  aurora, scroll progress, Ken Burns) is gated on `prefers-reduced-motion` via `useReducedMotion()`/`matchMedia` or the
  CSS media query. This was true by construction but NOT re-verified with an axe/Lighthouse run this round.
- **Known cosmetic-console note**: a single 401 network line per page load is expected signed-out behavior (the silent
  session probe); JS dedupe (10 s backoff) was added so component mounts no longer stack refresh attempts.
- **Still in-memory**: API state resets on restart; the persistence/Supabase work remains the top durability gap.
- **AI imagery**: the image-generation quota (free tier) was exhausted again on 2026-11-13 (~11.5 h to reset); the
  "4K fluid imagery" is delivered procedurally (canvas-baked circuit/holo panels + live fluid aurora), not with
  generated assets. No retry spam until the user asks.

## UI Enhancement Round 3 (2026-11-13) — verification notes

Third animation pass (living circuit pulses, gridwave horizon, nav/CTA micro-interactions, attack-runner feedback):

- **Same verification limits as round 2**: no browser available; evidence is typecheck-clean plus HTTP smoke checks
  (API `:4000/health` → 200; all 10 app routes + `/` → 200; the new gridwave art tile present in the landing SSR
  payload; auth split-screens intact). Visual/interaction behavior is code-verified only.
- **Image quota probed once more at the user's request** (they re-asked for image animation): still free-tier-blocked,
  ~11 h20m to reset. All "4K imagery" remains procedural (see ArtPanel). No further retries until asked.
- **New procedural work**: `circuit` panels now record trace geometry during the bake and animate glowing signal
  pulses along it (additive, tailed); new `gridwave` variant renders a 3D perspective horizon with an endless
  scrolling depth grid (third landing art tile).
- **Reduced-motion**: all new motion (pulse/grid loops, run-scan sweep, API-dot pulse, shimmer, CTA sweep) is gated
  via `prefers-reduced-motion` in the CSS layer or `matchMedia` in the canvas loops; again by construction, NOT
  re-verified with an axe/Lighthouse run.
- **Perf notes**: art-panel loops redraw one dpr-capped canvas per panel; hidden tabs keep scheduling but skip
  painting; ResizeObserver re-bakes are rAF-debounced. Pulse count is capped (every 6th trace, 4-dot tail).

## UI Round 4 — Lusion structure transplant (2026-11-13)

The landing was rebuilt following lusion.co's structural grammar (pinned scroll-driven 3D storytelling, sparse
typography acts, fullscreen menu, preloader, custom cursor, numbered index rows), themed for IoT security:

- **Story stage**: 480vh pinned section; the WebGL ensemble (core/shards/radar/starfield) morphs through four acts —
  assemble (firmware) → explode (unpacking) → hunt (radar) → settle (verdict) — driven by scroll progress shared to
  the render loop via a zustand store (no React re-renders per frame). Acts cross-fade on framer transforms.
- **Preloader**: once per browser session (the site navigates with full page loads); skipped for reduced-motion;
  hard 3.5s escape hatch if `load` stalls.
- **Fullscreen menu**: burger in the nav, staggered oversized links with descriptions, ESC + dedicated CLOSE button,
  body scroll lock while open.
- **Custom cursor**: instant dot + lagging ring that swells over interactive targets; desktop pointers only; native
  cursor hidden behind an `html` class so a JS failure never leaves the site cursorless.
- **Capability index**: the module grid became Lusion "Featured Work"-style numbered rows with tag pills and
  CSS-grid-rows hover descriptions; sections numbered 01–04.
- **Honest limits, same as prior rounds**: no browser available → the interactive behavior (pinned choreography,
  cursor, menu) is code-verified + typecheck-clean + HTTP-verified (SSR fallback copy, burger, styles present; all
  routes 200) but NOT visually verified. No scroll-hijack/smooth-scroll library was added — shipping untested scroll
  manipulation blind is a real risk; native scrolling + scroll-linked morphs stand in deliberately.
- **Reduced-motion**: story stage renders as plain stacked sections without the canvas; preloader and cursor skip;
  menu/index animate with zero-duration variants; CSS loops gated as before.
- Retired from the landing (files remain, tree-shaken): `CinematicHero.tsx`, `HeroScene.tsx` (superseded by
  `StoryScene.tsx`).

### Round-4 hotfix — `useScroll` target-ref crash (2026-11-13)

- **Reported live**: the landing threw "Something glitched. — Target ref is defined but not hydrated" (framer-motion
  `use-scroll` invariant). Root cause: `StoryStage` called `useScroll({ target: ref })` unconditionally, but when the
  OS reports reduced motion (common over RDP / Windows animation settings), the component renders the static stacked
  tree WITHOUT attaching `ref` — framer defers, its passive effect then throws the invariant. Verified against
  `node_modules/framer-motion/dist/es/value/use-scroll.mjs` (`isRefPending` → `invariant(...)`).
- **Fix**: removed `useScroll({ target })` from `StoryStage` entirely. Scroll progress is now measured manually
  (`getBoundingClientRect` on scroll/resize, passive listeners, clamped 0..1) and pushed into one `useMotionValue` +
  the zustand store the WebGL loop reads. The reduced-motion branch is safe by construction (effect early-returns on
  the unattached ref). `ScrollProgress` and `CinematicHero` were checked: the former calls `useScroll()` with no
  target (safe), the latter renders nowhere (tree-shaken).
- **Verification, honestly scoped**: typecheck clean; web + API return 200 with SSR fallback copy present. The crash
  path itself was reproduced from code inspection, not in a browser (none available this session) — so the pinned
  choreography remains code-verified, not visually verified.

## UI Round 5 — deep motion + readability pass (2026-11-13)

Built on the round-4 structure; no new routes, no API changes:

- **Story scene depth (WebGL, `StoryScene.tsx`)**: GLSL value-noise aurora backdrop that drifts continuously and
  flushes alert-red through "the hunt" (uniform lerped from scroll progress); data-stream lines arcing core → every
  shard with traveling additive pulses (same seeded shard layout drives both); two gyroscopic halo rings; key lights
  that drain cyan/violet → red/amber with alert level; subtle camera roll tied to pointer lean + hunt wobble;
  twinkling starfield; core bob + verdict brightness on the outer wireframe.
- **Copy choreography (`motionText.tsx`)**: eyebrows decode terminal-style (scramble → resolve, glyphs 0-1/hex/#);
  titles reveal word-by-word with blur-up (per-word gradient clip — per-word, not clipped against animated children,
  to keep background-clip:text correct); body copy fades as a block. Reveals are keyed to the active act (state
  changes only on act boundaries, not per frame).
- **Readability (`cinematic.css`)**: dark radial scrim behind act copy (text was floating directly over bright WebGL);
  eyebrow became a translucent chip; body copy brightened #94a3b8 → #cbd5e1 at 16.5px/1.72 with text-shadow; titles
  get drop-shadow + `text-wrap: balance`; rail items got chip backgrounds; ghost buttons over the scene get a
  translucent fill; menu descriptions brightened; `::selection` themed.
- **Other dynamics**: magnetic CTAs (pointer-lean, fine pointers only), bottom story progress line (scaleX from the
  scroll MotionValue), spotlight glow riding the pointer across capability rows (CSS vars, delegated listener), huge
  outlined ghost numerals (01–04) floating behind section headers, preloader now cycles boot status lines with a scan
  sweep.
- **Reduced-motion discipline kept**: decode/split-text collapse to plain text; magnetic + spotlight gated or inert;
  ghost/preloader-scan loops gated in CSS; the story still renders as static stacked sections without the canvas.
- **Honest scope, same as every round**: typecheck clean; landing + routes return 200; all motion is code-reviewed but
  NOT visually verified (no browser this session). The GLSL fragment shader in particular has zero runtime verification
  — if the aurora plane renders wrong (or black), that is the first suspect; fallback would be removing `<Aurora />`.

## UI Round 6 — nav chrome + inner-page header pass, GUI/UX audit (2026-11-13)

Code-level GUI/UX audit across the 11 pages (all pages use `PageHeader`, `Reveal`/`Tilt`/`CountUp`, glass cards, and
shared button/input classes — consistency is strong; the gaps were chrome polish and micro-feedback):

- **Nav**: richer glass (gradient + saturate + inner top highlight), pill links with hover lift, active pill glow ring,
  pill-aware underline sweep, brand sigil now breathes (drop-shadow loop) with a text sheen on hover, API status is a
  real bordered chip (color-coded LIVE/DOWN/pending, dot pulse kept), Login became a styled pill button, burger rebuilt
  as a proper 3-bar icon, staggered entrance cascade on load, `aria-current="page"` on the active link.
- **Inner-page headers (`PageHeader`)**: eyebrow decodes terminal-style (round-5 `DecodeText` reused), title reveals
  word-by-word (`SplitWords` gained an `as="h1"` mode; internal per-word delay removed so the container stagger sets the
  cadence), sub rises, and a gradient rule draws itself under the block. Reduced motion: static text + static rule.
- **Micro-feedback**: input focus gets an outer glow; scroll-progress bar thickened to 3px with a glow.
- **Reduced-motion gates added**: brand sigil/text, nav-link/login transitions.
- **Honest scope**: typecheck clean; all 10 routes + landing return 200; nav markup (3-bar burger) confirmed in SSR.
  Still no browser — visual verification remains outstanding for everything above.

## UI Round 7 — console-grade chrome + extreme audit pass (2026-11-13)

The "upper section" push continued; no page bodies changed, no API changes:

- **Nav**: live **UTC clock chip** (ticks every second — SSR shows a placeholder, hydration-safe), **tactical reticle
  brackets** floating around the active link pill (draw-in animation), **pointer spotlight** inside link pills
  (delegated CSS vars), a faint **ambient sheen** drifting across the glass every 9s, and nav entrance now includes
  blur. Press feedback (`:active` scale) on buttons/links.
- **Inner-page headers**: `.sf-eyebrow` unified as a translucent chip everywhere (incl. `ui.tsx` Eyebrow and
  `error.tsx`), and a console-style **`SF://<route>` path tag** pinned top-right of every header (leading slash
  stripped; hidden on mobile; SSR-verified on /dashboard).
- **Landing story stage**: two **HUD corner labels** (top-left system line, bottom-right meta) — aria-hidden, hidden
  on mobile. Note: these are client-only (StoryStage is `ssr:false` by design), so they cannot be confirmed via SSR.
- **Reduced-motion gates**: reticle draw-in, nav sheen, spotlight transition.
- **Honest scope**: typecheck clean; all routes 200; clock/path-tag/eyebrow-chip/reticle-markup confirmed in SSR;
  HUD and all motion remain code-verified only (no browser). The UTC clock is the only genuinely live chrome data —
  everything else remains real-API-driven or explicitly static.

## UI Round 8 — award-site DNA pass, benchmarked against awwwards.com/websites/3d (2026-11-13)

Benchmarked the project against Awwwards' showcase language (their chrome + the shared DNA of the 3D sites they
feature). What the project already had: preloader counter, custom cursor, marquees, numbered sections, monospace HUD
labels, magnetic buttons, decode/split text, pinned 3D story. What was missing — and shipped this round:

- **Film grain veil**: fixed fractal-noise SVG overlay (`feTurbulence`, data-URI, zero payload) over everything
  including the preloader; transform-only 6-step loop on the compositor thread when motion is allowed, static texture
  for reduced motion.
- **Mega footer**: the two-line utility strip became an award-site footer — giant outlined SENTINELFORGE wordmark
  (viewport-scaled, stroke-glow on hover), numbered quick links (01–09), gradient hairline, colophon base line.
- **Custom scrollbar**: thin dark track, cyan→violet gradient thumb (WebKit + Firefox `scrollbar-color`).
- **Page-enter choreography**: `.sf-page` (all 11 inner pages) and the landing wrapper land with a soft rise on every
  full page load; gated under reduced motion.
- **Display-type scale**: act titles 72px→96px cap (7vw), inner-page H1s 52px→62px cap — toward awwwards display
  scale, still balanced by the readability scrim.
- **Honest scope**: typecheck clean; all routes 200; grain/footer markup confirmed in SSR. Self-scored against the
  Awwwards jury axes (Design 40/Usability 30/Creativity 20/Content 10): ~8.0 → ~8.5 weighted — an estimate, not a
  jury score, and still not visually verified (no browser).

## UI Round 9 — depth + ambient-dynamics pass (2026-11-13)

"More 3D, more dynamic" round; no page bodies, no API changes:

- **WebGL (StoryScene)**: `Tracers` — three alternating orbital particle rings
  (252 seeded points, additive, twinkling, spool up during the hunt) threading
  the space between the shards and the starfield; `Shockwave` — flat energy
  rings that fire once when the story crosses the explode entry (~0.24–0.30,
  violet) and the verdict consensus (~0.78–0.84, cyan), re-arming on scroll-back.
  Both are plain three.js (no new GLSL), client-only inside the `ssr:false`
  stage, so they cannot be SSR-verified — same honest caveat as the aurora.
- **Site-wide card spotlight**: new `PointerGlow.tsx` — one delegated
  `pointermove` listener writes `--gx/--gy` CSS vars on the nearest `.sf-glass`,
  giving every glass panel on every page a cursor-tracked inner radial
  highlight (no per-card listeners, no re-renders). Print stylesheet already
  neutralizes `.sf-glass::before`.
- **Ambient nebula**: fixed two-field radial wash (`sf-nebula`, z-index 0)
  drifting on 26s/31s transform-only loops behind all content; motion gated,
  static wash under reduced motion; SSR-confirmed on / and /dashboard.
- **Details**: threat ticker gained fixed edge-fade masks (`.sf-ticker` class
  wired onto the wrapper — the print block already referenced it); inner-page
  header rules now carry a traveling light pulse (`sf-rule-sweep`, gated);
  footer gained a static three-gradient aurora wash at its base (no animation
  risk, paints behind content as background layers).
- **Perf guardrails**: nebula uses no blur filter (radial gradients only);
  all new loops are transform/opacity-only; tracers/shockwaves add ~0.3k
  vertices and one material each. Cumulative GPU load on the landing page is
  now the honest weak point (2 canvases + grain + nebula + RDP) — the dpr cap
  ([1,2]) and reduced-motion static branch remain the fallbacks.
- **Honest scope**: typecheck clean; all 10 routes + landing return 200;
  nebula/ticker/grain markup confirmed in SSR; Tracers/Shockwave and all
  motion remain code-verified only (no browser).

## UI Round 10 — fluid-motion pass (2026-11-13)

"More 3D, fluid + smooth" round; no page bodies, no API changes:

- **WebGL**: `Dust` — 170 ambient motes (seeded, additive, CPU-drifted with
  orbital + vertical sway) filling the space between the ensemble and the
  starfield; the hunt adds angular energy and opacity. Shards now **self-glow
  in sync with their data-stream pulses** (`emissiveIntensity` flare) — the
  lattice breathes with the energy flowing through it. No new GLSL.
- **Cursor**: third trailing layer (`sf-cur-halo`, 72px soft radial at 0.055
  lerp) behind the ring (0.16) — three stacked latencies read as fluid
  inertia; swells less than the ring on interactive targets. JS-only layer,
  still fully skipped for reduced motion / coarse pointers.
- **Nebula scroll parallax**: PointerGlow now also rAF-throttles a `--ns` var
  from `scrollY × 0.045` onto the fixed wash container; a 1.1s expo-out CSS
  transition turns raw scroll into a fluid chase (the container moves, the
  three field animations are untouched — no transform conflicts). Third
  nebula field (`sky-blue front`, 37s loop) added via a real `<i>` child.
- **Global fluidity**: unified `cubic-bezier(0.22, 1, 0.36, 1)` (expo-out)
  timing across every interactive chrome transition (nav links, buttons,
  cards, capability rows, footer links, menu) — hover states now decelerate
  like a spring settle instead of snapping. Deliberately NOT adding
  `scroll-behavior: smooth`: Next's route-change `scrollTo(0,0)` would become
  an animated scroll-back after every navigation — a real regression.
- **Reduced-motion gates**: nebula transform/transition and third-field loop;
  halo/parallax writers self-disable via matchMedia.
- **Honest scope**: typecheck clean; all 10 routes + landing return 200;
  nebula `<i>` child confirmed in SSR. Dust/shard-glow/halo/parallax are
  client-only or JS-driven — code-verified only (no browser). Landing GPU
  stack now: story canvas + grain + 3-field nebula + parallax listener —
  still all transform/opacity work; the reduced-motion static branch and dpr
  cap [1,2] remain the fallbacks if a low-end machine struggles.

## UI Round 11 — field reel + device-imagery round (2026-11-13)

The user explicitly asked for "4K IoT device images in video animations". Image
generation was attempted (user request lifts the earlier no-retry rule):

- **Quota still exhausted**: three generation jobs (gemini-nano-banana-2.1,
  free tier) all failed — daily request limit 0, "retry in ~9h40m". No images
  exist; no files were written. Honest fallback shipped instead, consistent
  with the project's procedural-imagery discipline.
- **`device` ArtPanel variant**: a fully procedural IoT hub render — rounded
  machined body with edge highlight, engraved spec lines (seeded), status-LED
  wells, port cluster, recessed LED ring, antenna with glowing tip, floor
  reflection and contact shadow. Animated: LED-ring sweep arc, inner ring
  pulse, blinking status LEDs, Ken Burns drift. Baked at native device
  resolution (dpr-capped 2) — crisp on a 4K display by construction.
- **`DeviceReel`** (landing section 03 · FIELD REEL, pipeline strip renumbered
  to 04): a looping video-wall reel — slides crossfade every 7s with slow Ken
  Burns, hover holds the loop, the progress rail fills in sync and pauses on
  hover, a scanline sweeps the glass, and the whole stage rides the existing
  `Tilt` (pointer 3D) with **true depth layers** (HUD, corner brackets, rail
  at translateZ 24–46px above the clipped glass; `transform-style:
  preserve-3d` on the stage, clipping isolated to the inner `.sf-reel` so the
  3D is not flattened). Only the current slide + two neighbors are mounted —
  at most two procedural canvases animate at once.
- **Automatic photo pickup**: on mount the reel HEAD-probes
  `/devices/reel-1|2|3.(jpg|png|webp)`; any that exist lead the reel with
  hardware-intake captions and zero code changes. Dropping real 4K renders
  into `apps/web/public/devices/` upgrades the reel with no further work —
  the probe logic is code-verified only (no files exist today).
- **Reduced-motion**: no loop, no scan sweep, no rail fill animation, no
  slide/img transitions; static first slide remains. Reel also excluded from
  print/PDF exports.
- **Honest scope**: typecheck clean; all 10 routes + landing return 200; reel
  markup (stage/slides/segments/eyebrow) confirmed in SSR. All animation and
  the 3D depth layering remain code-verified only (no browser); the photo
  probe path is untested against real files (none exist).

## UI Round 12 — browser verification pass begins; streaming-boundary hardening (2026-11-13)

A real browser became available mid-session. First findings:

- **Dev servers had died in the session restart** — both relaunched detached
  (API :4000 and web :3005 back to 200). API state is in-memory again → all
  accounts wiped; re-signup required for authenticated flows.
- **Image quota still exhausted** (daily limit 0, "retry in ~17.5h") — the
  reel-1 plate attempt failed like the others; no further retries today.
  Photography pickup remains automatic once `public/devices/` has files.
- **Embedded-browser rendering anomaly, diagnosed and NOT a site bug**: in
  the OpenCode embedded browser (window occluded), every page stuck on its
  loading fallback with the real content trapped in a hidden streamed
  segment. Root cause verified by probe: `requestAnimationFrame` never fires
  in an occluded window, and React's streamed-segment reveal machinery is
  rAF-driven — so reveals can never complete there. The user's own visible
  Chrome renders everything normally; the site console is clean (only the
  expected 401 on `/v1/auth/refresh` with no session).
- **HeroClient hardened** (kept, regardless): `next/dynamic` `ssr: false` for
  the story stage replaced with a plain client-side mount guard. Same first
  paint (the designed act-01 fallback), same post-hydration mount, but no
  streaming Suspense boundary / CSR-bailout error segment left in the page —
  this removes the entire class of round-4-style fragility discovered while
  diagnosing. Typecheck clean; routes re-verified 200.
- **Embedded-browser rendering anomaly — root cause now proven at byte level
  (refines and supersedes the earlier theories):** the served HTML (dev and
  prod alike) contains React 19.2's throttled-reveal bootstrap. When a
  Suspense boundary completes **before the first rAF has fired**, the reveal
  is scheduled via `requestAnimationFrame($RV)` (visible in the served bytes:
  `"number"!==typeof $RT?requestAnimationFrame($RV.bind(null,$RB)):…setTimeout(…)`).
  In the embedded browser the window's document is treated as hidden while
  occluded → rAF never fires → the queued pair in `$RB` is never drained →
  every route stays on its loading fallback indefinitely. When `$RT` is
  already a number (rAF won the race), the reveal falls back to `setTimeout`
  — which is exactly why some loads self-revealed and others never did.
  Not a site bug: the user's Chrome reveals within one frame. Console stayed
  clean throughout (only the expected logged-out 401 on `/v1/auth/refresh`).
- **Embedded-browser workaround that fully unblocks verification (no site
  code involved):** serve the **production build** (`next start -p 3006`,
  static prerender, streams resolve immediately) and, after load, invoke
  React's own `window.$RV(window.$RB)` manually — the exact call rAF would
  have made, so state stays React-consistent (this replaced the earlier DOM
  grafting shim). A following **client-side navigation** re-renders routes
  purely client-side, which lets the `HeroClient` mount guard mount the WebGL
  story stage.
- **Verification battery — now complete including the WebGL story stage:**
  - Landing story verified live: 480vh pinned section (3139 px), sticky 100vh
    viewport, **all four acts rendering** ("Every device hides a story." /
    "Unpack it. Map it. Taint it." / "Then the machines hunt." / "Confirmed.
    Or nothing."), full-viewport WebGL canvas (790×654), story HUD
    ("SF://FORGE · PREDICTIVE IOT DEFENSE").
  - 7 live canvases total on the landing (story ensemble + 6 procedural
    panels); FIELD REEL live (368 px stage, 3 slides, segments, scanline,
    HUD "SF://FEED · HARDWARE REEL 01 / 03").
  - All 10 routes render real designed content; client-side navigation works
    (dashboard round-trip verified); login 2 inputs / signup 4 inputs; no
    horizontal overflow at 800 px; nav wraps by design below 860 px.
  - Console across all routes: only the expected logged-out 401s. Zero
    hydration or runtime errors.
  - Only remaining gap: **screenshots** — the capture API requires the
    OpenCode window frontmost (it was occluded throughout; rAF alive but
    window-composited capture refused). Pixel-level review still pending.
- **Commit readiness verified**: `npm --prefix apps/web run build` passes
  (Next 16.4.2 / Turbopack, 13 routes prerendered static, single React tree
  confirmed — react 19.2.3) and the full test suite passes **118/118 across
  10 files**. The changeset (89 files, rounds 1–12) is ready to commit as soon
  as a fresh PAT is available.
- **Real bug found and fixed in `packages/db/schema.sql`**: the `auth_audit`
  table declared `id BIGGENERATED ALWAYS AS IDENTITY` — invalid SQL (missing
  `INT`; would have failed the very first provisioning attempt). Never caught
  before because the schema has never been run against a live database.
  Migrations 002–004 re-verified line-by-line: valid. A step-by-step Supabase
  provisioning guide now exists at `packages/db/README.md`, including the
  honest caveat that the SQL is hand-verified but not yet executed live.

## UI Round 12a — user-reported console errors: extension-induced hydration noise (2026-11-13)

The user pasted two React 19 hydration errors from their own Chrome:

- **Error 1 — extension attribute injection (confirmed, not a site bug):** the
  diff contained `bis_skin_checked` on every element level plus
  `data-darkreader-mode/scheme/proxy-injected` and a base64 `bis_register` —
  fingerprints of **Bitdefender** and **Dark Reader** rewriting the DOM before
  React hydrates. React's own error text names this case ("a browser
  extension … messes with the HTML before React loaded").
- **Error 2 — style diff downstream of error 1:** reported against the
  `Card` glass element (`app/components/ui.tsx`) via `AmbientScene` frames.
  Decisive tell: the "server rendered HTML" side contained `--gx: "543px"` /
  `--gy: "193.4…"px` — pointer-spotlight coordinates that only our runtime
  ever writes (`PointerGlow` pointermove effects; impossible in server HTML),
  i.e. values from a **previous visit restored by the extension's DOM
  snapshot**, plus framer-motion's longhand style serialization. Casualty
  noise of the extension-induced re-render, not an SSR bug. `AmbientScene`
  itself was re-audited: fully deterministic (seeded mulberry32, static
  gradients) — SSR-safe.
- **Mitigation shipped:** `suppressHydrationWarning` on `<html>` and `<body>`
  in `app/layout.tsx` — the canonical remedy for extension-injected
  attributes at the top level, scoped so real content mismatches deeper in
  the tree still surface. Typecheck clean.
- **User-side guidance:** the remaining deep-element warnings (and the
  one-time client re-render React 19 performs on mismatch) disappear when the
  site is viewed without those extensions active for localhost (e.g. clean
  profile/incognito). Nothing further can be done site-side about third-party
  DOM rewriting.

## UI Round 13 — fluid chrome: route curtain + command palette + reel expansion (2026-11-13)

"Move forward for more advancements and achieve superior quality" round:

- **Route curtain (`RouteCurtain.tsx`)** — Lusion-style page transitions:
  internal `<a>` clicks are intercepted at document level (capture; modifier
  keys/new tabs/external/same-path all respected), a two-tone skewed wipe
  covers the viewport (360 ms, expo-out), the route swaps underneath, then the
  wipe continues out (560 ms). Programmatic trips go through a `sf:transit`
  CustomEvent (the palette uses it). Safety net: a 1.6 s failsafe guarantees
  the user is never trapped behind a stalled push. Reduced motion: the
  curtain never mounts and clicks pass through untouched.
- **Command palette (`Palette.tsx`)** — Ctrl/Cmd+K (plus a ⌘K chip in the
  nav): one modal to reach all 11 surfaces with ranked fuzzy matching,
  ArrowUp/Down/Enter/Escape keyboard flow, scroll lock, focus
  save/restore, ARIA dialog+listbox semantics, and HUD-style footer hints.
  Reduced-motion safe via CSS gates.
- **Reel expanded to 5 slides** (device → holo → circuit → **gridwave** →
  **fluid** live aurora); only current + neighbors stay mounted (3 canvases
  max of 5), rail shows all 5 segments; device slide now also gets the slow
  Ken Burns drift.
- **Performance profiled for real** (Chrome CPU profiler, prod build, scripted
  full scroll of the 480vh story): main thread **~90 % idle** (7.4 s idle of
  ~8.2 s; program 57 ms; GC 27 ms; zero hot functions). The motion stack
  stays off the main thread — no optimization needed; recorded as baseline.
- **Browser-verified end-to-end (prod build on :3006)**: Ctrl+K opens (11
  rows, scroll locked, input focused) → ArrowDown selects → Enter closes
  palette + curtain covers → dashboard rendered, curtain gone, scroll
  unlocked. Plain nav-link click → curtain mid-transit → devices rendered.
  Programmatic transit round-trip → full 7735 px landing. Reel shows 3
  mounted slides / 5 rail segments. All 11 routes 200 on dev (:3005).
- **Honest scope**: reduced-motion curtain/palette paths are code-gated only
  (no reduced-motion browser session available); compositor/raster cost (e.g.
  the grain repaint) is not captured by the JS CPU profiler and remains
  unprofiled; curtain + page-enter compose but the combined look is verified
  structurally, not pixel-level (screenshots still blocked by occlusion).

## Engine Accuracy Round 14 — one priority definition, honest consensus, sharper rules (2026-11-13)

"Superior quality **and accuracy** of the features" round — aimed at the analysis
engine, not the chrome. Every fix below is covered by a test or a live,
hand-verified probe.

- **The drift bug — three priority definitions.** The triage priority
  (confidence tier + EPSS + SSVC) existed in three places that had silently
  diverged: workers `priorityOf` (the engine), web `scoring.ts` (the UI), and
  the API `quality.ts` calibration endpoint — the last two without the SSVC
  term at all. Consequence: the calibration endpoint's `averagePriority`
  disagreed with both the pipeline and the dashboard. Now `quality.ts`
  **imports and calls the engine's `priorityOf` directly** (zero inline math),
  the API returns each finding with an engine-computed `priority` field
  (`withPriority` in `findings.ts`), and the UI consumes that number first,
  falling back to its mirrored constants only for rows without one. One
  definition, computed once at the engine, consumed everywhere.
- **Consensus fix — sanitized taint can no longer manufacture "Confirmed".**
  A taint path that *passes a sanitizer* is provably not exploitable as-is;
  previously it was still added as a `taint` engine and could corroborate a
  static sink hit into `Confirmed` — the classic "confirmed but actually
  mitigated" false positive. Sanitized paths now attach an explainability
  note (`PASSES SANITIZER — not corroborating`) on the existing finding
  without contributing an engine; sinks are processed first so the note has a
  finding to land on. Unsanitized taint still corroborates normally.
- **Demo seed told the queue a confidence the engine would never derive.**
  Two demo findings were stored as `Likely` with a single engine
  (`['secrets']`, `['root-of-trust']`) — violating the platform's own
  documented policy ("unconfirmed: single engine — needs triage"). Fixed:
  the secrets row is now honestly corroborated (`['secrets','static']`, two
  same-family tools → `Likely` with a why-line saying exactly that), the
  UART row is `Unconfirmed`. Found because a hand-computed prediction of
  `averagePriority` did not match the live endpoint; the mismatch decomposed
  exactly into this data bug.
- **Secret rules tightened and extended.** `api-token` and `aws-secret-like`
  are now entropy-gated (charset-valid but zero-entropy values like 16 a's no
  longer report), and three self-validating near-zero-false-positive formats
  were added: `jwt-hardcoded` (3-segment eyJ…), `slack-token` (`xox[baprs]-`),
  `google-api-key` (`AIza…` + 35).
- **Tests:** 5 new accuracy cases in `stages.test.ts` (entropy gate on
  `aws_secret`; jwt/slack/google detection; sanitized-taint-never-corroborates;
  unsanitized-still-corroborates; sanitized-only-flow-produces-no-finding).
  Workers 46/46; full repo battery **123/123**; typechecks clean (workers,
  api, web).
- **Live, hand-verified against the running API** (fresh probe account,
  bcrypt + TOTP enroll via real speakeasy, seeded queue):
  `GET /v1/quality` → `total 6, averagePriority 48` — matching the
  hand-computed (100+88+50+10+10+30)/6 **exactly**, including the SSVC
  differential probe row (Unconfirmed + EPSS 0.4 + Attend = 30; the old
  no-SSVC inline math would have scored it 20). `corroborationRate 0.333`,
  confidence distribution Confirmed 2 / Likely 1 / Unconfirmed 3.
- **Browser end-to-end on dev (:3005):** signed in through the page's own
  fetch path (WebCrypto TOTP computed in-page), transited via the round-13
  curtain, and the dashboard rendered the engine's numbers in exact order:
  **P100 · P88 · P50 · P30 · P10 · P10** — the probe row at P30, proving the
  engine-computed priority flows from API to pixel. Production build rebuilt
  and redeployed on :3006.
- **Honest scope:** the verification queue uses seeded/demo findings — no
  real firmware image was re-run through the live pipeline this round, so the
  fixes are proven at the unit, API, and UI levels but not on a fresh
  binary's end-to-end output. The web fallback constants remain a mirror
  (bundling boundary), used only when an API row lacks the engine field.
  Auth probe accounts remain in-memory (relaunch wipes them; Supabase
  provisioning still awaits the user).

## Engine Throughput Round 15 — worker-thread pool, concurrent pipeline, live GUI→engine loop (2026-11-14)

- **Worker-thread pool (`apps/workers/src/pool.ts` + `pool/jobs.ts` +
  `pool/worker.ts`):** CPU-heavy engine stages (fuzz, protocol-fuzz, static)
  dispatch to a bounded pool — `MAX_WORKERS = max(1, min(parallelism-1, 4))`,
  round-robin dispatch under a hard-cap limiter. Every design decision is
  pinned: **singleton full-width init** — the spawn decision is one shared
  promise and the pool comes up at full width (per-worker capacity is fixed;
  an earlier lazy version measured 0.95× because a single worker served
  everything — bug found by the bench and fixed); **file-existence gate** —
  spawn requires `dist/pool/worker.js` to exist, so source/test contexts
  fall back inline permanently instead of a doomed worker's
  MODULE_NOT_FOUND escaping as an uncaught exception; **`unref()`** — idle
  workers never pin the host process; **job vs infrastructure failure** — a
  bad job re-runs inline and the pool keeps its threads, broken
  infrastructure (timeout/exit/load) degrades the pool permanently to
  inline; **observability** — `setPoolMode('inline'|'auto')` and
  `getPoolInfo()` (mode, workers, dispatched, threaded/inline counts,
  degradations). All exported from the package entry.
- **Concurrent pipeline (`pipeline.ts`):** tier 1 runs static ∥ SBOM ∥
  root-of-trust ∥ patch-report concurrently; discovery runs taint first
  (its sinks seed fuzz), then fuzz ∥ protocol-fuzz concurrently before
  correlate; the unpack plan is computed once and reused for the SBOM
  (duplicate `planUnpack` eliminated). Every run records **real engine
  metrics** (`RunMetrics`: wallMs, µs-resolution per-stage ms,
  jobsDispatched, fuzzExecsPerSec, protocolExecs, the poolMode actually
  used, findingsCount) and a new `pipeline.metrics` bus event publishes
  them.
- **Benchmark (compiled dist only — threads mode needs the built worker
  entry), honest post-fix numbers, 30k fuzz + 4k protocol + 98 KB static
  scan per campaign, 4 hardware workers:**

  | concurrent campaigns | inline | threads | speedup |
  |---|---|---|---|
  | 4  | 538k fuzz execs/s (222 ms)  | 597k (201 ms)   | 1.11× |
  | 8  | 533k fuzz execs/s (450 ms)  | 742k (323 ms)   | 1.39× |
  | 16 | 600k fuzz execs/s (800 ms)  | 1.109M (433 ms) | 1.85× |

  Pre-fix numbers (over-spawn bug: workers=16/4) were discarded, not
  averaged in. The bench output's `degradations:["manual
  setPoolMode(inline)"]` is the A/B forcing itself, not a failure. Run with
  `node apps/workers/dist/bench.js` (`BENCH_N` scales campaigns).
- **API executes queued runs:** `POST /v1/pipeline/runs` with
  `profile:'demo'` now actually runs the pooled engine (20k fuzz + 4k
  BLE-GATT protocol + a labeled synthetic ELF/static image) fire-and-forget
  — the run doc transitions queued → running → done/failed carrying
  `stageStatus`/`metrics`/`findingsCount`, with an in-flight guard against
  double executes. New `GET /v1/pipeline/metrics` returns the per-org
  throughput ledger (last 20 runs; in-memory until Supabase — honest).
  API tests 22/22 including a poll-to-done assertion chain.
- **GUI — ENGINE THROUGHPUT panel (`dashboard/Throughput.tsx`):** live pool
  chip (color-coded threads/inline), a **RUN ENGINE** control
  (attestation-gated via the persisted `sf_att` id; states exactly what is
  missing instead of failing silently), live run polling with a status
  line, RUNS / AVG WALL / BEST FUZZ RATE stats, and recent-runs ledger
  rows; reduced-motion safe.
- **Live, hand-verified end-to-end (dev :3005):** fresh session
  (`r15ui82221`), device + attestation registered through the real API,
  demo findings seeded, dashboard reloaded — panel showed
  `POOL: THREADS` (the API imports the **built** workers package, so
  threads mode is real even under tsx dev), pressed RUN ENGINE →
  **"run 85e7bdf2 done — wall 282ms"**, panel updated to RUNS 1 /
  AVG WALL 282ms / BEST 259.3k/s with ledger row
  `85e7bdf2 · 282ms · 259.3k/s · 4 findings · threads`. Production build
  rebuilt and redeployed on :3006 (the prerendered /dashboard carries the
  panel markup — fresh-build marker).
- **Tests:** workers 52/52 (limiter cap + FIFO order; offload fuzz/
  protocol/static; pipeline metrics reality-checked; resume-from-sbom),
  api 22/22, full repo battery **129/129** across 11 files; typechecks
  clean (workers, api, web).
- **Honest scope:** vitest runs the inline fallback by construction (the
  worker entry isn't compiled in src) — threads mode is exercised by the
  dist bench and the live API, and `getPoolInfo()` proves which ran.
  Demo-profile executions are labeled synthetic images, not real customer
  firmware (real acquisition is Module 1 wiring). The throughput ledger is
  in-memory (an API relaunch wipes it) until Supabase provisioning. The AI
  image quota remained exhausted (limit 0, ~20h cooldown) — the device
  reel still renders procedural variants; the photo drop-in convention
  (`reel-1/2/3.(jpg|png|webp)` in `apps/web/public/devices/`) is unchanged
  and auto-detecting.

## UI Round 15a — user-reported hydration mismatch: glass glow mutated pre-hydration DOM (2026-11-14)

- **Report:** console hydration error — the diff showed `--gx`/`--gy` inline
  styles present in the server HTML but absent from the client vdom (the
  shorthand/longhand lines around them were re-serialization noise of
  *identical* values; the pointer vars were the only real delta).
- **Root cause:** the round-9 `PointerGlow` ran a **document-level delegated
  `pointermove` listener** that wrote the glare vars into every `.sf-glass`
  under the pointer. It attached as soon as the layout hydrated, so it could
  mutate `.sf-glass` elements belonging to **not-yet-hydrated** components
  (streamed boundaries, late chunks) — React then compared its server HTML
  snapshot against the already-mutated DOM and logged "a tree hydrated but
  some attributes of the server rendered HTML didn't match … This won't be
  patched up."
- **Fix (structural, not a suppress):** the glow now rides **React's own
  delegated events** — a shared `glassGlow` handler exported from
  `components/ui.tsx`, attached as `onPointerMove` on every glass element
  (20 sites across 13 files; `Card`/`Stat` carry it centrally). React
  synthetic handlers dispatch only through hydrated fibers, so
  pre-hydration mutation is structurally impossible. Perf profile is
  unchanged: one native `pointermove` listener in total (React root
  delegation), zero per-card listeners, no re-renders. Elements without a
  handler keep a centered glow via the CSS var fallbacks
  (`var(--gx, 50%)` in `cinematic.css`). The old delegated listener was
  removed from `PointerGlow.tsx`.
- **Unchanged on purpose:** the nebula scroll-parallax (`--ns`) stays in
  `PointerGlow` — `.sf-nebula` is part of the root layout's initial
  hydration commit, so it is React-claimed before any effect can touch it
  (different hazard class than elements inside late-hydrating boundaries).
- **Verified live:** fresh dashboard load → **zero console errors**; a
  synthetic `pointermove` dispatched through React's delegation updated
  `--gx/--gy` to the exact pointer-relative coordinates on both dev (:3005,
  `40px/12px`) and prod (:3006, `25px/8px`). Production build rebuilt and
  redeployed. The only remaining console entries on :3006 are the
  DeviceReel's expected photo-probe 404s (`reel-1/2/3.(jpg|png|webp)` not
  generated yet — image quota still blocked), which are network noise from
  the documented auto-detection, not hydration errors.

## Sensory Round 16 — synthesized robotic audio, energy shell + lightning arcs, zero-noise reel (2026-11-14)

- **SF://AUDIO — the site's robotic soundscape (`app/audio/sfx.ts` +
  `app/audio/SoundToggle.tsx`), 100% synthesized, zero audio assets:**
  every sound is generated live with the Web Audio API — hover blips (filtered
  rising square sweeps), click confirm chirps, a route-transit noise whoosh
  (bandpass-swept noise bound to the existing `sf:transit` curtain event), a
  sonar ping with feedback echo, a two-detuned-saw + sub machine-room drone
  with a slow filter-breathing LFO, a four-note boot fanfare with a warm pad
  swell, and a "robotic narrator" line ("Sentinel Forge systems online…")
  spoken by the browser's own speech engine at pitch 0.3. Design decisions:
  **opt-in only** (the toggle click is the user gesture that arms the
  AudioContext; default OFF), preference persists (`sf_audio`) and a returning
  user's first pointer-down anywhere re-arms quietly (no stealth boot
  fanfare); the engine owns its delegated listeners and mutates **no
  React-managed DOM** (round-15a hydration rule); background tabs stay
  silent; master gain 0.6 through a compressor with per-sound gains
  0.02–0.12 — console, not arcade. The nav chip shows four CSS EQ bars when
  live (reduced-motion gated) and an ARMED state for a persisted-but-not-yet
  -gestured session. Feature moment: an engine run completing in the
  dashboard's RUN ENGINE panel fires a louder sonar ping.
- **WebGL round-16 additions (`StoryScene.tsx`):** a **fresnel energy shell**
  (custom GLSL — view-angle rim glow, cyan↔violet drift, alert-red shift
  during the hunt, verdict boost) wrapping the device core inside its group
  transform; and **lightning arcs** — a pooled `lineSegments` system (6
  slots × 7 jagged midpoint-displaced segments) that regenerates one bolt at
  a time between random shell points, crackles faster as the story heats
  up, and cools via frame-rate-independent per-vertex color decay. Both
  ride the existing scroll-store choreography (no React re-renders in the
  loop).
- **Chrome polish:** a holographic **scanline** now sweeps the pinned story
  viewport every ~9s (`sf-scan`, gradient + screen blend), and act titles
  get an **RGB-split glitch** on hover — both strictly
  `prefers-reduced-motion: no-preference` gated like every ambient effect
  in the kit.
- **Round-16a — the reel's 404 noise is gone (`app/api/reel-photos/route.ts`
  + `DeviceReel.tsx`):** the device reel no longer HEAD-probes
  `reel-1/2/3.(jpg|png|webp)` (six expected-but-noisy 404 console lines per
  page load). One clean request to a new route handler lists the plates that
  actually exist in `public/devices`; GET handlers are dynamic by default in
  this Next version, so the drop-in convention is unchanged (plates dropped
  in after a build are picked up on the next visit). A first cut of the
  fallback logic treated a *legitimate empty* list as "handler missing" and
  probed anyway — fixed to fall back only on actual request failure, and the
  fix was verified at the HTTP level (200 `{"photos":[]}`; no `/devices/`
  requests on a clean load).
- **Verified live (browser, while the render pipeline was unobstructed):**
  dev :3005 — chip OFF → click → `SF://AUDIO ON`, `aria-pressed=true`,
  `sf_audio=1` persisted, 4 EQ bars, **narrator actively speaking**
  (`speechSynthesis.speaking=true`); audio state survived a real
  nav-link click → curtain transit → /dashboard (whoosh path attached, no
  errors). Prod :3006 — same audio flow, then the story stage verified fully
  mounted: 4 acts, scanline with computed `sf-scan` animation, HUD chrome,
  progress line, rail, and the 790×654 story canvas rendering. Zero
  hydration errors on every load tested (dev and prod); the only console
  entries were the expected signed-out 401 session probe and (pre-fix) the
  reel probes. Typecheck + `next build` clean; full battery 129/129.
- **Honest scope:** late in the round the embedded browser window became
  fully occluded — with no paint, React passive effects (including the
  stage's mount flag and the reel's discovery fetch) starve indefinitely in
  the background window, so the *client-side* half of the reel-photos fix
  could not be re-observed live after the fix (it is verified at the HTTP
  level and by code path; the same build had mounted fully in both dev and
  prod earlier in the round, and the fallback can only fire on a failed
  request, which the healthy handler never produces). The narrator uses the
  OS/browser speech engine — voice character varies by platform, which is
  honest to note rather than hide. AI image quota remained untouched this
  round (no image generation requested); the reel still auto-adopts
  `reel-1/2/3.(jpg|png|webp)` the moment files land in
  `apps/web/public/devices/`.

## UI Round 17 — tactility & inertia: drag-to-orbit, contextual cursor, velocity marquee, weight scrub (2026-11-14)

- **Drag-to-orbit with inertia (`StoryScene.tsx` + `storyStore.ts`):** the
  pinned WebGL story ensemble is now grabbable — pointer-down on the canvas
  captures the pointer and drags the whole ensemble's yaw/pitch (clamped),
  release keeps the last drag velocity as momentum (frame-rate-independent
  exponential decay), then a gentle spring returns the ensemble to rest. Fine
  pointers only (touch keeps native scrolling); `prefers-reduced-motion`
  exempt (the reduced-motion audience never gets a canvas at all in the story
  stage). State lives in a module-level orbit object stepped by `useFrame` —
  the render loop never goes through React — plus a `dragging` flag in the
  zustand story store for the cursor. Servo pickup / release ticks fire via
  the synthesized-audio engine (`sfxBlip`, exported from `sfx.ts`) and are
  silent unless the user opted into SF://AUDIO. The story acts remain
  `pointer-events: none` (only their CTAs are interactive), so drags work
  across the whole stage; the camera's existing pointer parallax is
  untouched — ensemble rotation and camera parallax compose.
- **Contextual cursor state machine (`Cursor.tsx`):** elements can now declare
  a cursor intent with a `data-cursor` attribute — the WebGL stage declares
  `drag`, the device reel `view` — and the cursor grows and shows a small
  mono tip naming the affordance (DRAG / VIEW), flipping to ORBIT while the
  ensemble is actually grabbed (read live from the story store inside the
  rAF loop, no per-frame React renders). Label changes are rare React state
  transitions (only on hover-region changes), the tip is positioned by the
  existing rAF loop via transform only, and everything stays inside the
  round-15a discipline: no document-level DOM mutation, native cursor still
  hidden via the `<html>` class, still skipped for coarse pointers and
  reduced motion.
- **Velocity-reactive capability drift (`MarqueeBand.tsx`, new):** a
  full-bleed band of glass capability plates under the threat ticker whose
  speed and skew lean into scroll velocity (window-level `useScroll` →
  `useVelocity` → spring; the drift itself is one motion value stepped in
  `useAnimationFrame` with a modulo wrap over a duplicated half — surge-proof
  and seamless). Idle crawl 46 px/s, hard flick surges to ~830 px/s with a
  skew shear up to ±8°, hover pauses the drift, edge mask fades both sides.
  Reduced motion renders a static plate row. The glass plates participate in
  the round-15a spotlight pattern (`glassGlow` on each plate).
- **Weight-scrub finale (`ProveSection.tsx`, new — replaces the static
  closing `<h2>` in `page.tsx`):** as "Is your fleet ready to be proven?"
  crosses the viewport, a wave of font weight (220 → 900) sweeps across the
  seven words — the question literally gathers conviction as you arrive.
  Progress is measured manually (the StoryStage pattern: one
  rAF-throttled rect read per scroll event, no `useScroll({ target })` so
  hydration stays deterministic), weights are written straight into spans
  (no React re-renders), and reduced motion keeps the original static bold.
- **Verified live (prod `:3006`, browser):** new build prerenders the
  marquee (16 plates, 2×8) and all seven prove-words; drag-orbit state
  machine exercised end-to-end via dispatched pointer events — grab on the
  canvas flips the cursor tip to ORBIT (story store → cursor wiring),
  release returns the tip to pointer context; cursor VIEW label appears
  over the reel; the marquee drift is confirmed running with a seamless
  wrap (x advancing continuously); the weight scrub sweeps as designed —
  all words 220 at page top, staggered wave mid-scroll
  ([900, 900, 900, 900, 655, 220, 220]), all 900 when the section is fully
  crossed. Typecheck + `next build` clean; full battery 129/129 across 11
  files; zero hydration errors; the only console entry is the expected
  signed-out 401 session probe.
- **Honest scope:** the embedded browser window was fully occluded for most
  of this round (no paint → rAF throttled to ~1 Hz), so *velocity-reactive*
  behavior of the marquee (surge/skew magnitude under a flick) and the
  visual rotation of the dragged ensemble could not be observed live at
  fidelity — both verified at the state/wiring level (dragging flag, orbit
  handlers, drift advancing, wrap math) plus build/tests, and the same
  mechanics run their normal speed in a visible window (the delta clamp
  that keeps refocus jump-free also slows motion to 1/20 speed at 1 Hz
  rAF — visible-window behavior is unaffected). AI image quota untouched
  (none requested); reel still auto-adopts plates from
  `apps/web/public/devices/`.

## UI Round 18 — choreography round: masked reveals, act cuts, direction-aware curtain, press pulse, wordmark drift (2026-11-15)

- **MaskWords (`motionKit.tsx` + CSS):** the Lusion-signature reveal — every
  showcase section heading ("Bold firmware, brought to light.", "The machine,
  rendered.", "Hardware on the wall, in motion.", "From image to ranked
  chains.") now rises word-by-word out of overflow-hidden masks with a slight
  3° rotation and a left-to-right stagger on scroll-into-view. Pure static
  JSX (no scroll-target measurement), so hydration is deterministic; a bottom
  padding + negative-margin trick keeps descenders (y/g/p) from clipping;
  reduced motion renders the plain heading. Verified live: 19 word-masks
  prerendered and hydrated; the pre-reveal state is exactly the designed
  matrix (rotate 3° + 115% translateY). The IntersectionObserver-gated
  *reveal moment* itself could not be observed in the occluded test window
  (see honesty note) — the component reuses framer-motion's standard
  whileInView machinery proven across the site.
- **Act-cut choreography (`StoryStage.tsx` + `sfx.ts`):** story act changes
  now land like hard cuts instead of plain crossfades — a one-frame
  cyan/violet flash overlay (keyed remount replays the CSS animation; the
  initial mount doesn't flash), a giant ghost act numeral (01–04) slamming
  in behind the copy (scale 1.45 → 1 with blur → sharp), and an audio
  impact thud (`sfxImpact`: 170→38 Hz sine drop + filtered noise tick,
  silent unless SF://AUDIO is on). The bottom-right HUD now reports the
  live act (ACT 02/04 · SF://STORY) instead of a static label. All
  animations are `prefers-reduced-motion: no-preference` gated; the
  reduced-motion branch never renders the sticky stage at all.
- **Direction-aware route curtain (`RouteCurtain.tsx`):** the transit wipe
  now follows canonical nav order — moving "forward" through the nav sweeps
  left→right as before, moving "back" (e.g. Reports → Forge) sweeps
  right→left with mirrored skew (new `sf-curtain--back` keyframes), and the
  curtain names its destination (SF://REPORTS, SF://FORGE …) instead of a
  static TRANSIT label. Verified live in both directions: forward transit
  showed the plain curtain with the destination word; a back transit from
  /reports to / carried `sf-curtain--back`. The `sf:transit` listener now
  re-subscribes on pathname changes so the direction calc always sees the
  current route.
- **Universal press pulse (`ClickFx.tsx` + CSS, mounted in layout):** every
  pointer-down lands a small radial ring at the pointer — the interface
  acknowledging the hit. The ripple elements are created imperatively,
  appended to `<body>`, and self-remove after 640 ms: they never touch
  React-managed DOM (round-15a rule holds by construction), fine pointers
  only, `prefers-reduced-motion` skipped. Verified live: a synthetic
  pointerdown spawned the pulse at the exact coordinates and it removed
  itself on schedule.
- **Footer wordmark drift (`FooterMark.tsx`, new client island in the
  server footer):** the giant outlined SENTINELFORGE now translates
  horizontally (±6%) as the footer crosses the viewport — one
  rAF-throttled rect read per scroll event, the value written straight
  into a `--fp-x` CSS var (no React re-renders); the mark keeps its CSS
  hover glow; the wrapper clips overflow so the drift can never cause a
  horizontal scrollbar; reduced motion leaves it static. Verified live:
  the var is written and the transform applies while scrolling.
- **Verified live (prod `:3006`, browser):** 19 mask-words prerendered +
  hydrated; pre-reveal mask matrices correct; curtain direction verified
  both ways with correct destination labels; press pulse spawn/self-remove
  verified; footer var + transform verified; typecheck + `next build`
  clean; full battery 129/129 across 11 files; zero hydration errors.
- **Honest scope:** the embedded browser window was fully occluded through
  most of this round (no paint → rAF near-starved → IntersectionObserver
  never fires), so three *motion moments* were verified at the
  state/structure level rather than observed at full fidelity: the
  MaskWords reveal animation completing, the act-cut flash/slam (the story
  stage's client mount itself was starved — the same artifact documented in
  rounds 16/17), and the marquee/act audio timing. All are standard,
  previously-proven mechanisms (framer whileInView, keyed remounts, CSS
  media-gated keyframes); nothing here depends on new infrastructure. The
  API (`:4000`) also died mid-round (in-memory server, documented
  limitation) and was relaunched; the console noise observed during that
  window was the expected CORS/ERR_FAILED set, gone after the relaunch.
  AI image quota untouched (none requested).

## Pentest & UX Audit Round 19 — enumeration oracle closed, TOTP grind cap, sliding remember-me, auth form rebuilt (2026-11-15)

Dual-hat round: **pentester** (attack the auth/API surface) + **web designer**
(audit every page's UX, components, states). Method: full file inventory of the
web app (58 files) and API (16 files); line-read of the security core
(`auth.ts`, `routes/auth.ts`, `store.ts`, `middleware/rbac.ts`, `lib/auth.ts`,
`AuthForm.tsx`, `Gate.tsx`, `app.ts`); a route sweep of every
`router.(get|post|put|delete|patch)`; live probes against `:4000`; XSS
anti-pattern sweep (`dangerouslySetInnerHTML`, tokens in web storage).

### Findings

- **F1 — username-enumeration oracle (CONFIRMED LIVE):** failed login on an
  *unknown* identifier returned `{"error":"Invalid credentials"}` while the
  *same wrong password on a registered* account returned
  `{"error":"Invalid credentials. 4 attempt(s) left."}` — the attempts-remaining
  reply only ever fired for existing accounts, so login doubled as a
  registered-username oracle. Reproduced live with curl before the fix.
- **F2 — TOTP grind gap:** `verify-2fa` had no per-user failure cap inside the
  5-minute temp-token window; the only brake was the IP limiter, so an attacker
  holding one temp token could grind the 10⁶ code space at that pace.
- **F3 — remember-me was dead code end-to-end:** the signup-era checkbox was
  never sent by the form (pre-rewrite), and `/refresh` re-issued every rotated
  token at a fixed 7 days regardless — a "remember me for 30 days" login
  silently degraded to a 7-day session on first rotation.
- **F4 — cookie parser split every pair on `=`:** values containing `=` (JWT
  fragments, base64 padding) were truncated at the first `=`.
- **Clean sweeps (no action):** every `:id` route is org-scoped via
  `orgOf(req)` (IDOR sweep across emulator/pipeline/findings/patch/graph/…
  confirmed again); access token memory-only + HttpOnly refresh cookie (no
  token in web storage); no `dangerouslySetInnerHTML` anywhere; attestation
  gates present on all mutation-style endpoints; error/not-found/system states
  on-brand with retry affordances.

### Fixes (API)

- **A1 — uniform login failure:** both unknown-user and wrong-password now
  return byte-identical `[401] {"error":"Invalid credentials"}`. Account
  lockout keeps its distinct message — it can only surface after 5 real
  attempts against a real account, which is standard practice and not an
  oracle. Verified live: unknown-user and known-user-wrong-password probes now
  byte-identical.
- **A2 — TOTP grind cap:** in-memory sliding window per user
  (5 failures / 5 min, reset on success or fresh login). 6th miss →
  `[403] "Too many verification attempts — start again from the password
  step."` + `2fa_grind_blocked` audit event. Verified live: 5×
  `[401] Invalid 2FA code`, then `[403]` on attempt 6.
- **A3 — sliding remember-me:** `/refresh` now re-issues for the *presented*
  token's remaining lifetime (rounded up, clamped 1..30 days) instead of a
  fixed 7 — works with both the postgres and memory stores, no schema change,
  absolute expiry preserved. Verified live end-to-end with a real TOTP code
  computed by the same library the server uses (speakeasy): verify
  `rememberMe:true` → `Set-Cookie sf_refresh … Max-Age=2592000` (30.00 days) →
  `POST /v1/auth/refresh` → re-issued cookie `Max-Age=2592000` (30.00 days
  kept, rotation + fresh access token confirmed) → fresh login +
  `rememberMe:false` → `Max-Age=604800` (7.00 days), flags `HttpOnly;
  SameSite=Strict`.
- **A4 — cookie parser:** splits each pair on the first `=` only, so values
  containing `=` survive intact.

### AuthForm rebuild (designer hat)

- Real `<form>` elements on all three steps — Enter submits everywhere and
  password managers can autodetect the flow properly (plus `name` +
  `autocomplete` attributes: `username` / `current-password` / `new-password`
  / `email` / `one-time-code`).
- **Live password checklist** on signup (10+ chars / upper / lower / digit /
  symbol — matching the API's actual `PW_RULES`), each rule lighting up as
  it's met; submit stays disabled until all five pass.
- The **remember-me choice is real now**: one "Stay signed in for 30 days"
  checkbox wired through BOTH the login and the verify step, feeding A3's
  sliding session.
- **Auto-verify on the 6th digit** (with a re-arm after a wrong code so a
  corrected entry still auto-fires) — a stale-state bug was caught during
  implementation: the auto-fire originally read the not-yet-committed state,
  fixed by passing the fresh digits explicitly.
- Caps-lock warning on password fields; auto-focus on the code input;
  one-click copy for the enrollment key (with copied-feedback and a graceful
  fallback when clipboard is blocked); explicit Back step; `role="alert"`
  error surface; `credentials: 'include'` documented in-code as the reason the
  cross-origin refresh cookie actually lands.
- **Verified deployed on prod `:3006`** (fresh build, SSR markers confirmed
  served: `<form>`, `name="identifier"`, checklist items, remember-me label;
  DOM ground truth on `/signup`: 4 named inputs, checklist rendered, submit
  `disabled` while the password is empty).

### Verification & honest scope

- `tsc --noEmit` clean for web and api; full battery **129/129 across 11
  files**; `next build` clean; fresh prod build redeployed on `:3006` and
  confirmed serving round-19 markers (an earlier "deploy" turned out to be a
  stale server answering with round-18 markup — detection and re-kill
  documented below).
- **Embedded-window limitation (recurring):** the test browser window stayed
  fully occluded this session — React never hydrated in the tab (no fiber
  keys on DOM nodes, empty `__next_f` flight queue, `requestAnimationFrame`
  starved, card opacity frozen at 0 even after the `$RV/$RB` stream-reveal
  kick and a reload; CDP clicks errored). So the *interactive runtime*
  behaviors (checklist lighting on keystrokes, auto-verify firing on the 6th
  digit, Enter-submit) are verified at **structure level** (DOM ground truth)
  plus **protocol level** — the UI posts the exact payloads that were proven
  live against `:4000`. Nothing here is unproven because of the API; the gap
  is only observing the client-side render loop, the same artifact documented
  in rounds 16–18.
- **Environment/ops notes:** `Get-NetTCPConnection` and `netstat` both
  under-reported the listener on `:3006` this session (a stale server served
  old markup while both tools showed no listener) — port ownership is now
  confirmed by *content markers*, not just status codes, and processes are
  killed by command line. A duplicate crash-looping API dev tree was found
  (two `tsx watch` processes; the one holding `:4000` is healthy) — left
  untouched rather than risk killing the live API; restart hygiene to consolidate.
- **Known limitations documented, deliberately not "fixed" this round:**
  `express-rate-limit` counts by `req.ip` — correct standalone, but a reverse
  proxy in front would need `trust proxy` + `X-Forwarded-For` discipline (no
  proxy exists in this deployment); the audit trail stores `org_id` as NULL
  for system events by design — visibility rules for those rows are a
  product decision, not a bug; `packages/sfso/saml` remains a typed stub
  (documented since its introduction); durable persistence still requires
  provisioning Supabase (`packages/db/README.md`) — the in-memory store was
  wiped by the API restarts this round, which is exactly the documented
  behavior.

## Account Security Center Round 20 — session inventory, device revocation, password rotation, authenticator re-enrollment (2026-11-15)

Round 19 hardened the auth surface; round 20 hands users control over their own
security posture. Until now there was **no way to see which devices held a live
session, no way to revoke one, no password change flow, and no way to re-enroll
a lost authenticator** — all standard capabilities a security product should
model for its own operators.

### API (`/v1/auth/*`, all under requireAuth + the IP limiter)

- **`GET /sessions`** — the caller's live refresh sessions (jti, created,
  expires-in-days, `current` marker from the request's own cookie). The jti
  authorizes nothing on its own (tokens are signed server-side); exposing it
  to its owner is exactly what makes per-device kill possible.
- **`POST /sessions/revoke`** — kill ONE session, self-scoped (a jti that
  doesn't belong to the caller 404s, never a cross-user error). Revoking the
  session your own browser holds acts as a **logout**: the presented access
  token is denied and the cookie is cleared (`selfRevoked: true`).
- **`POST /sessions/revoke-all`** — every device out, including the caller.
- **`POST /password`** — rotate with re-auth (current password verified against
  bcrypt(12)); enforces the exact signup policy (shared `passwordSchema` +
  reject-unchanged); **other sessions die, the caller's own survives**; returns
  the count for the UI ("N other session(s) signed out").
- **`POST /totp/re-enroll`** — password re-auth → fresh secret + temp token,
  completed through the **existing** `/verify-2fa` (no new verify machinery).
  Revokes all other sessions. Safety property: if the flow is abandoned, the
  next login re-enrolls from scratch (login regenerates the secret whenever
  `totp_enrolled` is false) — **password knowledge can always recover the
  account**, so no permanent lockout path exists.
- **`REAUTH_FAILS` cap** (5 wrong-password / 5 min per user, shared `failCap`
  factory with the TOTP grind cap from round 19) on password rotation and
  re-enroll: someone holding a stolen *access* token must not be able to
  brute-force the password factor through these endpoints.
- `verify-2fa` and `/refresh` now return `sessionId` so each device can
  recognize itself in the list.

### Design flaw found and fixed during this round's own tests

The first per-device revocation tests **exposed a live design bug**: a revoked
device naturally replays its cookie on its next background refresh, and the
refresh-reuse detector treated that as **theft → family kill → the whole
account signed out** (including the device that did the revoking). Voluntary
revocation would have been indistinguishable from token theft. Fixed by
recording WHY a token is dead:

- `reason='rotated'` — normal rotation; **replay is still the theft signal**
  (family kill unchanged, original behavior preserved).
- `reason='revoked'` — owner action (device revoke / logout / password
  rotation / revoke-all); **replay is expected → quiet 401 "Session was
  revoked"**, no family kill. New `refresh_revoked_replay` audit event.
- Migration `packages/db/migrate-005.sql` (idempotent `reason` column); memory
  store mirrors it. Verified live: revoked device replays → quiet 401 while
  the surviving device keeps rotating.

### Web

- New **`/account` — Security Center** page (PageHeader + AmbientScene, three
  glass consoles): PASSWORD (re-auth + live shared-policy checklist + confirm),
  AUTHENTICATOR (enrolled status from `/me`, re-enroll stepper with manual-key
  display + copy + auto-verify on the 6th digit, reusing the login form's
  proven pattern), SESSIONS (live device list with THIS DEVICE badge, per-row
  REVOKE, SIGN OUT EVERYWHERE). Self-revoke and revoke-all return to /login.
- Shared **`lib/pwRules.ts`** — the signup checklist and the password card now
  read one source of truth that mirrors the API's zod schema.
- `lib/auth.ts` tracks the refresh `sessionId` in memory (updated by verify +
  silent refresh) and `getMe()` now surfaces `totpEnrolled`.
- Route registration across all five surfaces: Nav links, MenuOverlay
  ("Sessions · keys · posture"), command palette (ACCOUNT group), footer, and
  the direction-aware route curtain (`ROUTE_ORDER` + SF://ACCOUNT).
- Deployed and verified on prod `:3006`: SSR markers for the header, nav link,
  and the gated "CHECKING SESSION → No live session" client flow.

### Verification

- Full battery **135/135 across 12 files** (6 new tests in
  `apps/api/tests/account.test.ts`: auth gates on every endpoint, current-device
  marking, exact-one-revocation, cross-user/unknown jti 404s, revoke-all count,
  self-revoke-as-logout, password rotation incl. policy + old-password-dead +
  new-password-logs-in + other-sessions-die + own-session-survives,
  re-enroll incl. old-code-dies + new-code-verifies). Both typechecks clean;
  `next build` clean.
- **25/25 live protocol checks** against the running API (`:4000`) with real
  speakeasy-computed TOTP codes and three independent per-device cookie jars:
  the complete flow above including the survival checks (A keeps rotating
  after B is revoked; A keeps rotating after password rotation kills C) and
  revoked-cookie replay → quiet 401.
- Honest notes: the first live-script run used ONE cookie jar for three
  devices and produced a cascade of "failures" that were actually correct API
  behavior (B's verify overwrote A's cookie in the jar; revoking the session
  your own cookie holds correctly returned `selfRevoked: true`) — the script
  was rewritten per-device, and the accidental insight became a real test
  (self-revoke = logout). The embedded browser window stayed occluded/starved
  this session (same documented artifact since round 16), so the /account
  client-side render loop is verified at SSR + DOM-state level and through the
  protocol transcript, not visually. The API also died once mid-round (tsx
  watch crash after the store edits — the known in-memory/dev-watch fragility)
  and was relaunched; the duplicate second API dev tree from round 19 is still
  present and untouched. AI image quota untouched (none requested).
- Known limitations (documented, deliberate): revoking a device does not
  instantly kill its short-lived access token (it dies naturally within
  minutes — stated in the UI copy); re-enrollment revokes the caller's session
  too (the verify step issues a fresh one); TOTP recovery codes remain
  deferred — password knowledge is the recovery factor via login re-enrollment,
  which covers the lockout risk without a second credential store.

## Sensory Round 21 — cinematic post layer, horizon depth, preloader audio (2026-11-15)

Rounds 19–20 were both security rounds; the visual layer was due. This round
adds the award-site "post" look the WebGL scenes were missing — deliberately,
with ZERO new dependencies (no `postprocessing` package: one custom shader
pass, ~200 lines).

### PostFX — a single fullscreen grading pass on the pinned story scene

`apps/web/app/post/PostFX.tsx`, wired into `StoryScene` (the landing's
480vh centerpiece canvas):

- **chromatic aberration** that scales with scene motion energy (pointer
  speed + scroll + story-scrub delta, fast-attack/slow-settle) — the image
  splits when the ensemble is in motion and settles when it rests;
- **cheap HDR bloom** — bright-pass (threshold 0.55 on the linear HDR target)
  + two 8-tap rings, boosted by motion energy;
- **animated film grain** + **corner vignette**.

Correctness notes verified against the installed sources before writing it:
three r185 applies tone mapping ONLY when rendering to the default
framebuffer (`WebGLPrograms.js`: `currentRenderTarget === null`), so the
scene renders to a 4×MSAA HalfFloat render target as linear HDR and the post
pass itself applies the renderer's own ACES tone mapping
(`#include <tonemapping_fragment>`) + linear→sRGB
(`#include <colorspace_fragment>`) — the identical look the direct render
produced, plus effects. R3F's positive-priority `useFrame` subscriber takes
over rendering (confirmed in the fiber loop source), which is what makes the
two-pass chain possible with no new packages.

**Capability gate** (`usePostOK`): reduced-motion users, viewports < 900px,
and low-core/low-memory devices skip the pass entirely and render exactly as
before — the effect layer is an enhancement, never a requirement.

### Inner pages — perspective horizon grid

`AmbientScene` gained `.sf-horizon`: a pure-CSS depth floor (two repeating
gradients under a `perspective + rotateX` transform; the horizontal lines
flow toward the viewer in a seamless loop) beneath the starfield. Static
frame for reduced-motion users. Zero JS.

### Sound

Preloader reveal now lands with a soft rising sweep (`sfxBlip(340, 980, …)`)
— SF://AUDIO opt-in shell only; the sfx layer self-guards on the engine
existing, so silent by default as always.

### Verification

- Web typecheck clean, `next build` clean, full battery **135/135 across 12
  files** (no API changes this round).
- Deployed to prod `:3006`: SSR markers for the story fallback
  ("Every device hides a story." / ACT 01 / scroll cue) and the horizon grid
  div on inner pages; the PostFX shader is confirmed shipped in the client
  chunk (unique `tDiffuse` uniform string found in `.next/static/chunks`).
- Honest limits: the embedded browser stayed occluded/starved (documented
  artifact since round 16), so the post layer's VISUAL result is verified at
  SSR + bundle level and by source-level correctness checks, not by eye.
  The capability gate makes the worst case (gate misfires on) identical to
  the previous rendering. Legacy note: `CinematicHero`/`HeroScene` have been
  unmounted since the round-5 landing redesign — PostFX is wired there too
  (dormant) so a future remount inherits the look.

## Recovery Codes Round 22 — the lost-authenticator lockout hole closed (2026-11-16)

Round 20 shipped the Account Security Center and documented TOTP recovery
codes as "deliberately deferred" with the claim that password knowledge was
always a recovery factor. Writing round 22's plan surfaced that this claim had
a **real hole**: it covered only *abandoned re-enrollment flows* (where
`totp_enrolled` is already false). A user with an **active** enrollment who
loses their authenticator was hard-locked out — login demands a TOTP code,
and `/totp/re-enroll` requires an authenticated session they can no longer
obtain. Round 22 closes that hole end to end.

### API (`/v1/auth/*`)

- **Issuance at enrollment completion** — `verify-2fa` succeeding while
  `totp_enrolled=false` (first enrollment, or a round-20 re-enrollment)
  generates **10 single-use codes** and returns them in that ONE response.
  Plaintext never exists again afterwards (the store keeps SHA-256 digests
  only).
- **Recovery login path** — `verify-2fa` now accepts `recoveryCode` instead of
  the 6-digit `code`. A valid unused code completes the login without TOTP,
  **consumes itself**, **revokes every other session** (a lost authenticator
  is a compromise signal), flips `totp_enrolled=false` + clears the stored
  secret, and reports `usedRecoveryCode` + `recoveryRemaining`. The NEXT login
  therefore re-enrolls from scratch: password knowledge + one unused code
  always recovers the account, and the replacement authenticator gets a fresh
  set at that enrollment.
- **`GET /recovery-codes`** — remaining count only (never the codes).
- **`POST /recovery-codes`** — password re-auth (REAUTH_FAILS cap 5/5min) →
  fresh set of 10; the old set is fully invalidated.
- **Grind cap** — recovery attempts share the TOTP_FAILS cap (5 misses / 5min
  per user): a stolen temp token cannot grind the recovery-code space any
  more than the TOTP space.
- **Storage** — SHA-256 of the *normalized* code (uppercase, non-alphanumerics
  stripped), constant-time compare. Deliberate choice, documented: a slow
  hash buys nothing against a 50-bit random value offline, and online guessing
  is bounded by the grind cap + IP limiter — bcrypt stays reserved for the
  password class. Codes use a 31-symbol unambiguous alphabet (no 0/O/1/I/L)
  generated with rejection sampling (b < 248 = 8×31) for zero modulo bias.
- `packages/db/migrate-006.sql` (idempotent `recovery_codes` table; memory
  store mirrors it).

### Two real bugs caught by this round's own tests

1. **`undefined` inside issued codes**: the alphabet has 31 symbols but was
   indexed `% 32` — index 31 returned `undefined` and was string-concatenated
   into a code (live: `"UJDun-defined5PUGEU"`). The new per-code format
   assertion caught it immediately; fixed with `% 31` + rejection sampling.
2. **Store/compare asymmetry**: the route stored `sha256(code)` *with the
   dash* while verification compared `sha256(normalized)` *without it* —
   every valid code failed. Found via a scratch-trace test that dumped actual
   response bodies; both call sites now hash the normalized form.

(A third, embarrassing one: the test's alphabet regex itself was wrong twice —
excluding `J`/`U` that the alphabet keeps. The codes were right; the assertion
was wrong.)

### Web

- **AuthForm**: after enrollment, a one-time "Save your recovery codes" panel
  (2-col grid, copy-all, navigation held until acknowledged). The verify step
  gained a "Lost your phone? Use a recovery code" toggle switching to a
  free-form recovery field (uppercase, dashes OK); recovery sign-in lands with
  an amber banner ("N unused left — your authenticator is unlinked, the next
  login enrolls a new one").
- **Security Center** (`/account`): the AUTHENTICATOR card now carries a
  RECOVERY CODES console — live unused count, password-gated "NEW SET" flow
  with the same one-time display + copy-all pattern.
- Deployed to prod `:3006`; login/account SSR markers verified and the
  recovery UI confirmed in the shipped client chunk.

### Verification

- Full battery **138/138 across 12 files** (3 new tests in
  `account.test.ts`: issuance/uniqueness/format + auth-gated count; the
  complete recovery flow incl. replay-401, junk-401, forced re-enrollment and
  old-set death; regeneration incl. re-auth + full replacement). Both
  typechecks clean; `next build` clean.
- **20/20 live protocol checks** against the running API (`:4000`) with
  per-device cookie jars: issuance → count → junk 401 → recovery (remaining 9,
  OTHER SESSION REVOKED — the round-20 `reason='revoked'` quiet-401 semantics
  visible again) → replay 401 → re-enroll with fresh codes → old set dead →
  lowercase normalization accepted → regenerate (wrong pw 401, right pw 10
  fresh, pre-regen dead, new live).
- Honest notes: the API dev tree died once mid-round (the known tsx-watch
  fragility) and was relaunched — in-memory accounts wiped; tests and the
  live script both re-ran against the fresh process. The occluded embedded
  browser artifact persists, so UI verification is SSR + bundle level; the
  recovery flows themselves are protocol-verified end to end. Scratch debug
  test deleted after diagnosis. AI image quota untouched.

## Dependency Hygiene

- `npm audit --workspaces --audit-level=high` runs in CI
- Critical vulnerabilities in production dependencies block deployment
- `overrides` in root `package.json` pin vulnerable transitive dependencies
