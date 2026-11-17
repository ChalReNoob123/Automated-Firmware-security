'use client';

// SF://AUDIO — the site's robotic voice, fully synthesized. No audio assets:
// every blip, whoosh, drone and boot sequence is generated live with the Web
// Audio API, and the "robotic narrator" is the browser's own speech engine at
// a crushed pitch. Design decisions:
//  - DEFAULT-ON (round 28), gesture-gated by necessity: browsers suspend
//    AudioContext until a user gesture, so the FIRST pointer-down or keydown
//    anywhere arms the engine quietly (no stealth boot fanfare — a short chirp
//    on auto-resume; the boot fanfare plays only when the chip is clicked
//    explicitly). The preference persists: sf_audio=1 after enabling,
//    sf_audio=0 after an explicit mute — the only way sound stays off. There
//    is no autoplay-before-gesture path, ever.
//  - The engine OWNS its listeners: delegated pointerover/click sound hooks
//    and the sf:transit whoosh attach in enableAudio() and detach in
//    disableAudio(). They mutate no React-managed DOM (hydration-safe by
//    construction — the round-15a rule).
//  - Everything is QUIET: master 0.6 through a compressor, individual gains
//    0.02–0.12. The soundscape should feel like a console, not an arcade.
//  - Background tabs stay silent (document.hidden short-circuits), and
//    prefers-reduced-motion does not gate audio (sound ≠ motion), but the
//    visual EQ bars in SoundToggle are CSS-gated.

type Engine = {
  ac: AudioContext;
  master: GainNode;
  ambientGain: GainNode | null;
  pingTimer: number | null;
};

let engine: Engine | null = null;
let enabled = false;
const subs = new Set<(on: boolean) => void>();

const notify = () => subs.forEach((fn) => fn(enabled));

export function isAudioOn(): boolean {
  return enabled;
}

export function subscribeAudio(fn: (on: boolean) => void): () => void {
  subs.add(fn);
  return () => subs.delete(fn);
}

export function audioPreferred(): boolean {
  try {
    if (typeof window === 'undefined') return false;
    // round 28: sound is ON by default. An explicit '0' (the mute button) is
    // the only off state; '1' or no preference at all → the first user
    // gesture arms the engine.
    return localStorage.getItem('sf_audio') !== '0';
  } catch {
    return false;
  }
}

/* ---------------------------- synthesis helpers ---------------------------- */

function noiseBuffer(ac: AudioContext, seconds: number): AudioBuffer {
  const buf = ac.createBuffer(1, Math.floor(ac.sampleRate * seconds), ac.sampleRate);
  const data = buf.getChannelData(0);
  for (let i = 0; i < data.length; i++) data[i] = Math.random() * 2 - 1;
  return buf;
}

// short filtered square blip with a rising exponential pitch — the "console tick"
function blip(freq = 760, rise = 1500, dur = 0.055, vol = 0.03) {
  if (!engine || document.hidden) return;
  const { ac, master } = engine;
  const t = ac.currentTime;
  const osc = ac.createOscillator();
  const g = ac.createGain();
  const f = ac.createBiquadFilter();
  f.type = 'bandpass';
  f.frequency.value = freq * 1.4;
  f.Q.value = 1.2;
  osc.type = 'square';
  osc.frequency.setValueAtTime(freq, t);
  osc.frequency.exponentialRampToValueAtTime(rise, t + dur);
  g.gain.setValueAtTime(0, t);
  g.gain.linearRampToValueAtTime(vol, t + 0.008);
  g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
  osc.connect(f).connect(g).connect(master);
  osc.start(t);
  osc.stop(t + dur + 0.02);
}

// two-step confirmation chirp for clicks
function confirmChirp() {
  if (!engine || document.hidden) return;
  blip(880, 1240, 0.05, 0.034);
  const { ac } = engine;
  const t = ac.currentTime;
  const osc = ac.createOscillator();
  const g = ac.createGain();
  osc.type = 'triangle';
  osc.frequency.setValueAtTime(1318, t + 0.055);
  g.gain.setValueAtTime(0, t + 0.055);
  g.gain.linearRampToValueAtTime(0.032, t + 0.062);
  g.gain.exponentialRampToValueAtTime(0.0001, t + 0.13);
  osc.connect(g).connect(engine.master);
  osc.start(t + 0.055);
  osc.stop(t + 0.15);
}

// route-transit whoosh: filtered noise with a bandpass sweep
function whoosh() {
  if (!engine || document.hidden) return;
  const { ac, master } = engine;
  const t = ac.currentTime;
  const src = ac.createBufferSource();
  src.buffer = noiseBuffer(ac, 0.5);
  const bp = ac.createBiquadFilter();
  bp.type = 'bandpass';
  bp.Q.value = 1.1;
  bp.frequency.setValueAtTime(220, t);
  bp.frequency.exponentialRampToValueAtTime(2600, t + 0.16);
  bp.frequency.exponentialRampToValueAtTime(260, t + 0.4);
  const g = ac.createGain();
  g.gain.setValueAtTime(0, t);
  g.gain.linearRampToValueAtTime(0.11, t + 0.09);
  g.gain.exponentialRampToValueAtTime(0.0001, t + 0.42);
  src.connect(bp).connect(g).connect(master);
  src.start(t);
  src.stop(t + 0.5);
}

// sonar ping with a feedback echo — the ambient "the system is listening" cue
function ping(vol = 0.02) {
  if (!engine || document.hidden) return;
  const { ac, master } = engine;
  const t = ac.currentTime;
  const osc = ac.createOscillator();
  const g = ac.createGain();
  const delay = ac.createDelay(1);
  const fb = ac.createGain();
  osc.type = 'sine';
  osc.frequency.setValueAtTime(1150, t);
  osc.frequency.exponentialRampToValueAtTime(760, t + 0.5);
  g.gain.setValueAtTime(vol, t);
  g.gain.exponentialRampToValueAtTime(0.0001, t + 1.1);
  delay.delayTime.value = 0.31;
  fb.gain.value = 0.34;
  osc.connect(g);
  g.connect(master);
  g.connect(delay);
  delay.connect(fb).connect(delay);
  delay.connect(master);
  osc.start(t);
  osc.stop(t + 1.2);
}

// programmatic trigger for feature moments (engine run completion, etc.)
export function sfxPing(vol = 0.03): void {
  ping(vol);
}

// programmatic console tick for interaction features (drag pickup/drop, etc.)
export function sfxBlip(freq = 760, rise = 1500, dur = 0.055, vol = 0.03): void {
  blip(freq, rise, dur, vol);
}

// act-cut impact: a low register drop with a noise tick — the story changing
// scenes lands like a hard cut, not a crossfade (used on story act changes)
export function sfxImpact(): void {
  if (!engine || document.hidden) return;
  const { ac, master } = engine;
  const t = ac.currentTime;
  const osc = ac.createOscillator();
  const g = ac.createGain();
  osc.type = 'sine';
  osc.frequency.setValueAtTime(170, t);
  osc.frequency.exponentialRampToValueAtTime(38, t + 0.28);
  g.gain.setValueAtTime(0.06, t);
  g.gain.exponentialRampToValueAtTime(0.0001, t + 0.34);
  osc.connect(g).connect(master);
  osc.start(t);
  osc.stop(t + 0.4);
  const src = ac.createBufferSource();
  src.buffer = noiseBuffer(ac, 0.08);
  const bp = ac.createBiquadFilter();
  bp.type = 'bandpass';
  bp.frequency.value = 2400;
  bp.Q.value = 0.8;
  const ng = ac.createGain();
  ng.gain.setValueAtTime(0.05, t);
  ng.gain.exponentialRampToValueAtTime(0.0001, t + 0.07);
  src.connect(bp).connect(ng).connect(master);
  src.start(t);
}

// the boot fanfare: four rising console blips + a soft pad sweep + the narrator
function boot() {
  if (!engine) return;
  const notes = [392, 523.25, 659.25, 880];
  notes.forEach((n, i) => {
    window.setTimeout(() => blip(n, n * 1.35, 0.07, 0.036), i * 85);
  });
  // pad: slow saw swell under the blips, filtered warm
  const { ac, master } = engine;
  const t = ac.currentTime;
  const osc = ac.createOscillator();
  const g = ac.createGain();
  const lp = ac.createBiquadFilter();
  lp.type = 'lowpass';
  lp.frequency.setValueAtTime(240, t);
  lp.frequency.exponentialRampToValueAtTime(1400, t + 0.9);
  lp.frequency.exponentialRampToValueAtTime(300, t + 1.8);
  osc.type = 'sawtooth';
  osc.frequency.value = 110;
  g.gain.setValueAtTime(0, t);
  g.gain.linearRampToValueAtTime(0.05, t + 0.35);
  g.gain.exponentialRampToValueAtTime(0.0001, t + 1.8);
  osc.connect(lp).connect(g).connect(master);
  osc.start(t);
  osc.stop(t + 1.9);
  speak('Sentinel Forge systems online. All modules nominal.');
}

// the "robotic voice": the browser speech engine at a crushed pitch, vinyl-mono
function speak(text: string) {
  try {
    const synth = window.speechSynthesis;
    if (!synth) return;
    synth.cancel();
    const u = new SpeechSynthesisUtterance(text);
    u.pitch = 0.3; // deep synth register — reads as machine, not human
    u.rate = 0.94;
    u.volume = 0.85;
    const voices = synth.getVoices();
    const preferred =
      voices.find((v) => /en[-_](GB|US)/i.test(v.lang) && /male|daniel|david|alex|fred/i.test(v.name)) ??
      voices.find((v) => v.lang.startsWith('en'));
    if (preferred) u.voice = preferred;
    synth.speak(u);
  } catch {
    /* speech is a garnish — never a failure */
  }
}

/* ------------------------------ ambient drone ------------------------------ */

function startAmbient() {
  if (!engine || engine.ambientGain) return;
  const { ac, master } = engine;
  const t = ac.currentTime;
  const g = ac.createGain();
  g.gain.setValueAtTime(0, t);
  g.gain.linearRampToValueAtTime(1, t + 2.2); // fades in as a whole
  const lp = ac.createBiquadFilter();
  lp.type = 'lowpass';
  lp.frequency.value = 170;
  lp.Q.value = 0.8;
  // slow filter breathing — the drone "inhales"
  const lfo = ac.createOscillator();
  const lfoG = ac.createGain();
  lfo.frequency.value = 0.06;
  lfoG.gain.value = 46;
  lfo.connect(lfoG).connect(lp.frequency);
  // two detuned saws + a sub sine = machine-room hum
  const o1 = ac.createOscillator();
  o1.type = 'sawtooth';
  o1.frequency.value = 54;
  const o2 = ac.createOscillator();
  o2.type = 'sawtooth';
  o2.frequency.value = 54.55;
  const sub = ac.createOscillator();
  sub.type = 'sine';
  sub.frequency.value = 27;
  const subG = ac.createGain();
  subG.gain.value = 0.55;
  o1.connect(lp);
  o2.connect(lp);
  sub.connect(subG).connect(lp);
  lp.connect(g).connect(master);
  g.gain.value = 0;
  const out = 0.016; // drone sits under everything
  g.gain.linearRampToValueAtTime(out, t + 2.5);
  o1.start(t);
  o2.start(t);
  sub.start(t);
  lfo.start(t);
  engine.ambientGain = g;
  engine.pingTimer = window.setInterval(() => ping(0.016), 8200);
  const stopAll = () => {
    try {
      o1.stop();
      o2.stop();
      sub.stop();
      lfo.stop();
    } catch {
      /* already stopped */
    }
  };
  (g as GainNode & { __stopAll?: () => void }).__stopAll = stopAll;
}

function stopAmbient() {
  if (!engine?.ambientGain) return;
  const g = engine.ambientGain;
  const t = engine.ac.currentTime;
  g.gain.cancelScheduledValues(t);
  g.gain.setValueAtTime(g.gain.value, t);
  g.gain.linearRampToValueAtTime(0, t + 0.5);
  const stopAll = (g as GainNode & { __stopAll?: () => void }).__stopAll;
  window.setTimeout(() => stopAll?.(), 560);
  if (engine.pingTimer != null) {
    window.clearInterval(engine.pingTimer);
    engine.pingTimer = null;
  }
  engine.ambientGain = null;
}

/* ------------------------------ enable / disable ------------------------------ */

let uiHandlers: (() => void) | null = null;

export function enableAudio(resume = false): void {
  try {
    if (!engine) {
      const ac = new AudioContext();
      const master = ac.createGain();
      master.gain.value = 0.6;
      const comp = ac.createDynamicsCompressor();
      comp.threshold.value = -22;
      comp.ratio.value = 5;
      master.connect(comp).connect(ac.destination);
      engine = { ac, master, ambientGain: null, pingTimer: null };
    }
    void engine.ac.resume();
    if (enabled) return;
    enabled = true;
    try {
      localStorage.setItem('sf_audio', '1');
    } catch {
      /* private mode — session-only audio */
    }
    startAmbient();
    if (!resume) boot();
    else confirmChirp();
    // delegated UI sound hooks — attach once, mutate no DOM
    if (!uiHandlers) {
      let lastHover: Element | null = null;
      const over = (e: PointerEvent) => {
        const el = (e.target as Element | null)?.closest?.('a, button');
        if (!el || el === lastHover) return;
        lastHover = el;
        blip(920, 1420, 0.04, 0.022);
      };
      const out = (e: PointerEvent) => {
        if ((e.target as Element | null)?.closest?.('a, button') === lastHover) lastHover = null;
      };
      const down = () => confirmChirp();
      const transit = () => whoosh();
      document.addEventListener('pointerover', over, { passive: true });
      document.addEventListener('pointerout', out, { passive: true });
      document.addEventListener('pointerdown', down, { passive: true });
      window.addEventListener('sf:transit', transit);
      uiHandlers = () => {
        document.removeEventListener('pointerover', over);
        document.removeEventListener('pointerout', out);
        document.removeEventListener('pointerdown', down);
        window.removeEventListener('sf:transit', transit);
        lastHover = null;
      };
    }
    notify();
  } catch {
    /* AudioContext unavailable — the site is complete without sound */
  }
}

export function disableAudio(): void {
  if (!engine) {
    enabled = false;
    try {
      localStorage.removeItem('sf_audio');
    } catch {
      /* ignore */
    }
    notify();
    return;
  }
  enabled = false;
  try {
    // explicit mute persists as a real '0' — with the default-on policy,
    // removeItem would silently re-enable on the next visit
    localStorage.setItem('sf_audio', '0');
  } catch {
    /* ignore */
  }
  stopAmbient();
  try {
    window.speechSynthesis?.cancel();
  } catch {
    /* ignore */
  }
  uiHandlers?.();
  uiHandlers = null;
  void engine.ac.suspend();
  notify();
}

// Round 28: sound is default-ON, so this arms on the FIRST gesture for
// everyone who hasn't explicitly muted. The first pointerdown OR keydown
// counts (Tab-through users shouldn't miss the console). Quiet resume —
// no boot fanfare unless the chip is clicked.
export function armFromPreference(): void {
  if (enabled || !audioPreferred() || engine) return;
  const once = () => {
    document.removeEventListener('pointerdown', once, true);
    document.removeEventListener('keydown', once, true);
    if (!enabled && audioPreferred()) enableAudio(true);
  };
  document.addEventListener('pointerdown', once, true);
  document.addEventListener('keydown', once, true);
}
