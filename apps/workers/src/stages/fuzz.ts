// AI-guided coverage fuzzing — prototype (spec: Autonomous Discovery Engine §1).
// Real loop, real coverage, in-process: select → mutate → execute → keep-if-novel.
// "AI-guided" is a PLUGGABLE interface (GuidanceModel): the default scorer spends the
// time budget on novel coverage near tainted sinks; the model-serving microservice
// (traffic-trained mutation guidance, federated updates) implements the same interface
// in production. AFL++/QEMU-mode replaces `executeHarness` for real binaries.
// Deterministic PRNG (mulberry32) → every campaign reproduces from its seed + corpus.

export type HarnessResult = 'ok' | { crash: string };
export type Harness = (input: Uint8Array, cover: Set<number>) => HarnessResult;

// Scores a mutated candidate: higher = fuzz it sooner / retain on ties.
export type GuidanceModel = {
  name: string;
  score(candidate: Uint8Array, ctx: { coverage: number; parentNovel: boolean; sinkHints: string[] }): number;
};

export const noveltyGuidance: GuidanceModel = {
  name: 'novelty+sink-proximity (default heuristic)',
  score(candidate, ctx) {
    let s = ctx.parentNovel ? 2 : 1; // breed winners
    if (ctx.sinkHints.some((h) => Buffer.from(candidate).toString('latin1').includes(h))) s += 3; // near tainted sinks
    s += Math.min(candidate.length / 64, 2); // slight preference for structure
    return s;
  },
};

function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export type FuzzCrash = { inputHex: string; reason: string; atExec: number };
export type FuzzResult = {
  execs: number;
  coverage: number[]; // sorted covered block ids
  corpus: string[]; // hex of retained novel inputs
  crashes: FuzzCrash[];
  guidance: string;
};

function mutate(rng: () => number, base: Uint8Array, dict: Uint8Array[]): Uint8Array {
  const buf = Uint8Array.from(base);
  const op = Math.floor(rng() * 5);
  const at = buf.length > 0 ? Math.floor(rng() * buf.length) : 0;
  switch (op) {
    case 0: // bitflip
      if (buf.length) buf[at] ^= 1 << Math.floor(rng() * 8);
      break;
    case 1: // byte arithmetic
      if (buf.length) buf[at] = (buf[at] + (rng() < 0.5 ? 1 : 255)) & 0xff;
      break;
    case 2: // truncate / extend
      if (buf.length > 1 && rng() < 0.5) return buf.slice(0, Math.max(1, Math.floor(rng() * buf.length)));
      return Uint8Array.from([...buf, Math.floor(rng() * 256)]);
    case 3: // dictionary insert (protocol keywords, format chars)
      if (dict.length) {
        const w = dict[Math.floor(rng() * dict.length)];
        const out = new Uint8Array(buf.length + w.length);
        out.set(buf.slice(0, at), 0);
        out.set(w, at);
        out.set(buf.slice(at), at + w.length);
        return out;
      }
      break;
    default: // interesting bytes
      if (buf.length) buf[at] = [0x00, 0xff, 0x41, 0x25, 0x00][Math.floor(rng() * 5)];
  }
  return buf;
}

export const DEFAULT_DICT = ['%x', '%s', '%n', 'admin', '../', '\x00', '\xff\xff', 'GET ', 'AT+'];

export function fuzz(
  harness: Harness,
  opts: { seeds: Uint8Array[]; iterations: number; seed?: number; guidance?: GuidanceModel; sinkHints?: string[]; dict?: string[] }
): FuzzResult {
  // Hard ceiling: a campaign is CPU-bound synchronous work — never let a caller
  // pin the event loop indefinitely (MCP already caps at 20k; belt and braces).
  const totalIterations = Math.min(Math.max(Math.floor(opts.iterations), 1), 100_000);
  const rng = mulberry32(opts.seed ?? 0xF02CE);
  const guidance = opts.guidance ?? noveltyGuidance;
  const dict = (opts.dict ?? DEFAULT_DICT).map((s) => Buffer.from(s, 'latin1'));
  const sinkHints = opts.sinkHints ?? [];
  const covered = new Set<number>();
  const corpus: Uint8Array[] = opts.seeds.map((s) => Uint8Array.from(s));
  const crashes: FuzzCrash[] = [];
  let execs = 0;

  // baseline: run seeds once
  for (const s of corpus) {
    const cov = new Set<number>();
    const r = harness(s, cov);
    execs++;
    for (const b of cov) covered.add(b);
    if (r !== 'ok') crashes.push({ inputHex: Buffer.from(s).toString('hex'), reason: r.crash, atExec: execs });
  }

  for (let i = 0; i < totalIterations; i++) {
    // weighted pick: score corpus members, sample proportionally
    const weights = corpus.map((c) => guidance.score(c, { coverage: covered.size, parentNovel: true, sinkHints }));
    let pick = rng() * weights.reduce((a, b) => a + b, 0);
    let parent = corpus[0];
    for (let k = 0; k < corpus.length; k++) {
      pick -= weights[k];
      if (pick <= 0) {
        parent = corpus[k];
        break;
      }
    }
    const child = mutate(rng, parent, dict);
    const cov = new Set<number>();
    const r = harness(child, cov);
    execs++;
    if (r !== 'ok') {
      if (!crashes.some((c) => c.reason === r.crash && c.inputHex === Buffer.from(child).toString('hex')))
        crashes.push({ inputHex: Buffer.from(child).toString('hex'), reason: r.crash, atExec: execs });
      continue;
    }
    const novel = [...cov].some((b) => !covered.has(b));
    for (const b of cov) covered.add(b);
    if (novel && corpus.length < 512) corpus.push(child);
  }
  return {
    execs,
    coverage: [...covered].sort((a, b) => a - b),
    corpus: corpus.map((c) => Buffer.from(c).toString('hex')),
    crashes,
    guidance: guidance.name,
  };
}

// Demo target: simulated `httpd` query parser with a strcpy overflow reachable only
// past two magic checks — stands in for the emulator-hosted binary until the
// QEMU harness + FirmAE bridge lands. Coverage ids model basic blocks, including
// depth blocks (5, 6) so the novelty-guided loop can climb toward the overflow
// the same way real block coverage leads AFL++ deeper into a parser.
export function demoHarness(input: Uint8Array, cover: Set<number>): HarnessResult {
  cover.add(0); // entry
  const s = Buffer.from(input).toString('latin1');
  if (s.startsWith('GET ')) {
    cover.add(1);
    if (s.includes('admin')) {
      cover.add(2); // privileged path → tainted sink region
      if (input.length > 12) cover.add(5); // deeper parse state
      if (input.length > 18) cover.add(6);
      if (input.length > 24) return { crash: 'stack-overflow in strcpy (query → rsp buffer)' };
      cover.add(3);
    }
  }
  if (s.includes('%x')) cover.add(4); // format-string probe
  return 'ok';
}
