// Round 33 — the consensus model, on the client.
//
// This mirrors apps/workers/src/stages/consensus.ts (ENGINE_FAMILY,
// confidenceOf, priorityOf). The web app cannot import that package — it is a
// server-side bundle, and shipping the whole engine graph into a page chunk
// would be worse than this small table. The rule is therefore duplicated ON
// PURPOSE and kept deliberately narrow: families in, verdict out. The priority
// TOTAL shown on the evidence page is still the API's engine-computed number;
// these helpers only EXPLAIN it, so a drift here can never reorder a queue.
//
// If an engine is added to the workers map, add it here too — an unknown
// engine falls back to its own name as a family, which over-counts
// independence (that is the workers behaviour as well, not a local invention).

export type Confidence = 'Confirmed' | 'Likely' | 'Unconfirmed';

export const ENGINE_FAMILY: Record<string, string> = {
  static: 'static-analysis',
  secrets: 'static-analysis',
  yara: 'static-analysis',
  taint: 'symbolic',
  symbolic: 'symbolic',
  fuzz: 'dynamic',
  emulator: 'dynamic',
  'protocol-fuzz': 'protocol',
  protocol: 'protocol',
  heuristic: 'heuristic',
  anomaly: 'heuristic',
};

export const FAMILY_LABEL: Record<string, string> = {
  'static-analysis': 'Static analysis',
  symbolic: 'Symbolic · taint',
  dynamic: 'Dynamic execution',
  protocol: 'Protocol state machine',
  heuristic: 'Behavioural heuristic',
};

export function familyLabel(family: string): string {
  return FAMILY_LABEL[family] ?? family;
}

export function familiesOf(engines: string[]): string[] {
  return [...new Set(engines.map((e) => ENGINE_FAMILY[e] ?? e))];
}

// Same three rules the engine uses, in the same order. Two static scanners are
// NOT corroboration; only independent techniques are.
export function confidenceOf(engines: string[]): Confidence {
  const distinct = new Set(engines).size;
  const families = familiesOf(engines);
  if (families.length >= 2) return 'Confirmed';
  if (distinct >= 2) return 'Likely';
  if (engines.some((e) => e === 'fuzz' || e === 'emulator' || e === 'taint')) return 'Likely';
  return 'Unconfirmed';
}

// Human sentence for the rule that actually fired — the "why" the queue never
// showed. Kept next to the code it describes so the two cannot drift apart.
export function confidenceRule(engines: string[]): string {
  const families = familiesOf(engines);
  if (families.length >= 2) {
    return `Two or more independent techniques agree (${families.map(familyLabel).join(' + ')}). Corroboration holds, so the verdict is Confirmed.`;
  }
  if (new Set(engines).size >= 2) {
    return 'Two engines fired, but both live in the same technique family — the same evidence seen twice. That is Likely, not Confirmed.';
  }
  if (engines.some((e) => e === 'fuzz' || e === 'emulator' || e === 'taint')) {
    return 'A single engine fired, but dynamic or symbolic evidence carries weight alone — Likely, pending a second technique.';
  }
  return 'A single engine fired and no independent technique corroborates it. Unconfirmed: it belongs in triage, not the verdict column.';
}

const SSVC_W: Record<string, number> = { Track: 0, 'Track*': 5, Attend: 10, Act: 15 };

export type PriorityBreakdown = {
  derived: Confidence;
  base: number;
  epssPts: number;
  ssvcPts: number;
  raw: number;
  total: number;
  capped: boolean;
};

// Exact arithmetic of priorityOf, kept step by step so the page can show the
// sum instead of asserting a number.
export function priorityBreakdown(input: {
  engines: string[];
  epss: number | null;
  ssvc: string | null;
}): PriorityBreakdown {
  const derived = confidenceOf(input.engines);
  const base = derived === 'Confirmed' ? 70 : derived === 'Likely' ? 40 : 10;
  const epssPts = Math.min(Math.max(input.epss ?? 0, 0), 1) * 25;
  const ssvcPts = input.ssvc ? (SSVC_W[input.ssvc] ?? 0) : 0;
  const raw = Math.round(base + epssPts + ssvcPts);
  return { derived, base, epssPts, ssvcPts, raw, total: Math.min(100, raw), capped: raw > 100 };
}

// Where a score sits in the response ladder the README describes (critical
// threats are quarantined, low ones are only watched). The page prints the
// band so an analyst can read the number as an action.
export function priorityBand(total: number): { label: string; tone: 'rose' | 'amber' | 'cyan' | 'gray' } {
  if (total >= 81) return { label: 'Act now', tone: 'rose' };
  if (total >= 61) return { label: 'High', tone: 'amber' };
  if (total >= 31) return { label: 'Medium', tone: 'cyan' };
  return { label: 'Monitor', tone: 'gray' };
}
