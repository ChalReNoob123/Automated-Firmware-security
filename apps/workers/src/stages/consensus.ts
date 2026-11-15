// Multi-engine consensus & confidence scoring (spec: solves the false-positive problem).
// A finding is "Confirmed" ONLY when ≥2 independent engines corroborate it
// (e.g. taint path AND fuzzer crash at the same sink). Single-engine hits stay
// "Unconfirmed — needs triage" with distinct treatment. Priority layers CVSS-style
// severity with EPSS (exploitation probability) and SSVC (decision urgency) so
// analysts work the queue in exploitability order, not fuzzer-output order.

export type EngineId = 'static' | 'secrets' | 'taint' | 'fuzz' | 'emulator' | 'yara';
export type Confidence = 'Confirmed' | 'Likely' | 'Unconfirmed';
export type SsvcDecision = 'Track' | 'Track*' | 'Attend' | 'Act';

// ENGINE FAMILIES — corroboration must come from INDEPENDENT analysis techniques.
// Two engines in the same family (e.g. two static scanners) are not evidence of
// each other; counting them as confirmation is the classic false-positive bug.
//   static-analysis → pattern/regex/string analysis
//   symbolic       → taint & constraint reasoning
//   dynamic        → execution (fuzzing, emulation)
//   protocol       → state-machine fuzzing
//   heuristic      → anomaly/behavioural models
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

export function familiesOf(engines: string[]): string[] {
  return [...new Set(engines.map((e) => ENGINE_FAMILY[e] ?? e))];
}

export type Candidate = {
  key: string; // correlation key, e.g. sink name or crash site — same key = same underlying bug
  title: string;
  engines: EngineId[];
  sink?: string;
  epss?: number; // 0..1, real-world exploitation probability (cve-epss-mcp in Module 7+)
  ssvc?: SsvcDecision; // decision urgency (stakeholder-specific triage input)
  why: string[]; // explainability trace: one line per corroborating engine
  snapshotRef?: string | null; // emulator snapshot + input trace for repro
};

export type ScoredFinding = Candidate & { confidence: Confidence; priority: number; families: string[] };

export function confidenceOf(engines: EngineId[] | string[]): Confidence {
  const distinct = new Set(engines).size;
  const families = familiesOf(engines as string[]);
  // Corroboration requires independent techniques, not just two engines.
  if (families.length >= 2) return 'Confirmed';
  if (distinct >= 2) return 'Likely'; // same family, two tools — weaker evidence
  if (engines.some((e) => e === 'fuzz' || e === 'emulator' || e === 'taint')) return 'Likely';
  return 'Unconfirmed';
}

const SSVC_W: Record<SsvcDecision, number> = { Track: 0, 'Track*': 5, Attend: 10, Act: 15 };

export function priorityOf(
  c: Pick<Candidate, 'epss' | 'ssvc'> & { engines: EngineId[] | string[] },
): number {
  const conf = confidenceOf(c.engines);
  const base = conf === 'Confirmed' ? 70 : conf === 'Likely' ? 40 : 10;
  const epss = Math.min(Math.max(c.epss ?? 0, 0), 1) * 25;
  const ssvc = c.ssvc ? SSVC_W[c.ssvc] : 0;
  return Math.min(100, Math.round(base + epss + ssvc));
}

// Correlate raw engine outputs into deduplicated, scored findings.
export function correlate(inputs: {
  taintPaths: { sink: string; path: string[]; sanitized: boolean }[];
  fuzzCrashes: { reason: string; inputHex: string }[];
  sinks: { sink: string; count: number }[];
  secrets?: { ruleId: string }[];
  snapshotRef?: string | null;
}): ScoredFinding[] {
  const byKey = new Map<string, Candidate>();

  const add = (key: string, title: string, engine: EngineId, why: string, sink?: string) => {
    const cur = byKey.get(key);
    if (cur) {
      if (!cur.engines.includes(engine)) cur.engines.push(engine);
      cur.why.push(why);
    } else byKey.set(key, { key, title, engines: [engine], sink, why: [why], snapshotRef: inputs.snapshotRef ?? null });
  };
  // Attach an explainability note to an EXISTING candidate without adding an
  // engine. Accuracy rule: a taint path that PASSES A SANITIZER is not
  // corroborating evidence — the flow is provably not exploitable as-is, so
  // counting it toward 'Confirmed' manufactured false positives (the classic
  // "confirmed but actually mitigated" queue-poisoning bug). The trace is
  // still recorded on the finding for the analyst.
  const note = (key: string, why: string) => {
    byKey.get(key)?.why.push(why);
  };

  for (const s of inputs.sinks)
    add(`sink:${s.sink}`, `Dangerous sink ${s.sink} present`, 'static', `static scan: ${s.count} reference(s)`, s.sink);
  for (const t of inputs.taintPaths) {
    if (t.sanitized) {
      note(`sink:${t.sink}`, `taint path ${t.path.join(' → ')} (PASSES SANITIZER — not corroborating)`);
      continue;
    }
    add(`sink:${t.sink}`, `Tainted input reaches ${t.sink}`, 'taint', `taint path ${t.path.join(' → ')}`, t.sink);
  }
  for (const f of inputs.fuzzCrashes) {
    const sink = /strcpy|strcat|sprintf|gets|memcpy|system/i.exec(f.reason)?.[0]?.toLowerCase();
    add(sink ? `sink:${sink}` : `crash:${f.reason.slice(0, 48)}`, `Fuzzer crash: ${f.reason}`, 'fuzz', `crash at exec input ${f.inputHex.slice(0, 32)}…`, sink);
  }
  for (const sec of inputs.secrets ?? []) add(`secret:${sec.ruleId}`, `Exposed secret: ${sec.ruleId}`, 'secrets', `secret rule '${sec.ruleId}' matched in image`);

  return [...byKey.values()]
    .map((c) => {
      const families = familiesOf(c.engines);
      return { ...c, families, confidence: confidenceOf(c.engines), priority: priorityOf(c) };
    })
    .sort((a, b) => b.priority - a.priority || b.families.length - a.families.length);
}
