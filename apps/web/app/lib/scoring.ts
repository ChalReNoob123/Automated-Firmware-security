// Shared scoring. Round 14 accuracy rule: the API now returns each finding's
// priority computed by the ENGINE (workers priorityOf — covered by tests), and
// every UI surface consumes that number directly. The local formula below is
// only a fallback for rows that predate it; its constants mirror the engine's
// (Confirmed 70 / Likely 40 / Unconfirmed 10, EPSS 0..1 → +25, SSVC Track 0 /
// Track* 5 / Attend 10 / Act 15, cap 100) so a fallback can never reorder the
// queue differently from the engine.
const SSVC_W: Record<string, number> = { Track: 0, 'Track*': 5, Attend: 10, Act: 15 };

export function priority(f: {
  confidence: string;
  epss: number | null | undefined;
  ssvc?: string | null;
  priority?: number | null;
}): number {
  if (typeof f.priority === 'number') return f.priority; // engine-computed single source
  const base = f.confidence === 'Confirmed' ? 70 : f.confidence === 'Likely' ? 40 : 10;
  const ssvc = f.ssvc ? (SSVC_W[f.ssvc] ?? 0) : 0;
  return Math.min(100, Math.round(base + Math.min(Math.max(f.epss ?? 0, 0), 1) * 25 + ssvc));
}
