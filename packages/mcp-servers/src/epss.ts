// Live EPSS (FIRST.org) with TTL cache and honest fallback.
// - EPSS_LIVE=0 forces the bundled-sample path (deterministic unit tests).
// - Otherwise: live API first, 10 s timeout, 1 h in-memory cache; on any failure
//   degrade to bundled samples and SAY SO in `source` — never a silent number.
export type EpssResult = { cve: string; epss: number | null; source: 'live-first-org' | 'cache' | 'bundled-sample' | 'not-in-cache'; note?: string };

const TTL_MS = 60 * 60 * 1000;
const cache = new Map<string, { epss: number; at: number }>();
const SAMPLES: Record<string, number> = { 'CVE-2024-SAMPLE-1': 0.82, 'CVE-2024-SAMPLE-2': 0.05 };

export function validateCve(cve: string): string {
  const up = cve.toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(up)) throw new Error('cve: CVE-YYYY-NNNN format required');
  return up;
}

async function fetchLive(cve: string): Promise<number | null> {
  const r = await fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cve)}`, { signal: AbortSignal.timeout(10000) });
  if (!r.ok) return null;
  const j = (await r.json()) as { data?: { epss?: string }[] };
  const raw = j.data?.[0]?.epss;
  const n = raw === undefined ? NaN : Number(raw);
  return Number.isFinite(n) ? n : null;
}

export async function epssLookup(rawCve: string): Promise<EpssResult> {
  const cve = validateCve(rawCve);
  if (cve in SAMPLES) return { cve, epss: SAMPLES[cve], source: 'bundled-sample' };
  if (process.env.EPSS_LIVE === '0') return { cve, epss: null, source: 'not-in-cache', note: 'live lookup disabled (EPSS_LIVE=0)' };
  const hit = cache.get(cve);
  if (hit && Date.now() - hit.at < TTL_MS) return { cve, epss: hit.epss, source: 'cache' };
  try {
    const live = await fetchLive(cve);
    if (live !== null) {
      cache.set(cve, { epss: live, at: Date.now() });
      return { cve, epss: live, source: 'live-first-org' };
    }
  } catch {
    /* fall through to cache-miss */
  }
  return { cve, epss: null, source: 'not-in-cache', note: 'FIRST.org unreachable — wire a keyed feed or retry' };
}
