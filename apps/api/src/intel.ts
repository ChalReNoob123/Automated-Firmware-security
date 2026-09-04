import { parseNvd, type CveAdvisory } from '@sentinelforge/workers';

// Live intelligence wiring (all best-effort with honest fallbacks):
// - NVD 2.0 poller (optional NVD_API_KEY raises the rate limit 5→50 req/30s)
// - LLM narration for Copilot (any OpenAI-compatible endpoint via LLM_API_URL/KEY)

type FeedStatus = { lastPollAt: string | null; lastCount: number; lastError: string | null; source: string };
const status: FeedStatus = { lastPollAt: null, lastCount: 0, lastError: null, source: 'not-polled' };

export function feedStatus(): FeedStatus {
  return { ...status };
}

// Poll NVD for CVEs modified since `since` (ISO). NVD mandates BOTH bounds with
// a ≤120-day window — we always send lastModEndDate=now and clamp the range.
export async function pollNvd(since?: string): Promise<{ advisories: CveAdvisory[]; total: number }> {
  const end = Date.now();
  const start = since ? Date.parse(since) : end - 24 * 60 * 60 * 1000;
  if (!Number.isFinite(start)) throw new Error('since: ISO timestamp required');
  const clamped = Math.max(start, end - 120 * 24 * 60 * 60 * 1000);
  const fmt = (t: number) => new Date(t).toISOString().slice(0, 23);
  const url =
    `https://services.nvd.nist.gov/rest/json/cves/2.0` +
    `?lastModStartDate=${encodeURIComponent(fmt(clamped))}&lastModEndDate=${encodeURIComponent(fmt(end))}&resultsPerPage=50`;
  const headers: Record<string, string> = {};
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;
  try {
    const r = await fetch(url, { headers, signal: AbortSignal.timeout(20000) });
    if (r.status === 403 || r.status === 429) throw new Error(`NVD throttled (HTTP ${r.status}) — set NVD_API_KEY or retry later`);
    if (!r.ok) throw new Error(`NVD HTTP ${r.status}`);
    const j = (await r.json()) as { totalResults?: number; vulnerabilities?: { cve: Record<string, unknown> }[] };
    const items = (j.vulnerabilities ?? []).map((v) => v.cve);
    const advisories = parseNvd(items as Parameters<typeof parseNvd>[0]);
    status.lastPollAt = new Date().toISOString();
    status.lastCount = advisories.length;
    status.lastError = null;
    status.source = 'nvd-api';
    return { advisories, total: j.totalResults ?? advisories.length };
  } catch (e) {
    status.lastError = (e as Error).message;
    throw e;
  }
}

// Optional LLM narration: rewrites the templated copilot reply grounded STRICTLY
// in the supplied tool summary. Returns null when unconfigured or on any failure
// (caller falls back to the template — narration never blocks answers).
export async function narrate(intent: string, toolSummary: string): Promise<string | null> {
  const base = process.env.LLM_API_URL;
  const key = process.env.LLM_API_KEY;
  if (!base || !key) return null;
  try {
    const r = await fetch(`${base.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
      signal: AbortSignal.timeout(15000),
      body: JSON.stringify({
        model: process.env.LLM_MODEL ?? 'gpt-4o-mini',
        temperature: 0.2,
        max_tokens: 400,
        messages: [
          { role: 'system', content: 'You narrate IoT security tool output. Use ONLY the provided tool data — never invent CVEs, paths, or numbers. Keep citations intact.' },
          { role: 'user', content: `Intent: ${intent}\nTool output:\n${toolSummary.slice(0, 4000)}` },
        ],
      }),
    });
    if (!r.ok) return null;
    const j = (await r.json()) as { choices?: { message?: { content?: string } }[] };
    const text = j.choices?.[0]?.message?.content?.trim();
    return text || null;
  } catch {
    return null;
  }
}
