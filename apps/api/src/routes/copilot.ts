import { Router } from 'express';
import { z } from 'zod';
import { callLocal, listLocalTools } from '@sentinelforge/mcp-servers';
import { requireAuth } from '../middleware/rbac.js';
import { narrate } from '../intel.js';

// Security Copilot (spec §8): chat grounded in REAL scan/graph data via the MCP
// tool registry (same handlers external agents use over stdio). Template narration
// for now — an LLM composes from {tool outputs + citations} when the model key is
// configured. Read-only: no patches deployed, no devices reconfigured (trust layer).
//
// Dispatch is CONFIDENCE-scored, not first-regex-wins: every intent accumulates
// keyword hits and only a strict winner routes. Near-ties and zero-scores get a
// clarifying reply with clickable options instead of a misrouted answer.
const router = Router();

const DEMO_GRAPH = ['recv -> parse_query', 'parse_query -> strcpy', 'recv -> handle_cmd', 'handle_cmd -> system'].join('\n');

type Citation = { server: string; tool: string };
type Answer = { reply: string; citations: Citation[]; clarify?: { label: string; message: string }[] };

// Optional LLM polish over the template (grounded strictly in tool output;
// silent when unconfigured — narration never blocks or invents).
async function speak(intent: string, reply: string, citations: Citation[]): Promise<Answer> {
  const n = await narrate(intent, reply);
  return n ? { reply: n, citations } : { reply, citations };
}

// Never let one tool failure become a chat 500 — degrade to a partial answer.
async function tool(server: Parameters<typeof callLocal>[0], toolName: string, args: Record<string, unknown> = {}) {
  try {
    const r = await callLocal(server, toolName, args);
    return { ok: true as const, output: r.output };
  } catch (e) {
    return { ok: false as const, error: (e as Error).message };
  }
}

type IntentId = 'epss' | 'fuzz' | 'taint' | 'graph' | 'attacksim' | 'radar' | 'patch' | 'rot' | 'pipeline';
const INTENTS: { id: IntentId; label: string; example: string; patterns: RegExp[] }[] = [
  { id: 'epss', label: 'EPSS score', example: 'EPSS for CVE-2024-3094', patterns: [/cve-\d{4}-\d{4,}/i, /\bepss\b/i] },
  { id: 'fuzz', label: 'Fuzz campaign', example: 'run a fuzz campaign', patterns: [/\bfuzz\w*\b/i, /\bcampaign\b/i, /\bcrash\b/i] },
  { id: 'taint', label: 'Taint analysis', example: 'trace taint to sinks', patterns: [/\btaint\b/i, /symbolic/i, /call.?graph/i, /\bsinks?\b/i] },
  { id: 'graph', label: 'Attack paths', example: 'show attack paths', patterns: [/\bgraph\b/i, /attack.?paths?/i, /attack.?chains?/i, /\bexploit\b/i] },
  { id: 'attacksim', label: 'Attack scenario', example: 'run the Mirai scenario', patterns: [/attack.?sim/i, /scenario/i, /mirai/i, /adversary/i, /emulat/i] },
  { id: 'radar', label: 'N-day radar', example: 'check the N-day radar', patterns: [/radar/i, /n-?day/i, /disclosure/i] },
  { id: 'patch', label: 'Patch check', example: 'how do I verify a patch', patterns: [/\bpatch\b/i, /\bfix\b/i, /verif/i] },
  { id: 'rot', label: 'Secure boot', example: 'secure boot checklist', patterns: [/\brot\b/i, /secure.?boot/i, /\bpsa\b/i, /rollback/i, /\bjtag\b/i, /secure element/i] },
  { id: 'pipeline', label: 'Scanning help', example: 'how do I scan firmware', patterns: [/\bsbom\b/i, /pipeline/i, /\bstages?\b/i, /firmware/i, /\bscan\b/i, /\busb\b/i, /device/i] },
];

function route(message: string): { intent: IntentId } | { clarify: { label: string; message: string }[] } | { none: true } {
  const scored = INTENTS.map((intent) => ({ intent, score: intent.patterns.reduce((n, re) => n + (re.test(message) ? 1 : 0), 0) })).sort((a, b) => b.score - a.score);
  const [best, second] = scored;
  if (best.score === 0) return { none: true };
  if (best.score > (second?.score ?? 0)) return { intent: best.intent.id };
  const options = scored.filter((s) => s.score > 0).slice(0, 3).map((s) => ({ label: s.intent.label, message: s.intent.example }));
  return { clarify: options.length ? options : INTENTS.slice(0, 3).map((s) => ({ label: s.label, message: s.example })) };
}

async function answer(message: string): Promise<Answer> {
  const m = message.toLowerCase();
  if (/^help\b|what can you|capabilit/.test(m)) {
    const tools = listLocalTools()
      .map((s) => `• ${s.server}: ${s.tools.join(', ')}`)
      .join('\n');
    return {
      reply: `I answer from live tool output. Try:\n${INTENTS.map((i) => `• "${i.example}"`).join('\n')}\n\nServers:\n${tools}`,
      citations: [],
    };
  }

  const r = route(message);
  if ('clarify' in r) {
    return {
      reply: 'That could mean a few things — pick one and I\'ll run it against the live engines.',
      citations: [],
      clarify: r.clarify,
    };
  }
  if ('none' in r) {
    return {
      reply: `I'm grounded in live tool output — not general knowledge. Try "help" or one of:\n${INTENTS.map((i) => `• "${i.example}"`).join('\n')}`,
      citations: [],
    };
  }

  switch (r.intent) {
    case 'epss': {
      const cve = /cve-\d{4}-\d{4,}/i.exec(message)?.[0].toUpperCase() ?? '';
      const t = await tool('cve-epss-mcp', 'epss_lookup', { cve });
      if (!t.ok) return { reply: `Couldn't score ${cve || 'that CVE'}: ${t.error}. Check the CVE-YYYY-NNNN format and retry.`, citations: [] };
      const o = t.output as { epss: number | null; source: string; note?: string };
      if (o.epss === null)
        return {
          reply: `${cve}: no EPSS in the local cache (${o.source}). ${o.note ?? ''} Open /radar and paste the affected component to check it against your SBOM.`,
          citations: [{ server: 'cve-epss-mcp', tool: 'epss_lookup' }],
        };
      return speak(
        'epss-lookup',
        `${cve}: EPSS ${o.epss} (source: ${o.source}). Pair it with SSVC decision urgency, then check /radar for SBOM exposure.`,
        [{ server: 'cve-epss-mcp', tool: 'epss_lookup' }]
      );
    }
    case 'fuzz': {
      const t = await tool('fuzz-orchestrator-mcp', 'campaign_run', { seeds: ['GET /', 'GET /admin'], iterations: 500 });
      if (!t.ok) return { reply: `Fuzz campaign failed to start: ${t.error}. Retry, or run the full worker demo (demo-discovery).`, citations: [] };
      const o = t.output as { execs: number; coverage: number[]; crashCount: number; guidance: string; crashes: { reason: string }[] };
      const top = o.crashes.slice(0, 3).map((c, i) => `${i + 1}. ${c.reason}`).join('\n');
      return speak(
        'fuzz-campaign',
        `500-exec campaign (${o.guidance}): ${o.execs} execs, blocks [${o.coverage.join(', ')}], ${o.crashCount} crash(es).${top ? `\nTop crashes:\n${top}` : ''}\nFull campaigns run in the worker pool; crashes auto-capture emulator snapshots for replay.`,
        [{ server: 'fuzz-orchestrator-mcp', tool: 'campaign_run' }]
      );
    }
    case 'taint': {
      const t = await tool('symbolic-exec-mcp', 'trace_taint', { graphText: DEMO_GRAPH });
      if (!t.ok) return { reply: `Taint analysis failed: ${t.error}.`, citations: [] };
      const paths = t.output as { source: string; sink: string; path: string[]; sanitized: boolean }[];
      if (!paths.length) return { reply: 'No source→sink chains in the demo graph — paste a `caller -> callee` graph to analyze your own.', citations: [{ server: 'symbolic-exec-mcp', tool: 'trace_taint' }] };
      const lines = paths.map((p, i) => `${i + 1}. ${p.source} → ${p.sink} via ${p.path.join(' → ')}${p.sanitized ? ' (sanitized — lower priority)' : ''}`).join('\n');
      return speak(
        'taint-analysis',
        `${paths.length} source→sink chain(s) in the demo graph:\n${lines}\nProduction graphs come from Ghidra-headless + angr.`,
        [{ server: 'symbolic-exec-mcp', tool: 'trace_taint' }]
      );
    }
    case 'graph': {
      const t = await tool('graph-query-mcp', 'demo_graph', {});
      if (!t.ok) return { reply: `Attack-graph query failed: ${t.error}.`, citations: [] };
      const o = t.output as { paths: { nodes: string[]; risk: number; hops: number }[] };
      const lines = o.paths.map((p, i) => `${i + 1}. risk ${p.risk} (${p.hops} hops): ${p.nodes.join(' → ')}`).join('\n');
      return speak('attack-paths', `Ranked chains, attacker-cheapest first:\n${lines}`, [{ server: 'graph-query-mcp', tool: 'demo_graph' }]);
    }
    case 'attacksim':
      return { reply: 'Open /attacks and hit Execute: five adversary scenarios (Mirai telnet, BLE bypass, MQTT injection, OTA downgrade, DNS exfil) run live against a fresh twin with snapshots and repro bundles.', citations: [] };
    case 'radar':
      return { reply: 'Open /radar: the N-day feed matches fresh advisories against your SBOM and returns act-now / triage / clear verdicts with twin re-run descriptors.', citations: [] };
    case 'patch':
      return { reply: 'Open /radar and use the patch card: feed it old + new builds and it proves the vulnerable path is gone (or catches a version-string-only "fix").', citations: [] };
    case 'rot':
      return {
        reply: `Root-of-Trust checklist: 1) immutable ROM RoT measuring each stage, 2) anti-rollback fuse + monotonic counter, 3) no JTAG/UART/shell backdoors in boot config, 4) keys in SE/TPM/TrustZone — never raw in flash. The workers verifyRootOfTrust() check maps evidence to PSA readiness levels.`,
        citations: [],
      };
    case 'pipeline':
      return {
        reply: `Pipeline: acquisition → unpack → static+secrets → SBOM/VEX → RoT check → discovery (taint + fuzz, consensus-scored) → ranked chains. Start at /devices: pair over USB, attest, and the twin, lab and attack sim unlock.`,
        citations: [],
      };
  }
}

router.post('/chat', requireAuth, async (req, res) => {
  const p = z.object({ message: z.string().min(1).max(2000) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: 'message required' });
  try {
    res.json(await answer(p.data.message));
  } catch (e) {
    res.status(500).json({ error: 'copilot failed: ' + (e as Error).message });
  }
});

export default router;
