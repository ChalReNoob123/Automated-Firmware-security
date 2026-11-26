'use client';
import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Badge, Card, Empty, glassGlow } from '../components/ui';
import { apiFetch, getAccess } from '../lib/auth';
import { priority } from '../lib/scoring';
import { fmtUtcDateTime } from '../lib/time';

// Reports: pull the findings queue and export it — Markdown narrative, raw JSON,
// or CycloneDX VEX for downstream tooling. Downloads + printable view included.
type Finding = {
  id: string;
  title: string;
  emb3d: string | null;
  cvss_v4: number | null;
  epss: number | null;
  ssvc: string | null;
  confidence: string;
  corroborating_engines: string[];
  why_flagged: string | null;
  snapshot_ref: string | null;
  created_at: string;
  priority?: number | null; // engine-computed by the API (workers priorityOf)
};

function download(name: string, text: string, type: string) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

function toMarkdown(findings: Finding[]): string {
  const lines = [
    '# SentinelForge Findings Report',
    `_Generated ${fmtUtcDateTime(Date.now())} — ${findings.length} finding(s)_`,
    '',
    '| Priority | Confidence | Title | Engines | EPSS | Snapshot |',
    '|---|---|---|---|---|---|',
  ];
  for (const f of [...findings].sort((a, b) => priority(b) - priority(a))) {
    lines.push(`| ${priority(f)} | ${f.confidence} | ${f.title.replace(/\|/g, '\\|')} | ${(f.corroborating_engines ?? []).join(', ')} | ${f.epss ?? '—'} | ${f.snapshot_ref ?? '—'} |`);
    if (f.why_flagged) lines.push(`> ${f.why_flagged}`);
  }
  return lines.join('\n');
}

function toVex(findings: Finding[]) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: { timestamp: new Date().toISOString(), component: { type: 'firmware', name: 'sentinelforge-fleet', version: 'aggregate' } },
    vulnerabilities: findings.map((f, i) => ({
      'bom-ref': f.id || `finding-${i}`,
      id: f.emb3d || f.id || `finding-${i}`,
      description: f.title,
      analysis: {
        state: f.confidence === 'Confirmed' ? 'exploitable' : 'in_triage',
        detail: [f.why_flagged, f.snapshot_ref ? `repro: ${f.snapshot_ref}` : null].filter(Boolean).join(' — ') || undefined,
      },
      ratings: [
        ...(f.cvss_v4 !== null && f.cvss_v4 !== undefined ? [{ score: f.cvss_v4, method: 'CVSSv4' }] : []),
        ...(f.epss !== null && f.epss !== undefined ? [{ score: Math.round(f.epss * 10 * 10) / 10, method: 'EPSS' }] : []),
      ],
    })),
  };
}

export default function Reports() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [err, setErr] = useState('');

  useEffect(() => {
    (async () => {
      const tok = await getAccess();
      if (!tok) {
        setSignedIn(false);
        return;
      }
      setSignedIn(true);
      try {
        const r = await apiFetch('/v1/findings?limit=500');
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        setFindings(((await r.json()).findings ?? []) as Finding[]);
      } catch (e) {
        setErr((e as Error).message);
      }
    })();
  }, []);

  // Filename stamp stays ISO: it is a sortable machine value, not a label.
  const stamp = new Date().toISOString().slice(0, 10);

  return (
    <motion.div initial={{ opacity: 0, y: 22 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
      <Card style={{ marginTop: 0 }}>
        {signedIn === false ? (
          <div style={{ textAlign: 'center' }}>
            <p style={{ color: '#94a3b8' }}>Sign in to export your queue.</p>
            <a className="sf-btn sf-btn-accent" href="/login">Sign in</a>
          </div>
        ) : findings.length === 0 && !err ? (
          <Empty title="Nothing to export yet" hint="Seed the demo dataset from /dashboard, or file findings from discovery runs." />
        ) : (
          <>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
              <button className="sf-btn sf-btn-accent" onClick={() => download(`sentinelforge-report-${stamp}.md`, toMarkdown(findings), 'text/markdown')}>
                Markdown (.md)
              </button>
              <button className="sf-btn" onClick={() => download(`sentinelforge-findings-${stamp}.json`, JSON.stringify(findings, null, 2), 'application/json')}>
                JSON
              </button>
              <button className="sf-btn" onClick={() => download(`sentinelforge-vex-${stamp}.json`, JSON.stringify(toVex(findings), null, 2), 'application/json')}>
                CycloneDX VEX
              </button>
              <button className="sf-btn" onClick={() => window.print()}>Print / PDF</button>
              <span style={{ marginLeft: 'auto', fontSize: 13, color: '#64748b', alignSelf: 'center' }}>{findings.length} finding(s)</span>
            </div>
            {err && <p style={{ color: '#f87171', fontSize: 13 }}>{err}</p>}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {findings.map((f) => (
                <div key={f.id} className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 10, padding: '10px 14px', fontSize: 13 }}>
                  <b style={{ color: '#fff' }}>{f.title}</b>
                  <div style={{ marginTop: 4, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                    <Badge tone={f.confidence === 'Confirmed' ? 'green' : f.confidence === 'Likely' ? 'amber' : 'gray'}>{f.confidence.toUpperCase()}</Badge>
                    <span style={{ color: '#64748b' }}>{(f.corroborating_engines ?? []).join(' + ')}</span>
                    {f.snapshot_ref && <span style={{ color: '#22d3ee' }}>⎋ {f.snapshot_ref}</span>}
                  </div>
                  {f.why_flagged && <div style={{ color: '#94a3b8', marginTop: 4 }}>{f.why_flagged}</div>}
                </div>
              ))}
            </div>
          </>
        )}
      </Card>
    </motion.div>
  );
}
