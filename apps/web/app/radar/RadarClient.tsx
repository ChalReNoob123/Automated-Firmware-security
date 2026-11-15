'use client';
import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Card, Badge, Empty, glassGlow } from '../components/ui';
import { apiFetch, getAccess, API_URL } from '../lib/auth';
import { AttestField, SessionChip } from '../components/Gate';

const URGENCY: Record<string, 'rose' | 'amber' | 'green'> = { 'act-now': 'rose', triage: 'amber', clear: 'green' };

type Verdict = { advisoryId: string; exposed: boolean; urgency: string; detail: string; twinReRun: { firmwareRef: string; focus: string } | null };
type DemoOut = { sbom: { name: string; version: string }[]; results: { verdict: Verdict; matches: { component: string; installedVersion: string; inRange: boolean; rangeNote: string }[] }[] };
type PatchOut = { similarity: number; verdict: string; evidence: string[]; removedSinks: string[]; remainingSinks: string[] };

// Browser-safe hex encoding (Node's Buffer does not exist client-side —
// module-scope Buffer.from would crash /radar with "Buffer is not defined").
const toHex = (s: string) => {
  let out = '';
  for (let i = 0; i < s.length; i++) out += s.charCodeAt(i).toString(16).padStart(2, '0');
  return out;
};

const OLD_HEX = toHex('FIRMWARE-v1' + '\0'.repeat(2048));
const NEW_HEX = toHex('FIRMWARE-v2' + '\0'.repeat(2048));
const OLD_TEXT = 'strcpy(dst, src);\npassword = "s3cret"\n';
const FIXED_TEXT = 'strncpy(dst, src, sizeof(dst));\n';

export default function RadarClient() {
  const [feed, setFeed] = useState<DemoOut | null>(null);
  const [feedErr, setFeedErr] = useState('');
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [att, setAtt] = useState('');
  const [patch, setPatch] = useState<PatchOut | null>(null);
  const [patchErr, setPatchErr] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetch(`${API_URL}/v1/radar/demo`, { signal: AbortSignal.timeout(12000) })
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(setFeed)
      .catch((e) => setFeedErr(`Radar feed unreachable: ${(e as Error).message}. Start the API: npm run dev in apps/api.`));
    setAtt(localStorage.getItem('sf_att') ?? '');
    getAccess().then((t) => setSignedIn(!!t));
  }, []);

  const verify = async (fake: boolean) => {
    setBusy(true);
    setPatchErr('');
    setPatch(null);
    try {
      const body = fake
        ? { oldHex: OLD_HEX, newHex: OLD_HEX, oldText: OLD_TEXT, newText: OLD_TEXT, vulnSink: 'strcpy', oldVersion: '1.0', newVersion: '1.1' }
        : { oldHex: OLD_HEX, newHex: NEW_HEX, oldText: OLD_TEXT, newText: FIXED_TEXT, vulnSink: 'strcpy', oldVersion: '1.0', newVersion: '1.1' };
      const attId = att || localStorage.getItem('sf_att') || '';
      if (!attId) throw new Error('Attestation required — register the device at /devices first.');
      const r = await apiFetch('/v1/patch/verify', {
        method: 'POST',
        headers: { 'x-attestation-id': attId },
        body: JSON.stringify(body),
      });
      const j = await r.json();
      if (r.status === 401) {
        setSignedIn(false);
        throw new Error('Session expired — sign in at /login, then retry.');
      }
      if (!r.ok) throw new Error((j as { error?: string }).error ?? `HTTP ${r.status}`);
      setPatch(j as PatchOut);
    } catch (e) {
      setPatchErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <motion.div initial={{ opacity: 0, y: 22 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
        <Card style={{ marginTop: 0 }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 6 }}>
            <h2 style={{ margin: 0 }}>N-day radar</h2>
            <Badge tone="violet">LIVE MATCHING</Badge>
          </div>
          <p style={{ color: '#94a3b8', fontSize: 13.5, margin: '0 0 12px' }}>
            Canned disclosure feed matched against the demo SBOM ({feed?.sbom.map((c) => `${c.name}@${c.version}`).join(', ') ?? 'loading…'}).
            Production polls NVD 2.0 continuously and re-queues the twin per verdict.
          </p>
          {!feed && !feedErr && <Empty title="Contacting radar…" hint="Start the API: npm run dev in apps/api." />}
          {feedErr && <p role="alert" style={{ color: '#f87171', fontSize: 13 }}>{feedErr}</p>}
          {feed?.results.map(({ verdict, matches }) => (
            <div key={verdict.advisoryId} className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 12, padding: '12px 16px', marginBottom: 10, borderColor: verdict.exposed ? 'rgba(244,63,94,0.35)' : undefined }}>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                <code style={{ color: '#fff' }}>{verdict.advisoryId}</code>
                <Badge tone={URGENCY[verdict.urgency] ?? 'gray'}>{verdict.urgency.toUpperCase()}</Badge>
              </div>
              <div style={{ fontSize: 13.5, marginTop: 6 }}>{verdict.detail}</div>
              {matches.map((m) => (
                <div key={m.component} style={{ fontSize: 12.5, color: '#94a3b8', marginTop: 2 }}>
                  {m.component}@{m.installedVersion} — {m.rangeNote}
                </div>
              ))}
              {verdict.twinReRun && <div style={{ fontSize: 12.5, color: '#22d3ee', marginTop: 4 }}>↻ twin re-run queued: focus {verdict.twinReRun.focus}</div>}
            </div>
          ))}
        </Card>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 22 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.1 }}>
        <Card style={{ marginTop: 0 }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 6 }}>
            <h2 style={{ margin: 0 }}>Patch verification</h2>
            <Badge tone="cyan">PROOF, NOT LABELS</Badge>
          </div>
          <p style={{ color: '#94a3b8', fontSize: 13.5, margin: '0 0 12px' }}>
            Diff a rebuild against its prior image: is the vulnerable path gone, or did only the
            version string change? Try a real fix — then a fake one.
          </p>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 12, alignItems: 'center' }}>
            <SessionChip signedIn={signedIn} cta="Sign in to verify" />
            <AttestField att={att} onChange={setAtt} />
            <button
              className="sf-btn sf-btn-accent"
              onClick={() => void verify(false)}
              disabled={busy || signedIn !== true}
              title={signedIn !== true && !busy ? 'Verification runs against your account — sign in first' : undefined}
            >
              Verify real fix
            </button>
            <button
              className="sf-btn"
              onClick={() => void verify(true)}
              disabled={busy || signedIn !== true}
              title={signedIn !== true && !busy ? 'Verification runs against your account — sign in first' : undefined}
            >
              Catch a fake patch
            </button>
          </div>
          {patchErr && <p role="alert" style={{ color: '#f87171', fontSize: 13 }}>{patchErr}</p>}
          {patch && (
            <div className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 12, padding: '12px 16px', borderColor: patch.verdict === 'patched' ? 'rgba(52,211,153,0.4)' : 'rgba(244,63,94,0.4)' }}>
              <Badge tone={patch.verdict === 'patched' ? 'green' : 'rose'}>{String(patch.verdict).toUpperCase()}</Badge>
              <span style={{ marginLeft: 10, fontSize: 13, color: '#94a3b8' }}>similarity {patch.similarity}</span>
              <ul style={{ fontSize: 13.5, margin: '8px 0 0', paddingLeft: 18 }}>
                {patch.evidence.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            </div>
          )}
        </Card>
      </motion.div>
    </div>
  );
}
