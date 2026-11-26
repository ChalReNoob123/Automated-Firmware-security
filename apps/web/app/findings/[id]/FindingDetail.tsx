'use client';
import { useEffect, useState } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { Badge, Card, Code, Empty, glassGlow } from '../../components/ui';
import { apiFetch, getAccess } from '../../lib/auth';
import { confidenceOf, confidenceRule, familiesOf, familyLabel, priorityBand, priorityBreakdown, type Confidence } from '../../lib/engines';
import { fmtUtcDateTime } from '../../lib/time';

// Round 33 — the evidence chain behind one verdict.
//
// The queue only ever showed {title, confidence, priority}. Everything that
// PRODUCED those three numbers was already in the API and invisible: which
// engines fired, which technique families they belong to, the rule that set the
// confidence, the exact priority arithmetic, and the snapshot the finding can be
// replayed from. This view reconstructs it, and is deliberately explicit when
// the stored verdict and the engine's own rule disagree — that mismatch is a
// data-integrity signal an analyst should see, not something to paper over.

type Finding = {
  id: string;
  firmware_id: string | null;
  title: string;
  emb3d: string | null;
  cvss_v4: number | null;
  epss: number | null;
  ssvc: string | null;
  confidence: Confidence;
  corroborating_engines: string[];
  why_flagged: string | null;
  snapshot_ref: string | null;
  created_at: string;
  priority?: number | null;
};

const MONO = 'ui-monospace, Menlo, Consolas, monospace';
const EASE = [0.22, 1, 0.36, 1] as const;
const CONF_TONE: Record<Confidence, 'green' | 'amber' | 'gray'> = {
  Confirmed: 'green',
  Likely: 'amber',
  Unconfirmed: 'gray',
};


function SectionTitle({ tone, children }: { tone: string; children: React.ReactNode }) {
  return <h3 style={{ margin: '0 0 10px', fontSize: 13, letterSpacing: 2, color: tone }}>{children}</h3>;
}

function ContributionRow({ label, detail, pts, color }: { label: string; detail: string; pts: number; color: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, padding: '7px 0', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
      <span style={{ fontSize: 12.5, color: '#cbd5e1', minWidth: 132 }}>{label}</span>
      <span style={{ fontSize: 12, color: '#64748b', fontFamily: MONO, flex: 1 }}>{detail}</span>
      <b style={{ fontSize: 15, color, fontFamily: MONO }}>+{Number.isInteger(pts) ? pts : pts.toFixed(1)}</b>
    </div>
  );
}

export default function FindingDetail({ id }: { id: string }) {
  const reduced = useReducedMotion() ?? false;
  const [state, setState] = useState<'loading' | 'ready' | 'signed-out' | 'missing' | 'error'>('loading');
  const [finding, setFinding] = useState<Finding | null>(null);
  const [err, setErr] = useState('');

  useEffect(() => {
    let live = true;
    void (async () => {
      try {
        const tok = await getAccess();
        if (!tok) {
          if (live) setState('signed-out');
          return;
        }
        const r = await apiFetch(`/v1/findings/${encodeURIComponent(id)}`);
        if (r.status === 401) return void (live && setState('signed-out'));
        if (r.status === 404) return void (live && setState('missing'));
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const j = (await r.json()) as Finding;
        if (live) {
          setFinding(j);
          setState('ready');
        }
      } catch (e) {
        if (live) {
          setErr((e as Error).message);
          setState('error');
        }
      }
    })();
    return () => {
      live = false;
    };
  }, [id]);

  if (state === 'loading') {
    return (
      <Card style={{ marginTop: 0 }}>
        <p style={{ color: '#64748b', fontSize: 13, letterSpacing: 2, fontFamily: MONO }}>RECONSTRUCTING EVIDENCE CHAIN…</p>
      </Card>
    );
  }
  if (state === 'signed-out') {
    return (
      <Card style={{ marginTop: 0 }}>
        <Empty title="Sign in to open the evidence" hint="Every verdict is attributed; the reasoning is scoped to your org." />
        <div style={{ marginTop: 14 }}>
          <a className="sf-btn sf-btn-accent" href="/login">Sign in</a>
        </div>
      </Card>
    );
  }
  if (state === 'missing') {
    return (
      <Card style={{ marginTop: 0 }}>
        <Empty
          title="No such finding in this workspace"
          hint="It may belong to another org, or the row was deleted. The queue is authoritative."
        />
        <div style={{ marginTop: 14 }}>
          <a className="sf-btn" href="/dashboard">Back to the queue</a>
        </div>
      </Card>
    );
  }
  if (state === 'error' || !finding) {
    return (
      <Card style={{ marginTop: 0 }}>
        <Empty title="Could not load the evidence" hint={err || 'The API answered with an error.'} />
        <div style={{ marginTop: 14 }}>
          <a className="sf-btn" href="/dashboard">Back to the queue</a>
        </div>
      </Card>
    );
  }

  const f = finding;
  const engines = f.corroborating_engines ?? [];
  const families = familiesOf(engines);
  const derived = confidenceOf(engines);
  const b = priorityBreakdown({ engines, epss: f.epss, ssvc: f.ssvc });
  const total = typeof f.priority === 'number' ? f.priority : b.total;
  const band = priorityBand(total);
  const lines = f.why_flagged ? f.why_flagged.split(/;\s*/).filter(Boolean) : [];
  // The API stores one flat reasoning string; it is only attributable to an
  // engine when the counts line up (correlate() emits one line per engine).
  // Anything else is shown as an unattributed trace instead of guessed at.
  const aligned = lines.length > 0 && lines.length === engines.length;
  const mismatch = f.confidence !== derived;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* verdict header */}
      <Card style={{ marginTop: 0 }}>
        <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', alignItems: 'flex-start' }}>
          <div style={{ flex: '1 1 420px', minWidth: 0 }}>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 12 }}>
              <Badge tone={CONF_TONE[f.confidence] ?? 'gray'}>{f.confidence.toUpperCase()}</Badge>
              <Badge tone={band.tone}>{band.label.toUpperCase()}</Badge>
              {f.emb3d && <Badge tone="violet">{f.emb3d}</Badge>}
            </div>
            <h2 style={{ margin: '0 0 12px', fontSize: 'clamp(22px, 3vw, 32px)', lineHeight: 1.2, letterSpacing: -0.6, color: '#f1f5f9' }}>
              {f.title}
            </h2>
            <div style={{ display: 'flex', gap: 18, flexWrap: 'wrap', fontSize: 12.5, color: '#94a3b8', fontFamily: MONO }}>
              <span>
                ID <b style={{ color: '#e2e8f0' }}>{f.id.slice(0, 8)}</b>
              </span>
              {f.firmware_id && (
                <span>
                  FW <b style={{ color: '#e2e8f0' }}>{f.firmware_id}</b>
                </span>
              )}
              <span>
                RAISED <b style={{ color: '#e2e8f0' }}>{fmtUtcDateTime(f.created_at)}</b>
              </span>
            </div>
          </div>
          <div style={{ flex: '0 0 auto', minWidth: 150, textAlign: 'right' }}>
            <div style={{ fontSize: 11, letterSpacing: 2, color: '#64748b' }}>PRIORITY</div>
            <div className="sf-gradient-text" style={{ fontSize: 58, fontWeight: 800, lineHeight: 1, letterSpacing: -2 }}>{total}</div>
            <div style={{ fontSize: 11, color: '#64748b', fontFamily: MONO, marginTop: 4 }}>of 100 · {band.label.toLowerCase()}</div>
          </div>
        </div>
      </Card>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(330px, 1fr))', gap: 16 }}>
        {/* priority arithmetic */}
        <Card style={{ marginTop: 0 }}>
          <SectionTitle tone="#22d3ee">PRIORITY ARITHMETIC</SectionTitle>
          <p style={{ color: '#94a3b8', fontSize: 12.5, lineHeight: 1.6, margin: '0 0 6px' }}>
            The score the queue ranks by, decomposed. Base is set by the corroboration rule; EPSS and SSVC only add.
          </p>
          <ContributionRow label="Confidence base" detail={`${derived.toLowerCase()} verdict`} pts={b.base} color="#a5f3fc" />
          <ContributionRow
            label="EPSS × 25"
            detail={f.epss == null ? 'no EPSS published' : `EPSS ${f.epss} → ${(b.epssPts).toFixed(1)} pts`}
            pts={b.epssPts}
            color="#d8b4fe"
          />
          <ContributionRow
            label="SSVC weight"
            detail={f.ssvc ? `${f.ssvc} decision` : 'no SSVC decision'}
            pts={b.ssvcPts}
            color="#fcd34d"
          />
          <div style={{ display: 'flex', height: 8, borderRadius: 4, overflow: 'hidden', background: 'rgba(255,255,255,0.07)', margin: '14px 0 10px' }}>
            <span style={{ width: `${Math.min(100, b.base)}%`, background: '#0891b2' }} />
            <span style={{ width: `${Math.min(100 - Math.min(100, b.base), b.epssPts)}%`, background: '#a855f7' }} />
            <span style={{ width: `${Math.min(100 - Math.min(100, b.base + b.epssPts), b.ssvcPts)}%`, background: '#f59e0b' }} />
          </div>
          <p style={{ fontFamily: MONO, fontSize: 12, color: '#cbd5e1', margin: 0, lineHeight: 1.7 }}>
            min(100, round({b.base} + {b.epssPts.toFixed(1)} + {b.ssvcPts})) = <b style={{ color: '#fff' }}>{total}</b>
            {b.capped && <span style={{ color: '#fcd34d' }}> — capped at 100</span>}
          </p>
          {typeof f.priority === 'number' && f.priority !== b.total && (
            <p style={{ fontSize: 12, color: '#fcd34d', marginBottom: 0 }}>
              API reports {f.priority}; the decomposition lands on {b.total}. The API number wins for ranking.
            </p>
          )}
          <div style={{ display: 'flex', gap: 18, marginTop: 12, flexWrap: 'wrap', fontFamily: MONO, fontSize: 12, color: '#94a3b8' }}>
            <span>CVSS v4 <b style={{ color: '#e2e8f0' }}>{f.cvss_v4 ?? '—'}</b></span>
            <span>EPSS <b style={{ color: '#e2e8f0' }}>{f.epss ?? '—'}</b></span>
            <span>SSVC <b style={{ color: '#e2e8f0' }}>{f.ssvc ?? '—'}</b></span>
          </div>
        </Card>

        {/* confidence gate */}
        <Card style={{ marginTop: 0 }}>
          <SectionTitle tone="#a855f7">CONFIDENCE GATE</SectionTitle>
          <p style={{ color: '#94a3b8', fontSize: 12.5, lineHeight: 1.6, margin: '0 0 10px' }}>
            Corroboration counts independent techniques, not engine names. Two scanners in one family are the same
            evidence seen twice.
          </p>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
            {families.length ? (
              families.map((fam) => (
                <Badge key={fam} tone={families.length >= 2 ? 'green' : 'gray'}>
                  {familyLabel(fam)}
                </Badge>
              ))
            ) : (
              <Badge tone="gray">NO ENGINES RECORDED</Badge>
            )}
          </div>
          <div style={{ fontFamily: MONO, fontSize: 12, color: '#94a3b8', marginBottom: 8 }}>
            {families.length} famil{families.length === 1 ? 'y' : 'ies'} · {new Set(engines).size} engine
            {new Set(engines).size === 1 ? '' : 's'}
          </div>
          <p style={{ fontSize: 13.5, lineHeight: 1.6, color: '#cbd5e1', margin: '0 0 10px' }}>{confidenceRule(engines)}</p>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            <span style={{ color: '#64748b' }}>Rule verdict</span>
            <Badge tone={CONF_TONE[derived]}>{derived.toUpperCase()}</Badge>
          </div>
          {mismatch && (
            <p style={{ marginTop: 10, marginBottom: 0, fontSize: 12.5, color: '#fcd34d', lineHeight: 1.55 }}>
              Stored verdict is <b>{f.confidence}</b>, but these engines satisfy the <b>{derived}</b> rule. Treat the
              stored badge as unverified until the engines are re-run.
            </p>
          )}
        </Card>
      </div>

      {/* corroboration timeline */}
      <Card style={{ marginTop: 0 }}>
        <SectionTitle tone="#22d3ee">CORROBORATION TIMELINE</SectionTitle>
        <p style={{ color: '#94a3b8', fontSize: 12.5, lineHeight: 1.6, margin: '0 0 18px' }}>
          Each node is an engine that produced evidence for this finding, in the order recorded. The gate at the end is
          the rule that turned them into a verdict. Per-engine timestamps are not persisted, so this is evidence order,
          not wall-clock.
        </p>
        <div style={{ position: 'relative', paddingLeft: 34 }}>
          <div
            aria-hidden
            style={{ position: 'absolute', left: 10, top: 8, bottom: 8, width: 1, background: 'linear-gradient(180deg, rgba(34,211,238,0.5), rgba(168,85,247,0.5))' }}
          />
          {engines.map((e, i) => (
            <motion.div
              key={`${e}-${i}`}
              initial={reduced ? false : { opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={reduced ? undefined : { delay: 0.06 * i, duration: 0.5, ease: EASE }}
              style={{ position: 'relative', paddingBottom: 14 }}
            >
              <span
                aria-hidden
                style={{ position: 'absolute', left: -30, top: 16, width: 11, height: 11, borderRadius: '50%', background: '#22d3ee', boxShadow: '0 0 0 3px rgba(34,211,238,0.15)' }}
              />
              <div className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 12, padding: '12px 14px' }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  <span style={{ fontFamily: MONO, fontSize: 11, letterSpacing: 1.5, color: '#64748b' }}>
                    ENGINE {String(i + 1).padStart(2, '0')}
                  </span>
                  <Badge tone="gray">{familyLabel(familiesOf([e])[0] ?? e)}</Badge>
                </div>
                <div style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0', marginTop: 4, fontFamily: MONO }}>{e}</div>
                {aligned && (
                  <p style={{ margin: '6px 0 0', fontSize: 13, lineHeight: 1.55, color: '#94a3b8' }}>{lines[i]}</p>
                )}
              </div>
            </motion.div>
          ))}
          <motion.div
            initial={reduced ? false : { opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={reduced ? undefined : { delay: 0.06 * engines.length, duration: 0.5, ease: EASE }}
            style={{ position: 'relative' }}
          >
            <span
              aria-hidden
              style={{ position: 'absolute', left: -30, top: 16, width: 11, height: 11, borderRadius: '50%', background: '#a855f7', boxShadow: '0 0 0 3px rgba(168,85,247,0.18)' }}
            />
            <div style={{ borderRadius: 12, padding: '12px 14px', border: '1px solid rgba(168,85,247,0.35)', background: 'rgba(168,85,247,0.07)' }}>
              <div style={{ fontFamily: MONO, fontSize: 11, letterSpacing: 1.5, color: '#d8b4fe' }}>CONSENSUS GATE</div>
              <div style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0', marginTop: 4 }}>
                {families.length} independent famil{families.length === 1 ? 'y' : 'ies'} → {derived}
              </div>
              <p style={{ margin: '6px 0 0', fontSize: 13, lineHeight: 1.55, color: '#cbd5e1' }}>{confidenceRule(engines)}</p>
            </div>
          </motion.div>
        </div>
      </Card>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(330px, 1fr))', gap: 16 }}>
        {/* reasoning */}
        <Card style={{ marginTop: 0 }}>
          <SectionTitle tone="#fcd34d">WHY IT WAS FLAGGED</SectionTitle>
          {lines.length ? (
            <>
              <ol style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
                {lines.map((l, i) => (
                  <li key={i} style={{ display: 'flex', gap: 10 }}>
                    <span style={{ fontFamily: MONO, fontSize: 11.5, color: '#22d3ee', paddingTop: 3 }}>
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <span style={{ fontSize: 13.5, lineHeight: 1.6, color: '#cbd5e1' }}>{l}</span>
                  </li>
                ))}
              </ol>
              <details style={{ marginTop: 14 }}>
                <summary style={{ cursor: 'pointer', fontSize: 12, color: '#64748b', letterSpacing: 1.5 }}>RAW TRACE AS STORED</summary>
                <pre style={{ whiteSpace: 'pre-wrap', fontFamily: MONO, fontSize: 12, color: '#94a3b8', margin: '8px 0 0', lineHeight: 1.6 }}>
                  {f.why_flagged}
                </pre>
              </details>
              <p style={{ fontSize: 11.5, color: '#64748b', margin: '12px 0 0', lineHeight: 1.6 }}>
                {aligned
                  ? 'The trace is stored in engine order, so each line is attributed to the engine above.'
                  : 'Per-engine attribution is not persisted for this finding, so the trace is shown unattributed.'}
              </p>
            </>
          ) : (
            <Empty title="No reasoning recorded" hint="This row predates explainability traces — only the verdict is stored." />
          )}
        </Card>

        {/* repro */}
        <Card style={{ marginTop: 0 }}>
          <SectionTitle tone="#f43f5e">REPRODUCE IT</SectionTitle>
          {f.snapshot_ref ? (
            <>
              <p style={{ fontSize: 12.5, color: '#94a3b8', lineHeight: 1.6, margin: '0 0 10px' }}>
                The finding carries a twin snapshot plus the exact input trace. Replaying it steps the same inputs back
                through the session and reports MATCH or DIVERGED.
              </p>
              <div style={{ marginBottom: 14 }}>
                <Code>{f.snapshot_ref}</Code>
              </div>
              <a
                className="sf-btn sf-btn-accent"
                href={`/emulator?snapshot=${encodeURIComponent(f.snapshot_ref)}&finding=${encodeURIComponent(f.id)}`}
              >
                Replay in the twin
              </a>
              <p style={{ fontSize: 11.5, color: '#64748b', margin: '12px 0 0', lineHeight: 1.6 }}>
                Needs a signed-in session and the twin that captured it — snapshot ids are per session.
              </p>
            </>
          ) : (
            <Empty
              title="No repro bundle attached"
              hint="Snapshot-free findings can be re-derived by re-running the engine on the same firmware build."
            />
          )}
          <div style={{ display: 'flex', gap: 10, marginTop: 18, flexWrap: 'wrap' }}>
            <a className="sf-btn" href="/dashboard">Back to the queue</a>
            <a className="sf-btn" href="/reports">Export verdicts</a>
          </div>
        </Card>
      </div>
    </div>
  );
}
