'use client';
import { useEffect, useRef, useState } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { Badge, Card, Code, glassGlow } from './components/ui';
import { apiFetch, getAccess } from './lib/auth';

// Round 33 — firmware intake.
//
// This is the first surface in the product where bytes from an actual target
// device enter the system. Upload posts the raw image (octet-stream, not base64
// JSON), then queues a real pipeline run over it: acquisition → unpack →
// strings-based static → SBOM. Findings produced by that run are persisted and
// each one links straight to its evidence page.
//
// What this deliberately does NOT do: pretend to fuzz the image. Discovery and
// fuzzing need a call graph or a harness; running the demo harness against a
// real image would emit invented crashes. Those stages stay limited to the
// labeled demo profile, and the copy here says so.

type Device = { id: string; name: string; transport: string };
type RunFinding = { id: string; title: string; confidence: string; priority: number };
type RunDoc = {
  status: 'queued' | 'running' | 'done' | 'failed';
  error?: string;
  findingsCount?: number;
  findings?: RunFinding[];
  removed?: string[];
  artifacts?: {
    elf?: { valid: boolean; machine?: string; bits?: number; endian?: string };
    gzipMembers?: number;
    components?: number;
    sha256?: string;
  };
  stageStatus?: Record<string, string>;
};

const MAX_BYTES = 16 * 1024 * 1024;
const POLL_MS = 500;
const POLL_TRIES = 90;

const human = (n: number) => (n >= 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(2)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);
const CONF_TONE: Record<string, 'green' | 'amber' | 'gray'> = { Confirmed: 'green', Likely: 'amber', Unconfirmed: 'gray' };

export default function FirmwareIntake() {
  const reduced = useReducedMotion() ?? false;
  const fileRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [version, setVersion] = useState('');
  const [devices, setDevices] = useState<Device[]>([]);
  const [deviceId, setDeviceId] = useState('');
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState('');
  const [err, setErr] = useState('');
  const [result, setResult] = useState<{ firmwareId: string; sha256: string; bytes: number; run?: RunDoc } | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const tok = await getAccess();
        if (!tok) return;
        const r = await apiFetch('/v1/devices');
        if (!r.ok) return;
        const j = (await r.json()) as { devices?: Device[] };
        setDevices(j.devices ?? []);
      } catch {
        /* no device list — the upload still works unattributed to a target */
      }
    })();
  }, []);

  const pick = (f: File | null) => {
    setErr('');
    setResult(null);
    if (!f) {
      setFile(null);
      return;
    }
    if (f.size === 0) return setErr('That file is empty.');
    if (f.size > MAX_BYTES) return setErr(`Image is ${human(f.size)} — the intake cap is 16 MB.`);
    setFile(f);
    // sensible default version from the filename: vendor-1.4.2.bin → vendor-1.4.2
    setVersion((v) => v || f.name.replace(/\.[a-z0-9]{1,8}$/i, '').slice(0, 64));
  };

  const analyse = async () => {
    if (!file) return;
    setBusy(true);
    setErr('');
    setResult(null);
    setPhase('uploading');
    try {
      const att = localStorage.getItem('sf_att') ?? '';
      if (!att) throw new Error('Attestation required — register and attest the target at /devices first.');
      const buf = await file.arrayBuffer();
      const qs = new URLSearchParams({ version: version.trim() || 'unspecified' });
      if (deviceId) qs.set('deviceId', deviceId);
      const up = await apiFetch(`/v1/firmware?${qs.toString()}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream', 'x-attestation-id': att },
        body: buf,
      });
      const uj = (await up.json().catch(() => ({}))) as { id?: string; sha256?: string; bytes?: number; error?: string };
      if (!up.ok || !uj.id) throw new Error(uj.error ?? `upload HTTP ${up.status}`);
      setResult({ firmwareId: uj.id, sha256: uj.sha256 ?? '', bytes: uj.bytes ?? file.size });

      setPhase('queueing run');
      const q = await apiFetch('/v1/pipeline/runs', {
        method: 'POST',
        headers: { 'x-attestation-id': att },
        body: JSON.stringify({ firmwareId: uj.id }),
      });
      const qj = (await q.json().catch(() => ({}))) as { runId?: string; error?: string };
      if (!q.ok || !qj.runId) throw new Error(qj.error ?? `queue HTTP ${q.status}`);

      setPhase('analysing');
      let doc: RunDoc | null = null;
      for (let i = 0; i < POLL_TRIES; i++) {
        await new Promise((res) => setTimeout(res, POLL_MS));
        const g = await apiFetch(`/v1/pipeline/runs/${qj.runId}`);
        if (!g.ok) continue;
        doc = (await g.json()) as RunDoc;
        if (doc.status === 'done' || doc.status === 'failed') break;
      }
      if (!doc) throw new Error('The run did not report back — check /dashboard for the ledger.');
      if (doc.status === 'failed') throw new Error(doc.error || 'The engine failed on this image.');
      setResult((r) => ({ firmwareId: r?.firmwareId ?? uj.id!, sha256: r?.sha256 ?? uj.sha256 ?? '', bytes: r?.bytes ?? file.size, run: doc ?? undefined }));
      setPhase('');
    } catch (e) {
      setErr((e as Error).message);
      setPhase('');
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  const run = result?.run;

  return (
    <Card style={{ marginTop: 0 }}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 14, letterSpacing: 2, color: '#22d3ee', flex: 1 }}>FIRMWARE INTAKE</h3>
        <Badge tone="cyan">REAL BYTES</Badge>
      </div>
      <p style={{ color: '#94a3b8', fontSize: 12.5, lineHeight: 1.6, margin: '0 0 14px', maxWidth: 760 }}>
        Drop an image from the target device. The run hashes it, parses the container layout and ELF header, carves
        printable strings out of the bytes, and scans those for secrets and dangerous sinks — then files every verdict
        into the queue with its evidence attached. Discovery and fuzzing stay on the demo profile; they need a call
        graph or a harness, and inventing crashes on a real image would be worse than skipping the stage.
      </p>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          ref={fileRef}
          type="file"
          onChange={(e) => pick(e.target.files?.[0] ?? null)}
          style={{ display: 'none' }}
          id="sf-firmware-file"
        />
        <label className="sf-btn" htmlFor="sf-firmware-file" style={{ cursor: 'pointer' }}>
          {file ? 'Choose another image' : 'Choose image'}
        </label>
        <input
          className="sf-input"
          placeholder="version (e.g. gw200-1.4.2)"
          value={version}
          onChange={(e) => setVersion(e.target.value)}
          style={{ width: 210 }}
          aria-label="firmware version"
        />
        <select
          className="sf-input"
          value={deviceId}
          onChange={(e) => setDeviceId(e.target.value)}
          aria-label="target device"
          style={{ minWidth: 190 }}
        >
          <option value="">No target device</option>
          {devices.map((d) => (
            <option key={d.id} value={d.id}>
              {d.name} · {d.transport}
            </option>
          ))}
        </select>
        <button className="sf-btn sf-btn-accent" onClick={() => void analyse()} disabled={!file || busy}>
          {busy ? `${phase.toUpperCase()}…` : 'Upload & analyse'}
        </button>
      </div>

      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 8, fontSize: 11.5, color: '#64748b' }}>
        <span>{file ? `${file.name} · ${human(file.size)}` : 'No image selected · 16 MB cap'}</span>
        <span>Needs a signed-in session and an attestation from /devices.</span>
      </div>

      {busy && (
        <motion.div
          initial={reduced ? false : { opacity: 0 }}
          animate={{ opacity: 1 }}
          style={{ marginTop: 14, height: 3, borderRadius: 2, background: 'rgba(255,255,255,0.08)', overflow: 'hidden' }}
        >
          <motion.div
            animate={reduced ? { width: '100%' } : { x: ['-40%', '140%'] }}
            transition={reduced ? undefined : { duration: 1.1, repeat: Infinity, ease: 'easeInOut' }}
            style={{ width: '40%', height: '100%', background: 'linear-gradient(90deg, transparent, #22d3ee, transparent)' }}
          />
        </motion.div>
      )}

      {err && <p role="alert" style={{ color: '#f87171', fontSize: 13, margin: '12px 0 0' }}>{err}</p>}

      {result && (
        <div className="sf-glass" onPointerMove={glassGlow} style={{ marginTop: 16, borderRadius: 12, padding: '14px 16px' }}>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center', fontSize: 12, color: '#94a3b8' }}>
            <span>
              SHA-256 <Code>{result.sha256.slice(0, 16)}…</Code>
            </span>
            <span>
              SIZE <b style={{ color: '#e2e8f0' }}>{human(result.bytes)}</b>
            </span>
            <a className="sf-btn" href={`/emulator?firmware=${encodeURIComponent(result.firmwareId)}`} style={{ fontSize: 11, padding: '4px 10px' }}>
              Boot twin on this image →
            </a>
            {run?.artifacts?.elf && (
              <span>
                ELF{' '}
                <b style={{ color: run.artifacts.elf.valid ? '#6ee7b7' : '#94a3b8' }}>
                  {run.artifacts.elf.valid
                    ? `${run.artifacts.elf.machine ?? '?'} ${run.artifacts.elf.bits ?? '?'}-bit ${run.artifacts.elf.endian ?? ''}`
                    : 'not an ELF header'}
                </b>
              </span>
            )}
            {run?.artifacts && (
              <span>
                SBOM <b style={{ color: '#e2e8f0' }}>{run.artifacts.components ?? 0}</b> · GZ{' '}
                <b style={{ color: '#e2e8f0' }}>{run.artifacts.gzipMembers ?? 0}</b>
              </span>
            )}
            {run && (
              <span>
                FINDINGS <b style={{ color: '#e2e8f0' }}>{run.findingsCount ?? 0}</b>
              </span>
            )}
          </div>

          {run?.findings?.length ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 12 }}>
              {run.findings.map((f, i) => (
                <motion.a
                  key={f.id}
                  href={`/findings/${f.id}`}
                  initial={reduced ? false : { opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.04 * Math.min(i, 10), duration: 0.4 }}
                  style={{ display: 'flex', gap: 10, alignItems: 'center', textDecoration: 'none', color: 'inherit', fontSize: 12.5, padding: '7px 10px', borderRadius: 8, background: 'rgba(148,163,184,0.05)' }}
                >
                  <b style={{ color: '#fff', minWidth: 32, fontFamily: 'ui-monospace, monospace' }}>P{f.priority}</b>
                  <span style={{ flex: 1 }}>{f.title}</span>
                  <Badge tone={CONF_TONE[f.confidence] ?? 'gray'}>{f.confidence.toUpperCase()}</Badge>
                  <span aria-hidden style={{ color: '#22d3ee' }}>›</span>
                </motion.a>
              ))}
            </div>
          ) : (
            run && <p style={{ fontSize: 12.5, color: '#6ee7b7', margin: '12px 0 0' }}>No findings — the carved strings tripped no secret or sink rule.</p>
          )}

          {run?.removed?.length ? (
            <p style={{ fontSize: 12, color: '#fcd34d', margin: '10px 0 0' }}>
              Dropped {run.removed.length} stale verdict{run.removed.length === 1 ? '' : 's'} from the previous run:{' '}
              {run.removed.join(', ')}
            </p>
          ) : null}

          {run?.stageStatus && (
            <div style={{ marginTop: 12, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {Object.entries(run.stageStatus).map(([stage, st]) => (
                <span
                  key={stage}
                  style={{
                    fontSize: 10.5,
                    fontFamily: 'ui-monospace, monospace',
                    letterSpacing: 0.5,
                    padding: '3px 8px',
                    borderRadius: 999,
                    border: `1px solid ${st === 'done' ? 'rgba(110,231,183,0.35)' : 'rgba(148,163,184,0.25)'}`,
                    color: st === 'done' ? '#6ee7b7' : '#64748b',
                  }}
                >
                  {stage}:{st}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}
