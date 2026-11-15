'use client';
import { useState } from 'react';

// Shared gates for the attestation-gated, session-gated panels (emulator,
// attack runner, radar). One visual language for "who are you" and "do you
// hold a test authorization" instead of raw inputs — and the attestation id
// persists centrally here so panels don't each re-implement the same save.
export type SessionState = boolean | null; // null = silent refresh in flight

export function SessionChip({ signedIn, cta }: { signedIn: SessionState; cta: string }) {
  if (signedIn === false) {
    return (
      <a className="sf-btn sf-btn-accent" href="/login">
        {cta}
      </a>
    );
  }
  if (signedIn === null) {
    return <span style={{ fontSize: 12, letterSpacing: 2, color: '#64748b' }}>○ CHECKING SESSION…</span>;
  }
  return <span style={{ fontSize: 12, letterSpacing: 2, color: '#6ee7b7' }}>● SIGNED IN</span>;
}

// Compact status + edit toggle. Shows ATTESTED with an id prefix when a test
// authorization exists, NOT ATTESTED otherwise, and collapses the manual
// "attestation id" plumbing into an edit mode. Persists to sf_att on change.
export function AttestField({ att, onChange }: { att: string; onChange: (v: string) => void }) {
  const [editing, setEditing] = useState(false);
  const value = (att || '').trim();
  const attested = value.length > 0;

  const set = (v: string) => {
    onChange(v);
    try {
      if (v.trim()) localStorage.setItem('sf_att', v);
      else localStorage.removeItem('sf_att');
    } catch {
      /* storage unavailable — session-local only */
    }
  };

  if (editing) {
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <input
          className="sf-input"
          style={{ flex: '1 1 180px', minWidth: 180 }}
          placeholder="attestation id — register the device at /devices"
          value={att}
          autoFocus
          onChange={(e) => set(e.target.value)}
          onBlur={() => setEditing(false)}
          onKeyDown={(e) => e.key === 'Enter' && setEditing(false)}
          aria-label="Attestation id"
        />
        <button className="sf-btn" style={{ fontSize: 11.5, padding: '5px 10px' }} onClick={() => setEditing(false)}>
          done
        </button>
      </span>
    );
  }

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
      <span
        style={{
          fontSize: 12,
          letterSpacing: 1.5,
          color: attested ? '#6ee7b7' : '#fcd34d',
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
        }}
      >
        <span
          style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            background: attested ? '#34d399' : '#f59e0b',
            boxShadow: `0 0 8px ${attested ? '#34d399' : '#f59e0b'}`,
          }}
        />
        {attested ? `ATTESTED · ${value.slice(0, 8)}…` : 'NOT ATTESTED'}
      </span>
      <button className="sf-btn" style={{ fontSize: 11.5, padding: '5px 10px' }} onClick={() => setEditing(true)}>
        {attested ? 'edit' : 'add attestation id →'}
      </button>
      {!attested && (
        <a href="/devices" style={{ color: '#22d3ee', fontSize: 12 }}>
          register a device →
        </a>
      )}
    </span>
  );
}
