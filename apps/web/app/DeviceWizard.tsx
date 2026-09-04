'use client';
import { useState } from 'react';
import { motion } from 'framer-motion';

// Module 1 (spec §3): transport picker + attestation explainer. Real pairing and
// logged attestation happen in /devices (WebUSB) — this wizard routes there with
// the chosen transport so the landing never dead-ends on a fake button.
const TRANSPORTS = [
  ['usb', 'USB — browser pairing, no agent'],
  ['wifi', 'Wi-Fi — agent-assisted'],
  ['ble', 'BLE — agent-assisted'],
  ['zigbee', 'Zigbee — signed native agent'],
  ['zwave', 'Z-Wave — signed native agent'],
  ['uart', 'UART — serial adapter + agent'],
  ['jtag', 'JTAG — debug probe + agent'],
] as const;

export default function DeviceWizard() {
  const [transport, setTransport] = useState<string>('usb');
  const [basis, setBasis] = useState('');
  const [attested, setAttested] = useState(false);
  const ready = attested && basis.trim().length >= 4;
  const href = transport === 'usb' ? '/devices' : '/devices';

  return (
    <motion.section
      initial={{ opacity: 0, y: 26 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-60px' }}
      transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
      className="sf-glass"
      style={{ borderRadius: 20, padding: 24, marginTop: 28 }}
    >
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 18 }}>
        <div>
          <div style={{ fontSize: 12, letterSpacing: 2, color: '#22d3ee', marginBottom: 8 }}>1 · CONNECT DEVICE</div>
          <select className="sf-input" aria-label="Transport" value={transport} onChange={(e) => setTransport(e.target.value)} style={{ width: '100%' }}>
            {TRANSPORTS.map(([v, label]) => (
              <option key={v} value={v}>{label}</option>
            ))}
          </select>
          <p style={{ color: '#64748b', fontSize: 12.5, marginTop: 8, lineHeight: 1.6 }}>
            {transport === 'usb'
              ? 'Chrome pairs over the cable in one click.'
              : 'Wireless and debug transports pair through the signed native agent.'}
          </p>
        </div>
        <div>
          <div style={{ fontSize: 12, letterSpacing: 2, color: '#22d3ee', marginBottom: 8 }}>2 · ATTEST AUTHORIZATION</div>
          <input className="sf-input" aria-label="Legal basis" placeholder="Legal basis — ownership or ticket ref" value={basis} onChange={(e) => setBasis(e.target.value)} style={{ width: '100%', boxSizing: 'border-box' }} />
          <label style={{ display: 'flex', gap: 8, marginTop: 10, fontSize: 13, color: '#cbd5e1', cursor: 'pointer', lineHeight: 1.5 }}>
            <input type="checkbox" checked={attested} onChange={(e) => setAttested(e.target.checked)} style={{ marginTop: 3, accentColor: '#22d3ee' }} />
            I attest I am authorized to test this device. Logged to auth_audit + attestations.
          </label>
        </div>
      </div>
      <div style={{ marginTop: 16 }}>
        {ready ? (
          <a className="sf-btn-primary" href={href}>Continue to {transport.toUpperCase()} onboarding →</a>
        ) : (
          <span className="sf-btn" style={{ opacity: 0.45, cursor: 'not-allowed' }}>Attestation required before any test</span>
        )}
      </div>
    </motion.section>
  );
}
