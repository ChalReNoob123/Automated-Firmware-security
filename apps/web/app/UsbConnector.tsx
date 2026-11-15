'use client';
import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Card, Badge, Empty, Code, glassGlow } from './components/ui';
import { apiFetch, getAccess } from './lib/auth';

// USB onboarding (spec §3): auto-detect - descriptor readout - register +
// logged attestation against the API. Identity via memory token; the
// attestation id persists locally (test-scope grant, not identity).
//
// Detection reality check (live audit): the WebUSB picker HIDES devices whose
// interfaces are claimed by OS drivers (phones in file/MTP mode, hubs, HID-class
// gear), and the spec forbids enumerating devices without a user grant — so a
// plugged-in device is invisible to the picker by design. Since the API process
// runs on the same host, the page auto-fetches GET /v1/system/usb-devices (a
// read-only Windows PnP probe) every 12s: real connected hardware, no picker,
// no grant needed. Two more paths: navigator.usb.getDevices() restores devices
// paired in an earlier visit, and manual registration covers non-bus transports
// (wifi/ble/zigbee/...) when native probing can't see the target.

type UsbInfo = {
  vendorId: number;
  productId: number;
  productName?: string;
  manufacturerName?: string;
  serialNumber?: string;
  usbVersion: string;
};

// Minimal WebUSB shape (stable across TS DOM lib versions — no lib dependency).
type WebUsbDevice = {
  vendorId: number;
  productId: number;
  productName?: string;
  manufacturerName?: string;
  serialNumber?: string;
  usbVersionMajor: number;
  usbVersionMinor: number;
  usbVersionSubminor: number;
  configuration?: unknown;
  open(): Promise<void>;
  selectConfiguration(n: number): Promise<void>;
  claimInterface(n: number): Promise<void>;
};

// One Windows PnP row from GET /v1/system/usb-devices.
type SysDevice = {
  id: string;
  vid: string | null;
  pid: string | null;
  name: string;
  manufacturer: string | null;
  serial: string | null;
  status: string | null;
  problem: number | null;
};

// Unified selection for either path (native row or WebUSB descriptor readout).
type SelDevice = {
  source: 'usb' | 'native';
  vendorId: number;
  productId: number;
  productName?: string;
  manufacturerName?: string;
  serialNumber?: string;
  usbVersion?: string;
  instanceId?: string;
  problem?: number;
};

type RegDevice = { id: string; name: string; transport: string; fingerprint: string | null; created_at?: string };

const hex4 = (n: number) => '0x' + n.toString(16).padStart(4, '0');
const hex = (h: string) => '0x' + h.replace('0x', '').toLowerCase().padStart(4, '0');
const TRANSPORTS = ['usb', 'wifi', 'ble', 'zigbee', 'zwave', 'uart', 'jtag'] as const;

export default function UsbConnector({ onAttested }: { onAttested?: (attId: string, deviceId: string) => void }) {
  // Feature-detect AFTER mount: server has no navigator, so an initializer would
  // render false on the server and true on the client (hydration mismatch).
  const [supported, setSupported] = useState<boolean | null>(null);
  const [device, setDevice] = useState<SelDevice | null>(null);
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [registered, setRegistered] = useState<RegDevice[] | null>(null);
  const [native, setNative] = useState<SysDevice[] | null>(null);
  const [nativeSrc, setNativeSrc] = useState('');
  const [nativeNote, setNativeNote] = useState('');
  const [manual, setManual] = useState(false);
  const [name, setName] = useState('');
  const [basis, setBasis] = useState('');
  const [mName, setMName] = useState('');
  const [mTransport, setMTransport] = useState<string>('usb');
  const [mFp, setMFp] = useState('');
  const [mBasis, setMBasis] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [done, setDone] = useState('');

  const usb = () => (navigator as unknown as { usb: { requestDevice(o: unknown): Promise<WebUsbDevice>; getDevices(): Promise<WebUsbDevice[]> } }).usb;

  const pickDevice = async (d: WebUsbDevice, source: 'usb' | 'native' = 'usb') => {
    try {
      await d.open();
      if (d.configuration === undefined) await d.selectConfiguration(1);
      try {
        await d.claimInterface(0);
      } catch {
        /* composite/hub devices refuse claim — descriptors still readable */
      }
    } catch {
      /* already open or locked by OS — descriptors still readable */
    }
    setDevice({
      source,
      vendorId: d.vendorId,
      productId: d.productId,
      productName: d.productName,
      manufacturerName: d.manufacturerName,
      serialNumber: d.serialNumber,
      usbVersion: `${d.usbVersionMajor}.${d.usbVersionMinor}${d.usbVersionSubminor}`,
    });
    if (!name && d.productName) setName(d.productName);
  };

  const attachNative = (d: SysDevice) => {
    setDevice({
      source: 'native',
      vendorId: d.vid ? parseInt(d.vid, 16) : 0,
      productId: d.pid ? parseInt(d.pid, 16) : 0,
      productName: d.name,
      manufacturerName: d.manufacturer ?? undefined,
      serialNumber: d.serial ?? undefined,
      instanceId: d.id,
      problem: d.problem ?? undefined,
    });
    setName(d.name === '(unnamed device)' ? '' : d.name);
    setErr('');
  };

  const loadRegistered = async () => {
    try {
      const r = await apiFetch('/v1/devices');
      if (r.status === 401) {
        setSignedIn(false);
        setRegistered(null);
        return;
      }
      if (!r.ok) return;
      const j = (await r.json()) as { devices?: RegDevice[] };
      setRegistered(Array.isArray(j.devices) ? j.devices : []);
    } catch {
      setRegistered(null);
    }
  };

  const loadNative = async () => {
    try {
      const r = await apiFetch('/v1/system/usb-devices');
      if (r.status === 401) {
        setSignedIn(false);
        setNative(null);
        return;
      }
      if (!r.ok) {
        const j = (await r.json().catch(() => ({}))) as { error?: string };
        setNativeNote(j.error ?? 'System probe unavailable');
        setNative(null);
        return;
      }
      const j = (await r.json()) as { devices?: SysDevice[]; source?: string; note?: string };
      setNative(Array.isArray(j.devices) ? j.devices : []);
      setNativeSrc(j.source ?? '');
      setNativeNote(j.note ?? '');
    } catch {
      setNativeNote('System probe unreachable — is the API running?');
      setNative(null);
    }
  };

  useEffect(() => {
    const hasUsb = 'usb' in navigator;
    setSupported(hasUsb && window.isSecureContext);
    getAccess().then(async (t) => {
      setSignedIn(!!t);
      if (t) {
        void loadRegistered();
        void loadNative();
      }
      if (hasUsb) {
        // Restore devices paired in an earlier visit — the chooser grant persists.
        try {
          const ds = await usb().getDevices();
          if (ds[0]) void pickDevice(ds[0]);
        } catch {
          /* paired devices at browser level; failures here are non-fatal */
        }
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-refresh detection while signed in: plugged-in devices show up without
  // any user action. Server caches the probe 15s, so this stays cheap.
  useEffect(() => {
    if (signedIn !== true) return;
    const pull = () => {
      if (document.visibilityState === 'visible') void loadNative();
    };
    const iv = setInterval(pull, 12_000);
    document.addEventListener('visibilitychange', pull);
    return () => {
      clearInterval(iv);
      document.removeEventListener('visibilitychange', pull);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signedIn]);

  const connect = async () => {
    setErr('');
    setDone('');
    try {
      const d = await usb().requestDevice({ filters: [] });
      await pickDevice(d);
    } catch (e) {
      if ((e as Error).name === 'NotFoundError') return; // user cancelled picker
      setErr('USB: ' + (e as Error).message);
    }
  };

  const post = async (path: string, body: unknown) => {
    const r = await apiFetch(path, { method: 'POST', body: JSON.stringify(body) });
    const j = (await r.json().catch(() => ({}))) as { error?: string };
    if (r.status === 401) {
      setSignedIn(false);
      throw new Error('Session expired — sign in at /login, then retry.');
    }
    if (!r.ok) throw new Error(j.error ?? `HTTP ${r.status}`);
    return j as { id: string };
  };

  const register = async () => {
    if (!device || !name.trim() || !basis.trim()) {
      setErr('Device, name and legal basis are all required.');
      return;
    }
    setBusy(true);
    setErr('');
    setDone('');
    try {
      const dev = await post('/v1/devices', { name: name.trim(), transport: 'usb' });
      const hwTag =
        device.source === 'native'
          ? `${hex4(device.vendorId)}:${hex4(device.productId)} [win32 pnp ${device.instanceId ?? ''}]`
          : `[usb ${hex4(device.vendorId)}:${hex4(device.productId)}${device.serialNumber ? ' s/n ' + device.serialNumber : ''}]`;
      const att = (await post('/v1/attestations', {
        deviceId: dev.id,
        scope: 'firmware-extract,emulate,fuzz',
        legalBasis: `${basis.trim()} ${hwTag}`,
      })) as { id: string };
      localStorage.setItem('sf_att', att.id);
      setSignedIn(true);
      setDone(`Registered + attested. Attestation ${att.id} saved — emulator, lab and attack sim are now unlocked.`);
      onAttested?.(att.id, dev.id);
      await loadRegistered();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const registerManual = async () => {
    if (!mName.trim() || !mBasis.trim()) {
      setErr('Name and legal basis are required for manual registration.');
      return;
    }
    setBusy(true);
    setErr('');
    setDone('');
    try {
      const dev = await post('/v1/devices', { name: mName.trim(), transport: mTransport, ...(mFp.trim() ? { fingerprint: mFp.trim() } : {}) });
      const att = (await post('/v1/attestations', {
        deviceId: dev.id,
        scope: 'firmware-extract,emulate,fuzz',
        legalBasis: `${mBasis.trim()} [manual registration · ${mTransport}]`,
      })) as { id: string };
      localStorage.setItem('sf_att', att.id);
      setDone(`Registered + attested (${att.id}). Emulator, lab and attack sim are now unlocked.`);
      setManual(false);
      setMName('');
      setMFp('');
      setMBasis('');
      await loadRegistered();
      onAttested?.(att.id, dev.id);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (supported === null)
    return (
      <Card>
        <p style={{ color: '#64748b', fontSize: 13, letterSpacing: 2 }}>PROBING USB SUBSYSTEM…</p>
      </Card>
    );
  if (!supported)
    return (
      <Card>
        <Badge tone="amber">BROWSER LIMIT</Badge>
        <p style={{ color: '#94a3b8', fontSize: 14, lineHeight: 1.6 }}>
          USB onboarding needs <Code>WebUSB</Code> — Chrome/Edge over <Code>https</Code> or <Code>localhost</Code>.
          Open this page in Chrome on <Code>http://localhost:3005/devices</Code>, or register directly from the API (commands below).
        </p>
        <ManualForm />
      </Card>
    );

  return (
    <Card>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <Badge tone={device ? 'green' : 'gray'}>{device ? 'DEVICE SELECTED' : 'NO DEVICE'}</Badge>
        <button className="sf-btn sf-btn-accent" onClick={connect}>Connect via USB picker</button>
      </div>

      {/* AUTO-DETECTED HARDWARE — the OS picker can't see driver-bound devices
          (phones in MTP, hubs, HID); the API probes the real Windows device tree
          so these appear automatically. Presence ≠ ownership: registering still
          requires a legal-basis attestation. */}
      {signedIn === true && (
        <div className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 12, padding: 16, marginTop: 14 }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 12, letterSpacing: 2, color: '#94a3b8' }}>
              DETECTED ON THIS SYSTEM {native ? `(${native.length})` : '…'}
            </span>
            {nativeSrc && <Badge tone="gray">{nativeSrc}</Badge>}
            <button className="sf-btn" style={{ marginLeft: 'auto', padding: '4px 10px', fontSize: 12 }} onClick={() => void loadNative()}>
              Refresh
            </button>
          </div>
          <p style={{ color: '#64748b', fontSize: 12, marginTop: 6, lineHeight: 1.5 }}>
            Auto-detected from the Windows device tree via the local API — refreshed every 12s. Select a device to
            attest it. If a device you plugged in doesn't appear, wait a beat and hit Refresh, or use the picker / manual registration.
          </p>
          {native && native.length > 0 && (
            <motion.div
              initial="hidden"
              animate="show"
              variants={{ hidden: {}, show: { transition: { staggerChildren: 0.05 } } }}
              style={{ marginTop: 10, display: 'grid', gap: 6, maxHeight: 260, overflow: 'auto' }}
            >
              {native.map((d) => (
                <motion.div
                  key={d.id}
                  variants={{
                    hidden: { opacity: 0, x: -12 },
                    show: { opacity: 1, x: 0, transition: { duration: 0.35, ease: [0.22, 1, 0.36, 1] } },
                  }}
                  className="sf-dev-row"
                  style={{
                    display: 'flex',
                    gap: 10,
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    borderBottom: '1px solid rgba(148,163,184,0.14)',
                    paddingBottom: 6,
                    fontSize: 13,
                  }}
                >
                  <span style={{ color: d.status === 'OK' ? '#6ee7b7' : '#fbbf24' }}>●</span>
                  <b style={{ color: '#fff' }}>{d.name}</b>
                  {d.vid && d.pid && <Code>{hex(d.vid)}:{hex(d.pid)}</Code>}
                  {d.manufacturer && <span style={{ color: '#64748b', fontSize: 12 }}>{d.manufacturer}</span>}
                  {d.problem !== null && d.problem > 0 && <span style={{ color: '#fbbf24', fontSize: 12 }}>driver problem (code {d.problem})</span>}
                  <button
                    className="sf-btn"
                    style={{ marginLeft: 'auto', padding: '3px 10px', fontSize: 12 }}
                    onClick={() => attachNative(d)}
                  >
                    Select →
                  </button>
                </motion.div>
              ))}
            </motion.div>
          )}
          {native && native.length === 0 && (
            <Empty title="No USB devices detected right now" hint="Plug in a device, wait for Windows to install it, then press Refresh." />
          )}
          {nativeNote && <p style={{ color: '#94a3b8', fontSize: 12, marginTop: 6 }}>{nativeNote}</p>}
        </div>
      )}

      {device ? (
        <div className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 12, padding: 16, marginTop: 14, fontSize: 13.5 }}>
          <div style={{ fontSize: 12, letterSpacing: 2, color: '#94a3b8' }}>
            {device.source === 'native' ? 'SELECTED FROM AUTO-DETECTION' : 'SELECTED FROM USB PICKER'}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 8, marginTop: 8 }}>
            <div>Product <b style={{ color: '#fff' }}>{device.productName ?? 'unknown'}</b></div>
            <div>Maker <b style={{ color: '#fff' }}>{device.manufacturerName ?? 'unknown'}</b></div>
            <div>VID:PID <Code>{hex4(device.vendorId)}:{hex4(device.productId)}</Code></div>
            {device.usbVersion && <div>USB <b style={{ color: '#fff' }}>{device.usbVersion}</b></div>}
            {device.serialNumber && <div>Serial <Code>{device.serialNumber}</Code></div>}
            {device.source === 'native' && device.instanceId && <div>Windows instance <Code>{device.instanceId.slice(0, 40)}</Code></div>}
            {device.problem !== undefined && device.problem > 0 && <div style={{ color: '#fbbf24' }}>Driver problem (code {device.problem})</div>}
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 14, flexWrap: 'wrap', alignItems: 'center' }}>
            {signedIn === false ? (
              <a className="sf-btn sf-btn-accent" href="/login">Sign in to register</a>
            ) : (
              <span style={{ fontSize: 12, letterSpacing: 2, color: signedIn ? '#6ee7b7' : '#64748b' }}>
                {signedIn ? '● SIGNED IN' : '○ CHECKING SESSION…'}
              </span>
            )}
            <input className="sf-input" placeholder="device name (e.g. lab-pixel-3)" value={name} onChange={(e) => setName(e.target.value)} style={{ flex: '1 1 180px' }} />
            <input className="sf-input" placeholder="legal basis — ownership / ticket ref" value={basis} onChange={(e) => setBasis(e.target.value)} style={{ flex: '2 1 260px' }} />
            <button className="sf-btn sf-btn-accent" onClick={register} disabled={busy}>{busy ? 'Registering…' : 'Register + attest'}</button>
          </div>
        </div>
      ) : (
        <div style={{ marginTop: 14 }}>
          <Empty
            title="No device selected yet"
            hint="Detection is automatic — select a device above, or use the picker / manual registration below."
          />
        </div>
      )}

      {manual ? (
        <div className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 12, padding: 16, marginTop: 14, fontSize: 13.5 }}>
          <div style={{ fontSize: 12, letterSpacing: 2, color: '#94a3b8' }}>MANUAL REGISTRATION — NON-USB TRANSPORTS / OFF-BUS DEVICES</div>
          <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap', alignItems: 'center' }}>
            <select className="sf-input" value={mTransport} onChange={(e) => setMTransport(e.target.value)} style={{ flex: '0 1 130px' }}>
              {TRANSPORTS.map((t) => (<option key={t} value={t}>{t}</option>))}
            </select>
            <input className="sf-input" placeholder="device name (e.g. lab-pixel-3)" value={mName} onChange={(e) => setMName(e.target.value)} style={{ flex: '1 1 180px' }} />
            <input className="sf-input" placeholder="fingerprint — model / vid:pid / serial (optional)" value={mFp} onChange={(e) => setMFp(e.target.value)} style={{ flex: '1 1 240px' }} />
            <input className="sf-input" placeholder="legal basis — ownership / ticket ref" value={mBasis} onChange={(e) => setMBasis(e.target.value)} style={{ flex: '2 1 260px' }} />
            <button className="sf-btn sf-btn-accent" onClick={registerManual} disabled={busy}>{busy ? 'Registering…' : 'Register'}</button>
          </div>
        </div>
      ) : (
        <button className="sf-btn" style={{ marginTop: 12 }} onClick={() => { setManual(true); setErr(''); }}>
          Non-USB device (wifi / ble / zigbee…)? Register manually →
        </button>
      )}

      {signedIn && registered && registered.length > 0 && (
        <div className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 12, padding: 16, marginTop: 14, fontSize: 13 }}>
          <div style={{ fontSize: 12, letterSpacing: 2, color: '#94a3b8' }}>REGISTERED DEVICES ({registered.length})</div>
          <div style={{ marginTop: 10, display: 'grid', gap: 6 }}>
            {registered.map((d) => (
              <div key={d.id} style={{ display: 'flex', gap: 10, alignItems: 'baseline', borderBottom: '1px solid rgba(148,163,184,0.14)', paddingBottom: 6 }}>
                <b style={{ color: '#fff' }}>{d.name}</b>
                <Badge tone="gray">{d.transport}</Badge>
                {d.fingerprint && <span style={{ color: '#64748b', fontSize: 12 }}><Code>{String(d.fingerprint).slice(0, 48)}</Code></span>}
                <span style={{ color: '#475569', fontSize: 12 }}>{d.created_at ? d.created_at.slice(0, 10) : ''}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {err && <p style={{ color: '#f87171', fontSize: 13 }}>{err}</p>}
      {done && <p style={{ color: '#6ee7b7', fontSize: 13 }}>{done}</p>}
    </Card>
  );
}

// API instructions inside the unsupported-browser branch — manual registration without WebUSB.
function ManualForm() {
  return (
    <p style={{ color: '#64748b', fontSize: 13, lineHeight: 1.6 }}>
      Register from the API: <Code>POST /v1/devices</Code> with <Code>{'{ name, transport }'}</Code>, then{' '}
      <Code>POST /v1/attestations</Code> with <Code>{'{ deviceId, scope, legalBasis }'}</Code>.
    </p>
  );
}
