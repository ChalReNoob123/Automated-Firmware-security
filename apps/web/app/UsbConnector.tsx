'use client';
import { useEffect, useState } from 'react';
import { Card, Badge, Empty, Code } from './components/ui';
import { apiFetch, getAccess } from './lib/auth';

// USB onboarding (spec §3): real WebUSB device prompt → descriptor readout →
// register + logged attestation against the API. Identity via memory token;
// the attestation id persists locally (test-scope grant, not identity).

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

const hex4 = (n: number) => '0x' + n.toString(16).padStart(4, '0');

export default function UsbConnector({ onAttested }: { onAttested?: (attId: string, deviceId: string) => void }) {
  // Feature-detect AFTER mount: server has no navigator, so an initializer would
  // render false on the server and true on the client (hydration mismatch).
  const [supported, setSupported] = useState<boolean | null>(null);
  const [device, setDevice] = useState<UsbInfo | null>(null);
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [name, setName] = useState('');
  const [basis, setBasis] = useState('');
  const [err, setErr] = useState('');
  const [done, setDone] = useState('');

  useEffect(() => {
    setSupported('usb' in navigator && window.isSecureContext);
    getAccess().then((t) => setSignedIn(!!t));
  }, []);

  const connect = async () => {
    setErr('');
    setDone('');
    try {
      const nav = navigator as unknown as { usb: { requestDevice(o: unknown): Promise<WebUsbDevice>; getDevices(): Promise<WebUsbDevice[]> } };
      const d: WebUsbDevice = await nav.usb.requestDevice({ filters: [] });
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
        vendorId: d.vendorId,
        productId: d.productId,
        productName: d.productName,
        manufacturerName: d.manufacturerName,
        serialNumber: d.serialNumber,
        usbVersion: `${d.usbVersionMajor}.${d.usbVersionMinor}${d.usbVersionSubminor}`,
      });
      if (!name && d.productName) setName(d.productName);
    } catch (e) {
      if ((e as Error).name === 'NotFoundError') return; // user cancelled picker
      setErr('USB: ' + (e as Error).message);
    }
  };

  const register = async () => {
    if (!device || !name.trim() || !basis.trim()) {
      setErr('Device, name and legal basis are all required.');
      return;
    }
    setErr('');
    setDone('');
    try {
      const post = async (path: string, body: unknown) => {
        const r = await apiFetch(path, { method: 'POST', body: JSON.stringify(body) });
        const j = await r.json().catch(() => ({}));
        if (r.status === 401) {
          setSignedIn(false);
          throw new Error('Session expired — sign in at /login, then retry.');
        }
        if (!r.ok) throw new Error((j as { error?: string }).error ?? `HTTP ${r.status}`);
        return j;
      };
      const dev = (await post('/v1/devices', { name: name.trim(), transport: 'usb' })) as { id: string };
      const att = (await post('/v1/attestations', {
        deviceId: dev.id,
        scope: 'firmware-extract,emulate,fuzz',
        legalBasis: `${basis.trim()} [usb ${hex4(device.vendorId)}:${hex4(device.productId)}${device.serialNumber ? ' s/n ' + device.serialNumber : ''}]`,
      })) as { id: string };
      localStorage.setItem('sf_att', att.id);
      setSignedIn(true);
      setDone(`Registered + attested. Attestation ${att.id} saved — emulator, lab and attack sim are now unlocked.`);
      onAttested?.(att.id, dev.id);
    } catch (e) {
      setErr((e as Error).message);
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
          Open this page in Chrome on <Code>http://localhost:3005/devices</Code>, or register the device manually below via the API.
        </p>
      </Card>
    );

  return (
    <Card>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <Badge tone={device ? 'green' : 'gray'}>{device ? 'DEVICE PAIRED' : 'NO DEVICE'}</Badge>
        <button className="sf-btn sf-btn-accent" onClick={connect}>Connect USB device</button>
      </div>
      {device ? (
        <div className="sf-glass" style={{ borderRadius: 12, padding: 16, marginTop: 14, fontSize: 13.5 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 8 }}>
            <div>Product <b style={{ color: '#fff' }}>{device.productName ?? 'unknown'}</b></div>
            <div>Maker <b style={{ color: '#fff' }}>{device.manufacturerName ?? 'unknown'}</b></div>
            <div>VID:PID <Code>{hex4(device.vendorId)}:{hex4(device.productId)}</Code></div>
            <div>USB <b style={{ color: '#fff' }}>{device.usbVersion}</b></div>
            {device.serialNumber && <div>Serial <Code>{device.serialNumber}</Code></div>}
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
            <button className="sf-btn sf-btn-accent" onClick={register}>Register + attest</button>
          </div>
        </div>
      ) : (
        <div style={{ marginTop: 14 }}>
          <Empty title="No USB device paired" hint="Click Connect — your browser will show the system device picker. The cable is the onboarding." />
        </div>
      )}
      {err && <p style={{ color: '#f87171', fontSize: 13 }}>{err}</p>}
      {done && <p style={{ color: '#6ee7b7', fontSize: 13 }}>{done}</p>}
    </Card>
  );
}
