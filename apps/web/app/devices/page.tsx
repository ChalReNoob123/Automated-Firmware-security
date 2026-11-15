import AmbientScene from '../AmbientScene';
import { PageHeader } from '../motionKit';
import UsbConnector from '../UsbConnector';

export default function DevicesPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page">
        <PageHeader
          eyebrow="SENTINELFORGE v3 · ONBOARDING"
          title="Plug in. Pair. Prove ownership."
          sub="Detection is automatic: SentinelForge reads the real Windows device tree through the local API, so what you plug in appears without a picker. Select a device, confirm you are authorized to test it, and the attestation unlocks the twin, the lab and attack simulation."
        />
        <div style={{ marginTop: 8 }}>
          <UsbConnector />
        </div>
        <div style={{ display: 'flex', gap: 12, marginTop: 18, flexWrap: 'wrap' }}>
          <a className="sf-btn" href="/lab">Open device lab →</a>
          <a className="sf-btn" href="/emulator">Boot a twin →</a>
        </div>
      </main>
    </>
  );
}
