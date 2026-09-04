import AmbientScene from '../AmbientScene';
import UsbConnector from '../UsbConnector';

export default function DevicesPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page">
        <p className="sf-eyebrow">SENTINELFORGE v3 · ONBOARDING</p>
        <h1 className="sf-h1 sf-gradient-text">Plug in. Pair. Prove ownership.</h1>
        <p className="sf-sub">
          The cable is the onboarding: pair over USB, confirm you are authorized to test the
          hardware, and the attestation unlocks the twin, the lab and attack simulation.
        </p>
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
