import dynamic from 'next/dynamic';
import Showcase from './Showcase';
import DeviceWizard from './DeviceWizard';

const CinematicHero = dynamic(() => import('./CinematicHero'), {
  ssr: false,
  loading: () => (
    <header style={{ height: '94vh', minHeight: 620, display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#020617' }}>
      <p style={{ color: '#22d3ee', letterSpacing: 4, fontSize: 13 }}>INITIALIZING THREAT RADAR…</p>
    </header>
  ),
});

export default function Page() {
  return (
    <>
      <CinematicHero />
      <Showcase />
      <section style={{ maxWidth: 1100, margin: '0 auto', padding: '0 32px 72px' }}>
        <p style={{ color: '#22d3ee', letterSpacing: 5, fontSize: 12 }}>GET STARTED</p>
        <h2 style={{ fontSize: 'clamp(24px, 3.4vw, 36px)', margin: '8px 0 4px', letterSpacing: -1 }}>Connect a device. Attest. Scan.</h2>
        <p style={{ color: '#94a3b8', maxWidth: 640, lineHeight: 1.6 }}>
          USB, Wi-Fi, BLE, Zigbee, Z-Wave, UART or JTAG — every test begins with a logged
          authorization attestation. No attestation, no pipeline.
        </p>
        <DeviceWizard />
      </section>
    </>
  );
}
