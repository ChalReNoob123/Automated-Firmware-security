import './cinematic.css';
import Nav from './Nav';

export const metadata = {
  title: 'SentinelForge — Predictive IoT Vulnerability Discovery',
  description: 'Find uncatalogued flaws in IoT firmware and live devices, verify patches actually work, and react to new CVEs in minutes.',
};

export const viewport = { themeColor: '#020617' };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ background: '#020617', color: '#e2e8f0', margin: 0, fontFamily: 'system-ui' }}>
        <Nav />
        {children}
        <footer style={{ borderTop: '1px solid rgba(255,255,255,0.08)', padding: '22px 32px', display: 'flex', gap: 18, flexWrap: 'wrap', fontSize: 12, color: '#475569', position: 'relative', zIndex: 2 }}>
          <span>SENTINELFORGE v3 · dark-ops build</span>
          <span style={{ marginLeft: 'auto' }}>attestation-gated · isolated workloads · reproducible findings</span>
        </footer>
      </body>
    </html>
  );
}
