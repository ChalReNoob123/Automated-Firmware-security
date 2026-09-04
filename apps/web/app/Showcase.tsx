'use client';
import { motion } from 'framer-motion';

// Below-the-fold showcase: aggregate threat ticker, module grid, pipeline strip,
// consensus banner, CTA. All staged reveals; respects reduced motion via CSS.
const TRENDS = [
  ['BUFFER_OVERFLOW', '+12%', '#f43f5e'],
  ['HARDCODED_CREDS', '+8%', '#fb923c'],
  ['INSECURE_BOOT', '-4%', '#34d399'],
  ['EXPOSED_UART', '+6%', '#fb923c'],
  ['WEAK_CRYPTO', '-9%', '#34d399'],
  ['CMD_INJECTION', '+15%', '#f43f5e'],
  ['DEFAULT_PASSWORDS', '+3%', '#f59e0b'],
] as const;

const MODULES: [string, string][] = [
  ['Root of Trust', 'Secure-boot chain, anti-rollback, SE-backed keys — PSA mapped.'],
  ['Acquisition → SBOM', 'Binwalk unpacking, secret scan, CycloneDX + VEX output.'],
  ['Digital Twin', 'QEMU emulation with snapshot + step-by-step replay.'],
  ['Taint Tracking', 'Attacker input to dangerous sinks, sanitizer-aware.'],
  ['AI Fuzzing', 'Coverage-guided, novelty + sink-proximity mutation loop.'],
  ['Consensus', 'Confirmed only on 2+ engines. No alert floods.'],
  ['Attack Paths', 'Shortest exploit chains, ranked by attacker cost — via API + Copilot.'],
  ['MCP + Copilot', 'Seven tool servers; chat grounded in live scan data.'],
  ['N-Day Radar', 'New CVE hits your SBOM → verdict in minutes.'],
  ['Patch Verify', 'Binary diff proves the vulnerable path is gone.'],
  ['Auth & Audit', 'RBAC, TOTP, SSO, attestation-gated testing.'],
];

const STAGES = ['Acquisition', 'Unpack', 'Static', 'SBOM', 'RoT check', 'Discovery', 'Graph', 'Report'];

const rise = {
  hidden: { opacity: 0, y: 28 },
  show: { opacity: 1, y: 0, transition: { duration: 0.7, ease: [0.22, 1, 0.36, 1] as const } },
};

export default function Showcase() {
  const ticker = [...TRENDS, ...TRENDS];
  return (
    <>
      {/* aggregate threat ticker */}
      <div style={{ borderTop: '1px solid rgba(255,255,255,0.08)', borderBottom: '1px solid rgba(255,255,255,0.08)', background: 'rgba(2,6,23,0.7)', overflow: 'hidden', padding: '12px 0' }}>
        <div className="sf-ticker-track">
          {[0, 1].map((half) => (
            <span key={half} style={{ display: 'inline-flex' }}>
              {ticker.map(([name, delta, color], i) => (
                <span key={`${half}-${i}`} style={{ margin: '0 26px', fontSize: 13, letterSpacing: 2, color: '#94a3b8' }}>
                  {name} <b style={{ color }}>{delta}</b> <span style={{ color: '#334155' }}>· FLEET AGGREGATE</span>
                </span>
              ))}
            </span>
          ))}
        </div>
      </div>

      <main style={{ maxWidth: 1100, margin: '0 auto', padding: '72px 32px 32px' }}>
        {/* modules */}
        <motion.div initial="hidden" whileInView="show" viewport={{ once: true, margin: '-80px' }} transition={{ staggerChildren: 0.06 }}>
          <motion.p variants={rise} style={{ color: '#22d3ee', letterSpacing: 5, fontSize: 12 }}>THE PLATFORM</motion.p>
          <motion.h2 variants={rise} style={{ fontSize: 'clamp(28px, 4vw, 44px)', margin: '8px 0 26px', letterSpacing: -1 }}>
            Eleven modules. One continuous loop.
          </motion.h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 14 }}>
            {MODULES.map(([name, desc]) => (
              <motion.div key={name} variants={rise} className="sf-glass" style={{ borderRadius: 16, padding: 18 }}>
                <div style={{ color: '#fff', fontWeight: 700, marginBottom: 6 }}>{name}</div>
                <div style={{ color: '#94a3b8', fontSize: 13, lineHeight: 1.55 }}>{desc}</div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* pipeline strip */}
        <motion.div initial="hidden" whileInView="show" viewport={{ once: true, margin: '-80px' }} style={{ marginTop: 72 }}>
          <motion.p variants={rise} style={{ color: '#a855f7', letterSpacing: 5, fontSize: 12 }}>ALWAYS ON</motion.p>
          <motion.h2 variants={rise} style={{ fontSize: 'clamp(28px, 4vw, 44px)', margin: '8px 0 26px', letterSpacing: -1 }}>
            From image to ranked chains.
          </motion.h2>
          <motion.div variants={rise} style={{ position: 'relative', display: 'flex', gap: 8, overflowX: 'auto', padding: '18px 4px 22px' }}>
            <div className="sf-pipe-dot" />
            {STAGES.map((s, i) => (
              <div key={s} className="sf-glass" style={{ flex: '1 0 auto', borderRadius: 12, padding: '12px 16px', fontSize: 13, textAlign: 'center', minWidth: 100 }}>
                <span style={{ color: '#22d3ee', fontFamily: 'monospace', marginRight: 8 }}>{String(i + 1).padStart(2, '0')}</span>
                <span style={{ color: '#e2e8f0' }}>{s}</span>
              </div>
            ))}
          </motion.div>
        </motion.div>

        {/* consensus banner */}
        <motion.div
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: '-80px' }}
          variants={rise}
          className="sf-glass"
          style={{ marginTop: 56, borderRadius: 20, padding: 28, display: 'flex', gap: 20, alignItems: 'center', flexWrap: 'wrap' }}
        >
          <div style={{ flex: '1 1 280px' }}>
            <div style={{ fontSize: 20, fontWeight: 800 }}>Analysts drown in fuzzer output. Ours don&apos;t.</div>
            <div style={{ color: '#94a3b8', marginTop: 6, fontSize: 14, lineHeight: 1.6 }}>
              A finding is <b style={{ color: '#6ee7b7' }}>Confirmed</b> only when two independent engines corroborate it.
              Everything else waits in triage — with its reasoning attached.
            </div>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            {([['Confirmed', '#6ee7b7'], ['Likely', '#fcd34d'], ['Unconfirmed', '#94a3b8']] as const).map(([label, color]) => (
              <span key={label} style={{ border: `1px solid ${color}55`, background: `${color}14`, color, borderRadius: 999, padding: '8px 16px', fontSize: 13, fontWeight: 700 }}>
                {label}
              </span>
            ))}
          </div>
        </motion.div>

        {/* CTA */}
        <motion.div initial="hidden" whileInView="show" viewport={{ once: true }} variants={rise} style={{ textAlign: 'center', margin: '72px 0 40px' }}>
          <div className="sf-gradient-text" style={{ fontSize: 'clamp(26px, 3.6vw, 40px)', fontWeight: 800, letterSpacing: -1 }}>
            React before attackers do.
          </div>
          <div style={{ display: 'flex', gap: 14, justifyContent: 'center', marginTop: 22, flexWrap: 'wrap' }}>
            <a className="sf-btn-primary" href="/emulator">Boot a twin</a>
            <a className="sf-btn-ghost" href="/copilot">Ask the Copilot</a>
          </div>
        </motion.div>
      </main>
    </>
  );
}
