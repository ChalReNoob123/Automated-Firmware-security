'use client';
import { motion } from 'framer-motion';
import { GhostNum, MaskWords, Reveal } from './motionKit';
import { glassGlow } from './components/ui';
import ArtPanel from './ArtPanel';
import CapabilityIndex from './CapabilityIndex';
import DeviceReel from './DeviceReel';
import MarqueeBand from './MarqueeBand';

// Below-the-fold showcase: aggregate threat ticker, capability index (Lusion-
// style rows), pipeline strip, consensus banner, CTA. All staged reveals;
// respects reduced motion via CSS.
const TRENDS = [
  ['BUFFER_OVERFLOW', '+12%', '#f43f5e'],
  ['HARDCODED_CREDS', '+8%', '#fb923c'],
  ['INSECURE_BOOT', '-4%', '#34d399'],
  ['EXPOSED_UART', '+6%', '#fb923c'],
  ['WEAK_CRYPTO', '-9%', '#34d399'],
  ['CMD_INJECTION', '+15%', '#f43f5e'],
  ['DEFAULT_PASSWORDS', '+3%', '#f59e0b'],
] as const;

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
      <div className="sf-ticker" style={{ borderTop: '1px solid rgba(255,255,255,0.08)', borderBottom: '1px solid rgba(255,255,255,0.08)', background: 'rgba(2,6,23,0.7)', overflow: 'hidden', padding: '12px 0' }}>
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

      {/* round-17: velocity-reactive capability drift */}
      <MarqueeBand />

      <main style={{ maxWidth: 1100, margin: '0 auto', padding: '72px 32px 32px' }}>
        {/* capability index — Lusion-style numbered rows */}
        <motion.div initial="hidden" whileInView="show" viewport={{ once: true, margin: '-80px' }} transition={{ staggerChildren: 0.06 }} style={{ position: 'relative' }}>
          <GhostNum n="01" />
          <motion.p variants={rise} style={{ color: '#22d3ee', letterSpacing: 5, fontSize: 12 }}>01 · THE PLATFORM</motion.p>
          <MaskWords text="Bold firmware, brought to light." style={{ fontSize: 'clamp(30px, 4.6vw, 54px)', margin: '8px 0 10px', letterSpacing: -1.5 }} />
          <motion.p variants={rise} style={{ color: '#94a3b8', maxWidth: 640, lineHeight: 1.6, marginBottom: 26 }}>
            Eleven modules run as one continuous loop — acquisition to attested verdict. Hover a row to see what it
            proves.
          </motion.p>
          <CapabilityIndex />
        </motion.div>

        {/* cinematic art band — procedural panels, native-res bake, video-like motion */}
        <Reveal>
          <div style={{ marginTop: 72, position: 'relative' }}>
            <GhostNum n="02" />
            <p style={{ color: '#22d3ee', letterSpacing: 5, fontSize: 12 }}>02 · LIVE VISUAL SYSTEM</p>
            <MaskWords text="The machine, rendered." style={{ fontSize: 'clamp(28px, 4vw, 44px)', margin: '8px 0 10px', letterSpacing: -1 }} />
            <p style={{ color: '#94a3b8', maxWidth: 680, lineHeight: 1.6 }}>
              These panels are computed, not filmed: seeded procedural scenes baked at your display&apos;s native
              resolution (crisp on a 4K monitor), then animated — zero media payload, never out of focus.
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 14, marginTop: 26 }}>
              <ArtPanel variant="circuit" height={320}>
                <div className="sf-caption-eyebrow">MACRO FIRMWARE VIEW</div>
                <div className="sf-caption-title">PCB topology, procedurally baked</div>
                <div className="sf-caption-sub">Traces, vias and chip blocks from a seeded layout — slow Ken Burns drift.</div>
              </ArtPanel>
              <ArtPanel variant="holo" height={320}>
                <div className="sf-caption-eyebrow">DIGITAL TWIN</div>
                <div className="sf-caption-title">Wireframe twin, live sweep</div>
                <div className="sf-caption-sub">Orbiting particles and a scan sweep — the twin boots in this light.</div>
              </ArtPanel>
              <ArtPanel variant="gridwave" height={320} kenburns={false}>
                <div className="sf-caption-eyebrow">ATTACK-SURFACE HORIZON</div>
                <div className="sf-caption-title">Depth grid, scrolling forever</div>
                <div className="sf-caption-sub">Every line is a scan surface; the grid keeps coming like the queue does.</div>
              </ArtPanel>
            </div>
          </div>
        </Reveal>

        {/* field reel — device imagery as a looping, tilting video wall */}
        <Reveal>
          <div style={{ marginTop: 72, position: 'relative' }}>
            <GhostNum n="03" />
            <p style={{ color: '#22d3ee', letterSpacing: 5, fontSize: 12 }}>03 · FIELD REEL</p>
            <MaskWords text="Hardware on the wall, in motion." style={{ fontSize: 'clamp(28px, 4vw, 44px)', margin: '8px 0 10px', letterSpacing: -1 }} />
            <p style={{ color: '#94a3b8', maxWidth: 680, lineHeight: 1.6 }}>
              A looping device reel with true 3D depth — the stage tilts to your pointer, the HUD floats above the
              glass, and every slide drifts like a camera feed. Photographic plates are auto-detected from
              public/devices; until the render queue refills, the reel runs fully procedural.
            </p>
            <div style={{ marginTop: 26 }}>
              <DeviceReel />
            </div>
          </div>
        </Reveal>

        {/* pipeline strip */}
        <motion.div initial="hidden" whileInView="show" viewport={{ once: true, margin: '-80px' }} style={{ marginTop: 72, position: 'relative' }}>
          <GhostNum n="04" />
          <motion.p variants={rise} style={{ color: '#a855f7', letterSpacing: 5, fontSize: 12 }}>04 · ALWAYS ON</motion.p>
          <MaskWords text="From image to ranked chains." style={{ fontSize: 'clamp(28px, 4vw, 44px)', margin: '8px 0 26px', letterSpacing: -1 }} />
          <motion.div variants={rise} style={{ position: 'relative', display: 'flex', gap: 8, overflowX: 'auto', padding: '18px 4px 22px' }}>
            <div className="sf-pipe-dot" />
            {STAGES.map((s, i) => (
              <div key={s} className="sf-glass sf-card-hover" onPointerMove={glassGlow} style={{ flex: '1 0 auto', borderRadius: 12, padding: '12px 16px', fontSize: 13, textAlign: 'center', minWidth: 100 }}>
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
          onPointerMove={glassGlow}
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
