'use client';
import { useEffect, useRef } from 'react';
import { motion, useReducedMotion } from 'framer-motion';

// Lusion "Featured Work" structure → SentinelForge capability index: numbered
// full-width rows, big type, tag pills, and a description that unfolds on
// hover (CSS grid-rows trick — animates without JS layout thrash).

const CAPS: [string, string, string[]][] = [
  ['Root of Trust', 'Secure-boot chain, anti-rollback, SE-backed keys — PSA mapped.', ['secure-boot', 'psa', 'keys']],
  ['Acquisition → SBOM', 'Binwalk unpacking, secret scan, CycloneDX + VEX output.', ['binwalk', 'cyclonedx', 'vex']],
  ['Digital Twin', 'QEMU emulation with snapshot + step-by-step replay.', ['qemu', 'snapshot', 'replay']],
  ['Taint Tracking', 'Attacker input to dangerous sinks, sanitizer-aware.', ['taint', 'sinks', 'sanitizers']],
  ['AI Fuzzing', 'Coverage-guided, novelty + sink-proximity mutation loop.', ['coverage', 'novelty', 'sinks']],
  ['Consensus', 'Confirmed only on 2+ engines. No alert floods.', ['2+ engines', 'triage', 'reasoning']],
  ['Attack Paths', 'Shortest exploit chains, ranked by attacker cost.', ['chains', 'graph', 'ranked']],
  ['MCP + Copilot', 'Seven tool servers; chat grounded in live scan data.', ['mcp', '7 engines', 'grounded']],
  ['N-Day Radar', 'New CVE hits your SBOM → verdict in minutes.', ['cve', 'sbom', 'minutes']],
  ['Patch Verify', 'Binary diff proves the vulnerable path is gone.', ['diff', 'sinks', 'proof']],
  ['Auth & Audit', 'RBAC, TOTP, SSO, attestation-gated testing.', ['rbac', 'totp', 'attestation']],
];

export default function CapabilityIndex() {
  const root = useRef<HTMLDivElement>(null);
  const reduced = useReducedMotion() ?? false;

  // spotlight glow follows the pointer across rows (CSS vars, delegated)
  useEffect(() => {
    const el = root.current;
    if (!el) return;
    const move = (e: PointerEvent) => {
      const row = (e.target as Element | null)?.closest?.('.sf-cap-row') as HTMLElement | null;
      if (!row) return;
      const r = row.getBoundingClientRect();
      row.style.setProperty('--mx', `${e.clientX - r.left}px`);
      row.style.setProperty('--my', `${e.clientY - r.top}px`);
    };
    el.addEventListener('pointermove', move, { passive: true });
    return () => el.removeEventListener('pointermove', move);
  }, []);

  const item = reduced
    ? { hidden: { opacity: 0 }, show: { opacity: 1, transition: { duration: 0 } } }
    : { hidden: { opacity: 0, y: 30 }, show: { opacity: 1, y: 0, transition: { duration: 0.6, ease: [0.22, 1, 0.36, 1] as const } } };

  return (
    <motion.div
      ref={root}
      initial="hidden"
      whileInView="show"
      viewport={{ once: true, margin: '-60px' }}
      variants={{ hidden: {}, show: { transition: { staggerChildren: reduced ? 0 : 0.055 } } }}
      style={{ marginTop: 8 }}
    >
      {CAPS.map(([name, desc, tags], i) => (
        <motion.div key={name} variants={item} className="sf-cap-row">
          <span className="sf-cap-idx">{String(i + 1).padStart(2, '0')}</span>
          <span className="sf-cap-name">{name}</span>
          <span className="sf-cap-tags">
            {tags.map((t) => (
              <em key={t}>{t}</em>
            ))}
          </span>
          <span className="sf-cap-desc">
            <span>
              <span>{desc}</span>
            </span>
          </span>
        </motion.div>
      ))}
    </motion.div>
  );
}
