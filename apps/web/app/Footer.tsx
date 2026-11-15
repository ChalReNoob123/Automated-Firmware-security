// Mega footer, award-site style: a giant outlined wordmark moment, numbered
// quick links, and an honest colophon. Server component — the wordmark drift
// is a small client island (FooterMark); link motion stays pure CSS, gated
// under reduced motion.
import FooterMark from './FooterMark';

const LINKS: [string, string][] = [
  ['Forge', '/'],
  ['Dashboard', '/dashboard'],
  ['Devices', '/devices'],
  ['Device Lab', '/lab'],
  ['Emulator', '/emulator'],
  ['Attack Sim', '/attacks'],
  ['Radar', '/radar'],
  ['Reports', '/reports'],
  ['Copilot', '/copilot'],
];

export default function Footer() {
  return (
    <footer className="sf-footer">
      <FooterMark />
      <nav className="sf-footer-links" aria-label="Footer">
        {LINKS.map(([label, href], i) => (
          <a key={href} href={href}>
            <em>{String(i + 1).padStart(2, '0')}</em>
            {label}
          </a>
        ))}
      </nav>
      <div className="sf-footer-base">
        <span>SENTINELFORGE v3 · dark-ops build</span>
        <span>attestation-gated · isolated workloads · reproducible findings</span>
      </div>
    </footer>
  );
}
