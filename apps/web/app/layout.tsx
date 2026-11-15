import './cinematic.css';
import Nav from './Nav';
import ScrollProgress from './ScrollProgress';
import Cursor from './Cursor';
import ClickFx from './ClickFx';
import PointerGlow from './PointerGlow';
import Footer from './Footer';
import Palette from './Palette';
import RouteCurtain from './RouteCurtain';
import type { ReactNode } from 'react';

export const metadata = {
  title: 'SentinelForge — Predictive IoT Vulnerability Discovery',
  description: 'Find uncatalogued flaws in IoT firmware and live devices, verify patches actually work, and react to new CVEs in minutes.',
};

export const viewport = { themeColor: '#020617' };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    // suppressHydrationWarning on <html>/<body>: browser extensions (Dark
    // Reader, Bitdefender) rewrite the DOM before React hydrates and inject
    // attributes like data-darkreader-* / bis_skin_checked — React 19 reports
    // these as hydration mismatches and recovers by re-rendering the whole
    // root client-side. The suppression is scoped to these elements'
    // attributes, not real content mismatches elsewhere in the tree.
    <html lang="en" suppressHydrationWarning>
      <body className="sf-body" style={{ background: '#020617', color: '#e2e8f0', margin: 0, fontFamily: 'system-ui' }} suppressHydrationWarning>
        <Nav />
        <ScrollProgress />
        <Cursor />
        <ClickFx />
        <PointerGlow />
        {children}
        {/* ambient nebula wash: behind all content, under every canvas */}
        <div className="sf-nebula" aria-hidden>
          <i />
        </div>
        {/* film grain veil: sits over everything (incl. preloader), under the cursor */}
        <div className="sf-grain" aria-hidden />
        <RouteCurtain />
        <Palette />
        <Footer />
      </body>
    </html>
  );
}
