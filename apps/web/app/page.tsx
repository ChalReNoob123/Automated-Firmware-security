import HeroClient from './HeroClient';
import Showcase from './Showcase';
import ProveSection from './ProveSection';

export default function Page() {
  return (
    <div className="sf-fade-in">
      <HeroClient />
      <Showcase />
      {/* round-17: the closing headline is a scroll-scrubbed weight wave */}
      <ProveSection />
    </div>
  );
}
