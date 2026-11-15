'use client';
import { useEffect, useState } from 'react';
import Preloader from './Preloader';
import StoryStage from './StoryStage';

// Lusion-style landing composition: a once-per-session calibration preloader,
// then the pinned 480vh scroll story (WebGL ensemble + four copy acts).
//
// Round 12 hardening: `next/dynamic` with `ssr: false` was replaced by a
// plain client-side mount guard. The dynamic-SSR-false path relies on a
// streaming Suspense boundary that emits a "Switched to client rendering"
// error segment server-side and depends on the client runtime re-rendering
// that boundary after hydration — which we observed getting stuck pending
// forever (loading fallback visible, real stage trapped in a hidden segment)
// in an occluded window. The guard below is behaviorally identical (SSR
// paints the designed fallback, the stage mounts right after hydration,
// effects fire even in background windows) and has no Suspense machinery
// left to stall.
function StageFallback() {
  return (
    <header
      aria-busy="true"
      style={{
        height: '100vh',
        minHeight: 560,
        position: 'relative',
        overflow: 'hidden',
        background: 'radial-gradient(ellipse 60% 50% at 50% 40%, rgba(34,211,238,0.09), transparent 70%), #020617',
      }}
    >
      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', textAlign: 'center', padding: '0 24px' }}>
        <p className="sf-act-eyebrow">ACT 01 · THE FIRMWARE</p>
        <h1 className="sf-act-title sf-gradient-text" style={{ margin: '10px 0 12px' }}>
          Every device hides a story.
        </h1>
        <p className="sf-act-body" style={{ maxWidth: 560 }}>
          A camera, a router, a sensor board — each ships with code nobody reads. We read it.
        </p>
      </div>
      <div className="sf-story-cue" style={{ opacity: 0.7 }}>
        <span className="sf-story-cue-line" />
        scroll to explore
      </div>
    </header>
  );
}

export default function HeroClient() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
  }, []);
  return (
    <>
      <Preloader />
      {mounted ? <StoryStage /> : <StageFallback />}
    </>
  );
}
