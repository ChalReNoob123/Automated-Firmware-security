'use client';
import { useEffect, useState } from 'react';

// Round 32 — ULTRA-HD QUALITY ENGINE.
// One source of truth for "how much picture can this machine actually show?".
// Everything that costs pixels (WebGL dpr, post-processing strength, particle
// counts, 2D canvas bake resolution) reads a profile from here instead of
// inventing its own heuristics — so a 4K workstation gets a 4K-class raster
// while a phone or a reduced-motion user gets a profile that stays smooth.
//
// The tier is scored from FOUR independent signals, because any single one
// lies: hardwareConcurrency is spoofed/absent in some browsers, deviceMemory
// is Chromium-only, devicePixelRatio is 1 on plenty of 4K desktops whose OS
// runs at 100% scale, and the GPU string is the only way to catch software
// rasterizers (SwiftShader/llvmpipe) that report eight cores and 8 GB while
// painting in the CPU. Physical pixels (CSS size x dpr²) is the honest
// measure of the raster target, so a 3840-wide window counts as 4K whether it
// got there from 3840 CSS px or 1920 CSS px at dpr 2.

export type QualityTier = 'ultra' | 'high' | 'standard' | 'low';

export type QualityProfile = {
  tier: QualityTier;
  /** short instrument label, e.g. "4K ULTRA" */
  label: string;
  /** [floor, ceiling] device-pixel-ratio handed to <Canvas dpr> */
  dpr: [number, number];
  /** full post chain (bloom + streaks + grade) allowed */
  post: boolean;
  /** anamorphic streak weight, 0 disables the pass visually */
  streak: number;
  /** bloom composite weight */
  bloom: number;
  /** film-grain amplitude */
  grain: number;
  /** unsharp-mask amount (perceived resolution) */
  sharpen: number;
  /** multiplier for particle/star counts */
  particles: number;
  /** 2D canvas bake resolution ceiling */
  bakeDpr: number;
};

// The pre-mount profile. Deliberately the cheap one: SSR paints nothing that
// depends on capability, and the first client frame is never the expensive one.
export const SAFE_PROFILE: QualityProfile = {
  tier: 'standard',
  label: 'HD',
  dpr: [1.5, 2],
  post: false,
  streak: 0,
  bloom: 0.55,
  grain: 0.05,
  sharpen: 0.15,
  particles: 0.9,
  bakeDpr: 2,
};

const PROFILES: Record<QualityTier, QualityProfile> = {
  ultra: {
    tier: 'ultra',
    label: '4K ULTRA',
    dpr: [2, 2.5],
    post: true,
    streak: 0.55,
    bloom: 0.74,
    grain: 0.034,
    sharpen: 0.34,
    particles: 1.4,
    bakeDpr: 2.5,
  },
  high: {
    tier: 'high',
    label: 'QHD+',
    dpr: [1.75, 2.25],
    post: true,
    streak: 0.42,
    bloom: 0.64,
    grain: 0.042,
    sharpen: 0.26,
    particles: 1.15,
    bakeDpr: 2.25,
  },
  standard: {
    tier: 'standard',
    label: 'HD',
    dpr: [1.5, 2],
    post: true,
    streak: 0.26,
    bloom: 0.56,
    grain: 0.05,
    sharpen: 0.16,
    particles: 1,
    bakeDpr: 2,
  },
  low: {
    tier: 'low',
    label: 'ECO',
    dpr: [1, 1.5],
    post: false,
    streak: 0,
    bloom: 0.5,
    grain: 0.05,
    sharpen: 0,
    particles: 0.7,
    bakeDpr: 1.5,
  },
};

// Best-effort GPU name. Never throws: a missing WebGL context, a blocked
// extension or a hardened browser all just return ''.
function gpuName(): string {
  try {
    const c = document.createElement('canvas');
    const gl = (c.getContext('webgl2') ?? c.getContext('webgl')) as WebGLRenderingContext | null;
    if (!gl) return '';
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    const name = ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) ?? '') : '';
    // release the probe context immediately — browsers cap live contexts
    gl.getExtension('WEBGL_lose_context')?.loseContext();
    return name;
  } catch {
    return '';
  }
}

export function detectQuality(): QualityProfile {
  if (typeof window === 'undefined') return SAFE_PROFILE;
  // Accessibility wins over every other signal: no post, no streaks, the
  // cheap dpr range. The CSS layer is separately gated by media queries.
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return PROFILES.low;

  const nav = navigator as Navigator & { deviceMemory?: number };
  const cores = nav.hardwareConcurrency ?? 4;
  const mem = nav.deviceMemory ?? 4;
  const dpr = window.devicePixelRatio || 1;
  const cssPx = Math.max(1, window.innerWidth) * Math.max(1, window.innerHeight);
  const physical = cssPx * dpr * dpr; // raster target in device pixels
  const small = window.innerWidth < 900;
  const software = /swiftshader|llvmpipe|software|basic render/i.test(gpuName());

  let score = 0;
  score += cores >= 12 ? 3 : cores >= 8 ? 2 : cores >= 6 ? 1 : 0;
  score += mem >= 8 ? 2 : mem >= 4 ? 1 : 0;
  score += dpr >= 1.75 ? 2 : dpr >= 1.25 ? 1 : 0;
  // 4K raster (8.3 Mpx) is the top band; 1440p-class (3.7 Mpx) the middle.
  score += physical >= 3840 * 2160 ? 2 : physical >= 2560 * 1440 ? 1 : 0;
  if (software) score -= 3;
  if (small) score -= 1;

  const tier: QualityTier = score >= 6 ? 'ultra' : score >= 4 ? 'high' : score >= 2 ? 'standard' : 'low';
  const profile = PROFILES[tier];
  // A phone-sized viewport never needs 4K bloom — cap the ceiling so a
  // high-dpr handset doesn't silently rasterize 3x of 900px.
  if (small) return { ...profile, dpr: [Math.min(profile.dpr[0], 1.75), Math.min(profile.dpr[1], 2)] };
  return profile;
}

// Stable per-mount profile. Detection runs once after hydration (never during
// render — it touches navigator/window), so SSR and the first client frame
// agree with SAFE_PROFILE and there is no hydration mismatch.
export function useQuality(): QualityProfile {
  const [profile, setProfile] = useState<QualityProfile>(SAFE_PROFILE);
  useEffect(() => {
    setProfile(detectQuality());
  }, []);
  return profile;
}
