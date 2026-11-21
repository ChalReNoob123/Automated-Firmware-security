'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useFrame, useThree } from '@react-three/fiber';
import * as THREE from 'three';
import { useStory } from '../storyStore';
import { useQuality } from '../quality';

// Round 21 — cinematic post layer, ZERO new dependencies: chromatic
// aberration, film grain, vignette, tone mapping + sRGB handled IN the pass
// (verified against three r185: tone mapping only fires when rendering to the
// DEFAULT framebuffer, so the offscreen chain stays linear HDR and this pass
// reproduces the direct-render look exactly).
//
// Round 25 — the "high post-processing / high antialiasing" pass proper:
//   * a real dual-filter bloom: bright-pass with a soft knee down to a
//     quarter-res target, then a separable 9-tap gaussian ping-pong
//     (horizontal -> vertical -> wider horizontal -> vertical), composited in
//     the grading pass. Replaces round 21's 16-tap in-pass ring bloom, which
//     banded badly under bright sources,
//   * FXAA 3.11-lite folded into the grade pass (luma-driven span blend),
//   * the grading pass keeps velocity chromatic aberration / grain / vignette.
//
// Round 28 — the grade pass learns film: teal-shadow / warm-highlight split
// toning + a gentle S-curve (the "graded footage" look), a more present
// static chromatic aberration, and a deeper vignette.
//
// Round 32 — ULTRA-HD pass. Four additions, all still zero new dependencies:
//   * ANAMORPHIC STREAKS: a wide horizontal 13-tap smear of the already
//     blurred bloom, tinted cold blue and composited additively. This is the
//     single biggest "shot on a big lens" cue — bright emissives now flare
//     sideways instead of just swelling in a circle.
//   * UNSHARP MASK: a 4-tap cross high-pass on the HDR scene fed back at a
//     profile-controlled weight. At 4K this is what keeps wireframes and mono
//     type from reading soft after FXAA and the upscale.
//   * ADAPTIVE RESOLUTION: the render-target pair is measured against a
//     moving frame-time average; sustained frames over ~21 ms step the raster
//     down (never below 0.62x), sustained frames under ~11.5 ms step it back
//     toward native. 4K quality where the machine can hold it, no stutter
//     where it cannot — decided at runtime, not guessed at load.
//   * Profile-driven weights: bloom / streak / grain / sharpen arrive from
//     `useQuality()` (quality.ts) so every canvas grades identically.
//
// Chain (9 draws: 1 scene + 1 quarter-res bright + 4 quarter-res blurs + 1
// streak + 1 fullscreen grade). A positive-priority useFrame subscriber takes
// over rendering from R3F (confirmed in @react-three/fiber's loop).
//
// ANTIALIASING — deliberate architecture decision, live-diagnosed in round
// 25: rendering the scene into an MSAA renderbuffer target and sampling its
// resolved texture produced intermittent solid-black tile artifacts through
// the post chain on this ANGLE/D3D machine (never on direct-to-screen
// renders, never a GL error, not reproducible on demand). The deterministic
// cross-driver path is: NO samples on the scene target, supersample instead
// (Canvas dpr floor >= 1.5 -> the scene rasterizes above display resolution)
// and smooth what remains with FXAA in the grade pass. The direct path (post
// disabled) keeps the context's own antialias.
//
// Capability gate (`usePostOK`): skipped for reduced-motion users, small
// viewports, and low-core/low-memory devices — those render exactly as before.

const VERT = /* glsl */ `
varying vec2 vUv;
void main() {
  vUv = uv;
  gl_Position = vec4(position.xy, 0.0, 1.0);
}
`;

// bright-pass + box downsample: soft-knee threshold keeps midtones out of the
// bloom while letting HDR emissives (>1.0) really bloom
const BRIGHT_FRAG = /* glsl */ `
precision highp float;
varying vec2 vUv;
uniform sampler2D tDiffuse;
uniform vec2 uTexel;
uniform float uThreshold;

void main() {
  // 4-tap box downsample (quarter-res target)
  vec3 c = texture2D(tDiffuse, vUv + uTexel * vec2(-1.0, -1.0)).rgb;
  c += texture2D(tDiffuse, vUv + uTexel * vec2(1.0, -1.0)).rgb;
  c += texture2D(tDiffuse, vUv + uTexel * vec2(-1.0, 1.0)).rgb;
  c += texture2D(tDiffuse, vUv + uTexel * vec2(1.0, 1.0)).rgb;
  c *= 0.25;
  float l = max(max(c.r, c.g), c.b);
  // soft knee: everything below threshold-theta dies, above survives scaled
  float knee = uThreshold * 0.5;
  float soft = clamp(l - uThreshold + knee, 0.0, 2.0 * knee);
  soft = soft * soft / (4.0 * knee + 1e-4);
  float w = max(soft, l - uThreshold) / max(l, 1e-4);
  gl_FragColor = vec4(c * w, 1.0);
}
`;

// separable 9-tap gaussian (5 linear-fetch taps)
const BLUR_FRAG = /* glsl */ `
precision highp float;
varying vec2 vUv;
uniform sampler2D tDiffuse;
uniform vec2 uDir; // texel-space step direction, pre-scaled by radius

void main() {
  vec3 c = texture2D(tDiffuse, vUv).rgb * 0.2270270270;
  vec2 o1 = uDir * 1.3846153846;
  vec2 o2 = uDir * 3.2307692308;
  c += texture2D(tDiffuse, vUv + o1).rgb * 0.3162162162;
  c += texture2D(tDiffuse, vUv - o1).rgb * 0.3162162162;
  c += texture2D(tDiffuse, vUv + o2).rgb * 0.0702702703;
  c += texture2D(tDiffuse, vUv - o2).rgb * 0.0702702703;
  gl_FragColor = vec4(c, 1.0);
}
`;

// round 32: anamorphic streak — 13 exponential-weighted taps spread far apart
// on the HORIZONTAL axis only, with a whisper of vertical spread so the flare
// has thickness. Fed by the blurred bloom, so only genuinely bright pixels
// produce a streak. One draw, quarter res.
const STREAK_FRAG = /* glsl */ `
precision highp float;
varying vec2 vUv;
uniform sampler2D tDiffuse;
uniform vec2 uTexel;
uniform float uSpread;

void main() {
  vec3 c = vec3(0.0);
  float wsum = 0.0;
  for (int i = -6; i <= 6; i++) {
    float fi = float(i);
    float w = exp(-abs(fi) * 0.40);
    vec2 o = vec2(uTexel.x * fi * uSpread, uTexel.y * fi * 0.14);
    c += texture2D(tDiffuse, vUv + o).rgb * w;
    wsum += w;
  }
  gl_FragColor = vec4(c / wsum, 1.0);
}
`;

const GRADE_FRAG = /* glsl */ `
precision highp float;
varying vec2 vUv;
uniform sampler2D tDiffuse;
uniform sampler2D tBloom;
uniform sampler2D tStreak;
uniform vec2 uRes;
uniform vec2 uTexel;
uniform float uTime;
uniform float uVel;
uniform float uBloom;
uniform float uStreak;
uniform float uSharpen;
uniform float uGrain;

float hash(vec2 p) {
  return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123);
}

float luma(vec3 c) {
  return dot(c, vec3(0.299, 0.587, 0.114));
}

vec3 tex(vec2 uv) {
  return texture2D(tDiffuse, uv).rgb;
}

// FXAA 3.11-lite: luma-driven edge span blend on the scene target
vec3 fxaa(vec2 uv) {
  vec3 rgbNW = tex(uv + uTexel * vec2(-1.0, -1.0));
  vec3 rgbNE = tex(uv + uTexel * vec2(1.0, -1.0));
  vec3 rgbSW = tex(uv + uTexel * vec2(-1.0, 1.0));
  vec3 rgbSE = tex(uv + uTexel * vec2(1.0, 1.0));
  vec3 rgbM = tex(uv);
  float lNW = luma(rgbNW);
  float lNE = luma(rgbNE);
  float lSW = luma(rgbSW);
  float lSE = luma(rgbSE);
  float lM = luma(rgbM);
  float lMin = min(lM, min(min(lNW, lNE), min(lSW, lSE)));
  float lMax = max(lM, max(max(lNW, lNE), max(lSW, lSE)));
  // flat region: no work
  if (lMax - lMin < 0.026) return rgbM;
  vec2 dir;
  dir.x = -((lNW + lNE) - (lSW + lSE));
  dir.y = ((lNW + lSW) - (lNE + lSE));
  float dirReduce = max((lNW + lNE + lSW + lSE) * 0.25 * (1.0 / 8.0), 1.0 / 128.0);
  float rcpDirMin = 1.0 / (min(abs(dir.x), abs(dir.y)) + dirReduce);
  dir = clamp(dir * rcpDirMin, vec2(-8.0), vec2(8.0)) * uTexel;
  vec3 rgbA = 0.5 * (tex(uv + dir * (1.0 / 3.0 - 0.5)) + tex(uv + dir * (2.0 / 3.0 - 0.5)));
  vec3 rgbB = rgbA * 0.5 + 0.25 * (tex(uv + dir * -0.5) + tex(uv + dir * 0.5));
  float lB = luma(rgbB);
  if (lB < lMin || lB > lMax) return rgbA;
  return rgbB;
}

void main() {
  vec2 uv = vUv;

  // FXAA base, then a 4-tap unsharp mask for 4K perceived resolution.
  vec3 fx = fxaa(uv);
  if (uSharpen > 0.001) {
    vec3 cross = tex(uv + vec2(uTexel.x, 0.0)) + tex(uv - vec2(uTexel.x, 0.0))
               + tex(uv + vec2(0.0, uTexel.y)) + tex(uv - vec2(0.0, uTexel.y));
    // high-pass = centre - mean(neighbours); scaled small so emissives never halo
    fx += (fx - cross * 0.25) * uSharpen;
  }

  // radial chromatic aberration — R and B split along the vector from center,
  // opening further with motion (the R/B fringe taps stay raw — they only
  // open up in motion, where a little sparkle reads as speed, not aliasing).
  float ca = 0.0016 + uVel * 0.0042;
  vec2 dir = uv - 0.5;
  vec2 off = dir * dot(dir, dir) * ca * 14.0;
  vec3 col = vec3(
    texture2D(tDiffuse, uv + off).r,
    fx.g,
    texture2D(tDiffuse, uv - off).b
  );

  // dual-filter bloom composited on top (bloom target already blurred)
  vec3 bl = texture2D(tBloom, uv).rgb;
  col += bl * uBloom * (0.85 + uVel * 1.1);

  // round 32: anamorphic streak — cold blue horizontal flare riding on top of
  // the bloom and breathing with velocity, exactly like a fast anamorphic lens.
  vec3 st = texture2D(tStreak, uv).rgb;
  col += st * vec3(0.42, 0.78, 1.0) * uStreak * (0.9 + uVel * 1.6);

  // animated film grain (re-hashed every frame)
  float g = hash(uv * uRes + fract(uTime * 61.7) * 191.3) - 0.5;
  col += g * uGrain;

  // round 28: filmic split-tone — teal shadows, warm highlights — plus a
  // gentle S-curve for contrast. After the grain (which stays neutral
  // sparkle) and before the vignette (whose falloff then rides the grade).
  float l = clamp(luma(col), 0.0, 1.0);
  col *= mix(vec3(0.88, 1.0, 1.05), vec3(1.045, 1.0, 0.95), smoothstep(0.0, 0.72, l));
  vec3 s = clamp(col, 0.0, 1.0);
  col = mix(col, s * s * (3.0 - 2.0 * s), 0.16);

  // vignette (round 28: 0.38 -> 0.46, start pulled in)
  float d = length((uv - 0.5) * vec2(1.22, 1.0));
  col *= 1.0 - smoothstep(0.48, 1.05, d) * 0.46;

  gl_FragColor = vec4(max(col, 0.0), 1.0);
  // the direct render's look: renderer tone mapping (ACES) then sRGB encode
  #include <tonemapping_fragment>
  #include <colorspace_fragment>
}
`;

// Capability gate, now a thin view over the shared quality engine so every
// canvas agrees: returns false until mounted (SSR-safe) and false whenever the
// device is reduced-motion, small, or weak.
export function usePostOK(): boolean {
  return useQuality().post;
}

function fullscreenPass(geo: THREE.BufferGeometry, frag: string, uniforms: Record<string, THREE.IUniform>) {
  const mat = new THREE.ShaderMaterial({
    vertexShader: VERT,
    fragmentShader: frag,
    uniforms,
    depthTest: false,
    depthWrite: false,
  });
  const renderScene = new THREE.Scene();
  renderScene.add(new THREE.Mesh(geo, mat));
  return { mat, renderScene, cam: new THREE.Camera() };
}

export default function PostFX({
  bloom = 0.62,
  grain = 0.05,
  streak = 0.4,
  sharpen = 0.25,
}: {
  bloom?: number;
  grain?: number;
  streak?: number;
  sharpen?: number;
}) {
  const gl = useThree((s) => s.gl);
  const scene = useThree((s) => s.scene);
  const camera = useThree((s) => s.camera);
  const size = useThree((s) => s.size);
  const dpr = useThree((s) => s.viewport.dpr);

  // adaptive raster scale: 1 = full profile resolution, floor 0.62. Bumped
  // down/up only on threshold crossings, so targets are recreated rarely.
  const [resScale, setResScale] = useState(1);

  // smoothed motion energy 0..1: fast attack, slow settle
  const vel = useRef(0);
  const target = useRef(0);
  const lastP = useRef(0);
  // rolling frame-time window for adaptive resolution
  const perf = useRef({ frames: 0, acc: 0 });

  useEffect(() => {
    let lx = 0;
    let ly = 0;
    let lt = performance.now();
    const move = (e: PointerEvent) => {
      const now = performance.now();
      const dt = Math.max(8, now - lt);
      const d = Math.hypot(e.clientX - lx, e.clientY - ly);
      target.current = Math.min(1, target.current + d / dt / 2.2);
      lx = e.clientX;
      ly = e.clientY;
      lt = now;
    };
    let lastScroll = window.scrollY;
    const onScroll = () => {
      target.current = Math.min(1, target.current + Math.abs(window.scrollY - lastScroll) / 700);
      lastScroll = window.scrollY;
    };
    window.addEventListener('pointermove', move, { passive: true });
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('scroll', onScroll);
    };
  }, []);

  // shared fullscreen triangle (no camera math — raw clip space)
  const { geo, passes } = useMemo(() => {
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(new Float32Array([-1, -1, 0, 3, -1, 0, -1, 3, 0]), 3));
    g.setAttribute('uv', new THREE.BufferAttribute(new Float32Array([0, 0, 2, 0, 0, 2]), 2));
    return {
      geo: g,
      passes: {
        bright: fullscreenPass(g, BRIGHT_FRAG, {
          tDiffuse: { value: null },
          uTexel: { value: new THREE.Vector2() },
          uThreshold: { value: 0.62 },
        }),
        blur: fullscreenPass(g, BLUR_FRAG, {
          tDiffuse: { value: null },
          uDir: { value: new THREE.Vector2() },
        }),
        streak: fullscreenPass(g, STREAK_FRAG, {
          tDiffuse: { value: null },
          uTexel: { value: new THREE.Vector2() },
          uSpread: { value: 9.5 },
        }),
        grade: fullscreenPass(g, GRADE_FRAG, {
          tDiffuse: { value: null },
          tBloom: { value: null },
          tStreak: { value: null },
          uRes: { value: new THREE.Vector2(2, 2) },
          uTexel: { value: new THREE.Vector2(1 / 2, 1 / 2) },
          uTime: { value: 0 },
          uVel: { value: 0 },
          uBloom: { value: bloom },
          uStreak: { value: streak },
          uSharpen: { value: sharpen },
          uGrain: { value: grain },
        }),
      },
    };
  }, [bloom, grain, streak, sharpen]);

  // live weight updates (profile can settle after mount) without rebuilding
  useEffect(() => {
    passes.grade.mat.uniforms.uBloom.value = bloom;
    passes.grade.mat.uniforms.uGrain.value = grain;
    passes.grade.mat.uniforms.uStreak.value = streak;
    passes.grade.mat.uniforms.uSharpen.value = sharpen;
  }, [passes, bloom, grain, streak, sharpen]);

  useEffect(
    () => () => {
      geo.dispose();
      for (const p of Object.values(passes)) p.mat.dispose();
    },
    [geo, passes]
  );

  // targets: scene (linear HDR, NO driver MSAA — see header) + bloom ping-pong
  // at quarter res + a streak target at the same quarter res — recreated on
  // resize and on adaptive-scale changes. Filters pinned to Linear and mipmaps
  // off so no incomplete-pyramid sampling is possible.
  const rts = useRef<{
    scene?: THREE.WebGLRenderTarget;
    a?: THREE.WebGLRenderTarget;
    b?: THREE.WebGLRenderTarget;
    streak?: THREE.WebGLRenderTarget;
  }>({});
  useEffect(() => {
    const w = Math.max(2, Math.round(size.width * dpr * resScale));
    const h = Math.max(2, Math.round(size.height * dpr * resScale));
    const nextScene = new THREE.WebGLRenderTarget(w, h, {
      type: THREE.HalfFloatType,
      minFilter: THREE.LinearFilter,
      magFilter: THREE.LinearFilter,
      generateMipmaps: false,
    });
    const bw = Math.max(2, Math.round(w / 4));
    const bh = Math.max(2, Math.round(h / 4));
    const mk = (width: number, height: number) =>
      new THREE.WebGLRenderTarget(width, height, {
        type: THREE.HalfFloatType,
        depthBuffer: false,
        minFilter: THREE.LinearFilter,
        magFilter: THREE.LinearFilter,
        generateMipmaps: false,
      });
    const nextA = mk(bw, bh);
    const nextB = mk(bw, bh);
    const nextStreak = mk(bw, bh);
    for (const old of [rts.current.scene, rts.current.a, rts.current.b, rts.current.streak]) old?.dispose();
    rts.current = { scene: nextScene, a: nextA, b: nextB, streak: nextStreak };
    passes.grade.mat.uniforms.uRes.value.set(w, h);
    passes.grade.mat.uniforms.uTexel.value.set(1 / w, 1 / h);
    passes.bright.mat.uniforms.uTexel.value.set(1 / w, 1 / h);
    passes.streak.mat.uniforms.uTexel.value.set(1 / bw, 1 / bh);
    return () => {
      for (const t of [nextScene, nextA, nextB, nextStreak]) t.dispose();
      if (rts.current.scene === nextScene) rts.current = {};
    };
  }, [size.width, size.height, dpr, resScale, gl, passes]);
  useEffect(() => () => {
    for (const t of [rts.current.scene, rts.current.a, rts.current.b, rts.current.streak]) t?.dispose();
    rts.current = {};
  }, []);

  useFrame((state, delta) => {
    const { scene: sceneRT, a: bloomA, b: bloomB, streak: streakRT } = rts.current;
    if (!sceneRT || !bloomA || !bloomB || !streakRT) return;

    // motion energy: pointer/scroll targets decay here; story scrub adds directly
    const p = useStory.getState().p;
    const dp = Math.abs(p - lastP.current);
    lastP.current = p;
    if (dp > 0) target.current = Math.min(1, target.current + dp * 5);
    target.current *= 0.88;
    vel.current += (target.current - vel.current) * (target.current > vel.current ? 0.3 : 0.07);

    // pass 1: scene → linear HDR target
    gl.setRenderTarget(sceneRT);
    gl.render(scene, camera);

    // pass 2: bright-pass + downsample → quarter-res
    passes.bright.mat.uniforms.tDiffuse.value = sceneRT.texture;
    gl.setRenderTarget(bloomA);
    gl.render(passes.bright.renderScene, passes.bright.cam);

    // passes 3-6: separable gaussian ping-pong, second iteration ~2.6× wider
    const blur = passes.blur.mat.uniforms;
    const bw = bloomA.width;
    const bh = bloomA.height;
    blur.tDiffuse.value = bloomA.texture;
    blur.uDir.value.set(1 / bw, 0);
    gl.setRenderTarget(bloomB);
    gl.render(passes.blur.renderScene, passes.blur.cam);
    blur.tDiffuse.value = bloomB.texture;
    blur.uDir.value.set(0, 1 / bh);
    gl.setRenderTarget(bloomA);
    gl.render(passes.blur.renderScene, passes.blur.cam);
    blur.tDiffuse.value = bloomA.texture;
    blur.uDir.value.set(2.6 / bw, 0);
    gl.setRenderTarget(bloomB);
    gl.render(passes.blur.renderScene, passes.blur.cam);
    blur.tDiffuse.value = bloomB.texture;
    blur.uDir.value.set(0, 2.6 / bh);
    gl.setRenderTarget(bloomA);
    gl.render(passes.blur.renderScene, passes.blur.cam);

    // pass 7: anamorphic streak from the blurred bloom → streak target
    const sk = passes.streak.mat.uniforms;
    sk.tDiffuse.value = bloomA.texture;
    sk.uTexel.value.set(1 / bw, 1 / bh);
    gl.setRenderTarget(streakRT);
    gl.render(passes.streak.renderScene, passes.streak.cam);

    // pass 8: grade (FXAA + sharpen + CA + bloom + streak + grain + vignette)
    // + tone map + sRGB
    const u = passes.grade.mat.uniforms;
    u.uTime.value = state.clock.elapsedTime;
    u.uVel.value = vel.current;
    u.tDiffuse.value = sceneRT.texture;
    u.tBloom.value = bloomA.texture;
    u.tStreak.value = streakRT.texture;
    gl.setRenderTarget(null);
    gl.render(passes.grade.renderScene, passes.grade.cam);

    // adaptive resolution: a 72-frame rolling average decides at ~2.6 s
    // intervals. Falling over 21 ms (≈48 fps) sheds 10% of the raster; holding
    // under 11.5 ms (≈87 fps) with headroom earns 6% back. Hysteresis is wide
    // on purpose — a single GC hitch must never trigger a resize cascade.
    const pf = perf.current;
    pf.frames += 1;
    pf.acc += Math.min(64, delta * 1000);
    if (pf.frames >= 72) {
      const avg = pf.acc / pf.frames;
      pf.frames = 0;
      pf.acc = 0;
      setResScale((s) => {
        if (avg > 21 && s > 0.62) return Math.max(0.62, Math.round((s - 0.1) * 100) / 100);
        if (avg < 11.5 && s < 1) return Math.min(1, Math.round((s + 0.06) * 100) / 100);
        return s;
      });
    }
  }, 1);

  return null;
}
