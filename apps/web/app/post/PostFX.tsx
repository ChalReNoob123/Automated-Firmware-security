'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useFrame, useThree } from '@react-three/fiber';
import * as THREE from 'three';
import { useStory } from '../storyStore';

// Round 21 — cinematic post layer, ZERO new dependencies: chromatic
// aberration, film grain, vignette, tone mapping + sRGB handled IN the pass
// (verified against three r185: tone mapping only fires when rendering to the
// DEFAULT framebuffer, so the offscreen chain stays linear HDR and this pass
// reproduces the direct-render look exactly).
//
// Round 25 — the "high post-processing / high antialiasing" pass proper:
//   * a real dual-filter bloom: bright-pass with a soft knee down to a
//     quarter-res target, then a separable 9-tap gaussian ping-pong
//     (horizontal → vertical → wider horizontal → vertical), composited in
//     the grading pass. Replaces round 21's 16-tap in-pass ring bloom, which
//     banded badly under bright sources,
//   * FXAA 3.11-lite folded into the grade pass (luma-driven span blend),
//   * the grading pass keeps velocity chromatic aberration / grain / vignette.
//
// Chain (7 draws: 1 scene + 1 quarter-res bright + 4 quarter-res blurs + 1
// fullscreen grade). A positive-priority useFrame subscriber takes over
// rendering from R3F (confirmed in @react-three/fiber's loop).
//
// ANTIALIASING — deliberate architecture decision, live-diagnosed in round
// 25: rendering the scene into an MSAA renderbuffer target and sampling its
// resolved texture produced intermittent solid-black tile artifacts through
// the post chain on this ANGLE/D3D machine (never on direct-to-screen
// renders, never a GL error, not reproducible on demand). The deterministic
// cross-driver path is: NO samples on the scene target, supersample instead
// (Canvas dpr floor 1.5 → the scene rasterizes at ≥1.5× display resolution)
// and smooth what remains with FXAA in the grade pass. The direct path
// (post disabled) keeps the context's own antialias.
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

const GRADE_FRAG = /* glsl */ `
precision highp float;
varying vec2 vUv;
uniform sampler2D tDiffuse;
uniform sampler2D tBloom;
uniform vec2 uRes;
uniform vec2 uTexel;
uniform float uTime;
uniform float uVel;
uniform float uBloom;
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

// radial chromatic aberration — R and B split along the vector from center
vec3 sampleCA(vec2 uv, float amt) {
  vec2 dir = uv - 0.5;
  vec2 off = dir * dot(dir, dir) * amt * 14.0;
  return vec3(
    texture2D(tDiffuse, uv + off).r,
    texture2D(tDiffuse, uv).g,
    texture2D(tDiffuse, uv - off).b
  );
}

void main() {
  vec2 uv = vUv;

  // FXAA-blended base, then velocity chromatic aberration on top (the R/B
  // fringe taps stay raw — they only open up in motion, where a little
  // sparkle reads as speed, not aliasing)
  float ca = 0.0011 + uVel * 0.0042;
  vec2 dir = uv - 0.5;
  vec2 off = dir * dot(dir, dir) * ca * 14.0;
  vec3 fx = fxaa(uv);
  vec3 col = vec3(
    texture2D(tDiffuse, uv + off).r,
    fx.g,
    texture2D(tDiffuse, uv - off).b
  );

  // dual-filter bloom composited on top (bloom target already blurred)
  vec3 bl = texture2D(tBloom, uv).rgb;
  col += bl * uBloom * (0.85 + uVel * 1.1);

  // animated film grain (re-hashed every frame)
  float g = hash(uv * uRes + fract(uTime * 61.7) * 191.3) - 0.5;
  col += g * uGrain;

  // vignette
  float d = length((uv - 0.5) * vec2(1.22, 1.0));
  col *= 1.0 - smoothstep(0.52, 1.08, d) * 0.38;

  gl_FragColor = vec4(max(col, 0.0), 1.0);
  // the direct render's look: renderer tone mapping (ACES) then sRGB encode
  #include <tonemapping_fragment>
  #include <colorspace_fragment>
}
`;

// Client-side capability gate. Returns false until mounted (so SSR renders
// nothing and the scenes' first frames are never post-processed mid-hydration).
export function usePostOK(): boolean {
  const [ok, setOk] = useState(false);
  useEffect(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const small = window.innerWidth < 900;
    const nav = navigator as Navigator & { deviceMemory?: number };
    const weak = (navigator.hardwareConcurrency ?? 8) <= 4 || (nav.deviceMemory ?? 8) <= 4;
    setOk(!reduced && !small && !weak);
  }, []);
  return ok;
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

export default function PostFX({ bloom = 0.62, grain = 0.05 }: { bloom?: number; grain?: number }) {
  const gl = useThree((s) => s.gl);
  const scene = useThree((s) => s.scene);
  const camera = useThree((s) => s.camera);
  const size = useThree((s) => s.size);
  const dpr = useThree((s) => s.viewport.dpr);

  // smoothed motion energy 0..1: fast attack, slow settle
  const vel = useRef(0);
  const target = useRef(0);
  const lastP = useRef(0);

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
        grade: fullscreenPass(g, GRADE_FRAG, {
          tDiffuse: { value: null },
          tBloom: { value: null },
          uRes: { value: new THREE.Vector2(2, 2) },
          uTexel: { value: new THREE.Vector2(1 / 2, 1 / 2) },
          uTime: { value: 0 },
          uVel: { value: 0 },
          uBloom: { value: bloom },
          uGrain: { value: grain },
        }),
      },
    };
  }, [bloom, grain]);
  useEffect(() => () => {
    geo.dispose();
    for (const p of Object.values(passes)) p.mat.dispose();
  }, [geo, passes]);

  // targets: scene (linear HDR, NO driver MSAA — see header) + bloom ping-pong
  // at quarter res — recreated on resize. Filters pinned to Linear and
  // mipmaps off so no incomplete-pyramid sampling is possible.
  const rts = useRef<{ scene?: THREE.WebGLRenderTarget; a?: THREE.WebGLRenderTarget; b?: THREE.WebGLRenderTarget }>({});
  useEffect(() => {
    const w = Math.max(2, Math.round(size.width * dpr));
    const h = Math.max(2, Math.round(size.height * dpr));
    const nextScene = new THREE.WebGLRenderTarget(w, h, {
      type: THREE.HalfFloatType,
      minFilter: THREE.LinearFilter,
      magFilter: THREE.LinearFilter,
      generateMipmaps: false,
    });
    const bw = Math.max(2, Math.round(w / 4));
    const bh = Math.max(2, Math.round(h / 4));
    const nextA = new THREE.WebGLRenderTarget(bw, bh, {
      type: THREE.HalfFloatType,
      depthBuffer: false,
      minFilter: THREE.LinearFilter,
      magFilter: THREE.LinearFilter,
      generateMipmaps: false,
    });
    const nextB = new THREE.WebGLRenderTarget(bw, bh, {
      type: THREE.HalfFloatType,
      depthBuffer: false,
      minFilter: THREE.LinearFilter,
      magFilter: THREE.LinearFilter,
      generateMipmaps: false,
    });
    for (const old of [rts.current.scene, rts.current.a, rts.current.b]) old?.dispose();
    rts.current = { scene: nextScene, a: nextA, b: nextB };
    passes.grade.mat.uniforms.uRes.value.set(w, h);
    passes.grade.mat.uniforms.uTexel.value.set(1 / w, 1 / h);
    passes.bright.mat.uniforms.uTexel.value.set(1 / w, 1 / h);
    return () => {
      for (const t of [nextScene, nextA, nextB]) t.dispose();
      if (rts.current.scene === nextScene) rts.current = {};
    };
  }, [size.width, size.height, dpr, gl, passes]);
  useEffect(() => () => {
    for (const t of [rts.current.scene, rts.current.a, rts.current.b]) t?.dispose();
    rts.current = {};
  }, []);

  useFrame((state) => {
    const { scene: sceneRT, a: bloomA, b: bloomB } = rts.current;
    if (!sceneRT || !bloomA || !bloomB) return;

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

    // pass 7: grade (FXAA + CA + bloom + grain + vignette) + tone map + sRGB
    const u = passes.grade.mat.uniforms;
    u.uTime.value = state.clock.elapsedTime;
    u.uVel.value = vel.current;
    u.tDiffuse.value = sceneRT.texture;
    u.tBloom.value = bloomA.texture;
    gl.setRenderTarget(null);
    gl.render(passes.grade.renderScene, passes.grade.cam);
  }, 1);

  return null;
}
