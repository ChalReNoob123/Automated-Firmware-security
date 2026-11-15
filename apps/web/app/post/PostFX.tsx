'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useFrame, useThree } from '@react-three/fiber';
import * as THREE from 'three';
import { useStory } from '../storyStore';

// Round 21 — cinematic post layer, ZERO new dependencies. A single fullscreen
// pass that reproduces the lusion/awwwards look the scenes were missing:
//
//   chromatic aberration (scales with pointer/scroll/scrub velocity — the image
//     "splits" when the scene is in motion, settles when it rests),
//   cheap dual-ring bloom picked from HDR-emissive values,
//   animated film grain,
//   corner vignette.
//
// Render chain (verified against the installed three r185 source): tone
// mapping + sRGB conversion only happen when rendering to the DEFAULT
// framebuffer, so scene→render-target stays linear HDR, and THIS pass applies
// tone mapping (the renderer's own ACES via the injected `toneMapping()`)
// + linear→sRGB at the end — the identical look the direct render produced,
// plus effects. A positive-priority useFrame subscriber takes over rendering
// from R3F (confirmed in @react-three/fiber's loop), which is what makes the
// two-pass chain possible.
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

const FRAG = /* glsl */ `
precision highp float;
varying vec2 vUv;
uniform sampler2D tDiffuse;
uniform vec2 uRes;
uniform float uTime;
uniform float uVel;
uniform float uBloom;
uniform float uGrain;

float hash(vec2 p) {
  return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123);
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

  // base split + velocity kick
  float ca = 0.0011 + uVel * 0.0042;
  vec3 col = sampleCA(uv, ca);

  // cheap HDR bloom: bright-pass then two 8-tap rings (inner sharp, outer wide)
  vec3 bl = vec3(0.0);
  vec2 px = 1.7 / uRes;
  for (int i = 0; i < 8; i++) {
    float a = float(i) * 0.7853981634;
    vec2 o = vec2(cos(a), sin(a)) * px * (1.0 + uVel * 1.4);
    bl += max(texture2D(tDiffuse, uv + o).rgb - 0.55, 0.0);
  }
  px *= 3.2;
  for (int i = 0; i < 8; i++) {
    float a = float(i) * 0.7853981634 + 0.3927;
    vec2 o = vec2(cos(a), sin(a)) * px;
    bl += max(texture2D(tDiffuse, uv + o).rgb - 0.55, 0.0) * 0.7;
  }
  col += bl * (uBloom / 8.0) * (0.85 + uVel * 1.1);

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

export default function PostFX({ bloom = 0.55, grain = 0.05 }: { bloom?: number; grain?: number }) {
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

  // fullscreen triangle (no camera math — raw clip space)
  const quad = useMemo(() => {
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(new Float32Array([-1, -1, 0, 3, -1, 0, -1, 3, 0]), 3));
    geo.setAttribute('uv', new THREE.BufferAttribute(new Float32Array([0, 0, 2, 0, 0, 2]), 2));
    const mat = new THREE.ShaderMaterial({
      vertexShader: VERT,
      fragmentShader: FRAG,
      uniforms: {
        tDiffuse: { value: null },
        uRes: { value: new THREE.Vector2(2, 2) },
        uTime: { value: 0 },
        uVel: { value: 0 },
        uBloom: { value: bloom },
        uGrain: { value: grain },
      },
      depthTest: false,
      depthWrite: false,
    });
    const renderScene = new THREE.Scene();
    renderScene.add(new THREE.Mesh(geo, mat));
    return { geo, mat, renderScene, cam: new THREE.Camera() };
  }, [bloom, grain]);
  useEffect(() => () => {
    quad.geo.dispose();
    quad.mat.dispose();
  }, [quad]);

  // MSAA render target — linear HDR in (HalfFloat), recreated on resize
  const rt = useRef<THREE.WebGLRenderTarget | null>(null);
  useEffect(() => {
    const w = Math.max(2, Math.round(size.width * dpr));
    const h = Math.max(2, Math.round(size.height * dpr));
    const next = new THREE.WebGLRenderTarget(w, h, { type: THREE.HalfFloatType, samples: 4 });
    if (rt.current) rt.current.dispose();
    rt.current = next;
    quad.mat.uniforms.uRes.value.set(w, h);
    return () => {
      next.dispose();
      if (rt.current === next) rt.current = null;
    };
  }, [size.width, size.height, dpr, quad]);
  useEffect(() => () => {
    rt.current?.dispose();
    rt.current = null;
  }, []);

  useFrame((state) => {
    const target0 = rt.current;
    if (!target0) return;

    // motion energy: pointer/scroll targets decay here; story scrub adds directly
    const p = useStory.getState().p;
    const dp = Math.abs(p - lastP.current);
    lastP.current = p;
    if (dp > 0) target.current = Math.min(1, target.current + dp * 5);
    target.current *= 0.88;
    vel.current += (target.current - vel.current) * (target.current > vel.current ? 0.3 : 0.07);

    const u = quad.mat.uniforms;
    u.uTime.value = state.clock.elapsedTime;
    u.uVel.value = vel.current;
    u.tDiffuse.value = target0.texture;

    // pass 1: scene → linear HDR MSAA target
    gl.setRenderTarget(target0);
    gl.render(scene, camera);
    // pass 2: grade + tone map + encode → screen
    gl.setRenderTarget(null);
    gl.render(quad.renderScene, quad.cam);
  }, 1);

  return null;
}
