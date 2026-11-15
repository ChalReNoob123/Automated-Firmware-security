'use client';
import { useEffect, useMemo, useRef } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import * as THREE from 'three';
import { useStory, seg } from './storyStore';
import { sfxBlip } from './audio/sfx';
import PostFX, { usePostOK } from './post/PostFX';

// Lusion-style scroll story scene: one full-viewport WebGL canvas pinned
// behind the copy, whose ensemble MORPHS as the page scrolls through four
// acts — assemble (firmware) → explode (unpacking) → hunt (radar) → settle
// (verdict). Round 5 deep-motion pass: GLSL aurora backdrop that drifts and
// flushes alert-red during the hunt, data streams arcing from the core to
// every shard with traveling pulses, halo rings, alert-shifting key lights,
// a subtle camera roll, and a twinkling starfield. Deterministic seeded
// layout, capped pixel ratio, pointer parallax; scroll progress arrives via
// the zustand store (no React re-renders in the render loop).

function mulberry(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/* ------------- aurora backdrop: value-noise fbm, alert shift at the hunt ------------- */

const AUR_V = /* glsl */ `
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const AUR_F = /* glsl */ `
  varying vec2 vUv;
  uniform float uTime;
  uniform float uAlert;
  float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123); }
  float noise(vec2 p) {
    vec2 i = floor(p);
    vec2 f = fract(p);
    vec2 u = f * f * (3.0 - 2.0 * f);
    return mix(mix(hash(i), hash(i + vec2(1.0, 0.0)), u.x),
               mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), u.x), u.y);
  }
  void main() {
    vec2 uv = vUv;
    float t = uTime * 0.05;
    float n = 0.0;
    n += noise(uv * vec2(3.0, 2.0) + vec2(t, -t * 0.6)) * 0.55;
    n += noise(uv * vec2(6.0, 4.0) + vec2(-t * 1.4, t * 0.8)) * 0.28;
    n += noise(uv * vec2(12.0, 8.0) + vec2(t * 0.7, t)) * 0.17;
    vec3 deep = vec3(0.008, 0.023, 0.09);
    vec3 cyan = vec3(0.05, 0.42, 0.58);
    vec3 violet = vec3(0.29, 0.13, 0.5);
    vec3 alert = vec3(0.45, 0.1, 0.08);
    vec3 col = mix(deep, cyan, smoothstep(0.3, 0.75, n));
    col = mix(col, violet, smoothstep(0.62, 0.95, n) * 0.65);
    col = mix(col, alert * smoothstep(0.3, 0.7, n), uAlert * 0.5);
    float vig = smoothstep(1.05, 0.3, length((uv - 0.5) * vec2(1.25, 1.0)) * 2.0);
    col = mix(deep, col, vig);
    gl_FragColor = vec4(col, 1.0);
  }
`;

function Aurora() {
  const uniforms = useMemo(() => ({ uTime: { value: 0 }, uAlert: { value: 0 } }), []);
  useFrame((state, d) => {
    const p = useStory.getState().p;
    uniforms.uTime.value = state.clock.elapsedTime;
    const target = seg(p, 0.45, 0.62) * (1 - seg(p, 0.8, 0.95));
    uniforms.uAlert.value += (target - uniforms.uAlert.value) * Math.min(1, d * 3);
  });
  return (
    <mesh position={[0, 0, -16]} renderOrder={-1}>
      <planeGeometry args={[76, 44]} />
      <shaderMaterial uniforms={uniforms} vertexShader={AUR_V} fragmentShader={AUR_F} depthWrite={false} />
    </mesh>
  );
}

/* ------------- lights: key colors drain toward alert tones during the hunt ------------- */

function Lights() {
  const l1 = useRef<THREE.PointLight>(null);
  const l2 = useRef<THREE.PointLight>(null);
  const c1 = useMemo(() => new THREE.Color('#22d3ee'), []);
  const c1a = useMemo(() => new THREE.Color('#f43f5e'), []);
  const c2 = useMemo(() => new THREE.Color('#a855f7'), []);
  const c2a = useMemo(() => new THREE.Color('#fb923c'), []);
  const tmp = useMemo(() => new THREE.Color(), []);
  useFrame(() => {
    const p = useStory.getState().p;
    const alert = seg(p, 0.45, 0.62) * (1 - seg(p, 0.8, 0.95));
    if (l1.current) l1.current.color.copy(tmp.copy(c1).lerp(c1a, alert * 0.8));
    if (l2.current) l2.current.color.copy(tmp.copy(c2).lerp(c2a, alert * 0.6));
  });
  return (
    <>
      <pointLight ref={l1} position={[8, 6, 8]} intensity={60} color="#22d3ee" />
      <pointLight ref={l2} position={[-8, -4, 6]} intensity={50} color="#a855f7" />
    </>
  );
}

function Starfield({ count = 1200 }: { count?: number }) {
  const ref = useRef<THREE.Points>(null);
  const mat = useRef<THREE.PointsMaterial>(null);
  const geom = useMemo(() => {
    const rng = mulberry(0xf02e);
    const pos = new Float32Array(count * 3);
    const col = new Float32Array(count * 3);
    const palette = [new THREE.Color('#22d3ee'), new THREE.Color('#a855f7'), new THREE.Color('#e2e8f0')];
    for (let i = 0; i < count; i++) {
      const r = 14 + rng() * 26;
      const th = rng() * Math.PI * 2;
      const ph = Math.acos(2 * rng() - 1);
      pos[i * 3] = r * Math.sin(ph) * Math.cos(th);
      pos[i * 3 + 1] = r * Math.cos(ph) * 0.7;
      pos[i * 3 + 2] = r * Math.sin(ph) * Math.sin(th);
      const c = palette[Math.floor(rng() * palette.length)];
      col[i * 3] = c.r;
      col[i * 3 + 1] = c.g;
      col[i * 3 + 2] = c.b;
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    g.setAttribute('color', new THREE.BufferAttribute(col, 3));
    return g;
  }, [count]);
  useFrame((state, d) => {
    // spin accelerates during "the hunt"
    const a3 = seg(useStory.getState().p, 0.52, 0.74);
    if (ref.current) ref.current.rotation.y += d * (0.008 + a3 * 0.03);
    if (mat.current) mat.current.opacity = 0.72 + Math.sin(state.clock.elapsedTime * 1.6) * 0.12;
  });
  return (
    <points ref={ref} geometry={geom}>
      <pointsMaterial ref={mat} size={0.06} vertexColors transparent opacity={0.85} blending={THREE.AdditiveBlending} depthWrite={false} sizeAttenuation />
    </points>
  );
}

/* ------------- energy shell: fresnel rim glow breathing around the core ------------- */

const SHELL_V = /* glsl */ `
  varying vec3 vN;
  varying vec3 vI;
  void main() {
    vN = normalize(normalMatrix * normal);
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    vI = normalize(-mv.xyz);
    gl_Position = projectionMatrix * mv;
  }
`;

const SHELL_F = /* glsl */ `
  varying vec3 vN;
  varying vec3 vI;
  uniform float uTime;
  uniform float uAlert;
  uniform float uBoost;
  void main() {
    float rim = pow(1.0 - abs(dot(vN, vI)), 2.4);
    vec3 cyan = vec3(0.13, 0.83, 0.93);
    vec3 violet = vec3(0.66, 0.33, 0.98);
    vec3 alert = vec3(0.96, 0.24, 0.28);
    vec3 col = mix(cyan, violet, 0.5 + 0.5 * sin(uTime * 0.55));
    col = mix(col, alert, uAlert * 0.75);
    float pulse = 0.72 + 0.28 * sin(uTime * 2.3);
    gl_FragColor = vec4(col, rim * (0.3 + uBoost * 0.35) * pulse);
  }
`;

function CoreShell() {
  const uniforms = useMemo(() => ({ uTime: { value: 0 }, uAlert: { value: 0 }, uBoost: { value: 0 } }), []);
  useFrame((state, d) => {
    const p = useStory.getState().p;
    const a4 = seg(p, 0.78, 0.96);
    uniforms.uTime.value = state.clock.elapsedTime;
    uniforms.uBoost.value += (a4 - uniforms.uBoost.value) * Math.min(1, d * 2.5);
    uniforms.uAlert.value += (seg(p, 0.45, 0.62) * (1 - seg(p, 0.8, 0.95)) - uniforms.uAlert.value) * Math.min(1, d * 3);
  });
  return (
    <mesh>
      <sphereGeometry args={[2.16, 48, 32]} />
      <shaderMaterial
        uniforms={uniforms}
        vertexShader={SHELL_V}
        fragmentShader={SHELL_F}
        transparent
        depthWrite={false}
        blending={THREE.AdditiveBlending}
      />
    </mesh>
  );
}

function Core() {
  const root = useRef<THREE.Group>(null);
  const outer = useRef<THREE.Mesh>(null);
  const inner = useRef<THREE.Mesh>(null);
  const heart = useRef<THREE.Mesh>(null);
  useFrame((state, d) => {
    const t = state.clock.elapsedTime;
    const p = useStory.getState().p;
    const a1 = seg(p, 0.02, 0.24);
    const a4 = seg(p, 0.78, 0.96);
    // verdict act: the core burns brighter — consensus confirmed
    const s = 0.6 + a1 * 0.4 + a4 * 0.12;
    if (root.current) {
      root.current.scale.setScalar(s);
      root.current.position.y = Math.sin(t * 0.5) * 0.14;
    }
    if (outer.current) {
      outer.current.rotation.y += d * 0.12;
      outer.current.rotation.x = Math.sin(t * 0.2) * 0.25;
      (outer.current.material as THREE.MeshBasicMaterial).opacity = 0.5 + a4 * 0.22;
    }
    if (inner.current) {
      inner.current.rotation.y -= d * (0.2 + a4 * 0.15);
      inner.current.rotation.z += d * 0.07;
    }
    if (heart.current) {
      const pulse = 0.42 + Math.sin(t * (1.6 + a4 * 1.4)) * 0.05;
      heart.current.scale.setScalar(pulse);
      heart.current.rotation.y += d * 0.5;
      (heart.current.material as THREE.MeshStandardMaterial).emissiveIntensity = 2.2 + a4 * 2.4;
    }
  });
  return (
    <group ref={root}>
      <mesh ref={outer}>
        <icosahedronGeometry args={[1.7, 1]} />
        <meshBasicMaterial color="#22d3ee" wireframe transparent opacity={0.5} />
      </mesh>
      <mesh ref={inner}>
        <icosahedronGeometry args={[1.05, 0]} />
        <meshBasicMaterial color="#a855f7" wireframe transparent opacity={0.65} />
      </mesh>
      <mesh ref={heart}>
        <octahedronGeometry args={[1]} />
        <meshStandardMaterial color="#0ea5e9" emissive="#22d3ee" emissiveIntensity={2.2} roughness={0.2} />
      </mesh>
      <CoreShell />
    </group>
  );
}

/* ------------- shards + data streams (one seeded layout drives both) ------------- */

type ShardItem = {
  angle: number;
  rf: number;
  y: number;
  tilt: [number, number, number];
  size: [number, number, number];
  phase: number;
  cyan: boolean;
};

function makeShards(count: number): ShardItem[] {
  const rng = mulberry(0x5eed);
  return Array.from({ length: count }, (_, i) => ({
    angle: (i / count) * Math.PI * 2 + rng() * 0.4,
    rf: 0.72 + rng() * 0.55,
    y: (rng() - 0.5) * 2.4,
    tilt: [rng() * Math.PI, rng() * Math.PI, rng() * Math.PI] as [number, number, number],
    size: [0.7 + rng() * 0.7, 0.05, 0.45 + rng() * 0.45] as [number, number, number],
    phase: rng() * Math.PI * 2,
    cyan: rng() > 0.45,
  }));
}

function Shards({ count = 14 }: { count?: number }) {
  const group = useRef<THREE.Group>(null);
  const items = useMemo(() => makeShards(count), [count]);
  const streams = useMemo(() => {
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(new Float32Array(count * 6), 3));
    g.setAttribute('color', new THREE.BufferAttribute(new Float32Array(count * 6), 3));
    return g;
  }, [count]);
  useFrame((state, d) => {
    const t = state.clock.elapsedTime;
    const p = useStory.getState().p;
    // act choreography: converge → explode → hunt-wobble → settle
    const a1 = seg(p, 0.02, 0.24);
    const a2 = seg(p, 0.26, 0.48);
    const a3 = seg(p, 0.52, 0.74);
    const a4 = seg(p, 0.78, 0.96);
    const radius = 4.9 - a1 * 2.6 + a2 * 2.2 - a3 * 0.25 - a4 * 0.7;
    const spin = 0.05 + a3 * 0.42 + a4 * 0.1;
    if (group.current) group.current.rotation.y += d * spin;
    const pos = streams.attributes.position.array as Float32Array;
    const col = streams.attributes.color.array as Float32Array;
    const energy = 0.12 + a2 * 0.5 + a3 * 0.38; // streams wake during unpacking
    group.current?.children.forEach((m, i) => {
      const it = items[i];
      if (!it) return; // last child is the lineSegments mesh
      const wob = 1 + Math.sin(t * (0.5 + a3 * 0.8) + it.phase) * (0.05 + a3 * 0.12);
      const r = radius * it.rf * wob;
      const x = Math.cos(it.angle) * r;
      const y = it.y + Math.sin(t * 0.7 + it.phase) * 0.22;
      const z = Math.sin(it.angle) * r;
      m.position.set(x, y, z);
      m.rotation.x += d * (0.05 + a3 * 0.25);
      // data stream core → shard: traveling pulse brightens the far vertex
      const pulse = Math.max(0, Math.sin(t * 2.1 - i * 0.85)) ** 3 * energy;
      const base = it.cyan ? [0.13, 0.83, 0.93] : [0.66, 0.33, 0.98];
      pos[i * 6] = 0;
      pos[i * 6 + 1] = 0;
      pos[i * 6 + 2] = 0;
      pos[i * 6 + 3] = x;
      pos[i * 6 + 4] = y;
      pos[i * 6 + 5] = z;
      col[i * 6] = base[0] * 0.22;
      col[i * 6 + 1] = base[1] * 0.22;
      col[i * 6 + 2] = base[2] * 0.22;
      const e = 0.25 + pulse;
      col[i * 6 + 3] = base[0] * e;
      col[i * 6 + 4] = base[1] * e;
      col[i * 6 + 5] = base[2] * e;
      // shard self-glow flares with its stream pulse — the lattice breathes
      const mm = (m as THREE.Mesh).material as THREE.MeshStandardMaterial;
      if (mm) mm.emissiveIntensity = 0.55 + pulse * 1.9;
    });
    streams.attributes.position.needsUpdate = true;
    streams.attributes.color.needsUpdate = true;
  });
  return (
    <group ref={group}>
      {items.map((s, i) => (
        <mesh key={i} rotation={s.tilt}>
          <boxGeometry args={s.size} />
          <meshStandardMaterial color={s.cyan ? '#0e7490' : '#6d28d9'} emissive={s.cyan ? '#22d3ee' : '#a855f7'} emissiveIntensity={0.55} roughness={0.35} metalness={0.6} />
        </mesh>
      ))}
      <lineSegments geometry={streams}>
        <lineBasicMaterial vertexColors transparent opacity={0.8} blending={THREE.AdditiveBlending} depthWrite={false} />
      </lineSegments>
    </group>
  );
}

/* ------------- halo rings: gyroscopic calibration rings around the core ------------- */

function HaloRings() {
  const a = useRef<THREE.Mesh>(null);
  const b = useRef<THREE.Mesh>(null);
  useFrame((state, d) => {
    const p = useStory.getState().p;
    const a2 = seg(p, 0.26, 0.48);
    const s = Math.max(0.2, 0.4 + a2 * 0.5 + 0.25 * Math.sin(state.clock.elapsedTime * 0.6));
    if (a.current) {
      a.current.rotation.x += d * 0.3;
      a.current.rotation.y += d * 0.17;
      a.current.scale.setScalar(s);
    }
    if (b.current) {
      b.current.rotation.z -= d * 0.22;
      b.current.rotation.x = Math.PI / 2.4;
      b.current.scale.setScalar(s * 0.8);
    }
  });
  return (
    <group>
      <mesh ref={a}>
        <torusGeometry args={[2.6, 0.012, 8, 96]} />
        <meshBasicMaterial color="#22d3ee" transparent opacity={0.55} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      <mesh ref={b}>
        <torusGeometry args={[3.3, 0.01, 8, 96]} />
        <meshBasicMaterial color="#a855f7" transparent opacity={0.4} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
    </group>
  );
}

function Radar() {
  const rings = useRef<(THREE.Mesh | null)[]>([]);
  const sweep = useRef<THREE.Mesh>(null);
  const root = useRef<THREE.Group>(null);
  useFrame((state, d) => {
    const t = state.clock.elapsedTime;
    const p = useStory.getState().p;
    // radar wakes during "unpacking", rages in "the hunt", calms at the verdict
    const k = Math.min(1, seg(p, 0.3, 0.55) * 0.7 + seg(p, 0.52, 0.74)) * (1 - seg(p, 0.78, 0.96) * 0.35);
    const speed = 0.22 + seg(p, 0.52, 0.74) * 0.5;
    rings.current.forEach((r, i) => {
      if (!r) return;
      const rp = (t * speed + i / 3) % 1;
      const s = 1 + rp * 5.2;
      r.scale.set(s, s, s);
      (r.material as THREE.MeshBasicMaterial).opacity = 0.5 * (1 - rp) * (0.25 + 0.75 * k);
    });
    if (sweep.current) sweep.current.rotation.z -= d * (0.9 + seg(p, 0.52, 0.74) * 1.4);
    if (root.current) root.current.scale.setScalar(0.9 + k * 0.25);
  });
  return (
    <group ref={root} position={[0, -2.6, 0]} rotation-x={-Math.PI / 2}>
      {[0, 1, 2].map((i) => (
        <mesh key={i} ref={(m) => { rings.current[i] = m; }}>
          <ringGeometry args={[0.96, 1, 64]} />
          <meshBasicMaterial color="#22d3ee" transparent opacity={0.4} side={THREE.DoubleSide} depthWrite={false} />
        </mesh>
      ))}
      <mesh>
        <ringGeometry args={[2.2, 2.26, 64]} />
        <meshBasicMaterial color="#a855f7" transparent opacity={0.5} side={THREE.DoubleSide} depthWrite={false} />
      </mesh>
      <mesh ref={sweep}>
        <circleGeometry args={[2.2, 32, 0, 0.5]} />
        <meshBasicMaterial color="#22d3ee" transparent opacity={0.22} side={THREE.DoubleSide} depthWrite={false} blending={THREE.AdditiveBlending} />
      </mesh>
    </group>
  );
}

/* ------------- tracers: alternating orbital rings threading the ensemble ------------- */

function Tracers({ rings = 3, per = 84 }: { rings?: number; per?: number }) {
  const groups = useRef<(THREE.Group | null)[]>([]);
  const mats = useRef<(THREE.PointsMaterial | null)[]>([]);
  const geoms = useMemo(
    () =>
      Array.from({ length: rings }, (_, r) => {
        const rng = mulberry(0x7ac3 + r);
        const palette = [new THREE.Color('#22d3ee'), new THREE.Color('#a855f7'), new THREE.Color('#e2e8f0')];
        const radius = 5.2 + r * 0.85;
        const pos = new Float32Array(per * 3);
        const col = new Float32Array(per * 3);
        for (let i = 0; i < per; i++) {
          const th = (i / per) * Math.PI * 2 + rng() * 0.3;
          const rr = radius + (rng() - 0.5) * 0.7;
          pos[i * 3] = Math.cos(th) * rr;
          pos[i * 3 + 1] = (rng() - 0.5) * 0.5;
          pos[i * 3 + 2] = Math.sin(th) * rr;
          const c = palette[Math.floor(rng() * palette.length)];
          col[i * 3] = c.r;
          col[i * 3 + 1] = c.g;
          col[i * 3 + 2] = c.b;
        }
        const g = new THREE.BufferGeometry();
        g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
        g.setAttribute('color', new THREE.BufferAttribute(col, 3));
        return g;
      }),
    [rings, per],
  );
  useFrame((state, d) => {
    const p = useStory.getState().p;
    const a3 = seg(p, 0.52, 0.74);
    const t = state.clock.elapsedTime;
    groups.current.forEach((g, i) => {
      // alternating orbit directions, spooling up during the hunt
      if (g) g.rotation.y += d * (0.16 + i * 0.06 + a3 * 0.5) * (i % 2 ? -1 : 1);
    });
    mats.current.forEach((m, i) => {
      if (m) m.opacity = 0.5 + Math.sin(t * 1.8 + i * 2.1) * 0.18;
    });
  });
  return (
    <>
      {geoms.map((g, i) => (
        <group key={i} ref={(m) => { groups.current[i] = m; }} rotation={[0.42 + i * 0.3, 0, i * 0.35]}>
          <points geometry={g}>
            <pointsMaterial
              ref={(m) => { mats.current[i] = m; }}
              size={0.055}
              vertexColors
              transparent
              opacity={0.55}
              blending={THREE.AdditiveBlending}
              depthWrite={false}
              sizeAttenuation
            />
          </points>
        </group>
      ))}
    </>
  );
}

/* ------------- shockwave: a flat energy ring fires when an act threshold is crossed ------------- */

function Shockwave({ from, to, color = '#22d3ee', speed = 1.6 }: { from: number; to: number; color?: string; speed?: number }) {
  const ref = useRef<THREE.Mesh>(null);
  const armed = useRef(false);
  const t = useRef(1);
  useFrame((_, d) => {
    const k = seg(useStory.getState().p, from, to);
    if (k > 0.5 && !armed.current) {
      armed.current = true;
      t.current = 0;
    } else if (k < 0.5) {
      armed.current = false;
    }
    if (t.current >= 1 || !ref.current) return;
    t.current = Math.min(1, t.current + d * speed);
    const s = 0.9 + t.current * 9.5;
    ref.current.scale.set(s, s, s);
    (ref.current.material as THREE.MeshBasicMaterial).opacity = (1 - t.current) ** 1.7 * 0.55;
  });
  return (
    <mesh ref={ref} rotation-x={-Math.PI / 2} scale={0.001}>
      <ringGeometry args={[0.94, 1, 72]} />
      <meshBasicMaterial color={color} transparent opacity={0} blending={THREE.AdditiveBlending} depthWrite={false} side={THREE.DoubleSide} />
    </mesh>
  );
}

/* ------------- dust: slow ambient motes filling the space around the ensemble ------------- */

function Dust({ count = 170 }: { count?: number }) {
  const mat = useRef<THREE.PointsMaterial>(null);
  const seedsRef = useRef<{ th: number; r: number; y: number; s: number; ph: number }[]>([]);
  const geom = useMemo(() => {
    const rng = mulberry(0xd057);
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(new Float32Array(count * 3), 3));
    seedsRef.current = Array.from({ length: count }, () => ({
      th: rng() * Math.PI * 2,
      r: 2.5 + rng() * 8.5,
      y: (rng() - 0.5) * 7,
      s: 0.12 + rng() * 0.3,
      ph: rng() * Math.PI * 2,
    }));
    return g;
  }, [count]);
  useFrame((state) => {
    const p = useStory.getState().p;
    const a3 = seg(p, 0.52, 0.74);
    const t = state.clock.elapsedTime;
    const pos = geom.attributes.position.array as Float32Array;
    const seeds = seedsRef.current;
    for (let i = 0; i < seeds.length; i++) {
      const s = seeds[i];
      // slow orbital drift + vertical sway; the hunt adds angular energy
      const th = s.th + t * s.s * (0.25 + a3 * 0.55);
      pos[i * 3] = Math.cos(th) * s.r;
      pos[i * 3 + 1] = s.y + Math.sin(t * 0.4 + s.ph) * 0.6;
      pos[i * 3 + 2] = Math.sin(th) * s.r;
    }
    geom.attributes.position.needsUpdate = true;
    if (mat.current) mat.current.opacity = 0.3 + a3 * 0.22 + Math.sin(t * 1.2) * 0.05;
  });
  return (
    <points geometry={geom}>
      <pointsMaterial ref={mat} size={0.045} color="#7dd3fc" transparent opacity={0.3} blending={THREE.AdditiveBlending} depthWrite={false} sizeAttenuation />
    </points>
  );
}

function Rig() {
  const roll = useRef(0);
  useFrame((state, d) => {
    const p = useStory.getState().p;
    const a1 = seg(p, 0.02, 0.24);
    const a2 = seg(p, 0.26, 0.48);
    const a3 = seg(p, 0.52, 0.74);
    const a4 = seg(p, 0.78, 0.96);
    // dolly in during assemble, drift back through hunt/verdict — plus parallax
    const z = 12.5 - a1 * 1.9 - a2 * 0.6 + a3 * 1.1 + a4 * 0.7;
    const cx = state.pointer.x * 1.2;
    const cy = 1.4 + state.pointer.y * 0.8;
    const k = Math.min(1, d * 2.2);
    state.camera.position.x += (cx - state.camera.position.x) * k;
    state.camera.position.y += (cy - state.camera.position.y) * k;
    state.camera.position.z += (z - state.camera.position.z) * k;
    state.camera.lookAt(0, -0.35 - a2 * 0.35, 0);
    // subtle roll: pointer lean + a faint wobble while hunting
    const t = state.clock.elapsedTime;
    const target = -state.pointer.x * 0.035 + Math.sin(t * 0.8) * a3 * 0.012;
    roll.current += (target - roll.current) * Math.min(1, d * 2.5);
    state.camera.rotateZ(roll.current);
  });
  return null;
}

/* ------------- arcs: lightning discharges crackling around the core ------------- */
// One dynamic lineSegments pool. Slots regenerate one at a time (staggered),
// jagged midpoint-displaced paths between two random shell points, then fade
// by per-frame color decay. Wake follows unpacking, rages in the hunt, sparks
// at the verdict — the ensemble feels ALIVE, electrically.

const ARC_SLOTS = 6;
const ARC_SEGS = 7; // 7 segments = 8 points per bolt

function Arcs() {
  const geom = useMemo(() => {
    const verts = ARC_SLOTS * ARC_SEGS * 2;
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(new Float32Array(verts * 3), 3));
    g.setAttribute('color', new THREE.BufferAttribute(new Float32Array(verts * 3), 3));
    return g;
  }, []);
  const cursor = useRef(0);
  const cooldown = useRef(0.4);
  useFrame((state, d) => {
    const p = useStory.getState().p;
    const a2 = seg(p, 0.26, 0.48);
    const a3 = seg(p, 0.52, 0.74);
    const a4 = seg(p, 0.78, 0.96);
    const energy = Math.max(a2 * 0.72, a3, a4 * 0.6);
    const pos = geom.attributes.position.array as Float32Array;
    const col = geom.attributes.color.array as Float32Array;
    const v3 = ARC_SEGS * 2 * 3;

    // regenerate one slot when the cooldown allows — faster crackling when hot
    cooldown.current -= d;
    if (energy > 0.05 && cooldown.current <= 0) {
      cooldown.current = 0.16 - energy * 0.1;
      const slot = cursor.current;
      cursor.current = (cursor.current + 1) % ARC_SLOTS;
      const rng = mulberry((Math.floor(state.clock.elapsedTime * 1000) * 7919 + slot * 131) >>> 0);
      // two random shell points (start closer to the core, end further out)
      const pt = (rMin: number, rMax: number) => {
        const th = rng() * Math.PI * 2;
        const ph = Math.acos(2 * rng() - 1);
        const r = rMin + rng() * (rMax - rMin);
        return [r * Math.sin(ph) * Math.cos(th), r * Math.cos(ph) * 0.62, r * Math.sin(ph) * Math.sin(th)] as const;
      };
      const A = pt(1.9, 2.5);
      const B = pt(3.0, 4.6);
      const cyan = rng() > 0.38;
      const base = cyan ? [0.16, 0.9, 1.0] : [0.72, 0.38, 1.0];
      const hot = 0.55 + rng() * 0.45;
      const jag = 0.55 + energy * 0.75;
      // walk A→B in ARC_SEGS steps, displacing midpoints sideways
      const pts: [number, number, number][] = [];
      for (let s = 0; s <= ARC_SEGS; s++) {
        const k = s / ARC_SEGS;
        let x = A[0] + (B[0] - A[0]) * k;
        let y = A[1] + (B[1] - A[1]) * k;
        let z = A[2] + (B[2] - A[2]) * k;
        if (s > 0 && s < ARC_SEGS) {
          x += (rng() - 0.5) * jag;
          y += (rng() - 0.5) * jag;
          z += (rng() - 0.5) * jag;
        }
        pts.push([x, y, z]);
      }
      const head = slot * v3;
      for (let s = 0; s < ARC_SEGS; s++) {
        const w = 1 - Math.abs(s / ARC_SEGS - 0.45) * 1.1; // brightest mid-bolt
        const b = hot * Math.max(0.18, w);
        for (let e = 0; e < 2; e++) {
          const vi = head + (s * 2 + e) * 3;
          const P = pts[s + e];
          pos[vi] = P[0];
          pos[vi + 1] = P[1];
          pos[vi + 2] = P[2];
          col[vi] = base[0] * b;
          col[vi + 1] = base[1] * b;
          col[vi + 2] = base[2] * b;
        }
      }
    }

    // global per-frame decay — every bolt cools toward darkness
    const decay = Math.pow(0.06, d); // ~exponential fade, frame-rate independent
    for (let i = 3; i < col.length; i += 3) {
      col[i] *= decay;
      col[i + 1] *= decay;
      col[i + 2] *= decay;
    }
    geom.attributes.position.needsUpdate = true;
    geom.attributes.color.needsUpdate = true;
  });
  return (
    <lineSegments geometry={geom}>
      <lineBasicMaterial vertexColors transparent opacity={0.9} blending={THREE.AdditiveBlending} depthWrite={false} />
    </lineSegments>
  );
}

/* ------------- round-17: drag-to-orbit with inertia ------------- */
// Grab the WebGL canvas and the whole ensemble follows — yaw/pitch from the
// drag, momentum on release (frame-rate-independent decay), then a gentle
// spring back to rest. Fine pointers only (touch keeps native scrolling),
// reduced-motion exempt. State lives in a module-level object + the zustand
// `dragging` flag (cursor reads it for its ORBIT label) — the render loop
// never goes through React.

const orbit = { yaw: 0, pitch: 0, vy: 0, vp: 0, dragging: false };

function DragOrbit() {
  const gl = useThree((s) => s.gl);
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const el = gl.domElement;
    let lx = 0;
    let ly = 0;
    let lt = 0;
    const down = (e: PointerEvent) => {
      if (e.pointerType === 'touch' || e.button !== 0) return;
      orbit.dragging = true;
      try {
        el.setPointerCapture(e.pointerId);
      } catch {
        /* pointer already released */
      }
      lx = e.clientX;
      ly = e.clientY;
      lt = e.timeStamp;
      orbit.vy = 0;
      orbit.vp = 0;
      useStory.getState().setDragging(true);
      sfxBlip(430, 760, 0.06, 0.026); // servo pickup
    };
    const move = (e: PointerEvent) => {
      if (!orbit.dragging) return;
      const dx = e.clientX - lx;
      const dy = e.clientY - ly;
      const dt = Math.max(8, e.timeStamp - lt) / 1000;
      lx = e.clientX;
      ly = e.clientY;
      lt = e.timeStamp;
      orbit.yaw += dx * 0.0052;
      orbit.pitch = THREE.MathUtils.clamp(orbit.pitch + dy * 0.0034, -0.55, 0.55);
      orbit.vy = (dx * 0.0052) / dt; // rad/s — momentum source for release
      orbit.vp = (dy * 0.0034) / dt;
    };
    const up = (e: PointerEvent) => {
      if (!orbit.dragging) return;
      orbit.dragging = false;
      try {
        el.releasePointerCapture(e.pointerId);
      } catch {
        /* already released */
      }
      useStory.getState().setDragging(false);
      sfxBlip(820, 1280, 0.05, 0.022); // release tick
    };
    el.addEventListener('pointerdown', down);
    el.addEventListener('pointermove', move);
    el.addEventListener('pointerup', up);
    el.addEventListener('pointercancel', up);
    return () => {
      el.removeEventListener('pointerdown', down);
      el.removeEventListener('pointermove', move);
      el.removeEventListener('pointerup', up);
      el.removeEventListener('pointercancel', up);
      if (orbit.dragging) {
        orbit.dragging = false;
        useStory.getState().setDragging(false);
      }
    };
  }, [gl]);
  useFrame((_, d) => {
    if (orbit.dragging) return;
    // momentum release: velocities decay exponentially, offsets spring home
    orbit.yaw += orbit.vy * d;
    orbit.pitch += orbit.vp * d;
    const damp = Math.pow(0.3, d);
    orbit.vy *= damp;
    orbit.vp *= damp;
    const k = Math.min(1, d * 0.9);
    orbit.yaw -= orbit.yaw * k;
    orbit.pitch -= orbit.pitch * k;
  });
  return null;
}

function Ensemble() {
  const vp = useThree((s) => s.viewport);
  const g = useRef<THREE.Group>(null);
  useFrame(() => {
    if (!g.current) return;
    g.current.rotation.y = orbit.yaw;
    g.current.rotation.x = orbit.pitch;
  });
  return (
    <group ref={g} position={[0, -0.3, 0]} scale={Math.min(0.95, vp.width / 20)}>
      <Core />
      <Shards />
      <HaloRings />
      <Radar />
      <Tracers />
      <Dust />
      <Arcs />
      {/* energy rings fire once at the explode entry and the verdict consensus */}
      <Shockwave from={0.24} to={0.3} color="#a855f7" speed={1.7} />
      <Shockwave from={0.78} to={0.84} color="#22d3ee" speed={1.5} />
    </group>
  );
}

export default function StoryScene() {
  const fx = usePostOK();
  return (
    <div style={{ position: 'absolute', inset: 0 }} data-cursor="drag">
      <Canvas
        dpr={[1, 2]}
        camera={{ position: [0, 1.4, 12.5], fov: 55 }}
        gl={{ antialias: true, alpha: false, powerPreference: 'high-performance' }}
        style={{ position: 'absolute', inset: 0 }}
      >
        <color attach="background" args={['#020617']} />
        <fog attach="fog" args={['#020617', 12, 34]} />
        <ambientLight intensity={0.55} />
        <Lights />
        <Aurora />
        <Starfield />
        <Ensemble />
        <Rig />
        <DragOrbit />
        {/* round 21: grain + bloom + velocity chromatic aberration (gated) */}
        {fx && <PostFX />}
      </Canvas>
    </div>
  );
}
