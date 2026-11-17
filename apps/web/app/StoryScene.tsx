'use client';
import { useEffect, useMemo, useRef } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import * as THREE from 'three';
import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js';
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

/* ------------- round 25: procedural studio environment ------------- */

// A PMREM-baked RoomEnvironment gives every metal/clearcoat surface a real
// reflection to sample — without it, a high-metalness face pointing away from
// the lights resolves to pure black (the solid dark plates seen on some
// ensemble angles). Zero new dependencies: RoomEnvironment ships inside the
// three package. environmentIntensity keeps it subordinate to the emissive /
// bloom identity so the dark-space mood survives.
function Env() {
  const scene = useThree((s) => s.scene);
  const gl = useThree((s) => s.gl);
  useEffect(() => {
    const pmrem = new THREE.PMREMGenerator(gl);
    const room = new RoomEnvironment();
    const target = pmrem.fromScene(room, 0.04);
    scene.environment = target.texture;
    scene.environmentIntensity = 0.62; // round 28: 0.45 → 0.62 — the machined metal reads richer
    return () => {
      scene.environment = null;
      target.texture.dispose();
      target.dispose();
      room.dispose?.();
      pmrem.dispose();
    };
  }, [scene, gl]);
  return null;
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
      {/* round 25: a proper studio rig — directional key for the metal spec
          highlight, cool rim from behind for edge separation. The point lights
          alone gave the standard/physical materials no consistent key. */}
      <directionalLight position={[6, 10, 5]} intensity={1.35} color="#dff5ff" />
      <directionalLight position={[-7, 3, -9]} intensity={0.8} color="#a855f7" />
    </>
  );
}

/* round 28: orbiting rim lights — two colored point lights circle the
   ensemble at different heights, phases and speeds, so the clearcoat plates
   catch MOVING specular streaks even when the camera and pointer are still.
   Physically-correct decay: ~95cd at ~9 units out ≈ the standing lights. */
function RimLights() {
  const a = useRef<THREE.PointLight>(null);
  const b = useRef<THREE.PointLight>(null);
  useFrame(({ clock }) => {
    const t = clock.elapsedTime * 0.21;
    if (a.current) a.current.position.set(Math.cos(t) * 9.5, 2.6 + Math.sin(t * 0.7) * 1.4, Math.sin(t) * 9.5);
    if (b.current) b.current.position.set(Math.cos(-t * 0.8 + 2.2) * 11, -1.8 + Math.cos(t * 0.55) * 1.2, Math.sin(-t * 0.8 + 2.2) * 11);
  });
  return (
    <>
      <pointLight ref={a} intensity={95} color="#67e8f9" distance={44} />
      <pointLight ref={b} intensity={70} color="#c084fc" distance={44} />
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

  // round 25: flowing energy-cell surface — two fbm bands drift over the
  // shell and brighten as they cross the limb. The old shader was a flat
  // two-tone rim; this one reads as living plasma under bloom.
  float shash(vec2 p) {
    return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123);
  }
  float snoise(vec2 p) {
    vec2 i = floor(p);
    vec2 f = fract(p);
    vec2 u = f * f * (3.0 - 2.0 * f);
    return mix(mix(shash(i), shash(i + vec2(1.0, 0.0)), u.x), mix(shash(i + vec2(0.0, 1.0)), shash(i + vec2(1.0, 1.0)), u.x), u.y);
  }
  float fbm(vec2 p) {
    float v = 0.0;
    float a = 0.5;
    for (int k = 0; k < 4; k++) {
      v += a * snoise(p);
      p *= 2.13;
      a *= 0.5;
    }
    return v;
  }

  void main() {
    float ndv = abs(dot(vN, vI));
    float rim = pow(1.0 - ndv, 2.4);
    // spherical-ish surface uv from the normal (no seams at this gloss level)
    vec2 suv = vN.xy * 2.4 + vec2(vN.z * 1.7, vN.y * 0.8);
    float flow = fbm(suv + vec2(uTime * 0.12, -uTime * 0.07));
    float band = smoothstep(0.42, 0.62, flow) * 0.6 + smoothstep(0.55, 0.75, fbm(suv * 2.3 - vec2(uTime * 0.05, uTime * 0.03))) * 0.4;
    vec3 cyan = vec3(0.13, 0.83, 0.93);
    vec3 violet = vec3(0.66, 0.33, 0.98);
    vec3 alert = vec3(0.96, 0.24, 0.28);
    vec3 col = mix(cyan, violet, 0.5 + 0.5 * sin(uTime * 0.55));
    col = mix(col, alert, uAlert * 0.75);
    col *= 0.75 + band * 0.85;
    col += vec3(0.4, 0.8, 1.0) * rim * band;
    float pulse = 0.72 + 0.28 * sin(uTime * 2.3);
    gl_FragColor = vec4(col, rim * (0.3 + uBoost * 0.35) * pulse * (0.8 + band * 0.5));
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
        {/* round 25: clearcoat physical material — the heart now rolls a real
            specular highlight under the key light instead of a flat glow.
            fog=false: hero objects never bake toward the background color. */}
        <meshPhysicalMaterial color="#0ea5e9" emissive="#22d3ee" emissiveIntensity={2.2} roughness={0.22} metalness={0.85} clearcoat={1} clearcoatRoughness={0.18} fog={false} />
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
          {/* round 25: clearcoat plating — machined-metal panels with a sharp
              topcoat highlight, not flat plastic */}
          <meshPhysicalMaterial
            color={s.cyan ? '#0e7490' : '#6d28d9'}
            emissive={s.cyan ? '#22d3ee' : '#a855f7'}
            emissiveIntensity={0.55}
            roughness={0.28}
            metalness={0.85}
            clearcoat={1}
            clearcoatRoughness={0.28}
            fog={false}
          />
        </mesh>
      ))}
      <lineSegments geometry={streams}>
        <lineBasicMaterial vertexColors transparent opacity={0.8} blending={THREE.AdditiveBlending} depthWrite={false} />
      </lineSegments>
    </group>
  );
}

/* ------------- halo rings: gyroscopic calibration rings around the core ------------- */

/* round 25: SENTINEL DRONES — an instanced patrol of emissive octahedra
   orbiting the ensemble on individually inclined planes, each trailing a
   fading ribbon (ring-buffer line segments, head bright → tail dark). They
   tighten toward the core while it assembles, scatter wide during the hunt,
   and reform on the verdict — motion density that keeps the scene alive
   between act beats. Zero new dependencies; 9 instances + ~250 trail verts. */

const DRONE_TRAIL = 14;

type DroneSpec = { radius: number; speed: number; phase: number; yAmp: number; ySpeed: number; inc: number; node: number; dir: number };

function makeDrones(count: number): DroneSpec[] {
  const rng = mulberry(0xd07e);
  return Array.from({ length: count }, (_, i) => ({
    radius: 5.4 + rng() * 1.6,
    speed: 0.22 + rng() * 0.3,
    phase: (i / count) * Math.PI * 2 + rng() * 0.5,
    yAmp: 0.35 + rng() * 0.55,
    ySpeed: 0.4 + rng() * 0.5,
    inc: (rng() - 0.5) * 1.1,
    node: rng() * Math.PI * 2,
    dir: rng() > 0.5 ? 1 : -1,
  }));
}

function Drones({ count = 9 }: { count?: number }) {
  const meshes = useRef<THREE.InstancedMesh>(null);
  const specs = useMemo(() => makeDrones(count), [count]);
  // ring buffers of recent head positions per drone (trails). Circular index,
  // zero allocation per frame: newest sample overwrites the oldest slot.
  const trails = useMemo(() => specs.map(() => Array.from({ length: DRONE_TRAIL }, () => new THREE.Vector3(0, 0, 0))), [specs]);
  const trailIdx = useRef<number[]>(specs.map(() => 0));
  const geom = useMemo(() => {
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(new Float32Array(count * DRONE_TRAIL * 6), 3));
    g.setAttribute('color', new THREE.BufferAttribute(new Float32Array(count * DRONE_TRAIL * 6), 3));
    return g;
  }, [count]);
  const dummy = useMemo(() => new THREE.Object3D(), []);
  const tmpV = useMemo(() => new THREE.Vector3(), []);
  const tmpE = useMemo(() => new THREE.Euler(), []);

  useEffect(() => () => geom.dispose(), [geom]);

  useFrame((state, d) => {
    void d;
    const t = state.clock.elapsedTime;
    const p = useStory.getState().p;
    // choreography: gather during assemble → flare wide in the hunt → reform
    const a1 = seg(p, 0.02, 0.24);
    const a3 = seg(p, 0.52, 0.74);
    const a4 = seg(p, 0.78, 0.96);
    const radiusMul = 1 - a1 * 0.34 + a3 * 0.42 - a4 * 0.22;
    const speedMul = 1 + a3 * 1.35 + a4 * 0.3;
    const pos = geom.attributes.position.array as Float32Array;
    const col = geom.attributes.color.array as Float32Array;
    const im = meshes.current;
    if (!im) return;

    for (let i = 0; i < count; i++) {
      const sp = specs[i];
      const ang = sp.phase + t * sp.speed * sp.dir * speedMul;
      const r = sp.radius * radiusMul;
      // orbit in the XZ plane, then incline + rotate the plane per drone
      tmpV.set(Math.cos(ang) * r, Math.sin(t * sp.ySpeed + sp.phase) * sp.yAmp, Math.sin(ang) * r);
      tmpV.applyEuler(tmpE.set(sp.inc, sp.node, 0));
      const x = tmpV.x;
      const y = tmpV.y;
      const z = tmpV.z;

      // push the head onto this drone's trail ring buffer (circular, no alloc)
      const ring = trails[i];
      trailIdx.current[i] = (trailIdx.current[i] + 1) % DRONE_TRAIL;
      ring[trailIdx.current[i]].set(x, y, z);

      // instance transform: slow tumble + breathing scale
      dummy.position.set(x, y, z);
      dummy.rotation.set(t * 0.7 + i, t * 0.9 + sp.phase, 0);
      const s = 0.85 + 0.2 * Math.sin(t * 2.4 + i * 1.3);
      dummy.scale.setScalar(s);
      dummy.updateMatrix();
      im.setMatrixAt(i, dummy.matrix);

      // trail ribbon: newest → oldest, head bright fading to dark
      const base = sp.node > Math.PI ? [0.66, 0.33, 0.98] : [0.13, 0.83, 0.93];
      for (let k = 0; k < DRONE_TRAIL - 1; k++) {
        const vi = (i * DRONE_TRAIL + k) * 6;
        const aP = ring[(trailIdx.current[i] - k + DRONE_TRAIL * 2) % DRONE_TRAIL];
        const bP = ring[(trailIdx.current[i] - k - 1 + DRONE_TRAIL * 2) % DRONE_TRAIL];
        pos[vi] = aP.x;
        pos[vi + 1] = aP.y;
        pos[vi + 2] = aP.z;
        pos[vi + 3] = bP.x;
        pos[vi + 4] = bP.y;
        pos[vi + 5] = bP.z;
        const fade = Math.pow(1 - k / (DRONE_TRAIL - 1), 2.2) * 0.85;
        col[vi] = base[0] * fade;
        col[vi + 1] = base[1] * fade;
        col[vi + 2] = base[2] * fade;
        col[vi + 3] = base[0] * fade * 0.55;
        col[vi + 4] = base[1] * fade * 0.55;
        col[vi + 5] = base[2] * fade * 0.55;
      }
    }
    im.instanceMatrix.needsUpdate = true;
    geom.attributes.position.needsUpdate = true;
    geom.attributes.color.needsUpdate = true;
  });

  return (
    <group>
      <instancedMesh ref={meshes} args={[undefined, undefined, count]}>
        <octahedronGeometry args={[0.11, 0]} />
        <meshStandardMaterial color="#7dd3fc" emissive="#22d3ee" emissiveIntensity={1.6} roughness={0.3} metalness={0.6} toneMapped={false} fog={false} />
      </instancedMesh>
      <lineSegments geometry={geom}>
        <lineBasicMaterial vertexColors transparent opacity={0.9} blending={THREE.AdditiveBlending} depthWrite={false} />
      </lineSegments>
    </group>
  );
}

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

/* ---------- round 23: the camera performs the story ---------- */
// Keyframed camera stations — one shot per act, with travel between them:
//   0.00  establishing three-quarter drift-in (opening)
//   0.24  assembled: close frontal hero shot
//   0.48  unpacked: pulled-back 3/4 to read the exploded layout
//   0.74  hunt: high operator shot looking down at the radar table
//   0.90  verdict: swing wide
//   1.00  settled hero framing
// Sampled through a centripetal Catmull-Rom curve so the travel ARCS around
// the ensemble instead of cutting straight lines through it. The look-target
// lerps independently between the same stations. Pointer parallax and the
// hunt-roll wobble ride ON TOP of the path, and act boundaries fire a short
// decaying shake — the visual half of the act cut that sfxImpact already
// lands in audio. DragOrbit still owns the ENSEMBLE (yaw/pitch on the group),
// so dragging and the camera path compose cleanly.

const STATIONS: { p: number; pos: [number, number, number]; look: [number, number, number] }[] = [
  { p: 0.0, pos: [2.4, 2.9, 13.8], look: [0, -0.2, 0] },
  { p: 0.24, pos: [0.35, 1.15, 10.3], look: [0, -0.3, 0] },
  { p: 0.48, pos: [4.7, 0.8, 11.4], look: [0, -0.55, 0] },
  { p: 0.74, pos: [0.5, 6.4, 5.4], look: [0, -1.7, 0] },
  { p: 0.9, pos: [-3.6, 1.7, 12.0], look: [0, -0.35, 0] },
  { p: 1.0, pos: [0.0, 1.25, 11.4], look: [0, -0.3, 0] },
];

const ACT_CUTS = [0.26, 0.52, 0.78];

function Rig() {
  const roll = useRef(0);
  const shake = useRef(0);
  const lastP = useRef(0);
  const curve = useMemo(
    () => new THREE.CatmullRomCurve3(STATIONS.map((s) => new THREE.Vector3(...s.pos)), false, 'centripetal', 0.5),
    []
  );
  useFrame((state, d) => {
    const p = THREE.MathUtils.clamp(useStory.getState().p, 0, 1);
    // act-boundary shake impulses (crossing either direction)
    for (const b of ACT_CUTS) {
      if ((lastP.current < b && p >= b) || (lastP.current > b && p <= b)) shake.current = 1;
    }
    lastP.current = p;
    shake.current *= Math.pow(0.02, d); // frame-rate independent decay

    // piecewise p→curve-u remap so station i lands exactly at its keyframe p
    let i = 0;
    while (i < STATIONS.length - 2 && p > STATIONS[i + 1].p) i++;
    const a = STATIONS[i];
    const b = STATIONS[i + 1];
    const local = THREE.MathUtils.clamp((p - a.p) / Math.max(1e-4, b.p - a.p), 0, 1);
    const eased = local * local * (3 - 2 * local); // smoothstep — rests at stations
    const pos = curve.getPoint((i + eased) / (STATIONS.length - 1));
    const look = new THREE.Vector3(
      a.look[0] + (b.look[0] - a.look[0]) * eased,
      a.look[1] + (b.look[1] - a.look[1]) * eased,
      a.look[2] + (b.look[2] - a.look[2]) * eased
    );

    // pointer parallax rides on top of the path
    pos.x += state.pointer.x * 0.9;
    pos.y += state.pointer.y * 0.6;
    // decaying shake at act cuts
    const sh = shake.current * 0.07;
    const t = state.clock.elapsedTime;
    pos.x += Math.sin(t * 47.0) * sh;
    pos.y += Math.sin(t * 39.3 + 1.7) * sh;
    pos.z += Math.sin(t * 51.1 + 3.1) * sh * 0.6;

    const k = Math.min(1, d * 3.2);
    state.camera.position.lerp(pos, k);
    state.camera.lookAt(look);
    // subtle roll: pointer lean + a faint wobble while hunting
    const target = -state.pointer.x * 0.035 + Math.sin(t * 0.8) * seg(p, 0.52, 0.74) * 0.012;
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
        // round 25: dpr floor 1.5 supersamples the scene raster (the post
        // chain's antialias baseline — see PostFX header for why the MSAA
        // renderbuffer path was replaced). Round 28: when the post-quality
        // gate passes, the ceiling rises to 2.25 — the scene rasterizes at
        // up to 4320px wide on a 1080p display (4K-class sharpness). The
        // same gate keeps weak devices at the round-25 profile.
        dpr={fx ? [1.75, 2.25] : [1.5, 2]}
        camera={{ position: [0, 1.4, 12.5], fov: 55 }}
        gl={{ antialias: true, alpha: false, powerPreference: 'high-performance' }}
        style={{ position: 'absolute', inset: 0 }}
      >
        <color attach="background" args={['#020617']} />
        <fog attach="fog" args={['#020617', 12, 34]} />
        <Env />
        <ambientLight intensity={0.55} />
        <Lights />
        <RimLights />
        <Aurora />
        <Starfield />
        <Ensemble />
        <Drones />
        <Rig />
        <DragOrbit />
        {/* round 21: grain + bloom + velocity chromatic aberration (gated) */}
        {fx && <PostFX />}
      </Canvas>
    </div>
  );
}
