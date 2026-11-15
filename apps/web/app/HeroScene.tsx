'use client';
import { useMemo, useRef } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import * as THREE from 'three';
import PostFX, { usePostOK } from './post/PostFX';

// Cinematic hero scene: device core + exploded shards + threat-radar rings + sweep + starfield.
// Deterministic (seeded) layout, capped pixel ratio, pointer parallax. No postprocessing
// dependency — glow comes from emissive + additive materials + fog.
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

function Starfield({ count = 1400 }: { count?: number }) {
  const ref = useRef<THREE.Points>(null);
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
  useFrame((_, d) => {
    if (ref.current) ref.current.rotation.y += d * 0.008;
  });
  return (
    <points ref={ref} geometry={geom}>
      <pointsMaterial size={0.06} vertexColors transparent opacity={0.85} blending={THREE.AdditiveBlending} depthWrite={false} sizeAttenuation />
    </points>
  );
}

function Core() {
  const outer = useRef<THREE.Mesh>(null);
  const inner = useRef<THREE.Mesh>(null);
  const heart = useRef<THREE.Mesh>(null);
  useFrame((state, d) => {
    const t = state.clock.elapsedTime;
    if (outer.current) {
      outer.current.rotation.y += d * 0.12;
      outer.current.rotation.x = Math.sin(t * 0.2) * 0.25;
    }
    if (inner.current) {
      inner.current.rotation.y -= d * 0.2;
      inner.current.rotation.z += d * 0.07;
    }
    if (heart.current) {
      const s = 0.42 + Math.sin(t * 1.6) * 0.05;
      heart.current.scale.set(s, s, s);
      heart.current.rotation.y += d * 0.5;
    }
  });
  return (
    <group>
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
    </group>
  );
}

function Shards({ count = 14 }: { count?: number }) {
  const group = useRef<THREE.Group>(null);
  const items = useMemo(() => {
    const rng = mulberry(0x5eed);
    return Array.from({ length: count }, (_, i) => ({
      angle: (i / count) * Math.PI * 2 + rng() * 0.4,
      radius: 3.1 + rng() * 1.6,
      y: (rng() - 0.5) * 2.4,
      tilt: [rng() * Math.PI, rng() * Math.PI, rng() * Math.PI] as [number, number, number],
      size: [0.7 + rng() * 0.7, 0.05, 0.45 + rng() * 0.45] as [number, number, number],
      phase: rng() * Math.PI * 2,
      cyan: rng() > 0.45,
    }));
  }, [count]);
  useFrame((state, d) => {
    const t = state.clock.elapsedTime;
    if (group.current) group.current.rotation.y += d * 0.05;
    group.current?.children.forEach((m, i) => {
      m.position.y = items[i].y + Math.sin(t * 0.7 + items[i].phase) * 0.22;
    });
  });
  return (
    <group ref={group}>
      {items.map((s, i) => (
        <mesh key={i} position={[Math.cos(s.angle) * s.radius, s.y, Math.sin(s.angle) * s.radius]} rotation={s.tilt}>
          <boxGeometry args={s.size} />
          <meshStandardMaterial color={s.cyan ? '#0e7490' : '#6d28d9'} emissive={s.cyan ? '#22d3ee' : '#a855f7'} emissiveIntensity={0.55} roughness={0.35} metalness={0.6} />
        </mesh>
      ))}
    </group>
  );
}

function Radar() {
  const rings = useRef<(THREE.Mesh | null)[]>([]);
  const sweep = useRef<THREE.Mesh>(null);
  useFrame((state, d) => {
    const t = state.clock.elapsedTime;
    rings.current.forEach((r, i) => {
      if (!r) return;
      const p = (t * 0.22 + i / 3) % 1;
      const s = 1 + p * 5.2;
      r.scale.set(s, s, s);
      (r.material as THREE.MeshBasicMaterial).opacity = 0.5 * (1 - p);
    });
    if (sweep.current) sweep.current.rotation.z -= d * 0.9;
  });
  return (
    <group position={[0, -2.6, 0]} rotation-x={-Math.PI / 2}>
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

function Rig() {
  useFrame((state, d) => {
    const { x, y } = state.pointer;
    state.camera.position.x += (x * 1.4 - state.camera.position.x) * Math.min(1, d * 2.5);
    state.camera.position.y += (1.6 + y * 0.9 - state.camera.position.y) * Math.min(1, d * 2.5);
    state.camera.lookAt(0, -0.4, 0);
  });
  return null;
}

// Viewport-aware placement: the copy owns the left ~62% of any width, so the
// ensemble hugs the right edge and shrinks on narrow viewports — at 1280px it
// no longer slides under the headline (the old fixed [4.2, -0.35, 0] reached
// ~64% of the frame at that width and clipped the text).
function Ensemble() {
  const vp = useThree((s) => s.viewport);
  return (
    <group position={[vp.width * 0.5, -0.55, 0]} scale={Math.min(0.75, vp.width / 22.4)}>
      <Core />
      <Shards />
      <Radar />
    </group>
  );
}

export default function HeroScene() {
  const fx = usePostOK();
  return (
    <Canvas
      dpr={[1, 2]}
      camera={{ position: [0, 1.6, 11.5], fov: 52 }}
      gl={{ antialias: true, alpha: false, powerPreference: 'high-performance' }}
      style={{ position: 'absolute', inset: 0 }}
    >
      <color attach="background" args={['#020617']} />
      <fog attach="fog" args={['#020617', 12, 34]} />
      <ambientLight intensity={0.55} />
      <pointLight position={[8, 6, 8]} intensity={60} color="#22d3ee" />
      <pointLight position={[-8, -4, 6]} intensity={50} color="#a855f7" />
        <Starfield />
      {/* The hero copy owns the left half — the viewport-aware Ensemble keeps the
          device core right of that zone at any window size. */}
      <Ensemble />
      <Rig />
      {/* round 21: grain + bloom + velocity chromatic aberration (gated) */}
      {fx && <PostFX />}
    </Canvas>
  );
}
