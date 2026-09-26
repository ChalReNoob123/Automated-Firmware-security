// Firmware genome / similarity search (spec: Autonomous Discovery Engine §3).
// Every function/image is reduced to a MinHash signature over byte-shingle
// hashes; one finding then flags every other device sharing the same library —
// across the fleet or an opt-in anonymized corpus. Pure-TS, deterministic, no
// native deps. Jaccard over shingles is the ground truth; MinHash accelerates it.
function fnv1a(str: string, seed: number): number {
  let h = (0x811c9dc5 ^ seed) >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

export const SHINGLE_N = 16; // bytes per shingle
export const SHINGLE_STRIDE = 8;
export const MINHASH_K = 128;

export function shingles(bytes: Uint8Array, n = SHINGLE_N, stride = SHINGLE_STRIDE): Set<number> {
  const out = new Set<number>();
  if (bytes.length < n) {
    out.add(fnv1a([...bytes].join(','), 7));
    return out;
  }
  for (let o = 0; o + n <= bytes.length; o += stride) {
    let s = '';
    for (let i = 0; i < n; i++) s += String.fromCharCode(bytes[o + i]);
    out.add(fnv1a(s, 7));
  }
  return out;
}

export function jaccard(a: Set<number>, b: Set<number>): number {
  if (!a.size && !b.size) return 1;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  return inter / (a.size + b.size - inter);
}

// MinHash signature: min shingle-hash under K seeded permutations.
export function minhash(bytes: Uint8Array, k = MINHASH_K): number[] {
  const sh = [...shingles(bytes)];
  const sig: number[] = [];
  for (let seed = 0; seed < k; seed++) {
    let m = 0xffffffff;
    for (const h of sh) {
      const v = fnv1a(h.toString(36), seed * 2654435761);
      if (v < m) m = v;
    }
    sig.push(m);
  }
  return sig;
}

export function minhashSimilarity(a: number[], b: number[]): number {
  let same = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] === b[i]) same++;
  return same / Math.max(a.length, b.length);
}

export type GenomeHit = { id: string; jaccard: number; minhash: number };

export class GenomeIndex {
  private entries = new Map<string, { shingles: Set<number>; sig: number[]; bytes: number }>();

  add(id: string, bytes: Uint8Array): void {
    this.entries.set(id, { shingles: shingles(bytes), sig: minhash(bytes), bytes: bytes.length });
  }

  get size(): number {
    return this.entries.size;
  }

  // Two-phase: MinHash pre-filter, exact Jaccard for candidates above threshold/2.
  query(bytes: Uint8Array, threshold = 0.5): GenomeHit[] {
    const qSig = minhash(bytes);
    const qSh = shingles(bytes);
    const out: GenomeHit[] = [];
    for (const [id, e] of this.entries) {
      const mh = minhashSimilarity(qSig, e.sig);
      if (mh < threshold / 2) continue;
      const j = jaccard(qSh, e.shingles);
      if (j >= threshold) out.push({ id, jaccard: +j.toFixed(4), minhash: +mh.toFixed(4) });
    }
    return out.sort((a, b) => b.jaccard - a.jaccard);
  }
}
