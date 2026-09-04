// Real binary analysis primitives (no native toolchain required).
// - parseElf: full ELF header decode (class/endianness/machine/entry/program+section counts)
// - carveGzip: member scan with header decode + best-effort inflate via node:zlib
// - detectNativeTools: probe for binwalk/unblob/qemu/yara/ghidra on PATH so the
//   containerized workers escalate to the real tool when present, with this module
//   as the always-available fallback. Surfaced via GET /v1/capabilities.
import { execFileSync } from 'node:child_process';
import { gunzipSync } from 'node:zlib';
import { qemuAvailable } from './emulator.js';

export type ElfInfo = {
  valid: true;
  bits: 32 | 64;
  endian: 'little' | 'big';
  machine: string;
  machineCode: number;
  entry: string; // hex
  phCount: number;
  shCount: number;
  exeType: string;
};

const MACHINES: Record<number, string> = {
  2: 'SPARC', 3: 'x86', 8: 'MIPS', 20: 'PowerPC', 21: 'PowerPC64', 22: 'S390', 40: 'ARM',
  41: 'Alpha', 50: 'IA-64', 62: 'x86-64', 183: 'AArch64', 188: 'AMDGPU', 243: 'RISC-V', 253: 'C-SKY',
};
const TYPES: Record<number, string> = { 0: 'NONE', 1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE' };

export function parseElf(buf: Uint8Array): ElfInfo | { valid: false; reason: string } {
  if (buf.length < 52) return { valid: false, reason: 'too small for ELF header' };
  if (!(buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46)) return { valid: false, reason: 'bad magic' };
  const cls = buf[4];
  const enc = buf[5];
  if (cls !== 1 && cls !== 2) return { valid: false, reason: `unknown class ${cls}` };
  if (enc !== 1 && enc !== 2) return { valid: false, reason: `unknown endianness ${enc}` };
  const le = enc === 1;
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u16 = (o: number) => (le ? view.getUint16(o, true) : view.getUint16(o, false));
  const u32 = (o: number) => (le ? view.getUint32(o, true) : view.getUint32(o, false));
  const u64 = (o: number) => (le ? view.getBigUint64(o, true) : view.getBigUint64(o, false));
  const machineCode = u16(18);
  const is64 = cls === 2;
  const minLen = is64 ? 64 : 52;
  if (buf.length < minLen) return { valid: false, reason: 'truncated header' };
  return {
    valid: true,
    bits: is64 ? 64 : 32,
    endian: le ? 'little' : 'big',
    machine: MACHINES[machineCode] ?? `unknown(${machineCode})`,
    machineCode,
    entry: '0x' + (is64 ? u64(24).toString(16) : u32(24).toString(16)),
    phCount: u16(is64 ? 56 : 44),
    shCount: u16(is64 ? 60 : 48),
    exeType: TYPES[u16(16)] ?? `unknown(${u16(16)})`,
  };
}

export type GzipMember = {
  offset: number;
  mtime: number;
  os: string;
  name?: string;
  inflatedBytes: number | null; // null when trailing data defeats whole-buffer inflate
};

const GZ_OS: Record<number, string> = { 0: 'FAT', 3: 'Unix', 7: 'Macintosh', 11: 'NTFS' };
const INFLATE_CAP = 32 * 1024 * 1024;

export function carveGzip(buf: Uint8Array): GzipMember[] {
  const out: GzipMember[] = [];
  for (let off = 0; off + 10 <= buf.length; off++) {
    if (!(buf[off] === 0x1f && buf[off + 1] === 0x8b && buf[off + 2] === 0x08)) continue;
    const flg = buf[off + 3];
    if (flg & 0xe0) continue; // reserved bits — not a real member
    let p = off + 10;
    if (flg & 0x04) {
      if (p + 2 > buf.length) continue;
      const xlen = buf[p] | (buf[p + 1] << 8);
      p += 2 + xlen;
    }
    if (flg & 0x08) {
      while (p < buf.length && buf[p] !== 0) p++;
      p++;
    }
    if (flg & 0x10) {
      while (p < buf.length && buf[p] !== 0) p++;
      p++;
    }
    if (flg & 0x02) p += 2;
    if (p > buf.length) continue;
    let name: string | undefined;
    if (flg & 0x08) {
      let np = off + 10 + (flg & 0x04 ? 2 + (buf[off + 10] | (buf[off + 11] << 8)) : 0);
      let s = '';
      while (np < buf.length && buf[np] !== 0 && s.length < 256) s += String.fromCharCode(buf[np++]);
      if (s) name = s;
    }
    let inflatedBytes: number | null = null;
    try {
      const slice = Buffer.from(buf.subarray(off, Math.min(buf.length, off + INFLATE_CAP)));
      inflatedBytes = gunzipSync(slice).length;
    } catch {
      inflatedBytes = null;
    }
    out.push({
      offset: off,
      mtime: buf[off + 4] | (buf[off + 5] << 8) | (buf[off + 6] << 16) | (buf[off + 7] << 24),
      os: GZ_OS[buf[off + 9]] ?? `unknown(${buf[off + 9]})`,
      ...(name ? { name } : {}),
      inflatedBytes,
    });
    if (out.length >= 64) break; // sanity bound on pathological blobs
  }
  return out;
}

function onPath(bin: string): boolean {
  try {
    execFileSync(process.platform === 'win32' ? 'where' : 'which', [bin], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

export type NativeCaps = {
  binwalk: boolean;
  unblob: boolean;
  yara: boolean;
  ghidra: boolean;
  qemu: Record<string, boolean>;
};

// Probe the host for the heavy native toolchain. Container images install these;
// bare dev machines fall back to the pure-TS implementations above.
export function detectNativeTools(): NativeCaps {
  const qemu: Record<string, boolean> = {};
  for (const arch of ['arm', 'aarch64', 'mips', 'mipsel', 'x86', 'x86_64', 'riscv64'] as const) qemu[arch] = qemuAvailable(arch);
  return {
    binwalk: onPath('binwalk'),
    unblob: onPath('unblob'),
    yara: onPath('yara'),
    ghidra: onPath('ghidraRun') || onPath('analyzeHeadless'),
    qemu,
  };
}
