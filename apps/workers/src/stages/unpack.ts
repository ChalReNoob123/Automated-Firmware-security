// Stage 2 — Unpacking. Magic-byte container detection (binwalk/unblob do the real
// extraction in the containerized worker; this module decides WHAT to run and WHERE).
// Scans offset 0 plus embedded signatures in the first 64 KiB (common for OEM multi-image blobs).

export type ContainerKind =
  | 'squashfs'
  | 'jffs2'
  | 'ubi'
  | 'trx'
  | 'uimage'
  | 'gzip'
  | 'xz'
  | 'zip'
  | 'elf'
  | 'yaffs2';

export type ContainerHit = { kind: ContainerKind; offset: number; tool: string };

const MAGICS: { kind: ContainerKind; magic: number[]; tool: string }[] = [
  { kind: 'squashfs', magic: [0x68, 0x73, 0x71, 0x73], tool: 'sasquatch/unsquashfs' }, // hsqs
  { kind: 'jffs2', magic: [0x85, 0x19], tool: 'jefferson' },
  { kind: 'ubi', magic: [0x55, 0x42, 0x49, 0x23], tool: 'ubinize/ubireader' }, // UBI#
  { kind: 'trx', magic: [0x48, 0x44, 0x52, 0x30], tool: 'binwalk -e' }, // HDR0
  { kind: 'uimage', magic: [0x27, 0x05, 0x19, 0x56], tool: 'dumpimage (u-boot-tools)' },
  { kind: 'gzip', magic: [0x1f, 0x8b], tool: 'binwalk -e / unblob' },
  { kind: 'xz', magic: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], tool: 'unblob' },
  { kind: 'zip', magic: [0x50, 0x4b, 0x03, 0x04], tool: 'unzip' },
  { kind: 'elf', magic: [0x7f, 0x45, 0x4c, 0x46], tool: 'readelf (static analysis input)' },
  { kind: 'yaffs2', magic: [0x59, 0x41, 0x46, 0x46], tool: 'unspare/unyaffs2' },
];

const SCAN_WINDOW = 64 * 1024;

export function detectContainers(buf: Uint8Array): ContainerHit[] {
  const hits: ContainerHit[] = [];
  const seen = new Set<string>();
  const end = Math.min(buf.length, SCAN_WINDOW);
  for (const { kind, magic, tool } of MAGICS) {
    for (let off = 0; off + magic.length <= end; off++) {
      let ok = true;
      for (let i = 0; i < magic.length; i++) {
        if (buf[off + i] !== magic[i]) {
          ok = false;
          break;
        }
      }
      if (ok) {
        const key = `${kind}@${off}`;
        if (!seen.has(key)) {
          seen.add(key);
          hits.push({ kind, offset: off, tool });
        }
        break; // first occurrence per kind is enough for planning
      }
    }
  }
  return hits.sort((a, b) => a.offset - b.offset);
}

export type UnpackPlan = {
  hits: ContainerHit[];
  extraction: string[]; // ordered tool invocations the containerized worker attempts
  extractable: boolean;
};

export function planUnpack(buf: Uint8Array): UnpackPlan {
  const hits = detectContainers(buf);
  return {
    hits,
    extraction: hits.map((h) => `${h.tool}  # ${h.kind} @0x${h.offset.toString(16)}`),
    extractable: hits.length > 0,
  };
}
