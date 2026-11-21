import { createHash, randomUUID } from 'node:crypto';
import { extractStrings, parseElf } from './binary.js';
import { bootTimeoutMs, canLaunch, launchImage, type Arch } from './qemu.js';

// THE emulator implementation (round 36).
//
// Session semantics used to exist twice: this module owned dry-run sessions,
// snapshots and replay for the CLI/pipeline, while apps/api/src/routes/emulator.ts
// carried a near-copy with its own hashing, its own ELF→arch mapping and its own
// boot log. They drifted (an image-hash mismatch made every image-bound replay
// report DIVERGED). There is now one implementation of the model, and the API is
// only HTTP + org-scoped persistence around it.
//
// Two-phase boot:
//   buildTwin()  — synchronous, pure: derives arch/banner/boot context from the
//                  image, returns a session in `ready` (or `booting`).
//   launchTwin() — asynchronous: runs qemu (opt-in) and captures the console.
// The API persists between the phases, so creating a session never blocks on a
// slow boot.
export type Backend = 'dry-run' | 'image-bound' | 'qemu';
export type Execution = 'none' | 'qemu';
export type SessionStatus = 'booting' | 'ready' | 'crashed' | 'stopped' | 'failed';

export type TwinImage = {
  firmwareId: string;
  version: string;
  sha256: string;
  bytes: number;
  data: Uint8Array;
};

export type TwinImageInfo = Omit<TwinImage, 'data'> & {
  elf: { machine: string; bits: number; endian: string; entry: string; exeType: string } | null;
  banner: string[];
};

export type Snapshot = {
  id: string;
  sessionId: string;
  stateHash: string;
  inputTrace: string[];
  createdAt: string;
  note?: string;
};

export type CrashRecord = {
  id: string;
  sessionId: string;
  reason: string;
  snapshotId: string | null;
  inputTrace: string[];
  at: string;
};

export type TwinSession = {
  id: string;
  arch: string;
  memoryMb: number;
  kernelArgs: string;
  backend: Backend;
  execution: Execution;
  status: SessionStatus;
  bootLog: string[];
  inputTrace: string[];
  snapshots: Snapshot[];
  crashes: CrashRecord[];
  image?: TwinImageInfo;
  /** exact argv, when execution actually happened */
  command?: string;
  /** why it did not execute, when it didn't */
  launchError?: string;
  /** when a booting session stops being believable; cleared once it settles */
  bootDeadline?: string;
  startedAt: string;
  updatedAt: string;
};

/** Backwards-compatible alias: the pipeline and CLI already speak BootSession. */
export type BootSession = TwinSession;
export type EmulatorConfig = { arch: Arch; memoryMb: number; kernelArgs?: string };

const ARCH_BY_MACHINE: Record<number, string> = { 3: 'x86', 62: 'x86_64', 40: 'arm', 183: 'aarch64', 8: 'mips', 243: 'riscv64' };

const archForElf = (elf: { machineCode: number; endian: string }): string | null => {
  const base = ARCH_BY_MACHINE[elf.machineCode];
  if (!base) return null;
  return base === 'mips' && elf.endian === 'little' ? 'mipsel' : base;
};

// Real strings from the image, preferring version/build-looking lines. Purely
// observational — nothing is invented.
function pickBanner(data: Uint8Array): string[] {
  const lines = extractStrings(data)
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s.length >= 8 && s.length <= 120 && /[a-z]/i.test(s));
  const interesting = lines.filter((s) => /version|linux|u-?boot|firmware|build|release|rootfs|init/i.test(s));
  return [...new Set([...interesting, ...lines])].slice(0, 4);
}

function imageInfo(image: TwinImage, elf: ReturnType<typeof parseElf>): TwinImageInfo {
  const { data: _data, ...meta } = image;
  return {
    ...meta,
    elf: elf.valid ? { machine: elf.machine, bits: elf.bits, endian: elf.endian, entry: elf.entry, exeType: elf.exeType } : null,
    banner: pickBanner(image.data),
  };
}

function imageBootLog(img: TwinImageInfo): string[] {
  return [
    `[image] ${img.version} · sha256:${img.sha256.slice(0, 12)}… · ${img.bytes} bytes`,
    img.elf
      ? `[elf] ${img.elf.machine} ${img.elf.bits}-bit ${img.elf.endian} ${img.elf.exeType} · entry ${img.elf.entry}`
      : '[elf] no ELF header — raw image or container',
    ...img.banner.map((b) => `[strings] ${b}`),
    '[twin] image attached read-only; not executed yet',
    'login: ',
  ];
}

function hashState(s: TwinSession): string {
  return createHash('sha256')
    .update(JSON.stringify({ image: s.image?.sha256 ?? null, bootLog: s.bootLog, inputTrace: s.inputTrace }))
    .digest('hex');
}

// A launch can only still be alive inside this window: the console capture
// gives up after EMULATOR_QEMU_TIMEOUT_MS, plus a margin for the write-back.
// If a session is still 'booting' past that, its process is gone (an API restart
// is the usual cause) and the session must say so rather than stay booting.
export const BOOT_GRACE_MS = 10_000;
export const bootDeadlineFrom = (now = Date.now()) => new Date(now + bootTimeoutMs() + BOOT_GRACE_MS).toISOString();

/**
 * Settle a booting session whose deadline has passed: 'failed', with the reason
 * in launchError and the log. Returns true when it changed, so callers persist.
 */
export function failStaleBoot(s: TwinSession, now = Date.now()): boolean {
  if (s.status !== 'booting') return false;
  // A booting row without a deadline (written by an older build, or corrupt)
  // falls back to its last update plus the same window, so no row can sit in
  // 'booting' forever just because the field is missing.
  const deadline = s.bootDeadline
    ? Date.parse(s.bootDeadline)
    : Date.parse(s.updatedAt) + bootTimeoutMs() + BOOT_GRACE_MS;
  if (!Number.isFinite(deadline) || deadline > now) return false;
  s.status = 'failed';
  s.launchError = 'boot never reported back before its deadline — the API restarted while this session was launching';
  s.bootLog = [...s.bootLog.filter((l) => !l.startsWith('[twin] boot failed')), `[twin] boot failed: ${s.launchError}`];
  delete s.bootDeadline;
  s.updatedAt = new Date().toISOString();
  return true;
}

export function buildTwin(input: {
  arch?: string;
  memoryMb: number;
  kernelArgs?: string;
  image?: TwinImage;
}): TwinSession {
  // One parse, used for both the provenance record and the arch decision.
  const elf = input.image ? parseElf(input.image.data) : null;
  const img = input.image && elf ? imageInfo(input.image, elf) : undefined;
  const derived = elf?.valid ? archForElf(elf) : null;
  const arch = derived ?? input.arch ?? 'arm';
  const now = new Date().toISOString();
  const bootLog = img
    ? imageBootLog(img)
    : [`Linux version 5.10.0-forge (${arch}) #1 SMP PREEMPT`, 'Starting init: /sbin/init …', 'login: '];
  return {
    id: `emu_${randomUUID().slice(0, 8)}`,
    arch,
    memoryMb: input.memoryMb,
    kernelArgs: input.kernelArgs ?? '',
    backend: img ? 'image-bound' : 'dry-run',
    execution: 'none',
    // The caller promotes this to 'booting' only when a launch will actually
    // start; otherwise the session is usable immediately.
    status: 'ready',
    bootLog,
    inputTrace: [],
    snapshots: [],
    crashes: [],
    ...(img ? { image: img } : {}),
    startedAt: now,
    updatedAt: now,
  };
}

/** Would buildTwin()'s result be booted for real on this host? */
export const willLaunch = (s: TwinSession) => !!s.image && canLaunch(s.arch);

/**
 * Phase two: run the image and capture its console. Never throws — a launch
 * failure lands on the session as `launchError` so the caller can persist a
 * truthful result instead of losing the session to a rejected promise.
 */
export async function launchTwin(s: TwinSession, image: TwinImage, opts: { timeoutMs?: number } = {}): Promise<TwinSession> {
  const r = await launchImage({ arch: s.arch, memoryMb: s.memoryMb, image: image.data, ...(opts.timeoutMs ? { timeoutMs: opts.timeoutMs } : {}) });
  if (r.ok) {
    s.backend = 'qemu';
    s.execution = 'qemu';
    s.command = r.command;
    s.launchError = undefined;
    s.bootLog = [`[launch] ${r.command}`, ...r.console, ...(r.note ? [`[launch] ${r.note}`] : [])];
  } else {
    s.launchError = r.reason;
    // Replace rather than append on a retry: one truthful line, not a stack.
    s.bootLog = [...s.bootLog.filter((l) => !l.startsWith('[twin] cannot execute')), `[twin] cannot execute this image: ${r.reason}`];
  }
  s.status = 'ready';
  delete s.bootDeadline;
  s.updatedAt = new Date().toISOString();
  return s;
}

const sessions = new Map<string, TwinSession>();

/**
 * Synchronous convenience for the CLI/pipeline: build a session, and launch it
 * only if execution is actually possible. The API uses buildTwin/launchTwin
 * directly so the boot can be asynchronous.
 */
/** Registry lookup for sessions built by startSession (CLI, pipeline, MCP). */
export function getSession(id: string): TwinSession | undefined {
  return sessions.get(id);
}

export function startSession(config: EmulatorConfig): TwinSession {
  const s = buildTwin({ arch: config.arch, memoryMb: config.memoryMb, ...(config.kernelArgs ? { kernelArgs: config.kernelArgs } : {}) });
  sessions.set(s.id, s);
  while (sessions.size > 200) {
    const oldest = sessions.keys().next().value as string;
    if (oldest !== s.id) sessions.delete(oldest);
    else break;
  }
  return s;
}

export function feedInput(s: TwinSession, input: string): TwinSession {
  if (s.status === 'stopped') throw new Error('session stopped');
  if (s.status === 'booting') throw new Error('session still booting');
  if (s.status === 'failed') throw new Error('session failed to boot — start a new twin');
  s.inputTrace.push(input);
  s.bootLog.push(`> ${input}`);
  if (s.status === 'crashed') s.status = 'ready';
  s.updatedAt = new Date().toISOString();
  return s;
}

export function takeSnapshot(s: TwinSession, note?: string): Snapshot {
  if (s.status === 'stopped') throw new Error('session stopped');
  // A mid-boot snapshot would capture the pre-launch log, and the console that
  // arrives afterwards would make its replay diverge by construction.
  if (s.status === 'booting') throw new Error('session still booting');
  if (s.status === 'failed') throw new Error('session failed to boot — start a new twin');
  const snap: Snapshot = {
    id: `snap_${randomUUID().slice(0, 8)}`,
    sessionId: s.id,
    stateHash: hashState(s),
    inputTrace: [...s.inputTrace],
    createdAt: new Date().toISOString(),
    ...(note ? { note } : {}),
  };
  s.snapshots.push(snap);
  s.updatedAt = new Date().toISOString();
  return snap;
}

export function replay(s: TwinSession, snapshotId: string): { match: boolean; detail: string; steps: number } {
  const snap = s.snapshots.find((x) => x.id === snapshotId);
  if (!snap) throw new Error('snapshot not found');
  const prefix = s.inputTrace.slice(0, snap.inputTrace.length);
  const sameInputs = JSON.stringify(prefix) === JSON.stringify(snap.inputTrace);
  // feedInput appends exactly one `> input` line per input, so the snapshot-time
  // log is the current log minus one trailing line per post-snapshot input.
  const postSnapInputs = s.inputTrace.length - snap.inputTrace.length;
  const recomputed = createHash('sha256')
    .update(
      JSON.stringify({
        image: s.image?.sha256 ?? null,
        bootLog: s.bootLog.slice(0, s.bootLog.length - postSnapInputs),
        inputTrace: snap.inputTrace,
      })
    )
    .digest('hex');
  const match = sameInputs && recomputed === snap.stateHash;
  return {
    match,
    detail: match
      ? `reproduced ${snap.inputTrace.length} input steps → state ${snap.stateHash.slice(0, 12)}…`
      : 'diverged — inputs or state changed since snapshot',
    steps: snap.inputTrace.length,
  };
}

export function recordCrash(s: TwinSession, reason: string): CrashRecord {
  let snap: Snapshot | null = null;
  try {
    snap = takeSnapshot(s, `auto-snapshot at crash: ${reason}`);
  } catch {
    snap = null;
  }
  s.status = 'crashed';
  s.updatedAt = new Date().toISOString();
  const crash: CrashRecord = {
    id: `crash_${randomUUID().slice(0, 8)}`,
    sessionId: s.id,
    reason,
    snapshotId: snap?.id ?? null,
    inputTrace: [...s.inputTrace],
    at: new Date().toISOString(),
  };
  s.crashes.push(crash);
  return crash;
}

export function stopSession(s: TwinSession): TwinSession {
  s.status = 'stopped';
  s.updatedAt = new Date().toISOString();
  return s;
}
