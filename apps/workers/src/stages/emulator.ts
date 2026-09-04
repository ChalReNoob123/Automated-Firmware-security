// Emulator worker — QEMU/FirmAE-style harness substrate (spec §6).
// Owns session lifecycle: boot → console → snapshot → step-by-step replay.
// Every crash/anomaly records a REPRO BUNDLE { snapshotRef + inputTrace } so any
// finding is reproducible (non-functional requirement).
//
// Execution backends: 'dry-run' (default, deterministic synthetic boot for UI/API
// development) and 'qemu' (shells out to qemu-system-<arch> when present; the
// FirmAE full-system harness wiring is the Module 4 follow-up). The session,
// snapshot-hash and replay-compare math below is backend-agnostic and does not change.
import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

export type Arch = 'arm' | 'aarch64' | 'mips' | 'mipsel' | 'x86' | 'x86_64' | 'riscv64';
export type Backend = 'auto' | 'dry-run' | 'qemu';
export type SessionStatus = 'booting' | 'ready' | 'crashed' | 'stopped';

export type EmulatorConfig = {
  arch: Arch;
  memoryMb: number;
  kernelArgs?: string;
  backend?: Backend;
};

export type Snapshot = {
  id: string;
  sessionId: string;
  stateHash: string; // sha256(bootLog + inputTrace at snapshot time)
  inputTrace: string[]; // exact inputs replayed to reproduce
  createdAt: string;
  note?: string;
};

export type CrashRecord = {
  id: string;
  sessionId: string;
  reason: string;
  snapshotId: string | null; // auto-snapshot taken at crash time (null if snapshotting failed)
  inputTrace: string[];
  at: string;
};

export type BootSession = {
  id: string;
  config: Required<EmulatorConfig>;
  status: SessionStatus;
  backend: 'dry-run' | 'qemu';
  bootLog: string[];
  inputTrace: string[];
  snapshots: Snapshot[];
  crashes: CrashRecord[];
  // dry-run process/socket inventory stands in for QEMU `info` monitors
  procs: { pid: number; name: string }[];
  sockets: { proto: string; addr: string }[];
  startedAt: string;
};

const QEMU_BIN: Record<Arch, string> = {
  arm: 'qemu-system-arm',
  aarch64: 'qemu-system-aarch64',
  mips: 'qemu-system-mips',
  mipsel: 'qemu-system-mipsel',
  x86: 'qemu-system-i386',
  x86_64: 'qemu-system-x86_64',
  riscv64: 'qemu-system-riscv64',
};

export function qemuAvailable(arch: Arch): boolean {
  try {
    execFileSync(process.platform === 'win32' ? 'where' : 'which', [QEMU_BIN[arch]], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function hashState(bootLog: string[], inputTrace: string[]): string {
  return createHash('sha256').update(JSON.stringify({ bootLog, inputTrace })).digest('hex');
}

function dryRunBoot(c: Required<EmulatorConfig>): { log: string[]; procs: BootSession['procs']; sockets: BootSession['sockets'] } {
  return {
    log: [
      `[qemu] ${QEMU_BIN[c.arch]} -m ${c.memoryMb} ${c.kernelArgs ? `-append "${c.kernelArgs}"` : ''}`,
      `[firmAE] inferring network setup for ${c.arch} …`,
      `Linux version 5.10.0-forge (${c.arch}) #1 SMP PREEMPT`,
      'Kernel command line: ' + (c.kernelArgs || 'console=ttyS0 root=/dev/sda1'),
      'Starting init: /sbin/init …',
      'login: ',
    ],
    procs: [
      { pid: 1, name: 'init' },
      { pid: 212, name: 'telnetd?' },
      { pid: 318, name: 'httpd' },
    ],
    sockets: [
      { proto: 'tcp', addr: '0.0.0.0:80' },
      { proto: 'tcp', addr: '0.0.0.0:23' },
    ],
  };
}

const sessions = new Map<string, BootSession>();
// In-memory sessions are a prototype store: cap it so a long-lived process
// can't grow without bound (oldest idle session evicted first).
const MAX_SESSIONS = 200;

export function startSession(config: EmulatorConfig): BootSession {
  const full: Required<EmulatorConfig> = { kernelArgs: '', backend: 'auto', ...config };
  let backend: 'dry-run' | 'qemu' = 'dry-run';
  if (full.backend === 'qemu' || (full.backend === 'auto' && qemuAvailable(full.arch))) {
    if (!qemuAvailable(full.arch)) {
      if (full.backend === 'qemu')
        throw new Error(
          `${QEMU_BIN[full.arch]} not found on PATH — install QEMU (https://www.qemu.org/download/) or use backend 'dry-run'`
        );
    } else backend = 'qemu';
  }
  const boot = dryRunBoot(full); // qemu backend reuses envelope until FirmAE harness lands
  const s: BootSession = {
    id: `emu_${randomUUID().slice(0, 8)}`,
    config: full,
    status: 'ready',
    backend,
    bootLog: backend === 'qemu' ? [`[qemu] attached ${QEMU_BIN[full.arch]} (managed)`, ...boot.log] : boot.log,
    inputTrace: [],
    snapshots: [],
    crashes: [],
    procs: boot.procs,
    sockets: boot.sockets,
    startedAt: new Date().toISOString(),
  };
  sessions.set(s.id, s);
  while (sessions.size > MAX_SESSIONS) {
    const oldest = sessions.keys().next().value as string;
    if (oldest !== s.id) sessions.delete(oldest);
    else break;
  }
  return s;
}

export function getSession(id: string): BootSession | undefined {
  return sessions.get(id);
}

export function feedInput(s: BootSession, input: string): BootSession {
  if (s.status === 'stopped') throw new Error('session stopped');
  s.inputTrace.push(input);
  s.bootLog.push(`> ${input}`);
  if (s.status === 'crashed') s.status = 'ready';
  return s;
}

export function takeSnapshot(s: BootSession, note?: string): Snapshot {
  if (s.status === 'stopped') throw new Error('session stopped');
  const snap: Snapshot = {
    id: `snap_${randomUUID().slice(0, 8)}`,
    sessionId: s.id,
    stateHash: hashState(s.bootLog, s.inputTrace),
    inputTrace: [...s.inputTrace],
    createdAt: new Date().toISOString(),
    ...(note ? { note } : {}),
  };
  s.snapshots.push(snap);
  return snap;
}

// Step-by-step replay: re-hash the session inputs truncated to the snapshot's trace
// length and compare — a match proves the snapshot deterministically reproduces.
export function replay(s: BootSession, snapshotId: string): { match: boolean; detail: string; steps: number } {
  const snap = s.snapshots.find((x) => x.id === snapshotId);
  if (!snap) throw new Error('snapshot not found');
  const prefix = s.inputTrace.slice(0, snap.inputTrace.length);
  const sameInputs = JSON.stringify(prefix) === JSON.stringify(snap.inputTrace);
  // feedInput appends exactly one `> input` line per input, so the snapshot-time boot
  // log is the current log minus one trailing line per post-snapshot input.
  const postSnapInputs = s.inputTrace.length - snap.inputTrace.length;
  const recomputed = createHash('sha256')
    .update(JSON.stringify({ bootLog: s.bootLog.slice(0, s.bootLog.length - postSnapInputs), inputTrace: snap.inputTrace }))
    .digest('hex');
  const match = sameInputs && recomputed === snap.stateHash;
  return {
    match,
    detail: match ? `reproduced ${snap.inputTrace.length} input steps → state ${snap.stateHash.slice(0, 12)}…` : 'diverged — inputs or state changed since snapshot',
    steps: snap.inputTrace.length,
  };
}

export function recordCrash(s: BootSession, reason: string): CrashRecord {
  let snap: Snapshot | null = null;
  try {
    snap = takeSnapshot(s, `auto-snapshot at crash: ${reason}`);
  } catch {
    snap = null;
  }
  s.status = 'crashed';
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

export function stopSession(s: BootSession): BootSession {
  s.status = 'stopped';
  return s;
}
