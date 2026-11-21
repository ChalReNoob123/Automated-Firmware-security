import { execFileSync, spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// The ONE qemu substrate (round 36).
//
// Before this file existed the repo had two emulator stories: the workers stage
// pretended a `qemu` backend while reusing the dry-run envelope, and the API had
// a separate real launcher. Detection, binary mapping and process capture now
// live here, and the session builder in ./emulator.ts is their only caller.
//
// Executing an uploaded image means running untrusted code on the host, so it is
// OPT-IN: EMULATOR_QEMU=1. Without it nothing is spawned and the session records
// exactly why.
//
// Env:
//   EMULATOR_QEMU=1              allow real execution
//   EMULATOR_QEMU_BIN           override the binary (tests / non-standard installs)
//   EMULATOR_QEMU_TIMEOUT_MS    console capture window (default 8000)
export type Arch = 'arm' | 'aarch64' | 'mips' | 'mipsel' | 'x86' | 'x86_64' | 'riscv64';

const QEMU_BIN: Record<Arch, string> = {
  arm: 'qemu-system-arm',
  aarch64: 'qemu-system-aarch64',
  mips: 'qemu-system-mips',
  mipsel: 'qemu-system-mipsel',
  x86: 'qemu-system-i386',
  x86_64: 'qemu-system-x86_64',
  riscv64: 'qemu-system-riscv64',
};

const MAX_LINES = 200;
const MAX_BYTES = 32 * 1024;

export const qemuOptIn = () => process.env.EMULATOR_QEMU === '1';

/** Console-capture window for one launch; also the basis of the boot deadline. */
export function bootTimeoutMs(): number {
  const env = Number(process.env.EMULATOR_QEMU_TIMEOUT_MS ?? 8000) || 8000;
  return Math.max(500, env);
}

export function qemuAvailable(arch: Arch): boolean {
  try {
    execFileSync(process.platform === 'win32' ? 'where' : 'which', [QEMU_BIN[arch]], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/** The binary that would be launched, or null when this arch cannot be run. */
export function qemuBinaryFor(arch: string): string | null {
  const override = (process.env.EMULATOR_QEMU_BIN ?? '').trim();
  if (override) {
    // An explicit path is checked up front so a bad override reports the reason
    // on the session immediately instead of a booting phase that can only fail.
    // A bare command name is left to PATH, as before.
    return /[\\/]/.test(override) && !existsSync(override) ? null : override;
  }
  const bin = QEMU_BIN[arch as Arch];
  if (!bin) return null;
  return qemuAvailable(arch as Arch) ? bin : null;
}

/** True when a boot request would actually attempt execution right now. */
export const canLaunch = (arch: string) => qemuOptIn() && qemuBinaryFor(arch) !== null;

export type LaunchResult =
  | { ok: true; backend: 'qemu'; command: string; console: string[]; exitCode: number | null; note?: string }
  | { ok: false; reason: string };

export async function launchImage(opts: {
  arch: string;
  memoryMb: number;
  image: Uint8Array;
  timeoutMs?: number;
}): Promise<LaunchResult> {
  if (!qemuOptIn()) return { ok: false, reason: 'real execution is opt-in — set EMULATOR_QEMU=1 to allow it' };
  const bin = qemuBinaryFor(opts.arch);
  if (!bin) return { ok: false, reason: `no runnable qemu-system binary for arch ${opts.arch} (install QEMU or keep the twin image-bound)` };

  const timeoutMs = opts.timeoutMs ?? bootTimeoutMs();
  let dir = '';
  try {
    dir = await mkdtemp(join(tmpdir(), 'sf-twin-'));
    const imagePath = join(dir, 'firmware.bin');
    await writeFile(imagePath, opts.image);
    const args = ['-nographic', '-monitor', 'none', '-m', String(opts.memoryMb), '-kernel', imagePath];

    // A .cmd/.bat override needs cmd.exe, but never `shell: true`: that
    // concatenates args unescaped (Node DEP0190). cmd.exe /c keeps each arg
    // separate, exactly like the normal .exe path.
    const isScript = /\.(cmd|bat)$/i.test(bin);
    const spawnCmd = isScript ? 'cmd.exe' : bin;
    const spawnArgs = isScript ? ['/d', '/s', '/c', bin, ...args] : args;

    const captured = await new Promise<{ text: string; code: number | null; timedOut: boolean }>((resolve, reject) => {
      const child = spawn(spawnCmd, spawnArgs, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      let text = '';
      let timedOut = false;
      const take = (chunk: Buffer | string) => {
        if (text.length < MAX_BYTES) text += chunk.toString();
      };
      child.stdout?.on('data', take);
      child.stderr?.on('data', take);
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeoutMs);
      child.on('error', (e) => {
        clearTimeout(timer);
        reject(e);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({ text, code, timedOut });
      });
    });

    const consoleLines = captured.text
      .split(/\r?\n/)
      .map((l) => l.trimEnd())
      .filter((l) => l.length > 0)
      .slice(0, MAX_LINES);
    return {
      ok: true,
      backend: 'qemu',
      command: `${bin} ${args.join(' ')}`,
      console: consoleLines.length ? consoleLines : ['(qemu produced no console output)'],
      exitCode: captured.timedOut ? null : captured.code,
      ...(captured.timedOut ? { note: `capture window ${timeoutMs}ms elapsed — process killed; output above is what it printed` } : {}),
    };
  } catch (e) {
    return { ok: false, reason: `launch failed: ${(e as Error).message}` };
  } finally {
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}
