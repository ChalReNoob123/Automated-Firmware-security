// Root of Trust & Secure Boot Chain Verification (spec §4) — dedicated module.
// Answers what a certification body asks first: is secure boot enforced end-to-end
// (RoT → bootloader → OS → application), is downgrade blocked, are debug interfaces
// closed, and do keys live in hardware? Results map to PSA Certified RoT levels with
// a Common Criteria note. Honest naming throughout: these are readiness INDICATORS
// from firmware evidence, not a certification verdict.

// ── 1. Boot chain ──
export type BootStage = {
  name: string; // e.g. 'rom-rot', 'spl', 'u-boot', 'kernel', 'rootfs', 'app'
  hash: string; // hex digest the previous stage measured
  signed: boolean;
  signatureValid: boolean;
  keyRef: string; // which key verified it, e.g. 'OEM-root-CA' / 'none'
  immutable?: boolean; // true for the on-die ROM RoT
  measuresNext?: string; // digest this stage recorded for the next stage
};

export type ChainResult = { ok: boolean; issues: string[] };

export function verifyChain(stages: BootStage[]): ChainResult {
  const issues: string[] = [];
  if (stages.length === 0) return { ok: false, issues: ['no boot stages supplied — chain unverifiable'] };
  const [rot] = stages;
  if (!rot.immutable) issues.push(`first stage '${rot.name}' is not marked immutable — RoT must be on-die ROM`);
  stages.forEach((s, i) => {
    if (!s.signed) issues.push(`stage ${i} '${s.name}': unsigned`);
    else if (!s.signatureValid) issues.push(`stage ${i} '${s.name}': signature INVALID (keyRef=${s.keyRef})`);
    if (i < stages.length - 1) {
      const next = stages[i + 1];
      if (!s.measuresNext) issues.push(`stage '${s.name}': does not measure next stage — trust gap before '${next.name}'`);
      else if (s.measuresNext.toLowerCase() !== next.hash.toLowerCase())
        issues.push(`measurement mismatch: '${s.name}' recorded ${s.measuresNext} but '${next.name}' hashes to ${next.hash}`);
    }
  });
  return { ok: issues.length === 0, issues };
}

// ── 2. Anti-rollback / downgrade protection ──
export type RollbackEvidence = {
  version: string;
  prevVersion?: string; // version of the prior analyzed build, if any
  rollbackCounter?: number | null; // eFuse/RPMB monotonic counter
  antiRollbackFuse?: boolean; // OEM anti-rollback enforcement enabled
};

export type RollbackResult = { protected: boolean; downgrade: boolean; detail: string; issues: string[] };

function cmpVersions(a: string, b: string): number {
  const pa = a.split(/[.\-+]/).map((x) => parseInt(x, 10));
  const pb = b.split(/[.\-+]/).map((x) => parseInt(x, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = isNaN(pa[i] ?? NaN) ? 0 : (pa[i] ?? 0);
    const y = isNaN(pb[i] ?? NaN) ? 0 : (pb[i] ?? 0);
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export function checkRollback(ev: RollbackEvidence): RollbackResult {
  const issues: string[] = [];
  const downgrade = ev.prevVersion ? cmpVersions(ev.version, ev.prevVersion) < 0 : false;
  if (downgrade) issues.push(`downgrade: ${ev.prevVersion} → ${ev.version} accepted`);
  if (!ev.antiRollbackFuse) issues.push('anti-rollback enforcement not enabled — any signed older image may boot');
  if (ev.rollbackCounter == null) issues.push('no monotonic rollback counter (eFuse/RPMB) evidenced');
  const prot = !downgrade && !!ev.antiRollbackFuse && ev.rollbackCounter != null;
  return {
    protected: prot,
    downgrade,
    detail: prot
      ? `v${ev.version}, counter=${ev.rollbackCounter}, enforcement on`
      : `v${ev.version}` + (ev.prevVersion ? ` (prev v${ev.prevVersion})` : '') + ', protection incomplete',
    issues,
  };
}

// ── 3. Exposed debug interfaces (emulator / image probing) ──
export type DebugFinding = { id: string; risk: string; line: number; preview: string };

const DEBUG_PATTERNS: { id: string; risk: string; re: RegExp }[] = [
  { id: 'jtag-enabled', risk: 'physical attack surface: JTAG enabled', re: /\bjtag\b/i },
  { id: 'swd-enabled', risk: 'physical attack surface: SWD enabled', re: /\bswd(_io|io)?\b/i },
  { id: 'uart-console', risk: 'physical attack surface: UART console (root shell vector)', re: /console\s*=\s*tty(S|AMA|USB|O|mxc)/i },
  { id: 'boot-to-shell', risk: 'boot bypass: kernel boots straight to shell', re: /\binit=\/(bin\/(sh|bash)|sbin\/init\.sh)\b|\brdinit=\/bin\/sh\b|\bsingle\b/i },
  { id: 'telnetd', risk: 'unauthenticated remote shell service', re: /\btelnetd\b/i },
  { id: 'gdbserver', risk: 'remote debugger stub in production image', re: /\bgdbserver\b/i },
  { id: 'android-debuggable', risk: 'debuggable build (adbd root)', re: /ro\.debuggable\s*=\s*1|ro\.secure\s*=\s*0/i },
];

export function probeDebugInterfaces(text: string): DebugFinding[] {
  const out: DebugFinding[] = [];
  text.split('\n').forEach((line, i) => {
    for (const p of DEBUG_PATTERNS) {
      if (p.re.test(line)) out.push({ id: p.id, risk: p.risk, line: i + 1, preview: line.trim().slice(0, 120) });
    }
  });
  return out;
}

// ── 4. Key storage: hardware Secure Element / TPM / TrustZone vs unprotected flash ──
export type KeyStorage = 'hardware' | 'unprotected' | 'unknown';

const HW_RE = /atecc\d+|ecc508|se050|optiga|\btpm\b|trustzone|\btee\b|psa[_ -]?(its|ps)|secure[ -]?element|rpmb/i;
const RAW_KEY_RE = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\.pem["']?\s*[,}\]]?\s*$|\/etc\/.*\.key\b/i;

export function classifyKeyStorage(text: string): { storage: KeyStorage; detail: string } {
  const rawKey = RAW_KEY_RE.test(text);
  const hw = HW_RE.test(text);
  if (rawKey) return { storage: 'unprotected', detail: 'private key material present in image (flash-readable)' };
  if (hw) return { storage: 'hardware', detail: 'keys reference Secure Element/TPM/TrustZone/PSA storage, no raw material found' };
  return { storage: 'unknown', detail: 'no key references evidenced — supply key manifest or HSM attestation' };
}

// ── 5. Standards mapping ──
export type PsaReadiness = 'None' | 'Level 1' | 'Level 2' | 'Level 2+SE' | 'Level 3-indicators';

export function mapPsa(chainOk: boolean, rollbackProtected: boolean, keys: KeyStorage): { level: PsaReadiness; rationale: string } {
  if (chainOk && rollbackProtected && keys === 'hardware')
    return { level: 'Level 3-indicators', rationale: 'verified chain + anti-rollback + HW-backed keys evidenced' };
  if (chainOk && (rollbackProtected || keys === 'hardware'))
    return { level: 'Level 2+SE', rationale: 'verified chain plus one of anti-rollback / HW-backed keys' };
  if (chainOk) return { level: 'Level 2', rationale: 'verified chain; anti-rollback and HW key storage still open' };
  if (rollbackProtected || keys === 'hardware') return { level: 'Level 1', rationale: 'partial RoT hygiene, chain unverified' };
  return { level: 'None', rationale: 'no RoT properties evidenced' };
}

export const CC_NOTE =
  'Maps to CC FPT_STM (time/counter), FPT_TST (self-test/boot integrity) and FCS_CKM (key management) ' +
  'claim areas. A formal protection-profile evaluation is out of scope — this report is input evidence, not a verdict.';

// ── Report ──
export type RoTEvidence = { chain: BootStage[]; rollback: RollbackEvidence; probeText: string };

export type RoTReport = {
  chain: ChainResult;
  rollback: RollbackResult;
  debug: DebugFinding[];
  keys: ReturnType<typeof classifyKeyStorage>;
  psaReadiness: ReturnType<typeof mapPsa>;
  ccNote: string;
  passed: boolean;
};

export function verifyRootOfTrust(ev: RoTEvidence): RoTReport {
  const chain = verifyChain(ev.chain);
  const rollback = checkRollback(ev.rollback);
  const debug = probeDebugInterfaces(ev.probeText);
  const keys = classifyKeyStorage(ev.probeText);
  const psaReadiness = mapPsa(chain.ok, rollback.protected, keys.storage);
  const passed = chain.ok && rollback.protected && debug.length === 0 && keys.storage === 'hardware';
  return { chain, rollback, debug, keys, psaReadiness, ccNote: CC_NOTE, passed };
}
