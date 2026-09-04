// Automated patch verification (spec: binary-diff the new build against the prior
// one to confirm the vulnerable code path is actually gone — not just a version
// string bump). Method: 1 KiB content-defined-ish block matching (fixed 1 KiB grid
// over both images) + dangerous-sink and secret set comparison on extracted text.
// Verdicts: 'patched' | 'not-patched' | 'inconclusive', always with evidence.
import { createHash } from 'node:crypto';
import { scanSecrets, scanSinks } from './static.js';

export type PatchVerdict = 'patched' | 'not-patched' | 'inconclusive';

export type PatchReport = {
  similarity: number; // 0..1 block-set Dice coefficient
  commonBlocks: number;
  oldBlocks: number;
  newBlocks: number;
  removedSinks: string[];
  remainingSinks: string[];
  removedSecrets: string[];
  verdict: PatchVerdict;
  evidence: string[];
};

const BLOCK = 1024;
function blockSet(raw: Uint8Array): Set<string> {
  const set = new Set<string>();
  for (let o = 0; o < raw.length; o += BLOCK) {
    const h = createHash('sha256').update(raw.subarray(o, o + BLOCK)).digest('hex');
    set.add(h);
  }
  return set;
}

export function verifyPatch(input: {
  oldRaw: Uint8Array;
  newRaw: Uint8Array;
  oldText?: string; // strings/disassembly of the old build
  newText?: string; // strings/disassembly of the new build
  vulnSink?: string; // the sink the patch was supposed to eliminate, e.g. 'strcpy'
  oldVersion?: string;
  newVersion?: string;
}): PatchReport {
  const evidence: string[] = [];
  const A = blockSet(input.oldRaw);
  const B = blockSet(input.newRaw);
  const common = [...A].filter((h) => B.has(h)).length;
  const similarity = A.size + B.size === 0 ? 1 : +((2 * common) / (A.size + B.size)).toFixed(4);

  if ((input.oldVersion || input.newVersion) && input.oldVersion === input.newVersion)
    evidence.push('version strings identical — a real patch must change the image, not the label');
  if (similarity === 1) evidence.push('images are byte-identical — nothing was patched');

  const oldSinks = new Set((input.oldText ? scanSinks(input.oldText) : []).map((s) => s.sink));
  const newSinks = new Set((input.newText ? scanSinks(input.newText) : []).map((s) => s.sink));
  const removedSinks = [...oldSinks].filter((s) => !newSinks.has(s));
  const remainingSinks = [...oldSinks].filter((s) => newSinks.has(s));
  const oldSecrets = new Set((input.oldText ? scanSecrets(input.oldText) : []).map((s) => `${s.ruleId}@${s.line}`));
  const newSecrets = new Set((input.newText ? scanSecrets(input.newText) : []).map((s) => `${s.ruleId}@${s.line}`));
  const removedSecrets = [...oldSecrets].filter((s) => !newSecrets.has(s));

  if (removedSinks.length) evidence.push(`eliminated sinks: ${removedSinks.join(', ')}`);
  if (remainingSinks.length) evidence.push(`still present: ${remainingSinks.join(', ')}`);
  if (removedSecrets.length) evidence.push(`rotated out ${removedSecrets.length} hardcoded secret(s)`);

  let verdict: PatchVerdict = 'inconclusive';
  if (similarity === 1) {
    verdict = 'not-patched';
  } else if (input.vulnSink) {
    if (!newSinks.has(input.vulnSink) && oldSinks.has(input.vulnSink)) {
      verdict = 'patched';
      evidence.push(`target sink '${input.vulnSink}' gone from new build`);
    } else if (newSinks.has(input.vulnSink)) {
      verdict = 'not-patched';
      evidence.push(`target sink '${input.vulnSink}' STILL referenced — patch did not remove the vulnerable path`);
    } else {
      verdict = 'inconclusive';
      evidence.push(`target sink '${input.vulnSink}' in neither build's extracted text — supply fuller disassembly`);
    }
  } else if (removedSinks.length > 0 && remainingSinks.length === 0) {
    verdict = 'patched';
  } else if (similarity < 1 && remainingSinks.length === 0 && oldSinks.size > 0) {
    verdict = 'patched';
  }

  return { similarity, commonBlocks: common, oldBlocks: A.size, newBlocks: B.size, removedSinks, remainingSinks, removedSecrets, verdict, evidence };
}
