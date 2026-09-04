// Stage 3 — Static analysis & secret scanning (real rules, no placeholders).
// Runs on extracted text (strings output, configs, scripts). Binary YARA scanning and
// Ghidra/angr handoff happen downstream; this stage catches the cheap, high-signal wins
// and records dangerous-sink references for the symbolic engine (Module 5).

export type SecretFinding = {
  ruleId: string;
  severity: 'high' | 'medium';
  line: number;
  preview: string; // redacted
};

export type SinkHit = { sink: string; count: number };

const SECRET_RULES: { id: string; severity: SecretFinding['severity']; re: RegExp }[] = [
  { id: 'aws-access-key', severity: 'high', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'private-key', severity: 'high', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  // password= / passwd: "value"  (quoted, 4+ chars)
  { id: 'hardcoded-password', severity: 'high', re: /\b(passw(or)?d|passwd|pwd)\b\s*[:=]\s*['"][^'"]{4,}['"]/i },
  { id: 'api-token', severity: 'medium', re: /\b(api[_-]?key|secret|token)\b\s*[:=]\s*['"][A-Za-z0-9_\-.]{8,}['"]/i },
  { id: 'aws-secret-like', severity: 'medium', re: /\baws[_-]?secret\b\s*[:=]\s*['"][A-Za-z0-9/+=]{16,}['"]/i },
];

export const DANGEROUS_SINKS = [
  'strcpy',
  'strcat',
  'sprintf',
  'vsprintf',
  'gets',
  'memcpy',
  'system',
  'popen',
  'execve',
  'strtok',
] as const;

// YARA rule packs the containerized worker runs when a YARA runtime is present.
// Names only here — the .yar sources live in workers/yara/ (Module 2 follow-up).
export const YARA_PACKS = ['embedded_malware_strings', 'mirai_gafgyt_family', 'iot_default_creds', 'openssl_heartbleed_test'] as const;

function redact(m: string): string {
  return m.length <= 8 ? '****' : `${m.slice(0, 4)}…${m.slice(-2)}`;
}

export function scanSecrets(text: string): SecretFinding[] {
  const out: SecretFinding[] = [];
  const lines = text.split('\n');
  lines.forEach((line, i) => {
    for (const r of SECRET_RULES) {
      const m = line.match(r.re);
      if (m) out.push({ ruleId: r.id, severity: r.severity, line: i + 1, preview: redact(m[0]) });
    }
  });
  return out;
}

export function scanSinks(text: string): SinkHit[] {
  const out: SinkHit[] = [];
  for (const sink of DANGEROUS_SINKS) {
    const count = (text.match(new RegExp(`\\b${sink}\\b`, 'g')) ?? []).length;
    if (count > 0) out.push({ sink, count });
  }
  return out.sort((a, b) => b.count - a.count);
}
