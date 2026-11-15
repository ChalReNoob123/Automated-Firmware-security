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

// False-positive control: a value that looks assigned but is obviously a placeholder
// ("password": "changeme", "${API_KEY}") is not a finding — reporting it trains analysts
// to ignore the scanner.
const PLACEHOLDERS = new Set([
  'password', 'passwd', 'admin', 'root', 'test', 'example', 'changeme', 'change_me', 'default',
  'null', 'none', 'nil', 'xxx', 'xxxx', 'todo', 'fixme', 'placeholder', 'redacted', 'secret',
  'your_password', 'mypassword', '123456', 'qwerty', 'letmein', 'insert_key_here', 'dummy',
]);

// Shannon entropy per character — generic tokens need ≥3.2 bits/char to be interesting.
function entropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function looksLikePlaceholder(value: string): boolean {
  const v = value.trim().toLowerCase().replace(/^['"]|['"]$/g, '');
  if (!v) return true;
  if (PLACEHOLDERS.has(v)) return true;
  if (/^\$\{?[a-z_]+\}?$/.test(v)) return true; // ${API_KEY}, %TOKEN%
  if (/^<[a-z_]+>$/.test(v)) return true; // <your-key>
  if (/^\*+$|^x+$/i.test(v)) return true; // ****, xxxx
  return false;
}

export function isHighEntropy(value: string, minBits = 3.2): boolean {
  return value.length >= 12 && entropy(value) >= minBits;
}

const SECRET_RULES: { id: string; severity: SecretFinding['severity']; re: RegExp; entropy?: boolean }[] = [
  { id: 'aws-access-key', severity: 'high', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'private-key', severity: 'high', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  // password= / passwd: "value"  (quoted, 4+ chars)
  { id: 'hardcoded-password', severity: 'high', re: /\b(passw(or)?d|passwd|pwd)\b\s*[:=]\s*['"][^'"]{4,}['"]/i },
  { id: 'api-token', severity: 'medium', re: /\b(api[_-]?key|secret|token)\b\s*[:=]\s*['"][A-Za-z0-9_\-.]{8,}['"]/i, entropy: true },
  { id: 'aws-secret-like', severity: 'medium', re: /\baws[_-]?secret\b\s*[:=]\s*['"][A-Za-z0-9/+=]{16,}['"]/i, entropy: true },
  // Self-validating modern credential formats — charset-bound, near-zero FP.
  { id: 'jwt-hardcoded', severity: 'high', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { id: 'slack-token', severity: 'high', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'google-api-key', severity: 'high', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
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

// Extract the assigned VALUE from a rule match so FP filters can inspect it.
function valueOf(match: string): string {
  const m = match.match(/['"]([^'"]+)['"]/);
  return m ? m[1] : '';
}

export function scanSecrets(text: string): SecretFinding[] {
  const out: SecretFinding[] = [];
  const lines = text.split('\n');
  lines.forEach((line, i) => {
    for (const r of SECRET_RULES) {
      const m = line.match(r.re);
      if (!m) continue;
      const value = valueOf(m[0]);
      // Placeholders are never findings.
      if (value && looksLikePlaceholder(value)) continue;
      // Entropy-gated rules: "api_key": "abcdefgh" is a placeholder;
      // "api_key": "sk_live_9f2A..." is not. "aws_secret": "aaaaaaaaaaaaaaaa"
      // (16 a's, charset-valid but zero entropy) must also not report.
      if (r.entropy && value && !isHighEntropy(value)) continue;
      out.push({ ruleId: r.id, severity: r.severity, line: i + 1, preview: redact(m[0]) });
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
