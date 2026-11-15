// Input sanitization for anything a human types. Defense in depth: zod validates
// shape/length, this removes characters that break downstream consumers (log
// injection, terminal escape sequences, null-byte truncation in C-backed parsers).

// Strip C0/C1 control characters except tab/newline/carriage return.
const CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
// Unicode bidi overrides can spoof an extension/filename in a report.
const BIDI_RE = /[\u202A-\u202E\u2066-\u2069]/g;
// Null bytes can truncate strings in C-backed parsers.
const NULL_BYTE_RE = /\u0000/g;

export function stripControl(input: string, opts: { keepNewlines?: boolean } = {}): string {
  const cleaned = input.replace(CONTROL_RE, '').replace(BIDI_RE, '').replace(NULL_BYTE_RE, '');
  return opts.keepNewlines ? cleaned : cleaned.replace(/[\r\n\t]/g, ' ');
}

export function sanitizeText(input: string, max = 256): string {
  return stripControl(input).replace(/\s+/g, ' ').trim().slice(0, max);
}

export function sanitizeMultiline(input: string, max = 2000): string {
  return stripControl(input, { keepNewlines: true })
    .replace(/\r\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
    .slice(0, max);
}

// Reject prototype-pollution vectors outright (defense in depth; zod strips unknown
// keys, this also protects any future code that merges request bodies).
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// Maximum nesting depth for any JSON value — prevents deeply nested DoS.
const MAX_DEPTH = 16;

export function hasForbiddenKeys(value: unknown, depth = 0): boolean {
  if (depth > 12 || value === null || typeof value !== 'object') return false;
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.has(k)) return true;
    if (hasForbiddenKeys(v, depth + 1)) return true;
  }
  return false;
}

export function hasExcessiveDepth(value: unknown, depth = 0): boolean {
  if (depth > MAX_DEPTH) return true;
  if (value === null || typeof value !== 'object') return false;
  if (Array.isArray(value)) {
    return value.some((v) => hasExcessiveDepth(v, depth + 1));
  }
  for (const v of Object.values(value as Record<string, unknown>)) {
    if (hasExcessiveDepth(v, depth + 1)) return true;
  }
  return false;
}
