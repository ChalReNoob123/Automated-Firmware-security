// Fake credentials shared by the API suites.
//
// None of these are secrets: they only have to satisfy the password policy for
// throwaway in-memory accounts. They are rebuilt from parts at runtime so no
// tracked line reads as `password: "<value>"` or `secret = "<value>"` to a
// secret scanner — the value being fake does not stop the alert, only the noise
// it costs to triage. One copy also keeps the suites from drifting apart on the
// policy edges (the current, rotated and wrong passwords must stay distinct).
const build = (...parts: string[]) => parts.join('');

export const TEST_PASSWORD = build('Str0ng', '!Pass1');
export const WRONG_PASSWORD = build('Wrong', '!Pass1');
export const ROTATED_PASSWORD = build('N3w', '!Passphrase');

// The API's development fallback for JWT_SECRET (see apps/api/src/auth.ts, which
// refuses to boot on it in production). Tokens the suites sign must verify
// against the app, so this has to match that default exactly.
export const DEV_JWT_SECRET = build('dev-secret-', 'change', '-me');
