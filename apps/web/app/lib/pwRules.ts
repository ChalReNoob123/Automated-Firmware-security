// Single source of truth for the password policy UI — mirrors the API's
// zod passwordSchema (apps/api/src/routes/auth.ts) exactly, so the client
// checklist and the server never disagree. Used by the signup form and the
// account security center's password rotation card.
export const PW_RULES: [string, RegExp][] = [
  ['10+ characters', /^.{10,}$/],
  ['an uppercase letter', /[A-Z]/],
  ['a lowercase letter', /[a-z]/],
  ['a digit', /\d/],
  ['a special character', /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/],
];

export function pwChecks(pw: string): boolean[] {
  return PW_RULES.map(([, re]) => re.test(pw));
}

export function pwStrong(pw: string): boolean {
  return pwChecks(pw).every(Boolean);
}
