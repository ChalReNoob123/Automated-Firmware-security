# SentinelForge persistence — Supabase setup

The API auto-switches between in-memory (dev) and Postgres (production) based on
one environment variable. There is no code branch to maintain — Supabase is
just a `DATABASE_URL` away.

## Why bother

Without it, the API holds all state (accounts, sessions, emulator runs,
pipeline runs) in process memory. Every API relaunch wipes accounts and every
signup/verification you did is gone. With Postgres, state survives restarts.

## Steps

1. **Create the project** — [supabase.com](https://supabase.com) → New project
   (free tier is fine). Pick a region near you and a strong DB password.

2. **Run the SQL, in this order** — open the Supabase SQL editor and run each
   file's contents, one at a time:

   | Order | File | What it does |
   |---|---|---|
   | 1 | `schema.sql` | orgs, users, devices, attestations, firmware, findings + enums/indexes |
   | 2 | `migrate-002.sql` | auth columns (username, lockout, TOTP), refresh-token log, denylist, emulator/pipeline runtime tables |
   | 3 | `migrate-003.sql` | makes `findings.firmware_id` optional (attack-sim findings) |
   | 4 | `migrate-004.sql` | mandatory `org_id` on runtime tables (tenant isolation, fixes IDOR) |
   | 5 | `migrate-005.sql` | refresh-token revocation reasons (Account Security Center) |
   | 6 | `migrate-006.sql` | TOTP recovery codes |
   | 7 | `migrate-007.sql` | team management + audit target |
   | 8 | `migrate-008.sql` | `firmware_blobs` — the uploaded image bytes |
   | 9 | `migrate-009.sql` | one finding per (org, firmware, title) + truthful `encrypted_at_rest` backfill |
   | 10 | `migrate-010.sql` | `findings.source` provenance for per-run reconciliation |
   | 11 | `migrate-011.sql` | `findings.analysis_run_at` — concurrent runs can't delete each other's findings |
   | 12 | `migrate-012.sql` | `analysis_run_seq` sequence + `firmware.applied_run_seq` — run ordering without wall-clock timestamps |

   All files are idempotent (`IF NOT EXISTS` / guarded `ALTER`s) — re-running
   them is safe. Notes:
   - `schema.sql` enables the `citext` extension; Supabase supports this from
     the SQL editor as-is.
   - Supabase's SQL editor runs each file as a single transaction; run them as
     separate queries, in order.

3. **Copy the connection string** — Project settings → Database → Connection
   string → URI. Use the **connection pooler** (port 6543, "Transaction" mode)
   for serverless-style deployments, or the direct connection (port 5432) for
   the dev API. Replace `[YOUR-PASSWORD]` with the DB password from step 1.

4. **Set the env var** — create/edit `apps/api/.env.local`:

   ```
   DATABASE_URL=postgresql://postgres.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres
   ```

   TLS is applied automatically for any non-localhost URL (the API sets
   `ssl: { rejectUnauthorized: false }`, which Supabase requires).

5. **Restart the API and verify** — relaunch `apps/api` (`npm run dev`), then:

   ```
   GET http://localhost:4000/ready
   ```

   should report `"persistence": "postgres"` (it reports `"memory"` when the
   env var is absent). `/health` also exposes `postgres: true/false`.

## Integration test (real Postgres)

The restart and concurrent-reconcile paths are covered by `apps/api/tests/postgres.test.ts`.
It needs no database set up beforehand — `tests/pgHarness.ts` boots a throwaway
`embedded-postgres` cluster in the OS temp directory, applies the SQL files above and
removes it afterwards:

```bash
npm run test:pg -w @sentinelforge/api    # just the Postgres suite
npm test -w @sentinelforge/api           # whole API suite, Postgres included
```

`embedded-postgres` is an `apps/api` devDependency; its install step downloads the
platform's Postgres binaries. To reuse an existing server instead (a CI service
container, say), set `SF_TEST_DATABASE_URL` to a database that already exists:
the suite creates the schema, not the database. It drops and rebuilds the public
schema, so that database must be disposable and its name must contain `test`:

```bash
SF_TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/sentinelforge_test \
  npm run test:pg -w @sentinelforge/api
```

## Verified vs not

- `schema.sql` and `migrate-002..004.sql` are hand-verified SQL (a syntax error
  in `schema.sql` — `BIGGENERATED` — was found and fixed 2026-11-13). They have
  **not** been executed against a live Supabase/Postgres instance yet; the
  first real run is expected to be the provisioning step above.
- The Postgres code path in `apps/api/src/db.ts` / `store.ts` mirrors the
  in-memory shapes 1:1. The opt-in suite above exercises the schema, stale-boot
  settlement and finding reconciliation against a real server; a live signup →
  restart → login persistence check on your Supabase instance is still yours to run.
