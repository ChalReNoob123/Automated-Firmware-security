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

   All files are idempotent (`IF NOT EXISTS` / guarded `ALTER`s) — re-running
   them is safe. Notes:
   - `schema.sql` enables the `citext` extension; Supabase supports this from
     the SQL editor as-is.
   - Supabase's SQL editor runs each file as a single transaction; run them as
     four separate queries, in order.

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

## Verified vs not

- `schema.sql` and `migrate-002..004.sql` are hand-verified SQL (a syntax error
  in `schema.sql` — `BIGGENERATED` — was found and fixed 2026-11-13). They have
  **not** been executed against a live Supabase/Postgres instance yet; the
  first real run is expected to be the provisioning step above.
- The Postgres code path in `apps/api/src/db.ts` / `store.ts` mirrors the
  in-memory shapes 1:1 and is covered by the test suite's store contracts
  where applicable, but a live end-to-end signup → restart → login persistence
  check is still pending on your instance.
