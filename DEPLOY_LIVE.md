# SentinelForge — Live Deployment (Vercel + Supabase + Render)

Architecture for live testing:

| Piece | Host | Why |
|---|---|---|
| Web UI (`apps/web`) | **Vercel** | Static Next.js pages, global CDN |
| Postgres | **Supabase** | `DATABASE_URL` for the API (audit trail + future user store) |
| API (`apps/api`) | **Render** (free, `render.yaml` included) | Emulator sessions + pipeline runs are **in-memory** — serverless (Vercel functions) would wipe them. Needs one persistent Node process. |

## 0. Commit + push (Vercel and Render both deploy from git)

```bash
cd "D:\My Projects\automated-soc-monitoring-application"
git add apps packages render.yaml DEPLOY_LIVE.md package.json
git commit -m "feat: sentinelforge live deploy (vercel+supabase+render)"
git push origin main
```

> Vercel/Render only see **committed** code — uncommitted files never deploy.

## 1. Supabase — database (5 min, dashboard)

1. [supabase.com](https://supabase.com) → New project → name `sentinelforge`, any region near you, set a DB password.
2. Left nav **SQL Editor** → New query → paste the entire contents of `packages/db/schema.sql` → **Run**.
   - Creates `pgcrypto` + `citext` extensions, `orgs/users/auth_audit/devices/attestations/firmware/findings` tables.
   - Verify: **Table Editor** should list the 7 tables.
3. **Project Settings → Database** → Connection string, **Session pooler** tab → copy the URI
   (`postgresql://postgres.[ref]:[PASSWORD]@aws-0-…pooler.supabase.com:5432/postgres`).
   - Use the **session** pooler (port 5432), not transaction mode — the API holds simple pooled clients.
   - This is your `DATABASE_URL`. The API auto-enables TLS for non-localhost hosts.

## 2. Render — API (5 min, dashboard)

1. [render.com](https://render.com) → New → **Blueprint** → select repo `Ai-Soc` (it picks up `render.yaml`).
2. Fill secrets: `DATABASE_URL` (from step 1), `ALLOWED_ORIGINS` = `https://<your-vercel-app>.vercel.app`
   (you'll confirm the exact Vercel URL in step 3 — come back and update, then **Manual Deploy**).
   `JWT_SECRET` / `JWT_REFRESH_SECRET` auto-generate.
3. Deploy → note the URL, e.g. `https://sentinelforge-api.onrender.com`.
4. Health check: `GET https://<api>/health` → `{"ok":true,…}`.
   - Free tier **sleeps after 15 min idle** — first request can take ~50 s. Emulator sessions reset on sleep (testing-only limitation, documented).

## 3. Vercel — web UI (5 min, dashboard)

1. [vercel.com](https://vercel.com) → Add New → Project → Import `Ai-Soc`.
2. **Root Directory**: `apps/web` (Framework preset: Next.js — auto-detected).
3. **Environment Variables** (Production): `NEXT_PUBLIC_API_URL` = `https://<your-render-api>.onrender.com`
   - ⚠️ This bakes in at **build** time. Change the API URL later → redeploy the web project.
4. Deploy → open `https://<app>.vercel.app`.
5. Back in Render, set `ALLOWED_ORIGINS` to the exact Vercel URL → Manual Deploy → re-test.

## 4. Live test checklist

- [ ] Landing loads (3D hero needs WebGL — any modern browser).
- [ ] `GET <api>/v1/graph/demo` returns 11 nodes / 3 chains.
- [ ] Login flow: `POST <api>/v1/auth/login` → `verify-2fa` (any 6-digit code, dev stub) → paste token into `/emulator` or `/copilot`.
- [ ] Supabase **Table Editor → auth_audit** shows `signup/login_attempt/2fa_success` rows — proves the API is really on Postgres.
- [ ] `/devices` USB pairing works in desktop Chrome (WebUSB needs HTTPS — Vercel gives you that free).
- [ ] Attack sim end-to-end, then replay from `/emulator`.

## Gotchas (already handled in code, listed for honesty)

- API is stateful: one Render instance, no horizontal scaling yet (Temporal + Redis follow-up).
- Demo-auth accepts any 2FA code without `DATABASE_URL` users wired (bannered in `routes/auth.ts`).
- `NEXT_PUBLIC_API_URL` is build-time; `ALLOWED_ORIGINS` is runtime.
- Rate limit: 60 auth req / 15 min per IP.
