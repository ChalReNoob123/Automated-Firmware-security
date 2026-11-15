import dotenv from 'dotenv';
import { app } from './app.js';
import { pool } from './db.js';

dotenv.config();

const port = Number(process.env.API_PORT ?? 4000);
const server = app.listen(port, () => console.log(`[sentinelforge-api] listening on :${port}`));

// Graceful shutdown: stop accepting connections, drain in-flight requests, then
// close the pool. Prevents dropped requests during deploys/scale events.
let closing = false;
const shutdown = async (signal: string) => {
  if (closing) return;
  closing = true;
  console.log(`[sentinelforge-api] ${signal} — draining…`);
  server.close(async () => {
    try {
      await pool?.end();
    } catch {
      /* pool already closed */
    }
    console.log('[sentinelforge-api] closed cleanly');
    process.exit(0);
  });
  // Hard stop if connections refuse to drain.
  setTimeout(() => process.exit(1), 10_000).unref();
};
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('unhandledRejection', (reason) => console.error('[sentinelforge-api] unhandledRejection:', reason));
process.on('uncaughtException', (err) => {
  console.error('[sentinelforge-api] uncaughtException:', err);
  void shutdown('uncaughtException');
});
