// A database the integration suite may destroy.
//
// The suite drops and rebuilds the public schema, so it needs a disposable
// database. Set SF_TEST_DATABASE_URL to reuse one (CI service container, or a
// local server); otherwise this boots a throwaway embedded PostgreSQL in the OS
// temp directory and removes it on stop(). Either way the suite needs no
// database anyone has already set up.
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export type TestDatabase = { url: string; stop: () => Promise<void> };

const databaseName = (url: string) => {
  try {
    return decodeURIComponent(new URL(url).pathname.replace(/^\//, ''));
  } catch {
    return '';
  }
};

// Let the OS pick a listener port, then hand it to Postgres. A tiny race window
// remains, which is not worth guarding against for a local test server.
async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.unref();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      probe.close(() => (port ? resolve(port) : reject(new Error('could not reserve a port'))));
    });
  });
}

export async function ensureTestDatabase(): Promise<TestDatabase> {
  const provided = process.env.SF_TEST_DATABASE_URL?.trim();
  if (provided) {
    const name = databaseName(provided);
    if (!/test/i.test(name)) {
      throw new Error(
        `SF_TEST_DATABASE_URL points at "${name || provided}" — this suite drops and rebuilds the schema, so the database name must contain "test"`
      );
    }
    return { url: provided, stop: async () => undefined };
  }

  // Imported lazily: a run against a provided database never needs the binaries.
  const { default: EmbeddedPostgres } = await import('embedded-postgres');
  const databaseDir = await mkdtemp(join(tmpdir(), 'sentinelforge-pg-'));
  const port = await freePort();
  // The cluster is throwaway and listens on 127.0.0.1 only, so the password just
  // has to exist. Generated per run: a `password: 'postgres'` literal is exactly
  // the shape secret scanners report, and a false leak costs a triage round.
  const dbPassword = randomBytes(18).toString('base64url');
  const server = new EmbeddedPostgres({
    databaseDir,
    user: 'postgres',
    password: dbPassword,
    port,
    persistent: true, // removed by stop() below, so nothing is left behind
    autoRehydrateSymlinks: true,
  });

  const discard = async () => {
    await server.stop().catch(() => undefined);
    await rm(databaseDir, { recursive: true, force: true }).catch(() => undefined);
  };

  await server.initialise();
  await server.start();
  try {
    const client = server.getPgClient();
    await client.connect();
    // template0 + UTF8: a Windows cluster otherwise defaults to WIN1252.
    await client.query(`CREATE DATABASE sentinelforge_test ENCODING 'UTF8' TEMPLATE template0`);
    await client.end();
  } catch (e) {
    await discard();
    throw e;
  }

  return {
    url: `postgresql://postgres:${dbPassword}@127.0.0.1:${port}/sentinelforge_test`,
    stop: discard,
  };
}
