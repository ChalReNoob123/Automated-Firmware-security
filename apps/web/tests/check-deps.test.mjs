// Regression test for apps/web/scripts/check-deps.js.
//
// The guard once joined two levels up from scripts/ (landing on apps/), so it
// scanned apps/apps/web — a path that never exists — and could not fail no
// matter how many nested React copies sat in apps/web/node_modules. These tests
// run the real script against a throwaway tree so that bug cannot come back
// silently: the planted copy must make it exit non-zero, and a clean tree must
// still pass.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptSource = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'check-deps.js');

/** Build <tmp>/apps/web/scripts/check-deps.js with an optional nested React copy. */
function makeTree({ nested }) {
  const root = mkdtempSync(join(tmpdir(), 'sf-check-deps-'));
  const app = join(root, 'apps', 'web');
  mkdirSync(join(app, 'scripts'), { recursive: true });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'root', private: true, workspaces: ['apps/*'] }));
  writeFileSync(join(app, 'package.json'), JSON.stringify({ name: '@sentinelforge/web', version: '0.0.0' }));
  cpSync(scriptSource, join(app, 'scripts', 'check-deps.js'));
  for (const name of nested) {
    const dir = name.startsWith('@') ? join(app, 'node_modules', ...name.split('/')) : join(app, 'node_modules', name);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name, version: '19.2.3' }));
  }
  return { root, app, script: join(app, 'scripts', 'check-deps.js') };
}

function run(script) {
  // No React is installed in the temp tree, so the version lines print `null`;
  // only the duplicate detection under test can change the exit status.
  return spawnSync(process.execPath, [script], { encoding: 'utf8' });
}

test('fails when apps/web/node_modules holds its own react copy', () => {
  const tree = makeTree({ nested: ['react'] });
  try {
    const r = run(tree.script);
    assert.equal(r.status, 1, `expected a non-zero exit, got ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stderr, /Duplicate React copies found/);
    assert.match(r.stderr, /apps\/web\/node_modules\/react/);
  } finally {
    rmSync(tree.root, { recursive: true, force: true });
  }
});

test('fails when apps/web/node_modules holds its own next copy', () => {
  const tree = makeTree({ nested: ['next'] });
  try {
    const r = run(tree.script);
    assert.equal(r.status, 1, `expected a non-zero exit, got ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stderr, /apps\/web\/node_modules\/next/);
  } finally {
    rmSync(tree.root, { recursive: true, force: true });
  }
});

test('fails when apps/web/node_modules holds its own @types/react copy', () => {
  const tree = makeTree({ nested: ['@types/react'] });
  try {
    const r = run(tree.script);
    assert.equal(r.status, 1, `expected a non-zero exit, got ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stderr, /apps\/web\/node_modules\/@types\/react/);
  } finally {
    rmSync(tree.root, { recursive: true, force: true });
  }
});

test('passes on a clean hoisted tree', () => {
  const tree = makeTree({ nested: [] });
  try {
    const r = run(tree.script);
    assert.equal(r.status, 0, `expected exit 0, got ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stdout, /OK single React tree/);
  } finally {
    rmSync(tree.root, { recursive: true, force: true });
  }
});
