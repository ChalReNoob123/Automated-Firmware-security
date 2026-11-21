// Guards the single-React invariant for apps/web.
// The repo runs ONE React version (19.2.3) across the legacy app and the
// SentinelForge web app, so there must be exactly ONE @types/react in the tree.
// Two copies of React (or of @types/react) break SSR prerendering with errors
// like "ComponentType<{}> is not a valid JSX element type".
//
// Two places are checked, because the first used to hide the second:
//   1. apps/web/node_modules — a nested react/react-dom/next wins Node's
//      resolution race, so the app silently stops using the hoisted copy.
//   2. the app's own source tree — a stray nested node_modules further down.
const { createRequire } = require('node:module');
const path = require('node:path');
const fs = require('node:fs');

// __dirname is apps/web/scripts, so the app is one level up (the old two-level
// join landed on apps/, which made the scan look at apps/web/apps/web).
const appDir = path.join(__dirname, '..');
const repoRoot = path.join(appDir, '..', '..');
const req = createRequire(path.join(appDir, 'package.json'));
// Report duplicates relative to the repo root so CI logs stay readable.
const rel = (p) => path.relative(repoRoot, p).split(path.sep).join('/');

function versionOf(pkg) {
  try {
    return req(`${pkg}/package.json`).version;
  } catch {
    // exports maps may block package.json access — read from disk instead
    try {
      const dir = path.dirname(req.resolve(pkg));
      const file = path.join(dir, 'package.json');
      return JSON.parse(fs.readFileSync(file, 'utf8')).version;
    } catch {
      return null;
    }
  }
}

const react = versionOf('react');
const reactDom = versionOf('react-dom');
const types = versionOf('@types/react');

const nested = [];

// 1. The app's own node_modules. These copies are reached before the hoisted
//    workspace ones, so their presence is the duplicate, whatever the version.
for (const name of ['react', 'react-dom', 'next']) {
  const p = path.join(appDir, 'node_modules', name);
  if (fs.existsSync(p)) nested.push(rel(p));
}
const nestedTypes = path.join(appDir, 'node_modules', '@types', 'react');
if (fs.existsSync(nestedTypes)) nested.push(rel(nestedTypes));

// 2. Stray copies deeper in the source tree. node_modules is skipped here
//    because step 1 already owns it.
const scan = (dir, depth = 0) => {
  if (depth > 3) return;
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    if (e.name === 'node_modules') continue;
    if (e.name === 'react' || e.name === 'react-dom' || e.name === '@types') {
      const p = path.join(dir, e.name);
      if (e.name === '@types') {
        for (const t of fs.readdirSync(p)) {
          if (t.startsWith('react')) nested.push(rel(path.join(p, t)));
        }
      } else {
        nested.push(rel(p));
      }
    }
    if (e.name.startsWith('@')) continue;
    scan(path.join(dir, e.name), depth + 1);
  }
};
scan(appDir);

console.log(`react ${react} | react-dom ${reactDom} | @types/react ${types} (resolved from apps/web)`);
if (nested.length) {
  console.error('Duplicate React copies found:\n  ' + nested.join('\n  '));
  console.error('apps/web must resolve react, react-dom, next and @types/react from the');
  console.error('hoisted workspace tree. Delete apps/web/node_modules and re-run');
  console.error('`npm install` at the repo root so the workspaces provide them.');
  process.exit(1);
}
if (react && reactDom && react !== reactDom) {
  console.error(`react (${react}) and react-dom (${reactDom}) must match`);
  process.exit(1);
}
console.log('OK single React tree');
