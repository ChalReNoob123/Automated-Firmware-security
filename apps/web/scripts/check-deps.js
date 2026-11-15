// Guards the single-React invariant for apps/web.
// The repo now runs ONE React version (19.2.3) across the legacy app and the
// SentinelForge web app, so there must be exactly ONE @types/react in the tree.
// Two copies of React (or of @types/react) break SSR prerendering with errors
// like "ComponentType<{}> is not a valid JSX element type".
const { createRequire } = require('node:module');
const path = require('node:path');
const fs = require('node:fs');

const root = path.join(__dirname, '..', '..');
const req = createRequire(path.join(root, 'package.json'));

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

// Any stray nested copies of react / @types/react inside the web app break the build.
const nested = [];
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
    if (e.name === 'react' || e.name === 'react-dom' || e.name === '@types') {
      const p = path.join(dir, e.name);
      if (e.name === '@types') {
        for (const t of fs.readdirSync(p)) {
          if (t.startsWith('react')) nested.push(path.join(p, t));
        }
      } else {
        nested.push(p);
      }
    }
    if (e.name.startsWith('@') || e.name === 'node_modules') continue;
    scan(path.join(dir, e.name), depth + 1);
  }
};
scan(path.join(root, 'apps', 'web'));

console.log(`react ${react} | react-dom ${reactDom} | @types/react ${types}`);
if (nested.length) {
  console.error('Duplicate React copies found:\n  ' + nested.join('\n  '));
  console.error('Fix: npm install --workspaces (single React version across the repo)');
  process.exit(1);
}
if (react && reactDom && react !== reactDom) {
  console.error(`react (${react}) and react-dom (${reactDom}) must match`);
  process.exit(1);
}
console.log('OK single React tree');
