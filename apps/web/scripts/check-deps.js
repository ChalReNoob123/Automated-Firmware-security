// Guards the single-React invariant for apps/web.
// Root `npm install --workspaces` hoists styled-jsx to the repo root, where it
// resolves React 19 — while this app runs nested React 18. Two React copies
// crash SSR prerendering (styled-jsx StyleRegistry useContext null).
// If this fails, restore the nested tree:  npm --prefix apps/web install
const { createRequire } = require('node:module');
const path = require('node:path');

const anchor = path.join(__dirname, '..', 'package.json');
const req = createRequire(anchor);
const nestedRoot = path.join(__dirname, '..', 'node_modules') + path.sep;

let bad = false;
for (const name of ['react', 'react-dom', 'styled-jsx']) {
  let resolved;
  try {
    resolved = req.resolve(name);
  } catch {
    resolved = null;
  }
  const ok = !!resolved && resolved.startsWith(nestedRoot);
  console.log(`${ok ? 'OK    ' : 'BROKEN'} ${name} -> ${resolved ?? 'unresolvable'}`);
  if (!ok) bad = true;
}
if (bad) {
  console.error('\nSingle-React invariant broken. Fix: npm --prefix apps/web install');
  process.exit(1);
}
