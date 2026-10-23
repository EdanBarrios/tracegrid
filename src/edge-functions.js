// Inventory of supabase/functions/* and their verify_jwt setting from supabase/config.toml.
import fs from 'node:fs';
import path from 'node:path';

/** @returns {{ name: string, dir: string, verifyJwt: boolean|null }[]} */
export function listEdgeFunctions(root, functionsDir) {
  const dir = path.join(root, functionsDir);
  if (!fs.existsSync(dir)) return [];
  const jwt = readVerifyJwt(root);
  return fs.readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isDirectory() && !e.name.startsWith('_') && !e.name.startsWith('.') && e.name !== 'node_modules')
    .map((e) => ({ e, index: fs.readdirSync(path.join(dir, e.name)).find((f) => /^index\.(ts|js|tsx|mjs)$/.test(f)) }))
    .filter((x) => x.index)
    .map(({ e, index }) => ({ name: e.name, dir: `${functionsDir}/${e.name}`, entry: `${functionsDir}/${e.name}/${index}`, verifyJwt: jwt.has(e.name) ? jwt.get(e.name) : null }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** Minimal TOML read: [functions.<name>] verify_jwt = true|false. */
function readVerifyJwt(root) {
  const m = new Map();
  const p = path.join(root, 'supabase', 'config.toml');
  if (!fs.existsSync(p)) return m;
  let cur = null;
  for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
    const sec = /^\s*\[functions\.("?)([^"\]]+)\1\]\s*$/.exec(line);
    if (sec) { cur = sec[2]; continue; }
    if (/^\s*\[/.test(line)) { cur = null; continue; }
    const v = /^\s*verify_jwt\s*=\s*(true|false)/.exec(line);
    if (cur && v) m.set(cur, v[1] === 'true');
  }
  return m;
}
