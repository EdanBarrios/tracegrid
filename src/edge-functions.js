// Inventory of <supabaseDir>/functions/* with verify_jwt and entrypoint from config.toml.
import fs from 'node:fs';
import path from 'node:path';
import { isInside } from './safe.js';

const INDEX = /^index\.(ts|tsx|js|jsx|mjs|mts)$/;

/**
 * @param {string} root @param {string} functionsDir relative to root
 * @param {object|null} toml parsed config.toml @param {string} supabaseDir relative to root
 * @returns {{ name: string, dir: string, entry: string, verifyJwt: boolean|null }[]}
 */
export function listEdgeFunctions(root, functionsDir, toml = null, supabaseDir = 'supabase') {
  const conf = (toml && toml.functions) || {};
  const dir = path.join(root, functionsDir);
  const out = new Map();
  const names = new Set(Object.keys(conf));
  if (fs.existsSync(dir)) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if ((e.isDirectory() || e.isSymbolicLink()) && !e.name.startsWith('_') && !e.name.startsWith('.') && e.name !== 'node_modules') names.add(e.name);
    }
  }
  for (const name of names) {
    const c = conf[name] || {};
    let entry = null;
    if (typeof c.entrypoint === 'string') {
      const p = path.join(root, supabaseDir, c.entrypoint);
      if (isInside(root, p) && fs.existsSync(p)) entry = path.relative(root, p).split(path.sep).join('/');
    }
    if (!entry) {
      const d = path.join(dir, name);
      let files = [];
      try { if (isInside(root, d)) files = fs.readdirSync(d); } catch { /* not a directory */ }
      const idx = files.find((f) => INDEX.test(f));
      if (idx) entry = `${functionsDir}/${name}/${idx}`;
    }
    if (!entry) continue;
    out.set(name, { name, dir: `${functionsDir}/${name}`, entry, verifyJwt: typeof c.verify_jwt === 'boolean' ? c.verify_jwt : null });
  }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
}
