// Config loading and a tiny dependency-free glob matcher.
import fs from 'node:fs';
import path from 'node:path';

/** @typedef {{
 *   include: string[], exclude: string[], migrations: string, functionsDir: string,
 *   wrappers: { rpc: string[], from: string[], invoke: string[] },
 *   supabaseDefaultGrants: boolean,
 *   ignore: { functions: string[], edgeFunctions: string[], tables: string[], rpcs: string[] }
 * }} Config */

/** @type {Config} */
export const DEFAULTS = {
  include: ['src/**/*.{ts,tsx,js,jsx,mjs,cjs}', 'supabase/functions/**/*.{ts,tsx,js,jsx,mjs}'],
  exclude: ['**/node_modules/**', '**/*.test.*', '**/*.spec.*', '**/__tests__/**', '**/*.d.ts', '**/dist/**', '**/build/**'],
  migrations: 'supabase/migrations',
  functionsDir: 'supabase/functions',
  // Names of your own helper functions that take an RPC / table / edge function name
  // as their first argument, e.g. a local `rpc('name')` wrapper.
  wrappers: { rpc: [], from: [], invoke: [] },
  // Supabase grants EXECUTE on new public functions to anon and authenticated by default
  // (on top of Postgres' default EXECUTE to PUBLIC). Set false for a vanilla Postgres model.
  supabaseDefaultGrants: true,
  ignore: { functions: [], edgeFunctions: [], tables: [], rpcs: [] },
};

/** @param {string} root @param {string} [file] @returns {Config} */
export function loadConfig(root, file) {
  const p = file ? path.resolve(file) : path.join(root, 'supareach.config.json');
  if (!fs.existsSync(p)) return structuredClone(DEFAULTS);
  const user = JSON.parse(fs.readFileSync(p, 'utf8'));
  const c = structuredClone(DEFAULTS);
  for (const k of Object.keys(user)) {
    if (k === 'ignore' || k === 'wrappers') c[k] = { ...c[k], ...user[k] };
    else c[k] = user[k];
  }
  return c;
}

/** Convert a glob (supports **, *, ?, {a,b}) to a RegExp over forward-slash paths. */
export function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') { i++; re += '(?:.*/)?'; } else re += '.*';
      } else re += '[^/]*';
    } else if (ch === '?') re += '[^/]';
    else if (ch === '{') {
      const end = glob.indexOf('}', i);
      re += '(?:' + glob.slice(i + 1, end).split(',').map(escapeRe).join('|') + ')';
      i = end;
    } else re += escapeRe(ch);
  }
  return new RegExp('^' + re + '$');
}
const escapeRe = (s) => s.replace(/[.+^$()|[\]\\]/g, '\\$&');

/** Static prefix of a glob, used as the directory to walk. */
function globBase(glob) {
  const parts = glob.split('/');
  const out = [];
  for (const p of parts) { if (/[*?{]/.test(p)) break; out.push(p); }
  return out.join('/');
}

/** List files under root matching include globs and not matching exclude globs. */
export function findFiles(root, include, exclude) {
  const inc = include.map(globToRegExp);
  const exc = exclude.map(globToRegExp);
  const seen = new Set();
  const out = [];
  for (const g of include) {
    const base = path.join(root, globBase(g));
    if (!fs.existsSync(base)) continue;
    const stack = [base];
    while (stack.length) {
      const dir = stack.pop();
      let st;
      try { st = fs.statSync(dir); } catch { continue; }
      if (st.isFile()) { consider(dir); continue; }
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        if (e.name === 'node_modules' || e.name === '.git') continue;
        const full = path.join(dir, e.name);
        if (e.isDirectory()) stack.push(full);
        else if (e.isFile()) consider(full);
      }
    }
  }
  function consider(full) {
    const rel = path.relative(root, full).split(path.sep).join('/');
    if (seen.has(rel)) return;
    if (!inc.some((r) => r.test(rel))) return;
    if (exc.some((r) => r.test(rel))) return;
    seen.add(rel);
    out.push(rel);
  }
  return out.sort();
}
