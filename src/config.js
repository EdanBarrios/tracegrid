// Config loading and a tiny dependency-free glob matcher.
import fs from 'node:fs';
import path from 'node:path';
import { isInside, realOr } from './safe.js';
import { COLORWAYS } from './colorways.js';

/** @typedef {{
 *   include: string[], exclude: string[], migrations: string, functionsDir: string,
 *   wrappers: { rpc: string[], from: string[], invoke: string[] },
 *   supabaseDefaultGrants: 'auto'|'legacy'|'opt-in'|boolean|null,
 *   ignore: { functions: string[], edgeFunctions: string[], tables: string[], rpcs: string[] }
 * }} Config */

/** @type {Config} */
export const DEFAULTS = {
  // Code to scan. The default is the whole project; dot-directories (.next, .svelte-kit, .nuxt,
  // .output, .expo, .git ...) and node_modules are never walked.
  include: ['**/*.{ts,tsx,js,jsx,mjs,cjs,mts,cts,vue,svelte,astro}'],
  // Tests, mocks and stories are not callers: a function only a test calls is still dead in production.
  exclude: ['**/*.{test,spec}.{ts,tsx,js,jsx,mjs,cjs,mts,cts}', '**/__tests__/**', '**/__mocks__/**', '**/*.stories.{ts,tsx,js,jsx,mjs,mts,svelte,vue}',
    '**/*.d.ts', '**/*.d.mts', '**/*.d.cts'],
  // Directory names skipped when they sit at the project root or next to a package.json (build
  // output and native projects). The same names deeper in source (src/features/build/) are scanned.
  outputDirs: ['dist', 'build', 'out', 'ios', 'android', 'coverage', 'storybook-static'],
  // Which backend to check: "auto" (Supabase when a supabase/ project exists, else Firebase when
  // firebase.json does), "supabase" or "firebase".
  platform: 'auto',
  // Firebase: the firebase.json that names the rules files and functions codebases.
  firebaseJson: null,
  // The Supabase project directory (the one holding config.toml, migrations/ and functions/).
  // Auto-detected: the only **/supabase/config.toml (or **/supabase/migrations) in the project.
  // Colourway baked into graph.html as its default: graphite-amber, signal, mono or mint (--colorway overrides).
  colorway: null,
  supabaseDir: null,
  // Override migrations / functions directories (default: <supabaseDir>/migrations, <supabaseDir>/functions).
  migrations: null,
  functionsDir: null,
  // Names of your own helper functions that take an RPC / table / edge function name
  // as their first argument, e.g. a local `rpc('name')` wrapper.
  wrappers: { rpc: [], from: [], invoke: [] },
  // Which default privileges new objects in `public` get (on top of Postgres' global EXECUTE to PUBLIC):
  //   "legacy"  Supabase's per-schema grants to anon/authenticated/service_role on new tables and
  //             functions in public (projects created before the 2026 change; true means this),
  //   "opt-in"  no per-schema grants: new tables need an explicit GRANT (Supabase CLI v2.106.0+ when
  //             [api] auto_expose_new_tables is unset, and every project after 2026-10-30),
  //   false     vanilla Postgres,
  //   "auto"    (default) [api] auto_expose_new_tables from supabase/config.toml when it is set; otherwise
  //             "legacy" for the replayed migrations (existing projects keep the grants they already
  //             got) plus a notice that tables added after 2026-10-30 need explicit grants.
  // Explicit GRANT / REVOKE / ALTER DEFAULT PRIVILEGES in migrations always apply on top. --db-url reads the real ACLs.
  supabaseDefaultGrants: 'auto',
  // Schemas the Data API exposes (Supabase: Settings > API > Exposed schemas).
  exposedSchemas: ['public'],
  // Edge functions called from outside the codebase (webhooks, OAuth callbacks, auth hooks,
  // health checks): [{ "name": "stripe-webhook", "reason": "Stripe calls it" }].
  entryPoints: [],
  // Treat `verify_jwt = false` in supabase/config.toml as an external entry point (reported as such).
  autoEntryPoints: true,
  // Every ignore needs a reason: { "name": "...", "reason": "..." }; `findings` takes a full
  // fingerprint ("<rule>:<subject>") and works for any rule, plugins included.
  ignore: { functions: [], edgeFunctions: [], tables: [], rpcs: [], findings: [] },
  // SARIF result level per tier (code scanning shows error / warning / note).
  sarifLevels: { fix: 'error', review: 'warning', info: 'note' },
  // Extra rule modules (paths relative to the config file). Each exports `rules`: see src/engine.js.
  plugins: [],
};

/** @param {string} root @param {string} [file] @returns {Config} */
export function loadConfig(root, file) {
  const p = file ? path.resolve(file) : path.join(root, 'tracegrid.config.json');
  const c = structuredClone(DEFAULTS);
  Object.defineProperty(c, '_dir', { value: file ? path.dirname(p) : root, enumerable: false });
  Object.defineProperty(c, '_warnings', { value: [], enumerable: false });
  if (!fs.existsSync(p)) return c;
  let user;
  // Keys that could reach an object's prototype are dropped while parsing.
  try { user = JSON.parse(fs.readFileSync(p, 'utf8'), (k, v) => (k === '__proto__' || k === 'constructor' || k === 'prototype' ? undefined : v)); } catch (e) { throw new ConfigError(`${p}: ${e.message}`); }
  if (!user || typeof user !== 'object' || Array.isArray(user)) throw new ConfigError(`${p}: expected a JSON object`);
  Object.defineProperty(c, '_userKeys', { value: new Set(Object.keys(user)), enumerable: false });
  const plugins = Array.isArray(user.plugins) && user.plugins.length > 0;
  for (const k of Object.keys(user)) {
    if (!Object.prototype.hasOwnProperty.call(DEFAULTS, k)) {
      // Plugins may read their own keys; without plugins an unknown key is most likely a typo.
      if (plugins) c[k] = user[k];
      else c._warnings.push(`unknown config key "${k}" (ignored)`);
      continue;
    }
    if ((k === 'ignore' || k === 'wrappers' || k === 'sarifLevels') && user[k] && typeof user[k] === 'object') c[k] = { ...c[k], ...user[k] };
    else c[k] = user[k];
  }
  validateConfig(c, p);
  validatePaths(c, root, p);
  return c;
}

/** Config-derived paths stay inside the project: a fork PR controls the config file. */
export function validatePaths(c, root, file = 'config') {
  const bad = (msg) => { throw new ConfigError(`${file}: ${msg}`); };
  for (const k of ['include', 'exclude']) {
    if (!Array.isArray(c[k])) bad(`${k} must be an array of globs`);
    for (const g of c[k]) {
      if (typeof g !== 'string' || !g) bad(`${k} entries must be non-empty strings`);
      if (path.isAbsolute(g) || /^[A-Za-z]:/.test(g) || g.split('/').includes('..')) bad(`${k}: "${g}" points outside the project (no absolute paths or "..")`);
    }
  }
  for (const k of ['supabaseDir', 'migrations', 'functionsDir', 'firebaseJson']) {
    if (c[k] == null) continue;
    if (typeof c[k] !== 'string' || !c[k]) bad(`${k} must be a path relative to the project`);
    if (path.isAbsolute(c[k]) || !isInside(root, path.resolve(root, c[k]))) bad(`${k}: "${c[k]}" is outside the project root (".." and absolute paths are not allowed)`);
  }
}

export class ConfigError extends Error {}

/** Throw a ConfigError naming the first problem. */
export function validateConfig(c, file = 'config') {
  const bad = (msg) => { throw new ConfigError(`${file}: ${msg}`); };
  for (const [cat, list] of Object.entries(c.ignore || {})) {
    if (!(cat in DEFAULTS.ignore)) bad(`ignore.${cat}: unknown list (expected ${Object.keys(DEFAULTS.ignore).join(', ')})`);
    if (!Array.isArray(list)) bad(`ignore.${cat} must be an array`);
    const key = cat === 'findings' ? 'id' : 'name';
    list.forEach((x, i) => {
      if (typeof x === 'string') bad(`ignore.${cat}[${i}] is a bare string; write { "${key}": ${JSON.stringify(x)}, "reason": "why it is fine" }`);
      if (!x || typeof x[key] !== 'string' || !x[key]) bad(`ignore.${cat}[${i}] needs "${key}"`);
      if (typeof x.reason !== 'string' || !x.reason.trim()) bad(`ignore.${cat}[${i}] (${x[key]}) needs a non-empty "reason"`);
    });
  }
  if (c.colorway != null && !COLORWAYS.includes(c.colorway)) bad(`colorway: unknown colourway ${JSON.stringify(String(c.colorway)).slice(0, 60)} (expected ${COLORWAYS.join(', ')})`);
  if (!Array.isArray(c.plugins)) bad('plugins must be an array of paths');
  if (!['auto', 'supabase', 'firebase'].includes(c.platform)) bad('platform must be "auto", "supabase" or "firebase"');
  if (![null, 'auto', true, false, 'legacy', 'opt-in'].includes(c.supabaseDefaultGrants)) bad('supabaseDefaultGrants must be "auto", "legacy", "opt-in", true or false');
  for (const [t, l] of Object.entries(c.sarifLevels || {})) {
    if (!['fix', 'review', 'info'].includes(t)) bad(`sarifLevels.${t}: unknown tier (expected fix, review, info)`);
    if (!['error', 'warning', 'note', 'none'].includes(l)) bad(`sarifLevels.${t} must be "error", "warning", "note" or "none"`);
  }
  if (!Array.isArray(c.entryPoints)) bad('entryPoints must be an array');
  c.entryPoints.forEach((x, i) => {
    if (typeof x === 'string') bad(`entryPoints[${i}] is a bare string; write { "name": ${JSON.stringify(x)}, "reason": "who calls it" }`);
    if (!x || typeof x.name !== 'string' || !x.name) bad(`entryPoints[${i}] needs "name"`);
    if (typeof x.reason !== 'string' || !x.reason.trim()) bad(`entryPoints[${i}] (${x.name}) needs a non-empty "reason"`);
  });
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
      if (end < 0) { re += escapeRe(ch); continue; } // unclosed brace: a literal "{"
      re += '(?:' + glob.slice(i + 1, end).split(',').map(escapeRe).join('|') + ')';
      i = end;
    } else re += escapeRe(ch);
  }
  return new RegExp('^' + re + '$');
}
const escapeRe = (s) => s.replace(/[.+^$()|[\]\\{}]/g, '\\$&');

/** Static prefix of a glob, used as the directory to walk. */
function globBase(glob) {
  const parts = glob.split('/');
  const out = [];
  for (const p of parts) { if (/[*?{]/.test(p)) break; out.push(p); }
  return out.join('/');
}

/**
 * List files under root matching include globs and not matching exclude globs. Symbolic links are
 * followed only when their target is inside the project root; nothing outside the root is read.
 */
export function findFiles(root, include, exclude, { outputDirs = [] } = {}) {
  const outNames = new Set(outputDirs);
  const inc = include.map(globToRegExp);
  const exc = exclude.map(globToRegExp);
  const realRoot = realOr(root);
  const seen = new Set();
  const out = [];
  for (const g of include) {
    if (path.isAbsolute(g) || g.split('/').includes('..')) continue;
    const base = path.join(root, globBase(g));
    if (!isInside(realRoot, base)) continue;
    const stack = [[base, []]];
    while (stack.length) {
      const [dir, chain] = stack.pop();
      let st;
      try { st = fs.statSync(dir); } catch { continue; }
      if (st.isFile()) { consider(dir); continue; }
      if (!st.isDirectory()) continue;
      const real = realOr(dir);
      if (chain.includes(real) || chain.length > 64 || !isInside(realRoot, real)) continue; // a symlink loop, or outside the project
      const next = [...chain, real];
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
      for (const e of entries) {
        if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
        const full = path.join(dir, e.name);
        if (outNames.has(e.name) && (dir === root || fs.existsSync(path.join(dir, 'package.json')))) continue;
        if (e.isSymbolicLink()) {
          if (!isInside(realRoot, full)) continue; // link target outside the project: never followed
          let t;
          try { t = fs.statSync(full); } catch { continue; }
          if (t.isDirectory()) stack.push([full, next]);
          else if (t.isFile()) consider(full);
        } else if (e.isDirectory()) stack.push([full, next]);
        else if (e.isFile()) consider(full);
      }
    }
  }
  function consider(full) {
    const rel = path.relative(root, full).split(path.sep).join('/');
    if (seen.has(rel) || rel.startsWith('..')) return;
    if (!inc.some((r) => r.test(rel))) return;
    if (exc.some((r) => r.test(rel))) return;
    seen.add(rel);
    out.push(rel);
  }
  return out.sort();
}
