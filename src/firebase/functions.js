// Cloud Functions a codebase deploys: the exports of its entry module (followed through
// `export * from` and `export { a } from`), classified as callable, HTTP or trigger.
import fs from 'node:fs';
import path from 'node:path';
import { maskCode, splitArgs, closeOf } from './scan.js';
import { lineIndex } from './rules.js';

const KINDS = [
  ['callable', /^(?:[\w$.]*\.)?(?:https\.)?onCall\b|\.https\.onCall\b|\bonCallGenkit\b/],
  ['http', /^(?:[\w$.]*\.)?(?:https\.)?onRequest\b|\.https\.onRequest\b/],
  ['trigger', /\b(?:onDocument\w*|onValue\w*|onObject\w*|onSchedule|onMessagePublished|onTaskDispatched|onCustomEventPublished|beforeUser\w*|beforeSign\w*|onNewFatalIssuePublished|onAlertPublished|onTestMatrixCompleted)\s*\(|\.(?:firestore|database|storage|pubsub|auth|analytics|remoteConfig|testLab|tasks)\s*\.\s*(?:document|ref|object|bucket|topic|schedule|user|event|taskQueue)\s*\(/],
];

/** Entry module of a functions codebase: package.json main mapped back to TypeScript source when built. */
function entryOf(root, dir) {
  const abs = path.join(root, dir);
  let main = 'index.js';
  try { main = JSON.parse(fs.readFileSync(path.join(abs, 'package.json'), 'utf8')).main || main; } catch { /* default */ }
  // Source before build output: lib/ may be stale or absent from the repository.
  const tries = [main.replace(/^(?:\.\/)?(?:lib|dist|build|out)\//, 'src/').replace(/\.js$/, '.ts'), 'src/index.ts', 'index.ts', main, 'src/index.js', 'index.js'];
  for (const t of tries) if (fs.existsSync(path.join(abs, t)) && fs.statSync(path.join(abs, t)).isFile()) return path.posix.join(dir, t.replace(/^\.\//, ''));
  return null;
}

function resolveModule(root, fromFile, spec) {
  if (!spec.startsWith('.')) return null;
  const base = path.posix.join(path.posix.dirname(fromFile), spec).replace(/\.js$/, '');
  for (const c of [base + '.ts', base + '.js', base + '.mts', base + '.mjs', base + '/index.ts', base + '/index.js', base]) {
    try { if (fs.statSync(path.join(root, c)).isFile()) return c; } catch { /* next */ }
  }
  return null;
}

/** End of the statement starting at `from`: the first `;` or line break outside brackets (strings skipped). */
function statementEnd(t, from, limit) {
  let depth = 0;
  for (let k = from; k < limit; k++) {
    const c = t[k];
    if (c === '"' || c === "'" || c === '`') { k++; while (k < limit && t[k] !== c) k += t[k] === '\\' ? 2 : 1; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (depth <= 0 && (c === ';' || (c === '\n' && !/^\s*[.?]/.test(t.slice(k + 1, k + 80))))) return k;
  }
  return limit;
}

/**
 * One module: `defs` (local name -> { kind, line, body, trigger? }), `exported` (exported name -> local
 * name) and `reexports` from other modules. Handles `export const`, `exports.x =`, a local `const x`
 * exported later (`export { x as y }`, `module.exports = { x }`), and grouped functions
 * (`export * as group from`, `exports.group = require()`), which deploy as `group-name`.
 */
function readModule(root, file) {
  let src;
  try { src = fs.readFileSync(path.join(root, file), 'utf8'); } catch { return null; }
  const t = maskCode(src);
  const line = lineIndex(t);
  const defs = new Map();
  const exported = new Map();
  const reexports = [];
  const groupRefs = [];
  // Top-level declarations only (column 0): a `const` inside a handler must not cut its body short.
  const starts = [...t.matchAll(/^(?:(export\s+)?(?:const|let|var)\s+([\w$]+)|exports\.([\w$]+)|module\.exports\.([\w$]+))\s*(?::[^=\n]+)?=(?!=)\s*/gm)];
  for (let k = 0; k < starts.length; k++) {
    const m = starts[k];
    const name = m[2] || m[3] || m[4];
    const isExport = !!(m[1] || m[3] || m[4]);
    const from = m.index + m[0].length;
    const body = t.slice(from, statementEnd(t, from, k + 1 < starts.length ? starts[k + 1].index : t.length));
    const head = body.slice(0, 600);
    const req = /^require\(\s*(['"])([^'"]+)\1\s*\)\s*(?:;|$)/m.exec(body.split('\n')[0]);
    if (req && isExport) { reexports.push({ all: true, ns: name, spec: req[2] }); continue; }
    // A group as an object literal: `export const admin = { ban: onCall(...), audit }` deploys `admin-ban`, `admin-audit`.
    if (isExport && body.startsWith('{')) {
      const obj = body.slice(1, closeOf(body, 0) - 1);
      let off = from + 1;
      for (const entry of splitArgs(obj)) {
        const at = t.indexOf(entry, off);
        if (at >= 0) off = at + entry.length;
        const kv = /^([\w$]+|(['"])[\w$-]+\2)\s*(?::\s*([\s\S]+))?$/.exec(entry);
        if (!kv) continue;
        const key = kv[1].replace(/['"]/g, '');
        if (kv[3] === undefined) { groupRefs.push([`${name}-${key}`, key]); continue; }
        const k = (KINDS.find(([, re]) => re.test(kv[3].slice(0, 600))) || [])[0];
        if (k) { defs.set(`${name}-${key}`, { kind: k, line: line(at >= 0 ? at : m.index), body: kv[3] }); exported.set(`${name}-${key}`, `${name}-${key}`); } else if (/^[\w$]+$/.test(kv[3].trim())) groupRefs.push([`${name}-${key}`, kv[3].trim()]);
      }
      continue;
    }
    const kind = (KINDS.find(([, re]) => re.test(head)) || [])[0];
    if (!kind) { if (isExport && /^[\w$]+\s*;?\s*$/m.test(body.split('\n')[0])) defs.set(name, { alias: /^[\w$]+/.exec(body)[0], line: line(m.index) }); else continue; } else {
      const trig = kind === 'trigger' ? /(?:document|ref|path)\s*\(?\s*:?\s*(['"`])([^'"`]+\/[^'"`]*)\1/.exec(head) || /\(\s*(['"`])([^'"`]+\/[^'"`]*)\1/.exec(head) : null;
      defs.set(name, { kind, line: line(m.index), body, ...(trig ? { trigger: trig[2] } : {}) });
    }
    if (isExport) exported.set(name, name);
  }
  const parts = (list) => list.split(',').map((x) => x.trim()).filter(Boolean).map((x) => x.split(/\s+as\s+|\s*:\s*/).map((y) => y.trim()));
  for (const m of t.matchAll(/export\s*\*\s*(?:as\s+([\w$]+)\s*)?from\s*(['"])([^'"]+)\2/g)) reexports.push({ all: true, ns: m[1], spec: m[3] });
  for (const m of t.matchAll(/export\s*\{([^}]*)\}\s*from\s*(['"])([^'"]+)\2/g)) for (const [orig, as] of parts(m[1])) reexports.push({ name: orig, as: as || orig, spec: m[3] });
  const imports = new Map();
  for (const m of t.matchAll(/import\s*\{([^}]*)\}\s*from\s*(['"])([^'"]+)\2/g)) for (const [orig, as] of parts(m[1])) imports.set(as || orig, { name: orig, spec: m[3] });
  // `export { a, b as c };` and `module.exports = { a, c: b };` naming local or imported bindings.
  const local = [];
  for (const m of t.matchAll(/export\s*\{([^}]*)\}(?!\s*from)/g)) for (const [orig, as] of parts(m[1])) local.push([as || orig, orig]);
  for (const m of t.matchAll(/module\.exports\s*=\s*\{([^}]*)\}/g)) for (const [key, val] of parts(m[1])) local.push([key, val || key]);
  for (const [as, orig] of groupRefs) if (defs.has(orig)) exported.set(as, orig);
  for (const [as, orig] of local) {
    if (defs.has(orig)) exported.set(as, orig);
    else if (imports.has(orig)) reexports.push({ name: imports.get(orig).name, as, spec: imports.get(orig).spec });
  }
  for (const [name, d] of [...defs]) if (d.alias && imports.has(d.alias)) reexports.push({ name: imports.get(d.alias).name, as: name, spec: imports.get(d.alias).spec });
  // Namespaces: `import * as cat from './cat'` / `const cat = require('./cat')`, then
  // `export const add = cat.add;` or `export const { add, remove: drop } = cat;`.
  const ns = new Map();
  for (const m of t.matchAll(/import\s*\*\s*as\s+([\w$]+)\s+from\s*(['"])([^'"]+)\2/g)) ns.set(m[1], m[3]);
  for (const m of t.matchAll(/^(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*(['"])([^'"]+)\2\s*\)/gm)) ns.set(m[1], m[3]);
  for (const m of t.matchAll(/^(?:export\s+const\s+([\w$]+)|exports\.([\w$]+)|module\.exports\.([\w$]+))\s*=\s*([\w$]+)\s*\.\s*([\w$]+)\s*;?\s*$/gm)) {
    if (ns.has(m[4])) reexports.push({ name: m[5], as: m[1] || m[2] || m[3], spec: ns.get(m[4]) });
    // A named import of an object of functions (`export const cat = { add, remove }`): its members are
    // registered as `cat-add` (the object-literal group form) in that module.
    else if (imports.has(m[4])) reexports.push({ name: `${imports.get(m[4]).name}-${m[5]}`, as: m[1] || m[2] || m[3], spec: imports.get(m[4]).spec });
  }
  for (const m of t.matchAll(/^export\s+const\s*\{([^}]*)\}\s*=\s*([\w$]+)\s*;?/gm)) {
    if (!ns.has(m[2])) continue;
    for (const [orig, as] of parts(m[1])) reexports.push({ name: orig, as: as || orig, spec: ns.get(m[2]) });
  }
  return { defs, exported, reexports };
}

/**
 * Deployed functions of each codebase: [{ name, kind, file, line, at, body, trigger?, codebase }].
 * Without an entry module, every exported definition under the source directory counts.
 */
export function listCloudFunctions(root, sources) {
  const out = [];
  for (const s of sources) {
    const entry = entryOf(root, s.dir);
    const seen = new Set();
    /** Exports of `file` (only the one named `only`, deployed as `rename`), each prefixed with `prefix`. */
    const collect = (file, only, rename, prefix, depth) => {
      const key = `${file}|${only || '*'}|${prefix}`;
      if (depth > 12 || seen.has(key)) return;
      seen.add(key);
      const mod = readModule(root, file);
      if (!mod) return;
      for (const [as, localName] of mod.exported) {
        const d = mod.defs.get(localName);
        if (!d || !d.kind || (only && as !== only)) continue;
        out.push({ name: prefix + (only ? rename : as), kind: d.kind, file, line: d.line, at: `${file}:${d.line}`, body: d.body, trigger: d.trigger, codebase: s.codebase });
      }
      for (const r of mod.reexports) {
        const target = resolveModule(root, file, r.spec);
        if (!target) continue;
        if (r.all && r.ns) { if (!only) collect(target, null, null, `${prefix}${r.ns}-`, depth + 1); else if (only.startsWith(`${r.ns}-`)) collect(target, only.slice(r.ns.length + 1), rename, prefix, depth + 1); } else if (r.all) collect(target, only, rename, prefix, depth + 1);
        else if (!only || r.as === only) collect(target, r.name, only ? rename : r.as, prefix, depth + 1);
      }
    };
    if (entry) collect(entry, null, null, '', 0);
    else {
      const walk = (dir) => {
        let ents;
        try { ents = fs.readdirSync(path.join(root, dir), { withFileTypes: true }); } catch { return; }
        for (const e of ents) {
          if (e.name === 'node_modules' || e.name.startsWith('.') || e.name === 'lib' || e.name === '__tests__') continue;
          const rel = path.posix.join(dir, e.name);
          if (e.isDirectory()) walk(rel);
          else if (/\.(ts|js|mjs|cjs)$/.test(e.name) && !/\.(test|spec|d)\.[tj]s$/.test(e.name)) collect(rel, null, null, '', 0);
        }
      };
      walk(s.dir);
    }
  }
  const byName = new Map();
  for (const f of out) if (!byName.has(f.name)) byName.set(f.name, f);
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Does a callable handler check the caller? Text heuristic over the handler: any `auth` reference
 * (request.auth, context.auth, a requireAuth helper) or the request handed to another function,
 * which may be the gate. Returns null when a possible check is found, else the reason.
 */
export function missingAuthCheck(body) {
  if (/\bauth\b|Auth\b|[a-z]Auth[A-Z]|\bauth[A-Z]|\buid\b/.test(body)) return null;
  // The handler's parameters: (request) in v2, (data, context) in v1.
  const arrow = /\(\s*(?!async\b)([\w$]+)(?:\s*:[^,()]*)?(?:\s*,\s*([\w$]+))?[^()]*\)\s*(?::[^=]*)?=>|\bfunction\s*[\w$]*\s*\(\s*([\w$]+)(?:\s*:[^,()]*)?(?:\s*,\s*([\w$]+))?[^()]*\)/.exec(body);
  const params = arrow ? [arrow[1], arrow[2], arrow[3], arrow[4]].filter(Boolean) : [];
  const handler = arrow ? body.slice(arrow.index + arrow[0].length) : body;
  for (const p of params) {
    if (new RegExp(String.raw`[\w$]\s*\(\s*(?:[^()]*,\s*)?${p.replace(/\$/g, '\\$')}\s*[,)]`).test(handler)) return null;
  }
  return 'the handler never reads request.auth / context.auth';
}
