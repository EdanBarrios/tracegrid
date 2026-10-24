// Cloud Functions a codebase deploys: the exports of its entry module (followed through
// `export * from` and `export { a } from`), classified as callable, HTTP or trigger.
import fs from 'node:fs';
import path from 'node:path';
import { maskCode } from './scan.js';
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

/** Definitions in one module: name -> { kind, line, body, trigger? }; plus its re-exports. */
function readModule(root, file) {
  let src;
  try { src = fs.readFileSync(path.join(root, file), 'utf8'); } catch { return null; }
  const t = maskCode(src);
  const line = lineIndex(t);
  const defs = new Map();
  const starts = [...t.matchAll(/^[ \t]*(?:export\s+const\s+([\w$]+)|exports\.([\w$]+)|module\.exports\.([\w$]+))\s*(?::[^=]+)?=\s*/gm)];
  for (let k = 0; k < starts.length; k++) {
    const m = starts[k];
    const name = m[1] || m[2] || m[3];
    const from = m.index + m[0].length;
    const to = k + 1 < starts.length ? starts[k + 1].index : t.length;
    const body = t.slice(from, to);
    const head = body.slice(0, 600);
    const kind = (KINDS.find(([, re]) => re.test(head)) || [])[0];
    if (!kind) { if (/^[\w$]+\s*;/.test(body)) defs.set(name, { alias: /^[\w$]+/.exec(body)[0], line: line(m.index) }); continue; }
    const trig = kind === 'trigger' ? /(?:document|ref|path)\s*\(?\s*:?\s*(['"`])([^'"`]+\/[^'"`]*)\1/.exec(head) || /\(\s*(['"`])([^'"`]+\/[^'"`]*)\1/.exec(head) : null;
    defs.set(name, { kind, line: line(m.index), body, ...(trig ? { trigger: trig[2] } : {}) });
  }
  const reexports = [];
  for (const m of t.matchAll(/export\s*\*\s*from\s*(['"])([^'"]+)\1/g)) reexports.push({ all: true, spec: m[2] });
  for (const m of t.matchAll(/export\s*\{([^}]*)\}\s*from\s*(['"])([^'"]+)\2/g)) {
    for (const part of m[1].split(',').map((s) => s.trim()).filter(Boolean)) {
      const [orig, as] = part.split(/\s+as\s+/).map((s) => s.trim());
      reexports.push({ name: orig, as: as || orig, spec: m[3] });
    }
  }
  // `import { a } from './x'; export { a };` and `export const a = imported;`
  const imports = new Map();
  for (const m of t.matchAll(/import\s*\{([^}]*)\}\s*from\s*(['"])([^'"]+)\2/g)) {
    for (const part of m[1].split(',').map((s) => s.trim()).filter(Boolean)) { const [orig, as] = part.split(/\s+as\s+/).map((s) => s.trim()); imports.set(as || orig, { name: orig, spec: m[3] }); }
  }
  for (const m of t.matchAll(/export\s*\{([^}]*)\}\s*(?!\s*from)/g)) {
    if (/from\s*['"]/.test(t.slice(m.index + m[0].length - 1, m.index + m[0].length + 20))) continue;
    for (const part of m[1].split(',').map((s) => s.trim()).filter(Boolean)) {
      const [orig, as] = part.split(/\s+as\s+/).map((s) => s.trim());
      if (imports.has(orig)) reexports.push({ name: imports.get(orig).name, as: as || orig, spec: imports.get(orig).spec });
    }
  }
  for (const [name, d] of [...defs]) if (d.alias && imports.has(d.alias)) reexports.push({ name: imports.get(d.alias).name, as: name, spec: imports.get(d.alias).spec });
  return { defs, reexports };
}

/**
 * Deployed functions of each codebase: [{ name, kind, file, line, at, body, trigger?, codebase }].
 * Without an entry module, every definition under the source directory counts.
 */
export function listCloudFunctions(root, sources) {
  const out = [];
  for (const s of sources) {
    const entry = entryOf(root, s.dir);
    const seen = new Set();
    const collect = (file, only, rename, depth) => {
      if (depth > 12 || seen.has(`${file}|${only || '*'}`)) return;
      seen.add(`${file}|${only || '*'}`);
      const mod = readModule(root, file);
      if (!mod) return;
      for (const [name, d] of mod.defs) {
        if (!d.kind || (only && name !== only)) continue;
        const as = only ? rename : name;
        out.push({ name: as, kind: d.kind, file, line: d.line, at: `${file}:${d.line}`, body: d.body, trigger: d.trigger, codebase: s.codebase });
      }
      for (const r of mod.reexports) {
        if (only && !r.all && r.as !== only) continue;
        const target = resolveModule(root, file, r.spec);
        if (!target) continue;
        if (r.all) collect(target, only, rename, depth + 1);
        else collect(target, r.name, only ? rename : r.as, depth + 1);
      }
    };
    if (entry) collect(entry, null, null, 0);
    else {
      const walk = (dir) => {
        let ents;
        try { ents = fs.readdirSync(path.join(root, dir), { withFileTypes: true }); } catch { return; }
        for (const e of ents) {
          if (e.name === 'node_modules' || e.name.startsWith('.') || e.name === 'lib' || e.name === '__tests__') continue;
          const rel = path.posix.join(dir, e.name);
          if (e.isDirectory()) walk(rel);
          else if (/\.(ts|js|mjs|cjs)$/.test(e.name) && !/\.(test|spec|d)\.[tj]s$/.test(e.name)) collect(rel, null, null, 0);
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
