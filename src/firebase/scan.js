// Firebase call sites in app code: Firestore references and callable Cloud Functions, from Dart
// (FlutterFire) and JavaScript/TypeScript (web v9 modular, v8/compat chains, firebase-admin).
// Text-based, like the Dart side has to be: comments are masked, string literals are read, and
// anything that is not a literal or a resolvable constant is reported as unresolved, never dropped.
import fs from 'node:fs';
import path from 'node:path';
import { lineIndex } from './rules.js';

const MAX_FILE = 2 * 1024 * 1024;

/** Mask comments (Dart and JS: //, /* *\/), keeping strings, template literals and line breaks. */
export function maskCode(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === '/' && src[i + 1] === '/') { let j = i; while (j < n && src[j] !== '\n') j++; out += ' '.repeat(j - i); i = j; continue; }
    if (c === '/' && src[i + 1] === '*') { const e = src.indexOf('*/', i + 2); const j = e < 0 ? n : e + 2; out += src.slice(i, j).replace(/[^\n]/g, ' '); i = j; continue; }
    if (c === '"' || c === "'" || c === '`') {
      const triple = c !== '`' && src.startsWith(c.repeat(3), i);
      const close = triple ? c.repeat(3) : c;
      let j = i + close.length;
      while (j < n && !src.startsWith(close, j) && (triple || c === '`' || src[j] !== '\n')) j += src[j] === '\\' ? 2 : 1;
      j = Math.min(n, j + close.length);
      out += src.slice(i, j);
      i = j;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/** Index just past the bracket that closes the one at `at`. */
export function closeOf(t, at) {
  const open = t[at];
  const close = { '(': ')', '[': ']', '{': '}' }[open];
  let depth = 0;
  for (let k = at; k < t.length; k++) {
    const c = t[k];
    if (c === '"' || c === "'" || c === '`') {
      const triple = c !== '`' && t.startsWith(c.repeat(3), k);
      const q = triple ? c.repeat(3) : c;
      k += q.length;
      while (k < t.length && !t.startsWith(q, k)) k += t[k] === '\\' ? 2 : 1;
      k += q.length - 1;
      continue;
    }
    if (c === open) depth++;
    else if (c === close && --depth === 0) return k + 1;
  }
  return t.length;
}

/** Split an argument list on top-level commas. */
export function splitArgs(s) {
  const out = [];
  let depth = 0;
  let last = 0;
  for (let k = 0; k < s.length; k++) {
    const c = s[k];
    if (c === '"' || c === "'" || c === '`') { const e = closeQuote(s, k); k = e - 1; continue; }
    if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) depth--;
    else if (c === ',' && depth === 0) { out.push(s.slice(last, k).trim()); last = k + 1; }
  }
  const tail = s.slice(last).trim();
  if (tail || out.length) out.push(tail);
  return out.filter((x, idx, a) => x || idx < a.length - 1);
}
function closeQuote(s, k) {
  const c = s[k];
  const triple = c !== '`' && s.startsWith(c.repeat(3), k);
  const q = triple ? c.repeat(3) : c;
  let j = k + q.length;
  while (j < s.length && !s.startsWith(q, j)) j += s[j] === '\\' ? 2 : 1;
  return Math.min(s.length, j + q.length);
}

/**
 * A string literal argument as a path pattern: segments with interpolations (`$x`, `${x}`) as `*`.
 * Returns null when the argument is not a single string literal.
 */
export function literalPath(arg) {
  const m = /^r?(['"`])([\s\S]*)\1$/.exec(arg.trim()) || /^r?('''|""")([\s\S]*)\1$/.exec(arg.trim());
  if (!m) return null;
  const body = m[2];
  if (/^\s*$/.test(body)) return null;
  return body.split('/').filter((s) => s !== '').map((s) => (/\$\{|\$[A-Za-z_]/.test(s) ? '*' : s));
}

/** `a + '/x/' + b` or `'users/' + uid` (JS concatenation): segments, or null. */
function concatPath(arg) {
  const parts = arg.split(/\s*\+\s*/);
  if (parts.length < 2) return null;
  let s = '';
  for (const p of parts) {
    const lit = /^(['"`])([^'"`]*)\1$/.exec(p.trim());
    if (lit && !/\$\{/.test(lit[2])) s += lit[2];
    else if (/^[\w$.()?!]+$/.test(p.trim())) s += '\u0000';
    else return null;
  }
  if (!s.replace(/\u0000/g, '').trim()) return null;
  return s.split('/').filter((x) => x !== '').map((x) => (x.includes('\u0000') ? '*' : x));
}

/**
 * String constants declared in a file: [name, value]. Only names that read as constants
 * (`kUsers`, `USERS_COLLECTION`, `usersCollection`, `userDocPath`): a local `const uid = 'test'`
 * must not resolve every `doc(uid)` in the project.
 */
export const CONST_NAME = /^(?:k[A-Z]\w*|[A-Z][A-Z0-9_]*|\w*(?:Collection|Coll|Col|Path|Doc|DocId|Ref)s?)$/;
export function constantsIn(text) {
  const out = [];
  const re = /\b(?:static\s+)?(?:const|final|var|let)\s+(?:String\s+)?([A-Za-z_$][\w$]*)\s*=\s*(['"])([^'"\\\n$]*)\2\s*[;,]/g;
  let m;
  while ((m = re.exec(text))) if (CONST_NAME.test(m[1])) out.push([m[1], m[3]]);
  return out;
}

const ROOT_RECEIVER = /(?:^|[.\s(])(?:FirebaseFirestore\.instance(?:For\([^)]*\))?|firestore\(\s*\)|getFirestore\([^)]*\)|instance|_?db|_?firestore|_?fs|_?store|_?database|firestoreInstance|_?firestoreDb)$/;
const SERVER_HINT = /from\s+['"]firebase-admin|require\(\s*['"]firebase-admin|from\s+['"]firebase-functions|require\(\s*['"]firebase-functions/;

/** The expression immediately before offset `p` (a receiver like `FirebaseFirestore.instance` or `_db`). */
function receiverBefore(t, p) {
  const back = (k) => { while (k > 0 && /\s/.test(t[k - 1])) k--; return k; };
  let k = back(p);
  for (;;) {
    const c = t[k - 1];
    if (c === ')' || c === ']') {
      let depth = 0;
      let j = k - 1;
      for (; j >= 0; j--) { if (t[j] === c) depth++; else if (t[j] === (c === ')' ? '(' : '[')) { if (--depth === 0) break; } }
      k = j;
    } else if (c && /[\w$?!]/.test(c)) { while (k > 0 && /[\w$?!]/.test(t[k - 1])) k--; } else break;
    // Continue only across a member access (`a.b`, `a\n  .b`).
    const d = back(k);
    if (t[d - 1] !== '.') break;
    k = back(d - 1);
  }
  return t.slice(k, p).replace(/\s+/g, '');
}

/**
 * Scan one file. `consts` maps constant names to their value (or null when ambiguous).
 * Returns { calls, unresolved, wrappers } where calls are
 * { kind: 'doc'|'invoke', path?, anyPrefix?, name?, op?, file, line, confidence, privileged }.
 */
export function scanFirebaseFile(file, src, { consts = new Map(), privileged = false, invokeWrappers = [], pathWrappers = [] } = {}) {
  const t = maskCode(src);
  const line = lineIndex(t);
  const isDart = file.endsWith('.dart');
  const calls = [];
  const unresolved = [];
  const wrappers = [];
  const priv = privileged || (!isDart && SERVER_HINT.test(t));
  const usesFirestore = /firestore/i.test(t);
  const usesFunctions = /httpsCallable|cloudfunctions\.net/i.test(t);

  /** A path argument: literal, concatenation, or a resolvable constant (incl. `Cls.name`). */
  const argPath = (arg) => {
    const lit = literalPath(arg) || concatPath(arg);
    if (lit) return lit;
    const id = /^(?:[\w$]+\.)*([\w$]+)$/.exec(arg.trim());
    if (id && consts.get(id[1])) return consts.get(id[1]).split('/').filter(Boolean);
    return null;
  };

  // --- Firestore chains: .collection(...).doc(...).collection(...) (Dart, v8/compat, admin) ---
  const chainRe = /\.\s*(collection|collectionGroup|doc|document)\s*\(/g;
  const resolving = new Set();
  /** Segments for a chain whose receiver is the identifier `name`, from its assignment in this file. */
  const resolveVar = (name, before) => {
    if (resolving.has(name) || resolving.size > 4) return null;
    const esc = name.replace(/[$]/g, '\\$');
    const re = new RegExp(String.raw`(?:\b|^)(?:get\s+)?${esc}\s*(?:=>|=(?![=>]))\s*`, 'g');
    let m;
    let best = null;
    while ((m = re.exec(t))) {
      if (m.index > before && best) break;
      const startRhs = m.index + m[0].length;
      let k = startRhs;
      let depth = 0;
      for (; k < t.length; k++) {
        const c = t[k];
        if ('([{'.includes(c)) depth++;
        else if (')]}'.includes(c)) { if (depth === 0) break; depth--; } else if ((c === ';' || c === ',') && depth === 0) break;
      }
      best = [startRhs, k];
    }
    if (!best) return null;
    resolving.add(name);
    const sub = chains(best[0], best[1]);
    resolving.delete(name);
    const last = sub.filter((c) => c.ok).pop();
    return last && last.end >= best[1] - 2 ? last : null;
  };

  /** Chains in t[from, to): [{ segs, anyPrefix, endsOn, end, ok, start }]. */
  function chains(from, to) {
    const out = [];
    const re = new RegExp(chainRe.source, 'g');
    re.lastIndex = from;
    let m;
    let cur = null;
    while ((m = re.exec(t)) && m.index < to) {
      const open = m.index + m[0].length - 1;
      const end = closeOf(t, open);
      const args = splitArgs(t.slice(open + 1, end - 1));
      const method = m[1] === 'document' ? 'doc' : m[1];
      const continues = cur && cur.ok && /^\s*$/.test(t.slice(cur.end, m.index));
      if (!continues) {
        if (cur) out.push(cur);
        const recv = receiverBefore(t, m.index);
        cur = { segs: [], anyPrefix: false, ok: true, start: m.index, end, recv, method };
        if (method === 'collectionGroup') cur.anyPrefix = true;
        else if (!ROOT_RECEIVER.test(recv) && !/Firestore/.test(recv)) {
          const id = /([\w$]+)$/.exec(recv);
          const r = id ? resolveVar(id[1], m.index) : null;
          // Not a Firestore instance and not resolvable: the parent path is unknown.
          if (r) { cur.segs = [...r.segs]; cur.anyPrefix = r.anyPrefix; } else cur.anyPrefix = true;
        }
      }
      cur.end = end;
      cur.endsOn = method === 'doc' ? 'doc' : 'collection';
      if (!args.length || !args[0]) { cur.segs.push('*'); continue; }
      const p = argPath(args[0]);
      if (p) cur.segs.push(...p);
      else if (method === 'doc') cur.segs.push('*');
      else { cur.ok = false; cur.expr = t.slice(cur.start, end).replace(/\s+/g, ' ').slice(0, 160); }
    }
    if (cur) out.push(cur);
    return out;
  }

  const OPS = { get: 'read', snapshots: 'read', onSnapshot: 'read', where: 'read', orderBy: 'read', limit: 'read', count: 'read', stream: 'read', set: 'write', update: 'write', add: 'write', delete: 'write' };
  if (usesFirestore) {
    for (const c of chains(0, t.length)) {
      const at = line(c.start);
      if (!c.ok) { unresolved.push({ kind: 'firestore', file, line: at, expr: c.expr, privileged: priv }); continue; }
      if (!c.segs.length || c.segs.every((s) => s === '*')) {
        if (c.anyPrefix) continue; // a reference whose path is entirely unknown: nothing to link
      }
      const segs = [...c.segs];
      // Under an unknown parent, leading unknown segments are document ids: start at the collection.
      if (c.anyPrefix) while (segs[0] === '*') segs.shift();
      if (!segs.length) continue;
      // Rules match documents: a collection reference reaches the documents inside it.
      if (c.endsOn === 'collection' || (!c.anyPrefix && segs.length % 2 === 1)) segs.push('*');
      const after = /^\s*\.\s*(\w+)/.exec(t.slice(c.end, c.end + 80));
      calls.push({ kind: 'doc', path: segs, anyPrefix: c.anyPrefix, op: after && OPS[after[1]], file, line: at, confidence: c.anyPrefix ? 'inferred' : 'extracted', privileged: priv });
    }
    // --- Web v9 modular: collection(db, 'a', id, 'b'), doc(db, 'a/b'), collectionGroup(db, 'x') ---
    if (!isDart) {
      const mod = /(?<![.\w$])(collection|collectionGroup|doc)\s*\(/g;
      const nested = new Set();
      const modular = (start) => {
        const mm = /^(collection|collectionGroup|doc)\s*\(/.exec(t.slice(start, start + 40));
        if (!mm) return null;
        const open = start + mm[0].length - 1;
        const end = closeOf(t, open);
        const args = splitArgs(t.slice(open + 1, end - 1));
        if (!args.length) return null;
        const res = { segs: [], anyPrefix: mm[1] === 'collectionGroup', method: mm[1], ok: true, start, end };
        const first = args[0];
        const inner = /^(collection|collectionGroup|doc)\s*\(/.test(first) ? modular(open + 1 + t.slice(open + 1).indexOf(first)) : null;
        if (inner) { nested.add(inner.start); res.segs = inner.segs; res.anyPrefix = inner.anyPrefix; if (!inner.ok) { res.ok = false; res.expr = inner.expr; } } else if (!ROOT_RECEIVER.test(first) && !/firestore|db/i.test(first)) {
          const r = /^[\w$]+$/.test(first) ? resolveVar(first, start) : null;
          if (r) { res.segs = [...r.segs]; res.anyPrefix = r.anyPrefix; } else res.anyPrefix = true;
        }
        const rest = args.slice(1);
        if (!rest.length && mm[1] === 'doc') res.segs.push('*');
        rest.forEach((a, idx) => {
          const p = argPath(a);
          if (p) res.segs.push(...p);
          else if (/^[\w$.?!()]+$/.test(a) && (mm[1] === 'doc' || idx > 0)) res.segs.push('*');
          else { res.ok = false; res.expr = t.slice(start, end).replace(/\s+/g, ' ').slice(0, 160); }
        });
        res.endsOn = mm[1] === 'doc' ? 'doc' : 'collection';
        return res;
      };
      const found = [];
      let m;
      while ((m = mod.exec(t))) { const r = modular(m.index); if (r) found.push(r); }
      for (const c of found) {
        if (nested.has(c.start)) continue;
        const at = line(c.start);
        if (!c.ok) { unresolved.push({ kind: 'firestore', file, line: at, expr: c.expr, privileged: priv }); continue; }
        if (!c.segs.length) continue;
        const segs = [...c.segs];
        if (c.endsOn === 'collection' || (!c.anyPrefix && segs.length % 2 === 1)) segs.push('*');
        calls.push({ kind: 'doc', path: segs, anyPrefix: c.anyPrefix, file, line: at, confidence: c.anyPrefix ? 'inferred' : 'extracted', privileged: priv });
      }
    }
  }

  // --- Storage: FirebaseStorage.instance.ref('a').child('b') (Dart, v8), ref(storage, 'a/b') (web v9) ---
  if (/storage/i.test(t)) {
    const storageCall = (start, segs, end) => {
      // `.child(x)` continuations extend the path; a dynamic child is one unknown segment.
      for (;;) {
        const nx = /^\s*\.\s*child\s*\(/.exec(t.slice(end, end + 200));
        if (!nx) break;
        const open = end + nx[0].length - 1;
        const close = closeOf(t, open);
        const a = splitArgs(t.slice(open + 1, close - 1))[0] || '';
        segs.push(...(argPath(a) || ['*']));
        end = close;
      }
      if (segs.length) calls.push({ kind: 'storage', path: segs, file, line: line(start), confidence: segs.includes('*') ? 'inferred' : 'extracted', privileged: priv });
    };
    for (const m of t.matchAll(/\.\s*ref\s*\(/g)) {
      if (!/storage/i.test(receiverBefore(t, m.index))) continue;
      const open = m.index + m[0].length - 1;
      const end = closeOf(t, open);
      const a = splitArgs(t.slice(open + 1, end - 1))[0];
      storageCall(m.index, a ? argPath(a) || ['*'] : [], end);
    }
    if (!isDart) {
      for (const m of t.matchAll(/(?<![\w$.])ref\s*\(/g)) {
        const open = m.index + m[0].length - 1;
        const end = closeOf(t, open);
        const args = splitArgs(t.slice(open + 1, end - 1));
        if (args.length < 1 || !/storage/i.test(args[0])) continue;
        storageCall(m.index, args[1] ? argPath(args[1]) || ['*'] : [], end);
      }
    }
  }

  // --- Callable functions: httpsCallable('name') (Dart), httpsCallable(functions, 'name') (JS) ---
  if (usesFunctions) {
    const re = /\bhttpsCallable(FromUrl|FromURL)?\s*\(/g;
    let m;
    while ((m = re.exec(t))) {
      const open = m.index + m[0].length - 1;
      const args = splitArgs(t.slice(open + 1, closeOf(t, open) - 1));
      const at = line(m.index);
      const lits = args.map((a) => literalPath(a));
      if (m[1]) {
        const url = lits.find(Boolean);
        if (url && url.length && url[url.length - 1] !== '*') calls.push({ kind: 'invoke', name: url[url.length - 1], file, line: at, confidence: 'extracted', privileged: priv });
        else unresolved.push({ kind: 'invoke', file, line: at, expr: t.slice(m.index, closeOf(t, open)).replace(/\s+/g, ' ').slice(0, 160), privileged: priv });
        continue;
      }
      const idx = lits.findIndex((x) => x && x.length === 1 && x[0] !== '*');
      if (idx >= 0) { calls.push({ kind: 'invoke', name: lits[idx][0], file, line: at, confidence: 'extracted', privileged: priv }); continue; }
      const nameArg = isDart ? args[0] : args[1] ?? args[0];
      const cst = nameArg && /^(?:[\w$]+\.)*([\w$]+)$/.exec(nameArg.trim());
      if (cst && consts.get(cst[1])) { calls.push({ kind: 'invoke', name: consts.get(cst[1]), file, line: at, confidence: 'extracted', privileged: priv }); continue; }
      // A parameter passed straight through: the enclosing function is a wrapper (`_call('name', ...)`).
      if (cst && !nameArg.includes('.')) {
        const before = t.slice(Math.max(0, m.index - 4000), m.index);
        const decls = [...before.matchAll(new RegExp(String.raw`([A-Za-z_$][\w$]*)\s*(?:<[^>()]*>)?\s*\(([^()]*\b${cst[1]}\b[^()]*)\)\s*(?:async\s*)?(?:\{|=>)`, 'g'))];
        const d = decls.pop();
        if (d && !/^(if|for|while|switch|catch|function)$/.test(d[1])) {
          const pos = splitArgs(d[2]).findIndex((p) => new RegExp(String.raw`\b${cst[1]}\s*$`).test(p.replace(/=.*$/, '').trim()) || new RegExp(String.raw`^(?:required\s+)?(?:\w+\??\s+)?${cst[1]}\b`).test(p.trim()));
          wrappers.push({ name: d[1], arg: Math.max(0, pos), file, local: d[1].startsWith('_') });
          continue;
        }
      }
      unresolved.push({ kind: 'invoke', file, line: at, expr: t.slice(m.index, closeOf(t, open)).replace(/\s+/g, ' ').slice(0, 160), privileged: priv });
    }
    // HTTP functions called by URL.
    for (const u of t.matchAll(/cloudfunctions\.net\/([A-Za-z][\w-]*)/g)) calls.push({ kind: 'invoke', name: u[1], http: true, file, line: line(u.index), confidence: 'extracted', privileged: priv });
  }
  // Configured path wrappers: `docAt('users', uid)`, `new FirestoreDoc('apps', 'public')`, `query({ collectionId: 'x' })`.
  for (const name of pathWrappers) {
    const re = new RegExp(String.raw`(?<![\w$.])${name.replace(/\$/g, '\\$')}\s*\(`, 'g');
    let m;
    while ((m = re.exec(t))) {
      const open = m.index + m[0].length - 1;
      const end = closeOf(t, open);
      if (/^\s*(?:async\s*)?(?:\{|=>)/.test(t.slice(end, end + 12))) continue; // the helper's own declaration
      const args = splitArgs(t.slice(open + 1, end - 1));
      const at = line(m.index);
      const expr = t.slice(m.index, end).replace(/\s+/g, ' ').slice(0, 160);
      let segs = null;
      const obj = args[0] && args[0].startsWith('{') ? /\b(?:collectionId|collectionPath|collection|path)\s*:\s*(['"`][^'"`]*['"`])/.exec(args[0]) : null;
      if (obj) segs = literalPath(obj[1]);
      else if (args.length && argPath(args[0])) {
        segs = [];
        for (const a of args) { const p = argPath(a); if (p) segs.push(...p); else if (/^[\w$.?!()]+$/.test(a) && segs.length % 2 === 1) segs.push('*'); else break; }
      }
      if (!segs || !segs.length) { unresolved.push({ kind: 'firestore', file, line: at, expr, privileged: priv, via: name }); continue; }
      if (segs.length % 2 === 1) segs.push('*');
      calls.push({ kind: 'doc', path: segs, anyPrefix: false, file, line: at, confidence: 'inferred', privileged: priv, via: name });
    }
  }
  // Configured invoke wrappers: `callFunction('name', ...)`.
  for (const w of invokeWrappers) {
    if (w.local && w.file !== file) continue;
    const re = new RegExp(String.raw`(?<![\w$])${w.name.replace(/\$/g, '\\$')}\s*\(`, 'g');
    let m;
    while ((m = re.exec(t))) {
      const open = m.index + m[0].length - 1;
      const args = splitArgs(t.slice(open + 1, closeOf(t, open) - 1));
      const a = args[w.arg ?? 0];
      if (a === undefined) continue;
      const lit = literalPath(a);
      // The wrapper's own declaration has a parameter here, not a value.
      if (lit && lit.length === 1 && lit[0] !== '*') calls.push({ kind: 'invoke', name: lit[0], file, line: line(m.index), confidence: 'inferred', privileged: priv, via: w.name });
      else if (!/^\s*(?:async\s*)?(?:\{|=>)/.test(t.slice(closeOf(t, open), closeOf(t, open) + 12))) {
        unresolved.push({ kind: 'invoke', file, line: line(m.index), expr: t.slice(m.index, closeOf(t, open)).replace(/\s+/g, ' ').slice(0, 160), privileged: priv, via: w.name });
      }
    }
  }
  return { calls, unresolved, wrappers };
}

/**
 * Scan files (relative to root). `serverDirs`: Cloud Functions sources, whose Firestore access goes
 * through the Admin SDK and bypasses rules. Two passes: constants and invoke wrappers first.
 */
export function scanFirebase(root, files, { serverDirs = [], wrappers = [], pathWrappers = [] } = {}) {
  const texts = new Map();
  const failed = [];
  for (const f of files) {
    try {
      const abs = path.join(root, f);
      if (fs.statSync(abs).size > MAX_FILE) { failed.push({ file: f, error: 'larger than 2 MB' }); continue; }
      texts.set(f, fs.readFileSync(abs, 'utf8'));
    } catch (e) { failed.push({ file: f, error: e.code || e.message }); }
  }
  const constVals = new Map();
  for (const src of texts.values()) for (const [k, v] of constantsIn(maskCode(src))) { if (!constVals.has(k)) constVals.set(k, new Set()); constVals.get(k).add(v); }
  const consts = new Map([...constVals].map(([k, v]) => [k, v.size === 1 ? [...v][0] : null]));
  const isServer = (f) => serverDirs.some((d) => f === d || f.startsWith(d.replace(/\/?$/, '/')));
  const first = new Map();
  const found = [...wrappers.map((name) => ({ name, arg: 0, local: false }))];
  for (const [f, src] of texts) {
    const r = scanFirebaseFile(f, src, { consts, privileged: isServer(f), pathWrappers: pathWrappers.filter((w) => src.includes(w)) });
    first.set(f, r);
    found.push(...r.wrappers);
  }
  const calls = [];
  const unresolved = [];
  for (const [f, src] of texts) {
    let r = first.get(f);
    const mine = found.filter((w) => !w.local || w.file === f);
    if (mine.length && mine.some((w) => src.includes(w.name))) r = scanFirebaseFile(f, src, { consts, privileged: isServer(f), invokeWrappers: mine, pathWrappers: pathWrappers.filter((w) => src.includes(w)) });
    calls.push(...r.calls);
    unresolved.push(...r.unresolved);
  }
  return { calls, unresolved, failed, wrappers: found, texts };
}
