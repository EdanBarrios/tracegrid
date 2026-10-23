// Scan application and edge-function code with the TypeScript AST for Supabase calls.
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { parseHatches } from './hatches.js';

const TABLE_OPS = new Set(['select', 'insert', 'update', 'delete', 'upsert']);
const STORAGE_OPS = new Set(['upload', 'download', 'remove', 'list', 'move', 'copy', 'createSignedUrl', 'createSignedUrls', 'createSignedUploadUrl', 'uploadToSignedUrl', 'getPublicUrl', 'update']);
const FN_URL = /\/functions\/v1\/([A-Za-z0-9_-]+)/g;
const SUPABASE_RECEIVER = /supabase|client|\bdb\b|admin|\bsb\b|service/i;

/**
 * @typedef {{ kind: 'table'|'rpc'|'invoke'|'bucket', name: string, file: string, line: number,
 *   op?: string, confidence: 'extracted'|'inferred', via?: string }} CallSite
 * @typedef {{ kind: string, file: string, line: number, expr: string }} Unresolved
 */

/** Strip parentheses, `as`, `<T>x`, `x!`, `satisfies`. */
function unwrap(n) {
  while (n && (ts.isParenthesizedExpression(n) || ts.isAsExpression(n) || ts.isTypeAssertionExpression(n)
    || ts.isNonNullExpression(n) || (ts.isSatisfiesExpression && ts.isSatisfiesExpression(n)))) n = n.expression;
  return n;
}

/** Same-file `const X = 'literal'` map. Ambiguous names (two different values) are dropped. */
function constStrings(sf) {
  const m = new Map();
  const bad = new Set();
  const visit = (n) => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer
      && n.parent && (n.parent.flags & ts.NodeFlags.Const)) {
      const init = unwrap(n.initializer);
      if (ts.isStringLiteral(init) || ts.isNoSubstitutionTemplateLiteral(init)) {
        const k = n.name.text;
        if (m.has(k) && m.get(k) !== init.text) bad.add(k);
        m.set(k, init.text);
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  for (const k of bad) m.delete(k);
  return m;
}

/** Resolve a name argument to one or more string literals. */
function resolveName(arg, consts) {
  const a = unwrap(arg);
  if (!a) return null;
  if (ts.isStringLiteral(a) || ts.isNoSubstitutionTemplateLiteral(a)) return { names: [a.text], confidence: 'extracted' };
  if (ts.isConditionalExpression(a)) {
    const t = resolveName(a.whenTrue, consts);
    const f = resolveName(a.whenFalse, consts);
    if (t && f) return { names: [...new Set([...t.names, ...f.names])], confidence: 'inferred' };
    return null;
  }
  if (ts.isBinaryExpression(a) && (a.operatorToken.kind === ts.SyntaxKind.BarBarToken || a.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)) {
    const l = resolveName(a.left, consts);
    const r = resolveName(a.right, consts);
    if (l && r) return { names: [...new Set([...l.names, ...r.names])], confidence: 'inferred' };
    return null;
  }
  if (ts.isIdentifier(a) && consts.has(a.text)) return { names: [consts.get(a.text)], confidence: 'inferred' };
  if (ts.isIdentifier(a)) {
    // A parameter typed as a union of string literals: (fn: 'a' | 'b') => ...
    for (let p = a.parent; p; p = p.parent) {
      if (ts.isFunctionLike(p) && p.parameters) {
        const q = p.parameters.find((x) => ts.isIdentifier(x.name) && x.name.text === a.text);
        if (!q) continue;
        const lits = literalUnion(q.type);
        return lits ? { names: lits, confidence: 'inferred' } : null;
      }
    }
  }
  return null;
}

function literalUnion(t) {
  if (!t) return null;
  const parts = ts.isUnionTypeNode(t) ? t.types : [t];
  const out = [];
  for (const x of parts) {
    if (ts.isLiteralTypeNode(x) && ts.isStringLiteral(x.literal)) out.push(x.literal.text);
    else return null;
  }
  return out.length ? out : null;
}

/** Text of a string or template literal with substitutions shown as ${}. */
function literalText(n) {
  if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return n.text;
  if (ts.isTemplateExpression(n)) return n.head.text + n.templateSpans.map((s) => '${}' + s.literal.text).join('');
  return null;
}

/** Name of the method chained directly onto a call: x.from('t').select() -> 'select'. */
function nextMethod(call) {
  let p = call.parent;
  while (p && (ts.isParenthesizedExpression(p) || ts.isNonNullExpression(p) || ts.isAsExpression(p))) p = p.parent;
  if (p && ts.isPropertyAccessExpression(p) && p.parent && ts.isCallExpression(p.parent) && p.parent.expression === p) return p.name.text;
  return null;
}

function insideFetch(n) {
  for (let p = n.parent; p; p = p.parent) {
    if (ts.isCallExpression(p)) {
      const c = unwrap(p.expression);
      return ts.isIdentifier(c) && c.text === 'fetch';
    }
    if (ts.isBlock(p) || ts.isSourceFile(p)) return false;
  }
  return false;
}

const short = (s) => s.replace(/\s+/g, ' ').slice(0, 80);

/**
 * Scan one source text.
 * @param {string} text @param {string} file relative path
 * @param {{ rpc: string[], from: string[], invoke: string[] }} wrappers
 * @returns {{ calls: CallSite[], unresolved: Unresolved[] }}
 */
export function scanSource(text, file, wrappers = { rpc: [], from: [], invoke: [] }) {
  const kind = /\.(tsx|jsx)$/.test(file) ? ts.ScriptKind.TSX : /\.(js|mjs|cjs)$/.test(file) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, kind);
  const consts = constStrings(sf);
  /** @type {CallSite[]} */ const calls = [];
  /** @type {Unresolved[]} */ const unresolved = [];
  const lineOf = (n) => sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
  const hatches = parseHatches(text);
  const namesAt = new Map(hatches.filter((h) => h.directive === 'names' && !h.error).map((h) => [h.line, h.names]));

  /** Names from a `supareach: names` hatch on the call's line, the line above, or above its enclosing function. */
  function hatchNames(node) {
    if (!namesAt.size) return null;
    const lines = [lineOf(node)];
    for (let p = node.parent; p; p = p.parent) {
      if (ts.isFunctionLike(p)) {
        lines.push(lineOf(p));
        if (p.parent && ts.isVariableDeclaration(p.parent) && p.parent.parent && p.parent.parent.parent) lines.push(lineOf(p.parent.parent.parent));
        break;
      }
    }
    for (const l of lines) for (const k of [l, l - 1]) if (namesAt.has(k)) return namesAt.get(k);
    return null;
  }

  /** Local wrappers: name -> { kind, index, extra }. Seeded from config, grown by inference. */
  const local = new Map();
  for (const k of ['rpc', 'from', 'invoke']) for (const w of wrappers[k] || []) local.set(w, { kind: k === 'from' ? 'table' : k, index: 0, extra: k === 'from' ? { op: 'other', via: w } : { via: w } });

  /** What Supabase call (if any) this call expression is, and which argument names the target. */
  function classify(n) {
    const callee = unwrap(n.expression);
    if (ts.isPropertyAccessExpression(callee)) {
      const name = callee.name.text;
      const recv = unwrap(callee.expression);
      const arg = n.arguments[0];
      if (!arg) return null;
      if (name === 'rpc') return { kind: 'rpc', arg, extra: {} };
      if (name === 'invoke' && ts.isPropertyAccessExpression(recv) && recv.name.text === 'functions') return { kind: 'invoke', arg, extra: { via: 'functions.invoke' } };
      if (name === 'from') {
        const nm = nextMethod(n);
        if (ts.isPropertyAccessExpression(recv) && recv.name.text === 'storage') return { kind: 'bucket', arg, extra: nm && STORAGE_OPS.has(nm) ? { op: nm } : {} };
        if (ts.isIdentifier(recv) && /^[A-Z]/.test(recv.text)) return null; // Array.from, Buffer.from
        const looksSupabase = (nm && TABLE_OPS.has(nm)) || SUPABASE_RECEIVER.test(recv.getText(sf))
          || (ts.isCallExpression(recv) && ts.isPropertyAccessExpression(unwrap(recv.expression)) && unwrap(recv.expression).name.text === 'schema');
        if (looksSupabase || resolveName(arg, consts)) return { kind: 'table', arg, extra: { op: nm && TABLE_OPS.has(nm) ? nm : 'other' } };
      }
      return null;
    }
    if (ts.isIdentifier(callee) && local.has(callee.text)) {
      const w = local.get(callee.text);
      const arg = n.arguments[w.index];
      return arg ? { kind: w.kind, arg, extra: { ...w.extra, via: callee.text } } : null;
    }
    return null;
  }

  /** If `arg` is a parameter of the enclosing named function, return { name, index }. */
  function paramOfEnclosing(arg) {
    const a = unwrap(arg);
    if (!a || !ts.isIdentifier(a)) return null;
    for (let p = a.parent; p; p = p.parent) {
      if (ts.isFunctionDeclaration(p) || ts.isArrowFunction(p) || ts.isFunctionExpression(p)) {
        const index = p.parameters.findIndex((q) => ts.isIdentifier(q.name) && q.name.text === a.text);
        if (index < 0) return null;
        let name = p.name && p.name.text;
        if (!name && p.parent && ts.isVariableDeclaration(p.parent) && ts.isIdentifier(p.parent.name)) name = p.parent.name.text;
        return name ? { name, index } : null;
      }
    }
    return null;
  }

  // Pass 1: infer same-file wrappers (a named function that passes its parameter as the name), to a fixpoint.
  const allCalls = [];
  (function collect(n) { if (ts.isCallExpression(n)) allCalls.push(n); ts.forEachChild(n, collect); })(sf);
  for (let changed = true, rounds = 0; changed && rounds < 5; rounds++) {
    changed = false;
    for (const c of allCalls) {
      const k = classify(c);
      if (!k || resolveName(k.arg, consts)) continue;
      const w = paramOfEnclosing(k.arg);
      if (w && !local.has(w.name)) { local.set(w.name, { kind: k.kind, index: w.index, extra: { ...k.extra, via: w.name } }); changed = true; }
    }
  }

  function record(k, node, arg, extra = {}) {
    let r = arg ? resolveName(arg, consts) : null;
    if (!r) { const h = hatchNames(node); if (h) r = { names: h, confidence: 'inferred', hatch: true }; }
    if (!r) {
      const w = paramOfEnclosing(arg);
      const u = { kind: k, file, line: lineOf(node), expr: short(arg ? arg.getText(sf) : node.getText(sf)) };
      if (w && local.has(w.name)) u.wrapper = w.name;
      unresolved.push(u);
      return;
    }
    for (const name of r.names) calls.push({ kind: k, name, file, line: lineOf(node), confidence: r.confidence, ...extra, ...(r.hatch ? { via: 'hatch' } : {}) });
  }

  function visit(n) {
    if (ts.isCallExpression(n)) {
      const k = classify(n);
      if (k) record(k.kind, n, k.arg, k.extra);
    }
    // Any string/template literal that contains /functions/v1/<name>.
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) || ts.isTemplateExpression(n)) {
      const t = literalText(n);
      if (t && t.includes('/functions/v1/')) {
        const conf = insideFetch(n) ? 'extracted' : 'inferred';
        let hit = false;
        for (const m of t.matchAll(FN_URL)) { hit = true; calls.push({ kind: 'invoke', name: m[1], file, line: lineOf(n), confidence: conf, via: 'url' }); }
        if (!hit && /\/functions\/v1\/\$\{\}/.test(t)) unresolved.push({ kind: 'invoke', file, line: lineOf(n), expr: short(n.getText(sf)) });
      }
      if (ts.isTemplateExpression(n)) { n.templateSpans.forEach((s) => visit(s.expression)); return; }
    }
    ts.forEachChild(n, visit);
  }
  visit(sf);

  const suppress = [];
  const invalid = [];
  for (const h of hatches) {
    if (h.error) { invalid.push({ file, line: h.line, error: h.error }); continue; }
    if (h.directive !== 'ignore') continue;
    const subjects = [...new Set(calls.filter((c) => c.line === h.line || c.line === h.line + 1).map((c) => c.name))];
    if (!subjects.length) { invalid.push({ file, line: h.line, error: 'ignore: no Supabase call on this or the next line' }); continue; }
    for (const subject of subjects) suppress.push({ rule: h.rule, subject, reason: h.reason, at: `${file}:${h.line}` });
  }
  return { calls, unresolved, hatches: { suppress, invalid, raw: hatches } };
}

/** Scan a list of files relative to root. */
export function scanFiles(root, files, wrappers) {
  const calls = [];
  const unresolved = [];
  const failed = [];
  const hatches = { suppress: [], invalid: [], byFile: new Map() };
  for (const f of files) {
    let text;
    try { text = fs.readFileSync(path.join(root, f), 'utf8'); } catch (e) { failed.push({ file: f, error: String(e.message) }); continue; }
    try {
      const r = scanSource(text, f, wrappers);
      calls.push(...r.calls);
      unresolved.push(...r.unresolved);
      hatches.suppress.push(...r.hatches.suppress);
      hatches.invalid.push(...r.hatches.invalid);
      if (r.hatches.raw.length) hatches.byFile.set(f, r.hatches.raw);
    } catch (e) { failed.push({ file: f, error: String(e.message) }); }
  }
  return { calls, unresolved, failed, hatches };
}
