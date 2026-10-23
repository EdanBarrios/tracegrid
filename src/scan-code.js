// Scan application and edge-function code with the TypeScript AST for Supabase calls.
//
// Two passes over the project: the first summarises what each file exports (string constants,
// object maps, enums, Supabase clients, wrapper functions); the second scans every file for calls,
// resolving identifiers through lexical scope and imports. No type checker: names, bindings and
// literal values only.
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { parseHatches } from './hatches.js';

const TABLE_OPS = new Set(['select', 'insert', 'update', 'delete', 'upsert']);
const STORAGE_OPS = new Set(['upload', 'download', 'remove', 'list', 'move', 'copy', 'createSignedUrl', 'createSignedUrls', 'createSignedUploadUrl', 'uploadToSignedUrl', 'getPublicUrl', 'update', 'exists', 'info']);
/** Functions that return a supabase-js client. */
const CLIENT_FACTORY = /^(createClient|createBrowserClient|createServerClient|createRouteHandlerClient|createServerComponentClient|createClientComponentClient|createPagesBrowserClient|createPagesServerClient|createMiddlewareClient|createServerActionClient|useSupabaseClient|useSupabase|getSupabase\w*|supabaseClient|createSupabase\w*|create\w*SupabaseClient|createAdminClient|createServiceClient|createServiceRoleClient|useClient)$/;
/** Receiver names that are (almost certainly) a Supabase client. */
const SUPABASE_NAME = /supabase|client|^sb$|^db$|admin|service/i;
/** Receiver names and modules that are something else (query builders, RPC providers, observables). */
const NOT_SUPABASE_NAME = /^(knex|kysely|prisma|provider|ethers|web3|viem|trx|drizzle|sequelize|typeorm|mongoose|redis|octokit|qb|queryBuilder|obs|observable|rx|axios)$/i;
const NOT_SUPABASE_MODULE = /^(knex|kysely|ethers|viem|web3|rxjs|drizzle-orm|@prisma\/client|sequelize|typeorm|mongoose|ioredis|redis|@octokit\/.*|msw|axios)(\/|$)/;
/** A key argument or name that marks a client as privileged (service_role / secret key: bypasses RLS and grants). */
const PRIVILEGED_KEY = /service_?role|SERVICE_?ROLE|secret_?key|SECRET_?KEY|sb_secret_/;
const PRIVILEGED_NAME = /^(supabaseAdmin|adminClient|admin|adminSupabase|serviceClient|serviceRoleClient|supabaseService|serviceSupabase|supabaseServiceRole)$/;
const FN_URL = /(?:^|\/)functions\/v1\/([A-Za-z0-9_-]+)/g;
const REST_RPC = /\/rest\/v1\/rpc\/([A-Za-z_][\w]*)/g;
const REST_TABLE = /\/rest\/v1\/(?!rpc\/)([A-Za-z_][\w]*)/g;
const UNKNOWN = '\u0000';
const MAX_VALUES = 64;

/**
 * @typedef {{ kind: 'table'|'rpc'|'invoke'|'bucket'|'select', name: string, file: string, line: number,
 *   op?: string, confidence: 'extracted'|'inferred'|'ambiguous', via?: string, schema?: string,
 *   weak?: boolean, privileged?: boolean, anySchema?: boolean }} CallSite
 * @typedef {{ kind: string, file: string, line: number, expr: string, pattern?: string, wrapper?: string }} Unresolved
 */

/** Strip parentheses, `as`, `<T>x`, `x!`, `satisfies`, `await`. */
function unwrap(n) {
  while (n && (ts.isParenthesizedExpression(n) || ts.isAsExpression(n) || ts.isTypeAssertionExpression(n) || ts.isAwaitExpression(n)
    || ts.isNonNullExpression(n) || (ts.isSatisfiesExpression && ts.isSatisfiesExpression(n)))) n = n.expression;
  return n;
}
const isStr = (n) => n && (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n));
const propName = (n) => (n && (ts.isIdentifier(n) || ts.isStringLiteral(n) || ts.isNumericLiteral(n) || ts.isPrivateIdentifier(n)) ? n.text : null);
const short = (s) => s.replace(/\s+/g, ' ').slice(0, 80);
const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Name of the method chained directly onto a call: x.from('t').select() -> 'select'. */
function nextMethod(call) {
  let p = call.parent;
  while (p && (ts.isParenthesizedExpression(p) || ts.isNonNullExpression(p) || ts.isAsExpression(p))) p = p.parent;
  if (p && ts.isPropertyAccessExpression(p) && p.parent && ts.isCallExpression(p.parent) && p.parent.expression === p) return p.name.text;
  return null;
}

function insideFetch(n) {
  for (let p = n.parent; p; p = p.parent) {
    if (ts.isCallExpression(p) || ts.isNewExpression(p)) {
      const c = unwrap(p.expression);
      return ts.isIdentifier(c) && /^(fetch|URL|Request|ky|got|\$fetch|ofetch)$/.test(c.text) || (ts.isPropertyAccessExpression(c) && /^(get|post|put|patch|delete|request|fetch)$/.test(c.name.text) && !/^http$/.test(c.expression.getText()));
    }
    if (ts.isBlock(p) || ts.isSourceFile(p)) return false;
  }
  return false;
}

/**
 * PostgREST select string -> items. `id, full_name, alias:people_items(*), secrets!fk(value), ...x(y)`
 * gives [{ name: 'id' }, { name: 'full_name' }, { name: 'people_items', embed: true }, { name: 'secrets', embed: true }, ...].
 */
export function parseSelect(s, out = []) {
  let depth = 0, cur = '';
  const items = [];
  for (const c of s) {
    if (c === '(') depth++;
    if (c === ')') depth--;
    if (c === ',' && depth === 0) { items.push(cur); cur = ''; } else cur += c;
  }
  items.push(cur);
  for (let it of items) {
    it = it.trim().replace(/^\.\.\./, '');
    if (!it || it === '*') continue;
    const open = it.indexOf('(');
    const head = (open < 0 ? it : it.slice(0, open)).trim();
    const name = head.replace(/^[A-Za-z_][\w]*\s*:\s*/, '').replace(/^"|"$/g, '').split(/[!:\s-]/)[0].replace(/"/g, '');
    if (!/^[A-Za-z_][\w$]*$/.test(name)) continue;
    if (open >= 0 && it.endsWith(')')) {
      out.push({ name, embed: true });
      parseSelect(it.slice(open + 1, -1), out);
    } else out.push({ name, embed: false });
  }
  return out;
}

/** Binding path for `name` inside a binding name (identifier or destructuring pattern), or null. */
function bindingIn(b, name, pathSoFar = []) {
  if (!b) return null;
  if (ts.isIdentifier(b)) return b.text === name ? pathSoFar : null;
  if (ts.isObjectBindingPattern(b)) {
    for (const el of b.elements) {
      const key = el.propertyName ? propName(el.propertyName) : (ts.isIdentifier(el.name) ? el.name.text : null);
      const r = bindingIn(el.name, name, [...pathSoFar, key]);
      if (r) return r;
    }
  }
  if (ts.isArrayBindingPattern(b)) {
    for (let i = 0; i < b.elements.length; i++) {
      const el = b.elements[i];
      if (ts.isBindingElement(el)) { const r = bindingIn(el.name, name, [...pathSoFar, i]); if (r) return r; }
    }
  }
  return null;
}

/**
 * Declaration that an identifier refers to, by walking lexical scopes outwards.
 * Returns { kind: 'var'|'param'|'fn'|'class'|'enum'|'import'|'forof', ... } or null.
 */
function findDecl(id) {
  const name = id.text;
  for (let n = id.parent; n; n = n.parent) {
    if (ts.isFunctionLike(n)) {
      if (n.parameters) for (let i = 0; i < n.parameters.length; i++) {
        const p = n.parameters[i];
        const b = bindingIn(p.name, name);
        if (b) return { kind: 'param', param: p, index: i, fn: n, path: b };
      }
      if (ts.isFunctionExpression(n) && n.name && n.name.text === name) return { kind: 'fn', node: n };
    }
    if (ts.isCatchClause(n) && n.variableDeclaration && bindingIn(n.variableDeclaration.name, name)) return { kind: 'catch' };
    if ((ts.isForOfStatement(n) || ts.isForInStatement(n) || ts.isForStatement(n)) && n.initializer && ts.isVariableDeclarationList(n.initializer)) {
      for (const d of n.initializer.declarations) {
        const b = bindingIn(d.name, name);
        if (b) return ts.isForOfStatement(n) ? { kind: 'forof', loop: n, path: b } : { kind: 'loop' };
      }
    }
    if (ts.isClassLike(n) && n.name && n.name.text === name) return { kind: 'class', node: n };
    if (ts.isBlock(n) || ts.isSourceFile(n) || ts.isModuleBlock(n) || ts.isCaseClause(n) || ts.isDefaultClause(n)) {
      for (const s of n.statements) {
        if (ts.isVariableStatement(s)) {
          for (const d of s.declarationList.declarations) {
            const b = bindingIn(d.name, name);
            if (b) return { kind: 'var', decl: d, path: b, isConst: !!(s.declarationList.flags & ts.NodeFlags.Const), scope: n };
          }
        } else if ((ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s) || ts.isEnumDeclaration(s)) && s.name && s.name.text === name) {
          return { kind: ts.isFunctionDeclaration(s) ? 'fn' : ts.isClassDeclaration(s) ? 'class' : 'enum', node: s };
        } else if (ts.isImportDeclaration(s) && s.importClause && isStr(s.moduleSpecifier)) {
          const ic = s.importClause;
          const mod = s.moduleSpecifier.text;
          if (ic.name && ic.name.text === name) return { kind: 'import', module: mod, imported: 'default' };
          const nb = ic.namedBindings;
          if (nb && ts.isNamespaceImport(nb) && nb.name.text === name) return { kind: 'import', module: mod, imported: '*' };
          if (nb && ts.isNamedImports(nb)) for (const el of nb.elements) if (el.name.text === name) return { kind: 'import', module: mod, imported: el.propertyName ? propName(el.propertyName) : el.name.text };
        }
      }
    }
  }
  return null;
}

/** Initializer value at a binding path inside an expression (object literal properties, array elements). */
function atPath(init, p) {
  let e = unwrap(init);
  for (const k of p) {
    if (!e) return null;
    if (ts.isObjectLiteralExpression(e)) {
      const prop = e.properties.find((x) => (ts.isPropertyAssignment(x) || ts.isShorthandPropertyAssignment(x)) && propName(x.name) === String(k));
      if (!prop) return null;
      e = unwrap(ts.isPropertyAssignment(prop) ? prop.initializer : prop.name);
    } else if (ts.isArrayLiteralExpression(e) && typeof k === 'number') e = unwrap(e.elements[k]);
    else return null;
  }
  return e;
}


/** Parse one file (TS/JS/JSX, or the script parts of .vue/.svelte/.astro). */
function parse(text, file) {
  const sfc = /\.(vue|svelte|astro)$/.test(file);
  if (sfc) text = extractScripts(text, file);
  const kind = /\.(tsx|jsx)$/.test(file) ? ts.ScriptKind.TSX : /\.(js|mjs|cjs)$/.test(file) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
  return { sf: ts.createSourceFile(sfc ? file + '.ts' : file, text, ts.ScriptTarget.Latest, true, kind), text };
}

/**
 * Per-file analysis: value resolution, receiver kinds, wrappers. `project.lookup(file, module, name)`
 * resolves imported names through the first-pass summaries (or returns null).
 */
function analyzer(sf, file, configWrappers, project) {
  const lineOf = (n) => sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
  const lookup = (d) => (project && d && d.kind === 'import' ? project.lookup(file, d.module, d.imported) : null);
  const isMswFile = sf.statements.some((s) => ts.isImportDeclaration(s) && isStr(s.moduleSpecifier) && /^msw(\/|$)/.test(s.moduleSpecifier.text));

  // ---------------- values ----------------
  /** Possible string values: { vals, conf } | { pattern, conf } | null. */
  function str(e, d = 0) {
    e = unwrap(e);
    if (!e || d > 12) return null;
    if (isStr(e)) return { vals: [e.text], conf: 'extracted' };
    if (ts.isConditionalExpression(e) || (ts.isBinaryExpression(e) && [ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken].includes(e.operatorToken.kind))) {
      const [a, b] = ts.isConditionalExpression(e) ? [e.whenTrue, e.whenFalse] : [e.left, e.right];
      const l = str(a, d + 1), r = str(b, d + 1);
      if (l && r && l.vals && r.vals) return { vals: [...new Set([...l.vals, ...r.vals])], conf: 'ambiguous' };
      return null;
    }
    if ((ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.PlusToken) || ts.isTemplateExpression(e)) {
      const parts = ts.isTemplateExpression(e)
        ? [{ vals: [e.head.text], conf: 'extracted' }, ...e.templateSpans.flatMap((sp) => [str(sp.expression, d + 1), { vals: [sp.literal.text], conf: 'extracted' }])]
        : [str(e.left, d + 1), str(e.right, d + 1)];
      return concat(parts);
    }
    if (ts.isIdentifier(e)) return identStr(e, d);
    if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) {
      const key = ts.isPropertyAccessExpression(e) ? e.name.text : (isStr(unwrap(e.argumentExpression)) ? unwrap(e.argumentExpression).text : null);
      if (key == null) return null;
      const obj = objectOf(e.expression, d + 1);
      if (obj && obj[key]) return { vals: obj[key], conf: 'inferred' };
      return null;
    }
    return null;
  }
  /** Concatenate parts; unknown parts become a pattern. */
  function concat(parts) {
    let vals = [''];
    let conf = 'extracted';
    for (const p of parts) {
      const pv = !p ? [UNKNOWN] : p.vals || p.texts || [UNKNOWN];
      if (p && p.conf !== 'extracted') conf = p.conf === 'ambiguous' || conf === 'ambiguous' ? 'ambiguous' : 'inferred';
      if (pv.length > 1) conf = 'ambiguous';
      const next = [];
      for (const v of vals) for (const x of pv) if (next.length < MAX_VALUES) next.push(v + x);
      vals = next;
    }
    vals = [...new Set(vals)];
    if (!vals.some((v) => v.includes(UNKNOWN))) return { vals, conf };
    return { pattern: vals.map((v) => '^' + v.split(UNKNOWN).map(escRe).join('.*') + '$').join('|'), texts: vals, conf: 'ambiguous' };
  }
  function identStr(id, d) {
    const decl = findDecl(id);
    if (!decl) return null;
    if (decl.kind === 'var') {
      const init = decl.decl.initializer;
      if (decl.isConst) {
        const v = decl.path.length ? atPath(init, decl.path) : init;
        if (!v) return null;
        const r = str(v, d + 1);
        return r && r.vals ? { vals: r.vals, conf: r.vals.length > 1 ? 'ambiguous' : (r.conf === 'extracted' ? 'inferred' : r.conf) } : r;
      }
      // let/var: the initializer plus every plain assignment in scope, if all are literal
      if (decl.path.length) return null;
      const all = [];
      if (init) all.push(init);
      let bad = false;
      (function walk(n) {
        if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(n.left) && n.left.text === id.text) {
          const dd = findDecl(n.left);
          if (dd && dd.decl === decl.decl) all.push(n.right);
        } else if ((ts.isPrefixUnaryExpression(n) || ts.isPostfixUnaryExpression(n)) && ts.isIdentifier(n.operand) && n.operand.text === id.text) bad = true;
        ts.forEachChild(n, walk);
      })(decl.scope);
      if (bad || !all.length) return null;
      const vals = [];
      for (const x of all) { const r = str(x, d + 1); if (!r || !r.vals) return null; vals.push(...r.vals); }
      const u = [...new Set(vals)];
      return { vals: u, conf: u.length > 1 ? 'ambiguous' : 'inferred' };
    }
    if (decl.kind === 'param') {
      if (decl.path.length === 0) {
        const lits = literalUnion(decl.param.type);
        if (lits) return { vals: lits, conf: lits.length > 1 ? 'ambiguous' : 'inferred' };
      }
      // (f) => ... passed to ['a', 'b'].map / forEach / flatMap / filter
      const fn = decl.fn;
      const call = fn.parent && ts.isCallExpression(fn.parent) ? fn.parent : null;
      if (call && decl.index === 0 && decl.path.length === 0 && ts.isPropertyAccessExpression(unwrap(call.expression))
        && /^(map|forEach|flatMap|filter|some|every|find)$/.test(unwrap(call.expression).name.text)) {
        const arr = arrayOf(unwrap(call.expression).expression, d + 1);
        if (arr) return { vals: arr, conf: arr.length > 1 ? 'ambiguous' : 'inferred' };
      }
      return null;
    }
    if (decl.kind === 'forof') {
      if (decl.path.length) return null;
      const arr = arrayOf(decl.loop.expression, d + 1);
      return arr ? { vals: arr, conf: arr.length > 1 ? 'ambiguous' : 'inferred' } : null;
    }
    if (decl.kind === 'import') {
      const x = lookup(decl);
      if (x && x.type === 'str') return { vals: x.vals, conf: 'inferred' };
    }
    return null;
  }
  /** Array of string values: literal arrays, const arrays, imported arrays. */
  function arrayOf(e, d = 0) {
    e = unwrap(e);
    if (!e || d > 12) return null;
    if (ts.isArrayLiteralExpression(e)) {
      const out = [];
      for (const el of e.elements) { const r = str(el, d + 1); if (!r || !r.vals) return null; out.push(...r.vals); }
      return out.length ? [...new Set(out)] : null;
    }
    if (ts.isIdentifier(e)) {
      const decl = findDecl(e);
      if (decl && decl.kind === 'var' && decl.isConst && !decl.path.length) return arrayOf(decl.decl.initializer, d + 1);
      if (decl && decl.kind === 'import') { const x = lookup(decl); if (x && x.type === 'arr') return x.vals; }
    }
    if (ts.isCallExpression(e) && ts.isPropertyAccessExpression(unwrap(e.expression)) && /^(values|keys)$/.test(unwrap(e.expression).name.text)) {
      const o = objectOf(e.arguments[0], d + 1);
      if (o) return [...new Set(unwrap(e.expression).name.text === 'keys' ? Object.keys(o) : Object.values(o).flat())];
    }
    return null;
  }
  /** Object map of string values: const object literals, enums, imported objects/enums. */
  function objectOf(e, d = 0) {
    e = unwrap(e);
    if (!e || d > 12) return null;
    if (ts.isObjectLiteralExpression(e)) {
      const out = {};
      for (const p of e.properties) {
        if (!ts.isPropertyAssignment(p)) continue;
        const k = propName(p.name);
        const r = k != null ? str(p.initializer, d + 1) : null;
        if (r && r.vals) out[k] = r.vals;
      }
      return out;
    }
    if (ts.isIdentifier(e)) {
      const decl = findDecl(e);
      if (!decl) return null;
      if (decl.kind === 'var' && decl.isConst) return objectOf(decl.path.length ? atPath(decl.decl.initializer, decl.path) : decl.decl.initializer, d + 1);
      if (decl.kind === 'enum') return enumOf(decl.node);
      if (decl.kind === 'import') { const x = lookup(decl); if (x && x.type === 'obj') return x.props; }
    }
    if (ts.isPropertyAccessExpression(e)) {
      const o = objectOf(e.expression, d + 1);
      return o ? null : null;
    }
    return null;
  }
  function enumOf(node) {
    const out = {};
    for (const m of node.members) if (m.initializer && isStr(m.initializer)) out[propName(m.name)] = [m.initializer.text];
    return out;
  }

  // ---------------- receivers ----------------
  /**
   * What an expression is, as far as Supabase goes:
   * { t: 'client'|'rpc'|'functions'|'storage'|'other', schema?, privileged?, strong? } or null (unknown).
   */
  function kind(e, d = 0) {
    e = unwrap(e);
    if (!e || d > 10) return null;
    if (ts.isIdentifier(e)) {
      if (NOT_SUPABASE_NAME.test(e.text)) return { t: 'other' };
      const decl = findDecl(e);
      let k = null;
      if (decl && decl.kind === 'var' && decl.decl.initializer) {
        const base = kind(decl.decl.initializer, d + 1);
        k = decl.path.length ? member(base, decl.path[0]) : base;
        if (!k && decl.path.length === 1) k = member(nameKind(e.text), decl.path[0]);
      } else if (decl && decl.kind === 'import') {
        if (NOT_SUPABASE_MODULE.test(decl.module)) return { t: 'other' };
        const x = lookup(decl);
        if (x && x.type === 'client') k = { t: 'client', strong: true, schema: x.schema, privileged: x.privileged };
      } else if (decl && decl.kind === 'param' && decl.path.length === 1) {
        k = member(nameKind(decl.param.name && ts.isIdentifier(decl.param.name) ? decl.param.name.text : ''), decl.path[0]);
      } else if (decl && decl.kind === 'class') return { t: 'other' };
      if (!k) k = nameKind(e.text);
      if (k && k.t === 'client' && !k.privileged && PRIVILEGED_NAME.test(e.text)) k = { ...k, privileged: true };
      return k;
    }
    if (ts.isCallExpression(e)) {
      const c = unwrap(e.expression);
      const name = ts.isIdentifier(c) ? c.text : ts.isPropertyAccessExpression(c) ? c.name.text : null;
      if (name && CLIENT_FACTORY.test(name)) {
        const text = e.arguments.map((a) => a.getText(sf)).join(' ');
        const opts = e.arguments.find((a) => ts.isObjectLiteralExpression(unwrap(a)));
        const sch = opts ? atPath(opts, ['db', 'schema']) : null;
        const sv = sch ? str(sch) : null;
        return { t: 'client', strong: true, privileged: PRIVILEGED_KEY.test(text) || /admin|service/i.test(name), schema: sv && sv.vals && sv.vals.length === 1 ? sv.vals[0] : (sch ? '*' : undefined) };
      }
      if (ts.isPropertyAccessExpression(c)) {
        const base = kind(c.expression, d + 1);
        if (name === 'schema' && base && base.t === 'client') {
          const sv = e.arguments[0] ? str(e.arguments[0]) : null;
          return { ...base, schema: sv && sv.vals && sv.vals.length === 1 ? sv.vals[0] : '*' };
        }
        if (name === 'bind' && base && base.t === 'rpc') return base;
        if (/^(select|selectDistinct|insert|update|delete|where|innerJoin|leftJoin)$/.test(name) && !(base && base.t === 'client')) return { t: 'other' };
      }
      return null;
    }
    if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) {
      const key = ts.isPropertyAccessExpression(e) ? e.name.text : (isStr(unwrap(e.argumentExpression)) ? unwrap(e.argumentExpression).text : null);
      if (key == null) return null;
      const base = kind(e.expression, d + 1);
      return member(base, key) || (base ? null : nameKind(key));
    }
    if (ts.isNewExpression(e)) return /supabase/i.test(e.expression.getText(sf)) ? { t: 'client', strong: true } : { t: 'other' };
    return null;
  }
  const nameKind = (name) => (NOT_SUPABASE_NAME.test(name) ? { t: 'other' } : SUPABASE_NAME.test(name) ? { t: 'client', strong: true, privileged: PRIVILEGED_NAME.test(name) || undefined } : null);
  function member(k, key) {
    if (!k || k.t !== 'client') return null;
    if (key === 'rpc') return { ...k, t: 'rpc' };
    if (key === 'functions') return { ...k, t: 'functions' };
    if (key === 'storage') return { ...k, t: 'storage' };
    if (key === 'auth' || key === 'realtime') return { t: 'other' };
    return null;
  }

  // ---------------- wrappers ----------------
  /** Wrapper functions: function node -> { kind, index, prop?, extra, name }. */
  const wrappers = new Map();
  /** Config wrappers by name: name -> { kind, index }. */
  const named = new Map();
  for (const k of ['rpc', 'from', 'invoke']) {
    for (const w of (configWrappers && configWrappers[k]) || []) {
      const name = typeof w === 'string' ? w : w && w.name;
      if (!name) continue;
      named.set(name, { kind: k === 'from' ? 'table' : k, index: typeof w === 'object' && Number.isInteger(w.arg) ? w.arg : null, extra: k === 'from' ? { op: 'other', via: name } : { via: name } });
    }
  }
  const fnName = (fn) => {
    if (fn.name && propName(fn.name)) return propName(fn.name);
    if (fn.parent && ts.isVariableDeclaration(fn.parent) && ts.isIdentifier(fn.parent.name)) return fn.parent.name.text;
    if (fn.parent && ts.isPropertyAssignment(fn.parent)) return propName(fn.parent.name);
    return null;
  };
  /** Function node a callee refers to (identifier, obj.method, this.method, new C().method), or a summary wrapper. */
  function calleeTarget(callee) {
    callee = unwrap(callee);
    if (ts.isIdentifier(callee)) {
      const d = findDecl(callee);
      if (!d) return named.has(callee.text) ? { named: named.get(callee.text) } : null;
      if (d.kind === 'fn') return { fn: d.node };
      if (d.kind === 'var' && !d.path.length) {
        const init = unwrap(d.decl.initializer);
        if (init && (ts.isArrowFunction(init) || ts.isFunctionExpression(init))) return { fn: init };
        return named.has(callee.text) ? { named: named.get(callee.text) } : null;
      }
      if (d.kind === 'import') {
        const x = lookup(d);
        if (x && x.type === 'wrapper') return { summary: x, name: callee.text };
        return named.has(callee.text) ? { named: named.get(callee.text) } : null;
      }
      return null;
    }
    if (ts.isPropertyAccessExpression(callee)) {
      const m = callee.name.text;
      const container = containerOf(callee.expression);
      if (container) {
        const meth = methodIn(container, m);
        if (meth) return { fn: meth };
      }
      if (named.has(m) && !['call', 'apply', 'bind'].includes(m)) return { named: named.get(m) };
    }
    return null;
  }
  /** Object literal or class that an expression evaluates to (same file). */
  function containerOf(e) {
    e = unwrap(e);
    if (e.kind === ts.SyntaxKind.ThisKeyword) { for (let p = e.parent; p; p = p.parent) if (ts.isClassLike(p)) return p; return null; }
    if (ts.isObjectLiteralExpression(e)) return e;
    if (ts.isNewExpression(e) && ts.isIdentifier(e.expression)) { const d = findDecl(e.expression); return d && d.kind === 'class' ? d.node : null; }
    if (ts.isIdentifier(e)) {
      const d = findDecl(e);
      if (d && d.kind === 'var' && !d.path.length && d.decl.initializer) return containerOf(d.decl.initializer);
    }
    return null;
  }
  function methodIn(c, m) {
    const members = ts.isObjectLiteralExpression(c) ? c.properties : c.members;
    for (const x of members) {
      if (propName(x.name) !== m) continue;
      if (ts.isMethodDeclaration(x)) return x;
      if ((ts.isPropertyAssignment(x) || ts.isPropertyDeclaration(x)) && x.initializer) {
        const i = unwrap(x.initializer);
        if (ts.isArrowFunction(i) || ts.isFunctionExpression(i)) return i;
      }
    }
    return null;
  }
  /** Argument of a wrapper call site that carries the name. */
  function wrapperArg(call, w) {
    if (w.index == null) {
      // config wrapper without an index: argument 0, or the first string-like argument when 0 is an object
      const a0 = call.arguments[0];
      if (a0 && (ts.isObjectLiteralExpression(unwrap(a0)) || ts.isArrayLiteralExpression(unwrap(a0)))) return call.arguments.find((a) => str(a)) || a0;
      return a0;
    }
    const a = call.arguments[w.index];
    if (a && w.prop != null) return atPath(a, [w.prop]);
    return a;
  }

  // ---------------- classification ----------------
  /** What Supabase call (if any) this call expression is: { kind, arg, extra, weak?, privileged? } or null. */
  function classify(n) {
    const callee = unwrap(n.expression);
    if (ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee)) {
      const name = ts.isPropertyAccessExpression(callee) ? callee.name.text : (isStr(unwrap(callee.argumentExpression)) ? unwrap(callee.argumentExpression).text : null);
      const recv = unwrap(callee.expression);
      if (!name) return null;
      if (name === 'rpc') {
        if (!n.arguments[0]) return null;
        const k = kind(recv);
        if (k && k.t === 'other') return null;
        return withClient({ kind: 'rpc', arg: n.arguments[0], extra: {} }, k);
      }
      if ((name === 'call' || name === 'apply') && n.arguments[1]) {
        const k = kind(recv);
        if (k && k.t === 'rpc') {
          const arg = name === 'call' ? n.arguments[1] : atPath(n.arguments[1], [0]);
          return arg ? withClient({ kind: 'rpc', arg, extra: { via: `rpc.${name}` } }, k) : null;
        }
      }
      if (name === 'invoke' && n.arguments[0]) {
        const k = kind(recv);
        if (k && k.t === 'functions') return withClient({ kind: 'invoke', arg: n.arguments[0], extra: { via: 'functions.invoke' } }, k);
        if (ts.isPropertyAccessExpression(recv) && recv.name.text === 'functions' && !(k && k.t === 'other')) return { kind: 'invoke', arg: n.arguments[0], extra: { via: 'functions.invoke' } };
      }
      if (name === 'from' && n.arguments[0]) {
        if (ts.isIdentifier(recv) && /^[A-Z]/.test(recv.text) && !SUPABASE_NAME.test(recv.text)) return null; // Array.from, Buffer.from
        const nm = nextMethod(n);
        const k = kind(recv);
        if (k && k.t === 'storage') return withClient({ kind: 'bucket', arg: n.arguments[0], extra: nm && STORAGE_OPS.has(nm) ? { op: nm } : {} }, k);
        if (ts.isPropertyAccessExpression(recv) && recv.name.text === 'storage' && !k) return { kind: 'bucket', arg: n.arguments[0], extra: nm && STORAGE_OPS.has(nm) ? { op: nm } : {} };
        if (k && k.t === 'other') return null;
        if (nm && !TABLE_OPS.has(nm) && /^(where|join|innerJoin|leftJoin|orderBy|groupBy|pipe|subscribe)$/.test(nm)) return null;
        const op = nm && TABLE_OPS.has(nm) ? nm : 'other';
        if (k && k.t === 'client') return withClient({ kind: 'table', arg: n.arguments[0], extra: { op } }, k);
        return { kind: 'table', arg: n.arguments[0], extra: { op }, weak: !(nm && TABLE_OPS.has(nm)) };
      }
      if (name === 'on' && n.arguments.length >= 2 && isStr(unwrap(n.arguments[0])) && unwrap(n.arguments[0]).text === 'postgres_changes') {
        const t = atPath(n.arguments[1], ['table']);
        const sch = atPath(n.arguments[1], ['schema']);
        const sv = sch ? str(sch) : null;
        if (t) return { kind: 'table', arg: t, extra: { op: 'realtime', ...(sv && sv.vals && sv.vals.length === 1 ? { schema: sv.vals[0] } : {}) } };
      }
    }
    if (ts.isIdentifier(callee)) {
      const k = kind(callee);
      if (k && k.t === 'rpc' && n.arguments[0]) return withClient({ kind: 'rpc', arg: n.arguments[0], extra: { via: callee.text } }, k);
    }
    const target = calleeTarget(callee);
    if (target) {
      const w = target.fn ? wrappers.get(target.fn) : target.summary ? target.summary : target.named;
      if (w) {
        const arg = wrapperArg(n, w);
        const via = target.fn ? fnName(target.fn) : target.name || (ts.isIdentifier(callee) ? callee.text : callee.getText(sf));
        return arg ? { kind: w.kind, arg, extra: { ...w.extra, via }, ...(w.privileged ? { privileged: true } : {}), ...(w.weak ? { weak: true } : {}) } : null;
      }
    }
    return null;
  }
  function withClient(c, k) {
    if (!k) return { ...c, weak: true };
    if (k.privileged) c.privileged = true;
    if (k.schema) c.extra = { ...c.extra, schema: k.schema };
    if (!k.strong) c.weak = true;
    return c;
  }

  /** If `arg` is a parameter of the enclosing function: { fn, index, prop } (prop for a destructured parameter). */
  function paramOf(arg) {
    const a = unwrap(arg);
    if (!a || !ts.isIdentifier(a)) return null;
    const d = findDecl(a);
    if (!d || d.kind !== 'param' || d.path.length > 1) return null;
    return { fn: d.fn, index: d.index, prop: d.path.length ? d.path[0] : null };
  }

  return { lineOf, str, kind, classify, paramOf, wrappers, fnName, objectOf, arrayOf, isMswFile, findDecl, lookup };
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

/** Infer wrappers to a fixpoint: a function that passes its parameter as the name of a Supabase call. */
function inferWrappers(az, allCalls) {
  for (let changed = true, rounds = 0; changed && rounds < 6; rounds++) {
    changed = false;
    for (const c of allCalls) {
      const k = az.classify(c);
      if (!k || az.str(k.arg)) continue;
      const w = az.paramOf(k.arg);
      if (w && !az.wrappers.has(w.fn)) {
        az.wrappers.set(w.fn, { kind: k.kind, index: w.index, prop: w.prop, extra: { ...k.extra }, privileged: k.privileged, weak: k.weak, name: az.fnName(w.fn) });
        changed = true;
      }
    }
  }
}

/**
 * First pass: what a file exports. { name: { type: 'str'|'arr'|'obj'|'client'|'wrapper', ... } }
 * plus `star` (modules re-exported with `export *`) and `from` (named re-exports).
 */
export function summarize(text, file, configWrappers, project) {
  const { sf } = parse(text, file);
  const az = analyzer(sf, file, configWrappers, project);
  const allCalls = [];
  (function collect(n) { if (ts.isCallExpression(n)) allCalls.push(n); ts.forEachChild(n, collect); })(sf);
  inferWrappers(az, allCalls);
  const out = { exports: {}, star: [], from: {} };
  const exported = (s) => s.modifiers && s.modifiers.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
  const valueOf = (nameNode, init, fnNode) => {
    if (fnNode && az.wrappers.has(fnNode)) { const w = az.wrappers.get(fnNode); return { type: 'wrapper', kind: w.kind, index: w.index, prop: w.prop, extra: w.extra, privileged: w.privileged, weak: w.weak }; }
    if (!init) return null;
    const i = unwrap(init);
    if (i && (ts.isArrowFunction(i) || ts.isFunctionExpression(i)) && az.wrappers.has(i)) return valueOf(null, null, i);
    const k = az.kind(i);
    if (k && k.t === 'client') return { type: 'client', schema: k.schema, privileged: k.privileged };
    const s = az.str(i);
    if (s && s.vals) return { type: 'str', vals: s.vals };
    const a = ts.isArrayLiteralExpression(i) ? az.arrayOf(i) : null;
    if (a) return { type: 'arr', vals: a };
    if (ts.isObjectLiteralExpression(i)) return { type: 'obj', props: az.objectOf(i) };
    return null;
  };
  const local = new Map();
  for (const s of sf.statements) {
    if (ts.isVariableStatement(s)) for (const d of s.declarationList.declarations) {
      if (!ts.isIdentifier(d.name)) continue;
      const v = valueOf(d.name, d.initializer);
      if (v) { local.set(d.name.text, v); if (exported(s)) out.exports[d.name.text] = v; }
    } else if (ts.isFunctionDeclaration(s) && s.name) {
      const v = valueOf(s.name, null, s);
      if (v) { local.set(s.name.text, v); if (exported(s)) out.exports[s.name.text] = v; }
    } else if (ts.isEnumDeclaration(s)) {
      const props = {};
      for (const m of s.members) if (m.initializer && isStr(m.initializer)) props[propName(m.name)] = [m.initializer.text];
      local.set(s.name.text, { type: 'obj', props });
      if (exported(s)) out.exports[s.name.text] = { type: 'obj', props };
    } else if (ts.isExportDeclaration(s)) {
      const mod = s.moduleSpecifier && isStr(s.moduleSpecifier) ? s.moduleSpecifier.text : null;
      if (!s.exportClause && mod) out.star.push(mod);
      else if (s.exportClause && ts.isNamedExports(s.exportClause)) {
        for (const el of s.exportClause.elements) {
          const orig = el.propertyName ? propName(el.propertyName) : el.name.text;
          if (mod) out.from[el.name.text] = { module: mod, name: orig };
          else if (local.has(orig)) out.exports[el.name.text] = local.get(orig);
        }
      }
    } else if (ts.isExportAssignment(s) && !s.isExportEquals) {
      const v = valueOf(null, s.expression, ts.isArrowFunction(unwrap(s.expression)) || ts.isFunctionExpression(unwrap(s.expression)) ? unwrap(s.expression) : null);
      if (v) out.exports.default = v;
    }
  }
  return out;
}


/**
 * Scan one source text.
 * @param {string} text @param {string} file relative path
 * @param {{ rpc: (string|{name: string, arg?: number})[], from: [], invoke: [] }} wrappers
 * @param {{ lookup(file: string, module: string, name: string): object|null }} [project] cross-file summaries
 * @returns {{ calls: CallSite[], unresolved: Unresolved[] }}
 */
export function scanSource(text, file, wrappers = { rpc: [], from: [], invoke: [] }, project = null) {
  const parsed = parse(text, file);
  const sf = parsed.sf;
  text = parsed.text;
  const diags = sf.parseDiagnostics || [];
  const parseErrors = diags.slice(0, 3).map((d) => ({ line: sf.getLineAndCharacterOfPosition(d.start || 0).line + 1, message: ts.flattenDiagnosticMessageText(d.messageText, ' ') }));
  const az = analyzer(sf, file, wrappers, project);
  const { lineOf } = az;
  /** @type {CallSite[]} */ const calls = [];
  /** @type {Unresolved[]} */ const unresolved = [];
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

  const allCalls = [];
  (function collect(n) { if (ts.isCallExpression(n)) allCalls.push(n); ts.forEachChild(n, collect); })(sf);
  inferWrappers(az, allCalls);

  function record(k, node) {
    const { arg, extra = {} } = k;
    let r = arg ? az.str(arg) : null;
    if (!r || r.pattern) { const h = hatchNames(node); if (h) r = { vals: h, conf: 'inferred', hatch: true }; }
    const flags = { ...(k.weak ? { weak: true } : {}), ...(k.privileged ? { privileged: true } : {}) };
    if (!r || r.pattern) {
      if (k.weak) return; // an unknown receiver with a dynamic name: not evidence of anything
      const w = az.paramOf(arg);
      const u = { kind: k.kind, file, line: lineOf(node), expr: short(arg ? arg.getText(sf) : node.getText(sf)) };
      if (w && az.wrappers.has(w.fn)) u.wrapper = az.fnName(w.fn) || '(anonymous)';
      if (r && r.pattern && /[A-Za-z0-9_-]{3}/.test((r.texts || []).join('').replace(new RegExp(UNKNOWN, 'g'), ''))) u.pattern = r.pattern;
      if (extra.schema) u.schema = extra.schema;
      unresolved.push(u);
      return;
    }
    const sch = extra.schema;
    if (sch === '*') unresolved.push({ kind: 'schema', file, line: lineOf(node), expr: short(node.getText(sf)), note: `${k.kind} matched in any exposed schema` });
    const q = sch && sch !== 'public' && sch !== '*' ? `${sch}.` : '';
    for (const name of r.vals) {
      calls.push({ kind: k.kind, name: q + name, file, line: lineOf(node), confidence: r.conf, ...extra, ...(sch === '*' ? { anySchema: true, weak: true } : {}), ...flags, ...(r.hatch ? { via: 'hatch' } : {}) });
    }
  }

  /** `.select('...')` after `.from(t)` / `.rpc(f)` (a few hops back): embedded relations and computed fields. */
  function selectItems(n) {
    const callee = unwrap(n.expression);
    if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== 'select' || !n.arguments[0]) return;
    let base = unwrap(callee.expression);
    for (let hop = 0; hop < 4 && base && ts.isCallExpression(base); hop++) {
      const k = az.classify(base);
      if (k && (k.kind === 'table' || k.kind === 'rpc') && !k.weak) {
        const b = az.str(k.arg);
        const s = az.str(n.arguments[0]);
        if (!s || !s.vals) return;
        const items = parseSelect(s.vals.join(','));
        const baseName = b && b.vals && b.vals.length === 1 ? b.vals[0] : null;
        for (const it of items) {
          calls.push({ kind: 'select', name: it.name, embed: !!it.embed, base: baseName, baseKind: k.kind, file, line: lineOf(n), confidence: 'inferred',
            ...(k.extra && k.extra.schema ? { schema: k.extra.schema } : {}), ...(k.privileged ? { privileged: true } : {}) });
        }
        return;
      }
      const c = unwrap(base.expression);
      base = ts.isPropertyAccessExpression(c) ? unwrap(c.expression) : null;
    }
  }

  /** Top of a string expression (literal, template, or `+` chain) that is not part of a bigger one. */
  const isStringRoot = (n) => {
    const p = n.parent;
    if (p && ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.PlusToken) return false;
    if (p && (ts.isTemplateSpan(p) || ts.isTemplateExpression(p))) return false;
    if (ts.isBinaryExpression(n)) return n.operatorToken.kind === ts.SyntaxKind.PlusToken && hasStringPart(n);
    return isStr(n) || ts.isTemplateExpression(n);
  };
  const hasStringPart = (n) => (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken ? hasStringPart(n.left) || hasStringPart(n.right) : isStr(n) || ts.isTemplateExpression(n));
  /** Literal pieces of a string expression (for the prose check). */
  const literalPieces = (n) => {
    n = unwrap(n);
    if (isStr(n)) return [n.text];
    if (ts.isTemplateExpression(n)) return [n.head.text, ...n.templateSpans.map((s) => s.literal.text)];
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) return [...literalPieces(n.left), ...literalPieces(n.right)];
    return [];
  };

  /** URLs: /functions/v1/<name>, /rest/v1/rpc/<fn>, /rest/v1/<table>, built from literals, consts and concatenation. */
  function urls(n) {
    if (az.isMswFile) return; // mock handlers are not callers
    const pieces = literalPieces(n);
    const joined = pieces.join(UNKNOWN);
    if (!/functions\/v1\/|\/rest\/v1\//.test(joined)) return;
    if (pieces.some((p) => /\s/.test(p))) return; // prose (help text, error messages), not a URL
    const r = az.str(n);
    const texts = r ? (r.vals || r.texts) : [pieces.join(UNKNOWN)];
    const conf = insideFetch(n) ? 'extracted' : 'inferred';
    const line = lineOf(n);
    let hit = false, dyn = false;
    for (const t of texts) {
      for (const m of t.matchAll(FN_URL)) { hit = true; calls.push({ kind: 'invoke', name: m[1], file, line, confidence: conf, via: 'url' }); }
      for (const m of t.matchAll(REST_RPC)) { hit = true; calls.push({ kind: 'rpc', name: m[1], file, line, confidence: conf, via: 'url' }); }
      for (const m of t.matchAll(REST_TABLE)) { hit = true; calls.push({ kind: 'table', name: m[1], file, line, confidence: conf, via: 'url', op: 'rest' }); }
      if (new RegExp(`(?:^|/)functions/v1/${UNKNOWN}`).test(t)) dyn = true;
    }
    if (dyn || (!hit && /functions\/v1\/\u0000/.test(joined))) {
      const pre = texts.map((t) => (new RegExp(`functions/v1/([A-Za-z0-9_-]*)${UNKNOWN}`).exec(t) || [])[1]).find((x) => x);
      unresolved.push({ kind: 'invoke', file, line, expr: short(n.getText(sf)), ...(pre && pre.length >= 3 ? { pattern: `^${escRe(pre)}.*$` } : {}) });
    }
  }

  function visit(n) {
    // `if (false) { ... }`: dead code is not a caller
    if (ts.isIfStatement(n) && (n.expression.kind === ts.SyntaxKind.FalseKeyword || (ts.isNumericLiteral(n.expression) && n.expression.text === '0'))) {
      if (n.elseStatement) visit(n.elseStatement);
      return;
    }
    if (ts.isCallExpression(n)) {
      const k = az.classify(n);
      if (k) record(k, n);
      selectItems(n);
    }
    if (isStringRoot(n)) urls(n);
    ts.forEachChild(n, visit);
  }
  visit(sf);

  // After a syntax error the parser's recovery can swallow calls. Recover literal-name calls from the
  // raw text after the first error, as weak (ambiguous, link-only) call sites.
  if (diags.length) {
    const firstErr = Math.min(...diags.map((x) => x.start || 0));
    const seen = new Set(calls.map((c) => `${c.kind}|${c.name}|${c.line}`));
    const re = /\.(rpc|from|invoke)\s*\(\s*(['"`])([A-Za-z0-9_.-]+)\2/g;
    re.lastIndex = Math.max(0, text.lastIndexOf('\n', firstErr));
    for (let m; (m = re.exec(text));) {
      const kind = m[1] === 'rpc' ? 'rpc' : m[1] === 'invoke' ? 'invoke' : 'table';
      const line = sf.getLineAndCharacterOfPosition(m.index).line + 1;
      if (seen.has(`${kind}|${m[3]}|${line}`)) continue;
      calls.push({ kind, name: m[3], file, line, confidence: 'ambiguous', via: 'syntax-error recovery', weak: true });
    }
  }

  const suppress = [];
  const invalid = [];
  for (const h of hatches) {
    if (h.error) { invalid.push({ file, line: h.line, error: h.error }); continue; }
    if (h.directive !== 'ignore') continue;
    const subjects = [...new Set(calls.filter((c) => c.kind !== 'select' && (c.line === h.line || c.line === h.line + 1)).map((c) => c.name))];
    if (!subjects.length) { invalid.push({ file, line: h.line, error: 'ignore: no Supabase call on this or the next line' }); continue; }
    for (const subject of subjects) suppress.push({ rule: h.rule, subject, reason: h.reason, at: `${file}:${h.line}` });
  }
  return { calls, unresolved, hatches: { suppress, invalid, raw: hatches }, parseErrors, parseErrorCount: diags.length };
}

export const MAX_SOURCE_FILE = 2 * 1024 * 1024;
const EXTS = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro'];

/** Path aliases from tsconfig.json / jsconfig.json compilerOptions.paths, plus common defaults. */
function aliases(root) {
  const out = [['@/', ['', 'src/']], ['~/', ['', 'src/']], ['$lib/', ['src/lib/']]];
  for (const f of ['tsconfig.json', 'jsconfig.json']) {
    let j;
    try { j = JSON.parse(fs.readFileSync(path.join(root, f), 'utf8').replace(/\/\*[\s\S]*?\*\/|(^|[^:"])\/\/[^\n]*/g, '$1').replace(/,(\s*[}\]])/g, '$1')); } catch { continue; }
    const co = (j && j.compilerOptions) || {};
    const base = (co.baseUrl || '.').replace(/^\.\/?/, '').replace(/\/?$/, '/').replace(/^\/$/, '');
    for (const [k, v] of Object.entries(co.paths || {})) {
      if (!k.endsWith('/*') || !Array.isArray(v)) continue;
      out.unshift([k.slice(0, -1), v.filter((x) => typeof x === 'string' && x.endsWith('/*')).map((x) => path.posix.normalize(base + x.slice(0, -1).replace(/^\.\//, '')).replace(/^\.\/?/, ''))]);
    }
  }
  return out;
}

/** Scan a list of files relative to root: first-pass export summaries, then every file. */
export function scanFiles(root, files, wrappers) {
  const calls = [];
  const unresolved = [];
  const failed = [];
  const parseErrors = [];
  const hatches = { suppress: [], invalid: [], byFile: new Map() };
  const add = (to, from) => { for (const x of from) to.push(x); }; // no push(...spread): it overflows the stack on huge files
  const texts = new Map();
  for (const f of files) {
    try {
      const st = fs.statSync(path.join(root, f));
      if (st.size > MAX_SOURCE_FILE) { failed.push({ file: f, error: `file too large (${(st.size / 1024 / 1024).toFixed(1)} MB > ${MAX_SOURCE_FILE / 1024 / 1024} MB size cap); not scanned` }); continue; }
      const text = decodeSource(fs.readFileSync(path.join(root, f)));
      if (text == null) { failed.push({ file: f, error: 'binary or UTF-16 without a byte order mark; not scanned' }); continue; }
      texts.set(f, text);
    } catch (e) { failed.push({ file: f, error: String(e.message) }); }
  }
  // Pass 1: summaries, for imports across files.
  const known = new Set(texts.keys());
  const al = aliases(root);
  const resolveModule = (from, spec) => {
    let bases = [];
    if (spec.startsWith('.')) bases = [path.posix.join(path.posix.dirname(from), spec)];
    else for (const [prefix, targets] of al) if (spec.startsWith(prefix)) for (const t of targets) bases.push(path.posix.normalize(t + spec.slice(prefix.length)));
    for (const b of bases) {
      const noJs = b.replace(/\.(js|jsx|mjs|cjs)$/, '');
      for (const c of [b, ...EXTS.map((e) => noJs + e), ...EXTS.map((e) => `${b}/index${e}`)]) if (known.has(c)) return c;
    }
    return null;
  };
  const summaries = new Map();
  const project = {
    lookup(file, spec, name, depth = 0) {
      if (depth > 6) return null;
      const target = resolveModule(file, spec);
      const s = target && summaries.get(target);
      if (!s) return null;
      if (s.exports[name]) return s.exports[name];
      if (s.from[name]) return project.lookup(target, s.from[name].module, s.from[name].name, depth + 1);
      for (const m of s.star) { const x = project.lookup(target, m, name, depth + 1); if (x) return x; }
      return null;
    },
  };
  // Two summary rounds, so a wrapper of an imported wrapper (or a const of an imported const) resolves.
  for (let round = 0; round < 2; round++) {
    for (const [f, text] of texts) {
      if (!/\b(export|module\.exports)\b/.test(text)) continue;
      try { summaries.set(f, summarize(text, f, wrappers, project)); } catch { /* reported in pass 2 */ }
    }
  }
  for (const [f, text] of texts) {
    try {
      const r = scanSource(text, f, wrappers, project);
      add(calls, r.calls);
      add(unresolved, r.unresolved);
      add(hatches.suppress, r.hatches.suppress);
      add(hatches.invalid, r.hatches.invalid);
      if (r.hatches.raw.length) hatches.byFile.set(f, r.hatches.raw);
      if (r.parseErrorCount) parseErrors.push({ file: f, line: r.parseErrors[0].line, error: `${r.parseErrorCount} syntax error(s), first: ${r.parseErrors[0].message}; calls after the error may be missed` });
    } catch (e) { failed.push({ file: f, error: String(e.message) }); }
  }
  return { calls, unresolved, failed, parseErrors, hatches };
}


export function extractScripts(text, file) {
  const keep = [];
  if (/\.astro$/.test(file)) {
    const fm = /^(\s*---[^\S\n]*\n)([\s\S]*?)\n---[^\S\n]*(\n|$)/.exec(text);
    if (fm) keep.push([fm[1].length, fm[1].length + fm[2].length]);
  }
  const re = /<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi;
  let m;
  while ((m = re.exec(text))) {
    const start = m.index + m[0].indexOf('>') + 1;
    keep.push([start, start + m[1].length]);
  }
  const out = [];
  let pos = 0;
  const blank = (a, b) => out.push(text.slice(a, b).replace(/[^\n]/g, ' '));
  for (const [a, b] of keep.sort((x, y) => x[0] - y[0])) {
    if (a < pos) continue;
    blank(pos, a);
    out.push(text.slice(a, b));
    pos = b;
  }
  blank(pos, text.length);
  return out.join('');
}

/** Decode a source buffer: UTF-8 (BOM stripped), UTF-16 with a BOM; null for binary. */
export function decodeSource(buf) {
  if (buf[0] === 0xff && buf[1] === 0xfe) return buf.subarray(2).toString('utf16le');
  if (buf[0] === 0xfe && buf[1] === 0xff) { const b = Buffer.from(buf.subarray(2, buf.length - (buf.length % 2))); return b.swap16().toString('utf16le'); }
  let text = buf.toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  if (text.includes('\u0000')) return null;
  return text;
}
