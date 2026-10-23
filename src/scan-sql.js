// Parse supabase/migrations/*.sql in order and replay them into a final schema state.
// Regex over a light tokenizer: conservative, and anything it does not understand is reported.
//
// Privileges follow Postgres: default privileges have a global layer and per-schema layers that only
// add to each other (ALTER DEFAULT PRIVILEGES); EXECUTE and table privileges are inherited through
// role membership; GRANT/REVOKE ON ALL FUNCTIONS|PROCEDURES|ROUTINES touch only that kind.
import fs from 'node:fs';
import path from 'node:path';
import { parseHatches } from './hatches.js';
import { isInside } from './safe.js';

const IDENT = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][\w$]*)`;
const QNAME = String.raw`(${IDENT}(?:\s*\.\s*${IDENT})?)`;
const FN_URL = /\/functions\/v1\/([A-Za-z0-9_-]+)/g;
/** Files the Supabase CLI applies as migrations (pkg/migration/file.go). */
export const MIGRATION_FILE = /^([0-9]+)_(.*)\.sql$/;
export const MAX_STATEMENT = 256 * 1024;
export const MAX_MIGRATION_FILE = 2 * 1024 * 1024;

/** Normalise a possibly-qualified identifier: unquote, lowercase unquoted parts, drop `public.`. */
export function normName(s) {
  const parts = s.split(/\s*\.\s*(?=(?:[^"]*"[^"]*")*[^"]*$)/).map((p) => (p.startsWith('"') ? p.slice(1, -1).replace(/""/g, '"') : p.toLowerCase()));
  if (parts.length === 2 && parts[0] === 'public') return parts[1];
  return parts.join('.');
}
/** Schema of a normalised name. */
const schemaOfName = (n) => (n.includes('.') ? n.slice(0, n.indexOf('.')) : 'public');
const qualify = (schema, name) => (schema === 'public' ? name : `${schema}.${name}`);
const bare = (n) => (n.includes('.') ? n.slice(n.indexOf('.') + 1) : n);

/**
 * Split SQL into statements, removing comments. Each statement has
 * `text` (dollar bodies intact), `outer` (dollar bodies replaced by $BODY$), `bodies`, `line`.
 * Linear time; `BEGIN ATOMIC ... END` (SQL-standard function bodies) stays one statement.
 */
const isWordCode = (c) => (c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57) || c === 95 || c === 36;
const isWordAt = (s, i) => i >= 0 && i < s.length && isWordCode(s.charCodeAt(i));

export function splitStatements(sql) {
  const out = [];
  const n = sql.length;
  let i = 0, line = 1, startLine = 1, has = false, atomic = 0, run = -1;
  let text = [], outer = [], bodies = [];
  const both = (s) => { text.push(s); outer.push(s); };
  const endRun = (end) => { if (run >= 0 && end > run) both(sql.slice(run, end)); run = -1; };
  const mark = () => { if (!has) { has = true; startLine = line; } };
  const flush = () => {
    const t = text.join('').trim();
    if (t) out.push({ text: t, outer: outer.join('').trim(), bodies, line: startLine });
    text = []; outer = []; bodies = []; has = false; atomic = 0;
  };
  const lines = (s) => { for (let k = s.indexOf('\n'); k >= 0; k = s.indexOf('\n', k + 1)) line++; };
  while (i < n) {
    const c = sql[i];
    if (c === '-' && sql[i + 1] === '-') { endRun(i); const e = sql.indexOf('\n', i); i = e < 0 ? n : e; continue; }
    if (c === '/' && sql[i + 1] === '*') {
      endRun(i);
      let depth = 1; i += 2;
      while (i < n && depth) {
        if (sql[i] === '/' && sql[i + 1] === '*') { depth++; i += 2; } else if (sql[i] === '*' && sql[i + 1] === '/') { depth--; i += 2; } else { if (sql[i] === '\n') line++; i++; }
      }
      both(' '); continue;
    }
    if (c === "'" || c === '"') {
      endRun(i); mark();
      const escBackslash = c === "'" && /[eE]/.test(sql[i - 1] || '') && !/\w/.test(sql[i - 2] || '');
      let j = i + 1;
      while (j < n) {
        if (escBackslash && sql[j] === '\\') { j += 2; continue; }
        if (sql[j] === c) { if (sql[j + 1] === c) { j += 2; continue; } break; }
        j++;
      }
      const s = sql.slice(i, j + 1);
      lines(s); both(s); i = j + 1; continue;
    }
    if (c === '$' && !isWordAt(sql, i - 1)) {
      const m = /^\$([A-Za-z_][\w]*)?\$/.exec(sql.slice(i, i + 64));
      if (m) {
        endRun(i); mark();
        const tag = m[0];
        const end = sql.indexOf(tag, i + tag.length);
        const stop = end < 0 ? n : end + tag.length;
        const s = sql.slice(i, stop);
        lines(s);
        bodies.push(sql.slice(i + tag.length, end < 0 ? n : end));
        text.push(s); outer.push(' $BODY$ '); i = stop; continue;
      }
    }
    if (c === ';' && !atomic) { endRun(i); flush(); i++; continue; }
    const cc = sql.charCodeAt(i);
    if (((cc >= 97 && cc <= 122) || (cc >= 65 && cc <= 90) || cc === 95) && !isWordAt(sql, i - 1)) {
      mark();
      let j = i + 1;
      while (j < n && isWordCode(sql.charCodeAt(j))) j++;
      const w = j - i <= 6 ? sql.slice(i, j).toLowerCase() : '';
      if (w === 'begin' && /^\s+atomic\b/i.test(sql.slice(j, j + 40))) atomic++;
      else if (atomic && w === 'case') atomic++;
      else if (atomic && w === 'end') atomic--;
      if (run < 0) run = i;
      i = j; continue;
    }
    if (c === '\n') line++;
    else if (!has && c !== ' ' && c !== '\t' && c !== '\r') mark();
    if (run < 0) run = i;
    i++;
  }
  endRun(n);
  flush();
  return out;
}

/** Index of the paren matching the one at `open`, skipping quotes. */
function matchParen(s, open) {
  let d = 0;
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (c === "'" || c === '"') { const j = s.indexOf(c, i + 1); if (j < 0) return -1; i = j; continue; }
    if (c === '(') d++;
    else if (c === ')') { d--; if (d === 0) return i; }
  }
  return -1;
}

/** Split on commas at paren depth 0. */
function splitTop(s) {
  const out = []; let d = 0, cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "'" || c === '"') { const j = s.indexOf(c, i + 1); cur += s.slice(i, j + 1); i = j < 0 ? s.length : j; continue; }
    if (c === '(') d++; else if (c === ')') d--;
    if (c === ',' && d === 0) { out.push(cur.trim()); cur = ''; } else cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** Parse SQL function-call style args: string literals, dollar strings, or raw expressions. */
function parseCallArgs(s, open) {
  const close = matchParenDollar(s, open);
  if (close < 0) return null;
  const inner = s.slice(open + 1, close);
  const args = []; let i = 0, cur = '', d = 0;
  while (i < inner.length) {
    const c = inner[i];
    if (c === "'") {
      let j = i + 1; while (j < inner.length) { if (inner[j] === "'") { if (inner[j + 1] === "'") { j += 2; continue; } break; } j++; }
      cur += inner.slice(i, j + 1); i = j + 1; continue;
    }
    const m = c === '$' ? /^\$([A-Za-z_]\w*)?\$/.exec(inner.slice(i, i + 64)) : null;
    if (m) { const e = inner.indexOf(m[0], i + m[0].length); const stop = e < 0 ? inner.length : e + m[0].length; cur += inner.slice(i, stop); i = stop; continue; }
    if (c === '(') d++; else if (c === ')') d--;
    if (c === ',' && d === 0) { args.push(cur.trim()); cur = ''; i++; continue; }
    cur += c; i++;
  }
  if (cur.trim()) args.push(cur.trim());
  return args.map((a) => {
    const named = /^\w+\s*:?=>\s*/.exec(a);
    if (named) a = a.slice(named[0].length);
    const sq = /^'((?:[^']|'')*)'$/s.exec(a);
    if (sq) return { lit: sq[1].replace(/''/g, "'"), raw: a };
    const dq = /^\$([A-Za-z_]\w*)?\$([\s\S]*)\$\1\$$/.exec(a);
    if (dq) return { lit: dq[2], raw: a };
    return { lit: null, raw: a };
  });
}
function matchParenDollar(s, open) {
  let d = 0;
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (c === "'") { let j = i + 1; while (j < s.length) { if (s[j] === "'") { if (s[j + 1] === "'") { j += 2; continue; } break; } j++; } i = j; continue; }
    if (c === '$') { const m = /^\$([A-Za-z_]\w*)?\$/.exec(s.slice(i, i + 64)); if (m) { const e = s.indexOf(m[0], i + m[0].length); if (e < 0) return -1; i = e + m[0].length - 1; continue; } }
    if (c === '(') d++; else if (c === ')') { d--; if (d === 0) return i; }
  }
  return -1;
}


/** Role list of a GRANT/REVOKE/policy: lowercased unless quoted. */
function parseRoles(s) {
  return s.replace(/\bwith\s+(grant|admin|inherit|set)\s+(option|true|false)\b/gi, '').replace(/\bgranted\s+by\s+\S+/i, '').replace(/\b(cascade|restrict)\b/gi, '')
    .split(',').map((r) => r.trim().replace(/^group\s+/i, '')).filter(Boolean)
    .map((r) => (r.startsWith('"') ? r.slice(1, -1) : r.toLowerCase()));
}

/** Roles whose privileges `role` has: itself, PUBLIC, and every role it is (transitively) a member of. */
export function roleClosure(members, role) {
  const out = new Set([role, 'public']);
  const stack = [role];
  while (stack.length) for (const g of (members && members.get(stack.pop())) || []) if (!out.has(g)) { out.add(g); stack.push(g); }
  return out;
}
/** Can `role` execute with these grants (role -> bool), given role membership? */
export const canExec = (grants, role, members) => [...roleClosure(members, role)].some((r) => grants[r]);
/** Table privileges (role -> Set) `role` holds, given membership. */
export function tablePrivs(grants, role, members) {
  const out = new Set();
  for (const r of roleClosure(members, role)) for (const p of (grants && grants[r]) || []) out.add(p);
  return [...out].sort();
}

const TYPE_ALIAS = { int: 'integer', int4: 'integer', int8: 'bigint', int2: 'smallint', bool: 'boolean', varchar: 'character varying', float8: 'double precision', float4: 'real', timestamptz: 'timestamp with time zone', 'timestamp without time zone': 'timestamp', timetz: 'time with time zone', decimal: 'numeric', char: 'character' };
const MULTI_WORD_TYPE = /^(double\s+precision|character\s+varying|character\b|timestamp\b|time\b|bit\s+varying|interval\b)/;

/** Identity signature of an argument list: normalised types, OUT args and names/defaults removed. */
export function sigOf(args) {
  if (!args || !args.trim()) return '';
  return splitTop(args).map((a) => {
    let x = a.replace(/\s+default\s[\s\S]*$/i, '').replace(/\s*=[\s\S]*$/, '').trim().toLowerCase().replace(/"/g, '').replace(/\s+/g, ' ');
    const mode = /^(in|out|inout|variadic) /.exec(x);
    if (mode) { if (mode[1] === 'out') return null; x = x.slice(mode[0].length); }
    if (x.includes(' ') && !MULTI_WORD_TYPE.test(x)) x = x.slice(x.indexOf(' ') + 1);
    x = x.replace(/^public\./, '').replace(/\s*\([^)]*\)/g, '').trim();
    const arr = /(\[\])+$/.exec(x);
    const base = arr ? x.slice(0, arr.index).trim() : x;
    return (TYPE_ALIAS[base] || base) + (arr ? arr[0] : '');
  }).filter((x) => x !== null).join(',');
}

/** Function refs like `a(int), public.b, "c"(text)` -> [{ name, sig|null }]. */
function fnRefs(s) {
  return splitTop(s).map((p) => {
    const m = new RegExp('^' + QNAME + String.raw`\s*(\(([\s\S]*)\))?`).exec(p.trim());
    return m ? { name: normName(m[1]), sig: m[2] ? sigOf(m[3]) : null } : null;
  }).filter(Boolean);
}

/** Overloads of f addressed by an optional `(args)` string; falls back to the only overload. */
function pickOverloads(f, argsParen, st, loc, o, quiet) {
  if (!argsParen) return [...f.sigs.values()];
  const sig = sigOf(argsParen.trim().slice(1, -1));
  if (f.sigs.has(sig)) return [f.sigs.get(sig)];
  if (f.sigs.size === 1) return [...f.sigs.values()];
  st.unparsed.push({ ...loc, reason: `signature ${f.name}(${sig}) matched no known overload; applied to all`, text: short(o) });
  return [...f.sigs.values()];
}


/** Summary of a function across its overloads. */
export function fnSummary(f) {
  const ovs = [...f.sigs.values()];
  const last = ovs.reduce((a, b) => (b.file > a.file || (b.file === a.file && b.line > a.line) ? b : a));
  const can = (role) => ovs.some((ov) => canExec(ov.grants, role, f.members));
  return {
    name: f.name, overloads: ovs.length, args: last.args, returns: last.returns, kind: last.kind,
    securityDefiner: ovs.some((ov) => ov.securityDefiner), anon: can('anon'), authenticated: can('authenticated'),
    body: ovs.map((ov) => ov.body).join('\n'), file: last.file, line: last.line,
    triggerOnly: ovs.every((ov) => /^(setof\s+)?(trigger|event_trigger)$/.test(ov.returns)),
  };
}

/** Names out of a function list like `a(int), public.b, "c"(text)`. */
function fnList(s) {
  return splitTop(s).map((p) => {
    const m = new RegExp('^' + QNAME).exec(p.trim());
    return m ? normName(m[1]) : null;
  }).filter(Boolean);
}


const TABLE_PRIVS = ['select', 'insert', 'update', 'delete'];
const CLIENT_ROLES = ['anon', 'authenticated', 'service_role'];

/** Grant model: 'legacy' (Supabase per-schema grants in public), 'opt-in' (2026 default: none), or false (vanilla Postgres). */
export function grantModel(v) {
  if (v === false || v === 'false' || v === 'vanilla') return false;
  if (v === 'opt-in') return 'opt-in';
  return 'legacy';
}

/**
 * Default privileges. `global` applies in every schema; `schema[s]` only in s. At creation the
 * object gets the union of both (Postgres: per-schema defaults only add to the global ones).
 * PUBLIC's EXECUTE on functions is a global default; Supabase's grants to anon/authenticated/
 * service_role are per-schema in `public` (legacy model).
 */
function defaultLayers(model) {
  const layer = () => ({ functions: {}, tables: {} });
  const global = layer();
  global.functions.public = true;
  const schema = new Map();
  if (model === 'legacy') {
    const pub = layer();
    for (const r of CLIENT_ROLES) { pub.functions[r] = true; pub.tables[r] = new Set(TABLE_PRIVS); }
    schema.set('public', pub);
  }
  return { global, schema };
}
const layerFor = (st, schema) => {
  if (schema == null) return st.defaults.global;
  if (!st.defaults.schema.has(schema)) st.defaults.schema.set(schema, { functions: {}, tables: {} });
  return st.defaults.schema.get(schema);
};
function newFnGrants(st, schema) {
  const g = {};
  for (const l of [st.defaults.global, st.defaults.schema.get(schema)]) if (l) for (const [r, v] of Object.entries(l.functions)) if (v) g[r] = true;
  return g;
}
function newTableGrants(st, schema) {
  const g = {};
  for (const l of [st.defaults.global, st.defaults.schema.get(schema)]) if (l) for (const [r, v] of Object.entries(l.tables)) for (const p of v) (g[r] ||= new Set()).add(p);
  return g;
}

/**
 * @typedef {{ name: string, args: string, returns: string, securityDefiner: boolean, kind: 'function'|'procedure',
 *   grants: Record<string, boolean>, body: string, file: string, line: number }} SqlFunction
 */

export function createState(opts = {}) {
  const model = grantModel(opts.supabaseDefaultGrants);
  const members = new Map();
  return {
    model, members,
    tables: new Map(), views: new Map(), functions: new Map(), triggers: new Map(), cron: new Map(), dynamic: [],
    hatches: { suppress: [], invalid: [] },
    defaults: defaultLayers(model),
    dynamicApplied: [], rlsUncertain: null,
    unparsed: [], skipped: [], stats: { files: 0, statements: 0, handled: 0, ignored: 0, doBlocks: 0 },
  };
}
const fnEntry = (st, name) => {
  let f = st.functions.get(name);
  if (!f) { f = { name, sigs: new Map(), members: st.members }; st.functions.set(name, f); }
  return f;
};
const newTable = (st, name, loc, extra = {}) => ({ name, rls: false, policies: new Map(), text: '', indexText: '', grants: newTableGrants(st, schemaOfName(name)), ...loc, ...extra });

const IGNORE_RE = /^(create\s+(schema|extension|type|domain|sequence|collation|publication|server|foreign\s+data|cast|aggregate|operator|text\s+search)|alter\s+(type|sequence|schema|extension|publication|database|role|domain|index|default\s+privileges\s+.*\bon\s+(sequences|types|schemas))|drop\s+(index|type|schema|extension|sequence|domain)|comment\s+on|insert\s|update\s|delete\s|with\s|select\s|set\s|reset\s|begin|commit|rollback|start\s+transaction|notify|analyze|vacuum|truncate|refresh\s+materialized|lock\s|reindex|cluster|grant\s+(?!.*\b(execute|all)\b).*\bon\s+(schema|sequence|all\s+sequences|database|type|domain|language|foreign)|revoke\s+(?!.*\b(execute|all)\b).*\bon\s+(schema|sequence|all\s+sequences|database|type|domain|language|foreign)|grant\s+(usage|references|trigger|truncate)\b|revoke\s+(usage|references|trigger|truncate)\b|security\s+label|create\s+role|alter\s+role|drop\s+role|call\s)/i;

/** Apply one statement to the state. */
export function applyStatement(st, s, file) {
  st.stats.statements++;
  const o = s.outer.replace(/\s+/g, ' ').trim();
  const loc = { file, line: s.line };
  let m;

  // cron.schedule / cron.unschedule anywhere in a top-level statement or DO block
  if (/\bcron\s*\.\s*(schedule|schedule_in_database|unschedule)\s*\(/i.test(s.text) && !/^create\s/i.test(o)) {
    handleCron(st, s.text, loc);
    st.stats.handled++;
    return;
  }

  if ((m = /^do\b/i.exec(o))) {
    st.stats.doBlocks++;
    for (const body of s.bodies) doBlock(st, body, loc, file);
    return;
  }

  // CREATE TABLE
  if ((m = new RegExp(String.raw`^create\s+(?:(?:global\s+|local\s+)?(temp|temporary)\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?` + QNAME, 'i').exec(o))) {
    if (m[1]) return void st.stats.ignored++;
    const name = normName(m[2]);
    const partition = /\bpartition\s+of\b/i.test(o.slice(m[0].length, m[0].length + 200));
    if (!st.tables.has(name)) st.tables.set(name, newTable(st, name, loc, { text: s.text, partition }));
    else st.tables.get(name).text += '\n' + s.text;
    return void st.stats.handled++;
  }
  // CREATE VIEW
  if ((m = new RegExp(String.raw`^create\s+(or\s+replace\s+)?(?:temp(?:orary)?\s+)?(?:recursive\s+)?(materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?` + QNAME, 'i').exec(o))) {
    const name = normName(m[3]);
    const prev = st.views.get(name);
    st.views.set(name, { name, materialized: !!m[2], securityInvoker: /security_invoker\s*=?\s*(true|on|1|'true'|'on')/i.test(o), text: s.text, grants: prev ? prev.grants : newTableGrants(st, schemaOfName(name)), ...loc });
    return void st.stats.handled++;
  }
  // ALTER VIEW
  if ((m = new RegExp(String.raw`^alter\s+(materialized\s+)?view\s+(?:if\s+exists\s+)?` + QNAME + String.raw`\s+(.*)$`, 'i').exec(o))) {
    const name = normName(m[2]);
    const rest = m[3];
    const v = st.views.get(name);
    let r;
    if ((r = new RegExp(String.raw`^rename\s+to\s+` + QNAME, 'i').exec(rest))) {
      if (v) { st.views.delete(name); v.name = qualify(schemaOfName(name), bare(normName(r[1]))); st.views.set(v.name, v); }
    } else if ((r = new RegExp(String.raw`^set\s+schema\s+(${IDENT})`, 'i').exec(rest))) {
      if (v) { st.views.delete(name); v.name = qualify(normName(r[1]), bare(name)); st.views.set(v.name, v); }
    } else if (/security_invoker/i.test(rest) && v) {
      v.securityInvoker = /^set\b/i.test(rest) && /security_invoker\s*=?\s*(true|on|1|'true'|'on')/i.test(rest);
    }
    return void st.stats.handled++;
  }
  // ALTER TABLE
  if ((m = new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?` + QNAME + String.raw`\s+(.*)$`, 'i').exec(o))) {
    const name = normName(m[1]);
    const rest = m[2];
    let t = st.tables.get(name);
    let r;
    if ((r = new RegExp(String.raw`^rename\s+to\s+` + QNAME, 'i').exec(rest))) {
      if (t) { st.tables.delete(name); t.name = qualify(schemaOfName(name), bare(normName(r[1]))); st.tables.set(t.name, t); }
      else st.unparsed.push({ ...loc, reason: `rename of unknown table ${name}`, text: short(o) });
      return void st.stats.handled++;
    }
    if ((r = new RegExp(String.raw`^set\s+schema\s+(${IDENT})`, 'i').exec(rest))) {
      if (t) { st.tables.delete(name); t.name = qualify(normName(r[1]), bare(name)); st.tables.set(t.name, t); }
      return void st.stats.handled++;
    }
    if (!t && /row\s+level\s+security/i.test(rest)) {
      // table created outside migrations (or a view/partition); still track RLS state
      t = newTable(st, name, loc, { external: true });
      st.tables.set(name, t);
    }
    if (t) {
      if (/\benable\s+row\s+level\s+security\b/i.test(rest)) t.rls = true;
      if (/\bdisable\s+row\s+level\s+security\b/i.test(rest)) t.rls = false;
      t.text += '\n' + s.text;
    }
    return void st.stats.handled++;
  }
  // DROP TABLE / VIEW
  if ((m = /^drop\s+(table|view|materialized\s+view|foreign\s+table)\s+(?:if\s+exists\s+)?(.*?)(\s+(cascade|restrict))?$/i.exec(o))) {
    const map = /table/i.test(m[1]) ? st.tables : st.views;
    for (const n of fnList(m[2])) {
      map.delete(n);
      if (map === st.tables) for (const k of [...st.triggers.keys()]) if (st.triggers.get(k).table === n) st.triggers.delete(k);
    }
    return void st.stats.handled++;
  }
  // CREATE INDEX: functions used in index expressions are used.
  if ((m = new RegExp(String.raw`^create\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:(?:if\s+not\s+exists\s+)?${IDENT}\s+)?on\s+(?:only\s+)?` + QNAME, 'i').exec(o))) {
    const t = st.tables.get(normName(m[1]));
    if (t) t.indexText += '\n' + s.text;
    return void st.stats.handled++;
  }
  // CREATE FUNCTION / PROCEDURE (overloads tracked by argument-type signature)
  if ((m = new RegExp(String.raw`^create\s+(or\s+replace\s+)?(function|procedure)\s+` + QNAME + String.raw`\s*\(`, 'i').exec(o))) {
    const name = normName(m[3]);
    const open = m.index + m[0].length - 1;
    const close = matchParen(o, open);
    const args = close > 0 ? o.slice(open + 1, close).trim() : '';
    const after = close > 0 ? o.slice(close + 1) : o;
    const ret = /^\s*returns\s+(setof\s+)?(table\s*\(|[\w."]+(?:\s*\[\])?)/i.exec(after);
    const returns = ret ? (ret[1] || '').toLowerCase() + ret[2].replace(/\s*\($/, '').replace(/"/g, '').toLowerCase() : (m[2].toLowerCase() === 'procedure' ? 'void' : '?');
    const sig = sigOf(args);
    const f = fnEntry(st, name);
    const prev = f.sigs.get(sig);
    f.sigs.set(sig, {
      sig, args, returns, kind: m[2].toLowerCase(),
      securityDefiner: /\bsecurity\s+definer\b/i.test(after),
      grants: prev ? prev.grants : newFnGrants(st, schemaOfName(name)),
      body: s.bodies.length ? s.bodies.join('\n') : after,
      ...loc,
    });
    return void st.stats.handled++;
  }
  // ALTER FUNCTION
  if ((m = new RegExp(String.raw`^alter\s+(function|procedure|routine)\s+` + QNAME + String.raw`\s*(\((?:[^()]|\([^()]*\))*\))?\s*(.*)$`, 'i').exec(o))) {
    const name = normName(m[2]);
    const rest = m[4];
    const f = st.functions.get(name);
    let r;
    if (!f) { st.unparsed.push({ ...loc, reason: `alter of unknown function ${name}`, text: short(o) }); return void st.stats.handled++; }
    const ovs = pickOverloads(f, m[3], st, loc, o);
    const move = (to) => {
      const g = fnEntry(st, to);
      for (const ov of ovs) { f.sigs.delete(ov.sig); g.sigs.set(ov.sig, ov); }
      if (!f.sigs.size) st.functions.delete(name);
    };
    if ((r = new RegExp(String.raw`^rename\s+to\s+(${IDENT})`, 'i').exec(rest))) move(qualify(schemaOfName(name), normName(r[1])));
    else if ((r = new RegExp(String.raw`^set\s+schema\s+(${IDENT})`, 'i').exec(rest))) move(qualify(normName(r[1]), bare(name)));
    else if (/\bsecurity\s+definer\b/i.test(rest)) ovs.forEach((ov) => { ov.securityDefiner = true; });
    else if (/\bsecurity\s+invoker\b/i.test(rest)) ovs.forEach((ov) => { ov.securityDefiner = false; });
    return void st.stats.handled++;
  }
  // DROP FUNCTION
  if ((m = /^drop\s+(function|procedure|routine)\s+(?:if\s+exists\s+)?(.*?)(\s+(cascade|restrict))?$/i.exec(o))) {
    for (const ref of fnRefs(m[2])) {
      const f = st.functions.get(ref.name);
      if (!f) continue;
      if (ref.sig === null) st.functions.delete(ref.name);
      else {
        if (f.sigs.has(ref.sig)) f.sigs.delete(ref.sig);
        else if (f.sigs.size === 1) f.sigs.clear();
        else st.unparsed.push({ ...loc, reason: `drop of ${ref.name}(${ref.sig}) matched no known overload`, text: short(o) });
        if (!f.sigs.size) st.functions.delete(ref.name);
      }
    }
    return void st.stats.handled++;
  }
  // CREATE POLICY
  if ((m = new RegExp(String.raw`^create\s+policy\s+(${IDENT})\s+on\s+` + QNAME + String.raw`(.*)$`, 'i').exec(o))) {
    const pname = m[1].replace(/^"|"$/g, '');
    const table = normName(m[2]);
    const head = policyHead(m[3]);
    const cmd = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(head) || [, 'all'])[1].toLowerCase();
    const to = /\bto\s+(.+?)\s*$/i.exec(head);
    const roles = to ? parseRoles(to[1]) : ['public'];
    let t = st.tables.get(table);
    if (!t) {
      if (st.views.has(table)) return void st.stats.handled++;
      t = newTable(st, table, loc, { external: true });
      st.tables.set(table, t);
    }
    t.policies.set(pname, { name: pname, command: cmd, roles, restrictive: /\bas\s+restrictive\b/i.test(head), text: s.text, ...loc });
    return void st.stats.handled++;
  }
  if ((m = new RegExp(String.raw`^alter\s+policy\s+(${IDENT})\s+on\s+` + QNAME + String.raw`\s*(.*)$`, 'i').exec(o))) {
    const t = st.tables.get(normName(m[2]));
    const pname = m[1].replace(/^"|"$/g, '');
    const p = t && t.policies.get(pname);
    let r;
    if (!p) st.unparsed.push({ ...loc, reason: `alter of unknown policy ${pname}`, text: short(o) });
    else if ((r = new RegExp(String.raw`^rename\s+to\s+(${IDENT})`, 'i').exec(m[3]))) { t.policies.delete(pname); p.name = r[1].replace(/^"|"$/g, ''); t.policies.set(p.name, p); }
    else {
      const to = /\bto\s+(.+?)\s*$/i.exec(policyHead(m[3]));
      if (to) p.roles = parseRoles(to[1]);
      p.text += '\n' + s.text;
    }
    return void st.stats.handled++;
  }
  if ((m = new RegExp(String.raw`^drop\s+policy\s+(?:if\s+exists\s+)?(${IDENT})\s+on\s+` + QNAME, 'i').exec(o))) {
    const t = st.tables.get(normName(m[2]));
    if (t) t.policies.delete(m[1].replace(/^"|"$/g, ''));
    return void st.stats.handled++;
  }
  // GRANT / REVOKE EXECUTE
  if ((m = /^(grant|revoke)\s+(grant\s+option\s+for\s+)?(.+?)\s+on\s+(all\s+(functions|procedures|routines)\s+in\s+schema\s+(.+?)|(?:function|functions|procedure|procedures|routine|routines)\s+(.+?))\s+(to|from)\s+(.+)$/i.exec(o))) {
    const privs = m[3].toLowerCase();
    if (!/\b(execute|all)\b/.test(privs) || m[2]) return void st.stats.ignored++;
    const isGrant = m[1].toLowerCase() === 'grant';
    const roles = parseRoles(m[9]);
    let targets;
    if (m[5]) {
      const schemas = splitTop(m[6]).map((x) => normName(x.trim()));
      const kind = m[5].toLowerCase();
      // ALL FUNCTIONS excludes procedures, ALL PROCEDURES excludes functions; ALL ROUTINES is both.
      targets = [...st.functions.values()].filter((f) => schemas.includes(schemaOfName(f.name))).flatMap((f) => [...f.sigs.values()])
        .filter((ov) => kind === 'routines' || (kind === 'functions' ? ov.kind === 'function' : ov.kind === 'procedure'));
    } else {
      targets = [];
      for (const ref of fnRefs(m[7])) {
        const f = st.functions.get(ref.name);
        if (!f) { st.unparsed.push({ ...loc, reason: `${m[1].toLowerCase()} on unknown function ${ref.name}`, text: short(o) }); continue; }
        targets.push(...pickOverloads(f, ref.sig === null ? null : '(' + ref.sig + ')', st, loc, o, true));
      }
    }
    for (const ov of targets) for (const r of roles) { if (isGrant) ov.grants[r] = true; else delete ov.grants[r]; }
    return void st.stats.handled++;
  }
  // ALTER DEFAULT PRIVILEGES ... ON FUNCTIONS | ROUTINES | TABLES
  if ((m = /^alter\s+default\s+privileges\b(.*?)\b(grant|revoke)\s+(grant\s+option\s+for\s+)?(.+?)\s+on\s+(functions|routines|tables)\s+(to|from)\s+(.+)$/i.exec(o))) {
    if (m[3]) return void st.stats.handled++;
    // Migrations run as postgres; default privileges for another role do not apply to what they create.
    const forRole = /\bfor\s+(?:role|user)\s+(.+?)(?=\s+in\s+schema\b|$)/i.exec(m[1].trim());
    if (forRole && !parseRoles(forRole[1]).includes('postgres')) return void st.stats.handled++;
    const inSchema = /\bin\s+schema\s+(.+)$/i.exec(m[1].trim());
    const layers = inSchema ? splitTop(inSchema[1]).map((x) => layerFor(st, normName(x.trim()))) : [layerFor(st, null)];
    const grant = m[2].toLowerCase() === 'grant';
    const roles = parseRoles(m[7]);
    if (/^(functions|routines)$/i.test(m[5])) {
      if (/\b(execute|all)\b/i.test(m[4])) for (const l of layers) for (const r of roles) { if (grant) l.functions[r] = true; else delete l.functions[r]; }
    } else {
      const privs = tablePrivList(m[4]);
      for (const l of layers) for (const r of roles) {
        const cur = l.tables[r] || new Set();
        for (const p of privs) grant ? cur.add(p) : cur.delete(p);
        l.tables[r] = cur;
      }
    }
    return void st.stats.handled++;
  }
  // GRANT / REVOKE on tables and views
  if ((m = /^(grant|revoke)\s+(grant\s+option\s+for\s+)?(.+?)\s+on\s+(?:(all\s+tables\s+in\s+schema\s+(.+?))|(?:table\s+)?(?!(?:function|functions|procedure|procedures|routine|routines|schema|sequence|sequences|database|type|domain|language|large\s+object|foreign|tablespace|all)\b)(.+?))\s+(to|from)\s+(.+)$/i.exec(o))) {
    if (m[2]) return void st.stats.handled++;
    const privs = tablePrivList(m[3]);
    const roles = parseRoles(m[8]);
    const grant = m[1].toLowerCase() === 'grant';
    let objs;
    if (m[4]) {
      const schemas = splitTop(m[5]).map((x) => normName(x.trim()));
      objs = [...st.tables.values(), ...st.views.values()].filter((t) => schemas.includes(schemaOfName(t.name)));
    } else objs = fnList(m[6]).map((n) => st.tables.get(n) || st.views.get(n)).filter(Boolean);
    for (const t of objs) for (const r of roles) {
      const cur = t.grants[r] || new Set();
      for (const p of privs) grant ? cur.add(p) : cur.delete(p);
      t.grants[r] = cur;
    }
    return void st.stats.handled++;
  }
  // GRANT role TO role (membership: EXECUTE and table privileges are inherited)
  if ((m = /^(grant|revoke)\s+(admin\s+option\s+for\s+|inherit\s+option\s+for\s+|set\s+option\s+for\s+)?((?:"[^"]+"|[\w$]+)(?:\s*,\s*(?:"[^"]+"|[\w$]+))*)\s+(to|from)\s+(.+)$/i.exec(o)) && !/\bon\b/i.test(m[3])) {
    if (m[2]) return void st.stats.handled++;
    const groups = parseRoles(m[3]);
    for (const r of parseRoles(m[5])) {
      const cur = st.members.get(r) || new Set();
      for (const g of groups) m[1].toLowerCase() === 'grant' ? cur.add(g) : cur.delete(g);
      st.members.set(r, cur);
    }
    return void st.stats.handled++;
  }
  // TRIGGERS
  if ((m = new RegExp(String.raw`^create\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\s+(${IDENT})\s.*?\bon\s+` + QNAME + String.raw`\s.*?\bexecute\s+(?:function|procedure)\s+` + QNAME, 'i').exec(o))) {
    const tname = m[1].replace(/^"|"$/g, '');
    const table = normName(m[2]);
    st.triggers.set(`${table}.${tname}`, { name: tname, table, fn: normName(m[3]), text: s.text, ...loc });
    return void st.stats.handled++;
  }
  if ((m = new RegExp(String.raw`^create\s+event\s+trigger\s+(${IDENT})\s.*?\bexecute\s+(?:function|procedure)\s+` + QNAME, 'i').exec(o))) {
    st.triggers.set(`(event).${m[1]}`, { name: m[1], table: '(event)', fn: normName(m[2]), text: '', ...loc });
    return void st.stats.handled++;
  }
  if ((m = new RegExp(String.raw`^drop\s+trigger\s+(?:if\s+exists\s+)?(${IDENT})\s+on\s+` + QNAME, 'i').exec(o))) {
    st.triggers.delete(`${normName(m[2])}.${m[1].replace(/^"|"$/g, '')}`);
    return void st.stats.handled++;
  }
  if (/^drop\s+event\s+trigger/i.test(o)) return void st.stats.handled++;

  if (IGNORE_RE.test(o)) return void st.stats.ignored++;
  if (/^(create|alter|drop|grant|revoke)\b/i.test(o) || /\b(function|policy|row level security|table|view|trigger|execute)\b/i.test(o)) {
    st.unparsed.push({ ...loc, reason: 'unrecognised statement', text: short(o) });
  } else st.stats.ignored++;
}

/** The part of a CREATE/ALTER POLICY tail before USING / WITH CHECK, with string literals blanked. */
function policyHead(rest) {
  const masked = rest.replace(/'(?:[^']|'')*'/g, "''");
  const cut = masked.search(/\busing\s*\(|\bwith\s+check\s*\(/i);
  return cut < 0 ? masked : masked.slice(0, cut);
}

/** Table privileges named in a GRANT/REVOKE privilege list (column lists ignored). */
function tablePrivList(s) {
  const t = s.replace(/\([^)]*\)/g, '').toLowerCase();
  if (/\ball\b/.test(t)) return TABLE_PRIVS;
  return TABLE_PRIVS.filter((p) => new RegExp(`\\b${p}\\b`).test(t));
}

const short = (s) => s.replace(/\s+/g, ' ').slice(0, 120);
/** Statements whose loss changes who can reach what: grants, revokes, role membership, policies, RLS. */
export const RISKY_RE = /\b(grant|revoke)\b|\bdrop\s+policy\b|\b(create|alter)\s+policy\b|\balter\s+default\s+privileges\b|\brow\s+level\s+security\b/i;

/** Postgres format(): %s, %I, %L, %%, positional %n$. Throws on a missing argument. */
export function sqlFormat(tmpl, args) {
  let k = 0;
  return tmpl.replace(/%(?:(\d+)\$)?([sIL%])/g, (all, pos, t) => {
    if (t === '%') return '%';
    const v = args[pos ? Number(pos) - 1 : k++];
    if (v == null) throw new Error('format() argument missing');
    if (t === 'I') return /^[a-z_][a-z0-9_$]*$/.test(v) ? v : '"' + v.replace(/"/g, '""') + '"';
    if (t === 'L') return "'" + v.replace(/'/g, "''") + "'";
    return v;
  });
}

/** Same text with the contents of '...' literals blanked (same length), so keyword searches skip strings. */
const maskStrings = (t) => t.replace(/'(?:[^']|'')*'/g, (x) => "'" + ' '.repeat(x.length - 2) + "'");

const DDL_RE = /\b(create\s+(or\s+replace\s+)?(policy|function|procedure|table|view|trigger|index)\b|alter\s+default\s+privileges\b|alter\s+(table|function|procedure|routine|policy|view)\b|drop\s+(policy|function|procedure|table|view|trigger)\b|grant\s|revoke\s)/i;

/**
 * A DO block. EXECUTE with literal text, format() with literal arguments, and format() inside a
 * FOREACH/FOR loop over an array literal are expanded and applied. Anything else that builds DDL
 * dynamically is reported (risky when it touches grants, policies or RLS).
 */
function doBlock(st, body, loc, file) {
  const dynamic = /\bexecute\b/i.test(body);
  if (dynamic) st.dynamic.push({ text: body, ...loc });
  const apply = (sql, how) => {
    for (const inner of splitStatements(sql)) {
      st.dynamicApplied.push({ ...loc, text: short(inner.text), how });
      applyStatement(st, { ...inner, line: loc.line }, file);
    }
  };
  const report = (text, why) => {
    const risky = RISKY_RE.test(text);
    st.unparsed.push({ ...loc, reason: why, text: short(text), risky });
    if (/row\s+level\s+security/i.test(text)) {
      const t = new RegExp(String.raw`alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?` + QNAME + String.raw`\s`, 'i').exec(text);
      const name = t && !t[1].includes('%') ? normName(t[1]) : null;
      if (name && st.tables.get(name)) st.tables.get(name).rlsUncertain = `${loc.file}:${loc.line}`;
      else if (!name) st.rlsUncertain = `${loc.file}:${loc.line}`;
    }
  };
  /** Expand one EXECUTE at `idx` (pointing at the word) with variable bindings; returns false if not literal. */
  const expand = (src, idx, bind) => {
    const after = src.slice(idx + 7);
    const fm = /^\s*format\s*\(/i.exec(after);
    if (fm) {
      const args = parseCallArgs(src, idx + 7 + fm[0].length - 1);
      if (!args || !args.length || args[0].lit == null) return null;
      const vals = args.slice(1).map((a) => {
        if (a.lit != null) return a.lit;
        const v = /^(?:quote_ident\s*\(\s*)?([A-Za-z_]\w*)\s*\)?$/i.exec(a.raw);
        return v && bind && bind.has(v[1].toLowerCase()) ? bind.get(v[1].toLowerCase()) : undefined;
      });
      if (vals.some((v) => v === undefined)) return null;
      try { return sqlFormat(args[0].lit, vals); } catch { return null; }
    }
    const lit = /^\s*('(?:[^']|'')*'|\$([A-Za-z_]\w*)?\$[\s\S]*?\$\2\$)\s*(;|$)/.exec(after);
    if (lit) return lit[1].startsWith("'") ? lit[1].slice(1, -1).replace(/''/g, "'") : lit[1].replace(/^\$[^$]*\$|\$[^$]*\$$/g, '');
    return null;
  };
  let rest = body;
  if (dynamic) {
    const loopRe = /\b(?:foreach\s+([A-Za-z_]\w*)\s+in\s+array\s+(?:array\s*)?\[([^\]]*)\](?:\s*::\s*[\w\s]+\[\])?|for\s+([A-Za-z_]\w*)\s+in\s+(?:select\s+)?unnest\s*\(\s*(?:array\s*)?\[([^\]]*)\]\s*(?:::\s*[\w\s]+\[\])?\s*\))\s+loop\b([\s\S]*?)\bend\s+loop\b/gi;
    rest = body.replace(loopRe, (all, v1, list1, v2, list2, loopBody) => {
      const v = (v1 || v2).toLowerCase();
      const items = splitTop(list1 || list2).map((x) => /^'((?:[^']|'')*)'(?:\s*::\s*\w+)?$/.exec(x.trim()));
      const literal = items.length && items.every(Boolean);
      for (const ex of maskStrings(loopBody).matchAll(/\bexecute\b/gi)) {
        if (!literal) { report(loopBody, 'dynamic SQL (EXECUTE) in a loop over a non-literal list'); break; }
        const outs = items.map((it) => expand(loopBody, ex.index, new Map([[v, it[1].replace(/''/g, "'")]])));
        if (outs.some((x) => x == null)) report(loopBody.slice(ex.index, ex.index + 200), 'dynamic SQL (EXECUTE) with non-literal arguments');
        else for (const sql of outs) apply(sql, `EXECUTE in a loop over ${items.length} literal value(s)`);
      }
      return all.replace(/[^\n]/g, ' ');
    });
  }
  for (const inner of splitStatements(rest)) {
    const t = inner.outer.replace(/\s+/g, ' ');
    const ex = /\bexecute\b/i.exec(maskStrings(inner.text));
    if (ex && !/^\s*(create|alter)\s/i.test(t)) {
      const sql = expand(inner.text, ex.index, null);
      if (sql != null) { apply(sql, 'EXECUTE with literal arguments'); continue; }
      if (/\b(create|grant|revoke|alter|drop|policy|security)\b/i.test(inner.text)) report(inner.text, 'dynamic SQL (EXECUTE) in DO block');
      continue;
    }
    const k = DDL_RE.exec(t);
    if (k) {
      const off = inner.outer.search(new RegExp(k[0].replace(/\s+/g, '\\s+'), 'i'));
      applyStatement(st, { ...inner, text: inner.text, outer: inner.outer.slice(off), line: loc.line + inner.line - 1 }, file);
    } else if (/\bcron\s*\.\s*(schedule|unschedule)/i.test(inner.text)) handleCron(st, inner.text, loc);
  }
}

function handleCron(st, text, loc) {
  const re = /\bcron\s*\.\s*(schedule_in_database|schedule|unschedule)\s*\(/gi;
  let m;
  while ((m = re.exec(text))) {
    const args = parseCallArgs(text, m.index + m[0].length - 1);
    if (!args) { st.unparsed.push({ ...loc, reason: 'cron call with unbalanced parens', text: short(text) }); continue; }
    const fn = m[1].toLowerCase();
    if (fn === 'unschedule') {
      const a = args[0];
      if (a && a.lit != null) st.cron.delete(a.lit);
      else {
        const jn = /jobname\s*=\s*'([^']+)'/i.exec(text);
        if (jn) st.cron.delete(jn[1]);
        else st.unparsed.push({ ...loc, reason: 'cron.unschedule by job id', text: short(text) });
      }
      continue;
    }
    let name, schedule, command;
    if (args.length >= 3) [name, schedule, command] = args;
    else [schedule, command] = args;
    if (!command || command.lit == null) { st.unparsed.push({ ...loc, reason: 'cron.schedule with non-literal command', text: short(text) }); continue; }
    const jobName = name ? (name.lit != null ? name.lit : name.raw) : `(unnamed ${loc.file}:${loc.line})`;
    st.cron.set(jobName, { name: jobName, schedule: schedule && schedule.lit, command: command.lit, ...loc });
  }
}


const SUBJECT_RE = new RegExp(String.raw`^(?:create\s+(?:or\s+replace\s+)?(?:function|procedure|(?:materialized\s+)?view|table(?:\s+if\s+not\s+exists)?)|alter\s+(?:function|procedure|table|view))\s+` + QNAME, 'i');

/** `-- supareach: ignore <rule> <reason>` applies to the object the next statement creates or alters. */
export function sqlHatches(st, hatches, stmts, file) {
  for (const h of hatches) {
    if (h.error) { st.hatches.invalid.push({ file, line: h.line, error: h.error }); continue; }
    if (h.directive !== 'ignore') { st.hatches.invalid.push({ file, line: h.line, error: `${h.directive}: not valid in SQL (use ignore)` }); continue; }
    const next = stmts.find((s) => s.line > h.line);
    const m = next && SUBJECT_RE.exec(next.outer.replace(/\s+/g, ' ').trim());
    if (!m) { st.hatches.invalid.push({ file, line: h.line, error: 'ignore: the next statement does not create or alter a function, table or view' }); continue; }
    st.hatches.suppress.push({ rule: h.rule, subject: normName(m[1]), reason: h.reason, at: `${file}:${h.line}` });
  }
}


/** Parse migrations in a directory in version order, as the Supabase CLI does (only `<version>_<name>.sql`). */
export function scanMigrations(dir, opts = {}) {
  const st = createState(opts);
  if (!fs.existsSync(dir)) return st;
  const relDir = (opts.relDir || path.basename(dir)).replace(/\/+$/, '');
  const all = fs.readdirSync(dir).filter((f) => f.toLowerCase().endsWith('.sql'));
  const files = [];
  for (const f of all) {
    if (MIGRATION_FILE.test(f)) files.push(f);
    else st.skipped.push({ file: `${relDir}/${f}`, reason: 'not applied by the Supabase CLI (name must be <timestamp>_name.sql)' });
  }
  const ver = (f) => BigInt(MIGRATION_FILE.exec(f)[1]);
  files.sort((a, b) => { const x = ver(a), y = ver(b); return x < y ? -1 : x > y ? 1 : a < b ? -1 : a > b ? 1 : 0; });
  for (const f of files) {
    const rel = `${relDir}/${f}`;
    const full = path.join(dir, f);
    if (opts.root && !isInside(opts.root, full)) { st.skipped.push({ file: rel, reason: 'symbolic link to a file outside the project' }); continue; }
    let size = 0;
    try { size = fs.statSync(full).size; } catch { /* unreadable: reported below */ }
    if (size > MAX_MIGRATION_FILE) { st.skipped.push({ file: rel, reason: `larger than ${MAX_MIGRATION_FILE / 1024 / 1024} MB; not replayed`, risky: true }); continue; }
    st.stats.files++;
    const sql = fs.readFileSync(full, 'utf8');
    const stmts = splitStatements(sql);
    for (const s of stmts) {
      if (s.text.length > MAX_STATEMENT) { st.unparsed.push({ file: rel, line: s.line, reason: `statement larger than ${MAX_STATEMENT / 1024} KB; skipped`, text: short(s.text.slice(0, 200)), risky: RISKY_RE.test(s.text.slice(0, 4096)) }); continue; }
      const before = st.unparsed.length;
      try { applyStatement(st, s, rel); } catch (e) { st.unparsed.push({ file: rel, line: s.line, reason: 'parser error: ' + e.message, text: short(s.outer) }); }
      for (let i = before; i < st.unparsed.length; i++) if (st.unparsed[i].risky === undefined) st.unparsed[i].risky = RISKY_RE.test(s.text);
    }
    sqlHatches(st, parseHatches(sql), stmts, rel);
  }
  return st;
}

const STATEMENT_START = /^\s*(select|perform|insert|update|delete|with|call|create|alter|drop|grant|revoke|do)\b/i;
const isIdStart = (c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c === '_';
const isId = (c) => isIdStart(c) || (c >= '0' && c <= '9') || c === '$';

/** Read an identifier at i: [name (case-normalised), end, quoted]. */
function readIdent(t, i) {
  if (t[i] === '"') {
    let j = i + 1, out = '';
    while (j < t.length) { if (t[j] === '"') { if (t[j + 1] === '"') { out += '"'; j += 2; continue; } break; } out += t[j++]; }
    return [out, j + 1, true];
  }
  let j = i + 1;
  while (j < t.length && isId(t[j])) j++;
  return [t.slice(i, j).toLowerCase(), j, false];
}
const skipWs = (t, i) => { while (i < t.length && (t[i] === ' ' || t[i] === '\n' || t[i] === '\t' || t[i] === '\r')) i++; return i; };

/**
 * Calls `cb(schema|null, name)` for every `name(` / `schema.name(` in t, in linear time. A name right
 * after FUNCTION/PROCEDURE/ROUTINE is DDL about the function (ALTER/DROP/GRANT/COMMENT ON FUNCTION f()),
 * not a call, unless the keyword follows EXECUTE (a trigger's EXECUTE FUNCTION f()).
 */
function scanCalls(t, cb) {
  let i = 0, p1 = '', p2 = '';
  const n = t.length;
  while (i < n) {
    const c = t[i];
    if (c === "'") { const e = t.indexOf("'", i + 1); i = e < 0 ? n : e + 1; p2 = p1; p1 = "'"; continue; }
    if (isIdStart(c) || c === '"') {
      let [a, j, qa] = readIdent(t, i);
      let schema = null, name = a, k = skipWs(t, j);
      if (t[k] === '.') {
        const k2 = skipWs(t, k + 1);
        if (isIdStart(t[k2] || '') || t[k2] === '"') { const [b, j2] = readIdent(t, k2); schema = a; name = b; j = j2; k = skipWs(t, j2); }
      }
      if (t[k] === '(' && !(/^(function|procedure|routine|functions)$/.test(p1) && p2 !== 'execute')) cb(schema, name, qa);
      p2 = p1; p1 = schema ? '' : (qa ? '' : a);
      i = j; continue;
    }
    if (c !== ' ' && c !== '\n' && c !== '\t' && c !== '\r') { p2 = p1; p1 = c; }
    i++;
  }
}

/**
 * Function names (normalised, as in `fnNames`) and edge-function URLs referenced in a chunk of SQL.
 * `schema.f()` resolves only to that schema; an unqualified `f()` resolves to public (and to
 * `ownSchema` for code inside a function of another schema). Quoted names keep their case.
 * Names inside string literals count only when the string is itself a statement run by EXECUTE.
 */
export function sqlRefs(text, fnNames, ownSchema = 'public') {
  const fns = new Set();
  const edges = new Set();
  text = text.replace(/--[^\n]*/g, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ');
  for (const u of text.matchAll(FN_URL)) edges.add(u[1]);
  const hit = (schema, name) => {
    const keys = schema ? [qualify(schema, name)] : [name, ...(ownSchema && ownSchema !== 'public' ? [`${ownSchema}.${name}`] : [])];
    for (const k of keys) if (fnNames.has(k)) fns.add(k);
  };
  scanCalls(text, hit);
  if (/\bexecute\b/i.test(text)) {
    for (const s of text.matchAll(/'((?:[^']|'')*)'/g)) {
      const inner = s[1].replace(/''/g, "'");
      if (STATEMENT_START.test(inner)) scanCalls(inner, hit);
    }
  }
  return { fns, edges };
}
