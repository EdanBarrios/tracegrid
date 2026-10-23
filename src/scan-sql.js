// Parse supabase/migrations/*.sql in order and replay them into a final schema state.
// Regex over a light tokenizer: conservative, and anything it does not understand is reported.
import fs from 'node:fs';
import path from 'node:path';

const IDENT = String.raw`(?:"[^"]+"|[A-Za-z_][\w$]*)`;
const QNAME = String.raw`(${IDENT}(?:\s*\.\s*${IDENT})?)`;
const FN_URL = /\/functions\/v1\/([A-Za-z0-9_-]+)/g;

/** Normalise a possibly-qualified identifier: unquote, lowercase, drop `public.`. */
export function normName(s) {
  const parts = s.split(/\s*\.\s*(?=(?:[^"]*"[^"]*")*[^"]*$)/).map((p) => (p.startsWith('"') ? p.slice(1, -1) : p.toLowerCase()));
  if (parts.length === 2 && parts[0] === 'public') return parts[1];
  return parts.join('.');
}

/**
 * Split SQL into statements, removing comments. Each statement has
 * `text` (dollar bodies intact), `outer` (dollar bodies replaced by $BODY$), `bodies`, `line`.
 */
export function splitStatements(sql) {
  const out = [];
  let i = 0, line = 1, startLine = 1;
  let text = '', outer = '', bodies = [];
  const n = sql.length;
  const flush = () => {
    if (text.trim()) out.push({ text: text.trim(), outer: outer.trim(), bodies, line: startLine });
    text = ''; outer = ''; bodies = [];
  };
  while (i < n) {
    const c = sql[i];
    if (!text.trim()) startLine = line;
    if (c === '-' && sql[i + 1] === '-') { while (i < n && sql[i] !== '\n') i++; continue; }
    if (c === '/' && sql[i + 1] === '*') {
      let depth = 1; i += 2;
      while (i < n && depth) {
        if (sql[i] === '/' && sql[i + 1] === '*') { depth++; i += 2; } else if (sql[i] === '*' && sql[i + 1] === '/') { depth--; i += 2; } else { if (sql[i] === '\n') line++; i++; }
      }
      text += ' '; outer += ' '; continue;
    }
    if (c === "'" || c === '"') {
      const escBackslash = c === "'" && /[eE]$/.test(text) && !/\w[eE]$/.test(text);
      let j = i + 1;
      while (j < n) {
        if (escBackslash && sql[j] === '\\') { j += 2; continue; }
        if (sql[j] === c) { if (sql[j + 1] === c) { j += 2; continue; } break; }
        j++;
      }
      const s = sql.slice(i, j + 1);
      line += (s.match(/\n/g) || []).length;
      text += s; outer += s; i = j + 1; continue;
    }
    if (c === '$') {
      const m = /^\$([A-Za-z_][\w]*)?\$/.exec(sql.slice(i, i + 64));
      if (m && !/[\w$]$/.test(text)) {
        const tag = m[0];
        const end = sql.indexOf(tag, i + tag.length);
        const stop = end < 0 ? n : end + tag.length;
        const s = sql.slice(i, stop);
        line += (s.match(/\n/g) || []).length;
        bodies.push(sql.slice(i + tag.length, end < 0 ? n : end));
        text += s; outer += ' $BODY$ '; i = stop; continue;
      }
    }
    if (c === ';') { flush(); i++; continue; }
    if (c === '\n') line++;
    text += c; outer += c; i++;
  }
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

const ROLES = ['public', 'anon', 'authenticated'];
function parseRoles(s) {
  return s.replace(/\bwith\s+grant\s+option\b/i, '').replace(/\bgranted\s+by\s+\S+/i, '').replace(/\b(cascade|restrict)\b/gi, '')
    .split(',').map((r) => r.trim().replace(/^group\s+/i, '').replace(/"/g, '').toLowerCase()).filter(Boolean);
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
  const can = (role) => ovs.some((ov) => !!(ov.grants[role] || ov.grants.public));
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

/**
 * @typedef {{ name: string, args: string, returns: string, securityDefiner: boolean, kind: 'function'|'procedure',
 *   grants: Record<string, boolean>, body: string, file: string, line: number }} SqlFunction
 */

export function createState(opts = {}) {
  const sb = opts.supabaseDefaultGrants !== false;
  return {
    tables: new Map(), views: new Map(), functions: new Map(), triggers: new Map(), cron: new Map(), dynamic: [],
    defaults: { public: true, anon: sb, authenticated: sb },
    unparsed: [], stats: { files: 0, statements: 0, handled: 0, ignored: 0, doBlocks: 0 },
  };
}

const IGNORE_RE = /^(create\s+(unique\s+)?index|create\s+(schema|extension|type|domain|sequence|collation|publication|server|foreign|cast|aggregate|operator)|alter\s+(type|sequence|schema|extension|publication|database|role|domain|index|default\s+privileges\s+.*\bon\s+(tables|sequences|types))|drop\s+(index|type|schema|extension|sequence|domain)|comment\s+on|insert\s|update\s|delete\s|with\s|select\s|set\s|reset\s|begin|commit|rollback|start\s+transaction|notify|analyze|vacuum|truncate|refresh\s+materialized|lock\s|grant\s+(?!.*\b(execute|all)\b).*\bon\s+(table|schema|sequence|all\s+(tables|sequences))|revoke\s+(?!.*\b(execute|all)\b).*\bon\s+(table|schema|sequence|all\s+(tables|sequences))|grant\s+(usage|select|insert|update|delete|references|trigger|truncate)\b|revoke\s+(usage|select|insert|update|delete|references|trigger|truncate)\b|grant\s+[\w"]+\s+to\s|security\s+label|create\s+role|alter\s+role|call\s)/i;

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
    for (const body of s.bodies) {
      if (/\bexecute\b/i.test(body)) {
        st.dynamic.push({ text: body, ...loc });
        if (dynamicGrantLoop(st, body, loc)) continue;
      }
      for (const inner of splitStatements(body)) {
        const t = inner.outer.replace(/\s+/g, ' ');
        const k = /\b(create\s+(or\s+replace\s+)?(policy|function|procedure|table|view|trigger)\b|alter\s+default\s+privileges\b|alter\s+(table|function|policy|view)\b|drop\s+(policy|function|table|view|trigger)\b|grant\s|revoke\s)/i.exec(t);
        if (k && (/\bexecute\b/i.test(t.slice(0, k.index)) || /%[IsL]|\$\d|\|\|/.test(t.slice(k.index)))) {
          st.unparsed.push({ ...loc, line: s.line + inner.line - 1, reason: 'dynamic SQL (EXECUTE) in DO block', text: short(inner.text) });
        } else if (k) {
          const off = inner.outer.search(new RegExp(k[0].replace(/\s+/g, '\\s+'), 'i'));
          applyStatement(st, { ...inner, text: inner.text, outer: inner.outer.slice(off), line: s.line + inner.line - 1 }, file);
        } else if (/\bexecute\b/i.test(t) && /\b(create|grant|revoke|alter|drop)\b/i.test(inner.text)) {
          st.unparsed.push({ ...loc, reason: 'dynamic SQL (EXECUTE) in DO block', text: short(inner.text) });
        } else if (/\bcron\s*\.\s*(schedule|unschedule)/i.test(inner.text)) {
          handleCron(st, inner.text, loc);
        }
      }
    }
    return;
  }

  // CREATE TABLE
  if ((m = new RegExp(String.raw`^create\s+(?:(?:global\s+|local\s+)?(temp|temporary)\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?` + QNAME, 'i').exec(o))) {
    if (m[1]) return void st.stats.ignored++;
    const name = normName(m[2]);
    if (!st.tables.has(name)) st.tables.set(name, { name, rls: false, policies: new Map(), text: s.text, ...loc });
    else st.tables.get(name).text += '\n' + s.text;
    return void st.stats.handled++;
  }
  // CREATE VIEW
  if ((m = new RegExp(String.raw`^create\s+(or\s+replace\s+)?(?:temp(?:orary)?\s+)?(?:recursive\s+)?(materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?` + QNAME, 'i').exec(o))) {
    const name = normName(m[3]);
    st.views.set(name, { name, materialized: !!m[2], securityInvoker: /security_invoker\s*=?\s*(true|on|1|'true'|'on')/i.test(o), text: s.text, ...loc });
    return void st.stats.handled++;
  }
  // ALTER VIEW
  if ((m = new RegExp(String.raw`^alter\s+(materialized\s+)?view\s+(?:if\s+exists\s+)?` + QNAME + String.raw`\s+(.*)$`, 'i').exec(o))) {
    const name = normName(m[2]);
    const rest = m[3];
    const v = st.views.get(name);
    let r;
    if ((r = new RegExp(String.raw`^rename\s+to\s+` + QNAME, 'i').exec(rest))) {
      if (v) { st.views.delete(name); v.name = normName(r[1]); st.views.set(v.name, v); }
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
      if (t) { st.tables.delete(name); t.name = normName(r[1]); st.tables.set(t.name, t); }
      else st.unparsed.push({ ...loc, reason: `rename of unknown table ${name}`, text: short(o) });
      return void st.stats.handled++;
    }
    if (!t && /row\s+level\s+security/i.test(rest)) {
      // table created outside migrations (or a view/partition); still track RLS state
      t = { name, rls: false, policies: new Map(), text: '', external: true, ...loc };
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
    let f = st.functions.get(name);
    if (!f) { f = { name, sigs: new Map() }; st.functions.set(name, f); }
    const prev = f.sigs.get(sig);
    f.sigs.set(sig, {
      sig, args, returns, kind: m[2].toLowerCase(),
      securityDefiner: /\bsecurity\s+definer\b/i.test(after),
      grants: prev ? prev.grants : { ...st.defaults },
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
    if ((r = new RegExp(String.raw`^rename\s+to\s+(${IDENT})`, 'i').exec(rest))) {
      const to = normName(r[1]);
      let g = st.functions.get(to);
      if (!g) { g = { name: to, sigs: new Map() }; st.functions.set(to, g); }
      for (const ov of ovs) { f.sigs.delete(ov.sig); g.sigs.set(ov.sig, ov); }
      if (!f.sigs.size) st.functions.delete(name);
    } else if (/\bsecurity\s+definer\b/i.test(rest)) ovs.forEach((ov) => { ov.securityDefiner = true; });
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
    const rest = m[3];
    const cmd = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(rest) || [, 'all'])[1].toLowerCase();
    const to = /\bto\s+(.+?)(?=\s+using\b|\s+with\s+check\b|$)/i.exec(rest);
    const roles = to ? parseRoles(to[1]) : ['public'];
    let t = st.tables.get(table);
    if (!t) {
      if (st.views.has(table)) return void st.stats.handled++;
      t = { name: table, rls: false, policies: new Map(), text: '', external: true, ...loc };
      st.tables.set(table, t);
    }
    t.policies.set(pname, { name: pname, command: cmd, roles, restrictive: /\bas\s+restrictive\b/i.test(rest), text: s.text, ...loc });
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
      const to = /\bto\s+(.+?)(?=\s+using\b|\s+with\s+check\b|$)/i.exec(m[3]);
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
  if ((m = /^(grant|revoke)\s+(grant\s+option\s+for\s+)?(.+?)\s+on\s+(all\s+functions\s+in\s+schema\s+(.+?)|all\s+(?:procedures|routines)\s+in\s+schema\s+(.+?)|(?:function|functions|procedure|routine)\s+(.+?))\s+(to|from)\s+(.+)$/i.exec(o))) {
    const privs = m[3].toLowerCase();
    if (!/\b(execute|all)\b/.test(privs) || m[2]) return void st.stats.ignored++;
    const isGrant = m[1].toLowerCase() === 'grant';
    const roles = parseRoles(m[9]).filter((r) => ROLES.includes(r));
    let targets;
    if (m[5] || m[6]) {
      const schemas = (m[5] || m[6]).split(',').map((x) => normName(x.trim()));
      targets = [...st.functions.values()].filter((f) => schemas.includes(f.name.includes('.') ? f.name.split('.')[0] : 'public')).flatMap((f) => [...f.sigs.values()]);
    } else {
      targets = [];
      for (const ref of fnRefs(m[7])) {
        const f = st.functions.get(ref.name);
        if (!f) { st.unparsed.push({ ...loc, reason: `${m[1].toLowerCase()} on unknown function ${ref.name}`, text: short(o) }); continue; }
        targets.push(...pickOverloads(f, ref.sig === null ? null : '(' + ref.sig + ')', st, loc, o, true));
      }
    }
    for (const ov of targets) for (const r of roles) ov.grants[r] = isGrant;
    return void st.stats.handled++;
  }
  // ALTER DEFAULT PRIVILEGES ... ON FUNCTIONS
  if ((m = /^alter\s+default\s+privileges\b(.*?)\b(grant|revoke)\s+(.+?)\s+on\s+(functions|routines)\s+(to|from)\s+(.+)$/i.exec(o))) {
    if (/\bin\s+schema\b/i.test(m[1]) && !/\bin\s+schema\s+(public|"public")\b/i.test(m[1])) return void st.stats.ignored++;
    // Migrations run as postgres; default privileges for another role do not apply to what they create.
    const forRole = /\bfor\s+(?:role|user)\s+("?[\w]+"?)/i.exec(m[1]);
    if (forRole && forRole[1].replace(/"/g, '').toLowerCase() !== 'postgres') return void st.stats.ignored++;
    if (/\b(execute|all)\b/i.test(m[3])) for (const r of parseRoles(m[6]).filter((x) => ROLES.includes(x))) st.defaults[r] = m[2].toLowerCase() === 'grant';
    return void st.stats.handled++;
  }
  // TRIGGERS
  if ((m = new RegExp(String.raw`^create\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\s+(${IDENT})\s.*?\bon\s+` + QNAME + String.raw`\s.*?\bexecute\s+(?:function|procedure)\s+` + QNAME, 'i').exec(o))) {
    const tname = m[1].replace(/^"|"$/g, '');
    const table = normName(m[2]);
    st.triggers.set(`${table}.${tname}`, { name: tname, table, fn: normName(m[3]), ...loc });
    return void st.stats.handled++;
  }
  if ((m = new RegExp(String.raw`^create\s+event\s+trigger\s+(${IDENT})\s.*?\bexecute\s+(?:function|procedure)\s+` + QNAME, 'i').exec(o))) {
    st.triggers.set(`(event).${m[1]}`, { name: m[1], table: '(event)', fn: normName(m[2]), ...loc });
    return void st.stats.handled++;
  }
  if ((m = new RegExp(String.raw`^drop\s+trigger\s+(?:if\s+exists\s+)?(${IDENT})\s+on\s+` + QNAME, 'i').exec(o))) {
    st.triggers.delete(`${normName(m[2])}.${m[1].replace(/^"|"$/g, '')}`);
    return void st.stats.handled++;
  }
  if (/^drop\s+event\s+trigger/i.test(o)) return void st.stats.handled++;

  if (/^(grant|revoke)\s/i.test(o) && !/\b(function|functions|routine|routines|procedure|procedures)\b/i.test(o)) return void st.stats.ignored++;
  if (IGNORE_RE.test(o)) return void st.stats.ignored++;
  if (/^(create|alter|drop|grant|revoke)\b/i.test(o) || /\b(function|policy|row level security|table|view|trigger|execute)\b/i.test(o)) {
    st.unparsed.push({ ...loc, reason: 'unrecognised statement', text: short(o) });
  } else st.stats.ignored++;
}

const short = (s) => s.replace(/\s+/g, ' ').slice(0, 120);

/**
 * Heuristic for a common pattern: a DO block that loops over a literal list of function names and runs
 * `execute format('revoke execute on function %s from ...', fn)`. Applies the grant/revoke to every
 * known function named in a string literal in the block, and reports that it did.
 */
function dynamicGrantLoop(st, body, loc) {
  const g = /execute\s+format\s*\(\s*'(grant|revoke)\s+(?:execute|all)\s+on\s+(?:function|routine)\s+%[sI]\s+(to|from)\s+([\w\s,"]+?)'/i.exec(body);
  if (!g) return false;
  const roles = parseRoles(g[3]).filter((r) => ROLES.includes(r));
  const names = [...new Set([...body.matchAll(/'([A-Za-z_]\w*)'/g)].map((x) => x[1].toLowerCase()))].filter((n) => st.functions.has(n));
  const isGrant = g[1].toLowerCase() === 'grant';
  for (const n of names) for (const ov of st.functions.get(n).sigs.values()) for (const r of roles) ov.grants[r] = isGrant;
  st.unparsed.push({ ...loc, reason: `dynamic ${g[1].toLowerCase()} loop: applied heuristically to ${names.length} named function(s)`, text: short(names.join(', ')) });
  return true;
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

/** Parse all migrations in a directory in filename order. */
export function scanMigrations(dir, opts = {}) {
  const st = createState(opts);
  if (!fs.existsSync(dir)) return st;
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
  for (const f of files) {
    st.stats.files++;
    const rel = path.join(path.basename(dir), f);
    const sql = fs.readFileSync(path.join(dir, f), 'utf8');
    for (const s of splitStatements(sql)) {
      try { applyStatement(st, s, rel); } catch (e) { st.unparsed.push({ file: rel, line: s.line, reason: 'parser error: ' + e.message, text: short(s.outer) }); }
    }
  }
  return st;
}

/** Function names and edge-function URLs referenced in a chunk of SQL text. */
export function sqlRefs(text, fnNames) {
  const fns = new Set();
  const edges = new Set();
  text = text.replace(/--[^\n]*/g, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ');
  for (const u of text.matchAll(FN_URL)) edges.add(u[1]);
  // Names inside string literals (error messages, hints) are not calls, unless the SQL builds dynamic statements.
  if (!/\bexecute\b/i.test(text)) text = text.replace(/'(?:[^']|'')*'/g, "''");
  const re = /(?:\b[A-Za-z_]\w*\s*\.\s*)?"?([A-Za-z_]\w*)"?\s*\(/g;
  let m;
  while ((m = re.exec(text))) { const n = m[1].toLowerCase(); if (fnNames.has(n)) fns.add(n); }
  return { fns, edges };
}
