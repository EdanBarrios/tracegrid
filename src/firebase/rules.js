// Firebase Security Rules: Firestore and Storage rules files, and Realtime Database JSON rules.
//
// Each `allow` is classified by who can pass its condition, from the condition text alone:
//   public       anyone, signed in or not (`if true`, no condition, an unexpired test-mode date)
//   signed-in    any signed-in user (`request.auth != null` and nothing else)
//   conditional  something else decides (owner checks, field checks, get()/exists() lookups)
//   closed       nobody (`if false`, an expired test-mode date)
// Rule functions are inlined; `||` takes the most permissive side and `&&` the least. Anything not
// recognised is `conditional`, so the classes that produce findings (public, signed-in) only come
// from conditions the classifier fully understands.

export const ACCESS = ['closed', 'conditional', 'signed-in', 'public'];
const RANK = Object.fromEntries(ACCESS.map((c, i) => [c, i]));
export const rankOf = (c) => RANK[c] ?? 0;
export const OPS = ['get', 'list', 'create', 'update', 'delete'];
const OP_GROUPS = { read: ['get', 'list'], write: ['create', 'update', 'delete'] };

/** Replace // and /* *\/ comments with spaces (newlines kept), leaving strings intact. */
export function maskComments(src) {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < src.length && src[j] !== c && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
      out += src.slice(i, j + 1);
      i = j + 1;
    } else if (c === '/' && src[i + 1] === '/') {
      let j = i;
      while (j < src.length && src[j] !== '\n') j++;
      out += ' '.repeat(j - i);
      i = j;
    } else if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      const j = end < 0 ? src.length : end + 2;
      out += src.slice(i, j).replace(/[^\n]/g, ' ');
      i = j;
    } else { out += c; i++; }
  }
  return out;
}

/** 1-based line of each offset. */
export function lineIndex(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1);
  return (off) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= off) lo = mid; else hi = mid - 1; }
    return lo + 1;
  };
}

/** Split `e` on a top-level operator (outside brackets and strings). */
function splitTop(e, op) {
  const parts = [];
  let depth = 0;
  let last = 0;
  for (let k = 0; k < e.length; k++) {
    const c = e[k];
    if (c === '"' || c === "'") { k++; while (k < e.length && e[k] !== c) k += e[k] === '\\' ? 2 : 1; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (depth === 0 && e.startsWith(op, k)) { parts.push(e.slice(last, k)); k += op.length - 1; last = k + 1; }
  }
  parts.push(e.slice(last));
  return parts.map((p) => p.trim());
}

/** Strip parentheses that wrap the whole expression. */
function unwrap(e) {
  e = e.trim();
  while (e.startsWith('(') && e.endsWith(')')) {
    let depth = 0;
    let wraps = true;
    for (let k = 0; k < e.length - 1; k++) {
      if (e[k] === '(') depth++;
      else if (e[k] === ')') depth--;
      if (depth === 0) { wraps = false; break; }
    }
    if (!wraps) break;
    e = e.slice(1, -1).trim();
  }
  return e;
}

const SIGNED_IN = [
  /^(request\.)?auth\s*!==?\s*null$/, /^null\s*!==?\s*(request\.)?auth$/,
  /^(request\.)?auth\.uid\s*!==?\s*null$/, /^null\s*!==?\s*(request\.)?auth\.uid$/,
  /^request\.auth\.uid\s+is\s+string$/,
];
const TEST_MODE = /^request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)$/;

/**
 * Classify a condition: { cls, notes }. `scope` resolves rule function names to { params, lets, ret }.
 * `now` (a Date) decides whether a test-mode expiry has passed.
 */
export function classify(expr, scope = () => null, { now = new Date(), lets = null, depth = 0, stack = [] } = {}) {
  const notes = [];
  const go = (e, l, d, st) => {
    e = unwrap(e);
    if (!e) return 'public';
    if (d > 12) return 'conditional';
    if (splitTop(e, '?').length > 1) return 'conditional';
    const ors = splitTop(e, '||');
    if (ors.length > 1) return ors.map((x) => go(x, l, d, st)).reduce((a, b) => (RANK[b] > RANK[a] ? b : a));
    const ands = splitTop(e, '&&');
    if (ands.length > 1) return ands.map((x) => go(x, l, d, st)).reduce((a, b) => (RANK[b] < RANK[a] ? b : a));
    if (e === 'true') return 'public';
    if (e === 'false') return 'closed';
    if (SIGNED_IN.some((re) => re.test(e))) return 'signed-in';
    const tm = TEST_MODE.exec(e);
    if (tm) {
      const until = new Date(Date.UTC(+tm[1], +tm[2] - 1, +tm[3]));
      const day = until.toISOString().slice(0, 10);
      if (until > now) { notes.push(`test-mode rule: open to everyone until ${day}`); return 'public'; }
      notes.push(`test-mode rule expired on ${day}`);
      return 'closed';
    }
    if (l && /^\w+$/.test(e) && l.has(e)) return go(l.get(e), l, d + 1, st);
    const call = /^(\w+)\s*\(([\s\S]*)\)$/.exec(e);
    if (call) {
      const fn = scope(call[1]);
      // The whole atom must be one call: `f(a) == g(b)` also matches the pattern above.
      if (fn && balancedCall(e) && !st.includes(call[1])) return go(fn.ret, fn.lets, d + 1, [...st, call[1]]);
    }
    return 'conditional';
  };
  const cls = go(expr, lets, depth, stack);
  return { cls, notes: [...new Set(notes)] };
}

/** True when `e` is `name( ... )` with the first `(` closed by the final `)`. */
function balancedCall(e) {
  const open = e.indexOf('(');
  let depth = 0;
  for (let k = open; k < e.length; k++) {
    const c = e[k];
    if (c === '"' || c === "'") { k++; while (k < e.length && e[k] !== c) k += e[k] === '\\' ? 2 : 1; continue; }
    if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) return k === e.length - 1; }
  }
  return false;
}

/**
 * The condition with rule functions inlined (parameters replaced by the call's arguments, `let`
 * bindings by their values), for text checks that need to see what helpers do. Capped in size.
 */
export function expand(expr, scope = () => null, { lets = null, depth = 0, stack = [] } = {}) {
  const MAX = 20000;
  let e = expr;
  if (lets) for (const [k, v] of lets) e = e.replace(new RegExp(String.raw`(?<![\w.$])${k}(?![\w$(])`, 'g'), `(${v})`);
  if (depth > 8) return e.slice(0, MAX);
  let out = '';
  let k = 0;
  const re = /(?<![\w.$])([A-Za-z_]\w*)\s*\(/g;
  let m;
  while ((m = re.exec(e))) {
    const fn = scope(m[1]);
    if (!fn || stack.includes(m[1])) continue;
    const open = m.index + m[0].length - 1;
    let d = 0;
    let close = open;
    for (; close < e.length; close++) { if (e[close] === '(') d++; else if (e[close] === ')' && --d === 0) break; }
    const args = splitTop(e.slice(open + 1, close), ',');
    let body = fn.ret;
    const fl = new Map(fn.lets);
    fn.params.forEach((p, i) => {
      if (args[i] === undefined) return;
      const sub = (x) => x.replace(new RegExp(String.raw`(?<![\w.$])${p}(?![\w$])`, 'g'), `(${args[i]})`);
      body = sub(body);
      for (const [lk, lv] of fl) fl.set(lk, sub(lv));
    });
    out += e.slice(k, m.index) + '(' + expand(body, scope, { lets: fl, depth: depth + 1, stack: [...stack, m[1]] }) + ')';
    k = close + 1;
    re.lastIndex = k;
    if (out.length > MAX) break;
  }
  return (out + e.slice(k)).slice(0, MAX);
}

/** `{ let a = x; let b = y; return z; }` -> { lets: Map, ret }. */
function parseFunctionBody(body) {
  const lets = new Map();
  let ret = 'false';
  for (const st of splitTop(body, ';')) {
    const m = /^let\s+(\w+)\s*=\s*([\s\S]+)$/.exec(st);
    if (m) { lets.set(m[1], m[2]); continue; }
    const r = /^return\s+([\s\S]+)$/.exec(st);
    if (r) ret = r[1];
  }
  return { lets, ret };
}

/**
 * Parse a Firestore or Storage rules file. Returns { service, allows, errors } where each allow is
 * { path: [segments], ops: [get|list|create|update|delete], cond, cls, notes, line }. Paths have the
 * service prefix removed (`/databases/{database}/documents`, `/b/{bucket}/o`).
 */
export function parseRulesFile(src, { now = new Date() } = {}) {
  const t = maskComments(src);
  const line = lineIndex(t);
  const errors = [];
  const raw = [];
  let service = null;
  let i = 0;
  const ws = () => { while (i < t.length && /\s/.test(t[i])) i++; };
  const sticky = (re) => { re.lastIndex = i; const m = re.exec(t); if (m) i = re.lastIndex; return m; };
  const WORD = /[A-Za-z_][\w.]*/y;
  const SEG = /\/(\{[^}\s]*\}|[^/\s{]+)/y;

  /** Index just past the bracket matching the one at `at` (strings respected). */
  const skipBalanced = (at) => {
    const open = t[at];
    const close = { '{': '}', '(': ')', '[': ']' }[open];
    let depth = 0;
    for (let k = at; k < t.length; k++) {
      const c = t[k];
      if (c === '"' || c === "'") { k++; while (k < t.length && t[k] !== c && t[k] !== '\n') k += t[k] === '\\' ? 2 : 1; continue; }
      if (c === open) depth++;
      else if (c === close && --depth === 0) return k + 1;
    }
    return t.length;
  };

  /** An allow condition: up to `;`, a closing `}` or the next statement keyword, at depth 0. */
  const readExpr = () => {
    const start = i;
    let depth = 0;
    for (; i < t.length; i++) {
      const c = t[i];
      if (c === '"' || c === "'") { i++; while (i < t.length && t[i] !== c && t[i] !== '\n') i += t[i] === '\\' ? 2 : 1; continue; }
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']') depth--;
      else if (c === '}') { if (depth === 0) break; depth--; } else if (depth === 0 && c === ';') { const e = t.slice(start, i); i++; return e; } else if (depth === 0 && c === '\n' && /^\s*(allow|match|function)\b/.test(t.slice(i, i + 40))) break;
    }
    return t.slice(start, i);
  };

  const block = (prefix, scope) => {
    for (;;) {
      ws();
      if (i >= t.length) return;
      if (t[i] === '}') { i++; return; }
      const at = i;
      const w = sticky(WORD);
      if (!w) { errors.push({ line: line(at), error: `unexpected "${t[at]}"` }); i++; continue; }
      const kw = w[0];
      if (kw === 'match') {
        ws();
        const segs = [];
        let m;
        while ((m = sticky(SEG))) segs.push(m[1]);
        ws();
        if (t[i] !== '{') { errors.push({ line: line(at), error: 'match without a block' }); continue; }
        i++;
        block([...prefix, ...segs], { fns: new Map(), parent: scope });
      } else if (kw === 'allow') {
        ws();
        const opsStart = i;
        while (i < t.length && t[i] !== ':' && t[i] !== ';' && t[i] !== '}' && t[i] !== '\n') i++;
        const words = t.slice(opsStart, i).split(/[\s,]+/).filter(Boolean);
        const ops = [...new Set(words.flatMap((o) => OP_GROUPS[o] || (OPS.includes(o) ? [o] : [])))];
        let cond = '';
        if (t[i] === ':') { i++; ws(); if (t.startsWith('if', i) && /\W/.test(t[i + 2] || ' ')) i += 2; cond = readExpr(); } else if (t[i] === ';') i++;
        if (!ops.length) errors.push({ line: line(at), error: `allow with no known operation (${words.join(', ') || 'none'})` });
        else raw.push({ path: prefix, ops, cond: cond.replace(/\s+/g, ' ').trim(), line: line(at), scope });
      } else if (kw === 'function') {
        ws();
        const name = sticky(/\w+/y);
        ws();
        if (!name || t[i] !== '(') { errors.push({ line: line(at), error: 'malformed function' }); continue; }
        const pEnd = skipBalanced(i);
        const params = t.slice(i + 1, pEnd - 1).split(',').map((s) => s.trim()).filter(Boolean);
        i = pEnd;
        ws();
        if (t[i] !== '{') { errors.push({ line: line(at), error: `function ${name[0]} without a body` }); continue; }
        const bEnd = skipBalanced(i);
        scope.fns.set(name[0], { params, ...parseFunctionBody(t.slice(i + 1, bEnd - 1)) });
        i = bEnd;
      } else if (kw === 'service') {
        ws();
        const s = sticky(WORD);
        if (s) service = s[0];
        ws();
        if (t[i] === '{') { i++; block(prefix, { fns: new Map(), parent: scope }); }
      } else {
        // rules_version = '2'; and anything else: skip the statement.
        while (i < t.length && t[i] !== ';' && t[i] !== '\n' && t[i] !== '{' && t[i] !== '}') i++;
        if (t[i] === '{') { errors.push({ line: line(at), error: `unknown block "${kw}"` }); i = skipBalanced(i); } else if (t[i] === ';') i++;
        if (kw !== 'rules_version') errors.push({ line: line(at), error: `unknown statement "${kw}"` });
      }
    }
  };
  block([], { fns: new Map(), parent: null });

  const PREFIX = { 'cloud.firestore': ['databases', null, 'documents'], 'firebase.storage': ['b', null, 'o'] }[service];
  const strip = (segs) => {
    if (!PREFIX || segs.length < PREFIX.length) return segs;
    return PREFIX.every((p, k) => (p === null ? /^\{/.test(segs[k]) : segs[k] === p)) ? segs.slice(PREFIX.length) : segs;
  };
  const allows = raw.map((a) => {
    const lookup = (name) => { for (let s = a.scope; s; s = s.parent) if (s.fns.has(name)) return s.fns.get(name); return null; };
    const { cls, notes } = classify(a.cond, lookup, { now });
    return { path: strip(a.path), ops: a.ops, cond: a.cond, cls, notes, line: a.line, expanded: cls === 'closed' ? '' : expand(a.cond, lookup) };
  });
  return { service, allows, errors };
}

/** `{name=**}`: a recursive wildcard. */
export const isRecursive = (seg) => /^\{\w*=\*\*\}$/.test(seg);
const isWildcard = (seg) => /^\{\w*\}$/.test(seg);

/**
 * Does a rule path pattern match a code path? Code segments are literals or `*` (unknown at scan
 * time, e.g. a document id in a variable); `*` matches any rule segment. `anyPrefix` code paths
 * (a reference whose parent is unknown, a collection group) may match from any depth.
 */
export function pathMatches(rule, code, anyPrefix = false) {
  const memo = new Map();
  const m = (i, j) => {
    const k = i * 1000 + j;
    if (memo.has(k)) return memo.get(k);
    let r;
    if (i === rule.length) r = j === code.length;
    else if (isRecursive(rule[i])) { r = false; for (let jj = j; jj <= code.length && !r; jj++) r = m(i + 1, jj); } else if (j === code.length) r = false;
    else if (isWildcard(rule[i]) || code[j] === '*' || code[j] === rule[i]) r = m(i + 1, j + 1);
    else r = false;
    memo.set(k, r);
    return r;
  };
  if (!anyPrefix) return m(0, 0);
  // Unknown parent: the code path starts at some collection in the rule. A recursive wildcard there
  // would match any path at all, so the start must be a literal collection name equal to the code's
  // (or a single wildcard at a collection position, for a collection group under `{path=**}`).
  for (let i = 0; i < rule.length; i++) {
    if (isRecursive(rule[i])) { if (i + 1 < rule.length && m(i + 1, 0)) return true; continue; }
    if ((rule[i] === code[0] || (isWildcard(rule[i]) && i % 2 === 0 && code[0] !== '*')) && m(i, 0)) return true;
  }
  return false;
}

/**
 * Realtime Database rules (JSON). Returns { allows, errors } with the same allow shape; a grant at a
 * path cascades to everything below it, so every allow covers its subtree.
 */
export function parseDatabaseRules(src, { now = new Date() } = {}) {
  const errors = [];
  let json;
  try { json = JSON.parse(maskComments(src).replace(/,(\s*[}\]])/g, '$1')); } catch (e) { return { allows: [], errors: [{ line: 0, error: `not valid JSON: ${e.message}` }] }; }
  const root = json && typeof json === 'object' ? json.rules : null;
  if (!root || typeof root !== 'object') return { allows: [], errors: [{ line: 0, error: 'no top-level "rules" object' }] };
  const line = lineIndex(src);
  let cursor = 0;
  /** Approximate line of a key: the next occurrence in document order. */
  const lineOf = (key) => { const k = src.indexOf(JSON.stringify(key), cursor); if (k < 0) return 0; cursor = k + 1; return line(k); };
  const allows = [];
  const walk = (node, segs) => {
    for (const [k, v] of Object.entries(node)) {
      const ln = lineOf(k);
      if (k === '.read' || k === '.write') {
        const cond = typeof v === 'boolean' ? String(v) : typeof v === 'string' ? v : null;
        if (cond === null) { errors.push({ line: ln, error: `${k} is not a boolean or string` }); continue; }
        const { cls, notes } = classify(cond, () => null, { now });
        allows.push({ path: segs.map((s) => (s.startsWith('$') ? `{${s.slice(1)}}` : s)), ops: k === '.read' ? ['get', 'list'] : ['create', 'update', 'delete'], cond, cls, notes, line: ln });
      } else if (!k.startsWith('.') && v && typeof v === 'object') walk(v, [...segs, k]);
    }
  };
  walk(root, []);
  return { allows, errors };
}

/**
 * Documents the rules read to decide access: `get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role`
 * (and getAfter) give { path, field }; `exists(...)` gives { path, field: null }. Path segments are
 * literals or `*` for `$(...)`; `self` is true when the last one is `$(request.auth.uid)`.
 */
export function authzRefs(text) {
  const out = [];
  const re = /\b(get|getAfter|exists|existsAfter)\s*\(/g;
  let m;
  while ((m = re.exec(text))) {
    const open = m.index + m[0].length - 1;
    let d = 0;
    let close = open;
    for (; close < text.length; close++) { if (text[close] === '(') d++; else if (text[close] === ')' && --d === 0) break; }
    const arg = text.slice(open + 1, close).trim();
    const pm = /^\/databases\/(?:\$\([^)]*\)|[^/]+)\/documents\/(.+)$/.exec(arg);
    if (!pm) continue;
    const segs = [];
    let cur = '';
    let depth = 0;
    for (const c of pm[1]) {
      if (c === '(') depth++;
      if (c === ')') depth--;
      if (c === '/' && depth === 0) { segs.push(cur); cur = ''; } else cur += c;
    }
    segs.push(cur);
    const norm = segs.map((x) => x.trim()).filter(Boolean);
    const self = /^\$\(\s*\(?\s*request\.auth\.uid\s*\)?\s*\)$/.test(norm[norm.length - 1] || '');
    const path = norm.map((x) => (x.startsWith('$(') ? '*' : x));
    if (m[1].startsWith('exists')) { out.push({ path, field: null, self }); continue; }
    // `.data.role`, `.data['role']`, or `(get(...).data).role` once a helper returning `.data` is inlined.
    // `.data.get('role', 'user')` is the map's get(): the field is its first argument.
    const after = /^\s*\.\s*data\s*\)*\s*(?:\.\s*get\s*\(\s*['"]([^'"]+)['"]|\.\s*([A-Za-z_]\w*)(?!\s*\()|\[\s*['"]([^'"]+)['"]\s*\])/.exec(text.slice(close + 1, close + 120));
    if (after) out.push({ path, field: after[1] || after[2] || after[3], self });
  }
  return out;
}

/**
 * Can a caller for whom `holds(atom)` is false still pass `expr`? Atoms are split on top-level
 * `||` / `&&`; an atom that is `false` fails; an atom `holds` marks (one that needs the privilege
 * being checked) fails unless negated; anything else may pass.
 */
export function passableWithout(expr, holds) {
  const go = (e, d) => {
    e = unwrap(e);
    if (d > 40) return true;
    const ors = splitTop(e, '||');
    if (ors.length > 1) return ors.some((x) => go(x, d + 1));
    const ands = splitTop(e, '&&');
    if (ands.length > 1) return ands.every((x) => go(x, d + 1));
    if (e === 'false') return false;
    if (e.startsWith('!')) return true;
    return !holds(e);
  };
  return go(expr, 0);
}
