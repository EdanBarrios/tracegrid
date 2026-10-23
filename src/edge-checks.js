// Two review-tier hints about edge function code, found by text search in each function's own
// files (not _shared): a service_role / secret-key client used before any recognisable auth check,
// and fetch() of a URL taken from the request body (server-side request forgery). Heuristics:
// reported as review items, never fix.
import fs from 'node:fs';
import path from 'node:path';
import { MAX_SOURCE_FILE } from './scan-code.js';

/** Calls and patterns that count as authenticating or authorising the request. */
const AUTH_CHECK = /\.auth\s*\.\s*getUser\s*\(|\bgetClaims\s*\(|\bjwtVerify\s*\(|\bverify(?:Jwt|JWT|Token|Signature|Webhook|Hmac|Request|Auth|Caller|User)\w*\s*\(|\bconstructEvent(?:Async)?\s*\(|\b(?:check|verify|validate|assert|ensure|require)(?:Cron|Secret|Signature|Token|Auth|User|Caller|Role|Webhook|Admin|Jwt|JWT|Hmac|Session|Bearer|ApiKey|Key|Svix|Stripe|Member|Access|Permission)\w*\s*\(|\bauthori[sz]e\w*\s*\(|\bauthenticate\w*\s*\(|\bgetUser\s*\(|\btimingSafeEqual\b|crypto\s*\.\s*subtle\s*\.\s*verify\b|\bwebhooks?\s*\.\s*verify\b|\bCRON_SECRET\b/;
/** Webhook verifiers under any name, svix / standard-webhooks headers, HMAC verify, constant-time compares. */
const VERIFIER = /\bverify\w*(?:Signature|Webhook|Hmac|Token)\w*\s*\(|['"`](?:svix-signature|svix-id|webhook-signature|webhook-id)['"`]|\bnew\s+Webhook\s*\(|\bsubtle\s*\.\s*verify\b|\b(?:timingSafe\w*|constantTime\w*|safeEqual|secureCompare|timingSafeEqual)\s*\(/i;
const CONST_TIME = /\b(?:timingSafe\w*|constantTime\w*|safeEqual|secureCompare)\s*\(/i;
const SHA256 = /subtle\s*\.\s*digest\s*\(\s*['"`]SHA-?256|createHash\s*\(\s*['"`]sha-?256|\bsha-?256\w*\s*\(|\bhashToken\w*\s*\(/i;
const TOKEN_SOURCE = /searchParams\s*\.\s*get\s*\(|\.pathname\b|headers\s*\.\s*get\s*\(/;
const RATE_LIMIT_RPC = /\.rpc\s*\(\s*['"`](\w*(?:claim_\w*attempt|rate_limit|throttle)\w*)['"`]/gi;
const EARLY_EXIT = /\bif\s*\([^\n]*(?:!|error|null|undefined|denied|limit)[^\n]*\)?[\s\S]{0,200}?\b(?:return|throw)\b|\?\?\s*\(?\s*throw\b/;
const lineAt = (text, idx) => text.slice(0, idx).split('\n').length;
const mask = (text) => text.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' ')).replace(/(^|[^:])\/\/[^\n]*/g, (c, a) => a + ' '.repeat(c.length - a.length));

/** A match that is a function's or constant's own definition, not a call. */
const isDefinition = (text, idx) => /\b(?:function\s*\*?|(?:const|let|var))\s*$/.test(text.slice(Math.max(0, idx - 20), idx));

/** Line of the first match of `re` that is a use, not a definition. */
function firstUse(text, re) {
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  for (let m; (m = g.exec(text));) if (!isDefinition(text, m.index)) return lineAt(text, m.index);
  return null;
}
/** Line where the statement containing `idx` starts (walks up `.chain()` continuation lines). */
function stmtLine(text, idx) {
  const lines = text.split('\n');
  let l = lineAt(text, idx);
  while (l > 1 && lines[l - 1].trim().startsWith('.')) l--;
  return l;
}
const windowAfter = (text, idx, n = 12) => text.slice(idx).split('\n').slice(0, n).join('\n');
const balanced = (text, open) => { let d = 0; for (let i = open; i < text.length; i++) { if (text[i] === '(') d++; else if (text[i] === ')' && --d === 0) return text.slice(open, i + 1); } return text.slice(open); };

const DECL = /(?:\bfunction\s*\*?\s+([A-Za-z_$][\w$]*)|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[^=\n]+?)?=>)/g;
/** End index of the body of a function declaration matched by DECL, or null if not found. */
function declEnd(text, d) {
  const after = d.index + d[0].length;
  const rest = text.slice(after);
  const arrow = d[0].includes('=>');
  const m = arrow ? /^\s*(?::[^{]*)?\{/.exec(rest) : /\)\s*(?::[^{]*)?\{/.exec(rest);
  if (!m) return arrow ? after + 60 : null;
  const open = after + m.index + m[0].length - 1;
  let depth = 0;
  for (let i = open; i < text.length; i++) { if (text[i] === '{') depth++; else if (text[i] === '}' && --depth === 0) return i; }
  return text.length;
}
/** Name of the outermost named function whose body contains `idx`, or null (top level). */
function outerFn(text, idx) {
  for (const d of text.matchAll(DECL)) {
    if (d.index > idx) break;
    const end = declEnd(text, d);
    if (end != null && idx < end) return d[1] || d[2];
  }
  return null;
}

/**
 * Names that hand back a client built from the anon / publishable key plus the request's
 * Authorization header (RLS runs as the caller). Variables bound to one, and the helper functions
 * that return one.
 */
function callerScopedNames(text) {
  const vars = new Set();
  const helpers = new Set();
  const decls = [...text.matchAll(DECL)];
  for (const m of text.matchAll(/\bcreateClient\s*(?:<[^>(]*>)?\s*\(/g)) {
    const args = balanced(text, m.index + m[0].length - 1);
    if (!/Authorization/i.test(args) || !/anon|publishable/i.test(args) || /service[_-]?role|service[_-]?key|secret/i.test(args)) continue;
    const bind = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:await\s+)?$/.exec(text.slice(Math.max(0, m.index - 120), m.index));
    if (bind) vars.add(bind[1]);
    for (const d of decls.filter((x) => x.index < m.index).reverse().slice(0, 4)) {
      const end = declEnd(text, d);
      if (end != null && m.index < end) { helpers.add(d[1] || d[2]); break; }
    }
  }
  return { vars, helpers };
}
const esc = (n) => n.replace(/\$/g, '\\$');

/** Line of the first read through a caller-scoped (RLS) client whose result gates the request (returns or throws when missing). */
function callerScopedGate(text, sharedHelpers) {
  const { vars, helpers } = callerScopedNames(text);
  for (const h of sharedHelpers) helpers.add(h);
  for (const h of helpers) for (const m of text.matchAll(new RegExp(String.raw`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:await\s+)?${esc(h)}\s*\(`, 'g'))) vars.add(m[1]);
  const alts = [...vars].map((v) => `\\b${esc(v)}`).concat([...helpers].map((h) => `\\b${esc(h)}\\s*\\([^)]*\\)`));
  if (!alts.length) return null;
  const re = new RegExp(`(?:${alts.join('|')})\\s*\\.\\s*(?:from|rpc)\\s*\\(`, 'g');
  for (let m; (m = re.exec(text));) {
    if (isDefinition(text, m.index)) continue;
    if (EARLY_EXIT.test(windowAfter(text, m.index))) return stmtLine(text, m.index);
  }
  return null;
}

/** Hashed opaque token (sha-256) compared in constant time, or passed on to an RPC as the credential. */
function tokenGate(text) {
  if (!TOKEN_SOURCE.test(text)) return null;
  const g = new RegExp(SHA256.source, 'gi');
  for (let m; (m = g.exec(text));) {
    const rest = text.slice(m.index + m[0].length);
    if (CONST_TIME.test(rest) || /\.rpc\s*\(/.test(rest)) return stmtLine(text, m.index);
  }
  return null;
}

/** A secret-looking value read from the URL or a header and passed as the only argument of an RPC. Weak: never a full gate. */
function keyRpcUse(text) {
  const names = [...text.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*[^;\n]*?(?:searchParams\s*\.\s*get|headers\s*\.\s*get)\s*\(/g)].map((m) => m[1]).filter((n) => /token|key|secret|code|hash|sig|nonce|link/i.test(n));
  if (!names.length) return null;
  const alt = names.map(esc).join('|');
  const re = new RegExp(String.raw`\.rpc\s*\(\s*['"\x60]([\w.]+)['"\x60]\s*,\s*(?:\{\s*[\w$]+\s*:\s*(${alt})\s*,?\s*\}|(${alt})\s*\))`, 'g');
  const m = re.exec(text);
  return m ? { line: stmtLine(text, m.index), rpc: m[1], name: m[2] || m[3] } : null;
}

/** First rate-limit / attempt-claim RPC whose failure returns early. */
function rateLimitGate(text) {
  for (const m of text.matchAll(RATE_LIMIT_RPC)) if (EARLY_EXIT.test(windowAfter(text, m.index))) return stmtLine(text, m.index);
  return null;
}

/** Every recognised gate in a file: { line, what }; the earliest decides. */
function gatesOf(text, sharedHelpers) {
  const out = [];
  const add = (line, what) => { if (line != null) out.push({ line, what }); };
  add(firstUse(text, AUTH_CHECK), 'auth check');
  add(firstUse(text, VERIFIER), 'signature / token verifier');
  add(callerScopedGate(text, sharedHelpers), 'caller-scoped RLS read');
  add(tokenGate(text), 'hashed token capability');
  add(rateLimitGate(text), 'rate-limit gate');
  return out.sort((a, b) => a.line - b.line);
}

/** Masked text of a project file, or null when unreadable or too large. */
function readMasked(root, file) {
  try { const st = fs.statSync(path.join(root, file)); if (st.size > MAX_SOURCE_FILE) return null; return mask(fs.readFileSync(path.join(root, file), 'utf8')); } catch { return null; }
}

/** Files `text` (in `file`) imports through relative paths. */
function relativeImports(file, text, files) {
  const out = [];
  for (const m of text.matchAll(/\bfrom\s+['"](\.{1,2}\/[^'"]+)['"]/g)) {
    const target = path.posix.normalize(path.posix.join(path.posix.dirname(file), m[1]));
    const hit = [target, target + '.ts', target + '.tsx', target + '.js', target + '/index.ts'].find((c) => files.includes(c));
    if (hit) out.push(hit);
  }
  return out;
}

/**
 * A token capability endpoint: some file reachable from `file` within three import hops hashes with
 * sha-256 and compares in constant time (the verifier), and the request token is read in the
 * verifier or a file on the import chain that leads to it. Hash and compare in unrelated files,
 * or a token read off the verifier's chain, do not count.
 */
function tokenCapability(root, file, files, chain = [], tokenSeen = false) {
  if (chain.length > 3 || chain.includes(file)) return false;
  const text = readMasked(root, file);
  if (text == null) return false;
  const token = tokenSeen || TOKEN_SOURCE.test(text);
  if (token && SHA256.test(text) && CONST_TIME.test(text)) return true;
  return relativeImports(file, text, files).some((f) => tokenCapability(root, f, files, [...chain, file], token));
}

/** Helper names defined in _shared that return a caller-scoped client. */
function sharedScopedHelpers(root, files) {
  const names = new Set();
  for (const f of files) {
    if (!/(?:^|\/)functions\/_shared\//.test(f)) continue;
    try {
      const st = fs.statSync(path.join(root, f));
      if (st.size > MAX_SOURCE_FILE) continue;
      for (const h of callerScopedNames(mask(fs.readFileSync(path.join(root, f), 'utf8'))).helpers) names.add(h);
    } catch { /* unreadable: skip */ }
  }
  return names;
}

/**
 * @param {string} root
 * @param {{ name: string, dir: string, entry?: string }[]} edgeFns
 * @param {string[]} files scanned files (relative)
 * @param {{ file: string, line: number, kind?: string, privileged?: boolean }[]} calls
 * @returns {Map<string, { serviceBeforeAuth?: { at: string, gate: string|null, kind: 'no-gate'|'before-gate'|'inert'|'key-rpc', key?: { name: string, rpc: string } }, requestFetch?: { at: string, expr: string } }>}
 */
export function edgeHints(root, edgeFns, files, calls) {
  const out = new Map();
  const shared = sharedScopedHelpers(root, files);
  for (const e of edgeFns) {
    const prefix = e.dir.replace(/\/$/, '') + '/';
    const mine = files.filter((f) => f.startsWith(prefix));
    const h = {};
    const per = [];
    for (const f of mine) {
      let text;
      try { const st = fs.statSync(path.join(root, f)); if (st.size > MAX_SOURCE_FILE) continue; text = mask(fs.readFileSync(path.join(root, f), 'utf8')); } catch { continue; }
      // Data uses of a privileged client: reads, writes, rpc, storage, auth.admin. Not the `select` embeds (same statement).
      const uses = calls.filter((c) => c.file === f && c.privileged && c.kind !== 'select').map((c) => c.line);
      for (const m of text.matchAll(/\.\s*auth\s*\.\s*admin\s*\./g)) uses.push(lineAt(text, m.index));
      // A use inside a helper defined above the request handler happens when the handler calls it.
      const hs = /\b(?:Deno\s*\.\s*serve|serve[A-Z]\w*|serve)\s*\(/.exec(text);
      const handlerLine = hs ? lineAt(text, hs.index) : null;
      const adj = [];
      for (const l of uses) {
        if (handlerLine == null || l >= handlerLine) { adj.push(l); continue; }
        const idx = text.split('\n').slice(0, l - 1).join('\n').length + 1;
        const fn = outerFn(text, idx);
        if (!fn) { adj.push(l); continue; }
        const call = text.split('\n').findIndex((ln, i) => i + 1 >= handlerLine && new RegExp(`\\b${esc(fn)}\\b`).test(ln));
        if (call >= 0) adj.push(call + 1);
      }
      uses.length = 0; uses.push(...adj);
      uses.sort((a, b) => a - b);
      const gates = gatesOf(text, shared);
      per.push({ f, text, uses, gate: gates[0] || null, keyRpc: keyRpcUse(text) });
      if (!h.requestFetch) {
        const fetchHit = requestFetch(text);
        if (fetchHit) h.requestFetch = { at: `${f}:${lineAt(text, fetchHit.index)}`, expr: fetchHit.expr };
      }
    }
    const gatedElsewhere = per.some((p) => p.gate);
    const roots = e.entry && per.some((p) => p.f === e.entry) ? [e.entry] : per.map((p) => p.f);
    const capability = roots.some((f) => tokenCapability(root, f, files));
    for (const p of per) {
      if (!p.uses.length || h.serviceBeforeAuth || capability) continue;
      const lines = p.text.split('\n');
      const inert = p.uses.every((l) => /\bhead\s*:\s*true\b/.test(lines.slice(l - 1, l + 6).join('\n')));
      const first = p.uses[0];
      let kind;
      if (p.gate && first >= p.gate.line) continue;
      if (!p.gate && gatedElsewhere && e.entry && p.f !== e.entry) continue;
      if (p.keyRpc && !inert && first >= p.keyRpc.line && (!p.gate || first < p.gate.line)) {
        h.serviceBeforeAuth = { at: `${p.f}:${first}`, gate: null, kind: 'key-rpc', key: p.keyRpc };
        continue;
      }
      kind = inert ? 'inert' : p.gate ? 'before-gate' : 'no-gate';
      h.serviceBeforeAuth = { at: `${p.f}:${first}`, gate: p.gate ? `${p.f}:${p.gate.line} (${p.gate.what})` : null, kind };
    }
    if (h.serviceBeforeAuth || h.requestFetch) out.set(e.name, h);
  }
  return out;
}

/** fetch() whose URL is a value read from the request body (`await req.json()` / `formData()`). */
export function requestFetch(text) {
  const names = new Set();
  const objs = new Set();
  const src = /\b(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*await\s+(?:req|request|r|event\.request)\s*\.\s*(?:json|formData)\s*\(\s*\)/g;
  for (const m of text.matchAll(src)) {
    if (m[1].startsWith('{')) for (const part of m[1].slice(1, -1).split(',')) { const n = /(?:^|:)\s*([A-Za-z_$][\w$]*)\s*(?:=.*)?$/.exec(part.trim()); if (n) names.add(n[1]); }
    else objs.add(m[1]);
  }
  if (!names.size && !objs.size) return null;
  const ident = [...names].map((n) => n.replace(/\$/g, '\\$')).join('|');
  const obj = [...objs].map((n) => n.replace(/\$/g, '\\$')).join('|');
  const val = [ident && `(?:${ident})\\b(?!\\s*[.(\\[])`, obj && `(?:${obj})\\s*(?:\\.\\s*[A-Za-z_$][\\w$]*|\\[\\s*['"][^'"]+['"]\\s*\\])`].filter(Boolean).join('|');
  const re = new RegExp(String.raw`\bfetch\s*\(\s*(?:new\s+URL\s*\(\s*)?(?:` + '`\\$\\{\\s*' + `)?(${val})`, 'g');
  const m = re.exec(text);
  return m ? { index: m.index, expr: m[0].replace(/\s+/g, ' ').slice(0, 80) } : null;
}
