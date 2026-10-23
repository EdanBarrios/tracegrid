// Two review-tier hints about edge function code, found by text search in each function's own
// files (not _shared): a service_role / secret-key client used before any recognisable auth check,
// and fetch() of a URL taken from the request body (server-side request forgery). Heuristics:
// reported as review items, never fix.
import fs from 'node:fs';
import path from 'node:path';
import { MAX_SOURCE_FILE } from './scan-code.js';

/** Calls and patterns that count as authenticating or authorising the request. */
const AUTH_CHECK = /\.auth\s*\.\s*getUser\s*\(|\bgetClaims\s*\(|\bjwtVerify\s*\(|\bverify(?:Jwt|JWT|Token|Signature|Webhook|Hmac|Request|Auth|Caller|User)\w*\s*\(|\bconstructEvent(?:Async)?\s*\(|\b(?:check|verify|validate|assert|ensure|require)(?:Cron|Secret|Signature|Token|Auth|User|Caller|Role|Webhook|Admin|Jwt|JWT|Hmac|Session|Bearer|ApiKey|Key|Svix|Stripe|Member|Access|Permission)\w*\s*\(|\bauthori[sz]e\w*\s*\(|\bauthenticate\w*\s*\(|\bgetUser\s*\(|\btimingSafeEqual\b|crypto\s*\.\s*subtle\s*\.\s*verify\b|\bwebhooks?\s*\.\s*verify\b|\bCRON_SECRET\b/;
const lineAt = (text, idx) => text.slice(0, idx).split('\n').length;

/** Line of the first auth check that is a call, not a function's own definition. */
function firstAuthCheck(text) {
  const re = new RegExp(AUTH_CHECK.source, 'g');
  for (let m; (m = re.exec(text));) {
    if (/\bfunction\s*\*?\s*$/.test(text.slice(Math.max(0, m.index - 20), m.index))) continue;
    return lineAt(text, m.index);
  }
  return null;
}

/**
 * @param {string} root
 * @param {{ name: string, dir: string }[]} edgeFns
 * @param {string[]} files scanned files (relative)
 * @param {{ file: string, line: number, privileged?: boolean }[]} calls
 * @returns {Map<string, { serviceBeforeAuth?: { at: string, auth: string|null }, requestFetch?: { at: string, expr: string } }>}
 */
export function edgeHints(root, edgeFns, files, calls) {
  const out = new Map();
  for (const e of edgeFns) {
    const prefix = e.dir.replace(/\/$/, '') + '/';
    const mine = files.filter((f) => f.startsWith(prefix));
    const h = {};
    for (const f of mine) {
      let text;
      try { const st = fs.statSync(path.join(root, f)); if (st.size > MAX_SOURCE_FILE) continue; text = fs.readFileSync(path.join(root, f), 'utf8'); } catch { continue; }
      const masked = text.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' ')).replace(/(^|[^:])\/\/[^\n]*/g, (c, a) => a + ' '.repeat(c.length - a.length));
      const priv = calls.filter((c) => c.file === f && c.privileged).map((c) => c.line).sort((a, b) => a - b)[0];
      const authLine = firstAuthCheck(masked);
      if (priv && !h.serviceBeforeAuth && (authLine == null || priv < authLine)) h.serviceBeforeAuth = { at: `${f}:${priv}`, auth: authLine ? `${f}:${authLine}` : null };
      if (!h.requestFetch) {
        const fetchHit = requestFetch(masked);
        if (fetchHit) h.requestFetch = { at: `${f}:${lineAt(masked, fetchHit.index)}`, expr: fetchHit.expr };
      }
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
