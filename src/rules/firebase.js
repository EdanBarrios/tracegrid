// Firebase rules: Security Rules exposure and Cloud Functions reachability, written against the same
// contract as the Supabase core rules (see src/engine.js). Rule paths are 'table' nodes (Storage paths
// are 'bucket' nodes) carrying `access`: { get|list|create|update|delete: { cls, at, cond, notes } }.
import { rankOf, pathMatches, passableWithout, authzRefs } from '../firebase/rules.js';

const WRITE = ['create', 'update', 'delete'];
const READ = ['get', 'list'];
const ruleNodes = (graph) => graph.nodes.filter((n) => n.access && !n.missing);
const opsWith = (n, ops, test) => ops.filter((o) => n.access[o] && test(n.access[o].cls));
const firstAt = (n, ops) => (ops.length ? n.access[ops[0]].at : n.at);
const notesOf = (n, ops) => [...new Set(ops.flatMap((o) => n.access[o].notes || []))].join('; ') || undefined;
const callers = (graph, id) => graph.incoming(id).filter((e) => e.source !== id);
/** Callers that go through the client SDK (rules apply); Admin SDK callers bypass rules. */
const clientCallers = (graph, id) => callers(graph, id).filter((e) => !e.relation.endsWith('-service') && e.relation !== 'trigger');
const where = (n) => (n.service === 'firestore' ? 'Firestore' : n.service === 'storage' ? 'Storage' : 'Realtime Database');

const WHO = { public: 'anyone', 'signed-in': 'any signed-in user', conditional: 'whoever passes the write rule, e.g. the owner' };
const escRe = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/**
 * Does a write condition constrain `field`? It reads the incoming value (`request.resource.data.role`),
 * names the key in a key check (`'role' in ...`, `hasAny(['role'])`), or allow-lists the written keys.
 * Merely reading the field elsewhere (an isAdmin() helper inlined into the condition) does not count.
 */
function fieldProtected(text, field) {
  const f = escRe(field);
  // `(request.resource.data).role` once a helper taking the data as a parameter is inlined.
  if (new RegExp(String.raw`request\.resource\.data\s*\)*\s*(?:\.\s*${f}(?![\w$])|\[\s*['"]${f}['"]\s*\]|\.\s*get\s*\(\s*['"]${f}['"])`).test(text)) return true;
  if (new RegExp(String.raw`['"]${f}['"]`).test(text)) return true;
  return /\.\s*hasOnly\s*\(/.test(text) && /affectedKeys\s*\(|keys\s*\(/.test(text);
}
/** A condition that only ties the document to the caller: signed-in checks and `request.auth.uid == x`. */
function onlyIdentity(text) {
  const parts = text.replace(/[()]/g, ' ').split('&&').map((p) => p.trim()).filter(Boolean);
  return parts.length > 0 && parts.every((p) => /^(request\.)?auth\s*!==?\s*null$/.test(p) || /^request\.auth\.uid\s*==\s*[\w$.]+$/.test(p) || /^[\w$.]+\s*==\s*request\.auth\.uid$/.test(p) || /^request\.auth\.uid\s*!=\s*null$/.test(p));
}

function caveat(f, sites, what) {
  if (!sites.length) return f;
  return { ...f, level: f.level === 'note' ? 'note' : 'warning', tier: f.tier === 'info' ? 'info' : 'review', confidence: 'low',
    note: [f.note, `${sites.length} unresolved ${what} reference(s) with a dynamic name could reach it (first: ${sites[0].file}:${sites[0].line}); check them first`].filter(Boolean).join('; ') };
}

export const firebaseRules = [
  {
    id: 'firebase-rules-public-write',
    level: 'error',
    tier: 'fix',
    title: 'Security Rules that let anyone write, signed in or not',
    why: 'An `allow create/update/delete/write` whose condition is always true (`if true`, no condition, or a test-mode date that has not passed). Anyone with the project\'s public config can create, change or delete these documents or files. Require sign-in and an ownership or role check. Open `create` alone is a Review item: it is how contact forms and guest orders are often written, and the question is validation and abuse, not takeover.',
    run({ graph }) {
      return ruleNodes(graph).map((n) => ({ n, ops: opsWith(n, WRITE, (c) => c === 'public') })).filter(({ ops }) => ops.length)
        .map(({ n, ops }) => ({ id: n.label, node: n.id, at: firstAt(n, ops), message: `${ops.join(', ')} open to everyone in ${where(n)}`,
          ...(ops.length === 1 && ops[0] === 'create' && n.service !== 'storage'
            ? { level: 'warning', tier: 'review', note: [notesOf(n, ops), 'create only (existing documents cannot be changed): check that the rule validates the fields and that abuse is bounded'].filter(Boolean).join('; ') }
            : { note: notesOf(n, ops) }) }));
    },
  },
  {
    id: 'firebase-rules-open-catch-all',
    level: 'error',
    tier: 'fix',
    title: 'Catch-all rules that open the whole database',
    why: 'A Firestore `match /{document=**}` at the root, or a Realtime Database `.read`/`.write` at the root, applies to every document, including collections added later, and rules OR together, so more specific rules cannot narrow it. Here it grants access to anyone or to any signed-in user. Remove it and write a rule per collection.',
    run({ graph }) {
      return ruleNodes(graph).filter((n) => n.rootCatchAll)
        .map((n) => ({ n, ops: opsWith(n, [...READ, ...WRITE], (c) => rankOf(c) >= rankOf('signed-in')) })).filter(({ ops }) => ops.length)
        .map(({ n, ops }) => ({ id: n.label, node: n.id, at: firstAt(n, ops), message: ops.map((o) => `${o}: ${n.access[o].cls}`).join(', '), note: notesOf(n, ops) }));
    },
  },
  {
    id: 'firestore-self-writable-access-field',
    level: 'error',
    tier: 'fix',
    title: 'Fields the rules trust for access that the client can write',
    why: 'Rules read a field with `get(...).data.<field>` to decide access (a role, a plan, a team id), and a create or update rule on that document lets the client write it without naming the field (no `request.resource.data.<field> == resource.data.<field>`, no `affectedKeys().hasOnly([...])` or `keys().hasOnly([...])` allow-list). A user can then set `role: "admin"` or another team\'s id on their own document and pass every rule that trusts it. Protect the field in the write rule, or move it to custom claims or a document only Cloud Functions write. Text heuristic over the expanded rules: a write rule that checks the field in a way not recognised here looks unprotected.',
    run({ graph, firebase }) {
      if (!firebase) return [];
      const out = [];
      const nodes = ruleNodes(graph).filter((n) => n.service === 'firestore');
      const seen = new Set();
      for (const ref of firebase.refs.filter((x) => x.field)) {
        for (const n of nodes.filter((x) => pathMatches(x.path, ref.path))) {
          const byOp = firebase.allowsByNode.get(n.id) || {};
          // The caller's own document (`users/$(request.auth.uid)`): creating or updating it with the field
          // grants access everywhere the rules read it. Another document (`teams/$(teamId)`): creating it
          // only affects that new document, and its writers (an owner) may manage the field by design, so
          // only a write any signed-in user (or anyone) can make counts.
          const ops = ref.self ? ['update', 'create'] : ['update'];
          const min = ref.self ? 'conditional' : 'signed-in';
          // A write only an already privileged caller passes (`allow write: if isAdmin()`) is not escalation.
          // Also privileged: a specific identity (`request.auth.token.email == 'me@x.com'`, `request.auth.uid == 'abc'`)
          // or a custom claim, which only the server can set (`request.auth.token.admin == true`).
          // Any branch that reads a stored privilege (any get() / exists()) needs an already privileged caller:
          // admins or members managing the field is the design, not escalation.
          const needsIt = (atom) => authzRefs(atom).length > 0
            || /request\.auth\.(?:uid|token\.email)\s*(?:==\s*['"]|in\s*\[)|['"]\s*==\s*request\.auth\.(?:uid|token\.email)\b|request\.auth\.token\.email\s*\.\s*matches\s*\(/.test(atom)
            || /request\.auth\.token\.(?!email\b|email_verified\b|firebase\b|sign_in_provider\b|phone_number\b|name\b|picture\b)\w+/.test(atom);
          const open = ops.flatMap((op) => (byOp[op] || []).filter((a) => rankOf(a.cls) >= rankOf(min) && !fieldProtected(a.expanded, ref.field) && passableWithout(a.expanded, needsIt)).map((a) => ({ op, ...a })));
          if (!open.length) continue;
          const worst = open.reduce((x, y) => (rankOf(y.cls) > rankOf(x.cls) ? y : x));
          if (seen.has(`${n.id}|${ref.field}`)) continue;
          seen.add(`${n.id}|${ref.field}`);
          out.push({ id: `${n.label}.${ref.field}`, node: n.id, at: worst.at,
            message: `${[...new Set(open.map((a) => a.op))].join(' and ')} can set "${ref.field}" (${WHO[worst.cls]}); rules read it for access at ${ref.at}` });
        }
      }
      return out;
    },
  },
  {
    id: 'firestore-self-grantable-membership',
    level: 'warning',
    tier: 'review',
    title: 'Membership documents a user may create for themselves',
    why: 'Rules grant access when a document exists (`exists(/databases/$(database)/documents/admins/$(request.auth.uid))`), and the create rule for that path only checks that the document id is the caller\'s uid. A user can create their own membership document and gain the access it stands for. Restrict creation to Cloud Functions or an existing member.',
    run({ graph, firebase }) {
      if (!firebase) return [];
      const out = [];
      const nodes = ruleNodes(graph).filter((n) => n.service === 'firestore');
      // exists() next to a get() of the same document is a guard before reading a field, not membership.
      const read = new Set(firebase.refs.filter((x) => x.field).map((x) => x.path.join('/')));
      for (const ref of firebase.refs.filter((x) => !x.field && x.self && !read.has(x.path.join('/')))) {
        for (const n of nodes.filter((x) => pathMatches(x.path, ref.path))) {
          const creates = ((firebase.allowsByNode.get(n.id) || {}).create || []).filter((a) => a.cls !== 'closed' && onlyIdentity(a.expanded));
          if (creates.length) out.push({ id: n.label, node: n.id, at: creates[0].at, message: `create checks only the caller's uid; rules treat the document's existence as access at ${ref.at}` });
        }
      }
      return out;
    },
  },
  {
    id: 'firebase-rules-signed-in-write',
    level: 'warning',
    tier: 'review',
    title: 'Security Rules that let any signed-in user write',
    why: 'The only condition is that the caller is signed in (`request.auth != null`). Every account, including one anyone can create through your sign-in flow, can change or delete every document at this path, not only their own. Add an ownership check (`request.auth.uid == userId`) or a role check.',
    run({ graph }) {
      return ruleNodes(graph).filter((n) => !n.rootCatchAll)
        .map((n) => ({ n, ops: opsWith(n, WRITE, (c) => c === 'signed-in') })).filter(({ ops }) => ops.length)
        .map(({ n, ops }) => ({ id: n.label, node: n.id, at: firstAt(n, ops), message: `${ops.join(', ')} open to any signed-in user` }));
    },
  },
  {
    id: 'firebase-rules-public-read',
    level: 'warning',
    tier: 'review',
    title: 'Security Rules that let anyone read, signed in or not',
    why: 'Readable without signing in. Right for public content (a shop catalogue, public assets); a leak for anything personal. Check what the documents or files hold.',
    run({ graph }) {
      return ruleNodes(graph).filter((n) => !n.rootCatchAll)
        .map((n) => ({ n, ops: opsWith(n, READ, (c) => c === 'public') })).filter(({ ops }) => ops.length)
        .map(({ n, ops }) => ({ id: n.label, node: n.id, at: firstAt(n, ops), message: `${ops.join(', ')} open to everyone in ${where(n)}`, note: notesOf(n, ops) }));
    },
  },
  {
    id: 'firestore-rule-unused',
    level: 'error',
    tier: 'fix',
    title: 'Firestore rule paths open to clients that no client code uses',
    why: 'Security Rules allow clients some access to these paths, but no Firestore reference in the app code (Dart or JavaScript client SDK) reaches them. Cloud Functions use the Admin SDK, which bypasses rules, so they never need a rule. Each is surface a client can use but the app does not: close it (`allow read, write: if false`) or ignore it with a reason. Open to any signed-in user or to anyone: Fix; open behind a condition: Review.',
    run({ graph, unresolved = [] }) {
      const dyn = unresolved.filter((u) => u.kind === 'firestore' && !u.privileged);
      return ruleNodes(graph).filter((n) => n.service === 'firestore' && !n.rootCatchAll && clientCallers(graph, n.id).length === 0)
        .map((n) => ({ n, open: opsWith(n, [...READ, ...WRITE], (c) => c !== 'closed') })).filter(({ open }) => open.length)
        .map(({ n, open }) => {
          const wide = open.filter((o) => rankOf(n.access[o].cls) >= rankOf('signed-in'));
          const admin = callers(graph, n.id).filter((e) => e.relation.endsWith('-service'));
          const f = { id: n.label, node: n.id, at: firstAt(n, wide.length ? wide : open),
            message: open.map((o) => `${o}: ${n.access[o].cls}`).join(', '),
            ...(wide.length ? {} : { level: 'warning', tier: 'review' }),
            ...(admin.length ? { note: `only the Admin SDK uses it (${admin[0].at[0]}), which does not need a rule` } : {}) };
          return caveat(f, dyn, 'Firestore');
        });
    },
  },
  {
    id: 'firestore-path-without-rule',
    level: 'warning',
    tier: 'review',
    title: 'Firestore paths the client uses that no rule allows',
    why: 'Client code reads or writes these paths, but no `allow` that can pass matches them, so Firestore denies the request (rules deny by default). A functional break, not an exposure; or the path in code is misspelled.',
    run({ graph }) {
      return graph.nodes.filter((n) => n.type === 'table' && n.missing && n.service === 'firestore')
        .map((n) => ({ n, inc: clientCallers(graph, n.id) })).filter(({ inc }) => inc.length)
        .map(({ n, inc }) => ({ id: n.label, node: n.id, at: inc.flatMap((e) => e.at)[0], sites: inc.reduce((a, e) => a + e.count, 0), ...(n.closedBy ? { note: `only closed rules match (${n.closedBy})` } : {}) }));
    },
  },
  {
    id: 'uncalled-callable-function',
    level: 'warning',
    tier: 'review',
    title: 'Callable Cloud Functions that nothing calls',
    why: 'Deployed with `onCall` (or `onRequest` when autoEntryPoints is off), but no `httpsCallable`, wrapper call or URL in the app code reaches them, and they are not declared in `entryPoints`. Any signed-in user (often anyone) can still call them. Delete them, or declare them as entry points if another app calls them.',
    run({ graph, unresolved = [] }) {
      const dyn = unresolved.filter((u) => u.kind === 'invoke' && !u.privileged);
      return graph.nodes.filter((n) => n.type === 'edge_function' && !n.missing && (n.kind === 'callable' || n.kind === 'http') && callers(graph, n.id).length === 0)
        .map((n) => caveat({ id: n.label, node: n.id, at: n.at, message: n.kind === 'http' ? 'HTTP function (onRequest)' : undefined }, dyn, 'httpsCallable'));
    },
  },
  {
    id: 'missing-callable-function',
    level: 'error',
    tier: 'review',
    title: 'Cloud Functions called that no codebase exports',
    why: 'Called by name, but no functions codebase in firebase.json exports a function with that name: renamed, deleted, deployed from another repository, or misspelled.',
    run({ graph }) {
      return graph.nodes.filter((n) => n.type === 'edge_function' && n.missing).map((n) => {
        const inc = graph.incoming(n.id);
        return { id: n.label, node: n.id, at: inc.flatMap((e) => e.at)[0], sites: inc.reduce((a, e) => a + e.count, 0) };
      });
    },
  },
  {
    id: 'duplicate-cloud-function',
    level: 'note',
    tier: 'info',
    title: 'Cloud Functions that are near-copies of each other',
    why: 'The handlers are the same code with different names and literals (85% or more of their token sequences match once local names and literals are normalized). Typical of functions added by separate sessions or agents that did not know the first one existed. Each copy is another endpoint to secure and to keep in step: a fix to one is easy to miss in the others. Merge them into one parameterised function or a shared helper.',
    run({ graph }) {
      const seen = new Set();
      return graph.nodes.filter((n) => n.type === 'edge_function' && n.duplicates).map((n) => [n.label, ...n.duplicates].sort())
        .filter((names) => { const k = names.join('|'); if (seen.has(k)) return false; seen.add(k); return true; })
        .map((names) => { const n = graph.node(`edge:${names[0]}`); return { id: names.join(' ~ '), node: n.id, at: n.at, message: `${names.length} near-identical functions (similarity ${n.similarity}): ${names.join(', ')}` }; });
    },
  },
  {
    id: 'callable-without-auth-check',
    level: 'warning',
    tier: 'review',
    title: 'Callable Cloud Functions that never look at the caller',
    why: 'The handler never reads `request.auth` / `context.auth` and does not pass the request to a helper that could, so anyone who can reach the function runs it, signed in or not, and it runs with Admin SDK rights. Fine for genuinely public endpoints; otherwise check `request.auth` first. Text heuristic: a review item.',
    run({ graph }) {
      return graph.nodes.filter((n) => n.type === 'edge_function' && !n.missing && n.kind === 'callable' && n.noAuthCheck)
        .map((n) => ({ id: n.label, node: n.id, at: n.at, message: n.noAuthCheck }));
    },
  },
];
