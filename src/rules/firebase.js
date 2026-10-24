// Firebase rules: Security Rules exposure and Cloud Functions reachability, written against the same
// contract as the Supabase core rules (see src/engine.js). Rule paths are 'table' nodes (Storage paths
// are 'bucket' nodes) carrying `access`: { get|list|create|update|delete: { cls, at, cond, notes } }.
import { rankOf } from '../firebase/rules.js';

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
    why: 'An `allow create/update/delete/write` whose condition is always true (`if true`, no condition, or a test-mode date that has not passed). Anyone with the project\'s public config can create, change or delete these documents or files. Require sign-in and an ownership or role check.',
    run({ graph }) {
      return ruleNodes(graph).map((n) => ({ n, ops: opsWith(n, WRITE, (c) => c === 'public') })).filter(({ ops }) => ops.length)
        .map(({ n, ops }) => ({ id: n.label, node: n.id, at: firstAt(n, ops), message: `${ops.join(', ')} open to everyone in ${where(n)}`, note: notesOf(n, ops) }));
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
