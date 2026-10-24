// Build the graph and findings for a Firebase project: Security Rules, app code (Dart and JS/TS)
// and Cloud Functions. Same result shape as analyze() for Supabase, so report.md, graph.html,
// SARIF, the baseline and --check work unchanged. Node mapping: a rule path is a 'table' (Storage
// paths are 'bucket'), a Cloud Function is an 'edge_function', a source file is a 'file'.
import fs from 'node:fs';
import path from 'node:path';
import { findFiles, DEFAULTS } from '../config.js';
import { runRules, makeGraph, TIERS } from '../engine.js';
import { firebaseRules } from '../rules/firebase.js';
import { resolveFirebase, readText } from './project.js';
import { parseRulesFile, parseDatabaseRules, pathMatches, isRecursive, rankOf, OPS, authzRefs } from './rules.js';
import { scanFirebase } from './scan.js';
import { listCloudFunctions, missingAuthCheck } from './functions.js';
import { makeSuppressor, codeRoots, SCHEMA_VERSION } from '../analyze.js';

/** Code scanned by default in a Firebase project: Dart plus the usual JS/TS. */
export const FIREBASE_INCLUDE = ['**/*.dart', '**/*.html', ...DEFAULTS.include];
const FIREBASE_EXCLUDE = ['**/*.g.dart', '**/*.freezed.dart', '**/*.mocks.dart', '**/*_test.dart', 'test/**', 'integration_test/**', 'test_driver/**', '**/test/**'];

/** Config ignore list that applies to each Firebase rule. */
export const FIREBASE_IGNORE = {
  'firebase-rules-public-write': 'tables', 'firebase-rules-open-catch-all': 'tables', 'firebase-rules-signed-in-write': 'tables', 'firebase-rules-public-read': 'tables',
  'firestore-rule-unused': 'tables', 'firestore-path-without-rule': 'tables',
  'firestore-self-writable-access-field': 'tables', 'firestore-self-grantable-membership': 'tables',
  'uncalled-callable-function': 'edgeFunctions', 'missing-callable-function': 'edgeFunctions', 'callable-without-auth-check': 'edgeFunctions',
};

export function analyzeFirebase(root, { cfg, plugins = [], warnings = [], now = new Date() }) {
  const project = resolveFirebase(root, cfg);
  const notices = [];
  const unparsed = [];

  // Security Rules
  const rulesets = [];
  const read = (file) => { try { return readText(path.join(root, file)); } catch (e) { unparsed.push({ file, line: 0, reason: e.code || e.message, text: '' }); return null; } };
  for (const f of project.firestore) { const s = read(f.rules); if (s != null) rulesets.push({ ...parseRulesFile(s, { now }), service: 'firestore', file: f.rules, scope: f.database !== '(default)' ? f.database : '' }); }
  for (const f of project.storage) { const s = read(f.rules); if (s != null) rulesets.push({ ...parseRulesFile(s, { now }), service: 'storage', file: f.rules, scope: f.bucket || '' }); }
  for (const f of project.database) { const s = read(f.rules); if (s != null) rulesets.push({ ...parseDatabaseRules(s, { now }), service: 'rtdb', file: f.rules, scope: f.instance || '' }); }
  for (const r of rulesets) for (const e of r.errors) unparsed.push({ file: r.file, line: e.line, reason: e.error, text: '' });
  for (const m of project.missing) warnings.push(`${project.configFile} names ${m}, which does not exist.`);
  const multi = (svc) => rulesets.filter((r) => r.service === svc).length > 1;

  const nodes = new Map();
  const edges = new Map();
  const node = (id, type, label, extra = {}) => {
    if (!nodes.has(id)) nodes.set(id, { id, type, label, ...extra });
    else Object.assign(nodes.get(id), extra);
    return nodes.get(id);
  };
  const RANK = { ambiguous: 0, inferred: 1, extracted: 2 };
  const edge = (source, target, relation, confidence, at, op) => {
    const k = `${source}|${target}|${relation}`;
    let e = edges.get(k);
    if (!e) { e = { source, target, relation, confidence, ops: [], at: [], count: 0 }; edges.set(k, e); }
    e.count++;
    if (RANK[confidence] > RANK[e.confidence]) e.confidence = confidence;
    if (op && !e.ops.includes(op)) e.ops.push(op);
    if (at && e.at.length < 50) e.at.push(at);
  };

  // Firestore allows by node and operation (expanded conditions, for field-level checks), and the
  // documents and fields the rules read to decide access.
  const allowsByNode = new Map();
  const refs = [];
  const PREFIX = { firestore: '', storage: 'storage:', rtdb: 'rtdb:' };
  const ruleNodes = [];
  let allowCount = 0;
  for (const r of rulesets) {
    for (const a of r.allows) {
      allowCount++;
      const label = `${PREFIX[r.service]}${multi(r.service) ? `${r.scope || r.file}:` : ''}/${a.path.join('/')}`;
      const id = `table:${r.service}:${label}`;
      const n = node(id, r.service === 'storage' ? 'bucket' : 'table', label, { service: r.service, path: a.path, rulesFile: r.file });
      if (!n.access) {
        n.access = {};
        n.at = `${r.file}:${a.line}`;
        // Grants that cover the whole database: a root recursive wildcard (Firestore), the root (RTDB cascades).
        // (Storage: a catch-all is how public asset buckets are written; its reads and writes are judged on their own.)
        n.rootCatchAll = r.service === 'rtdb' ? a.path.length === 0 : r.service === 'firestore' && a.path.length > 0 && isRecursive(a.path[0]);
        ruleNodes.push(n);
      }
      if (r.service === 'firestore') {
        if (!allowsByNode.has(id)) allowsByNode.set(id, {});
        const byOp = allowsByNode.get(id);
        for (const op of a.ops) (byOp[op] = byOp[op] || []).push({ cls: a.cls, expanded: a.expanded || '', at: `${r.file}:${a.line}` });
        for (const ref of authzRefs(a.expanded || '')) refs.push({ ...ref, at: `${r.file}:${a.line}` });
      }
      for (const op of a.ops) {
        const cur = n.access[op];
        if (!cur || rankOf(a.cls) > rankOf(cur.cls)) n.access[op] = { cls: a.cls, at: `${r.file}:${a.line}`, cond: a.cond.slice(0, 200), ...(a.notes.length ? { notes: a.notes } : {}) };
      }
    }
  }
  for (const n of ruleNodes) for (const op of OPS) if (!n.access[op]) n.access[op] = { cls: 'closed', at: n.at, cond: '(no allow)' };

  // Code
  const userInclude = cfg._userKeys && cfg._userKeys.has('include');
  const include = userInclude ? cfg.include : FIREBASE_INCLUDE;
  const fnDirs = project.functions.map((f) => f.dir);
  // Built output of a functions codebase (lib/ from tsc) duplicates its src/.
  const exclude = [...cfg.exclude, ...(userInclude ? [] : FIREBASE_EXCLUDE), ...fnDirs.flatMap((d) => [`${d}/lib/**`, `${d}/dist/**`, `${d}/**/__tests__/**`, `${d}/test/**`])];
  const files = findFiles(root, include, exclude, { outputDirs: cfg.outputDirs || [] });
  const code = scanFirebase(root, files, { serverDirs: fnDirs, wrappers: (cfg.wrappers && cfg.wrappers.invoke) || [], pathWrappers: (cfg.wrappers && cfg.wrappers.firestore) || [] });
  const isServer = (f) => fnDirs.some((d) => f.startsWith(d.replace(/\/?$/, '/')));
  const fileNode = (file) => node(`file:${file}`, 'file', file, { side: isServer(file) ? 'edge' : 'client' });

  // Cloud Functions
  const fns = listCloudFunctions(root, project.functions);
  const fnNames = new Set(fns.map((f) => f.name));
  for (const f of fns) {
    const noAuth = f.kind === 'callable' ? missingAuthCheck(f.body) : null;
    node(`edge:${f.name}`, 'edge_function', f.name, { kind: f.kind, at: f.at, codebase: f.codebase, ...(f.trigger ? { trigger: f.trigger } : {}), ...(noAuth ? { noAuthCheck: noAuth } : {}) });
  }

  const firestoreNodes = ruleNodes.filter((n) => n.service === 'firestore');
  const openOps = (n) => OPS.some((o) => n.access[o].cls !== 'closed');
  const rel = (base, c) => (c.privileged ? `${base}-service` : base);
  for (const c of code.calls) {
    const at = `${c.file}:${c.line}`;
    if (c.kind === 'doc') {
      const hits = firestoreNodes.filter((n) => pathMatches(n.path, c.path, c.anyPrefix));
      fileNode(c.file);
      const conf = c.anyPrefix && hits.length > 1 ? 'ambiguous' : c.confidence;
      for (const n of hits) edge(`file:${c.file}`, n.id, rel('from', c), conf, at, c.op);
      // A client path no allow can pass: Firestore denies it (rules deny by default).
      if (!c.privileged && !c.anyPrefix && rulesets.some((r) => r.service === 'firestore') && !hits.some(openOps)) {
        const label = '/' + c.path.join('/');
        const id = `table:firestore-missing:${label}`;
        node(id, 'table', label, { service: 'firestore', path: c.path, missing: true, ...(hits.length ? { closedBy: hits[0].at } : {}) });
        edge(`file:${c.file}`, id, 'from', c.confidence, at, c.op);
      }
    } else if (c.kind === 'storage') {
      // Storage rules match object paths; link to every rule path that covers this one.
      const hits = ruleNodes.filter((n) => n.service === 'storage' && pathMatches(n.path, c.path));
      if (!hits.length) continue;
      fileNode(c.file);
      for (const n of hits) edge(`file:${c.file}`, n.id, rel('storage', c), hits.length > 1 && c.path.includes('*') ? 'ambiguous' : c.confidence, at);
    } else if (c.kind === 'invoke') {
      fileNode(c.file);
      if (!fnNames.has(c.name)) node(`edge:${c.name}`, 'edge_function', c.name, { missing: true });
      edge(`file:${c.file}`, `edge:${c.name}`, rel('invoke', c), c.confidence, at);
    }
  }
  // A callable's name as a string literal in client code (a provider or table of callables the
  // scan cannot follow): an ambiguous caller.
  const uncalled = fns.filter((f) => (f.kind === 'callable' || f.kind === 'http') && ![...edges.values()].some((e) => e.target === `edge:${f.name}`));
  if (uncalled.length) {
    for (const [file, src] of code.texts) {
      if (isServer(file)) continue;
      for (const f of uncalled) {
        const k = src.search(new RegExp(String.raw`(['"\`])${f.name.replace(/\$/g, '\\$')}\1`));
        if (k < 0) continue;
        fileNode(file);
        edge(`file:${file}`, `edge:${f.name}`, 'invoke', 'ambiguous', `${file}:${src.slice(0, k).split('\n').length}`);
      }
    }
  }
  // Triggers: the rule path a Firestore trigger watches feeds the function.
  for (const f of fns.filter((x) => x.trigger)) {
    const segs = f.trigger.split('/').filter(Boolean).map((s) => (/^\{.*\}$/.test(s) ? '*' : s));
    for (const n of firestoreNodes) if (pathMatches(n.path, segs)) edge(n.id, `edge:${f.name}`, 'trigger', 'inferred', f.at);
  }

  // External entry points: config, and HTTP functions when autoEntryPoints is on.
  const entries = [];
  const entryInvalid = [];
  for (const ep of cfg.entryPoints) {
    if (fnNames.has(ep.name)) entries.push({ name: ep.name, reason: ep.reason, source: 'config', confidence: 'extracted' });
    else entryInvalid.push({ file: 'config', line: 0, error: `entryPoints: no Cloud Function named ${ep.name}` });
  }
  if (cfg.autoEntryPoints) for (const f of fns.filter((x) => x.kind === 'http')) entries.push({ name: f.name, reason: 'HTTP function (onRequest): assumed to be called from outside (webhook, browser, scheduler)', source: f.at, confidence: 'inferred' });
  const entryByName = new Map();
  for (const ep of entries) if (!entryByName.has(ep.name)) entryByName.set(ep.name, ep);
  if (entryByName.size) node('external:http', 'external', 'external callers');
  for (const ep of entryByName.values()) { node(`edge:${ep.name}`, 'edge_function', ep.name, { entryPoint: ep.reason }); edge('external:http', `edge:${ep.name}`, 'entry-point', ep.confidence, ep.source); }

  // Findings
  const graph = makeGraph([...nodes.values()], [...edges.values()]);
  const ran = runRules([...firebaseRules, ...plugins], { graph, config: cfg, root, unresolved: code.unresolved, platform: 'firebase', catalog: null, firebase: { allowsByNode, refs } }, makeSuppressor(cfg, [], FIREBASE_IGNORE));
  for (const f of ran.findings) f.source = 'firebase-rules';

  const scope_problems = [];
  const clientCalls = code.calls.filter((c) => !c.privileged);
  if (!files.length) scope_problems.push(`0 code files matched \`include\` (${include.join(', ')}); every "nothing uses" finding is meaningless. Set "include" in tracegrid.config.json.`);
  else if (!clientCalls.length && !code.unresolved.length) scope_problems.push(`${files.length} code files scanned but 0 Firebase call sites found in client code; check "include" and that the app uses the Firestore / Cloud Functions client SDKs.`);
  if (!rulesets.length) scope_problems.push(`no Security Rules found: ${project.configFile} names no firestore/storage/database rules file and none of firestore.rules, storage.rules, database.rules.json exists.`);
  warnings.unshift(...scope_problems);
  if (unparsed.length) warnings.push(`${unparsed.length} rules statement(s) not understood (first: ${unparsed[0].file}:${unparsed[0].line}: ${unparsed[0].reason}); findings that depend on them may be wrong.`);
  if (code.failed.length) warnings.push(`${code.failed.length} code file(s) could not be read (first: ${code.failed[0].file}: ${code.failed[0].error}).`);
  const rtdbUnlisted = ['database.rules.json', 'firebase.rules.json'].filter((f) => !project.database.some((d) => d.rules === f) && fs.existsSync(path.join(root, f)));
  if (rtdbUnlisted.length && !project.database.length) notices.push(`${rtdbUnlisted.join(', ')} exists but ${project.configFile} has no "database" entry, so it is not deployed by \`firebase deploy\` and was not checked.`);

  const distinct = (pred) => new Set(code.calls.filter(pred).map((c) => (c.path ? c.path.join('/') : c.name))).size;
  const stats = {
    files_scanned: files.length,
    call_sites: code.calls.length,
    unresolved: code.unresolved.length,
    firestore_paths_used: { client: distinct((c) => c.kind === 'doc' && !c.privileged), server: distinct((c) => c.kind === 'doc' && c.privileged) },
    callables_called: distinct((c) => c.kind === 'invoke' && !c.privileged),
    rules_files: rulesets.length,
    rule_paths: ruleNodes.length,
    allows: allowCount,
    rules_unparsed: unparsed.length,
    cloud_functions: fns.length,
    cloud_functions_by_kind: Object.fromEntries(['callable', 'http', 'trigger'].map((k) => [k, fns.filter((f) => f.kind === k).length])),
    // Keys the Supabase report reads, kept so older consumers do not break.
    edge_functions: fns.length, distinct_edge_functions_invoked: distinct((c) => c.kind === 'invoke'),
  };

  return {
    schema_version: SCHEMA_VERSION,
    generated_at: new Date().toISOString(),
    root: path.basename(root),
    platform: 'firebase',
    source: 'firebase-rules',
    project: {
      platform: 'firebase', configFile: project.configFile,
      rules: rulesets.map((r) => ({ service: r.service, file: r.file, allows: r.allows.length })),
      functions: project.functions, codeRoots: codeRoots(files),
    },
    scope_problems,
    notices,
    warnings,
    stats,
    rules: ran.rules,
    counts: Object.fromEntries(ran.rules.map((r) => [r.id, ran.findings.filter((f) => f.rule === r.id).length])),
    tiers: Object.fromEntries(TIERS.map((t) => [t, ran.findings.filter((f) => f.tier === t).length])),
    sarifLevels: { ...cfg.sarifLevels },
    findings: ran.findings,
    suppressed: ran.suppressed,
    info: {
      storage_buckets: [],
      unresolved_dynamic_calls: code.unresolved.map(({ kind, file, line, expr }) => ({ kind, file, line, expr })),
      unparsed_sql: unparsed,
      dynamic_sql_applied: [],
      unreadable_files: code.failed,
      skipped_migrations: [],
      external_entry_points: [...entryByName.values()].map(({ name, reason, source }) => ({ id: name, reason, source })),
      invalid_hatches: entryInvalid,
      invoke_wrappers: code.wrappers.filter((w) => w.file).map((w) => ({ name: w.name, file: w.file })),
    },
    directed: true,
    multigraph: false,
    graph: { name: path.basename(root), tool: 'tracegrid' },
    nodes: [...nodes.values()],
    links: [...edges.values()],
  };
}
