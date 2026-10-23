// Build the graph and findings from code, SQL and edge-function scans.
import path from 'node:path';
import { loadConfig, findFiles } from './config.js';
import { scanFiles } from './scan-code.js';
import { scanMigrations, sqlRefs, fnSummary } from './scan-sql.js';
import { listEdgeFunctions } from './edge-functions.js';
import { coreRules } from './rules/core.js';
import { loadPlugins, runRules, makeGraph } from './engine.js';

export const SCHEMA_VERSION = 1;

/** Config ignore list that applies to each core rule. */
const IGNORE_CATEGORY = {
  'exposed-uncalled-function': 'functions',
  'client-table-without-rls': 'tables', 'client-table-without-policies': 'tables', 'unknown-table': 'tables',
  'missing-rpc': 'rpcs',
  'uncalled-edge-function': 'edgeFunctions',
};

/** Subject match: exact, or a function name matching any of its overloads (`name/arity`). */
const sameSubject = (id, name) => id === name || id.startsWith(name + '/');

function makeSuppressor(cfg, hatches) {
  const ign = cfg.ignore;
  return (f) => {
    const byId = (ign.findings || []).find((x) => x.id === f.fingerprint);
    if (byId) return `config ignore.findings: ${byId.reason}`;
    const cat = IGNORE_CATEGORY[f.rule];
    const hit = cat && (ign[cat] || []).find((x) => sameSubject(f.id, x.name));
    if (hit) return `config ignore.${cat}: ${hit.reason}`;
    const h = hatches.find((x) => x.rule === f.rule && sameSubject(f.id, x.subject));
    if (h) return `hatch at ${h.at}: ${h.reason}`;
    return null;
  };
}

export async function analyze(root, opts = {}) {
  root = path.resolve(root);
  const cfg = opts.config || loadConfig(root, opts.configFile);
  const plugins = opts.rules || await loadPlugins(cfg._dir || root, cfg.plugins || []);
  const files = findFiles(root, cfg.include, cfg.exclude);
  const code = scanFiles(root, files, cfg.wrappers);
  const sql = scanMigrations(path.join(root, cfg.migrations), { supabaseDefaultGrants: cfg.supabaseDefaultGrants });
  const edgeFns = listEdgeFunctions(root, cfg.functionsDir);
  const edgeNames = new Set(edgeFns.map((e) => e.name));
  const fnPrefix = cfg.functionsDir.replace(/\/$/, '') + '/';

  /** Which graph node a code file belongs to. */
  const callerOf = (file) => {
    if (file.startsWith(fnPrefix)) {
      const dir = file.slice(fnPrefix.length).split('/')[0];
      if (edgeNames.has(dir)) return { id: `edge:${dir}`, side: 'edge' };
      return { id: `file:${file}`, side: 'edge' };
    }
    return { id: `file:${file}`, side: 'client' };
  };

  const nodes = new Map();
  const edges = new Map();
  const node = (id, type, label, extra = {}) => {
    if (!nodes.has(id)) nodes.set(id, { id, type, label, ...extra });
    else Object.assign(nodes.get(id), extra);
    return nodes.get(id);
  };
  const edge = (source, target, kind, confidence, at, op) => {
    const k = `${source}|${target}|${kind}`;
    let e = edges.get(k);
    if (!e) { e = { source, target, kind, confidence, ops: [], at: [], count: 0 }; edges.set(k, e); }
    e.count++;
    if (confidence === 'extracted') e.confidence = 'extracted';
    if (op && !e.ops.includes(op)) e.ops.push(op);
    if (at && e.at.length < 50) e.at.push(at);
  };

  // Schema nodes
  for (const t of sql.tables.values()) node(`table:${t.name}`, 'table', t.name, { rls: t.rls, policies: t.policies.size, defined: !t.external, at: `${t.file}:${t.line}` });
  for (const v of sql.views.values()) node(`table:${v.name}`, 'view', v.name, { securityInvoker: v.securityInvoker, at: `${v.file}:${v.line}` });
  const fns = new Map([...sql.functions.values()].map((f) => [f.name, fnSummary(f)]));
  for (const f of fns.values()) {
    node(`fn:${f.name}`, 'function', f.name, {
      kind: f.kind, triggerOnly: f.triggerOnly || undefined, securityDefiner: f.securityDefiner, returns: f.returns, args: f.args, anon: f.anon,
      authenticated: f.authenticated, at: `${f.file}:${f.line}`, overloads: f.overloads > 1 ? f.overloads : undefined,
    });
  }
  for (const e of edgeFns) node(`edge:${e.name}`, 'edge_function', e.name, { verifyJwt: e.verifyJwt, at: e.dir });
  for (const c of sql.cron.values()) node(`cron:${c.name}`, 'cron', c.name, { schedule: c.schedule, at: `${c.file}:${c.line}` });

  // Code edges
  const invoked = new Map();
  const buckets = new Map();
  const push = (m, k, v) => { if (!m.has(k)) m.set(k, []); m.get(k).push(v); };
  for (const c of code.calls) {
    const caller = callerOf(c.file);
    if (caller.id.startsWith('file:')) node(caller.id, 'file', c.file, { side: caller.side });
    const at = `${c.file}:${c.line}`;
    if (c.kind === 'rpc') {
      node(`fn:${c.name}`, 'function', c.name, nodes.has(`fn:${c.name}`) ? {} : { missing: true });
      edge(caller.id, `fn:${c.name}`, 'rpc', c.confidence, at);
    } else if (c.kind === 'table') {
      if (!nodes.has(`table:${c.name}`)) node(`table:${c.name}`, 'table', c.name, { missing: true });
      edge(caller.id, `table:${c.name}`, 'from', c.confidence, at, c.op);
    } else if (c.kind === 'invoke') {
      if (!nodes.has(`edge:${c.name}`)) node(`edge:${c.name}`, 'edge_function', c.name, { missing: true });
      edge(caller.id, `edge:${c.name}`, 'invoke', c.confidence, at);
      push(invoked, c.name, at);
    } else if (c.kind === 'bucket') {
      node(`bucket:${c.name}`, 'bucket', c.name);
      edge(caller.id, `bucket:${c.name}`, 'storage', c.confidence, at, c.op);
      push(buckets, c.name, at);
    }
  }

  // SQL edges (all inferred: found by text search in SQL bodies)
  const fnNames = new Set([...sql.functions.keys()]);
  const sqlCalled = new Map(); // fn -> [referrer]
  const sqlInvoked = new Map(); // edge fn -> [referrer]
  const refsFrom = (srcId, text, at, kind, self) => {
    const r = sqlRefs(text, fnNames);
    for (const f of r.fns) if (f !== self) { edge(srcId, `fn:${f}`, kind, 'inferred', at); push(sqlCalled, f, srcId); }
    for (const e of r.edges) {
      if (!nodes.has(`edge:${e}`)) node(`edge:${e}`, 'edge_function', e, { missing: true });
      edge(srcId, `edge:${e}`, 'http', 'inferred', at); push(sqlInvoked, e, srcId);
    }
  };
  for (const f of fns.values()) refsFrom(`fn:${f.name}`, f.body, `${f.file}:${f.line}`, 'sql-call', f.name);
  for (const v of sql.views.values()) refsFrom(`table:${v.name}`, v.text, `${v.file}:${v.line}`, 'view-uses', null);
  for (const t of sql.tables.values()) {
    refsFrom(`table:${t.name}`, t.text, `${t.file}:${t.line}`, 'default-uses', null);
    for (const p of t.policies.values()) refsFrom(`table:${t.name}`, p.text, `${p.file}:${p.line}`, 'policy-uses', null);
  }
  for (const tr of sql.triggers.values()) {
    const src = tr.table === '(event)' ? `fn:${tr.fn}` : `table:${tr.table}`;
    if (sql.functions.has(tr.fn)) { edge(src, `fn:${tr.fn}`, 'trigger', 'extracted', `${tr.file}:${tr.line}`); push(sqlCalled, tr.fn, `trigger:${tr.name}`); }
  }
  if (sql.dynamic.length) {
    // DO blocks with EXECUTE may create policies/triggers we cannot see; count their references (conservative).
    node('sql:dynamic', 'cron', 'DO blocks (dynamic SQL)', { at: `${sql.dynamic.length} block(s)` });
    for (const d of sql.dynamic) refsFrom('sql:dynamic', d.text, `${d.file}:${d.line}`, 'dynamic-sql', null);
  }
  for (const c of sql.cron.values()) refsFrom(`cron:${c.name}`, c.command, `${c.file}:${c.line}`, 'cron', null);

  // Findings
  const graph = makeGraph([...nodes.values()], [...edges.values()]);
  const suppress = makeSuppressor(cfg, [...code.hatches.suppress, ...sql.hatches.suppress]);
  const ran = runRules([...coreRules, ...plugins], { graph, catalog: sql, config: cfg, root }, suppress);

  const info = {
    storage_buckets: [...buckets.entries()].map(([id, at]) => ({ id, sites: at.length, at: at[0] })),
    unresolved_dynamic_calls: code.unresolved,
    unparsed_sql: sql.unparsed,
    unreadable_files: code.failed,
    invalid_hatches: [...code.hatches.invalid, ...sql.hatches.invalid],
  };

  const stats = {
    files_scanned: files.length,
    call_sites: code.calls.length,
    distinct_rpcs_called: { client: distinct(code.calls, 'rpc', callerOf, 'client'), edge: distinct(code.calls, 'rpc', callerOf, 'edge') },
    distinct_tables_touched: { client: distinct(code.calls, 'table', callerOf, 'client'), edge: distinct(code.calls, 'table', callerOf, 'edge') },
    distinct_edge_functions_invoked: invoked.size,
    unresolved: code.unresolved.length,
    migrations: sql.stats.files,
    sql_statements: sql.stats.statements,
    sql_unparsed: sql.unparsed.length,
    tables: sql.tables.size, views: sql.views.size, functions: sql.functions.size,
    policies: [...sql.tables.values()].reduce((a, t) => a + t.policies.size, 0),
    cron_jobs: sql.cron.size, edge_functions: edgeFns.length,
  };

  return {
    schema_version: SCHEMA_VERSION,
    generated_at: new Date().toISOString(),
    root: path.basename(root),
    stats,
    rules: ran.rules,
    counts: Object.fromEntries(ran.rules.map((r) => [r.id, ran.findings.filter((f) => f.rule === r.id).length])),
    findings: ran.findings,
    suppressed: ran.suppressed,
    info,
    nodes: [...nodes.values()],
    edges: [...edges.values()],
  };
}

function distinct(calls, kind, callerOf, side) {
  return new Set(calls.filter((c) => c.kind === kind && callerOf(c.file).side === side).map((c) => c.name)).size;
}
