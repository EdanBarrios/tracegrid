// Build the graph and findings from code, SQL and edge-function scans.
import path from 'node:path';
import { loadConfig, findFiles } from './config.js';
import { scanFiles } from './scan-code.js';
import { scanMigrations, sqlRefs } from './scan-sql.js';
import { fromMigrations, schemaOf } from './catalog.js';
import { listEdgeFunctions } from './edge-functions.js';
import { coreRules } from './rules/core.js';
import { loadPlugins, runRules, makeGraph } from './engine.js';

export const SCHEMA_VERSION = 1;

/** Config ignore list that applies to each core rule. */
const IGNORE_CATEGORY = {
  'exposed-uncalled-function': 'functions', 'granted-helper-function': 'functions',
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
  const catalog = fromMigrations(sql);
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
  for (const t of catalog.tables) node(`table:${t.name}`, 'table', t.name, { schema: t.schema, rls: t.rls, policies: t.policies.length, defined: !t.external, at: t.at });
  for (const v of catalog.views) node(`table:${v.name}`, 'view', v.name, { schema: v.schema, securityInvoker: v.securityInvoker, at: v.at });
  const fnIdsByName = new Map();
  for (const f of catalog.functions) {
    node(`fn:${f.key}`, 'function', f.name, {
      schema: f.schema, arity: f.arity, kind: f.kind, triggerOnly: f.triggerOnly || undefined, securityDefiner: f.securityDefiner,
      returns: f.returns, args: f.args, anon: f.anon, authenticated: f.authenticated, at: f.at,
      signatures: f.signatures.length > 1 ? f.signatures : undefined,
    });
    if (!fnIdsByName.has(f.name)) fnIdsByName.set(f.name, []);
    fnIdsByName.get(f.name).push(`fn:${f.key}`);
  }
  /** Node ids for a function name: every arity, or one `missing` node. */
  const fnTargets = (name) => fnIdsByName.get(name) || [node(`fn:${name}`, 'function', name, { schema: schemaOf(name), missing: true }).id];
  for (const e of edgeFns) node(`edge:${e.name}`, 'edge_function', e.name, { verifyJwt: e.verifyJwt, at: e.dir });
  // External entry points: config, `// supareach: entry-point <reason>` hatches, verify_jwt = false.
  const entries = [];
  const entryInvalid = [];
  for (const ep of cfg.entryPoints) {
    if (edgeNames.has(ep.name)) entries.push({ name: ep.name, reason: ep.reason, source: 'config', confidence: 'extracted' });
    else entryInvalid.push({ file: 'config', line: 0, error: `entryPoints: no edge function named ${ep.name}` });
  }
  for (const [file, hs] of code.hatches.byFile) {
    for (const h of hs.filter((x) => x.directive === 'entry-point' && !x.error)) {
      const dir = file.startsWith(fnPrefix) ? file.slice(fnPrefix.length).split('/')[0] : null;
      if (dir && edgeNames.has(dir)) entries.push({ name: dir, reason: h.reason, source: `hatch ${file}:${h.line}`, confidence: 'extracted' });
      else entryInvalid.push({ file, line: h.line, error: 'entry-point: only valid inside an edge function directory' });
    }
  }
  if (cfg.autoEntryPoints) {
    for (const e of edgeFns) if (e.verifyJwt === false) entries.push({ name: e.name, reason: 'verify_jwt = false in supabase/config.toml: assumed to be called from outside (webhook, callback, health check)', source: 'supabase/config.toml', confidence: 'inferred' });
  }
  const entryByName = new Map();
  for (const ep of entries) if (!entryByName.has(ep.name)) entryByName.set(ep.name, ep);
  if (entryByName.size) node('external:http', 'external', 'outside callers (webhooks, callbacks, hooks)');
  for (const ep of entryByName.values()) {
    node(`edge:${ep.name}`, 'edge_function', ep.name, { entryPoint: ep.reason });
    edge('external:http', `edge:${ep.name}`, 'entry-point', ep.confidence, ep.source);
  }

  for (const c of catalog.cron) node(`cron:${c.name}`, 'cron', c.name, { schedule: c.schedule, at: c.at });

  // Code edges
  const invoked = new Map();
  const buckets = new Map();
  const push = (m, k, v) => { if (!m.has(k)) m.set(k, []); m.get(k).push(v); };
  for (const c of code.calls) {
    const caller = callerOf(c.file);
    if (caller.id.startsWith('file:')) node(caller.id, 'file', c.file, { side: caller.side });
    const at = `${c.file}:${c.line}`;
    if (c.kind === 'rpc') {
      for (const t of fnTargets(c.name)) edge(caller.id, t, 'rpc', c.confidence, at);
    } else if (c.kind === 'table') {
      if (!nodes.has(`table:${c.name}`)) node(`table:${c.name}`, 'table', c.name, { schema: schemaOf(c.name), missing: true });
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
  const fnNames = new Set(fnIdsByName.keys());
  const refsFrom = (srcId, text, at, kind, self) => {
    const r = sqlRefs(text, fnNames);
    for (const f of r.fns) for (const t of fnIdsByName.get(f)) if (t !== self) edge(srcId, t, kind, 'inferred', at);
    for (const e of r.edges) {
      if (!nodes.has(`edge:${e}`)) node(`edge:${e}`, 'edge_function', e, { missing: true });
      edge(srcId, `edge:${e}`, 'http', 'inferred', at);
    }
  };
  for (const f of catalog.functions) refsFrom(`fn:${f.key}`, f.body, f.at, 'sql-call', `fn:${f.key}`);
  for (const v of catalog.views) refsFrom(`table:${v.name}`, v.text, v.at, 'view-uses', null);
  for (const t of catalog.tables) {
    refsFrom(`table:${t.name}`, t.text, t.at, 'default-uses', null);
    for (const p of t.policies) refsFrom(`table:${t.name}`, p.text, p.at, 'policy-uses', null);
  }
  for (const tr of catalog.triggers) {
    for (const t of fnIdsByName.get(tr.fn) || []) {
      const src = tr.table === '(event)' ? t : `table:${tr.table}`;
      if (src !== t) edge(src, t, 'trigger', 'extracted', tr.at);
      else edge('sql:event-trigger', t, 'trigger', 'extracted', tr.at);
    }
  }
  if (nodes.size && [...edges.values()].some((e) => e.source === 'sql:event-trigger')) node('sql:event-trigger', 'cron', 'event triggers');
  if (catalog.dynamic.length) {
    // DO blocks with EXECUTE may create policies/triggers we cannot see; count their references (conservative).
    node('sql:dynamic', 'cron', 'DO blocks (dynamic SQL)', { at: `${catalog.dynamic.length} block(s)` });
    for (const d of catalog.dynamic) refsFrom('sql:dynamic', d.text, d.at, 'dynamic-sql', null);
  }
  for (const c of catalog.cron) refsFrom(`cron:${c.name}`, c.command, c.at, 'cron', null);

  // Findings
  const graph = makeGraph([...nodes.values()], [...edges.values()]);
  const suppress = makeSuppressor(cfg, [...code.hatches.suppress, ...sql.hatches.suppress]);
  const ran = runRules([...coreRules, ...plugins], { graph, catalog, config: cfg, root }, suppress);

  const info = {
    storage_buckets: [...buckets.entries()].map(([id, at]) => ({ id, sites: at.length, at: at[0] })),
    unresolved_dynamic_calls: code.unresolved,
    unparsed_sql: catalog.unparsed,
    unreadable_files: code.failed,
    external_entry_points: [...entryByName.values()].map(({ name, reason, source }) => ({ id: name, reason, source })),
    invalid_hatches: [...code.hatches.invalid, ...sql.hatches.invalid, ...entryInvalid],
  };

  const stats = {
    files_scanned: files.length,
    call_sites: code.calls.length,
    distinct_rpcs_called: { client: distinct(code.calls, 'rpc', callerOf, 'client'), edge: distinct(code.calls, 'rpc', callerOf, 'edge') },
    distinct_tables_touched: { client: distinct(code.calls, 'table', callerOf, 'client'), edge: distinct(code.calls, 'table', callerOf, 'edge') },
    distinct_edge_functions_invoked: invoked.size,
    unresolved: code.unresolved.length,
    migrations: catalog.stats.migrations,
    sql_statements: catalog.stats.statements,
    sql_unparsed: catalog.unparsed.length,
    tables: catalog.tables.length, views: catalog.views.length, functions: catalog.functions.length,
    policies: catalog.tables.reduce((a, t) => a + t.policies.length, 0),
    cron_jobs: catalog.cron.length, edge_functions: edgeFns.length,
    rpcs_called_by_code: graph.nodes.filter((n) => n.type === 'function' && !n.missing && graph.incoming(n.id).some((e) => e.kind === 'rpc')).length,
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
