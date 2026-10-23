// Build the graph and findings from code, SQL and edge-function scans.
import path from 'node:path';
import { loadConfig, findFiles } from './config.js';
import { scanFiles } from './scan-code.js';
import { scanMigrations, sqlRefs, roleClosure, grantModel } from './scan-sql.js';
import { fromMigrations, schemaOf } from './catalog.js';
import { readCatalog, fromDb } from './db.js';
import { listEdgeFunctions } from './edge-functions.js';
import { resolveProject } from './supabase-project.js';
import { coreRules } from './rules/core.js';
import { loadPlugins, runRules, makeGraph, RuleError } from './engine.js';

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
  const warnings = [];
  let plugins = opts.rules;
  if (!plugins) {
    const listed = cfg.plugins || [];
    if (listed.length && !opts.allowPlugins) {
      if (!opts.noPlugins) {
        throw new RuleError(`config lists ${listed.length} plugin(s), which run as code with your environment: plugins are disabled unless you pass --allow-plugins (only in trusted runs; never on pull requests from forks). Pass --no-plugins to run without them.`);
      }
      warnings.push(`${listed.length} plugin(s) in the config were not loaded (--no-plugins).`);
      plugins = [];
    } else plugins = await loadPlugins(cfg._dir || root, listed, { root });
  }
  const project = resolveProject(root, cfg);
  const files = findFiles(root, cfg.include, cfg.exclude, { outputDirs: cfg.outputDirs || [] });
  const code = scanFiles(root, files, cfg.wrappers);
  // Grant model: config, else config.toml [api] auto_expose_new_tables, else legacy (the conservative choice).
  const tomlExpose = project.toml && project.toml.api && typeof project.toml.api.auto_expose_new_tables === 'boolean' ? project.toml.api.auto_expose_new_tables : null;
  const model = grantModel(cfg.supabaseDefaultGrants != null ? cfg.supabaseDefaultGrants : tomlExpose === false ? 'opt-in' : 'legacy');
  const modelSource = cfg.supabaseDefaultGrants != null ? 'config' : tomlExpose != null ? `${project.configToml} [api] auto_expose_new_tables` : 'default';
  const sql = scanMigrations(path.join(root, project.migrations), { supabaseDefaultGrants: model, relDir: project.migrations, root });
  const replayed = fromMigrations(sql);
  // Catalog wins over migration replay when a database is given; migrations still supply file:line.
  const catalog = opts.dbUrl ? fromDb(readCatalog(opts.dbUrl, opts.dbExec ? { exec: opts.dbExec, root } : { root }), replayed) : replayed;
  const edgeFns = listEdgeFunctions(root, project.functionsDir, project.toml, project.supabaseDir);
  const edgeNames = new Set(edgeFns.map((e) => e.name));
  const fnPrefix = project.functionsDir.replace(/\/$/, '') + '/';

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

  // Schema nodes
  const members = new Map(Object.entries(catalog.members || {}).map(([k, v]) => [k, new Set(v)]));
  const clientRoles = new Set([...roleClosure(members, 'anon'), ...roleClosure(members, 'authenticated')]);
  /** Privileges anon or authenticated hold (union), or undefined when unknown. */
  const clientPrivs = (g) => (g ? [...new Set([...(g.anon || []), ...(g.authenticated || [])])].sort() : undefined);
  for (const t of catalog.tables) {
    const permissive = t.policies.filter((p) => p.permissive !== false && (p.roles || ['public']).some((r) => clientRoles.has(r))).length;
    node(`table:${t.name}`, 'table', t.name, {
      schema: t.schema, rls: t.rls, policies: t.policies.length, clientPolicies: permissive, defined: !t.external, at: t.at,
      ...(t.grants !== undefined ? { clientPrivs: clientPrivs(t.grants) } : {}),
      ...(t.partition ? { partition: true } : {}), ...(t.rlsUncertain ? { rlsUncertain: t.rlsUncertain } : {}),
    });
  }
  const rlsTables = new Map(catalog.tables.filter((t) => t.rls).map((t) => [t.name, t]));
  for (const v of catalog.views) {
    // Tables the view reads that have RLS: an owner-rights view returns their rows without it.
    const reads = [...rlsTables.keys()].filter((name) => new RegExp(String.raw`(^|[^\w$."])` + (name.includes('.') ? '' : String.raw`(?:public\s*\.\s*)?`) + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + String.raw`(?![\w$])`, 'i').test(v.text || ''));
    node(`table:${v.name}`, 'view', v.name, { schema: v.schema, securityInvoker: v.securityInvoker, materialized: v.materialized || undefined, readsRls: reads.length ? reads : undefined, at: v.at,
      ...(v.grants !== undefined ? { clientPrivs: clientPrivs(v.grants) } : {}) });
  }
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
  for (const e of edgeFns) node(`edge:${e.name}`, 'edge_function', e.name, { verifyJwt: e.verifyJwt, at: e.entry });
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
    for (const e of edgeFns) if (e.verifyJwt === false) entries.push({ name: e.name, reason: `verify_jwt = false in ${project.configToml}: assumed to be called from outside (webhook, callback, health check)`, source: project.configToml, confidence: 'inferred' });
  }
  const entryByName = new Map();
  for (const ep of entries) if (!entryByName.has(ep.name)) entryByName.set(ep.name, ep);
  if (entryByName.size) node('external:http', 'external', 'external callers');
  for (const ep of entryByName.values()) {
    node(`edge:${ep.name}`, 'edge_function', ep.name, { entryPoint: ep.reason });
    edge('external:http', `edge:${ep.name}`, 'entry-point', ep.confidence, ep.source);
  }

  for (const c of catalog.cron) node(`cron:${c.name}`, 'cron', c.name, { schedule: c.schedule, at: c.at, ...(c.active === false ? { active: false } : {}) });
  for (const b of catalog.buckets || []) node(`bucket:${b.name}`, 'bucket', b.name, { public: b.public });

  // Code edges. Calls through a service_role / secret-key client get a `-service` relation: they are
  // callers, but they bypass grants and RLS, so they neither justify an anon/authenticated grant nor
  // make a table "client-touched". Calls on a receiver that may not be Supabase (`weak`) only link to
  // objects that exist and never create missing-* findings.
  const invoked = new Map();
  const buckets = new Map();
  const push = (m, k, v) => { if (!m.has(k)) m.set(k, []); m.get(k).push(v); };
  const rel = (base, c) => (c.privileged ? `${base}-service` : base);
  const fnByBare = new Map();
  for (const f of catalog.functions) { const b = f.name.split('.').pop(); if (!fnByBare.has(b)) fnByBare.set(b, []); fnByBare.get(b).push(`fn:${f.key}`); }
  const tableExists = (n) => nodes.has(`table:${n}`) && !nodes.get(`table:${n}`).missing;
  const selects = [];
  for (const c of code.calls) {
    const caller = callerOf(c.file);
    const at = `${c.file}:${c.line}`;
    const fileNode = () => { if (caller.id.startsWith('file:')) node(caller.id, 'file', c.file, { side: caller.side }); };
    if (c.kind === 'select') { selects.push({ c, caller, at }); continue; }
    if (c.kind === 'rpc') {
      const targets = c.anySchema ? (fnByBare.get(c.name.split('.').pop()) || []) : (c.weak ? fnIdsByName.get(c.name) || [] : fnTargets(c.name));
      if (targets.length) fileNode();
      for (const t of targets) edge(caller.id, t, rel('rpc', c), c.weak ? 'ambiguous' : c.confidence, at);
    } else if (c.kind === 'table') {
      if (c.weak || c.anySchema) {
        if (!tableExists(c.name)) continue;
        fileNode();
        edge(caller.id, `table:${c.name}`, 'from-weak', 'ambiguous', at, c.op);
        continue;
      }
      fileNode();
      if (!nodes.has(`table:${c.name}`)) node(`table:${c.name}`, 'table', c.name, { schema: schemaOf(c.name), missing: true });
      edge(caller.id, `table:${c.name}`, rel('from', c), c.confidence, at, c.op);
    } else if (c.kind === 'invoke') {
      fileNode();
      if (!nodes.has(`edge:${c.name}`)) node(`edge:${c.name}`, 'edge_function', c.name, { missing: true });
      edge(caller.id, `edge:${c.name}`, rel('invoke', c), c.confidence, at);
      push(invoked, c.name, at);
    } else if (c.kind === 'bucket') {
      fileNode();
      if (!nodes.has(`bucket:${c.name}`)) node(`bucket:${c.name}`, 'bucket', c.name, catalog.buckets ? { missing: true } : {});
      edge(caller.id, `bucket:${c.name}`, rel('storage', c), c.confidence, at, c.op);
      push(buckets, c.name, at);
    }
  }
  // PostgREST select(): embedded relations are table reads; computed fields and computed
  // relationships are functions taking the row type (`f(people)`), called by name.
  const fnArgsMention = (id, table) => { const n = nodes.get(id); return !!n && n.arity === 1 && new RegExp(String.raw`(^|[\s."])` + table.split('.').pop() + String.raw`("|\s|$|\[)`, 'i').test(n.args || ''); };
  for (const { c, caller, at } of selects) {
    const q = c.schema && c.schema !== 'public' && c.schema !== '*' ? `${c.schema}.` : '';
    const name = q + c.name;
    const fns = (fnIdsByName.get(name) || []).filter((id) => (c.base ? fnArgsMention(id, c.base) : nodes.get(id).arity === 1));
    if (c.embed && tableExists(name)) {
      if (caller.id.startsWith('file:')) node(caller.id, 'file', c.file, { side: caller.side });
      edge(caller.id, `table:${name}`, rel('from', c), 'inferred', at, 'embed');
    } else if (fns.length) {
      if (caller.id.startsWith('file:')) node(caller.id, 'file', c.file, { side: caller.side });
      for (const t of fns) edge(caller.id, t, rel('rpc', c), 'inferred', at);
    }
  }
  // Dynamic names with a known shape (`fn_${x}`, `'report-' + kind`): ambiguous links to every match.
  for (const u of code.unresolved) {
    if (!u.pattern) continue;
    const re = new RegExp(u.pattern);
    const caller = callerOf(u.file);
    const targets = u.kind === 'rpc' ? catalog.functions.filter((f) => re.test(f.name.split('.').pop())).map((f) => `fn:${f.key}`)
      : u.kind === 'invoke' ? edgeFns.filter((e) => re.test(e.name)).map((e) => `edge:${e.name}`) : [];
    if (targets.length && caller.id.startsWith('file:')) node(caller.id, 'file', u.file, { side: caller.side });
    for (const t of targets) edge(caller.id, t, u.kind === 'rpc' ? 'rpc' : 'invoke', 'ambiguous', `${u.file}:${u.line}`);
  }
  // Auth hooks in config.toml call a Postgres function (pg-functions://) or an edge function (HTTP).
  const hooks = [];
  for (const [hname, h] of Object.entries((project.toml && project.toml.auth && project.toml.auth.hook) || {})) {
    if (!h || typeof h.uri !== 'string' || h.enabled === false) continue;
    const pg = /^pg-functions:\/\/[^/]+\/([^/]+)\/([^/?#]+)/.exec(h.uri);
    const http = /\/functions\/v1\/([A-Za-z0-9_-]+)/.exec(h.uri);
    const at = `${project.configToml}:[auth.hook.${hname}]`;
    if (pg) {
      const name = pg[1] === 'public' ? pg[2] : `${pg[1]}.${pg[2]}`;
      for (const t of fnIdsByName.get(name) || []) { node('external:auth', 'external', 'Supabase Auth hooks'); edge('external:auth', t, 'auth-hook', 'extracted', at); hooks.push({ hook: hname, node: t }); }
    } else if (http) {
      node('external:auth', 'external', 'Supabase Auth hooks');
      if (!nodes.has(`edge:${http[1]}`)) node(`edge:${http[1]}`, 'edge_function', http[1], { missing: true });
      edge('external:auth', `edge:${http[1]}`, 'auth-hook', 'extracted', at);
    }
  }

  // SQL edges (all inferred: found by text search in SQL bodies)
  const fnNames = new Set(fnIdsByName.keys());
  const refsFrom = (srcId, text, at, kind, self, ownSchema) => {
    const r = sqlRefs(text || '', fnNames, ownSchema);
    for (const f of r.fns) for (const t of fnIdsByName.get(f)) if (t !== self) edge(srcId, t, kind, 'inferred', at);
    for (const e of r.edges) {
      if (!nodes.has(`edge:${e}`)) node(`edge:${e}`, 'edge_function', e, { missing: true });
      edge(srcId, `edge:${e}`, 'http', 'inferred', at);
    }
  };
  for (const f of catalog.functions) refsFrom(`fn:${f.key}`, f.body, f.at, 'sql-call', `fn:${f.key}`, f.schema);
  for (const v of catalog.views) refsFrom(`table:${v.name}`, v.text, v.at, 'view-uses', null);
  for (const t of catalog.tables) {
    refsFrom(`table:${t.name}`, t.text, t.at, 'default-uses', null);
    if (t.indexText) refsFrom(`table:${t.name}`, t.indexText, t.at, 'index-uses', null);
    for (const p of t.policies) refsFrom(`table:${t.name}`, p.text, p.at, 'policy-uses', null);
  }
  for (const tr of catalog.triggers) {
    // Database webhooks: supabase_functions.http_request('https://.../functions/v1/<name>', ...)
    if (tr.text && tr.table !== '(event)') for (const e of sqlRefs(tr.text, new Set()).edges) {
      if (!nodes.has(`edge:${e}`)) node(`edge:${e}`, 'edge_function', e, { missing: true });
      edge(`table:${tr.table}`, `edge:${e}`, 'webhook', 'extracted', tr.at);
    }
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
  const ran = runRules([...coreRules, ...plugins], { graph, catalog, config: cfg, root, unresolved: code.unresolved, hooks }, suppress);

  const info = {
    storage_buckets: [...buckets.entries()].map(([id, at]) => ({ id, sites: at.length, at: at[0] })),
    unresolved_dynamic_calls: code.unresolved,
    unparsed_sql: catalog.source === 'migrations' ? catalog.unparsed : [],
    dynamic_sql_applied: catalog.source === 'migrations' ? sql.dynamicApplied : [],
    unreadable_files: code.failed,
    parse_errors: code.parseErrors,
    skipped_migrations: sql.skipped,
    external_entry_points: [...entryByName.values()].map(({ name, reason, source }) => ({ id: name, reason, source })),
    invalid_hatches: [...code.hatches.invalid, ...sql.hatches.invalid, ...entryInvalid],
  };

  for (const f of ran.findings) f.source = f.source || catalog.source;
  warnings.push(...(catalog.notes || []));
  const risky = catalog.unparsed.filter((u) => u.risky);
  if (catalog.source === 'migrations' && risky.length) {
    warnings.push(`${risky.length} migration statement(s) the parser did not apply change grants, role membership, policies or RLS `
      + `(first: ${risky[0].file}:${risky[0].line}). Findings that depend on grants and policies may be wrong; `
      + 'run with --db-url against a database built from these migrations to use the real catalog.');
  }

  // Loud failures: an empty side of the analysis makes every "nothing calls" finding meaningless.
  const scope_problems = [];
  if (!files.length) scope_problems.push(`0 code files matched \`include\` (${cfg.include.join(', ')}); every "nothing calls" finding is meaningless. Set "include" in supareach.config.json.`);
  else if (!code.calls.length && !code.unresolved.length) scope_problems.push(`${files.length} code files scanned but 0 Supabase call sites found; check "include" and that the code uses supabase-js.`);
  if (catalog.source === 'migrations' && !catalog.stats.migrations) scope_problems.push(`0 migrations found in ${project.migrations}; the schema side is empty. Set "supabaseDir" or "migrations", or use --db-url.`);
  warnings.unshift(...scope_problems);
  const failedFiles = [...code.failed, ...code.parseErrors];
  if (failedFiles.length) warnings.push(`${failedFiles.length} code file(s) could not be parsed completely (first: ${failedFiles[0].file}: ${failedFiles[0].error}); calls in them may be missing.`);
  if (sql.skipped.length) warnings.push(`${sql.skipped.length} file(s) in ${project.migrations} skipped (first: ${sql.skipped[0].file}: ${sql.skipped[0].reason}).`);

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
    rpcs_called_by_code: graph.nodes.filter((n) => n.type === 'function' && !n.missing && graph.incoming(n.id).some((e) => e.relation === 'rpc')).length,
  };

  return {
    schema_version: SCHEMA_VERSION,
    generated_at: new Date().toISOString(),
    root: path.basename(root),
    source: catalog.source,
    project: { grantModel: { model: model || 'vanilla', source: modelSource, ...(catalog.meta && catalog.meta.default_grants ? { live: catalog.meta.default_grants } : {}) }, supabaseDir: project.supabaseDir, how: project.how, migrations: project.migrations, functionsDir: project.functionsDir, configToml: project.toml ? project.configToml : null, codeRoots: codeRoots(files) },
    scope_problems,
    ...(catalog.meta ? { database: catalog.meta } : {}),
    warnings,
    stats,
    rules: ran.rules,
    counts: Object.fromEntries(ran.rules.map((r) => [r.id, ran.findings.filter((f) => f.rule === r.id).length])),
    findings: ran.findings,
    suppressed: ran.suppressed,
    info,
    // Graph section: networkx node-link format (Graphify-compatible): nodes, links, relation, confidence.
    directed: true,
    multigraph: false,
    graph: { name: path.basename(root), tool: 'supareach' },
    nodes: [...nodes.values()],
    links: [...edges.values()],
  };
}

/** Top-level directories the scanned files live in, with counts: [{ dir, files }]. */
function codeRoots(files) {
  const m = new Map();
  for (const f of files) { const i = f.indexOf('/'); const d = i < 0 ? '.' : f.slice(0, i); m.set(d, (m.get(d) || 0) + 1); }
  return [...m].sort((a, b) => b[1] - a[1]).map(([dir, n]) => ({ dir, files: n }));
}

function distinct(calls, kind, callerOf, side) {
  return new Set(calls.filter((c) => c.kind === kind && callerOf(c.file).side === side).map((c) => c.name)).size;
}
