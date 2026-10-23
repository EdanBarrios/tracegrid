// Core rules, written against the same contract as plugins (see src/engine.js).

const isClientFrom = (graph) => (e) => e.relation === 'from' && (graph.node(e.source) || {}).side === 'client';

/** Tables the client (code outside edge functions) queries: Map id -> { at, sites }. */
function clientTables(graph) {
  const m = new Map();
  const f = isClientFrom(graph);
  for (const e of graph.links) if (f(e)) { if (!m.has(e.target)) m.set(e.target, { at: [], sites: 0 }); const x = m.get(e.target); x.at.push(...e.at); x.sites += e.count; }
  return m;
}

/** Can anon or authenticated reach the relation at all? Unknown grants count as reachable. */
const reachable = (n) => !Array.isArray(n.clientPrivs) || n.clientPrivs.length > 0;
const callers = (graph, id) => graph.incoming(id).filter((e) => e.source !== id);
/** Callers that justify a grant to anon/authenticated: everything except service_role / secret-key clients. */
const roleCallers = (graph, id) => callers(graph, id).filter((e) => !e.relation.endsWith('-service'));
const exposed = (config) => new Set(config.exposedSchemas || ['public']);
/** Functions in an exposed schema that anon or authenticated can execute. */
const grantedFunctions = (graph, config) => graph.nodes.filter((n) => n.type === 'function' && !n.missing && n.kind === 'function'
  && !n.triggerOnly && exposed(config).has(n.schema || 'public') && (n.anon || n.authenticated));
/**
 * Unresolved (dynamic-name) call sites of a kind that could reach `name`. A site with a known
 * name pattern (`fn_${x}`) only counts for names matching it.
 */
const couldReach = (unresolved = [], kind, name) => unresolved.filter((u) => u.kind === kind && (!u.pattern || new RegExp(u.pattern).test(name)));
/** Downgrade a "nothing calls" error to a warning, with an explanation, when dynamic call sites could reach it. */
function caveat(f, sites, what) {
  if (!sites.length) return f;
  const first = sites[0];
  return { ...f, level: f.level === 'note' ? 'note' : 'warning', note: `${sites.length} unresolved ${what} call site(s) with a dynamic name could reach it (first: ${first.file}:${first.line}); check them before revoking` };
}
/**
 * SECURITY INVOKER and callable by authenticated only: runs with the caller's privileges, so RLS and
 * grants still apply; a warning. SECURITY DEFINER, or callable by anon (no sign-in): an error.
 */
function severity(f, n) {
  if (n.securityDefiner || n.anon) return { ...f, level: 'error' };
  return { ...f, level: 'warning', note: 'SECURITY INVOKER, authenticated only: runs with the caller\'s privileges' };
}
/** Relations through which the calling role itself executes the helper (so it needs EXECUTE). */
const NEEDS_GRANT = new Set(['policy-uses', 'view-uses', 'default-uses', 'index-uses']);
const fnFinding = (n, extra = {}) => ({ id: n.id.slice(3), node: n.id, at: n.at, roles: ['anon', 'authenticated'].filter((r) => n[r]), securityDefiner: n.securityDefiner, ...extra });

export const coreRules = [
  {
    id: 'exposed-uncalled-function',
    level: 'error',
    title: 'Functions callable by anon/authenticated that nothing calls',
    why: 'No `.rpc()` in code, and no cron job, trigger, policy, view or other SQL function references them. Each is surface any signed-in (or anonymous) user can call through the Data API. Revoke the grant, or ignore it with a reason if a caller is coming.',
    run({ graph, config, unresolved }) {
      return grantedFunctions(graph, config).filter((n) => roleCallers(graph, n.id).length === 0)
        .map((n) => {
          const svc = callers(graph, n.id).filter((e) => e.relation.endsWith('-service'));
          const f = severity(fnFinding(n), n);
          if (svc.length) f.note = [f.note, `called only through a service_role/secret-key client (${svc[0].at[0]}), which does not need the anon/authenticated grant`].filter(Boolean).join('; ');
          return caveat(f, couldReach(unresolved, 'rpc', n.label.split('.').pop()), '.rpc()');
        });
    },
  },
  {
    id: 'granted-helper-function',
    level: 'note',
    title: 'Helper functions callable by anon/authenticated that only SQL uses',
    why: 'No `.rpc()` in code calls these, but a policy, view, trigger, cron job or other SQL function does. They are still callable directly through the Data API. A helper used by RLS policies or invoker views needs the grant; one used only by cron, triggers or SECURITY DEFINER functions usually does not.',
    run({ graph, config }) {
      return grantedFunctions(graph, config)
        .map((n) => ({ n, inc: roleCallers(graph, n.id) }))
        .filter(({ inc }) => inc.length && !inc.some((e) => e.relation === 'rpc' || e.relation === 'auth-hook'))
        .map(({ n, inc }) => {
          const usedBy = [...new Set(inc.map((e) => e.relation))].sort();
          // Does any caller run it as the requesting role? Policies, views, defaults, index expressions,
          // and SQL in non-definer functions (triggers included) do; cron and definer functions do not.
          const needsGrant = inc.some((e) => NEEDS_GRANT.has(e.relation) || ((e.relation === 'sql-call' || e.relation === 'trigger') && !(graph.node(e.source) || {}).securityDefiner));
          const f = fnFinding(n, { usedBy });
          if (n.securityDefiner && (n.anon || !needsGrant)) {
            return { ...f, level: 'warning', note: `SECURITY DEFINER and directly callable through /rpc by ${f.roles.join(', ')}${needsGrant ? '' : '; no caller needs that grant'}. Revoke it, or move the function to a schema the Data API does not expose` };
          }
          return f;
        });
    },
  },
  {
    id: 'client-table-without-rls',
    level: 'error',
    title: 'Client-touched tables with RLS off',
    why: 'App code outside edge functions queries these, and row level security is not enabled on them.',
    run({ graph }) {
      return [...clientTables(graph)].map(([id, at]) => ({ n: graph.node(id), at }))
        .filter(({ n }) => n && n.type === 'table' && !n.missing && !n.rls && !n.partition && reachable(n))
        .map(({ n, at }) => ({ id: n.label, node: n.id, at: at.at[0], sites: at.sites,
          ...(n.rlsUncertain ? { confidence: 'low', note: `low confidence: dynamic SQL at ${n.rlsUncertain} may change RLS` } : {}) }));
    },
  },
  {
    id: 'client-table-not-granted',
    level: 'warning',
    title: 'Client-touched tables that anon and authenticated have no privileges on',
    why: 'App code queries these, but neither anon nor authenticated holds SELECT, INSERT, UPDATE or DELETE on them, so the calls fail with "permission denied". Expected for tables created after Supabase stopped granting new tables to the Data API by default: add an explicit GRANT (with RLS) if the client should reach it.',
    run({ graph }) {
      return [...clientTables(graph)].map(([id, at]) => ({ n: graph.node(id), at }))
        .filter(({ n }) => n && (n.type === 'table' || n.type === 'view') && !n.missing && Array.isArray(n.clientPrivs) && !n.clientPrivs.length)
        .map(({ n, at }) => ({ id: n.label, node: n.id, at: at.at[0], sites: at.sites }));
    },
  },
  {
    id: 'client-view-without-security-invoker',
    level: 'error',
    title: 'Client-read views that bypass RLS (owner rights)',
    why: 'App code reads these views, and they run with the view owner\'s rights (no `security_invoker`, or materialized), over tables that have RLS. The owner (postgres) bypasses RLS, so every row is returned to anon/authenticated. Recreate the view `with (security_invoker = true)`, or revoke it from anon/authenticated.',
    run({ graph }) {
      return [...clientTables(graph)].map(([id, at]) => ({ n: graph.node(id), at }))
        .filter(({ n }) => n && n.type === 'view' && !n.securityInvoker && n.readsRls && reachable(n))
        .map(({ n, at }) => ({ id: n.label, node: n.id, at: at.at[0], sites: at.sites, message: `reads ${n.readsRls.join(', ')}${n.materialized ? '; materialized views never apply RLS' : ''}` }));
    },
  },
  {
    id: 'client-table-without-policies',
    level: 'warning',
    title: 'Client-touched tables with RLS on but no policy for anon/authenticated',
    why: 'RLS with no permissive policy that applies to anon, authenticated or PUBLIC denies everything to the client (restrictive policies alone, or policies only for other roles such as service_role, return no rows). Usually a bug if the client reads it.',
    run({ graph }) {
      return [...clientTables(graph)].map(([id, at]) => ({ n: graph.node(id), at }))
        .filter(({ n }) => n && n.type === 'table' && !n.missing && n.rls && !(n.clientPolicies ?? n.policies) && reachable(n))
        .map(({ n, at }) => ({ id: n.label, node: n.id, at: at.at[0], sites: at.sites }));
    },
  },
  {
    id: 'auth-hook-function-exposed',
    level: 'warning',
    title: 'Auth hook functions callable by anon/authenticated',
    why: 'Supabase Auth calls these Postgres functions (`[auth.hook.*]` in config.toml) as supabase_auth_admin; clients should not. Revoke EXECUTE from anon, authenticated and public, and grant it to supabase_auth_admin only.',
    run({ graph, hooks = [] }) {
      return hooks.map((h) => graph.node(h.node)).filter((n) => n && (n.anon || n.authenticated))
        .map((n) => fnFinding(n, { message: `revoke execute on function ${n.label}(${n.args || ''}) from anon, authenticated, public` }));
    },
  },
  {
    id: 'missing-rpc',
    level: 'error',
    title: 'RPCs called that the schema does not define',
    why: 'Either created outside migrations (dashboard), dropped, or misspelled.',
    run({ graph }) {
      return graph.nodes.filter((n) => n.type === 'function' && n.missing).map((n) => {
        const inc = graph.incoming(n.id);
        return { id: n.label, node: n.id, at: inc.flatMap((e) => e.at)[0], sites: inc.reduce((a, e) => a + e.count, 0) };
      });
    },
  },
  {
    id: 'unknown-table',
    level: 'warning',
    title: 'Tables or views referenced in code that the schema does not define',
    why: 'May live in another schema, be created outside migrations, or be misspelled.',
    run({ graph }) {
      return graph.nodes.filter((n) => n.type === 'table' && n.missing).map((n) => {
        const inc = graph.incoming(n.id);
        return { id: n.label, node: n.id, at: inc.flatMap((e) => e.at)[0], sites: inc.reduce((a, e) => a + e.count, 0) };
      });
    },
  },
  {
    id: 'uncalled-edge-function',
    level: 'warning',
    title: 'Edge functions with no caller',
    why: 'No `functions.invoke`, no `/functions/v1/<name>` URL in code, cron or SQL, and not declared as an external entry point. Webhooks, OAuth callbacks and auth hooks are legitimately uncalled: declare them in `entryPoints` or with a `// supareach: entry-point <reason>` hatch. `verify_jwt = false` functions are treated as entry points automatically (`autoEntryPoints`).',
    run({ graph, unresolved }) {
      return graph.nodes.filter((n) => n.type === 'edge_function' && !n.missing && callers(graph, n.id).length === 0)
        .map((n) => caveat({ id: n.label, node: n.id, at: n.at, note: n.verifyJwt === false ? 'verify_jwt=false (autoEntryPoints is off)' : undefined }, couldReach(unresolved, 'invoke', n.label), 'functions.invoke / URL'));
    },
  },
  {
    id: 'missing-edge-function',
    level: 'error',
    title: 'Edge functions invoked that do not exist',
    why: 'Called by name or URL, but there is no `supabase/functions/<name>/index.*`.',
    run({ graph }) {
      return graph.nodes.filter((n) => n.type === 'edge_function' && n.missing).map((n) => {
        const at = graph.incoming(n.id).flatMap((e) => e.at);
        return { id: n.label, node: n.id, at: at[0] };
      });
    },
  },
];
