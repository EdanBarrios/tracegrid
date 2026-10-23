// Core rules, written against the same contract as plugins (see src/engine.js).

const isClientFrom = (graph) => (e) => e.relation === 'from' && (graph.node(e.source) || {}).side === 'client';

/** Tables the client (code outside edge functions) queries: Map id -> { at, sites }. */
function clientTables(graph) {
  const m = new Map();
  const f = isClientFrom(graph);
  for (const e of graph.links) if (f(e)) { if (!m.has(e.target)) m.set(e.target, { at: [], sites: 0 }); const x = m.get(e.target); x.at.push(...e.at); x.sites += e.count; }
  return m;
}

const callers = (graph, id) => graph.incoming(id).filter((e) => e.source !== id);
const exposed = (config) => new Set(config.exposedSchemas || ['public']);
/** Functions in an exposed schema that anon or authenticated can execute. */
const grantedFunctions = (graph, config) => graph.nodes.filter((n) => n.type === 'function' && !n.missing && n.kind === 'function'
  && !n.triggerOnly && exposed(config).has(n.schema || 'public') && (n.anon || n.authenticated));
const fnFinding = (n, extra = {}) => ({ id: n.id.slice(3), node: n.id, at: n.at, roles: ['anon', 'authenticated'].filter((r) => n[r]), securityDefiner: n.securityDefiner, ...extra });

export const coreRules = [
  {
    id: 'exposed-uncalled-function',
    level: 'error',
    title: 'Functions callable by anon/authenticated that nothing calls',
    why: 'No `.rpc()` in code, and no cron job, trigger, policy, view or other SQL function references them. Each is surface any signed-in (or anonymous) user can call through the Data API. Revoke the grant, or ignore it with a reason if a caller is coming.',
    run({ graph, config }) {
      return grantedFunctions(graph, config).filter((n) => callers(graph, n.id).length === 0).map((n) => fnFinding(n));
    },
  },
  {
    id: 'granted-helper-function',
    level: 'note',
    title: 'Helper functions callable by anon/authenticated that only SQL uses',
    why: 'No `.rpc()` in code calls these, but a policy, view, trigger, cron job or other SQL function does. They are still callable directly through the Data API. A helper used by RLS policies or invoker views needs the grant; one used only by cron, triggers or SECURITY DEFINER functions usually does not.',
    run({ graph, config }) {
      return grantedFunctions(graph, config)
        .map((n) => ({ n, inc: callers(graph, n.id) }))
        .filter(({ inc }) => inc.length && !inc.some((e) => e.relation === 'rpc'))
        .map(({ n, inc }) => fnFinding(n, { usedBy: [...new Set(inc.map((e) => e.relation))].sort() }));
    },
  },
  {
    id: 'client-table-without-rls',
    level: 'error',
    title: 'Client-touched tables with RLS off',
    why: 'App code outside edge functions queries these, and row level security is not enabled on them.',
    run({ graph }) {
      return [...clientTables(graph)].map(([id, at]) => ({ n: graph.node(id), at }))
        .filter(({ n }) => n && n.type === 'table' && !n.missing && !n.rls)
        .map(({ n, at }) => ({ id: n.label, node: n.id, at: at.at[0], sites: at.sites }));
    },
  },
  {
    id: 'client-table-without-policies',
    level: 'warning',
    title: 'Client-touched tables with RLS on but no policies',
    why: 'RLS with no policy denies everything to anon and authenticated. Usually a bug if the client reads it.',
    run({ graph }) {
      return [...clientTables(graph)].map(([id, at]) => ({ n: graph.node(id), at }))
        .filter(({ n }) => n && n.type === 'table' && !n.missing && n.rls && !n.policies)
        .map(({ n, at }) => ({ id: n.label, node: n.id, at: at.at[0], sites: at.sites }));
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
    run({ graph }) {
      return graph.nodes.filter((n) => n.type === 'edge_function' && !n.missing && callers(graph, n.id).length === 0)
        .map((n) => ({ id: n.label, node: n.id, at: n.at, note: n.verifyJwt === false ? 'verify_jwt=false (autoEntryPoints is off)' : undefined }));
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
