// Example plugin: a project-specific rule on the same contract as the core rules.
// Loaded through "plugins" in supareach.config.json. Findings from it are baselined,
// ignored and reported exactly like core findings.
export const rules = [
  {
    id: 'demo/client-writes-protected-table',
    level: 'error',
    title: 'Client code writes to a table that only the server should write',
    why: 'Tables listed in `protectedTables` in the config hold records the browser must not change (audit trails, money). Write them from an edge function or a SECURITY DEFINER function instead.',
    run({ graph, config }) {
      const protectedTables = new Set(config.protectedTables || []);
      const out = [];
      for (const e of graph.edges) {
        const from = graph.node(e.source);
        const to = graph.node(e.target);
        if (e.kind !== 'from' || !from || from.side !== 'client' || !to || !protectedTables.has(to.label)) continue;
        const writes = e.ops.filter((op) => ['insert', 'update', 'upsert', 'delete'].includes(op));
        if (writes.length) out.push({ id: to.label, node: to.id, at: e.at[0], message: `${writes.join('/')} from ${from.label}` });
      }
      return out;
    },
  },
];
