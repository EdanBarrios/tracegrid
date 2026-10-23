// One schema shape for every source. Migration replay (src/scan-sql.js) and the live catalog
// (src/db.js) both produce it; analyze.js and rules only ever see this shape.
//
// Functions are keyed by name + arity (`name/2`): PostgREST and SQL references resolve by name,
// grants are per signature, and two overloads with the same arity are merged (grants OR'd), with
// every signature kept in `signatures`. The same key is used in both modes so a baseline written
// from migrations still matches a catalog run.
import { canExec, tablePrivs } from './scan-sql.js';

/** Schema part of a normalised name (`x.t` -> `x`, `t` -> `public`). */
export const schemaOf = (name) => (name.includes('.') ? name.split('.')[0] : 'public');

const loc = (o) => (o.file ? `${o.file}:${o.line}` : undefined);

/** Number of input arguments in a normalised signature string from sigOf(). */
export const arityOf = (sig) => (sig ? sig.split(',').length : 0);

/** Merge per-signature rows into one entry per name/arity. */
export function groupFunctions(rows) {
  const out = new Map();
  for (const r of rows) {
    const key = `${r.name}/${r.arity}`;
    let g = out.get(key);
    if (!g) {
      g = { key, name: r.name, schema: schemaOf(r.name), arity: r.arity, signatures: [], kind: r.kind, returns: r.returns, args: r.args,
        securityDefiner: false, anon: false, authenticated: false, body: '', at: r.at, triggerOnly: true };
      out.set(key, g);
    }
    g.signatures.push(r.signature);
    g.securityDefiner ||= !!r.securityDefiner;
    g.anon ||= !!r.anon;
    g.authenticated ||= !!r.authenticated;
    g.body += (g.body ? '\n' : '') + (r.body || '');
    g.triggerOnly &&= /^(setof\s+)?(trigger|event_trigger)$/.test(r.returns || '');
    if (r.kind === 'function') g.kind = 'function';
  }
  return [...out.values()];
}

/** Catalog from the replayed migration state. */
export function fromMigrations(st) {
  const rows = [];
  const m = st.members;
  for (const f of st.functions.values()) {
    for (const ov of f.sigs.values()) {
      rows.push({ name: f.name, arity: arityOf(ov.sig), signature: `${f.name}(${ov.sig})`, args: ov.args, returns: ov.returns, kind: ov.kind,
        securityDefiner: ov.securityDefiner, anon: canExec(ov.grants, 'anon', m), authenticated: canExec(ov.grants, 'authenticated', m),
        body: ov.body, at: loc(ov) });
    }
  }
  const grantsOf = (g) => ({ anon: tablePrivs(g, 'anon', m), authenticated: tablePrivs(g, 'authenticated', m) });
  return {
    source: 'migrations',
    model: st.model,
    tables: [...st.tables.values()].map((t) => ({
      name: t.name, schema: schemaOf(t.name), rls: t.rls, external: !!t.external, text: t.text, indexText: t.indexText || '', at: loc(t),
      partition: !!t.partition, rlsUncertain: t.rlsUncertain || st.rlsUncertain || undefined,
      // External tables (created outside migrations) have unknown grants.
      grants: t.external ? null : grantsOf(t.grants),
      policies: [...t.policies.values()].map((p) => ({ name: p.name, command: p.command, roles: p.roles, permissive: !p.restrictive, text: p.text, at: loc(p) })),
    })),
    views: [...st.views.values()].map((v) => ({ name: v.name, schema: schemaOf(v.name), securityInvoker: v.securityInvoker, materialized: v.materialized, text: v.text, grants: grantsOf(v.grants), at: loc(v) })),
    functions: groupFunctions(rows),
    members: Object.fromEntries([...m].map(([k, v]) => [k, [...v]])),
    triggers: [...st.triggers.values()].map((t) => ({ name: t.name, table: t.table, fn: t.fn, text: t.text || '', at: loc(t) })),
    cron: [...st.cron.values()].map((c) => ({ name: c.name, schedule: c.schedule, command: c.command, at: loc(c) })),
    buckets: null,
    dynamic: st.dynamic.map((d) => ({ text: d.text, at: loc(d) })),
    dynamicApplied: st.dynamicApplied,
    unparsed: st.unparsed,
    stats: { migrations: st.stats.files, statements: st.stats.statements },
  };
}
