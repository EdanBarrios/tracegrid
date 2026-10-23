// Markdown report.
const TITLES = {
  exposed_uncalled_functions: ['Functions callable by anon/authenticated that nothing calls', 'No `.rpc()` in code, no cron job, trigger, policy, view or other SQL function references them. Each is reachable attack surface through PostgREST. Revoke the grant, or add to `ignore.functions` if a caller is coming.'],
  client_tables_without_rls: ['Client-touched tables with RLS off', 'App code (outside edge functions) queries these, and the final migration state never enables row level security.'],
  client_tables_without_policies: ['Client-touched tables with RLS on but no policies', 'RLS with no policy denies everything to anon/authenticated. Usually a bug if the client reads it.'],
  missing_rpcs: ['RPCs called that no migration defines', 'Either created outside migrations (dashboard), dropped, or misspelled.'],
  unknown_tables: ['Tables/views referenced in code that no migration defines', 'May live in another schema, be created outside migrations, or be misspelled.'],
  uncalled_edge_functions: ['Edge functions with no caller', 'No `functions.invoke`, no `/functions/v1/<name>` URL in code, cron or SQL. Webhooks and auth hooks are legitimately uncalled; add them to `ignore.edgeFunctions`.'],
  missing_edge_functions: ['Edge functions invoked that do not exist', 'Called by name or URL, but there is no `supabase/functions/<name>/index.*`.'],
};

const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/`/g, "'");

export function renderReport(r) {
  const L = [];
  L.push(`# supagraph report: ${r.root}`, '', `Generated ${r.generated_at}. Schema version ${r.schema_version}. v0, best effort: static analysis, read the limitations in the README before acting on a finding.`, '');
  L.push('## Summary', '', '| Finding | Count |', '|---|---|');
  for (const [k, n] of Object.entries(r.counts)) L.push(`| ${TITLES[k][0]} | ${n} |`);
  L.push(`| Storage buckets referenced (info) | ${r.info.storage_buckets.length} |`);
  L.push(`| Unresolved dynamic names (info) | ${r.info.unresolved_dynamic_calls.length} |`);
  L.push(`| SQL statements not understood (info) | ${r.info.unparsed_sql.length} |`, '');
  const s = r.stats;
  L.push('## What was scanned', '',
    `- ${s.files_scanned} code files, ${s.call_sites} resolved call sites, ${s.unresolved} unresolved.`,
    `- Distinct RPCs called: ${s.distinct_rpcs_called.client} from client code, ${s.distinct_rpcs_called.edge} from edge functions.`,
    `- Distinct tables/views touched: ${s.distinct_tables_touched.client} client, ${s.distinct_tables_touched.edge} edge.`,
    `- ${s.migrations} migrations, ${s.sql_statements} statements, ${s.sql_unparsed} not understood.`,
    `- Final schema: ${s.tables} tables, ${s.views} views, ${s.functions} functions, ${s.policies} policies, ${s.cron_jobs} cron jobs.`,
    `- ${s.edge_functions} edge functions, ${s.distinct_edge_functions_invoked} invoked from code.`, '');

  for (const [k, items] of Object.entries(r.findings)) {
    const [title, why] = TITLES[k];
    L.push(`## ${title} (${items.length})`, '', why, '');
    if (!items.length) { L.push('None.', ''); continue; }
    for (const it of items) {
      const bits = [];
      if (it.roles) bits.push(`callable by ${it.roles.join(', ')}`);
      if (it.securityDefiner) bits.push('SECURITY DEFINER');
      if (it.sites) bits.push(`${it.sites} site(s)`);
      if (it.note) bits.push(it.note);
      L.push(`- \`${it.id}\`${bits.length ? ' (' + bits.join('; ') + ')' : ''}${it.at ? ' at `' + it.at + '`' : ''}`);
    }
    L.push('');
  }

  L.push(`## Storage buckets referenced (${r.info.storage_buckets.length})`, '');
  for (const b of r.info.storage_buckets) L.push(`- \`${b.id}\`: ${b.sites} site(s), first at \`${b.at}\``);
  L.push('');
  L.push(`## Unresolved dynamic names (${r.info.unresolved_dynamic_calls.length})`, '', 'Calls whose target name is not a literal. They are counted and listed, never dropped. A function reached only through one of these may appear in "nothing calls" above.', '');
  if (r.info.unresolved_dynamic_calls.length) {
    L.push('| Kind | Where | Expression |', '|---|---|---|');
    for (const u of r.info.unresolved_dynamic_calls) L.push(`| ${u.kind} | \`${u.file}:${u.line}\` | \`${esc(u.expr)}\` |`);
  }
  L.push('');
  L.push(`## SQL not understood (${r.info.unparsed_sql.length})`, '', 'Statements the migration parser skipped or could not apply. State derived from them may be wrong.', '');
  if (r.info.unparsed_sql.length) {
    L.push('| Where | Reason | Statement |', '|---|---|---|');
    for (const u of r.info.unparsed_sql) L.push(`| \`${u.file}:${u.line}\` | ${esc(u.reason)} | \`${esc(u.text)}\` |`);
  }
  L.push('');
  if (r.info.unreadable_files.length) {
    L.push('## Files that failed to parse', '');
    for (const f of r.info.unreadable_files) L.push(`- \`${f.file}\`: ${f.error}`);
    L.push('');
  }
  return L.join('\n');
}
