// Markdown report. Every name, path and message can come from the scanned project, so all of it goes
// through mdCode() (inline code) or mdText() (escaped prose): no data can add lines, headings or HTML.
import { mdCode, mdText } from './safe.js';

const esc = mdText;
const code = mdCode;

/** Inline code inside a table cell: `|` must be escaped even inside a code span. */
const tcode = (s) => code(s).replace(/\|/g, '\\|');

export function renderReport(r) {
  const L = [];
  L.push(`# supareach report: ${esc(r.root)}`, '', `Generated ${r.generated_at}. Schema version ${r.schema_version}. v0, best effort: static analysis, read the limitations in the README before acting on a finding.`, '');
  if (r.warnings && r.warnings.length) { for (const w of r.warnings) L.push(`> **Warning:** ${esc(w)}`, ''); }
  L.push(`Schema source: **${r.source}**${r.source === 'migrations' ? ' (replayed from migration files; best effort)' : ' (read from a live database catalog)'}.`, '');
  if (r.project) {
    const g = r.project.grantModel || {};
    L.push(`Supabase project: ${code(r.project.supabaseDir)} (${esc(r.project.how)}). Default-grant model: **${esc(g.model)}** (${esc(g.source)}).`
      + (g.live ? ` Live database: tables ${esc(g.live.tables)}; functions ${esc(g.live.functions)}.` : ''), '');
  }
  L.push('## Summary', '', '| Finding | Count |', '|---|---|');
  for (const rule of r.rules) L.push(`| ${rule.title} (\`${rule.id}\`, ${rule.level}) | ${r.counts[rule.id]} |`);
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

  for (const rule of r.rules) {
    const items = r.findings.filter((f) => f.rule === rule.id);
    L.push(`## ${rule.title} (${items.length})`, '', `\`${rule.id}\`, ${rule.level}${rule.plugin ? `, from plugin \`${rule.plugin}\`` : ''}. ${rule.why}`, '');
    if (!items.length) { L.push('None.', ''); continue; }
    for (const it of items) {
      const bits = [];
      if (it.roles) bits.push(`callable by ${it.roles.join(', ')}`);
      if (it.securityDefiner) bits.push('SECURITY DEFINER');
      if (it.sites) bits.push(`${it.sites} site(s)`);
      if (it.usedBy) bits.push(`used by ${it.usedBy.join(', ')}`);
      if (it.message) bits.push(it.message);
      if (it.note) bits.push(it.note);
      L.push(`- ${code(it.id)}${bits.length ? ' (' + esc(bits.join('; ')) + ')' : ''}${it.at ? ' at ' + code(it.at) : ''}`);
    }
    L.push('');
  }

  if (r.suppressed.length) {
    L.push(`## Suppressed (${r.suppressed.length})`, '', 'Findings silenced by config or an in-source hatch, with the reason given.', '');
    for (const f of r.suppressed) L.push(`- ${code(f.fingerprint)}: ${esc(f.suppressed)}`);
    L.push('');
  }
  const ext = r.info.external_entry_points || [];
  L.push(`## External entry points (${ext.length})`, '', 'Edge functions treated as called from outside the codebase, so they are not reported as uncalled. Check the reasons still hold.', '');
  for (const e of ext) L.push(`- ${code(e.id)}: ${esc(e.reason)} (${esc(e.source)})`);
  L.push('');
  L.push(`## Storage buckets referenced (${r.info.storage_buckets.length})`, '');
  for (const b of r.info.storage_buckets) L.push(`- ${code(b.id)}: ${b.sites} site(s), first at ${code(b.at)}`);
  L.push('');
  L.push(`## Unresolved dynamic names (${r.info.unresolved_dynamic_calls.length})`, '', 'Calls whose target name is not a literal. They are counted and listed, never dropped. A function reached only through one of these may appear in "nothing calls" above.', '');
  if (r.info.unresolved_dynamic_calls.length) {
    L.push('| Kind | Where | Expression |', '|---|---|---|');
    for (const u of r.info.unresolved_dynamic_calls) L.push(`| ${esc(u.kind)} | ${tcode(`${u.file}:${u.line}`)} | ${tcode(u.expr)} |`);
  }
  L.push('');
  L.push(`## SQL not understood (${r.info.unparsed_sql.length})`, '', 'Statements the migration parser skipped or could not apply. State derived from them may be wrong.', '');
  if (r.info.unparsed_sql.length) {
    L.push('| Where | Reason | Statement |', '|---|---|---|');
    for (const u of r.info.unparsed_sql) L.push(`| ${tcode(`${u.file}:${u.line}`)} | ${u.risky ? '**touches grants/policies** ' : ''}${esc(u.reason)} | ${tcode(u.text)} |`);
  }
  L.push('');
  const applied = r.info.dynamic_sql_applied || [];
  if (applied.length) {
    L.push(`## Dynamic SQL applied (${applied.length})`, '', 'EXECUTE statements in DO blocks whose text was fully known (literals, or a loop over an array literal) and that were applied like ordinary statements.', '');
    L.push('| Where | How | Statement |', '|---|---|---|');
    for (const d of applied) L.push(`| ${tcode(`${d.file}:${d.line}`)} | ${esc(d.how)} | ${tcode(d.text)} |`);
    L.push('');
  }
  const skipped = r.info.skipped_migrations || [];
  if (skipped.length) {
    L.push(`## Files in the migrations directory not replayed (${skipped.length})`, '');
    for (const f of skipped) L.push(`- ${code(f.file)}: ${esc(f.reason)}`);
    L.push('');
  }
  if ((r.info.parse_errors || []).length) {
    L.push(`## Files with syntax errors (${r.info.parse_errors.length})`, '', 'Parsed with error recovery; calls after the error may be missing.', '');
    for (const f of r.info.parse_errors) L.push(`- ${code(`${f.file}:${f.line}`)}: ${esc(f.error)}`);
    L.push('');
  }
  if (r.info.invalid_hatches.length) {
    L.push(`## Hatches that were not applied (${r.info.invalid_hatches.length})`, '');
    for (const h of r.info.invalid_hatches) L.push(`- ${code(`${h.file}:${h.line}`)}: ${esc(h.error)}`);
    L.push('');
  }
  if (r.info.unreadable_files.length) {
    L.push('## Files that failed to parse', '');
    for (const f of r.info.unreadable_files) L.push(`- ${code(f.file)}: ${esc(f.error)}`);
    L.push('');
  }
  return L.join('\n');
}
