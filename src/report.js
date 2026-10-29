// Markdown report. Every name, path and message can come from the scanned project, so all of it goes
// through mdCode() (inline code) or mdText() (escaped prose): no data can add lines, headings or HTML.
import { mdCode, mdText } from './safe.js';

const esc = mdText;
const code = mdCode;

/** Inline code inside a table cell: `|` must be escaped even inside a code span. */
const tcode = (s) => code(s).replace(/\|/g, '\\|');

const TIER_OF_LEVEL = { error: 'fix', warning: 'review', note: 'info' };

export function renderReport(r) {
  const L = [];
  r = { ...r, findings: r.findings.map((f) => (f.tier ? f : { ...f, tier: TIER_OF_LEVEL[f.level] || 'review' })) };
  L.push(`# tracegrid report: ${esc(r.root)}`, '', `Generated ${r.generated_at}. Schema version ${r.schema_version}. v0, best effort: static analysis, read the limitations in the README before acting on a finding.`, '');
  if (r.warnings && r.warnings.length) { for (const w of r.warnings) L.push(`> **Warning:** ${esc(w)}`, ''); }
  const fb = r.platform === 'firebase';
  if (fb) {
    const pj = r.project;
    L.push(`Firebase project: ${code(pj.configFile)}. Rules: ${pj.rules.length ? pj.rules.map((x) => `${code(x.file)} (${esc(x.service)}, ${x.allows} allow statements)`).join(', ') : 'none found'}. `
      + `Functions: ${pj.functions.length ? pj.functions.map((f) => code(f.dir)).join(', ') : 'none'}.`, '');
  } else L.push(`Schema source: **${r.source}**${r.source === 'migrations' ? ' (replayed from migration files; best effort)' : ' (read from a live database catalog)'}.`, '');
  if (r.project && !fb) {
    const g = r.project.grantModel || {};
    L.push(`Supabase project: ${code(r.project.supabaseDir)} (${esc(r.project.how)}). Default-grant model: **${esc(g.model)}** (${esc(g.source)}).`
      + (g.live ? ` Live database: tables ${esc(g.live.tables)}; functions ${esc(g.live.functions)}.` : ''), '');
  }
  for (const n of r.notices || []) L.push(`> **Note:** ${esc(n)}`, '');
  const t = r.tiers || { fix: 0, review: 0, info: 0 };
  const inTier = (rule, tier) => r.findings.filter((f) => f.rule === rule && f.tier === tier).length;
  L.push('## Summary', '', `**Fix ${t.fix}** · Review ${t.review} · Info ${t.info}`, '',
    fb ? '- **Fix**: high confidence. Rules that let anyone write, catch-all rules that open the whole database, or paths open to any signed-in user that no client code uses (and no dynamic reference could reach). Act on these.'
      : '- **Fix**: high confidence. Reachable by anon/authenticated (or PUBLIC) with no recognised caller and no dynamic call that could reach it, or client-used tables without RLS. Act on these.',
    '- **Review**: the same kinds of problem with a caveat (dynamic calls or dynamic SQL, heuristic client detection, indirect reachability), or a functional problem rather than an exposure.',
    '- **Info**: intended or benign patterns (helpers RLS policies need, notes).', '',
    '| Finding | Fix | Review | Info |', '|---|---:|---:|---:|');
  for (const rule of r.rules) L.push(`| ${rule.title} (\`${rule.id}\`) | ${inTier(rule.id, 'fix')} | ${inTier(rule.id, 'review')} | ${inTier(rule.id, 'info')} |`);
  if (!fb) L.push(`| Storage buckets referenced (info) | | | ${r.info.storage_buckets.length} |`);
  L.push(`| Unresolved dynamic names (info) | | | ${r.info.unresolved_dynamic_calls.length} |`);
  L.push(`| ${fb ? 'Rules statements' : 'SQL statements'} not understood (info) | | | ${r.info.unparsed_sql.length} |`, '');
  const s = r.stats;
  if (fb) {
    const k = s.cloud_functions_by_kind;
    L.push('## What was scanned', '',
      `- ${s.files_scanned} code files, ${s.call_sites} resolved call sites, ${s.unresolved} unresolved.`,
      `- Distinct Firestore paths used: ${s.firestore_paths_used.client} from client code, ${s.firestore_paths_used.server} from Cloud Functions (Admin SDK, bypasses rules).`,
      `- ${s.rules_files} rules file(s): ${s.rule_paths} rule paths, ${s.allows} allow statements, ${s.rules_unparsed} not understood.`,
      `- ${s.cloud_functions} Cloud Functions (${k.callable} callable, ${k.http} HTTP, ${k.trigger} triggers); ${s.callables_called} called by name from client code.`, '');
  } else L.push('## What was scanned', '',
    `- ${s.files_scanned} code files, ${s.call_sites} resolved call sites, ${s.unresolved} unresolved.`,
    `- Distinct RPCs called: ${s.distinct_rpcs_called.client} from client code, ${s.distinct_rpcs_called.edge} from edge functions.`,
    `- Distinct tables/views touched: ${s.distinct_tables_touched.client} client, ${s.distinct_tables_touched.edge} edge.`,
    `- ${s.migrations} migrations, ${s.sql_statements} statements, ${s.sql_unparsed} not understood.`,
    `- Final schema: ${s.tables} tables, ${s.views} views, ${s.functions} functions, ${s.policies} policies, ${s.cron_jobs} cron jobs.`,
    `- ${s.edge_functions} edge functions, ${s.distinct_edge_functions_invoked} invoked from code.`, '');

  // Rule `title` and `why` are emitted as Markdown without escaping. They are trusted: core rules ship
  // with tracegrid, and plugin rules are code that only loads with --allow-plugins (refused on pull
  // request events), so their author can already run anything. Finding data is always escaped.
  const TITLES = { fix: 'Fix', review: 'Review', info: 'Info' };
  for (const tier of ['fix', 'review', 'info']) {
    const n = r.findings.filter((f) => f.tier === tier).length;
    L.push(`## ${TITLES[tier]} (${n})`, '');
    if (!n) { L.push('Nothing in this tier.', ''); continue; }
    for (const rule of r.rules) {
      const items = r.findings.filter((f) => f.rule === rule.id && f.tier === tier);
      if (!items.length) continue;
      L.push(`### ${rule.title} (${items.length})`, '', `\`${rule.id}\`${rule.plugin ? `, from plugin \`${rule.plugin}\`` : ''}. ${rule.why}`, '');
      for (const it of items) {
        const bits = [];
        if (it.level !== rule.level) bits.push(it.level);
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
  }

  if (r.suppressed.length) {
    L.push(`## Suppressed (${r.suppressed.length})`, '', 'Findings silenced by config or an in-source hatch, with the reason given.', '');
    for (const f of r.suppressed) L.push(`- ${code(f.fingerprint)}: ${esc(f.suppressed)}`);
    L.push('');
  }
  const ext = r.info.external_entry_points || [];
  L.push(`## External entry points (${ext.length})`, '', `${fb ? 'Cloud Functions' : 'Edge functions'} treated as called from outside the codebase, so they are not reported as uncalled. Check the reasons still hold.`, '');
  for (const e of ext) L.push(`- ${code(e.id)}: ${esc(e.reason)} (${esc(e.source)})`);
  L.push('');
  if (!fb) {
    L.push(`## Storage buckets referenced (${r.info.storage_buckets.length})`, '');
    for (const b of r.info.storage_buckets) L.push(`- ${code(b.id)}: ${b.sites} site(s), first at ${code(b.at)}`);
    L.push('');
  }
  L.push(`## Unresolved dynamic names (${r.info.unresolved_dynamic_calls.length})`, '', 'Calls whose target name is not a literal. They are counted and listed, never dropped. A function reached only through one of these may appear in "nothing calls" above.', '');
  if (r.info.unresolved_dynamic_calls.length) {
    L.push('| Kind | Where | Expression |', '|---|---|---|');
    for (const u of r.info.unresolved_dynamic_calls) L.push(`| ${esc(u.kind)} | ${tcode(`${u.file}:${u.line}`)} | ${tcode(u.expr)} |`);
  }
  L.push('');
  L.push(`## ${fb ? 'Rules' : 'SQL'} not understood (${r.info.unparsed_sql.length})`, '', fb ? 'Rules statements the parser skipped. Access derived from them may be wrong.' : 'Statements the migration parser skipped or could not apply. State derived from them may be wrong.', '');
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
  if (r.info.invalid_hatches.length) {
    L.push(`## Hatches that were not applied (${r.info.invalid_hatches.length})`, '');
    for (const h of r.info.invalid_hatches) L.push(`- ${code(`${h.file}:${h.line}`)}: ${esc(h.error)}`);
    L.push('');
  }
  if (r.info.unreadable_files.length) {
    L.push(`## Files not scanned, or scanned only partly (${r.info.unreadable_files.length})`, '', 'Calls in these files may be missing, so a function they call can appear uncalled.', '');
    for (const f of r.info.unreadable_files) L.push(`- ${code(f.line ? `${f.file}:${f.line}` : f.file)}: ${esc(f.error)}`);
    L.push('');
  }
  return L.join('\n');
}
