// CI outputs: SARIF 2.1.0 for code scanning, GitHub workflow-command annotations and a step summary.
import path from 'node:path';
import { mdCode, mdText } from './safe.js';

export const DEFAULT_SARIF_LEVELS = { fix: 'error', review: 'warning', info: 'note' };
/** SARIF / annotation level for a finding: by tier, with the config's sarifLevels overrides. */
export const levelOf = (f, map = {}) => ({ ...DEFAULT_SARIF_LEVELS, ...map })[f.tier] || f.level || 'warning';

/** One-line description of a finding, shared by every output. */
export function describe(f, rule) {
  const bits = [];
  if (f.roles && f.roles.length) bits.push(`callable by ${f.roles.join(', ')}`);
  if (f.securityDefiner) bits.push('SECURITY DEFINER');
  if (f.usedBy) bits.push(`used by ${f.usedBy.join(', ')}`);
  if (f.sites) bits.push(`${f.sites} call site(s)`);
  if (f.message) bits.push(f.message);
  if (f.note) bits.push(f.note);
  return `${f.tier ? `[${f.tier}] ` : ''}${rule ? rule.title : f.rule}: ${f.id}${bits.length ? ` (${bits.join('; ')})` : ''}`;
}

/** `file:line` (or `file`) -> { file, line } relative to the repository; null for db: locations. */
export function location(at, prefix = '') {
  if (!at || /^db:/.test(at)) return null;
  const m = /^(.*?):(\d+)$/.exec(at);
  const file = (m ? m[1] : at).split(path.sep).join('/');
  return { file: prefix ? `${prefix.replace(/\/+$/, '')}/${file}` : file, line: m ? Number(m[2]) : 1 };
}

/** Relative path -> URI reference (each segment percent-encoded). */
export const uriOf = (p) => p.split('/').map(encodeURIComponent).join('/');

/**
 * SARIF 2.1.0. Findings without a file location (objects that exist only in the database) point at
 * `fallbackUri`, line 1, since code scanning wants a location for every result.
 */
export function toSarif(r, { version = '0.0.0', prefix = '', fallbackUri = 'supabase/config.toml' } = {}) {
  const ruleIndex = new Map(r.rules.map((x, i) => [x.id, i]));
  const byId = new Map(r.rules.map((x) => [x.id, x]));
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'tracegrid',
          version,
          informationUri: 'https://github.com/EdanBarrios/tracegrid',
          rules: r.rules.map((x) => ({
            id: x.id,
            name: x.id.replace(/[^A-Za-z0-9]+(.)?/g, (_, c) => (c ? c.toUpperCase() : '')),
            shortDescription: { text: x.title },
            fullDescription: { text: x.why },
            help: { text: x.why, markdown: x.why },
            defaultConfiguration: { level: levelOf({ tier: x.tier, level: x.level }, r.sarifLevels) },
            properties: { tags: ['security', 'supabase'], tier: x.tier, ...(x.plugin ? { plugin: x.plugin } : {}) },
          })),
        },
      },
      automationDetails: { id: `tracegrid/${r.source}/` },
      invocations: [{
        executionSuccessful: !(r.scope_problems || []).length,
        toolExecutionNotifications: [
          ...(r.scope_problems || []).map((t) => ({ level: 'error', message: { text: t } })),
          ...((r.info && r.info.unreadable_files) || []).map((f) => ({
            level: 'warning', message: { text: `${f.file}: ${f.error}` },
            locations: [{ physicalLocation: { artifactLocation: { uri: uriOf(prefix ? `${prefix}/${f.file}` : f.file), uriBaseId: '%SRCROOT%' }, ...(f.line ? { region: { startLine: f.line } } : {}) } }],
          })),
        ],
      }],
      results: r.findings.map((f) => {
        const loc = location(f.at, prefix) || { file: prefix ? `${prefix}/${fallbackUri}` : fallbackUri, line: 1 };
        return {
          ruleId: f.rule,
          ruleIndex: ruleIndex.get(f.rule),
          level: levelOf(f, r.sarifLevels),
          message: { text: describe(f, byId.get(f.rule)) + (f.at && /^db:/.test(f.at) ? ` [${f.at}]` : '') },
          locations: [{ physicalLocation: { artifactLocation: { uri: uriOf(loc.file), uriBaseId: '%SRCROOT%' }, region: { startLine: loc.line } } }],
          partialFingerprints: { 'tracegrid/v1': f.fingerprint },
          properties: { source: f.source, tier: f.tier, ...(f.confidence ? { confidence: f.confidence } : {}) },
        };
      }),
    }],
  };
}

const escData = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escProp = (s) => escData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
const CMD = { error: 'error', warning: 'warning', note: 'notice' };

/** GitHub workflow commands, one per finding. */
export function githubAnnotations(findings, rules, prefix = '', levels = {}) {
  const byId = new Map(rules.map((x) => [x.id, x]));
  return findings.map((f) => {
    const loc = location(f.at, prefix);
    const props = [loc ? `file=${escProp(loc.file)}` : null, loc ? `line=${loc.line}` : null, `title=${escProp(`tracegrid ${f.rule}`)}`].filter(Boolean).join(',');
    const lvl = levelOf(f, levels);
    return lvl === 'none' ? null : `::${CMD[lvl] || 'warning'} ${props}::${escData(describe(f, byId.get(f.rule)))}`;
  }).filter(Boolean);
}

/** Markdown for $GITHUB_STEP_SUMMARY. `fresh` is the list of new findings when --check ran, else null. */
export function stepSummary(r, fresh) {
  const L = ['## tracegrid', ''];
  L.push(`Schema source: **${r.source}**. ${r.stats.call_sites} call sites, ${r.stats.unresolved} unresolved.`, '');
  for (const w of r.warnings || []) L.push(`> **Warning:** ${mdText(w)}`, '');
  if (r.tiers) L.push(`**Fix ${r.tiers.fix}** · Review ${r.tiers.review} · Info ${r.tiers.info}`, '');
  L.push('| Rule | Fix | Review | Info |', '|---|---:|---:|---:|');
  for (const x of r.rules) {
    const n = (t) => r.findings.filter((f) => f.rule === x.id && f.tier === t).length;
    L.push(`| ${mdText(x.title)} (${mdCode(x.id).replace(/\|/g, '\\|')}) | ${n('fix')} | ${n('review')} | ${n('info')} |`);
  }
  L.push('');
  if (fresh) {
    L.push(fresh.length ? `### ${fresh.length} new finding(s) not in the baseline` : '### No new findings', '');
    for (const f of fresh.slice(0, 50)) L.push(`- ${f.tier} ${mdCode(f.fingerprint)}${f.at ? ` at ${mdCode(f.at)}` : ''}`);
    if (fresh.length > 50) L.push(`- ... and ${fresh.length - 50} more`);
    L.push('');
  }
  return L.join('\n') + '\n';
}
