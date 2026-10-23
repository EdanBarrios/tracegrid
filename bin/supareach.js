#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { analyze } from '../src/analyze.js';
import { renderReport } from '../src/report.js';
import { renderHtml } from '../src/html.js';
import { ConfigError } from '../src/config.js';
import { RuleError, pluginRefusal } from '../src/engine.js';
import { oneLine } from '../src/safe.js';
import { DbError } from '../src/db.js';
import { readBaseline, writeBaseline, compareBaseline, BaselineError } from '../src/baseline.js';
import { toSarif, githubAnnotations, stepSummary } from '../src/ci.js';

const HELP = `supareach [dir] [options]

What can a signed-in user reach that no code calls? Maps how app code reaches a
Supabase schema and reports dead or risky surface. Static, offline by default.

Options:
  --out <dir>          Output directory (default ./supareach-out)
  --config <file>      Config file (default <dir>/supareach.config.json)
  --baseline <file>    Baseline file (default <dir>/supareach.baseline.json)
  --db-url <url>       Read the schema from a live database (postgres:// URL) instead of
                       replaying migrations. Runs psql in a read-only transaction; use a
                       read-only role. Also read from SUPAREACH_DB_URL.
  --check              Exit 1 if any error/warning finding is not in the baseline
  --update-baseline    Write current findings to the baseline (only removes entries
                       from an existing baseline unless --force)
  --force              Let --update-baseline add new entries
  --sarif <file>       Also write SARIF 2.1.0 (for github/codeql-action/upload-sarif)
  --github             Print GitHub annotations (new findings only with --check) and
                       append a table to $GITHUB_STEP_SUMMARY
  --no-output          Do not write graph.json / report.md / graph.html
  --allow-plugins      Load the rule plugins listed in the config. Plugins are code from the
                       repository: never use this on pull requests (refused on GitHub
                       pull_request and pull_request_target events)
  --no-plugins         Run without the plugins listed in the config
  -h, --help           Show this help
  -v, --version        Show version

Exit codes: 0 clean, 1 new findings (or a refused baseline update), 2 usage or tool error.
`;

function parseArgs(argv) {
  const a = { dir: '.', out: 'supareach-out', output: true };
  const need = (i, x) => { if (i >= argv.length || argv[i].startsWith('--')) fail(`${x} needs a value`); return argv[i]; };
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    if (x === '--out') a.out = need(++i, x);
    else if (x === '--config') a.config = need(++i, x);
    else if (x === '--baseline') a.baseline = need(++i, x);
    else if (x === '--db-url') a.dbUrl = need(++i, x);
    else if (x === '--check') a.check = true;
    else if (x === '--sarif') a.sarif = need(++i, x);
    else if (x === '--github') a.github = true;
    else if (x === '--update-baseline') a.update = true;
    else if (x === '--force') a.force = true;
    else if (x === '--no-output') a.output = false;
    else if (x === '--allow-plugins') a.allowPlugins = true;
    else if (x === '--no-plugins') a.noPlugins = true;
    else if (x === '-h' || x === '--help') a.help = true;
    else if (x === '-v' || x === '--version') a.version = true;
    else if (x.startsWith('-')) fail(`Unknown option ${x}\n\n${HELP}`);
    else a.dir = x;
  }
  return a;
}

function fail(msg) { console.error(msg); process.exit(2); }
// Console output carries names from the scanned project: one line per datum, control characters
// escaped, so nothing a pull request writes can become a GitHub workflow command.
const say = (...lines) => { for (const l of lines) console.log(oneLine(l)); };
const warn = (...lines) => { for (const l of lines) console.error(oneLine(l)); };

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { process.stdout.write(HELP); return 0; }
  if (args.version) {
    const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    console.log(pkg.version); return 0;
  }

  const root = path.resolve(args.dir);
  if (!fs.existsSync(root)) fail(`No such directory: ${root}`);
  let r;
  const dbUrl = args.dbUrl || process.env.SUPAREACH_DB_URL || undefined;
  if (args.allowPlugins && args.noPlugins) fail('--allow-plugins and --no-plugins are exclusive');
  if (args.allowPlugins) { const why = pluginRefusal(); if (why) fail(`supareach: ${why}`); }
  try { r = await analyze(root, { configFile: args.config, dbUrl, allowPlugins: !!args.allowPlugins, noPlugins: !!args.noPlugins }); } catch (e) {
    if (e instanceof ConfigError || e instanceof RuleError || e instanceof DbError) fail(oneLine(`supareach: ${e.message}`));
    throw e;
  }

  if (args.output) {
    const out = path.resolve(args.out);
    fs.mkdirSync(out, { recursive: true });
    fs.writeFileSync(path.join(out, 'graph.json'), JSON.stringify(r, null, 1));
    fs.writeFileSync(path.join(out, 'report.md'), renderReport(r));
    fs.writeFileSync(path.join(out, 'graph.html'), renderHtml(r));
    const rel = path.relative(process.cwd(), out);
    console.log(`Wrote ${rel && !rel.startsWith('..') ? rel : out}/{graph.json,report.md,graph.html}`);
  }

  const s = r.stats;
  const pj = r.project;
  say(`Supabase project: ${pj.supabaseDir} (${pj.how}${pj.configToml ? '' : ', no config.toml'}); migrations ${pj.migrations}, functions ${pj.functionsDir}`);
  const roots = pj.codeRoots.slice(0, 8).map((x) => `${x.dir === '.' ? '(root)' : x.dir + '/'} ${x.files}`).join(', ');
  say(`Code: ${s.files_scanned} files${roots ? ` (${roots}${pj.codeRoots.length > 8 ? ', ...' : ''})` : ''}`);
  say(`${s.call_sites} call sites (${s.unresolved} unresolved), ${s.edge_functions} edge functions; schema from ${r.source === 'catalog' ? `the database catalog (${s.functions} functions, ${s.policies} policies)` : `${s.migrations} migrations (${s.sql_unparsed} statements not understood)`}`);
  const w = Math.max(...r.rules.map((x) => x.id.length)) + 2;
  for (const rule of r.rules) say(`  ${rule.id.padEnd(w)} ${String(r.counts[rule.id]).padStart(4)}  ${rule.level}`);
  if (r.suppressed.length) console.log(`  (${r.suppressed.length} suppressed with a reason; see report.md)`);
  for (const w of r.warnings) warn(`warning: ${w}`);
  for (const h of r.info.invalid_hatches) warn(`warning: ignored hatch at ${h.file}:${h.line}: ${h.error}`);

  const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  const prefixFrom = (base) => { const p = path.relative(base, root).split(path.sep).join('/'); return p.startsWith('..') ? '' : p; };
  if (args.sarif) {
    const fallbackUri = [args.config ? path.relative(root, path.resolve(args.config)) : 'supareach.config.json', 'supabase/config.toml', 'package.json']
      .find((f) => fs.existsSync(path.join(root, f))) || 'supabase/config.toml';
    fs.writeFileSync(path.resolve(args.sarif), JSON.stringify(toSarif(r, { version: pkg.version, prefix: prefixFrom(process.cwd()), fallbackUri }), null, 1));
    console.log(`SARIF written to ${args.sarif}`);
  }
  let fresh = null;

  const baselinePath = path.resolve(args.baseline || path.join(root, 'supareach.baseline.json'));
  let code = 0;
  if (args.update) {
    let prev = null;
    if (fs.existsSync(baselinePath)) {
      try { prev = readBaseline(baselinePath); } catch (e) { if (!args.force) throw e; }
    }
    const res = writeBaseline(baselinePath, r, prev, { force: args.force });
    if (res.refused) {
      warn(`--update-baseline refused: it would add ${res.added.length} finding(s) to the baseline:`, ...res.added.map((x) => `  ${x}`), 'Fix them, ignore them with a reason, or rerun with --force.');
      code = 1;
    } else say(`Baseline written to ${baselinePath} (${res.total} finding(s); ${res.added.length} added, ${res.removed.length} removed)`);
  }
  if (args.check && r.scope_problems.length) {
    warn(`check: refusing to pass: ${r.scope_problems.length} scope problem(s) above make the result empty, not clean.`);
    return 2;
  }
  if (args.check) {
    if (!fs.existsSync(baselinePath)) fail(`--check: no baseline at ${baselinePath}. Run with --update-baseline first.`);
    const c = compareBaseline(readBaseline(baselinePath), r);
    fresh = c.fresh;
    for (const f of c.fresh) warn(`NEW ${f.level} ${f.fingerprint}${f.at ? `  (${f.at})` : ''}`);
    if (c.fixed.length) say(`${c.fixed.length} baselined finding(s) no longer present (run --update-baseline to lock that in):`, ...c.fixed.map((x) => `  ${x}`));
    if (c.fresh.length) { console.error(`check: ${c.fresh.length} new finding(s) not in the baseline`); code = 1; }
    else console.log('check: no new findings');
  }
  if (args.github) {
    const prefix = prefixFrom(process.env.GITHUB_WORKSPACE || process.cwd());
    for (const line of githubAnnotations(fresh || r.findings, r.rules, prefix)) console.log(line);
    if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, stepSummary(r, fresh));
  }
  return code;
}

main().then((c) => process.exit(c), (e) => { console.error(e instanceof BaselineError ? oneLine(`supareach: ${e.message}`) : String((e && e.stack) || e).split('\n').map(oneLine).join('\n')); process.exit(2); });
