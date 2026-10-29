#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyze } from '../src/analyze.js';
import { renderReport } from '../src/report.js';
import { renderHtml } from '../src/html.js';
import { ConfigError, loadConfig } from '../src/config.js';
import { RuleError, pluginRefusal } from '../src/engine.js';
import { oneLine } from '../src/safe.js';
import { DbError } from '../src/db.js';
import { readBaseline, writeBaseline, compareBaseline, BaselineError } from '../src/baseline.js';
import { COLORWAYS } from '../src/colorways.js';
import { toSarif, githubAnnotations, stepSummary } from '../src/ci.js';
import { startServer, DEFAULT_PORT } from '../src/serve.js';

const HELP = () => `tracegrid [dir] [options]
tracegrid --demo [firebase] run on a bundled example project (Supabase, or Firebase + Flutter)
tracegrid help              this text

What can a signed-in user reach that no code calls? Maps how app code reaches a
Supabase schema and reports dead or risky surface. Static, offline by default.
Scans the whole project and auto-detects the Supabase directory; see the README
for tracegrid.config.json.

Options:
  --out <dir>          Output directory (default ./tracegrid-out)
  --config <file>      Config file (default <dir>/tracegrid.config.json)
  --baseline <file>    Baseline file (default <dir>/tracegrid.baseline.json)
  --db-url <url>       Read the schema from a live database (postgres:// URL) instead of
                       replaying migrations. Runs psql in a read-only transaction; use a
                       read-only role. Also read from TRACEGRID_DB_URL.
  --check              Exit 1 if any new Fix-tier finding is not in the baseline
  --check-level <t>    What --check gates: fix (default) or review (fix + review).
                       Info findings never gate
  --update-baseline    Write current findings to the baseline (only removes entries
                       from an existing baseline unless --force)
  --force              Let --update-baseline add new entries
  --sarif <file>       Also write SARIF 2.1.0 (for github/codeql-action/upload-sarif)
  --github             Print GitHub annotations (new findings only with --check) and
                       append a table to $GITHUB_STEP_SUMMARY
  --colorway <name>    Default colourway of graph.html: ${COLORWAYS.join(', ')} (config key
                       "colorway"; the page's settings and ?colorway= can still change it)
  --json               Print one JSON object to stdout (tier counts, Fix and Review findings with
                       file:line, scope problems, warnings) and send the human text to stderr.
                       For scripts and coding agents; exit codes are unchanged
  --serve              Serve graph.html on http://127.0.0.1:<port>/ with a Refresh button that
                       re-scans the project (also /graph.json, /report.md). Localhost only
  --watch              With --serve: re-scan when files change (the page marks Refresh when new
                       results are ready)
  --port <n>           With --serve: port to listen on (default ${DEFAULT_PORT}; 0 picks a free one)
  --no-output          Do not write graph.json / report.md / graph.html
  --allow-plugins      Load the rule plugins listed in the config. Plugins are code from the
                       repository: never use this on pull requests (refused on GitHub
                       pull_request and pull_request_target events)
  --no-plugins         Run without the plugins listed in the config
  --demo               Analyze the example project bundled with tracegrid
  -h, --help           Show this help
  -v, --version        Show version

Exit codes: 0 clean, 1 new findings (or a refused baseline update), 2 usage or tool
error, or (with --check) a scan that found no code, no call sites or no migrations.
`;

/** Subcommand names kept free for later versions. */
const RESERVED = new Set(['explain', 'path', 'init']);

function parseArgs(argv) {
  const a = { dir: null, out: 'tracegrid-out', output: true };
  const need = (i, x) => { if (i >= argv.length || argv[i].startsWith('--')) fail(`${x} needs a value`); return argv[i]; };
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    if (x === '--out') a.out = need(++i, x);
    else if (x === '--config') a.config = need(++i, x);
    else if (x === '--baseline') a.baseline = need(++i, x);
    else if (x === '--db-url') a.dbUrl = need(++i, x);
    else if (x === '--check') a.check = true;
    else if (x === '--check-level') { a.checkLevel = need(++i, x); if (!['fix', 'review'].includes(a.checkLevel)) fail(`--check-level must be fix or review (got ${oneLine(a.checkLevel)})`); }
    else if (x === '--colorway') { a.colorway = need(++i, x); if (!COLORWAYS.includes(a.colorway)) fail(`--colorway must be one of ${COLORWAYS.join(', ')} (got ${oneLine(a.colorway)})`); }
    else if (x === '--sarif') a.sarif = need(++i, x);
    else if (x === '--github') a.github = true;
    else if (x === '--update-baseline') a.update = true;
    else if (x === '--force') a.force = true;
    else if (x === '--no-output') a.output = false;
    else if (x === '--allow-plugins') a.allowPlugins = true;
    else if (x === '--no-plugins') a.noPlugins = true;
    else if (x === '-h' || x === '--help') a.help = true;
    else if (x === '-v' || x === '--version') a.version = true;
    else if (x === '--json') a.json = true;
    else if (x === '--serve') a.serve = true;
    else if (x === '--watch') a.watch = true;
    else if (x === '--port') { const v = need(++i, x); if (!/^\d+$/.test(v) || +v > 65535) fail(`--port must be a number from 0 to 65535 (got ${oneLine(v)})`); a.port = +v; }
    else if (x === '--demo') a.demo = true;
    else if (x.startsWith('-')) fail(`Unknown option ${oneLine(x)}\n\n${HELP()}`);
    else if (a.dir === null && i === 0 && x === 'help') a.help = true;
    else if (a.dir === null && i === 0 && RESERVED.has(x)) fail(`tracegrid ${x}: not available in this version (the name is reserved for a later one). See tracegrid --help.`);
    else if (a.dir === null) a.dir = x;
    else fail(`Unexpected argument ${oneLine(x)}: tracegrid takes one directory (got ${oneLine(a.dir)} already). Options start with --.`);
  }
  if (a.demo && (a.dir === 'firebase' || a.dir === 'supabase')) { a.demo = a.dir; a.dir = null; }
  if (a.demo && a.dir !== null) fail('--demo takes no directory (only `firebase` to pick the Firebase example)');
  if (a.dir === null) a.dir = '.';
  if ((a.watch || a.port !== undefined) && !a.serve) fail('--watch and --port only apply with --serve');
  if (a.serve) for (const [k, flag] of [['check', '--check'], ['update', '--update-baseline'], ['sarif', '--sarif'], ['github', '--github'], ['json', '--json']]) if (a[k]) fail(`--serve cannot be combined with ${flag}`);
  return a;
}

function fail(msg) { console.error(msg); process.exit(2); }
// Console output carries names from the scanned project: one line per datum, control characters
// escaped, so nothing a pull request writes can become a GitHub workflow command.
const say = (...lines) => { for (const l of lines) console.log(oneLine(l)); };
const warn = (...lines) => { for (const l of lines) console.error(oneLine(l)); };

/**
 * One scan: analyze, then (unless --no-output) write graph.json, report.md and graph.html. With `serve`, also
 * render the copy the server sends, which has the Refresh button (the file on disk does not).
 * Throws ConfigError / RuleError / DbError; the caller decides whether that ends the process.
 */
async function build(args, root, demo, { serve } = {}) {
  const dbUrl = args.dbUrl || process.env.TRACEGRID_DB_URL || undefined;
  // The demo's plugin ships inside the tracegrid package, not in the scanned project: it is trusted.
  const r = await analyze(root, { configFile: args.config, dbUrl, allowPlugins: !!args.allowPlugins || (!!demo && !args.noPlugins), noPlugins: !!args.noPlugins });
  const baselinePath = path.resolve(args.baseline || path.join(root, 'tracegrid.baseline.json'));
  const out = { r, baselinePath, wrote: null };
  if (!args.output && !serve) return out;
  // The page shows new / fixed findings against the baseline when one is readable (display only).
  let baseline = null;
  if (fs.existsSync(baselinePath)) {
    try { const c = compareBaseline(readBaseline(baselinePath), r, 'review'); baseline = { file: path.basename(baselinePath), fresh: c.fresh.map((f) => f.fingerprint), fixed: c.fixed }; } catch { baseline = null; }
  }
  let colorway = args.colorway;
  if (!colorway) { try { colorway = loadConfig(root, args.config).colorway || undefined; } catch { colorway = undefined; } }
  if (args.output) {
    const dir = path.resolve(args.out);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'graph.json'), JSON.stringify(r, null, 1));
    fs.writeFileSync(path.join(dir, 'report.md'), renderReport(r));
    fs.writeFileSync(path.join(dir, 'graph.html'), renderHtml(r, { baseline, colorway }));
    const rel = path.relative(process.cwd(), dir);
    out.wrote = rel && !rel.startsWith('..') ? rel : dir;
  }
  if (serve) out.serveHtml = renderHtml(r, { baseline, colorway, serve });
  return out;
}

/** The compact, machine-readable view of a run: what an agent needs without opening report.md. */
function agentSummary(r, baselinePath, wrote) {
  let fresh = null;
  try { if (fs.existsSync(baselinePath)) fresh = new Set(compareBaseline(readBaseline(baselinePath), r, 'review').fresh.map((f) => f.fingerprint)); } catch { fresh = null; }
  const RANK = { fix: 0, review: 1 };
  const findings = r.findings.filter((f) => f.tier !== 'info').sort((a, b) => RANK[a.tier] - RANK[b.tier])
    .map((f) => ({ tier: f.tier, level: f.level, rule: f.rule, id: f.id, at: f.at || null, note: f.note || null, confidence: f.confidence || null, fingerprint: f.fingerprint, ...(fresh ? { new: fresh.has(f.fingerprint) } : {}) }));
  return {
    platform: r.platform || 'supabase', tiers: r.tiers, findings,
    // A scan that found no code, no call sites or nothing to read is empty, not clean.
    scope_problems: r.scope_problems, warnings: r.warnings, notices: r.notices || [], stats: r.stats,
    baseline: fresh ? { file: path.basename(baselinePath), new: findings.filter((f) => f.new).length } : null,
    output: wrote,
  };
}

/** --serve: scan, then serve graph.html with a Refresh button until interrupted. */
async function serve(args, root, demo) {
  const outDir = path.resolve(args.out);
  let server;
  try {
    server = await startServer({
      port: args.port,
      watch: args.watch ? { root, ignore: [outDir] } : null,
      log: (l) => say(l),
      build: async () => {
        const b = await build(args, root, demo, { serve: { watch: !!args.watch } });
        return { html: b.serveHtml, json: JSON.stringify(b.r, null, 1), report: renderReport(b.r), generated_at: b.r.generated_at, tiers: b.r.tiers };
      },
    });
  } catch (e) {
    if (e instanceof ConfigError || e instanceof RuleError || e instanceof DbError) fail(oneLine(`tracegrid: ${e.message}`));
    fail(oneLine(`tracegrid: ${e.message}`));
  }
  say(`tracegrid serving ${server.url}${args.watch ? ' (watching for changes)' : ''}  Ctrl-C to stop`);
  await new Promise((resolve) => { for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, resolve); });
  await server.close();
  return 0;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { process.stdout.write(HELP()); return 0; }
  if (args.version) {
    const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    console.log(pkg.version); return 0;
  }

  const demo = args.demo ? path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'examples', args.demo === 'firebase' ? 'firebase-demo' : 'demo-app') : null;
  if (demo && !fs.existsSync(demo)) fail('--demo: the bundled example is missing from this installation');
  const root = path.resolve(demo || args.dir);
  if (!fs.existsSync(root)) fail(`No such directory: ${root}`);
  if (args.allowPlugins && args.noPlugins) fail('--allow-plugins and --no-plugins are exclusive');
  if (args.allowPlugins) { const why = pluginRefusal(); if (why) fail(`tracegrid: ${why}`); }
  if (args.serve) return serve(args, root, demo);
  // --json: stdout carries only the JSON object; everything else the CLI says goes to stderr.
  const printJson = console.log.bind(console);
  if (args.json) console.log = (...a) => console.error(...a);
  let b;
  try { b = await build(args, root, demo); } catch (e) {
    if (e instanceof ConfigError || e instanceof RuleError || e instanceof DbError) fail(oneLine(`tracegrid: ${e.message}`));
    throw e;
  }
  const { r, baselinePath } = b;
  if (b.wrote) console.log(`Wrote ${b.wrote}/{graph.json,report.md,graph.html}`);
  if (args.json) printJson(JSON.stringify(agentSummary(r, baselinePath, b.wrote)));

  const s = r.stats;
  const pj = r.project;
  const fb = r.platform === 'firebase';
  if (fb) say(`Firebase project: ${pj.configFile}; rules ${pj.rules.map((x) => x.file).join(', ') || '(none)'}; functions ${pj.functions.map((f) => f.dir).join(', ') || '(none)'}`);
  else say(`Supabase project: ${pj.supabaseDir} (${pj.how}${pj.configToml ? '' : ', no config.toml'}); migrations ${pj.migrations}, functions ${pj.functionsDir}`);
  const roots = pj.codeRoots.slice(0, 8).map((x) => `${x.dir === '.' ? '(root)' : x.dir + '/'} ${x.files}`).join(', ');
  say(`Code: ${s.files_scanned} files${roots ? ` (${roots}${pj.codeRoots.length > 8 ? ', ...' : ''})` : ''}`);
  if (fb) say(`${s.call_sites} call sites (${s.unresolved} unresolved), ${s.cloud_functions} Cloud Functions; ${s.rule_paths} rule paths, ${s.allows} allow statements (${s.rules_unparsed} not understood)`);
  else say(`${s.call_sites} call sites (${s.unresolved} unresolved), ${s.edge_functions} edge functions; schema from ${r.source === 'catalog' ? `the database catalog (${s.functions} functions, ${s.policies} policies)` : `${s.migrations} migrations (${s.sql_unparsed} statements not understood)`}`);
  const w = Math.max(...r.rules.map((x) => x.id.length)) + 2;
  // Per rule: the count, split by the level each finding actually has (a rule's findings can be
  // downgraded, e.g. errors to warnings when dynamic calls could reach them).
  for (const rule of r.rules) {
    const mine = r.findings.filter((f) => f.rule === rule.id);
    const byLevel = ['error', 'warning', 'note'].map((l) => [l, mine.filter((f) => f.level === l).length]).filter(([, n]) => n);
    say(`  ${rule.id.padEnd(w)} ${String(mine.length).padStart(4)}  ${byLevel.length ? byLevel.map(([l, n]) => (byLevel.length > 1 ? `${n} ${l}` : l)).join(', ') : '-'}`);
  }
  if (r.suppressed.length) say(`  (${r.suppressed.length} suppressed with a reason; see report.md)`);
  const t = r.tiers;
  say('', `Fix ${t.fix}  ·  Review ${t.review}  ·  Info ${t.info}`);
  const RANK = { fix: 0, review: 1, info: 2 };
  const LRANK = { error: 0, warning: 1, note: 2 };
  const top = [...r.findings].filter((f) => f.tier !== 'info').sort((a, b) => RANK[a.tier] - RANK[b.tier] || LRANK[a.level] - LRANK[b.level]);
  if (top.length) {
    say('', top[0].tier === 'fix' ? 'Fix first:' : 'Nothing in Fix. Review:');
    let tier = top[0].tier;
    for (const f of top.slice(0, 10)) {
      if (f.tier !== tier) { tier = f.tier; say('Review:'); }
      say(`  ${f.rule}  ${f.id}${f.at ? `  ${f.at}` : ''}${f.note ? `  (${f.note})` : ''}`);
    }
    if (top.length > 10) say(`  ... and ${top.length - 10} more in report.md`);
  }
  for (const n of r.notices || []) say(`note: ${n}`);
  for (const w of r.warnings) warn(`warning: ${w}`);
  for (const h of r.info.invalid_hatches) warn(`warning: ignored hatch at ${h.file}:${h.line}: ${h.error}`);

  const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  const prefixFrom = (base) => { const p = path.relative(base, root).split(path.sep).join('/'); return p.startsWith('..') ? '' : p; };
  if (args.sarif) {
    const fallbackUri = [args.config ? path.relative(root, path.resolve(args.config)) : 'tracegrid.config.json', 'supabase/config.toml', 'package.json']
      .find((f) => fs.existsSync(path.join(root, f))) || 'supabase/config.toml';
    fs.writeFileSync(path.resolve(args.sarif), JSON.stringify(toSarif(r, { version: pkg.version, prefix: prefixFrom(process.cwd()), fallbackUri }), null, 1));
    console.log(`SARIF written to ${args.sarif}`);
  }
  let fresh = null;

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
    let known = new Set();
    if (fs.existsSync(baselinePath)) known = readBaseline(baselinePath);
    else warn(`check: no baseline at ${baselinePath}, so every ${args.checkLevel === 'review' ? 'Fix and Review' : 'Fix'} finding counts as new. To accept today's findings and fail only on new ones: tracegrid --update-baseline, then commit tracegrid.baseline.json.`);
    const c = compareBaseline(known, r, args.checkLevel || 'fix');
    fresh = c.fresh;
    for (const f of c.fresh) warn(`NEW ${f.tier} ${f.fingerprint}${f.at ? `  (${f.at})` : ''}`);
    if (c.fixed.length) say(`${c.fixed.length} baselined finding(s) no longer present (run --update-baseline to lock that in):`, ...c.fixed.map((x) => `  ${x}`));
    const gate = args.checkLevel === 'review' ? 'Fix/Review' : 'Fix';
    if (c.fresh.length) { console.error(`check: ${c.fresh.length} new ${gate} finding(s) not in the baseline`); code = 1; }
    else console.log(`check: no new ${gate} findings`);
  }
  if (!args.check && !args.update) say('', 'Not gating: findings do not change the exit code. Use --check (with a baseline from --update-baseline) in CI.');
  if (args.github) {
    const prefix = prefixFrom(process.env.GITHUB_WORKSPACE || process.cwd());
    for (const line of githubAnnotations(fresh || r.findings, r.rules, prefix, r.sarifLevels)) console.log(line);
    if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, stepSummary(r, fresh));
  }
  return code;
}

main().then((c) => process.exit(c), (e) => { console.error(e instanceof BaselineError ? oneLine(`tracegrid: ${e.message}`) : String((e && e.stack) || e).split('\n').map(oneLine).join('\n')); process.exit(2); });
