#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { analyze } from '../src/analyze.js';
import { renderReport } from '../src/report.js';
import { renderHtml } from '../src/html.js';
import { ConfigError } from '../src/config.js';
import { RuleError } from '../src/engine.js';
import { readBaseline, writeBaseline, compareBaseline, BaselineError } from '../src/baseline.js';

const HELP = `supareach [dir] [options]

What can a signed-in user reach that no code calls? Maps how app code reaches a
Supabase schema and reports dead or risky surface. Static, offline by default.

Options:
  --out <dir>          Output directory (default ./supareach-out)
  --config <file>      Config file (default <dir>/supareach.config.json)
  --baseline <file>    Baseline file (default <dir>/supareach.baseline.json)
  --check              Exit 1 if any error/warning finding is not in the baseline
  --update-baseline    Write current findings to the baseline (only removes entries
                       from an existing baseline unless --force)
  --force              Let --update-baseline add new entries
  --no-output          Do not write graph.json / report.md / graph.html
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
    else if (x === '--check') a.check = true;
    else if (x === '--update-baseline') a.update = true;
    else if (x === '--force') a.force = true;
    else if (x === '--no-output') a.output = false;
    else if (x === '-h' || x === '--help') a.help = true;
    else if (x === '-v' || x === '--version') a.version = true;
    else if (x.startsWith('-')) fail(`Unknown option ${x}\n\n${HELP}`);
    else a.dir = x;
  }
  return a;
}

function fail(msg) { console.error(msg); process.exit(2); }

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
  try { r = await analyze(root, { configFile: args.config }); } catch (e) {
    if (e instanceof ConfigError || e instanceof RuleError) fail(`supareach: ${e.message}`);
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
  console.log(`${s.files_scanned} files, ${s.call_sites} call sites (${s.unresolved} unresolved), ${s.migrations} migrations (${s.sql_unparsed} statements not understood), ${s.edge_functions} edge functions`);
  const w = Math.max(...r.rules.map((x) => x.id.length)) + 2;
  for (const rule of r.rules) console.log(`  ${rule.id.padEnd(w)} ${String(r.counts[rule.id]).padStart(4)}  ${rule.level}`);
  if (r.suppressed.length) console.log(`  (${r.suppressed.length} suppressed with a reason; see report.md)`);
  for (const w of r.warnings) console.error(`warning: ${w}`);
  for (const h of r.info.invalid_hatches) console.error(`warning: ignored hatch at ${h.file}:${h.line}: ${h.error}`);

  const baselinePath = path.resolve(args.baseline || path.join(root, 'supareach.baseline.json'));
  let code = 0;
  if (args.update) {
    let prev = null;
    if (fs.existsSync(baselinePath)) {
      try { prev = readBaseline(baselinePath); } catch (e) { if (!args.force) throw e; }
    }
    const res = writeBaseline(baselinePath, r, prev, { force: args.force });
    if (res.refused) {
      console.error(`--update-baseline refused: it would add ${res.added.length} finding(s) to the baseline:\n  ${res.added.join('\n  ')}\nFix them, ignore them with a reason, or rerun with --force.`);
      code = 1;
    } else console.log(`Baseline written to ${baselinePath} (${res.total} finding(s); ${res.added.length} added, ${res.removed.length} removed)`);
  }
  if (args.check) {
    if (!fs.existsSync(baselinePath)) fail(`--check: no baseline at ${baselinePath}. Run with --update-baseline first.`);
    const c = compareBaseline(readBaseline(baselinePath), r);
    for (const f of c.fresh) console.error(`NEW ${f.level} ${f.fingerprint}${f.at ? `  (${f.at})` : ''}`);
    if (c.fixed.length) console.log(`${c.fixed.length} baselined finding(s) no longer present (run --update-baseline to lock that in):\n  ${c.fixed.join('\n  ')}`);
    if (c.fresh.length) { console.error(`check: ${c.fresh.length} new finding(s) not in the baseline`); code = 1; }
    else console.log('check: no new findings');
  }
  return code;
}

main().then((c) => process.exit(c), (e) => { console.error(e instanceof BaselineError ? `supareach: ${e.message}` : (e && e.stack) || e); process.exit(2); });
