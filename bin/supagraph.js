#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { analyze, GATED, SCHEMA_VERSION } from '../src/analyze.js';
import { renderReport } from '../src/report.js';
import { renderHtml } from '../src/html.js';

const HELP = `supagraph [dir] [options]

Map how app code reaches a Supabase schema and report dead or risky surface.

Options:
  --out <dir>          Output directory (default ./supagraph-out)
  --config <file>      Config file (default <dir>/supagraph.config.json)
  --baseline <file>    Baseline file (default <dir>/supagraph.baseline.json)
  --check              Exit 1 if any finding count rose above the baseline
  --update-baseline    Write the current counts to the baseline file
  --no-output          Do not write graph.json / report.md / graph.html
  -h, --help           Show this help
  -v, --version        Show version
`;

function parseArgs(argv) {
  const a = { dir: '.', out: 'supagraph-out', output: true };
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    if (x === '--out') a.out = argv[++i];
    else if (x === '--config') a.config = argv[++i];
    else if (x === '--baseline') a.baseline = argv[++i];
    else if (x === '--check') a.check = true;
    else if (x === '--update-baseline') a.update = true;
    else if (x === '--no-output') a.output = false;
    else if (x === '-h' || x === '--help') a.help = true;
    else if (x === '-v' || x === '--version') a.version = true;
    else if (x.startsWith('-')) { console.error(`Unknown option ${x}\n\n${HELP}`); process.exit(2); }
    else a.dir = x;
  }
  return a;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) { process.stdout.write(HELP); process.exit(0); }
if (args.version) {
  const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  console.log(pkg.version); process.exit(0);
}

const root = path.resolve(args.dir);
if (!fs.existsSync(root)) { console.error(`No such directory: ${root}`); process.exit(2); }
const r = analyze(root, { configFile: args.config });

if (args.output) {
  const out = path.resolve(args.out);
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'graph.json'), JSON.stringify(r, null, 1));
  fs.writeFileSync(path.join(out, 'report.md'), renderReport(r));
  fs.writeFileSync(path.join(out, 'graph.html'), renderHtml(r));
  { const rel = path.relative(process.cwd(), out); console.log(`Wrote ${rel && !rel.startsWith('..') ? rel : out}/{graph.json,report.md,graph.html}`); }
}

console.log(`${r.stats.files_scanned} files, ${r.stats.call_sites} call sites (${r.stats.unresolved} unresolved), ${r.stats.migrations} migrations (${r.stats.sql_unparsed} statements not understood), ${r.stats.edge_functions} edge functions`);
for (const k of GATED) console.log(`  ${k.padEnd(32)} ${r.counts[k]}`);

const baselinePath = path.resolve(args.baseline || path.join(root, 'supagraph.baseline.json'));
if (args.update) {
  const b = { schema_version: SCHEMA_VERSION, counts: r.counts, ids: Object.fromEntries(GATED.map((k) => [k, r.findings[k].map((f) => f.id).sort()])) };
  fs.writeFileSync(baselinePath, JSON.stringify(b, null, 2) + '\n');
  console.log(`Baseline written to ${baselinePath}`);
}
if (args.check) {
  if (!fs.existsSync(baselinePath)) { console.error(`--check: no baseline at ${baselinePath}. Run with --update-baseline first.`); process.exit(2); }
  const b = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
  let failed = false;
  for (const k of GATED) {
    const was = (b.counts && b.counts[k]) || 0;
    const now = r.counts[k];
    if (now > was) {
      failed = true;
      const known = new Set((b.ids && b.ids[k]) || []);
      const fresh = r.findings[k].filter((f) => !known.has(f.id)).map((f) => `${f.id}${f.at ? ` (${f.at})` : ''}`);
      console.error(`FAIL ${k}: ${was} -> ${now}${fresh.length ? `\n    new: ${fresh.join('\n         ')}` : ''}`);
    } else if (now < was) console.log(`improved ${k}: ${was} -> ${now} (run --update-baseline to lock it in)`);
  }
  if (failed) process.exit(1);
  console.log('check: no finding count rose');
}
