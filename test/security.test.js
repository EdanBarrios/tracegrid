// Security regressions: tracegrid runs in CI on pull requests, where the PR author controls the
// config, migrations, scanned files and node_modules/.bin. Fixtures are generated in temp dirs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { project, rm } from './helpers.js';
import { CATALOG_SQL, urlToEnv, DbError } from '../src/db.js';
import { findFiles, loadConfig } from '../src/config.js';
import { renderReport } from '../src/report.js';
import { stepSummary } from '../src/ci.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const bin = path.join(here, '..', 'bin', 'tracegrid.js');
const run = (args, env = {}, opts = {}) => spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', env: { ...process.env, ...env }, ...opts });

const EVIL_PLUGIN = `import fs from 'node:fs';\nfs.writeFileSync(process.env.EXFIL_FILE, 'db=' + process.env.TRACEGRID_DB_URL);\nexport const rules = [];\n`;

test('S0-1 plugins listed in the project config are not imported without --allow-plugins', () => {
  const d = project({ 'evil.mjs': EVIL_PLUGIN, 'tracegrid.config.json': '{ "plugins": ["./evil.mjs"] }', 'src/a.ts': 'export const z = supabase.rpc("ok");\n' });
  const marker = path.join(d, 'exfil.txt');
  const r = run([d, '--no-output'], { GITHUB_ACTIONS: 'true', GITHUB_EVENT_NAME: 'pull_request', EXFIL_FILE: marker, TRACEGRID_DB_URL: 'postgresql://ro:S3CRET@127.0.0.1:1/db', TRACEGRID_PSQL: '/usr/bin/false' });
  assert.ok(!fs.existsSync(marker), 'the plugin module ran');
  assert.equal(r.status, 2);
  assert.match(r.stderr, /plugins? .*(disabled|refused|--allow-plugins)/i);
  // --allow-plugins is refused outright on pull_request events.
  const r2 = run([d, '--no-output', '--allow-plugins'], { GITHUB_ACTIONS: 'true', GITHUB_EVENT_NAME: 'pull_request', EXFIL_FILE: marker });
  assert.ok(!fs.existsSync(marker));
  assert.equal(r2.status, 2);
  assert.match(r2.stderr, /refused on GitHub "pull_request"/);
  // --no-plugins runs without them, with a warning.
  const r3 = run([d, '--no-output', '--no-plugins'], { EXFIL_FILE: marker });
  assert.ok(!fs.existsSync(marker));
  assert.match(r3.stderr, /not loaded/);
  // Trusted run: --allow-plugins loads them.
  const r4 = run([d, '--no-output', '--allow-plugins'], { EXFIL_FILE: marker, GITHUB_ACTIONS: '', GITHUB_EVENT_NAME: '' });
  assert.equal(r4.status, 0, r4.stderr);
  assert.ok(fs.existsSync(marker));
  rm(d);
});

test('S0-1b plugin paths outside the project root are refused even when plugins are allowed', () => {
  const outside = project({ 'evil.mjs': EVIL_PLUGIN });
  const d = project({ 'src/a.ts': 'export const z = supabase.rpc("ok");\n' });
  fs.writeFileSync(path.join(d, 'tracegrid.config.json'), JSON.stringify({ plugins: [path.relative(d, path.join(outside, 'evil.mjs')).split(path.sep).join('/')] }));
  const marker = path.join(outside, 'exfil.txt');
  const r = run([d, '--no-output', '--allow-plugins'], { EXFIL_FILE: marker, GITHUB_ACTIONS: '' });
  assert.ok(!fs.existsSync(marker), 'plugin outside root was imported');
  assert.equal(r.status, 2);
  assert.match(r.stderr, /outside the project/i);
  rm(d); rm(outside);
});

test('S0-2 a psql found under the project directory is never executed', { skip: process.platform === 'win32' }, () => {
  const H = project({ 'package.json': '{"name":"victim","private":true}', 'src/a.ts': 'export const z = supabase.rpc("ok");\n',
    'node_modules/.bin/psql': '#!/bin/sh\necho "pw=$PGPASSWORD" > "$HIJACK_OUT"\n' });
  fs.chmodSync(path.join(H, 'node_modules', '.bin', 'psql'), 0o755);
  const marker = path.join(H, 'hijack.txt');
  const PATH = path.join(H, 'node_modules', '.bin') + path.delimiter + process.env.PATH; // what `npx tracegrid` does
  const r = run(['.', '--no-output', '--db-url', 'postgresql://ro:S3CRET@db.invalid:5432/postgres'], { PATH, HIJACK_OUT: marker, TRACEGRID_PSQL: '' }, { cwd: H });
  assert.ok(!fs.existsSync(marker), 'node_modules/.bin/psql from the project ran and received PGPASSWORD');
  assert.equal(r.status, 2, r.stdout + r.stderr);
  assert.match(r.stderr, /psql.*(inside|under) the project|refus/i);
  // A relative TRACEGRID_PSQL is refused too.
  const r2 = run(['.', '--no-output', '--db-url', 'postgresql://ro:x@db.invalid/postgres'], { TRACEGRID_PSQL: 'node_modules/.bin/psql', HIJACK_OUT: marker }, { cwd: H });
  assert.equal(r2.status, 2);
  assert.ok(!fs.existsSync(marker));
  rm(H);
});

test('S1-1 catalog script pins search_path to pg_catalog before any query', () => {
  // pg_temp listed last: unlisted, it would be searched first for relations.
  assert.match(CATALOG_SQL, /^\s*begin[^;]*read only;\s*set local search_path (?:to|=) pg_catalog, pg_temp\s*;/i);
});

test('S1-1b --db-url rejects ?options= (PGOPTIONS can set search_path and other settings)', () => {
  assert.throws(() => urlToEnv('postgresql://u:p@h/db?options=-c%20search_path%3Devil,pg_catalog'), DbError);
});

const hostileResult = () => ({
  root: 'x', generated_at: 'now', schema_version: 1, source: 'migrations', warnings: ['w\n## Injected warning heading'],
  rules: [{ id: 'missing-rpc', level: 'error', title: 'RPCs called that the schema does not define', why: 'w' }],
  counts: { 'missing-rpc': 1 },
  findings: [{ rule: 'missing-rpc', level: 'error', id: 'y\n\n## Fake heading\n\nNone.\n', fingerprint: 'missing-rpc:y\n\n## Fake heading\n\nNone.\n', at: 'src/a`b.ts:1', sites: 1 }],
  suppressed: [], stats: { files_scanned: 1, call_sites: 1, unresolved: 0, distinct_rpcs_called: { client: 1, edge: 0 }, distinct_tables_touched: { client: 0, edge: 0 }, migrations: 0, sql_statements: 0, sql_unparsed: 0, tables: 0, views: 0, functions: 0, policies: 0, cron_jobs: 0, edge_functions: 0, distinct_edge_functions_invoked: 0 },
  info: { storage_buckets: [], unresolved_dynamic_calls: [{ kind: 'rpc', file: 'a|b.ts', line: 1, expr: 'x\n# h' }], unparsed_sql: [], invalid_hatches: [], unreadable_files: [{ file: 'q.ts', error: 'e\n## Bad' }], external_entry_points: [] },
});

test('S1-2 report.md cannot gain headings or lines from project data', () => {
  const lines = renderReport(hostileResult()).split('\n');
  assert.ok(!lines.some((l) => /^#+ (Fake|Injected|h$|Bad)/.test(l)), 'injected heading rendered as markdown');
  assert.equal(lines.filter((l) => l === 'None.').length, 0, 'injected "None." line');
});

test('S1-2b step summary cannot gain headings or lines from a fingerprint', () => {
  const r = hostileResult();
  const lines = stepSummary(r, r.findings).split('\n');
  assert.ok(!lines.some((l) => /^## (Fake|Injected)/.test(l)));
});

test('S1-3 no console line produced from project data starts with "::"', () => {
  const F = project({
    'src/api.ts': [
      "import { supabase } from './client';",
      "export const a = () => supabase.rpc('x\\n::warning title=pwned::no new findings\\n');",
      "export const d = () => supabase.rpc('y\\n\\n## Fake heading\\n\\nNone.\\n');",
      "export const f = () => supabase.functions.invoke('ef\\n::error::boom');",
    ].join('\n'),
    'src/weird name#1.ts': "export const g = () => supabase.from('t\\r::notice::x').select('*');\n",
    'supabase/migrations/0001_init.sql': 'create table "t<b>bold</b>" (id int);\ncreate function "f""n"(x int) returns int language sql as $$ select 1 $$;\n',
    'b.json': '{"schema_version":1,"tool":"tracegrid","findings":[]}',
  });
  const b = path.join(F, 'b.json');
  const r = run([F, '--no-output', '--baseline', b, '--check']); // no --github: nothing legitimate starts with ::
  const bad = (r.stdout + r.stderr).split(/\r?\n/).filter((l) => l.startsWith('::'));
  assert.deepEqual(bad, [], 'these lines would be executed as workflow commands by the Actions runner');
  const r2 = run([F, '--no-output', '--baseline', b, '--update-baseline']);
  assert.deepEqual((r2.stdout + r2.stderr).split(/\r?\n/).filter((l) => l.startsWith('::')), []);
  rm(F);
});

test('S2-1 include globs cannot leave the project root', () => {
  const base = project({ 'repo/src/a.ts': 'x', 'outside/code/secret.ts': 'y' });
  const files = findFiles(path.join(base, 'repo'), ['src/**/*.ts', '../outside/code/**/*.ts'], []);
  assert.deepEqual(files, ['src/a.ts']);
  rm(base);
});

test('S2-1b migrations / functionsDir / include outside the root are a config error', () => {
  const base = project({ 'repo/tracegrid.config.json': '{ "migrations": "../outside/sql" }', 'outside/sql/0001_x.sql': 'create table t (x int);' });
  assert.throws(() => loadConfig(path.join(base, 'repo')), /outside/);
  fs.writeFileSync(path.join(base, 'repo', 'tracegrid.config.json'), '{ "include": ["../outside/**/*.ts"] }');
  assert.throws(() => loadConfig(path.join(base, 'repo')), /outside/);
  fs.writeFileSync(path.join(base, 'repo', 'tracegrid.config.json'), '{ "functionsDir": "/etc" }');
  assert.throws(() => loadConfig(path.join(base, 'repo')), /outside/);
  rm(base);
});

test('S2-1c symlinks are followed only when the target is inside the project', { skip: process.platform === 'win32' }, () => {
  const base = project({ 'elsewhere/deep/x.ts': 'leak', 'elsewhere/outside.sql': 'create table leaked (x int);', 'repo/pkg/a.ts': 'ok',
    'repo/supabase/migrations/0001_init.sql': 'create table t (x int);' });
  const repo = path.join(base, 'repo');
  fs.symlinkSync(path.join(base, 'elsewhere'), path.join(repo, 'src-out'));
  fs.symlinkSync(path.join(base, 'elsewhere', 'deep', 'x.ts'), path.join(repo, 'filelink.ts'));
  fs.symlinkSync('pkg', path.join(repo, 'pkg-link'));
  fs.symlinkSync(path.join(base, 'elsewhere', 'outside.sql'), path.join(repo, 'supabase', 'migrations', '0002_link.sql'));
  assert.deepEqual(findFiles(repo, ['**/*.ts'], []), ['pkg-link/a.ts', 'pkg/a.ts']);
  const r = run([repo, '--out', path.join(base, 'out')]);
  const g = JSON.parse(fs.readFileSync(path.join(base, 'out', 'graph.json'), 'utf8'));
  assert.ok(!g.nodes.some((n) => n.id === 'table:leaked'), 'a symlinked migration outside the project was replayed');
  assert.ok(!fs.readFileSync(path.join(base, 'out', 'report.md'), 'utf8').includes('leak'), r.stderr);
  rm(base);
});

// ---------------------------------------------------------------------------------------------
// Resource limits and parser robustness on inputs a pull request controls.
const inChild = (code, timeout) => spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8', timeout });
const srcUrl = (f) => JSON.stringify(new URL(`../src/${f}`, import.meta.url).href);

test('S2-2 splitStatements is linear: a 200 KB statement finishes in under 2 s', () => {
  const r = inChild(`import { splitStatements } from ${srcUrl('scan-sql.js')};
    splitStatements('insert into t values (' + '1,'.repeat(100000) + '1)');`, 2000 + 1500);
  assert.equal(r.status, 0, 'killed by timeout: quadratic');
});

test('S2-2b sqlRefs is linear: an 80 KB identifier finishes in under 1 s', async () => {
  const { sqlRefs } = await import('../src/scan-sql.js');
  const t0 = performance.now();
  sqlRefs('a'.repeat(80000), new Set(['x']));
  sqlRefs('a.'.repeat(40000) + '(', new Set(['x']));
  assert.ok(performance.now() - t0 < 1000, 'quadratic scan');
});

test('S2-2c hatch comment regex is linear on trailing whitespace', async () => {
  const { parseHatches } = await import('../src/hatches.js');
  const t0 = performance.now();
  parseHatches('// tracegrid: names x' + ' '.repeat(80000) + '*/x');
  assert.ok(performance.now() - t0 < 1000, 'quadratic regex');
});

test('S2-2d source files over 2 MB and statements over 256 KB are skipped and listed', async () => {
  const { scanFiles } = await import('../src/scan-code.js');
  const { scanMigrations } = await import('../src/scan-sql.js');
  const d = project({
    'src/big.ts': 'export const x = supabase.rpc("a");\n'.repeat(80000),
    'supabase/migrations/1_big.sql': `insert into t values ('${'x'.repeat(300 * 1024)}');\ncreate table ok (id int);\n`,
  });
  const r = scanFiles(d, ['src/big.ts'], { rpc: [], from: [], invoke: [] });
  assert.equal(r.calls.length, 0);
  assert.match(r.failed[0].error, /too large/);
  const st = scanMigrations(path.join(d, 'supabase', 'migrations'));
  assert.ok(st.tables.has('ok'));
  assert.match(st.unparsed[0].reason, /larger than 256 KB/);
  rm(d);
});

test('S2-3 globToRegExp terminates on an unclosed brace (treated as a literal)', () => {
  const r = inChild(`import { globToRegExp } from ${srcUrl('config.js')};
    const re = globToRegExp('src/{a');
    if (!re.test('src/{a')) process.exit(3);`, 3000);
  assert.equal(r.status, 0, r.status === 3 ? 'unclosed { not literal' : 'hung (killed by timeout)');
});

test('S3-1 SARIF percent-encodes file paths', async () => {
  const { toSarif } = await import('../src/ci.js');
  const r = hostileResult();
  r.findings[0].at = 'src/weird name#1.ts:1';
  const s = toSarif(r, { version: '0', prefix: '' });
  assert.equal(s.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'src/weird%20name%231.ts');
});

test('S3-2 __proto__ / constructor keys in the config have no effect; unknown keys warn', async () => {
  const d = project({ 'tracegrid.config.json': '{ "__proto__": { "polluted": true, "include": ["x/**"] }, "constructor": { "prototype": { "p": 1 } }, "inclde": ["src/**"] }' });
  const cfg = loadConfig(d);
  assert.equal(cfg.polluted, undefined);
  assert.equal(Object.getPrototypeOf(cfg), Object.prototype);
  assert.notDeepEqual(cfg.include, ['x/**']);
  assert.equal({}.p, undefined);
  assert.deepEqual(cfg._warnings, ['unknown config key "inclde" (ignored)']);
  rm(d);
});
