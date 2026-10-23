import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateRule, runRules, makeGraph, loadPlugins, RuleError } from '../src/engine.js';
import { coreRules } from '../src/rules/core.js';
import { analyze } from '../src/analyze.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const demo = path.join(here, '..', 'examples', 'demo-app');
const ok = { id: 'x/y', level: 'warning', title: 't', why: 'w', run: () => [] };

test('core rules satisfy the contract', () => {
  for (const r of coreRules) validateRule(r);
  assert.ok(coreRules.length >= 7);
});

test('validateRule rejects malformed rules', () => {
  validateRule(ok);
  assert.throws(() => validateRule({ ...ok, id: 'Bad Id' }), RuleError);
  assert.throws(() => validateRule({ ...ok, level: 'fatal' }), RuleError);
  assert.throws(() => validateRule({ ...ok, why: '' }), RuleError);
  assert.throws(() => validateRule({ ...ok, run: 1 }), RuleError);
});

test('runRules stamps fingerprints, dedupes subjects and applies suppression', () => {
  const r = { ...ok, run: () => [{ id: 'b' }, { id: 'a' }, { id: 'a' }, { id: 'c' }] };
  const res = runRules([r], { graph: makeGraph([], []) }, (f) => (f.id === 'c' ? 'because' : null));
  assert.deepEqual(res.findings.map((f) => f.fingerprint), ['x/y:a', 'x/y:b']);
  assert.deepEqual(res.suppressed.map((f) => [f.fingerprint, f.suppressed]), [['x/y:c', 'because']]);
  assert.throws(() => runRules([r, r], { graph: makeGraph([], []) }), /duplicate rule id/);
  assert.throws(() => runRules([{ ...ok, run: () => [{}] }], {}), /string id/);
});

test('plugins load from config paths and run like core rules', async () => {
  const r = await analyze(demo, { allowPlugins: true });
  const f = r.findings.filter((x) => x.rule === 'demo/client-writes-protected-table');
  assert.deepEqual(f.map((x) => x.id), ['audit_log']);
  assert.equal(f[0].level, 'error');
  assert.ok(r.rules.some((x) => x.id === 'demo/client-writes-protected-table' && x.plugin));
});

test('a plugin without a rules export is a clear error', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tracegrid-'));
  fs.writeFileSync(path.join(tmp, 'p.mjs'), 'export const nope = 1;');
  await assert.rejects(loadPlugins(tmp, ['p.mjs']), /must export `rules`/);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('hatches: names resolve, ignore needs a reason and suppresses, SQL ignore targets the next object', async () => {
  const { parseHatches } = await import('../src/hatches.js');
  const { scanSource } = await import('../src/scan-code.js');
  const { createState, splitStatements, applyStatement, sqlHatches } = await import('../src/scan-sql.js');
  assert.equal(parseHatches('// tracegrid: ignore missing-rpc')[0].error.startsWith('ignore: needs'), true);
  assert.equal(parseHatches('// tracegrid: entry-point')[0].error.startsWith('entry-point: needs'), true);
  assert.match(parseHatches('// tracegrid: frobnicate x')[0].error, /unknown directive/);

  const r = scanSource(`
    // tracegrid: names tasks, projects
    export function count(tableName: string) { return supabase.from(tableName).select('*'); }
    const t = (n: string) =>
      supabase.from(n).select(); // not covered: stays unresolved
    supabase.rpc('gone'); // tracegrid: ignore missing-rpc removed next release
    // tracegrid: ignore missing-rpc
    supabase.rpc('also_gone');
  `, 'a.ts');
  assert.deepEqual(r.calls.filter((c) => c.kind === 'table').map((c) => [c.name, c.via]), [['tasks', 'hatch'], ['projects', 'hatch']]);
  assert.equal(r.unresolved.length, 1);
  assert.deepEqual(r.hatches.suppress.map((h) => [h.rule, h.subject, h.reason]), [['missing-rpc', 'gone', 'removed next release']]);
  assert.equal(r.hatches.invalid.length, 1);

  const st = createState();
  const sql = `-- tracegrid: ignore exposed-uncalled-function called by the partner API\ncreate function public.f() returns int language sql as $$ select 1 $$;\n-- tracegrid: ignore exposed-uncalled-function no target\nselect 1;`;
  const ss = splitStatements(sql);
  for (const s of ss) applyStatement(st, s, 'm.sql');
  sqlHatches(st, parseHatches(sql), ss, 'm.sql');
  assert.deepEqual(st.hatches.suppress.map((h) => [h.subject, h.at]), [['f', 'm.sql:1']]);
  assert.equal(st.hatches.invalid.length, 1);
});
