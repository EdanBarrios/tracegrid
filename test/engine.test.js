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
  const r = await analyze(demo);
  const f = r.findings.filter((x) => x.rule === 'demo/client-writes-protected-table');
  assert.deepEqual(f.map((x) => x.id), ['audit_log']);
  assert.equal(f[0].level, 'error');
  assert.ok(r.rules.some((x) => x.id === 'demo/client-writes-protected-table' && x.plugin));
});

test('a plugin without a rules export is a clear error', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'supareach-'));
  fs.writeFileSync(path.join(tmp, 'p.mjs'), 'export const nope = 1;');
  await assert.rejects(loadPlugins(tmp, ['p.mjs']), /must export `rules`/);
  fs.rmSync(tmp, { recursive: true, force: true });
});
