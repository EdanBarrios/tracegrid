import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { analyze } from '../src/analyze.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const demo = path.join(here, '..', 'examples', 'demo-app');
const bin = path.join(here, '..', 'bin', 'supareach.js');

test('demo app findings', async () => {
  const r = await analyze(demo);
  const ids = (k) => r.findings.filter((f) => f.rule === k).map((f) => f.id).sort();
  assert.deepEqual(ids('exposed-uncalled-function'), ['internal_cleanup', 'next_invoice_number']);
  assert.deepEqual(ids('client-table-without-rls'), ['audit_log']);
  assert.deepEqual(ids('client-table-without-policies'), ['invoices']);
  assert.deepEqual(ids('missing-rpc'), ['delete_everything']);
  assert.deepEqual(ids('uncalled-edge-function'), ['export-csv']); // payment-webhook ignored by config
  assert.deepEqual(ids('unknown-table'), []);
  assert.deepEqual(r.suppressed.map((f) => f.fingerprint), ['uncalled-edge-function:payment-webhook']);
  assert.ok(r.findings.every((f) => f.fingerprint === `${f.rule}:${f.id}` && f.level));
  assert.deepEqual(r.info.storage_buckets.map((b) => b.id).sort(), ['avatars', 'invoice-pdfs']);
  assert.equal(r.info.unresolved_dynamic_calls.length, 1);
  assert.equal(r.schema_version, 1);
  // graph shape
  const e = r.edges.find((x) => x.target === 'fn:project_stats_v2');
  assert.equal(e.confidence, 'inferred');
  assert.ok(r.edges.some((x) => x.source === 'cron:nightly-digest' && x.target === 'edge:nightly-digest'));
  assert.ok(r.edges.some((x) => x.source === 'table:tasks' && x.target === 'fn:is_project_member' && x.kind === 'policy-uses'));
});

const run = (...a) => spawnSync(process.execPath, [bin, ...a], { encoding: 'utf8' });

test('CLI writes outputs; --check gates on fingerprints, not counts', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'supareach-'));
  const out = path.join(tmp, 'out');
  const baseline = path.join(tmp, 'baseline.json');
  let r = run(demo, '--out', out, '--baseline', baseline, '--update-baseline');
  assert.equal(r.status, 0, r.stderr);
  for (const f of ['graph.json', 'report.md', 'graph.html']) assert.ok(fs.existsSync(path.join(out, f)), f);
  const html = fs.readFileSync(path.join(out, 'graph.html'), 'utf8');
  assert.doesNotMatch(html, /<script[^>]+src=/);
  assert.doesNotMatch(html, /<link[^>]+href=/);
  const b = JSON.parse(fs.readFileSync(baseline, 'utf8'));
  assert.ok(b.findings.includes('missing-rpc:delete_everything'));

  r = run(demo, '--no-output', '--baseline', baseline, '--check');
  assert.equal(r.status, 0, r.stderr);

  // Count-neutral swap: the baseline has a finding that is gone and lacks one that is present.
  const swapped = b.findings.filter((x) => x !== 'missing-rpc:delete_everything').concat('missing-rpc:something_fixed');
  fs.writeFileSync(baseline, JSON.stringify({ ...b, findings: swapped }));
  r = run(demo, '--no-output', '--baseline', baseline, '--check');
  assert.equal(r.status, 1);
  assert.match(r.stderr, /NEW error missing-rpc:delete_everything/);
  assert.match(r.stdout, /no longer present[\s\S]*missing-rpc:something_fixed/);

  // --update-baseline only shrinks unless --force.
  r = run(demo, '--no-output', '--baseline', baseline, '--update-baseline');
  assert.equal(r.status, 1);
  assert.match(r.stderr, /refused[\s\S]*missing-rpc:delete_everything/);
  r = run(demo, '--no-output', '--baseline', baseline, '--update-baseline', '--force');
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(fs.readFileSync(baseline, 'utf8')).findings, b.findings);

  r = run(demo, '--no-output', '--baseline', path.join(tmp, 'none.json'), '--check');
  assert.equal(r.status, 2);
  fs.writeFileSync(path.join(tmp, 'old.json'), JSON.stringify({ counts: {} }));
  r = run(demo, '--no-output', '--baseline', path.join(tmp, 'old.json'), '--check');
  assert.equal(r.status, 2);
  assert.match(r.stderr, /expected \{ "findings"/);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('ignores without a reason are a config error (exit 2)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'supareach-'));
  const cfg = path.join(tmp, 'c.json');
  fs.writeFileSync(cfg, JSON.stringify({ ignore: { functions: ['internal_cleanup'] } }));
  let r = run(demo, '--no-output', '--config', cfg);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /bare string/);
  fs.writeFileSync(cfg, JSON.stringify({ ignore: { functions: [{ name: 'internal_cleanup', reason: ' ' }] } }));
  r = run(demo, '--no-output', '--config', cfg);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /non-empty "reason"/);
  fs.rmSync(tmp, { recursive: true, force: true });
});
