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

test('demo app findings', () => {
  const r = analyze(demo);
  const ids = (k) => r.findings[k].map((f) => f.id).sort();
  assert.deepEqual(ids('exposed_uncalled_functions'), ['internal_cleanup', 'next_invoice_number']);
  assert.deepEqual(ids('client_tables_without_rls'), ['audit_log']);
  assert.deepEqual(ids('client_tables_without_policies'), ['invoices']);
  assert.deepEqual(ids('missing_rpcs'), ['delete_everything']);
  assert.deepEqual(ids('uncalled_edge_functions'), ['export-csv']); // payment-webhook ignored by config
  assert.deepEqual(ids('unknown_tables'), []);
  assert.deepEqual(r.info.storage_buckets.map((b) => b.id).sort(), ['avatars', 'invoice-pdfs']);
  assert.equal(r.info.unresolved_dynamic_calls.length, 1);
  assert.equal(r.schema_version, 1);
  // graph shape
  const e = r.edges.find((x) => x.target === 'fn:project_stats_v2');
  assert.equal(e.confidence, 'inferred');
  assert.ok(r.edges.some((x) => x.source === 'cron:nightly-digest' && x.target === 'edge:nightly-digest'));
  assert.ok(r.edges.some((x) => x.source === 'table:tasks' && x.target === 'fn:is_project_member' && x.kind === 'policy-uses'));
});

test('CLI writes outputs and --check gates on rising counts', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'supareach-'));
  const out = path.join(tmp, 'out');
  const baseline = path.join(tmp, 'baseline.json');
  execFileSync(process.execPath, [bin, demo, '--out', out, '--baseline', baseline, '--update-baseline'], { stdio: 'pipe' });
  for (const f of ['graph.json', 'report.md', 'graph.html']) assert.ok(fs.existsSync(path.join(out, f)), f);
  const html = fs.readFileSync(path.join(out, 'graph.html'), 'utf8');
  assert.doesNotMatch(html, /<script[^>]+src=/);
  assert.doesNotMatch(html, /<link[^>]+href=/);

  let r = spawnSync(process.execPath, [bin, demo, '--no-output', '--baseline', baseline, '--check']);
  assert.equal(r.status, 0, r.stderr.toString());

  const b = JSON.parse(fs.readFileSync(baseline, 'utf8'));
  b.counts.missing_rpcs = 0;
  b.ids.missing_rpcs = [];
  fs.writeFileSync(baseline, JSON.stringify(b));
  r = spawnSync(process.execPath, [bin, demo, '--no-output', '--baseline', baseline, '--check']);
  assert.equal(r.status, 1);
  assert.match(r.stderr.toString(), /FAIL missing_rpcs: 0 -> 1[\s\S]*delete_everything/);

  r = spawnSync(process.execPath, [bin, demo, '--no-output', '--baseline', path.join(tmp, 'none.json'), '--check']);
  assert.equal(r.status, 2);
  fs.rmSync(tmp, { recursive: true, force: true });
});
