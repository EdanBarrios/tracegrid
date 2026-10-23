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
  const r = await analyze(demo, { allowPlugins: true });
  const ids = (k) => r.findings.filter((f) => f.rule === k).map((f) => f.id).sort();
  assert.deepEqual(ids('exposed-uncalled-function'), ['internal_cleanup/0', 'next_invoice_number/1']);
  assert.deepEqual(ids('granted-helper-function'), ['is_project_member/1']);
  assert.deepEqual(r.findings.find((f) => f.rule === 'granted-helper-function').usedBy, ['policy-uses']);
  assert.deepEqual(ids('client-table-without-rls'), ['audit_log']);
  assert.deepEqual(ids('client-table-without-policies'), ['invoices']);
  assert.deepEqual(ids('missing-rpc'), ['delete_everything']);
  assert.deepEqual(ids('uncalled-edge-function'), ['export-csv']); // payment-webhook: verify_jwt = false
  assert.deepEqual(ids('unknown-table'), []);
  assert.deepEqual(r.info.external_entry_points.map((e) => [e.id, e.source]), [['payment-webhook', 'supabase/config.toml']]);
  assert.ok(r.links.some((x) => x.source === 'external:http' && x.target === 'edge:payment-webhook' && x.relation === 'entry-point'));
  assert.ok(r.findings.every((f) => f.fingerprint === `${f.rule}:${f.id}` && f.level));
  assert.deepEqual(r.info.storage_buckets.map((b) => b.id).sort(), ['avatars', 'invoice-pdfs']);
  assert.equal(r.info.unresolved_dynamic_calls.length, 1);
  assert.equal(r.schema_version, 1);
  // graph shape
  const e = r.links.find((x) => x.target === 'fn:project_stats_v2/1');
  assert.equal(e.confidence, 'ambiguous');
  assert.ok(r.links.some((x) => x.source === 'cron:nightly-digest' && x.target === 'edge:nightly-digest'));
  assert.ok(r.links.some((x) => x.source === 'table:tasks' && x.target === 'fn:is_project_member/1' && x.relation === 'policy-uses'));
});

const run = (...a) => spawnSync(process.execPath, [bin, ...a, '--allow-plugins'], { encoding: 'utf8' });

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

test('entry points: config with reason, hatch, and autoEntryPoints off', async () => {
  const { loadConfig } = await import('../src/config.js');
  const base = loadConfig(demo);
  let r = await analyze(demo, { allowPlugins: true, config: { ...base, autoEntryPoints: false, entryPoints: [{ name: 'export-csv', reason: 'downloaded by the ops team by URL' }, { name: 'nope', reason: 'x' }] } });
  const ids = (k) => r.findings.filter((f) => f.rule === k).map((f) => f.id).sort();
  assert.deepEqual(ids('uncalled-edge-function'), ['payment-webhook']);
  assert.deepEqual(r.info.external_entry_points.map((e) => e.id), ['export-csv']);
  assert.match(r.info.invalid_hatches.map((h) => h.error).join(), /no edge function named nope/);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'supareach-'));
  fs.cpSync(demo, tmp, { recursive: true });
  const idx = path.join(tmp, 'supabase/functions/export-csv/index.ts');
  fs.writeFileSync(idx, '// supareach: entry-point linked from the admin email\n' + fs.readFileSync(idx, 'utf8'));
  r = await analyze(tmp, { allowPlugins: true });
  assert.deepEqual(r.findings.filter((f) => f.rule === 'uncalled-edge-function').map((f) => f.id), []);
  assert.match(r.info.external_entry_points.find((e) => e.id === 'export-csv').source, /^hatch supabase\/functions\/export-csv\/index.ts:1$/);
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

test('graph.json is networkx node-link shaped (Graphify-compatible)', async () => {
  const r = await analyze(demo, { allowPlugins: true });
  assert.equal(r.schema_version, 1);
  assert.equal(r.directed, true);
  assert.equal(r.multigraph, false);
  assert.equal(typeof r.graph, 'object');
  assert.equal(r.edges, undefined);
  const ids = new Set(r.nodes.map((n) => n.id));
  for (const n of r.nodes) assert.ok(n.id && n.label && n.type, JSON.stringify(n));
  for (const l of r.links) {
    assert.ok(ids.has(l.source) && ids.has(l.target), `dangling link ${l.source} -> ${l.target}`);
    assert.ok(typeof l.relation === 'string' && l.relation);
    assert.ok(['extracted', 'inferred', 'ambiguous'].includes(l.confidence));
  }
  const conf = new Set(r.links.map((l) => l.confidence));
  assert.deepEqual([...conf].sort(), ['ambiguous', 'extracted', 'inferred']);
});
