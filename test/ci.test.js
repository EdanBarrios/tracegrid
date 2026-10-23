import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { analyze } from '../src/analyze.js';
import { toSarif, githubAnnotations, location } from '../src/ci.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const demo = path.join(here, '..', 'examples', 'demo-app');
const bin = path.join(here, '..', 'bin', 'supareach.js');

test('SARIF 2.1.0: rules, results with locations and fingerprints', async () => {
  const r = await analyze(demo, { allowPlugins: true });
  const s = toSarif(r, { version: '9.9.9', prefix: 'examples/demo-app' });
  assert.equal(s.version, '2.1.0');
  const run = s.runs[0];
  assert.equal(run.tool.driver.name, 'supareach');
  assert.deepEqual(run.tool.driver.rules.map((x) => x.id), r.rules.map((x) => x.id));
  for (const x of run.tool.driver.rules) assert.ok(x.shortDescription.text && x.fullDescription.text && x.help.text);
  assert.equal(run.results.length, r.findings.length);
  for (const res of run.results) {
    assert.ok(['error', 'warning', 'note'].includes(res.level));
    assert.equal(run.tool.driver.rules[res.ruleIndex].id, res.ruleId);
    assert.ok(res.message.text);
    assert.match(res.locations[0].physicalLocation.artifactLocation.uri, /^examples\/demo-app\//);
    assert.ok(res.locations[0].physicalLocation.region.startLine >= 1);
    assert.match(res.partialFingerprints['supareach/v1'], /^[^:]+:.+/);
  }
  const mr = run.results.find((x) => x.ruleId === 'missing-rpc');
  assert.equal(mr.locations[0].physicalLocation.artifactLocation.uri, 'examples/demo-app/src/features/projects/api.ts');
  const fn = run.results.find((x) => x.partialFingerprints['supareach/v1'] === 'exposed-uncalled-function:next_invoice_number/1');
  assert.match(fn.locations[0].physicalLocation.artifactLocation.uri, /supabase\/migrations\/20240201000000_billing\.sql$/);
});

test('GitHub annotations escape data and map levels', () => {
  const rules = [{ id: 'r', title: 'T', level: 'error' }];
  const out = githubAnnotations([
    { rule: 'r', id: 'a,b', level: 'error', at: 'src/x.ts:3', message: '50% done\nnext' },
    { rule: 'r', id: 'c', level: 'note', at: 'db:c()' },
  ], rules, 'app');
  assert.equal(out[0], '::error file=app/src/x.ts,line=3,title=supareach r::T: a,b (50%25 done%0Anext)');
  assert.equal(out[1], '::notice title=supareach r::T: c');
  assert.deepEqual(location('supabase/functions/x/index.ts'), { file: 'supabase/functions/x/index.ts', line: 1 });
});

test('CLI --sarif and --github with --check annotate only new findings and write a step summary', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'supareach-'));
  const baseline = path.join(tmp, 'b.json');
  const summary = path.join(tmp, 'summary.md');
  let r = spawnSync(process.execPath, [bin, demo, '--allow-plugins', '--no-output', '--baseline', baseline, '--update-baseline'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const b = JSON.parse(fs.readFileSync(baseline, 'utf8'));
  fs.writeFileSync(baseline, JSON.stringify({ ...b, findings: b.findings.filter((x) => x !== 'client-table-without-rls:audit_log' && x !== 'missing-rpc:delete_everything') }));
  const env = { ...process.env, GITHUB_STEP_SUMMARY: summary, GITHUB_WORKSPACE: path.join(here, '..') };
  r = spawnSync(process.execPath, [bin, demo, '--allow-plugins', '--no-output', '--baseline', baseline, '--check', '--github', '--sarif', path.join(tmp, 'out.sarif')], { encoding: 'utf8', env });
  assert.equal(r.status, 1);
  const ann = r.stdout.split('\n').filter((l) => l.startsWith('::'));
  assert.deepEqual(ann, ['::error file=examples/demo-app/src/features/billing/api.ts,line=10,title=supareach client-table-without-rls::[fix] Client-touched tables with RLS off: audit_log (1 call site(s))']);
  const md = fs.readFileSync(summary, 'utf8');
  assert.match(md, /## supareach/);
  assert.match(md, /1 new finding\(s\) not in the baseline[\s\S]*fix `client-table-without-rls:audit_log`/);
  assert.match(md, /\*\*Fix \d+\*\* · Review \d+ · Info \d+/);
  const sarif = JSON.parse(fs.readFileSync(path.join(tmp, 'out.sarif'), 'utf8'));
  assert.equal(sarif.version, '2.1.0');
  fs.rmSync(tmp, { recursive: true, force: true });
});
