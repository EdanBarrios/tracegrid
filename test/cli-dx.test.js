// CLI ergonomics and packaging.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { toSarif } from '../src/ci.js';
import { project, rm } from './helpers.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.join(here, '..');
const bin = path.join(repo, 'bin', 'supareach.js');
const run = (args, opts = {}) => spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', ...opts });
const json = (f) => JSON.parse(fs.readFileSync(path.join(repo, f), 'utf8'));

test('help alias, extra positionals rejected, reserved subcommands', () => {
  const h = run(['help']);
  assert.equal(h.status, 0);
  assert.match(h.stdout, /supareach --demo/);
  const x = run(['a', 'b']);
  assert.equal(x.status, 2);
  assert.match(x.stderr, /Unexpected argument b/);
  for (const sub of ['explain', 'path', 'init']) {
    const r = run([sub, 'x']);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /reserved/);
  }
});

test('--demo works from any directory and prints top findings with file:line', () => {
  const d = project({ 'x.txt': '' });
  const r = run(['--demo', '--no-output'], { cwd: d });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /Supabase project: supabase \(auto-detected\)/);
  assert.match(r.stdout, /Fix \d+ {2}· {2}Review \d+ {2}· {2}Info \d+/);
  assert.match(r.stdout, /Fix first:\n {2}\S+ {2}\S+ {2}\S+:\d+/);
  assert.match(r.stdout, /Not gating/);
  rm(d);
});

test('--check without a baseline explains what to do and treats every finding as new', () => {
  const d = project({
    'supabase/migrations/1_a.sql': 'create function public.f() returns int language sql as $$ select 1 $$;',
    'src/a.ts': "declare const supabase: any; supabase.rpc('g');",
  });
  const r = run([d, '--no-output', '--check']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /no baseline .* --update-baseline/);
  assert.doesNotMatch(r.stdout, /Not gating/);
  rm(d);
});

test('versions agree; package ships the demo, skill and plugin; SARIF points at the repository', () => {
  const pkg = json('package.json');
  assert.equal(pkg.version, '0.2.0');
  assert.equal(json('.claude-plugin/plugin.json').version, pkg.version);
  assert.match(fs.readFileSync(path.join(repo, 'action.yml'), 'utf8'), new RegExp(`default: ${pkg.version.replace(/\./g, '\\.')}`));
  assert.equal(pkg.engines.node, '>=20');
  assert.match(pkg.repository.url, /github\.com\/EdanBarrios\/supareach/);
  for (const f of ['examples', 'skills', '.claude-plugin']) assert.ok(pkg.files.includes(f), f);
  assert.equal(Object.keys(pkg.dependencies).join(), 'typescript');
  const skill = fs.readFileSync(path.join(repo, 'skills/supareach/SKILL.md'), 'utf8');
  assert.match(skill, /^---\nname: supareach\ndescription: /);
  assert.ok(skill.split('\n').length < 500);
  assert.match(fs.readFileSync(path.join(repo, 'README.md'), 'utf8'), /!\[[^\]]*\]\(https:\/\//);
  const s = toSarif({ rules: [], findings: [], source: 'migrations' });
  assert.equal(s.runs[0].tool.driver.informationUri, 'https://github.com/EdanBarrios/supareach');
});

