// App-code extraction and scan scope. Each case is a tiny synthetic project in a temp dir.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { analyze } from '../src/analyze.js';
import { scanSource } from '../src/scan-code.js';
import { project, rm } from './helpers.js';

const bin = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'supareach.js');

const SQL = `
create table public.items (id bigint primary key, owner uuid);
alter table public.items enable row level security;
create policy "own" on public.items for select to authenticated using (owner = auth.uid());
create table public.secrets (id bigint primary key, item_id bigint references public.items(id), value text);
create table public.people (id bigint primary key, first text, last text);
alter table public.people enable row level security;
create policy "read" on public.people for select to authenticated using (true);
create function public.target_fn() returns int language sql as $$ select 1 $$;
create function public.other_fn() returns int language sql as $$ select 2 $$;
create function public.never_called() returns int language sql as $$ select 3 $$;
create function public.full_name(p public.people) returns text language sql stable as $$ select p.first || ' ' || p.last $$;
create function public.people_items(p public.people) returns setof public.items language sql stable as $$ select * from public.items $$;
`;

/** Build a throwaway project and analyze it. files: { path: text | Buffer }, links: { path: target } */
export async function run(files, { sql = '', config, links, opts } = {}) {
  const dir = project({ 'supabase/migrations/20240101000000_init.sql': SQL + sql, ...files });
  for (const [p, t] of Object.entries(links || {})) { fs.mkdirSync(path.dirname(path.join(dir, p)), { recursive: true }); fs.symlinkSync(t, path.join(dir, p)); }
  if (config) fs.writeFileSync(path.join(dir, 'supareach.config.json'), JSON.stringify(config));
  try { return await analyze(dir, opts); } finally { rm(dir); }
}
const fp = (r) => new Set(r.findings.map((f) => f.fingerprint));
const uncalled = (r) => new Set(r.findings.filter((f) => f.rule === 'exposed-uncalled-function').map((f) => f.id.split('/')[0]));

// ---------------- scope ----------------

test('F1 Next.js app/, lib/, monorepo and RN-root code is scanned by default', async () => {
  for (const p of ['app/actions.ts', 'app/api/x/route.ts', 'lib/db.ts', 'apps/web/src/a.ts', 'App.tsx', 'components/Widget.tsx']) {
    const r = await run({ [p]: `declare const supabase: any; supabase.rpc('target_fn');` });
    assert.ok(!uncalled(r).has('target_fn'), `${p}: target_fn reported uncalled with ${r.stats.files_scanned} files scanned`);
  }
});

test('F1 zero code files, zero call sites and zero migrations are loud', async () => {
  const r = await run({});
  assert.equal(r.stats.files_scanned, 0);
  assert.ok(r.warnings.some((w) => /0 code files/.test(w)));
  const r2 = await run({ 'src/a.ts': 'export const x = 1;' });
  assert.ok(r2.warnings.some((w) => /0 Supabase call sites/.test(w)));
  const d = project({ 'src/a.ts': `declare const supabase: any; supabase.rpc('x');` });
  const r3 = await analyze(d);
  assert.ok(r3.scope_problems.some((w) => /0 migrations/.test(w)));
  // --check refuses an empty result instead of passing it
  fs.writeFileSync(path.join(d, 'supareach.baseline.json'), '{"findings":[]}');
  const c = spawnSync(process.execPath, [bin, d, '--no-output', '--check'], { encoding: 'utf8' });
  assert.equal(c.status, 2, c.stdout + c.stderr);
  assert.match(c.stderr, /empty, not clean/);
  rm(d);
});

test('F2 .vue / .svelte / .astro / .mts / .cts are scanned, with correct lines', async () => {
  const files = {
    'src/A.vue': `<template>\n  <p>Run \`npm i first</p>\n</template>\n<script setup lang="ts">\nimport { supabase } from './c';\nawait supabase.rpc('target_fn');\n</script>`,
    'src/routes/+page.svelte': `<script lang="ts">\nimport { supabase } from '$lib/c';\nsupabase.rpc('other_fn');\n</script>`,
    'src/pages/index.astro': `---\nconst { data } = await supabase.rpc('full_name');\n---\n<p>{data}</p>`,
    'src/x.mts': `declare const supabase: any; supabase.rpc('people_items');`,
    'src/y.cts': `declare const supabase: any; supabase.rpc('never_called');`,
  };
  const r = await run(files);
  const u = uncalled(r);
  for (const n of ['target_fn', 'other_fn', 'full_name', 'people_items', 'never_called']) assert.ok(!u.has(n), `${n} reported uncalled`);
  const at = r.links.find((l) => l.target === 'fn:target_fn/0').at[0];
  assert.equal(at, 'src/A.vue:6');
});

test('F2 edge-function helper in a .mts file is scanned', async () => {
  const r = await run({
    'supabase/functions/ef-one/index.ts': `import { go } from './handler.mts'; Deno.serve(go);`,
    'supabase/functions/ef-one/handler.mts': `declare const sb: any; export const go = async () => { await sb.rpc('target_fn'); return new Response('ok'); };`,
  }, { config: { entryPoints: [{ name: 'ef-one', reason: 'test' }] } });
  assert.ok(!uncalled(r).has('target_fn'));
});

test('F9 when dynamic rpc call sites exist, exposed-uncalled findings are downgraded with a caveat', async () => {
  const r = await run({ 'src/a.ts': `declare const supabase: any; declare const n: string; supabase.rpc(n);` });
  const f = r.findings.find((x) => x.fingerprint === 'exposed-uncalled-function:target_fn/0');
  assert.ok(f, 'fixture sanity');
  assert.equal(f.level, 'warning');
  assert.match(f.note, /unresolved .*src\/a.ts:1/);
});

test('F10 symlinked source directories inside the project are followed', { skip: process.platform === 'win32' }, async () => {
  const r = await run({ 'pkg/a.ts': `declare const supabase: any; supabase.rpc('target_fn');` }, { links: { 'src/linked': '../pkg' } });
  assert.ok(!uncalled(r).has('target_fn'));
});

test('F11 default excludes skip build output at package roots but not source folders named build/dist', async () => {
  const r = await run({
    'src/features/build/api.ts': `declare const supabase: any; supabase.rpc('target_fn');`,
    'src/dist/api.ts': `declare const supabase: any; supabase.rpc('other_fn');`,
    'dist/bundle.js': `supabase.rpc('never_called');`,
    'apps/web/package.json': '{}', 'apps/web/build/x.js': `supabase.rpc('never_called');`,
    '.next/server/x.js': `supabase.rpc('never_called');`,
    'src/latest.spec.config.ts': `declare const supabase: any; supabase.rpc('full_name');`,
    'src/a.test.ts': `declare const supabase: any; supabase.rpc('people_items');`,
  });
  const u = uncalled(r);
  assert.ok(!u.has('target_fn') && !u.has('other_fn') && !u.has('full_name'));
  assert.ok(u.has('never_called'), 'build output was scanned');
  assert.ok(u.has('people_items'), 'tests are not callers');
});

test('F12 parse errors, UTF-16 files and huge files are handled and reported', async () => {
  const r = await run({ 'src/a.ts': `declare const supabase: any;\nfunction broken( {\nsupabase.rpc('target_fn');\n` });
  assert.ok(r.info.parse_errors.length === 1 && r.warnings.some((w) => /could not be parsed completely/.test(w)));
  const buf = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`declare const supabase: any; supabase.rpc('target_fn');`, 'utf16le')]);
  assert.ok(!uncalled(await run({ 'src/a.ts': buf })).has('target_fn'));
  let s = 'declare const supabase: any;\n';
  for (let i = 0; i < 135000; i++) s += `supabase.from('items').select('*');\n`;
  s += `supabase.rpc('target_fn');\n`;
  const big = await run({ 'src/gen.ts': s });
  assert.equal(big.info.unreadable_files.length, 0, JSON.stringify(big.info.unreadable_files));
  assert.ok(!uncalled(big).has('target_fn'));
});

test('monorepo: the Supabase project is auto-detected and named; several need supabaseDir', async () => {
  const d = project({
    'apps/db/supabase/config.toml': 'project_id = "x"\n',
    'apps/db/supabase/migrations/001_init.sql': 'create function public.get_stats() returns int language sql as $$ select 1 $$;',
    'apps/web/src/a.ts': `export const x = (s: any) => s.rpc('get_stats');`,
  });
  const r = await analyze(d);
  assert.equal(r.project.supabaseDir, 'apps/db/supabase');
  assert.equal(r.project.how, 'auto-detected');
  assert.deepEqual(r.findings.filter((f) => f.rule === 'exposed-uncalled-function'), []);
  fs.mkdirSync(path.join(d, 'other/supabase'), { recursive: true });
  fs.writeFileSync(path.join(d, 'other/supabase/config.toml'), '');
  await assert.rejects(analyze(d), /found 2 Supabase projects .*supabaseDir/);
  fs.writeFileSync(path.join(d, 'supareach.config.json'), '{ "supabaseDir": "apps/db/supabase" }');
  assert.equal((await analyze(d)).project.how, 'config');
  rm(d);
});

test('control: a plain call is seen', async () => {
  assert.deepEqual(scanSource(`supabase.rpc('target_fn')`, 'a.ts').calls.map((c) => c.name), ['target_fn']);
  const r = await run({ 'src/a.ts': `declare const supabase: any; supabase.rpc('target_fn');` });
  assert.ok(!uncalled(r).has('target_fn') && uncalled(r).has('never_called'));
});
