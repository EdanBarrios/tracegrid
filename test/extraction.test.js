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
  assert.ok(r.info.unreadable_files.length === 1 && r.info.unreadable_files[0].partial && r.warnings.some((w) => /could not be parsed completely/.test(w)));
  assert.ok(!uncalled(r).has('target_fn'), 'the call swallowed by error recovery is recovered from the text');
  const buf = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`declare const supabase: any; supabase.rpc('target_fn');`, 'utf16le')]);
  assert.ok(!uncalled(await run({ 'src/a.ts': buf })).has('target_fn'));
  // >130k call sites in one file (under the 2 MB cap) used to overflow the stack in push(...spread)
  const s = 'declare const db: any;\n' + "db.from('t');\n".repeat(140000) + "db.rpc('target_fn');\n";
  assert.ok(s.length < 2 * 1024 * 1024);
  const big = await run({ 'src/gen.ts': s });
  assert.equal(big.info.unreadable_files.length, 0, JSON.stringify(big.info.unreadable_files));
  assert.ok(!uncalled(big).has('target_fn'));
  assert.ok(big.stats.call_sites > 140000);
  // over the cap: skipped and listed loudly, not parsed
  const huge = await run({ 'src/huge.ts': "supabase.rpc('target_fn');\n".repeat(90000) });
  assert.match(huge.info.unreadable_files[0].error, /too large/);
  assert.ok(huge.warnings.some((w) => /huge\.ts/.test(w)));
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

// ---------------- extraction ----------------

const EF = { 'supabase/functions/ef-one/index.ts': `Deno.serve(() => new Response('ok'));` };

test('F3 destructured / bound / call / apply / element-access rpc is recorded', () => {
  for (const src of [
    `const { rpc } = supabase; rpc('target_fn');`,
    `const call = supabase.rpc.bind(supabase); call('target_fn');`,
    `supabase.rpc.call(supabase, 'target_fn');`,
    `supabase.rpc.apply(supabase, ['target_fn']);`,
    `supabase['rpc']('target_fn');`,
  ]) assert.deepEqual(scanSource(src, 'a.ts').calls.filter((c) => c.kind === 'rpc').map((c) => c.name), ['target_fn'], src);
});

test('F3 functions.invoke through an alias or destructuring is recorded', async () => {
  for (const src of [`const { functions } = supabase; functions.invoke('ef-one');`, `const fns = supabase.functions; fns.invoke('ef-one');`]) {
    const r = await run({ ...EF, 'src/a.ts': `declare const supabase: any;\n${src}` });
    assert.ok(!fp(r).has('uncalled-edge-function:ef-one'), src);
  }
});

test('F4 PostgREST computed fields and computed relationships in select() count as calls', async () => {
  const r = await run({ 'src/a.ts': `declare const supabase: any;\nsupabase.from('people').select('id, full_name, people_items(*)');` });
  assert.ok(!uncalled(r).has('full_name') && !uncalled(r).has('people_items'));
  assert.ok(uncalled(r).has('never_called'));
});

test('F5 /functions/v1/ URLs built by concatenation, const template or relative URL', async () => {
  for (const s of [
    `declare const base: string; const name = 'ef-one'; fetch(base + '/functions/v1/' + name);`,
    'declare const base: string; const FN = "ef-one"; fetch(`${base}/functions/v1/${FN}`);',
    `declare const base: string; fetch(new URL('functions/v1/ef-one', base));`,
  ]) assert.ok(!fp(await run({ ...EF, 'src/a.ts': s })).has('uncalled-edge-function:ef-one'), s);
  assert.equal(scanSource(`fetch(base + '/functions/v1/' + name);`, 'a.ts').unresolved.length, 1);
});

test('F6 raw PostgREST fetches: /rest/v1/rpc/<fn> is a call, /rest/v1/<table> a table access', async () => {
  const r = await run({ 'src/a.ts': 'declare const U: string; fetch(`${U}/rest/v1/rpc/target_fn`, { method: "POST" });\nfetch(`${U}/rest/v1/secrets?select=*`);' });
  assert.ok(!uncalled(r).has('target_fn'));
  assert.ok(fp(r).has('client-table-without-rls:secrets'));
});

test('F7 a parameter that shadows a same-file const is not resolved to the const', async () => {
  const r = await run({ 'src/a.ts': `declare const supabase: any;\nconst name = 'other_fn';\nsupabase.rpc(name);\nexport function call(name: string) { return supabase.rpc(name); }\ncall('target_fn');\nfunction b(x: any) { const name = x.n; return supabase.rpc(name); }` });
  assert.ok(!uncalled(r).has('target_fn') && !uncalled(r).has('other_fn'));
  assert.ok(r.info.unresolved_dynamic_calls.some((u) => u.line === 6), 'b() is genuinely dynamic and listed');
});

test('F8 createClient({ db: { schema } }) and .schema(<dynamic>)', async () => {
  const r = await run({ 'src/a.ts': `import { createClient } from '@supabase/supabase-js';\nconst api = createClient('u', 'k', { db: { schema: 'api' } });\napi.rpc('api_fn');` }, {
    sql: `create schema api; create function api.api_fn() returns int language sql as $$ select 1 $$; grant execute on function api.api_fn() to authenticated;`,
    config: { exposedSchemas: ['public', 'api'] },
  });
  assert.ok(!fp(r).has('exposed-uncalled-function:api.api_fn/0'));
  assert.ok(!fp(r).has('missing-rpc:api_fn'));
  const d = await run({ 'src/a.ts': `declare const supabase: any; declare const env: any;\nsupabase.schema(env.S).rpc('api_fn');` }, {
    sql: `create schema api; create function api.api_fn() returns int language sql as $$ select 1 $$; grant execute on function api.api_fn() to authenticated;`,
    config: { exposedSchemas: ['public', 'api'] },
  });
  assert.ok(!fp(d).has('exposed-uncalled-function:api.api_fn/0'), 'dynamic schema: matches api_fn in any schema');
  assert.ok(!fp(d).has('missing-rpc:api_fn'));
});

test('F9 statically knowable names resolve: arrays, maps, enums, concat, let, imported consts', async () => {
  const cases = {
    loop: `declare const supabase: any; const FNS = ['target_fn'] as const; for (const f of FNS) supabase.rpc(f);`,
    map: `declare const supabase: any; ['target_fn'].map((f) => supabase.rpc(f));`,
    object: `declare const supabase: any; const RPC = { t: 'target_fn' } as const; supabase.rpc(RPC.t);`,
    enum: `declare const supabase: any; enum Fn { T = 'target_fn' } supabase.rpc(Fn.T);`,
    concat: `declare const supabase: any; const P = 'target'; supabase.rpc(P + '_fn');`,
    let: `declare const supabase: any; declare const c: boolean; let fn = 'other_fn'; if (c) fn = 'target_fn'; supabase.rpc(fn);`,
  };
  for (const [k, src] of Object.entries(cases)) assert.ok(!uncalled(await run({ 'src/a.ts': src })).has('target_fn'), k);
  const r = await run({ 'src/names.ts': `export const T = 'target_fn';`, 'src/index.ts': `export * from './names';`, 'src/a.ts': `import { T } from './index'; declare const supabase: any; supabase.rpc(T);` });
  assert.ok(!uncalled(r).has('target_fn'), 'imported const through a barrel');
  const a = await run({ 'src/lib/names.ts': `export const T = 'target_fn';`, 'src/a.ts': `import { T } from '@/lib/names'; declare const supabase: any; supabase.rpc(T);`, 'tsconfig.json': '{ "compilerOptions": { "paths": { "@/*": ["./src/*"] } } }' });
  assert.ok(!uncalled(a).has('target_fn'), 'path alias');
});

test('F9 a partially known name links ambiguously to the matching functions', async () => {
  const r = await run({ 'src/a.ts': `declare const supabase: any; declare const k: string; supabase.rpc('target_' + k);` });
  assert.ok(!uncalled(r).has('target_fn'));
  assert.ok(uncalled(r).has('other_fn'));
});

test('F9 cross-file wrappers, hooks and class/object-method wrappers resolve their call sites', async () => {
  const projects = {
    'exported arrow': { 'src/lib/rpc.ts': `declare const supabase: any; export const callRpc = (name: string) => supabase.rpc(name);`, 'src/a.ts': `import { callRpc } from './lib/rpc'; callRpc('target_fn');` },
    'generic hook': { 'src/hooks.ts': `declare const supabase: any; export function useRpc<T>(fn: string) { return supabase.rpc(fn) as T; }`, 'src/a.tsx': `import { useRpc } from './hooks'; export const C = () => { useRpc<number>('target_fn'); return null; };` },
    'class method': { 'src/a.ts': `export class Api { constructor(private c: any) {} call(name: string) { return this.c.rpc(name); } }\nnew Api(null).call('target_fn');` },
    'object method': { 'src/a.ts': `declare const supabase: any; export const api = { call(name: string) { return supabase.rpc(name); } };\napi.call('target_fn');` },
    'destructured param': { 'src/a.ts': `declare const supabase: any; const call = ({ fn }: { fn: string }) => supabase.rpc(fn);\ncall({ fn: 'target_fn' });` },
  };
  for (const [k, files] of Object.entries(projects)) assert.ok(!uncalled(await run(files)).has('target_fn'), k);
});

test('F9 config wrappers can name the argument index; without one, an object first argument is skipped', async () => {
  let r = await run({ 'src/a.ts': `import { callRpc } from './lib'; callRpc({ retries: 2 }, 'target_fn');` }, { config: { wrappers: { rpc: [{ name: 'callRpc', arg: 1 }] } } });
  assert.ok(!uncalled(r).has('target_fn'));
  r = await run({ 'src/a.ts': `import { callRpc } from './lib'; callRpc({ retries: 2 }, 'target_fn');` }, { config: { wrappers: { rpc: ['callRpc'] } } });
  assert.ok(!uncalled(r).has('target_fn'));
});

test('F13 embedded relations, realtime postgres_changes and raw REST are table access', async () => {
  for (const src of [
    `supabase.from('items').select('*, secrets(value)');`,
    `supabase.rpc('target_fn').select('*, secrets(value)');`,
    `supabase.channel('c').on('postgres_changes', { event: '*', schema: 'public', table: 'secrets' }, () => {}).subscribe();`,
  ]) assert.ok(fp(await run({ 'src/a.ts': `declare const supabase: any;\n${src}` })).has('client-table-without-rls:secrets'), src);
});

test('F14 .rpc / .from on non-Supabase receivers (ethers, knex, drizzle, rxjs) invent nothing', async () => {
  for (const src of [
    `import { JsonRpcProvider } from 'ethers'; const provider = new JsonRpcProvider(); provider.rpc('eth_blockNumber');`,
    `declare const knex: any; knex.from('secrets').where({ id: 1 });`,
    `import { db } from './db'; import { users } from './schema'; export const all = () => db.select().from(users);`,
    `import { from } from 'rxjs'; declare const obs: any; obs.from('secrets');`,
  ]) {
    const r = await run({ 'src/a.ts': src });
    assert.ok(!r.findings.some((f) => /missing-rpc|client-table|unknown-table/.test(f.rule)), src);
    assert.equal(r.info.unresolved_dynamic_calls.length, 0, src);
  }
});

test('F15 storage.from through an alias or destructuring is a bucket, not a table', async () => {
  for (const src of [`const storage = supabase.storage; storage.from('secrets').upload('a', b);`, `const { storage } = supabase; storage.from('avatars').upload('a', b);`, `const B = { A: 'avatars' } as const; supabase.storage.from(B.A).upload('a', b);`]) {
    const r = await run({ 'src/a.ts': `declare const supabase: any; declare const b: any;\n${src}` });
    assert.ok(!fp(r).has('client-table-without-rls:secrets') && !fp(r).has('unknown-table:avatars'), src);
    assert.equal(r.info.storage_buckets.length, 1, src);
  }
});

test('F16 an inferred wrapper does not capture an unrelated same-named local function', async () => {
  const r = await run({ 'src/a.ts': `declare const supabase: any;\nfunction run(n: string) { return supabase.rpc(n); }\nrun('target_fn');\nfunction other() { const run = (s: string) => s; return run('nope_fn'); }` });
  assert.ok(!fp(r).has('missing-rpc:nope_fn'));
  assert.ok(!uncalled(r).has('target_fn'));
});

test('F17 config.toml entrypoint and index.jsx edge functions are inventoried', async () => {
  const r = await run({
    'supabase/config.toml': `[functions.ef-one]\nverify_jwt = true\nentrypoint = "./functions/ef-one/main.ts"\n`,
    'supabase/functions/ef-one/main.ts': `Deno.serve(() => new Response('ok'));`,
    'supabase/functions/ef-two/index.jsx': `Deno.serve(() => new Response('ok'));`,
    'src/a.ts': `declare const supabase: any; supabase.functions.invoke('ef-one'); supabase.functions.invoke('ef-two');`,
  });
  assert.ok(!fp(r).has('missing-edge-function:ef-one') && !fp(r).has('missing-edge-function:ef-two'));
});

test('F18 stories, __mocks__, msw handlers, help text and if(false) are not callers', async () => {
  const r = await run({
    ...EF,
    'src/A.stories.tsx': `declare const supabase: any; supabase.rpc('target_fn');`,
    'src/__mocks__/client.ts': `declare const supabase: any; supabase.rpc('other_fn');`,
    'src/mocks/handlers.ts': `import { http } from 'msw'; export const h = [http.post('*/functions/v1/ef-one', () => null)];`,
    'src/help.ts': `export const help = 'POST https://x.supabase.co/functions/v1/ef-one to retry';`,
    'src/dead.ts': `declare const supabase: any;\nif (false) { supabase.rpc('full_name'); }`,
  });
  for (const n of ['target_fn', 'other_fn', 'full_name']) assert.ok(uncalled(r).has(n), n);
  assert.ok(fp(r).has('uncalled-edge-function:ef-one'));
});

test('F19 / b4 service_role clients: callers that neither clear grant findings nor trigger browser rules', async () => {
  const r = await run({
    'src/admin.server.ts': `import { createClient } from '@supabase/supabase-js';\nconst admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\nexport const get = () => admin.from('items').select();\nexport const run = () => admin.rpc('target_fn');`,
    'src/b.ts': `import { admin2 } from './c'; admin2.from('secrets').select();`,
    'src/c.ts': `import { createClient } from '@supabase/supabase-js'; export const admin2 = createClient('u', process.env.SECRET_KEY!);`,
  }, { sql: `create table public.customers (id uuid primary key); alter table public.customers enable row level security;` });
  const f = r.findings.find((x) => x.fingerprint === 'exposed-uncalled-function:target_fn/0');
  assert.ok(f, 'a service_role caller does not justify the anon/authenticated grant');
  assert.match(f.note, /service_role/);
  assert.ok(!fp(r).has('client-table-without-rls:secrets'), 'privileged client (imported) is not a browser client');
  assert.ok(r.links.some((l) => l.relation === 'rpc-service'));
});

test('auth hooks in config.toml are callers; a client-callable hook function is flagged', async () => {
  const r = await run({
    'supabase/config.toml': `[auth.hook.custom_access_token]\nenabled = true\nuri = "pg-functions://postgres/public/token_hook"\n\n[auth.hook.send_email]\nenabled = true\nuri = "http://host.docker.internal:54321/functions/v1/ef-one"\n`,
    ...EF,
  }, { sql: `create function public.token_hook(event jsonb) returns jsonb language plpgsql as $$ begin return event; end $$;` });
  assert.ok(!fp(r).has('exposed-uncalled-function:token_hook/1'));
  assert.ok(fp(r).has('auth-hook-function-exposed:token_hook/1'));
  assert.ok(!fp(r).has('uncalled-edge-function:ef-one'));
});

test('F20 hatches work with CR-only line endings', async () => {
  const r = await run({ 'src/a.ts': "declare const supabase: any;\r\r// supareach: ignore missing-rpc test reason\rsupabase.rpc('nope_fn');\r" });
  assert.ok(!fp(r).has('missing-rpc:nope_fn'));
});

test('S1 Nuxt serverSupabaseServiceRole and SERVICE_KEY / SUPABASE_SECRET env names are privileged clients', async () => {
  const r = await run({
    'server/api/a.ts': `export default defineEventHandler(async (event) => {\n  const client = await serverSupabaseServiceRole(event);\n  await client.from('secrets').select();\n  return client.rpc('target_fn');\n});`,
    'server/api/b.ts': `import { createClient } from '@supabase/supabase-js';\nconst sb = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_KEY!);\nexport const x = () => sb.rpc('other_fn');`,
    'server/api/c.ts': `import { createClient } from '@supabase/supabase-js';\nconst sb = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SECRET!);\nexport const y = () => sb.from('secrets').select();`,
    'pages/p.vue': `<script setup>\nconst client = serverSupabaseClient(event);\nclient.rpc('never_called');\n</script>`,
  });
  assert.ok(!fp(r).has('client-table-without-rls:secrets'), 'service-role reads do not make a table client-touched');
  for (const n of ['target_fn', 'other_fn']) assert.ok(fp(r).has(`exposed-uncalled-function:${n}/0`), `${n}: privileged caller does not justify the grant`);
  assert.ok(r.links.filter((l) => l.relation === 'rpc-service').length >= 2);
  assert.ok(!fp(r).has('exposed-uncalled-function:never_called/0'), 'serverSupabaseClient is a user-scoped client');
});

test('S2 path aliases from the nearest tsconfig (with extends) and workspace package names', async () => {
  const r = await run({
    'apps/web/tsconfig.json': '{ "extends": "./tsconfig.base.json" }',
    'apps/web/tsconfig.base.json': '{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["./app/*"], "#names": ["./app/names.ts"] } } }',
    'apps/web/app/lib/names.ts': `export const T = 'target_fn';`,
    'apps/web/app/names.ts': `export const O = 'other_fn';`,
    'apps/web/app/page.ts': `import { T } from '@/lib/names'; import { O } from '#names'; declare const supabase: any; supabase.rpc(T); supabase.rpc(O);`,
    'packages/db/package.json': '{ "name": "@acme/db", "main": "./src/index.ts" }',
    'packages/db/src/index.ts': `export const N = 'never_called';`,
    'packages/db/src/more.ts': `export const F = 'full_name';`,
    'apps/admin/x.ts': `import { N } from '@acme/db'; import { F } from '@acme/db/more'; declare const supabase: any; supabase.rpc(N); supabase.rpc(F);`,
    'tsconfig.json': '{ "compilerOptions": { "paths": { "@/*": ["./src/*"] } } }',
  });
  for (const n of ['target_fn', 'other_fn', 'never_called']) assert.ok(!uncalled(r).has(n), n);
  assert.ok(!r.info.unresolved_dynamic_calls.length, JSON.stringify(r.info.unresolved_dynamic_calls));
});

test('R5 edge hints: service_role used before any auth check, and fetch of a request-body URL', async () => {
  const r = await run({
    'supabase/functions/ef-admin/index.ts': `import { createClient } from 'npm:@supabase/supabase-js';\nconst admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);\nDeno.serve(async (req) => {\n  const { data } = await admin.from('items').select();\n  const { data: u } = await admin.auth.getUser(req.headers.get('Authorization')!);\n  return new Response(JSON.stringify(data));\n});`,
    'supabase/functions/ef-safe/index.ts': `import { createClient } from 'npm:@supabase/supabase-js';\nconst admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);\nDeno.serve(async (req) => {\n  const { data: { user } } = await admin.auth.getUser(req.headers.get('Authorization')!.slice(7));\n  if (!user) return new Response('no', { status: 401 });\n  return new Response(JSON.stringify(await admin.from('items').select()));\n});`,
    'supabase/functions/ef-proxy/index.ts': `Deno.serve(async (req) => {\n  const { url, method } = await req.json();\n  const res = await fetch(url, { method });\n  return new Response(await res.text());\n});`,
    'supabase/functions/ef-fixed/index.ts': `Deno.serve(async (req) => {\n  const body = await req.json();\n  return fetch('https://api.example.com/v1/' + encodeURIComponent(body.id));\n});`,
    'supabase/functions/ef-proxy2/index.ts': `Deno.serve(async (req) => {\n  const body = await req.json();\n  return fetch(new URL(body.target));\n});`,
  });
  const f = fp(r);
  assert.ok(f.has('edge-service-role-before-auth:ef-admin'));
  assert.ok(!f.has('edge-service-role-before-auth:ef-safe'));
  assert.ok(f.has('edge-request-controlled-fetch:ef-proxy'));
  assert.ok(f.has('edge-request-controlled-fetch:ef-proxy2'));
  assert.ok(!f.has('edge-request-controlled-fetch:ef-fixed'));
  assert.ok(r.findings.filter((x) => x.rule.startsWith('edge-')).every((x) => x.tier === 'review'));
});
