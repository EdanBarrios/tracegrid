// Postgres / Supabase privilege and replay semantics. Each expectation was checked against
// PostgreSQL 17 (Supabase local image) inside rolled-back transactions; doc references inline.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { analyze } from '../src/analyze.js';
import { createState, applyStatement, splitStatements, fnSummary, scanMigrations, sqlRefs } from '../src/scan-sql.js';
import { CATALOG_SQL } from '../src/db.js';
import { project, rm } from './helpers.js';

function replay(text, opts) {
  const st = createState(opts);
  for (const s of splitStatements(text)) applyStatement(st, s, 'm.sql');
  return st;
}
const summary = (st, name) => {
  const f = st.functions.get(name);
  if (!f) throw new Error(`function ${name} not in state (${[...st.functions.keys()].join(', ')})`);
  return fnSummary(f);
};
const CLIENT = `export const supabase = { from: (t: string) => ({ select: (_: string) => null }), rpc: (f: string) => null } as any;\n`;
/** A project with one migration (or several), optional code and config; analyzed and removed. */
async function run(migrations, { code = {}, config, opts } = {}) {
  const files = {};
  const migs = typeof migrations === 'string' ? { '20240101000000_init.sql': migrations } : migrations;
  for (const [f, sql] of Object.entries(migs)) files[`supabase/migrations/${f}`] = sql;
  for (const [f, src] of Object.entries(code)) files[f] = src;
  if (Object.keys(code).some((k) => k.startsWith('src/'))) files['src/c.ts'] = CLIENT;
  if (config) files['tracegrid.config.json'] = JSON.stringify(config);
  const d = project(files);
  try { return await analyze(d, opts); } finally { rm(d); }
}
const ids = (r, rule) => r.findings.filter((f) => f.rule === rule).map((f) => f.id).sort();
const from = (...tables) => ({ 'src/a.ts': `import { supabase } from './c';\n` + tables.map((t, i) => `export const f${i} = () => supabase.from('${t}').select('*');\n`).join('') });
const catalogLines = ({ functions = [], relations = [], policies = [], triggers = [] } = {}) => [
  ['meta', { server_version_num: '170006', transaction_read_only: 'on', current_user: 'ro', roles: ['anon', 'authenticated'] }],
  ['functions', functions], ['relations', relations], ['policies', policies], ['triggers', triggers], ['event_triggers', []],
].map(([section, data]) => JSON.stringify({ section, data })).join('\n') + '\n';
const DB_URL = 'postgresql://ro:x@db.example.com:5432/postgres';

// ---- default privileges: two layers (sql-alterdefaultprivileges.html) ----

test('S0-1 per-schema REVOKE ... FROM PUBLIC is a no-op; the function stays callable by everyone', async () => {
  const st = replay(`
    alter default privileges in schema public revoke execute on functions from public, anon, authenticated;
    create function public.internal_fn() returns void language sql security definer as $$ select 1 $$;`);
  assert.equal(summary(st, 'internal_fn').anon, true, 'anon still has EXECUTE through PUBLIC');
  for (const sql of [
    'alter default privileges in schema public revoke execute on functions from public, anon, authenticated;',
    'alter default privileges for role postgres in schema public revoke execute on functions from public, anon, authenticated;',
  ]) {
    const r = await run(sql + '\ncreate function public.internal_fn() returns void language sql security definer as $$ select 1 $$;');
    assert.deepEqual(ids(r, 'exposed-uncalled-function'), ['internal_fn/0']);
  }
  const ok = await run(`
    alter default privileges for role postgres revoke execute on functions from public;
    alter default privileges for role postgres in schema public revoke execute on functions from anon, authenticated;
    create function public.internal_fn() returns void language sql security definer as $$ select 1 $$;`);
  assert.deepEqual(ids(ok, 'exposed-uncalled-function'), [], 'both layers revoked: locked');
});

test('S0-2 a GLOBAL revoke from anon/authenticated does not cancel the per-schema Supabase grant', async () => {
  const sql = `
    alter default privileges for role postgres revoke execute on functions from public, anon, authenticated;
    create function public.still_open() returns void language sql security definer as $$ select 1 $$;`;
  const f = summary(replay(sql), 'still_open');
  assert.equal(f.anon, true);
  assert.equal(f.authenticated, true);
  assert.deepEqual(ids(await run(sql), 'exposed-uncalled-function'), ['still_open/0']);
});

test('S0-3 IN SCHEMA "public" (quoted, as pg_dump writes it) is applied, never ignored', () => {
  const st = replay(`
    alter default privileges for role postgres revoke execute on functions from public;
    alter default privileges for role postgres in schema public revoke execute on functions from anon, authenticated;
    alter default privileges for role "postgres" in schema "public" grant execute on functions to "authenticated";
    create function public.regranted_fn() returns void language sql security definer as $$ select 1 $$;`);
  const f = summary(st, 'regranted_fn');
  assert.equal(f.authenticated, true);
  assert.equal(f.anon, false);
  assert.equal(st.stats.ignored, 0);
});

// ---- grants ----

test('S0-4 EXECUTE granted to a role that authenticated is a member of is inherited', async () => {
  const sql = `
    create role app_reader nologin;
    create function public.reader_fn() returns void language sql security definer as $$ select 1 $$;
    revoke execute on function public.reader_fn() from public, anon, authenticated;
    grant execute on function public.reader_fn() to app_reader;
    grant app_reader to authenticated;`;
  assert.equal(summary(replay(sql), 'reader_fn').authenticated, true);
  assert.equal(summary(replay(sql), 'reader_fn').anon, false);
  assert.deepEqual(ids(await run(sql), 'exposed-uncalled-function'), ['reader_fn/0']);
  // membership granted before the function grant works too; revoking membership removes it
  const st = replay(`create function f() returns void language sql as $$ $$; revoke execute on function f() from public, anon, authenticated;
    grant g to authenticated; grant execute on function f() to g; revoke g from authenticated;`);
  assert.equal(summary(st, 'f').authenticated, false);
});

test('S0-5 / S0-6 ALL PROCEDURES and ALL FUNCTIONS touch only their kind; ALL ROUTINES both', () => {
  const base = `create function public.f() returns void language sql as $$ select 1 $$;
    create procedure public.p() language sql as $$ select 1 $$;`;
  let st = replay(base + 'revoke execute on all procedures in schema public from public, anon, authenticated;');
  assert.equal(summary(st, 'f').anon, true);
  assert.equal(summary(st, 'p').anon, false);
  st = replay(base + 'revoke execute on all functions in schema public from public, anon, authenticated;');
  assert.equal(summary(st, 'f').anon, false);
  assert.equal(summary(st, 'p').anon, true);
  st = replay(base + 'revoke execute on all routines in schema "public" from public, anon, authenticated;');
  assert.equal(summary(st, 'f').anon, false);
  assert.equal(summary(st, 'p').anon, false);
});

test('S1-7 only files the Supabase CLI applies (<version>_name.sql) are replayed, in version order', async () => {
  const d = project({
    'supabase/migrations/20240101000000_init.sql': 'create function public.f() returns void language sql as $$ select 1 $$;\n',
    'supabase/migrations/notes.sql': 'revoke execute on function public.f() from public, anon, authenticated;\n',
    'supabase/migrations/9_later.sql': 'create table b (id int);\n',
    'supabase/migrations/10_last.sql': 'alter table b rename to c;\n',
  });
  const st = scanMigrations(path.join(d, 'supabase', 'migrations'));
  assert.equal(st.stats.files, 3);
  assert.equal(summary(st, 'f').anon, true, 'the revoke in notes.sql never ran');
  assert.deepEqual(st.skipped.map((x) => x.file), ['migrations/notes.sql']);
  assert.ok(st.tables.has('c') && !st.tables.has('b'), 'versions sort numerically: 9_ before 10_');
  const r = await analyze(d);
  assert.ok(r.warnings.some((w) => /notes\.sql/.test(w)));
  rm(d);
});

// ---- dynamic SQL ----

test('S0-8 RLS toggled through EXECUTE format() with literal arguments is applied', async () => {
  const sql = `
    create table public.secrets (id int);
    alter table public.secrets enable row level security;
    create table public.notes (id int);
    do $$ begin
      execute format('alter table public.%I disable row level security', 'secrets');
      execute format('alter table public.%I enable row level security', 'notes');
    end $$;`;
  const st = replay(sql);
  assert.equal(st.tables.get('secrets').rls, false);
  assert.equal(st.tables.get('notes').rls, true);
  const r = await run(sql, { code: from('secrets', 'notes') });
  assert.deepEqual(ids(r, 'client-table-without-rls'), ['secrets']);
});

test('S0-8b RLS enabled in a FOREACH loop over an array literal is applied', async () => {
  const r = await run(`create table public.notes (id int primary key, owner uuid);
    do $$ declare t text; begin
      foreach t in array array['notes'] loop
        execute format('alter table public.%I enable row level security', t);
      end loop;
    end $$;
    create policy notes_own on public.notes for select to authenticated using (owner = auth.uid());`, { code: from('notes') });
  assert.deepEqual(ids(r, 'client-table-without-rls'), []);
});

test('S0-8c RLS changed by non-literal dynamic SQL is a risky warning and a low-confidence finding', async () => {
  const r = await run(`create table public.secrets (id int);
    do $$ declare r record; begin
      for r in select tablename from pg_tables where schemaname = 'public' loop
        execute format('alter table public.%I enable row level security', r.tablename);
      end loop;
    end $$;`, { code: from('secrets') });
  const f = r.findings.find((x) => x.fingerprint === 'client-table-without-rls:secrets');
  assert.equal(f.confidence, 'low');
  assert.ok(r.warnings.some((w) => /did not apply/.test(w)));
});

test('S1-9 a revoke loop over pg_proc applies to nobody (and warns), never to the names it excludes', () => {
  const st = replay(`
    create function public.a() returns void language sql as $$ select 1 $$;
    create function public.keep_me() returns void language sql as $$ select 1 $$;
    do $$ declare r record; begin
      for r in select proname from pg_proc where pronamespace = 'public'::regnamespace and proname not in ('keep_me') loop
        execute format('revoke execute on function %I from public, anon, authenticated', r.proname);
      end loop;
    end $$;`);
  assert.equal(summary(st, 'keep_me').anon, true);
  assert.ok(st.unparsed.some((u) => u.risky));
});

// ---- references ----

test('S2-10 a quoted mixed-case function referenced from a policy counts as used', async () => {
  const r = await run(`
    create function public."MyFn"(p int) returns boolean language sql as $$ select p > 0 $$;
    create table public.t (id int);
    alter table public.t enable row level security;
    create policy p on public.t for select to authenticated using (public."MyFn"(id));`);
  assert.deepEqual(ids(r, 'exposed-uncalled-function'), []);
  assert.deepEqual(ids(r, 'granted-helper-function'), ['MyFn/1']);
});

test('S1-11 the schema qualifier of a reference is respected', async () => {
  const r = await run(`
    create schema private;
    create function private.is_admin() returns boolean language sql as $$ select false $$;
    create function public.is_admin() returns boolean language sql security definer as $$ select true $$;
    create table public.t (id int);
    alter table public.t enable row level security;
    create policy p on public.t for select to authenticated using (private.is_admin());`);
  assert.deepEqual(ids(r, 'exposed-uncalled-function'), ['is_admin/0']);
  const names = new Set(['is_admin', 'uid']);
  assert.deepEqual([...sqlRefs('select private.is_admin()', names).fns], []);
  assert.deepEqual([...sqlRefs('select auth.uid()', names).fns], []);
  assert.deepEqual([...sqlRefs('select public.is_admin()', names).fns], ['is_admin']);
  assert.deepEqual([...sqlRefs('select is_admin()', names).fns], ['is_admin']);
});

test('S2-12 BEGIN ATOMIC bodies are one statement', async () => {
  const s = splitStatements(`create function public.caller() returns int language sql
    begin atomic
      insert into public.log values (1);
      select case when true then public.helper() end;
    end;
    revoke execute on function public.caller() from public, anon, authenticated;`);
  assert.equal(s.length, 2);
  const r = await run(`
    create function public.helper() returns int language sql as $$ select 42 $$;
    create table public.log (x int);
    create function public.caller() returns int language sql
    begin atomic
      insert into public.log values (1);
      select public.helper();
    end;
    revoke execute on function public.caller() from public, anon, authenticated;`);
  assert.deepEqual(ids(r, 'exposed-uncalled-function'), []);
  assert.deepEqual(ids(r, 'granted-helper-function'), ['helper/0']);
});

test('S2-13 a database-webhook trigger URL counts as a caller of the edge function', async () => {
  const r = await run(`
    create table public.orders (id int);
    create trigger orders_webhook after insert on public.orders for each row
      execute function supabase_functions.http_request('https://ref.supabase.co/functions/v1/on-order', 'POST', '{"Content-Type":"application/json"}', '{}', '5000');`,
  { code: { 'supabase/functions/on-order/index.ts': `Deno.serve(() => new Response('ok'));\n` } });
  assert.deepEqual(ids(r, 'uncalled-edge-function'), []);
  assert.ok(r.links.some((l) => l.target === 'edge:on-order' && l.relation === 'webhook'));
});

test('S2-14 a function used only in an index expression is used', async () => {
  const r = await run(`
    create function public.norm(t text) returns text language sql immutable as $$ select lower(t) $$;
    create table public.t (name text);
    create index t_norm_idx on public.t (public.norm(name));`);
  assert.deepEqual(ids(r, 'exposed-uncalled-function'), []);
});

test('bug 6: DDL mentions of a function in DO blocks and string literals are not calls', async () => {
  for (const sql of [
    `create function public.wipe_everything() returns void language sql security definer as $$ select 1 $$;
     do $$ begin
       if to_regprocedure('public.wipe_everything()') is not null then
         execute 'alter function public.wipe_everything() set search_path = public';
       end if;
     end $$;`,
    `create function public.wipe_everything() returns void language sql security definer as $$ select 1 $$;
     comment on function public.wipe_everything() is 'calls nothing';
     create function public.audit() returns text language sql as $$ select 'wipe_everything() is dangerous' $$;`,
  ]) {
    const r = await run(sql);
    assert.ok(ids(r, 'exposed-uncalled-function').includes('wipe_everything/0'), sql);
  }
});

// ---- tables, views, policies ----

test('S2-15 RLS off but no privileges for anon/authenticated is not client-reachable (migrations and catalog)', async () => {
  const sql = `create table public.internal_cfg (k text, v text);
    revoke all on table public.internal_cfg from anon, authenticated;`;
  const r = await run(sql, { code: from('internal_cfg') });
  assert.deepEqual(ids(r, 'client-table-without-rls'), []);
  assert.deepEqual(ids(r, 'client-table-not-granted'), ['internal_cfg']);
  const lines = catalogLines({ relations: [{ schema: 'public', name: 'internal_cfg', relkind: 'r', rls: false, security_invoker: 'false', definition: '', defaults: '', anon_privs: [], authenticated_privs: [] }] });
  const c = await run(sql, { code: from('internal_cfg'), opts: { dbUrl: DB_URL, dbExec: () => lines } });
  assert.equal(c.source, 'catalog');
  assert.deepEqual(ids(c, 'client-table-without-rls'), []);
});

test('opt-in grant model: new tables are not granted unless a migration grants them', async () => {
  const sql = `create table public.a (id int); create table public.b (id int);
    grant select on table public.b to authenticated;`;
  const r = await run(sql, { code: from('a', 'b'), config: { supabaseDefaultGrants: 'opt-in' } });
  assert.deepEqual(ids(r, 'client-table-not-granted'), ['a']);
  assert.deepEqual(ids(r, 'client-table-without-rls'), ['b']);
  assert.equal(r.project.grantModel.model, 'opt-in');
  const t = await run(sql, { code: { ...from('a', 'b'), 'supabase/config.toml': '[api]\nauto_expose_new_tables = false\n' } });
  assert.equal(t.project.grantModel.model, 'opt-in');
  assert.match(t.project.grantModel.source, /auto_expose_new_tables/);
});

test('S2-16 RLS on with only restrictive or other-role policies is like "no policies"', async () => {
  const r = await run(`
    create table public.r_only (id int);
    alter table public.r_only enable row level security;
    create policy lim on public.r_only as restrictive for select to authenticated using (id > 0);
    create table public.sr_only (id int);
    alter table public.sr_only enable row level security;
    create policy srv on public.sr_only for all to service_role using (true);
    create table public.ok (id int);
    alter table public.ok enable row level security;
    create policy p on public.ok for select to authenticated using (true);`, { code: from('r_only', 'sr_only', 'ok') });
  assert.deepEqual(ids(r, 'client-table-without-policies'), ['r_only', 'sr_only']);
});

test('S2-17 ALTER FUNCTION/TABLE ... SET SCHEMA moves the object out of the exposed schema', async () => {
  const r = await run(`
    create schema private;
    create function public.moved_fn() returns void language sql security definer as $$ select 1 $$;
    alter function public.moved_fn() set schema private;
    create table public.moved_tbl (id int);
    alter table public.moved_tbl set schema private;`, { code: from('moved_tbl') });
  assert.deepEqual(ids(r, 'exposed-uncalled-function'), []);
  assert.deepEqual(ids(r, 'client-table-without-rls'), []);
  assert.deepEqual(ids(r, 'unknown-table'), ['moved_tbl']);
});

test('S2-18 Supabase default grants apply IN SCHEMA public only', async () => {
  const r = await run(`
    create schema api;
    grant usage on schema api to anon, authenticated;
    create function api.locked() returns void language sql as $$ select 1 $$;
    revoke execute on function api.locked() from public;
    create function api.open() returns void language sql as $$ select 1 $$;`, { config: { exposedSchemas: ['public', 'api'] } });
  assert.deepEqual(ids(r, 'exposed-uncalled-function'), ['api.open/0']);
});

test('S1-19 a client-read view without security_invoker over an RLS table is reported', async () => {
  const r = await run(`
    create table public.secret (id int, owner uuid);
    alter table public.secret enable row level security;
    create policy own on public.secret for select to authenticated using (owner = auth.uid());
    create view public.secret_v as select * from public.secret;
    create view public.secret_safe with (security_invoker = true) as select * from public.secret;`, { code: from('secret_v', 'secret_safe') });
  assert.deepEqual(ids(r, 'client-view-without-security-invoker'), ['secret_v']);
});

test('S3-20 a policy whose USING contains "to" inside a literal applies to PUBLIC', () => {
  const st = replay(`create table pt (status text); create policy p1 on pt for select using (status = 'sent to x');`);
  assert.deepEqual([...st.tables.get('pt').policies.values()][0].roles, ['public']);
});

// ---- severity ----

test('S3-23 invoker + authenticated-only is a warning; definer or anon-callable stays an error', async () => {
  const r = await run(`
    create function public.pub_only() returns void language sql as $$ select 1 $$;
    revoke execute on function public.pub_only() from public;
    create function public.inv_auth() returns int language sql security invoker as $$ select 1 $$;
    revoke execute on function public.inv_auth() from public, anon;
    create function public.def_auth() returns int language sql security definer as $$ select 1 $$;
    revoke execute on function public.def_auth() from public, anon;`);
  const by = Object.fromEntries(r.findings.filter((f) => f.rule === 'exposed-uncalled-function').map((f) => [f.id, f]));
  assert.equal(by['inv_auth/0'].level, 'warning');
  assert.equal(by['def_auth/0'].level, 'error');
  assert.equal(by['pub_only/0'].level, 'error');
});

test('bug 5: a SECURITY DEFINER helper callable by anon and reached only from SQL is a warning, not a note', async () => {
  const r = await run(`
    create table public.files (id int primary key, path text);
    alter table public.files enable row level security;
    create function public.delete_object(p text) returns void language plpgsql security definer as $$ begin delete from storage.objects where name = p; end $$;
    create function public.on_file_delete() returns trigger language plpgsql as $$ begin perform public.delete_object(old.path); return old; end $$;
    create trigger t after delete on public.files for each row execute function public.on_file_delete();
    create function public.helper_inv() returns boolean language sql as $$ select true $$;
    create policy p on public.files for select to authenticated using (public.helper_inv());`);
  const by = Object.fromEntries(r.findings.filter((f) => f.rule === 'granted-helper-function').map((f) => [f.id, f]));
  assert.equal(by['delete_object/1'].level, 'warning');
  assert.match(by['delete_object/1'].note, /SECURITY DEFINER/);
  assert.equal(by['helper_inv/0'].level, 'note');
});

// ---- catalog mode ----

test('S2-21 / S2-22 catalog mode checks schema USAGE and reads SQL-standard bodies', () => {
  assert.match(CATALOG_SQL, /has_schema_privilege/);
  assert.match(CATALOG_SQL, /pg_get_functiondef/);
  assert.match(CATALOG_SQL, /pg_default_acl/);
  assert.match(CATALOG_SQL, /pg_get_triggerdef/);
});

test('auto grant model: legacy replay plus a notice when config.toml is silent; explicit settings win', async () => {
  const sql = `create table public.a (id int); alter table public.a enable row level security; create policy p on public.a for select to authenticated using (true);`;
  const r = await run(sql, { code: from('a') });
  assert.equal(r.project.grantModel.model, 'legacy');
  assert.match(r.project.grantModel.source, /^auto/);
  assert.equal(r.notices.length, 1);
  assert.match(r.notices[0], /2026-10-30/);
  assert.ok(!r.findings.some((f) => f.rule === 'client-table-not-granted'));
  const t = await run(sql, { code: { ...from('a'), 'supabase/config.toml': '[api]\nauto_expose_new_tables = true\n' } });
  assert.equal(t.notices.length, 0);
  const o = await run(sql, { code: from('a'), config: { supabaseDefaultGrants: 'opt-in' } });
  assert.equal(o.notices.length, 0);
  const f = o.findings.find((x) => x.rule === 'client-table-not-granted');
  assert.ok(f && /opt-in/.test(f.note));
});

test('R1 a helper named in a DO block that alters policies via EXECUTE format() is policy-used, never a revoke candidate', async () => {
  const sql = `
    create table public.rooms (id int, org int); alter table public.rooms enable row level security;
    create table public.doors (id int, org int); alter table public.doors enable row level security;
    create function public.may_enter(o int) returns boolean language sql stable security definer as $$ select o > 0 $$;
    create policy p on public.rooms for select to authenticated using (true);
    create policy p on public.doors for select to authenticated using (true);
    do $$ declare t text; begin
      for t in select tablename from pg_tables where schemaname = 'public' loop
        execute format('alter policy p on public.%I using (%s)', t, 'public.may_enter(org)');
      end loop;
    end $$;`;
  const r = await run(sql);
  assert.ok(!ids(r, 'exposed-uncalled-function').includes('may_enter/1'));
  const f = r.findings.find((x) => x.fingerprint === 'granted-helper-function:may_enter/1');
  assert.ok(f, 'reported as a helper');
  assert.ok(f.usedBy.includes('dynamic-policy-uses'));
  assert.notEqual(f.tier, 'fix');
});

test('R2 a revoke loop over pg_proc with a literal name list is applied; a LIKE list makes exposure uncertain', async () => {
  const r = await run(`
    create function public.a() returns void language sql as $$ select 1 $$;
    create function public.a(x int) returns void language sql as $$ select 1 $$;
    create function public.b() returns void language sql as $$ select 1 $$;
    create function public.adm_x() returns void language sql as $$ select 1 $$;
    create function public.keep() returns void language sql as $$ select 1 $$;
    do $$ declare r record; begin
      for r in select p.oid from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.proname in ('a', 'b') loop
        execute format('revoke execute on function %s from public, anon, authenticated', r.oid::regprocedure);
      end loop;
      for r in select oid from pg_proc where proname like 'adm\\_%' loop
        execute format('revoke execute on function %s from anon', r.oid::regprocedure);
      end loop;
    end $$;`);
  const uncalled = ids(r, 'exposed-uncalled-function');
  for (const n of ['a/0', 'a/1', 'b/0']) assert.ok(!uncalled.includes(n), n);
  assert.ok(uncalled.includes('keep/0'));
  const adm = r.findings.find((x) => x.fingerprint === 'exposed-uncalled-function:adm_x/0');
  assert.ok(adm && adm.confidence === 'low' && adm.tier === 'review', JSON.stringify(adm));
  assert.equal(r.findings.find((x) => x.fingerprint === 'exposed-uncalled-function:keep/0').tier, 'fix');
});

test('R3 column-level grants count as table privileges; a column list built in a DO block is uncertain', async () => {
  const base = `create table public.t (id int, name text, secret text); alter table public.t enable row level security;
    create policy p on public.t for select to authenticated using (true);`;
  const a = await run(base + `grant select (id, name) on public.t to authenticated; revoke select (secret) on public.t from authenticated;`, { code: from('t'), config: { supabaseDefaultGrants: 'opt-in' } });
  assert.deepEqual(ids(a, 'client-table-not-granted'), []);
  const b = await run(base + `do $$ declare cols text; begin
      select string_agg(quote_ident(column_name), ', ') into cols from information_schema.columns where table_name = 't' and column_name <> 'secret';
      execute format('grant select (%s) on public.t to authenticated', cols);
    end $$;`, { code: from('t'), config: { supabaseDefaultGrants: 'opt-in' } });
  const f = b.findings.find((x) => x.rule === 'client-table-not-granted');
  assert.ok(f && f.confidence === 'low' && f.tier === 'review', JSON.stringify(f));
});

test('R2b nested loops: FOREACH over a declared array, then pg_proc rows by that name (definer overloads only)', async () => {
  const r = await run(`
    create function public.alpha() returns void language sql security definer as $$ select 1 $$;
    create function public.alpha(x int) returns void language sql as $$ select 1 $$;
    create function public.beta(t text) returns void language sql security definer as $$ select 1 $$;
    create function public.gamma() returns void language sql security definer as $$ select 1 $$;
    do $$
    declare
      revoked text[] := array[
        -- a comment inside the list
        'alpha',
        'beta'
      ];
      name text;
      fn regprocedure;
    begin
      foreach name in array revoked loop
        for fn in select p.oid::regprocedure from pg_proc p join pg_namespace ns on ns.oid = p.pronamespace
          where ns.nspname = 'public' and p.proname = name and p.prosecdef
        loop
          execute format('revoke execute on function %s from public, anon, authenticated', fn);
        end loop;
      end loop;
    end $$;`);
  const uncalled = ids(r, 'exposed-uncalled-function');
  assert.ok(!uncalled.includes('alpha/0') && !uncalled.includes('beta/1'), uncalled.join(','));
  assert.ok(uncalled.includes('alpha/1'), 'the non-definer overload is not revoked');
  assert.ok(uncalled.includes('gamma/0'));
  assert.equal(r.findings.find((f) => f.id === 'gamma/0').tier, 'fix');
  assert.ok(!r.info.unparsed_sql.length, JSON.stringify(r.info.unparsed_sql));
});

test('R2c default privileges inside a DO block (with an exception handler) do not make existing functions uncertain', async () => {
  const r = await run(`
    create function public.f() returns void language sql as $$ select 1 $$;
    do $$ begin
      alter default privileges for role supabase_admin in schema public revoke execute on functions from public, anon, authenticated;
    exception when insufficient_privilege then raise notice 'not permitted';
    end $$;`);
  const f = r.findings.find((x) => x.id === 'f/0');
  assert.ok(f && f.tier === 'fix' && !f.confidence, JSON.stringify(f));
  assert.ok(!r.info.unparsed_sql.some((u) => u.risky), JSON.stringify(r.info.unparsed_sql));
});

// ---- tables created outside the replayed migrations ----

test('S-ext-1 a table the migrations only grant or give policies to has unknown RLS: Review, with a notice naming the dump', async () => {
  const r = await run(`grant select on public.contacts to anon;
create policy "own" on public.contacts for select to authenticated using (true);`, {
    code: { ...from('contacts'), 'supabase/baseline.sql': 'create function public.f() returns int language sql as $$ select 1 $$;\ncreate table public.contacts (id int);\nalter table public.contacts enable row level security;\n' },
  });
  const f = r.findings.filter((x) => x.rule === 'client-table-without-rls');
  assert.deepEqual(f.map((x) => [x.id, x.tier, x.confidence]), [['contacts', 'review', 'low']]);
  assert.ok(r.notices.some((n) => /1 table\(s\) are altered.*\(contacts\).*supabase\/baseline\.sql/.test(n)), r.notices.join('\n'));
});

test('S-ext-2 an explicit DISABLE on a table created elsewhere is known: still Fix', async () => {
  const r = await run(`alter table public.contacts disable row level security;`, { code: from('contacts') });
  assert.deepEqual(r.findings.filter((x) => x.rule === 'client-table-without-rls').map((x) => [x.id, x.tier]), [['contacts', 'fix']]);
  assert.ok(!r.notices.some((n) => /never created there/.test(n)));
});

test('S-ext-3 a table created in the migrations with RLS off stays Fix and gets no notice', async () => {
  const r = await run(`create table public.contacts (id int);`, { code: from('contacts') });
  assert.deepEqual(r.findings.filter((x) => x.rule === 'client-table-without-rls').map((x) => [x.id, x.tier]), [['contacts', 'fix']]);
  assert.ok(!r.notices.some((n) => /never created there/.test(n)));
});

test('S-schema-1 a name missing from public but defined in another exposed schema links there ambiguously, not missing', async () => {
  const r = await run(`create schema shop;
create table shop.store (id int);
alter table shop.store enable row level security;
create function shop.restock(n int) returns void language sql as $$ select 1 $$;`, {
    code: { 'src/a.ts': `import { supabase } from './c';\nexport const a = () => supabase.from('store').select('*');\nexport const b = () => supabase.rpc('restock', { n: 1 });\n` },
    config: { exposedSchemas: ['public', 'shop'] },
  });
  assert.deepEqual(ids(r, 'unknown-table'), []);
  assert.deepEqual(ids(r, 'missing-rpc'), []);
  const e = r.links.filter((l) => l.source === 'file:src/a.ts').map((l) => [l.target, l.confidence]).sort();
  assert.deepEqual(e, [['fn:shop.restock/1', 'ambiguous'], ['table:shop.store', 'ambiguous']]);
});

test('S-schema-2 a name in neither public nor any other schema is still reported', async () => {
  const r = await run(`create schema shop;\ncreate table shop.store (id int);`, { code: from('stor') });
  assert.deepEqual(ids(r, 'unknown-table'), ['stor']);
});

test('S-schema-3 exposed schemas default to config.toml [api] schemas (multi-line array)', async () => {
  const r = await run(`create schema shop;\ncreate table shop.store (id int);`, {
    code: { ...from('store'), 'supabase/config.toml': '[api]\nschemas = [\n  "public", # default\n  "shop",\n]\n' },
  });
  assert.deepEqual(ids(r, 'unknown-table'), []);
});

test('S-schema-4 a table in a schema the Data API does not expose is still unknown to a public client', async () => {
  const r = await run(`create schema private;\ncreate table private.store (id int);`, { code: from('store') });
  assert.deepEqual(ids(r, 'unknown-table'), ['store']);
});

test('S-schema-5 a weak call (receiver not provably Supabase) still counts as a possible caller in another exposed schema', async () => {
  const sql = `create schema shop;\ngrant usage on schema shop to anon, authenticated;\ncreate function shop.restock(n int) returns void language sql security definer as $$ select 1 $$;`;
  const config = { exposedSchemas: ['public', 'shop'] };
  const called = await run(sql, { config, code: { 'src/a.ts': `declare const db: any;\nexport const a = () => db.rpc('restock', { n: 1 });\n` } });
  assert.deepEqual(ids(called, 'exposed-uncalled-function'), []);
  const uncalled = await run(sql, { config, code: { 'src/a.ts': `export const a = 1;\n` } });
  assert.deepEqual(ids(uncalled, 'exposed-uncalled-function'), ['shop.restock/1']);
});

test('S-schema-6 Supabase platform schemas (Queues, GraphQL) are not the app\'s uncalled functions', async () => {
  const r = await run(`create schema pgmq_public;\ngrant usage on schema pgmq_public to anon, authenticated;\ncreate function pgmq_public.pop(q text) returns void language sql as $$ select 1 $$;`,
    { config: { exposedSchemas: ['public', 'pgmq_public'] }, code: { 'src/a.ts': `export const a = 1;\n` } });
  assert.deepEqual(ids(r, 'exposed-uncalled-function'), []);
});
