import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createState, applyStatement, splitStatements, sigOf, fnSummary, sqlRefs } from '../src/scan-sql.js';

function run(sql, opts) {
  const st = createState(opts);
  for (const s of splitStatements(sql)) applyStatement(st, s, 'm.sql');
  return st;
}
const fn = (st, n) => fnSummary(st.functions.get(n));

test('splitter keeps dollar bodies and strips comments', () => {
  const s = splitStatements(`-- c; x\ncreate function f() returns int as $body$ select 1; $body$ language sql; /* ; */ select 'a;b';`);
  assert.equal(s.length, 2);
  assert.match(s[0].text, /select 1;/);
  assert.equal(s[1].line, 2);
});

test('tables, renames, drops and RLS', () => {
  const st = run(`
    create table public.a (id int); create table if not exists "B" (id int);
    alter table a enable row level security;
    alter table public.a rename to c;
    drop table if exists "B" cascade;`);
  assert.deepEqual([...st.tables.keys()], ['c']);
  assert.equal(st.tables.get('c').rls, true);
});

test('policies: command, roles, drop', () => {
  const st = run(`
    create table t (id int);
    create policy "read" on public.t for select to authenticated using (true);
    create policy w on t as restrictive for insert with check (false);
    drop policy if exists "read" on t;`);
  const p = [...st.tables.get('t').policies.values()];
  assert.equal(p.length, 1);
  assert.deepEqual([p[0].name, p[0].command, p[0].roles], ['w', 'insert', ['public']]);
});

test('Supabase default grants: revoking PUBLIC alone leaves anon/authenticated', () => {
  const st = run(`
    create function a() returns void language sql as $$ select $$;
    revoke execute on function a() from public;
    create function b() returns void language sql as $$ select $$;
    revoke all on function public.b() from public, anon, authenticated;
    grant execute on function b to authenticated;`);
  assert.equal(fn(st, 'a').anon, true);
  assert.equal(fn(st, 'b').anon, false);
  assert.equal(fn(st, 'b').authenticated, true);
});

test('vanilla Postgres model: PUBLIC only', () => {
  const st = run(`create function a() returns void language sql as $$ $$; revoke execute on function a() from public;`, { supabaseDefaultGrants: false });
  assert.equal(fn(st, 'a').authenticated, false);
});

test('create or replace keeps grants; drop and recreate resets them', () => {
  const st = run(`
    create function f(x int) returns int language sql as $$ select x $$;
    revoke execute on function f(integer) from public, anon, authenticated;
    create or replace function f(p int) returns int language sql security definer as $$ select p $$;`);
  assert.equal(fn(st, 'f').authenticated, false);
  assert.equal(fn(st, 'f').securityDefiner, true);
  const st2 = run(`
    create function f() returns int language sql as $$ select 1 $$;
    revoke execute on function f() from public, anon, authenticated;
    drop function f();
    create function f() returns int language sql as $$ select 1 $$;`);
  assert.equal(fn(st2, 'f').authenticated, true);
});

test('overloads have their own grants', () => {
  const st = run(`
    create function v(p_id uuid, p_name text) returns void language sql as $$ $$;
    create function v(p_id uuid) returns void language sql as $$ $$;
    revoke execute on function v(uuid, text) from public, anon, authenticated;
    grant execute on function v(uuid, text) to authenticated;
    revoke execute on function v(uuid) from public, anon, authenticated;`);
  assert.equal(fn(st, 'v').overloads, 2);
  assert.equal(fn(st, 'v').authenticated, true);
  assert.equal(fn(st, 'v').anon, false);
});

test('sigOf normalises names, defaults, aliases and OUT args', () => {
  assert.equal(sigOf('p_id uuid, p_n int default 3, out total bigint, p_ts timestamptz'), 'uuid,integer,timestamp with time zone');
  assert.equal(sigOf('uuid, integer, timestamp with time zone'), 'uuid,integer,timestamp with time zone');
  assert.equal(sigOf('ids int4[], v varchar(20)'), 'integer[],character varying');
});

test('function rename and alter default privileges', () => {
  const st = run(`
    alter default privileges in schema public revoke execute on functions from public, anon, authenticated;
    create function old() returns void language sql as $$ $$;
    alter function public.old() rename to new_name;`);
  assert.deepEqual([...st.functions.keys()], ['new_name']);
  assert.equal(fn(st, 'new_name').anon, false);
  assert.equal(fn(st, 'new_name').authenticated, false);
});

test('cron schedule, unschedule and edge-function URLs', () => {
  const st = run(`
    select cron.schedule('a', '* * * * *', $$ select public.tick() $$);
    select cron.schedule('b', '0 1 * * *', $c$ select net.http_post(url := 'https://x/functions/v1/digest') $c$);
    select cron.schedule('c', '* * * * *', 'select 1');
    select cron.unschedule('c');`);
  assert.deepEqual([...st.cron.keys()], ['a', 'b']);
  const r = sqlRefs(st.cron.get('b').command, new Set());
  assert.deepEqual([...r.edges], ['digest']);
  assert.deepEqual([...sqlRefs(st.cron.get('a').command, new Set(['tick'])).fns], ['tick']);
});

test('sqlRefs ignores comments and string messages', () => {
  const fns = new Set(['helper']);
  assert.equal(sqlRefs(`-- helper() is gone\n raise exception 'use helper() instead';`, fns).fns.size, 0);
  assert.equal(sqlRefs(`select helper(1)`, fns).fns.size, 1);
});

test('triggers and DO blocks', () => {
  const st = run(`
    create table t (id int);
    create function trg() returns trigger language plpgsql as $$ begin return new; end $$;
    create trigger t_trg before update on public.t for each row execute function public.trg();
    do $$ begin
      if not exists (select 1 from pg_policies where policyname = 'p') then
        create policy p on public.t for select to authenticated using (true);
      end if;
    end $$;`);
  assert.equal(st.triggers.get('t.t_trg').fn, 'trg');
  assert.equal(st.tables.get('t').policies.size, 1);
  assert.equal(fn(st, 'trg').triggerOnly, true);
});

test('dynamic SQL is reported, and a revoke loop over named functions is applied', () => {
  const st = run(`
    create function a() returns void language sql as $$ $$;
    create function b() returns void language sql as $$ $$;
    do $$ declare n text; begin
      foreach n in array array['a', 'b'] loop
        execute format('revoke execute on function %s from public, anon, authenticated', n);
      end loop; end $$;
    do $$ begin execute format('alter table %I enable row level security', 'x'); end $$;`);
  assert.equal(fn(st, 'a').authenticated, false);
  assert.equal(fn(st, 'b').anon, false);
  assert.ok(st.unparsed.some((u) => /heuristically/.test(u.reason)));
  assert.ok(st.unparsed.some((u) => /dynamic SQL/.test(u.reason)));
});

test('unknown statements are reported, not silently dropped', () => {
  const st = run(`create aggregate x (int) (sfunc = f, stype = int); create statistics s on a, b from t; create rule r as on insert to t do nothing;`);
  assert.ok(st.unparsed.length >= 1);
});

test('catalog groups functions by name + arity; same-arity overloads merge with grants ORed', async () => {
  const { fromMigrations } = await import('../src/catalog.js');
  const st = run(`
    create function f(a int) returns int language sql as $$ select 1 $$;
    revoke execute on function f(int) from public, anon, authenticated;
    create function f(a int, b int) returns int language sql as $$ select 2 $$;
    create function g(a int) returns int language sql as $$ select 1 $$;
    create function g(a text) returns int language sql as $$ select 1 $$;
    revoke execute on function g(int) from public, anon, authenticated;
    create function s.h() returns int language sql as $$ select 1 $$;`);
  const c = fromMigrations(st);
  const by = Object.fromEntries(c.functions.map((f) => [f.key, f]));
  assert.deepEqual(Object.keys(by).sort(), ['f/1', 'f/2', 'g/1', 's.h/0']);
  assert.equal(by['f/1'].authenticated, false);
  assert.equal(by['f/2'].authenticated, true);
  assert.equal(by['g/1'].authenticated, true);
  assert.deepEqual(by['g/1'].signatures, ['g(integer)', 'g(text)']);
  assert.equal(by['s.h/0'].schema, 's');
});

test('unparsed statements touching grants or policies are flagged risky and raise a warning', async () => {
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const { scanMigrations } = await import('../src/scan-sql.js');
  const { analyze } = await import('../src/analyze.js');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'supareach-'));
  fs.mkdirSync(path.join(tmp, 'supabase/migrations'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'supabase/migrations/1_a.sql'), `
    create table t (id int);
    do $$ declare r record; begin
      for r in select policyname from pg_policies where tablename = 't' loop
        execute format('drop policy %I on t', r.policyname);
      end loop;
    end $$;
    do $$ begin execute 'create index i on t(id)'; end $$;`);
  const st = scanMigrations(path.join(tmp, 'supabase/migrations'));
  assert.deepEqual(st.unparsed.map((u) => u.risky), [true, false]);
  const r = await analyze(tmp);
  assert.equal(r.warnings.length, 1);
  assert.match(r.warnings[0], /1 migration statement\(s\)[\s\S]*--db-url/);
  fs.rmSync(tmp, { recursive: true, force: true });
});
