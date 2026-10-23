// Catalog mode: read the schema from a live database through `psql`, inside a read-only transaction.
//
// No npm dependency: shells out to the `psql` client (override with SUPAREACH_PSQL). The connection
// URL is split into PG* environment variables so the password never appears in a process list.
// Only catalog tables and has_*_privilege() are read; nothing is written, and no Supabase API key is
// involved (supareach talks Postgres, never PostgREST, so it never needs service_role).
import { spawnSync } from 'node:child_process';
import { groupFunctions } from './catalog.js';

export class DbError extends Error {}

/** Schemas that belong to Postgres or the Supabase platform, never to the app. */
export const SYSTEM_SCHEMAS = ['pg_catalog', 'information_schema', 'pg_toast', 'auth', 'storage', 'extensions', 'graphql', 'graphql_public',
  'realtime', '_realtime', 'supabase_functions', 'supabase_migrations', 'vault', 'pgsodium', 'pgsodium_masks', 'net', 'cron', 'pgbouncer',
  '_analytics', 'pgtle', 'tiger', 'tiger_data', 'topology'];

const sysList = SYSTEM_SCHEMAS.map((s) => `'${s}'`).join(', ');
const appSchema = (col) => `${col} not in (${sysList}) and ${col} not like 'pg\\_%'`;
const priv = (fn, role, obj, p) => `(select ${fn}(r.oid, ${obj}, '${p}') from pg_roles r where r.rolname = '${role}')`;

/** The whole read, as one psql script. Each select prints one line of JSON: { "section", "data" }. */
export const CATALOG_SQL = String.raw`
begin transaction isolation level repeatable read read only;
set local statement_timeout = '60s';
select jsonb_build_object('section', 'meta', 'data', jsonb_build_object(
  'server_version_num', current_setting('server_version_num'),
  'transaction_read_only', current_setting('transaction_read_only'),
  'current_user', current_user,
  'roles', (select coalesce(jsonb_agg(rolname order by rolname), '[]') from pg_roles where rolname in ('anon', 'authenticated'))));
select
  coalesce(has_table_privilege(to_regclass('cron.job')::oid, 'SELECT'), false) as supareach_has_cron,
  coalesce(has_table_privilege(to_regclass('storage.buckets')::oid, 'SELECT'), false) as supareach_has_buckets
\gset
select jsonb_build_object('section', 'functions', 'data', coalesce(jsonb_agg(jsonb_build_object(
  'schema', n.nspname, 'name', p.proname, 'nargs', p.pronargs,
  'identity_args', pg_get_function_identity_arguments(p.oid), 'args', pg_get_function_arguments(p.oid),
  'returns', coalesce(pg_get_function_result(p.oid), 'void'), 'kind', p.prokind, 'security_definer', p.prosecdef,
  'anon', ${priv('has_function_privilege', 'anon', 'p.oid', 'EXECUTE')},
  'authenticated', ${priv('has_function_privilege', 'authenticated', 'p.oid', 'EXECUTE')},
  'body', case when l.lanname in ('sql', 'plpgsql') then p.prosrc else '' end
) order by n.nspname, p.proname, p.oid), '[]'))
from pg_proc p join pg_namespace n on n.oid = p.pronamespace join pg_language l on l.oid = p.prolang
where ${appSchema('n.nspname')} and p.prokind in ('f', 'p')
  and not exists (select 1 from pg_depend d where d.classid = 'pg_proc'::regclass and d.objid = p.oid and d.deptype = 'e');
select jsonb_build_object('section', 'relations', 'data', coalesce(jsonb_agg(jsonb_build_object(
  'schema', n.nspname, 'name', c.relname, 'relkind', c.relkind, 'rls', c.relrowsecurity,
  'security_invoker', coalesce((select option_value from pg_options_to_table(c.reloptions) where option_name = 'security_invoker'), 'false'),
  'definition', case when c.relkind in ('v', 'm') then pg_get_viewdef(c.oid) else '' end,
  'defaults', (select coalesce(string_agg(pg_get_expr(d.adbin, d.adrelid), ' '), '') from pg_attrdef d where d.adrelid = c.oid),
  'anon_select', ${priv('has_table_privilege', 'anon', 'c.oid', 'SELECT')},
  'authenticated_select', ${priv('has_table_privilege', 'authenticated', 'c.oid', 'SELECT')}
) order by n.nspname, c.relname), '[]'))
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where ${appSchema('n.nspname')} and c.relkind in ('r', 'p', 'v', 'm', 'f');
select jsonb_build_object('section', 'policies', 'data', coalesce(jsonb_agg(jsonb_build_object(
  'schema', schemaname, 'table', tablename, 'name', policyname, 'permissive', permissive, 'roles', to_jsonb(roles),
  'cmd', cmd, 'qual', qual, 'with_check', with_check) order by schemaname, tablename, policyname), '[]'))
from pg_policies where schemaname not in ('pg_catalog', 'information_schema');
select jsonb_build_object('section', 'triggers', 'data', coalesce(jsonb_agg(jsonb_build_object(
  'name', t.tgname, 'schema', n.nspname, 'table', c.relname, 'fn_schema', pn.nspname, 'fn', p.proname) order by n.nspname, c.relname, t.tgname), '[]'))
from pg_trigger t join pg_class c on c.oid = t.tgrelid join pg_namespace n on n.oid = c.relnamespace
join pg_proc p on p.oid = t.tgfoid join pg_namespace pn on pn.oid = p.pronamespace
where not t.tgisinternal and ${appSchema('pn.nspname')};
select jsonb_build_object('section', 'event_triggers', 'data', coalesce(jsonb_agg(jsonb_build_object(
  'name', e.evtname, 'fn_schema', pn.nspname, 'fn', p.proname) order by e.evtname), '[]'))
from pg_event_trigger e join pg_proc p on p.oid = e.evtfoid join pg_namespace pn on pn.oid = p.pronamespace;
\if :supareach_has_cron
select jsonb_build_object('section', 'cron', 'data', coalesce(jsonb_agg(jsonb_build_object(
  'name', coalesce(jobname, 'job ' || jobid), 'schedule', schedule, 'command', command, 'active', active) order by jobid), '[]'))
from cron.job;
\endif
\if :supareach_has_buckets
select jsonb_build_object('section', 'buckets', 'data', coalesce(jsonb_agg(jsonb_build_object('name', id, 'public', public) order by id), '[]'))
from storage.buckets;
\endif
rollback;
`;

const ENV_PARAMS = { sslmode: 'PGSSLMODE', sslrootcert: 'PGSSLROOTCERT', sslcert: 'PGSSLCERT', sslkey: 'PGSSLKEY', application_name: 'PGAPPNAME', connect_timeout: 'PGCONNECT_TIMEOUT', options: 'PGOPTIONS' };

/** postgres:// URL -> PG* environment. Throws DbError on anything else. */
export function urlToEnv(url) {
  let u;
  try { u = new URL(url); } catch { throw new DbError('--db-url must be a postgres:// or postgresql:// URL'); }
  if (!/^postgres(ql)?:$/.test(u.protocol)) throw new DbError('--db-url must be a postgres:// or postgresql:// URL');
  const env = { PGCONNECT_TIMEOUT: '10', PGAPPNAME: 'supareach' };
  if (u.hostname) env.PGHOST = decodeURIComponent(u.hostname.replace(/^\[|\]$/g, ''));
  if (u.port) env.PGPORT = u.port;
  if (u.username) env.PGUSER = decodeURIComponent(u.username);
  if (u.password) env.PGPASSWORD = decodeURIComponent(u.password);
  const db = decodeURIComponent(u.pathname.replace(/^\//, ''));
  if (db) env.PGDATABASE = db;
  for (const [k, v] of u.searchParams) {
    if (k === 'host') env.PGHOST = v;
    else if (ENV_PARAMS[k]) env[ENV_PARAMS[k]] = v;
    else throw new DbError(`--db-url: unsupported parameter "${k}"`);
  }
  return env;
}

/** Run the catalog script through psql; returns raw sections. `exec` is injectable for tests. */
export function readCatalog(url, { exec = execPsql } = {}) {
  const env = urlToEnv(url);
  const out = exec(CATALOG_SQL, env);
  const sections = {};
  for (const line of out.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    let j;
    try { j = JSON.parse(t); } catch { throw new DbError(`unexpected psql output: ${t.slice(0, 120)}`); }
    if (j && j.section) sections[j.section] = j.data;
  }
  for (const k of ['meta', 'functions', 'relations', 'policies', 'triggers']) if (!sections[k]) throw new DbError(`catalog read returned no "${k}" section`);
  if (sections.meta.transaction_read_only !== 'on') throw new DbError('refusing to continue: the catalog read did not run in a read-only transaction');
  return sections;
}

function execPsql(sql, env) {
  const bin = process.env.SUPAREACH_PSQL || 'psql';
  const r = spawnSync(bin, ['-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-f', '-'], {
    input: sql, encoding: 'utf8', env: { ...process.env, ...env }, maxBuffer: 512 * 1024 * 1024, timeout: 120000,
  });
  if (r.error && r.error.code === 'ENOENT') throw new DbError(`${bin} not found. --db-url needs the PostgreSQL client (psql) on PATH, or set SUPAREACH_PSQL.`);
  if (r.error) throw new DbError(`psql failed: ${r.error.message}`);
  if (r.status !== 0) throw new DbError(`psql exited ${r.status}: ${(r.stderr || '').trim().split('\n').slice(0, 3).join(' / ')}`);
  return r.stdout;
}

const qn = (schema, name) => (schema === 'public' ? name : `${schema}.${name}`);

/**
 * Catalog shape (see src/catalog.js) from the raw sections. `fallback` is the migration catalog:
 * it supplies file:line locations, and cron jobs when cron.job could not be read.
 */
export function fromDb(sec, fallback) {
  const fnAt = new Map();
  for (const f of fallback ? fallback.functions : []) { fnAt.set(f.key, f.at); if (!fnAt.has(f.name)) fnAt.set(f.name, f.at); }
  const relAt = new Map([...(fallback ? fallback.tables : []), ...(fallback ? fallback.views : [])].map((t) => [t.name, t.at]));
  const notes = [];
  const roles = sec.meta.roles || [];
  if (!roles.includes('anon') || !roles.includes('authenticated')) notes.push('roles anon/authenticated not found: not a Supabase database? Grant-based findings will be empty.');

  const rows = sec.functions.map((f) => {
    const name = qn(f.schema, f.name);
    const key = `${name}/${f.nargs}`;
    return { name, arity: f.nargs, signature: `${name}(${f.identity_args})`, args: f.args, returns: String(f.returns || '').toLowerCase(),
      kind: f.kind === 'p' ? 'procedure' : 'function', securityDefiner: f.security_definer, anon: !!f.anon, authenticated: !!f.authenticated,
      body: f.body || '', at: fnAt.get(key) || fnAt.get(name) || `db:${name}(${f.identity_args})` };
  });
  const policies = new Map();
  for (const p of sec.policies) {
    const t = qn(p.schema, p.table);
    if (!policies.has(t)) policies.set(t, []);
    policies.get(t).push({ name: p.name, command: String(p.cmd || 'ALL').toLowerCase(), roles: p.roles || [], text: [p.qual, p.with_check].filter(Boolean).join('\n'), at: relAt.get(t) || `db:${t}` });
  }
  const tables = [];
  const views = [];
  const seen = new Set(sec.relations.map((r) => qn(r.schema, r.name)));
  // Policies and triggers on platform tables (storage.objects, auth.users) still reference app functions.
  for (const [t, ps] of policies) if (!seen.has(t)) tables.push({ name: t, schema: t.split('.')[0], rls: true, external: true, text: '', at: relAt.get(t) || `db:${t}`, policies: ps });
  for (const r of sec.relations) {
    const name = qn(r.schema, r.name);
    const at = relAt.get(name) || `db:${name}`;
    if (r.relkind === 'v' || r.relkind === 'm') views.push({ name, schema: r.schema, securityInvoker: /^(true|on|1|yes)$/i.test(String(r.security_invoker)), materialized: r.relkind === 'm', text: r.definition || '', at });
    else tables.push({ name, schema: r.schema, rls: !!r.rls, external: false, text: r.defaults || '', at, policies: policies.get(name) || [],
      grants: { anon: { select: !!r.anon_select }, authenticated: { select: !!r.authenticated_select } } });
  }
  const triggers = [
    ...sec.triggers.map((t) => ({ name: t.name, table: qn(t.schema, t.table), fn: qn(t.fn_schema, t.fn), at: relAt.get(qn(t.schema, t.table)) || 'db:trigger' })),
    ...(sec.event_triggers || []).map((t) => ({ name: t.name, table: '(event)', fn: qn(t.fn_schema, t.fn), at: 'db:event trigger' })),
  ];
  let cron;
  if (sec.cron) cron = sec.cron.map((c) => ({ name: c.name, schedule: c.schedule, command: c.command || '', active: c.active, at: `db:cron.job ${c.name}` }));
  else {
    cron = fallback ? fallback.cron : [];
    notes.push('cron.job is absent or not readable by this role: cron jobs come from migrations.');
  }
  return {
    source: 'catalog',
    tables, views,
    functions: groupFunctions(rows),
    triggers, cron,
    buckets: sec.buckets ? sec.buckets.map((b) => ({ name: b.name, public: !!b.public })) : null,
    dynamic: [],
    unparsed: [],
    notes,
    meta: { server_version_num: sec.meta.server_version_num, current_user: sec.meta.current_user },
    stats: fallback ? fallback.stats : { migrations: 0, statements: 0 },
  };
}
