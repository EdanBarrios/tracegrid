import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readCatalog, fromDb, urlToEnv, CATALOG_SQL, DbError } from '../src/db.js';
import { analyze } from '../src/analyze.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const demo = path.join(here, '..', 'examples', 'demo-app');
const bin = path.join(here, '..', 'bin', 'supareach.js');
const fixture = path.join(here, 'fixtures', 'demo-catalog.jsonl');
const fakePsql = path.join(here, 'fixtures', 'fake-psql.mjs');
const fixtureText = fs.readFileSync(fixture, 'utf8');
const URL_ = 'postgresql://ro_user:s3cr%40t@db.example.com:6543/postgres?sslmode=require';

test('URL is split into PG* env; the password never goes on argv', () => {
  assert.deepEqual(urlToEnv(URL_), {
    PGCONNECT_TIMEOUT: '10', PGAPPNAME: 'supareach', PGHOST: 'db.example.com', PGPORT: '6543', PGUSER: 'ro_user', PGPASSWORD: 's3cr@t', PGDATABASE: 'postgres', PGSSLMODE: 'require',
  });
  assert.throws(() => urlToEnv('mysql://x'), DbError);
  assert.throws(() => urlToEnv('postgres://h/db?weird=1'), /unsupported parameter/);
});

test('catalog script is read-only and never writes', () => {
  assert.match(CATALOG_SQL, /^\s*begin transaction isolation level repeatable read read only;/);
  assert.match(CATALOG_SQL, /rollback;\s*$/);
  const statements = CATALOG_SQL.replace(/'[^']*'/g, "''");
  assert.doesNotMatch(statements, /\b(insert|update|delete|create|drop|alter|grant|revoke|truncate|commit)\b/i);
  assert.match(CATALOG_SQL, /has_function_privilege/);
  assert.match(CATALOG_SQL, /from pg_policies/);
  assert.match(CATALOG_SQL, /cron\.job/);
  assert.match(CATALOG_SQL, /storage\.buckets/);
});

test('readCatalog refuses output that did not come from a read-only transaction', () => {
  const bad = fixtureText.replace('"transaction_read_only": "on"', '"transaction_read_only": "off"');
  assert.throws(() => readCatalog(URL_, { exec: () => bad }), /read-only transaction/);
  assert.throws(() => readCatalog(URL_, { exec: () => 'ERROR' }), /unexpected psql output/);
});

test('catalog wins over migrations: dashboard revokes, dashboard functions and cron jobs', async () => {
  const mig = await analyze(demo, { allowPlugins: true });
  const db = await analyze(demo, { allowPlugins: true, dbUrl: URL_, dbExec: () => fixtureText });
  const ids = (r, k) => r.findings.filter((f) => f.rule === k).map((f) => f.id).sort();
  assert.equal(db.source, 'catalog');
  assert.ok(db.findings.every((f) => f.source === 'catalog'));
  assert.ok(mig.findings.every((f) => f.source === 'migrations'));
  // internal_cleanup was revoked outside migrations; dashboard_fn was created outside them.
  assert.deepEqual(ids(mig, 'exposed-uncalled-function'), ['internal_cleanup/0', 'next_invoice_number/1']);
  assert.deepEqual(ids(db, 'exposed-uncalled-function'), ['dashboard_fn/0', 'next_invoice_number/1']);
  assert.equal(db.findings.find((f) => f.id === 'dashboard_fn/0').at, 'db:dashboard_fn()');
  assert.match(db.findings.find((f) => f.id === 'next_invoice_number/1').at, /^supabase\/migrations\/20240201000000_billing\.sql:\d+$/);
  // Helpers referenced from storage.objects policies count as used (platform-schema policies are read).
  assert.deepEqual(ids(db, 'granted-helper-function'), ['can_upload_avatar/1', 'is_project_member/1']);
  assert.ok(db.links.some((e) => e.source === 'table:auth.users' && e.target === 'fn:handle_new_user/0' && e.relation === 'trigger'));
  // A cron job added in the dashboard calls export-csv.
  assert.deepEqual(ids(mig, 'uncalled-edge-function'), ['export-csv']);
  assert.deepEqual(ids(db, 'uncalled-edge-function'), []);
  assert.deepEqual(ids(db, 'client-table-without-rls'), ['audit_log']);
  assert.deepEqual(ids(db, 'client-table-without-policies'), ['invoices']);
  assert.ok(db.nodes.some((n) => n.id === 'bucket:avatars' && n.public === false && !n.missing));
  assert.deepEqual(db.warnings, []);
  assert.equal(db.database.current_user, 'supareach_ro');
});

test('without cron.job access, cron comes from migrations, with a warning', () => {
  const lines = fixtureText.split('\n').filter((l) => !l.startsWith('{"section": "cron"'));
  const sec = readCatalog(URL_, { exec: () => lines.join('\n') });
  const c = fromDb(sec, { functions: [], tables: [], views: [], cron: [{ name: 'from-migrations', command: '', at: 'm.sql:1' }], stats: { migrations: 1, statements: 1 } });
  assert.deepEqual(c.cron.map((x) => x.name), ['from-migrations']);
  assert.match(c.notes.join(), /cron\.job is absent or not readable/);
});

test('CLI --db-url shells out to psql with env credentials and stdin SQL', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'supareach-'));
  const log = path.join(tmp, 'psql.json');
  const env = { ...process.env, SUPAREACH_PSQL: fakePsql, FAKE_PSQL_FIXTURE: fixture, FAKE_PSQL_LOG: log };
  let r = spawnSync(process.execPath, [bin, demo, '--allow-plugins', '--no-output', '--db-url', URL_], { env, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /schema from the database catalog/);
  const call = JSON.parse(fs.readFileSync(log, 'utf8'));
  assert.ok(!call.argv.join(' ').includes('s3cr'), 'password must not be on argv');
  assert.equal(call.env.PGPASSWORD, 's3cr@t');
  assert.equal(call.env.PGSSLMODE, 'require');
  assert.match(call.stdin, /read only/);

  r = spawnSync(process.execPath, [bin, demo, '--allow-plugins', '--no-output'], { env: { ...env, SUPAREACH_DB_URL: URL_ }, encoding: 'utf8' });
  assert.match(r.stdout, /schema from the database catalog/);

  r = spawnSync(process.execPath, [bin, demo, '--allow-plugins', '--no-output', '--db-url', URL_], { env: { ...env, FAKE_PSQL_FAIL: '1' }, encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /psql exited 2: psql: error: connection refused/);

  r = spawnSync(process.execPath, [bin, demo, '--allow-plugins', '--no-output', '--db-url', URL_], { env: { ...env, SUPAREACH_PSQL: path.join(tmp, 'no-such-psql') }, encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /not found/);
  fs.rmSync(tmp, { recursive: true, force: true });
});
