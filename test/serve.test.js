// --serve (localhost server behind the Refresh button) and --json (machine-readable output for agents).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startServer } from '../src/serve.js';
import { renderHtml } from '../src/html.js';
import { project, rm } from './helpers.js';

const repo = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(repo, 'bin', 'tracegrid.js');
const run = (args, opts = {}) => spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', ...opts });

/** A build() that counts scans; each result carries its number so tests can tell which one they got. */
function fakeBuild() {
  const b = { n: 0, fail: false, gate: null };
  b.build = async () => {
    b.n++;
    if (b.gate) await b.gate;
    if (b.fail) throw new Error('boom\nsecond line');
    return { html: `<html>scan ${b.n}</html>`, json: `{"scan":${b.n}}`, report: `# scan ${b.n}`, generated_at: `t${b.n}`, tiers: { fix: b.n, review: 0, info: 0 } };
  };
  return b;
}

/** Raw request, so a test can set Host and Origin exactly (fetch forbids Host). */
function req(srv, { method = 'GET', url = '/', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port: srv.port, method, path: url, headers }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });
    r.on('error', reject);
    r.end();
  });
}
const same = (srv) => ({ Host: `127.0.0.1:${srv.port}`, Origin: `http://127.0.0.1:${srv.port}`, 'X-Tracegrid': '1' });

test('serve: routes, no-store, and the loopback-only bind', async () => {
  const f = fakeBuild();
  const srv = await startServer({ build: f.build, port: 0 });
  try {
    assert.match(srv.url, /^http:\/\/127\.0\.0\.1:\d+\/$/);
    const page = await req(srv);
    assert.equal(page.status, 200);
    assert.equal(page.body, '<html>scan 1</html>');
    assert.equal(page.headers['cache-control'], 'no-store');
    assert.equal(page.headers['x-content-type-options'], 'nosniff');
    assert.equal((await req(srv, { url: '/graph.json' })).body, '{"scan":1}');
    assert.equal((await req(srv, { url: '/report.md?x=1' })).body, '# scan 1');
    assert.deepEqual(JSON.parse((await req(srv, { url: '/status' })).body), { generated_at: 't1', running: false, error: null });
    assert.equal((await req(srv, { url: '/etc/passwd' })).status, 404);
    assert.equal((await req(srv, { method: 'PUT', url: '/refresh' })).status, 405);
    assert.equal(f.n, 1, 'reading never scans');
  } finally { await srv.close(); }
});

test('serve: a wrong Host (DNS rebinding) is refused on every route', async () => {
  const srv = await startServer({ build: fakeBuild().build, port: 0 });
  try {
    for (const url of ['/', '/graph.json', '/status']) assert.equal((await req(srv, { url, headers: { Host: 'evil.example' } })).status, 403, url);
    assert.equal((await req(srv, { url: '/status', headers: { Host: `localhost:${srv.port}` } })).status, 200, 'localhost is fine');
    assert.equal((await req(srv, { url: '/status', headers: { Host: `127.0.0.1:${srv.port + 1}` } })).status, 403, 'wrong port');
  } finally { await srv.close(); }
});

test('serve: POST /refresh needs a same-origin request with the custom header', async () => {
  const f = fakeBuild();
  const srv = await startServer({ build: f.build, port: 0 });
  try {
    const host = `127.0.0.1:${srv.port}`;
    assert.equal((await req(srv, { method: 'POST', url: '/refresh', headers: { Host: host } })).status, 403, 'no origin, no header');
    assert.equal((await req(srv, { method: 'POST', url: '/refresh', headers: { Host: host, Origin: 'http://evil.example', 'X-Tracegrid': '1' } })).status, 403, 'cross-site origin');
    assert.equal((await req(srv, { method: 'POST', url: '/refresh', headers: { Host: host, Origin: `http://${host}` } })).status, 403, 'no custom header');
    assert.equal(f.n, 1, 'none of those scanned');
    const ok = await req(srv, { method: 'POST', url: '/refresh', headers: same(srv) });
    assert.equal(ok.status, 200);
    assert.deepEqual(JSON.parse(ok.body), { generated_at: 't2', tiers: { fix: 2, review: 0, info: 0 } });
    assert.equal((await req(srv, { url: '/graph.json' })).body, '{"scan":2}', 'the page now serves the new scan');
  } finally { await srv.close(); }
});

test('serve: concurrent refreshes share one scan; a failed refresh keeps the last good result', async () => {
  const f = fakeBuild();
  const srv = await startServer({ build: f.build, port: 0 });
  try {
    let release;
    f.gate = new Promise((r) => { release = r; });
    const a = req(srv, { method: 'POST', url: '/refresh', headers: same(srv) });
    const b = req(srv, { method: 'POST', url: '/refresh', headers: same(srv) });
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(JSON.parse((await req(srv, { url: '/status' })).body).running, true);
    release();
    const [ra, rb] = await Promise.all([a, b]);
    assert.equal(ra.status, 200);
    assert.equal(rb.status, 200);
    assert.equal(f.n, 2, 'two requests, one scan (plus the first)');
    f.gate = null; f.fail = true;
    const bad = await req(srv, { method: 'POST', url: '/refresh', headers: same(srv) });
    assert.equal(bad.status, 500);
    assert.deepEqual(JSON.parse(bad.body), { error: 'boom' }, 'first line only');
    assert.equal((await req(srv, { url: '/graph.json' })).body, '{"scan":2}', 'still the last good scan');
    assert.equal(JSON.parse((await req(srv, { url: '/status' })).body).error, 'boom');
  } finally { await srv.close(); }
});

test('serve: a failing first scan or a busy port rejects instead of serving nothing', async () => {
  const f = fakeBuild(); f.fail = true;
  await assert.rejects(startServer({ build: f.build, port: 0 }), /boom/);
  const a = await startServer({ build: fakeBuild().build, port: 0 });
  try { await assert.rejects(startServer({ build: fakeBuild().build, port: a.port }), /port \d+ is in use/); } finally { await a.close(); }
});

test('serve: --watch rescans on a change, ignoring node_modules and the output directory', async () => {
  const d = project({ 'src/a.ts': '', 'node_modules/x/i.js': '', 'out/graph.json': '' });
  const f = fakeBuild();
  const srv = await startServer({ build: f.build, port: 0, watch: { root: d, ignore: [path.join(d, 'out')] } });
  const settle = (ms) => new Promise((r) => setTimeout(r, ms));
  try {
    // FSEvents (macOS) can replay the fixture's own writes just after the watcher starts: let that pass.
    await settle(1500);
    const n0 = f.n;
    fs.writeFileSync(path.join(d, 'node_modules/x/i.js'), 'x');
    fs.writeFileSync(path.join(d, 'out/graph.json'), 'x');
    await settle(1200);
    assert.equal(f.n, n0, 'ignored paths do not rescan');
    fs.writeFileSync(path.join(d, 'src/a.ts'), 'export {}');
    fs.writeFileSync(path.join(d, 'src/b.ts'), 'export {}');
    await settle(1500);
    assert.equal(f.n, n0 + 1, 'a burst of changes is one rescan');
    assert.equal((await req(srv, { url: '/graph.json' })).body, `{"scan":${n0 + 1}}`);
  } finally { await srv.close(); rm(d); }
});

test('page: the Refresh button exists only in the served copy, never in the file on disk', () => {
  const r = { root: 'x', generated_at: 'now', nodes: [], links: [], tiers: { fix: 0, review: 0, info: 0 }, findings: [], rules: [], platform: 'supabase' };
  const data = (h) => JSON.parse(/<script type="application\/json" id="data">([\s\S]*?)<\/script>/.exec(h)[1]);
  assert.equal(data(renderHtml(r)).serve, null);
  assert.deepEqual(data(renderHtml(r, { serve: { watch: false } })).serve, { watch: false });
  assert.deepEqual(data(renderHtml(r, { serve: { watch: true } })).serve, { watch: true });
  const code = /<script>([\s\S]*?)<\/script>/.exec(renderHtml(r, { serve: { watch: true } }).split('id="data"')[1])[1];
  assert.match(code, /if\(D\.serve\)/, 'guarded by the flag');
  assert.match(code, /fetch\('\/refresh',\{method:'POST',headers:\{'X-Tracegrid':'1'\}\}\)/);
  assert.doesNotThrow(() => new Function(code), 'the client script parses');
});

test('--json: one JSON object on stdout, human text on stderr, exit codes unchanged', () => {
  const r = run(['--demo', 'firebase', '--json', '--no-output']);
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim().split('\n').length, 1, 'stdout is a single line');
  const j = JSON.parse(r.stdout);
  assert.equal(j.platform, 'firebase');
  assert.equal(j.tiers.fix, j.findings.filter((f) => f.tier === 'fix').length);
  assert.ok(j.findings.length > 0 && j.findings.every((f) => f.tier !== 'info'), 'Fix and Review only');
  assert.ok(j.findings.findIndex((f) => f.tier === 'review') > j.findings.map((f) => f.tier).lastIndexOf('fix'), 'Fix first');
  for (const k of ['rule', 'id', 'at', 'fingerprint', 'level', 'note', 'confidence']) assert.ok(k in j.findings[0], k);
  assert.deepEqual(j.scope_problems, []);
  assert.equal(j.baseline, null);
  assert.match(r.stderr, /Fix \d+/, 'the usual summary went to stderr');
});

test('--json: an empty scan says so, and marks findings new against a baseline', () => {
  const d = project({ 'src/a.ts': 'export {}' });
  try {
    const e = JSON.parse(run([d, '--json', '--no-output']).stdout);
    assert.ok(e.scope_problems.length > 0, 'an empty scan is reported as a scope problem, not as clean');
  } finally { rm(d); }
  const demo = path.join(repo, 'examples', 'firebase-demo');
  const b = project({ '.keep': '' });
  try {
    const base = path.join(b, 'base.json');
    assert.equal(run([demo, '--update-baseline', '--force', '--baseline', base, '--no-output']).status, 0);
    const clean = JSON.parse(run([demo, '--json', '--no-output', '--baseline', base]).stdout);
    assert.equal(clean.baseline.new, 0);
    assert.ok(clean.findings.every((f) => f.new === false));
  } finally { rm(b); }
});

test('flags: --serve cannot gate or print JSON; --watch and --port need --serve; --port is validated', () => {
  for (const flag of ['--check', '--update-baseline', '--json']) assert.match(run(['--demo', '--serve', flag]).stderr, new RegExp(`--serve cannot be combined with ${flag}`));
  assert.equal(run(['--demo', '--serve', '--check']).status, 2);
  assert.match(run(['--demo', '--watch']).stderr, /only apply with --serve/);
  assert.match(run(['--demo', '--port', '80']).stderr, /only apply with --serve/);
  assert.match(run(['--demo', '--serve', '--port', 'abc']).stderr, /--port must be a number/);
  assert.match(run(['--demo', '--serve', '--port', '70000']).stderr, /--port must be a number/);
});
