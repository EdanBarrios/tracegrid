// graph.html smoke tests (no browser): the page parses, embeds escaped data, never builds markup
// from data, and loads the optional 3D library only from a pinned URL with an SRI hash.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { renderHtml, FG3D } from '../src/html.js';

const bin = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'tracegrid.js');
const EVIL = '</script><img src=x onerror=alert(1)>\u2028\u2029<!--';

function hostile() {
  const nodes = [{ id: `fn:${EVIL}/0`, type: 'function', label: EVIL, anon: true, at: `${EVIL}:1` },
    { id: `file:src/${EVIL}.ts`, type: 'file', label: `src/${EVIL}.ts`, side: 'client' }];
  const links = [{ source: `file:src/${EVIL}.ts`, target: `fn:${EVIL}/0`, relation: 'rpc', confidence: 'extracted', ops: [], at: [`src/${EVIL}.ts:1`] }];
  return { root: EVIL, generated_at: 'now', nodes, links, tiers: { fix: 1, review: 0, info: 0 }, notices: [EVIL],
    findings: [{ rule: 'r', id: `${EVIL}/0`, node: `fn:${EVIL}/0`, tier: 'fix', level: 'error', note: EVIL, at: `${EVIL}:1` }],
    rules: [{ id: 'r', level: 'error', tier: 'fix', title: 'T', why: 'W' }] };
}

/** Split the page into its two script elements; the closing tag of each must be the real one. */
function scripts(html) {
  const json = /<script type="application\/json" id="data">([\s\S]*?)<\/script>/.exec(html);
  const code = /<script>([\s\S]*?)<\/script>/.exec(html.slice(json.index + json[0].length));
  return { json: json[1], code: code[1] };
}

test('graph.html parses: JSON data round-trips and the client script compiles', () => {
  const r = hostile();
  const h = renderHtml(r);
  assert.equal((h.match(/<\/script>/gi) || []).length, 2, 'only the two real closing tags');
  const { json, code } = scripts(h);
  const d = JSON.parse(json);
  assert.equal(d.root, EVIL);
  assert.equal(d.findings[0].note, EVIL);
  assert.doesNotThrow(() => new Function(code));
  assert.doesNotMatch(json, /<|\u2028|\u2029/, 'escaped: no <, U+2028 or U+2029 inside the data element');
  // The <title> is the only place data is interpolated into markup, and it is HTML-escaped.
  assert.match(h, /<title>tracegrid: &lt;\/script&gt;&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(h.replace(/<script[\s\S]*?<\/script>/g, ''), /<img/);
});

test('graph.html never builds markup or handlers from data', () => {
  const { code } = scripts(renderHtml(hostile()));
  // innerHTML only in the 3D tooltip, whose data parts go through esc().
  const assigns = code.match(/innerHTML\s*=/g) || [];
  assert.equal(assigns.length, 0, 'no innerHTML assignments');
  assert.match(code, /nodeLabel\(function\(n\)\{return'<div class="tip">'\+esc\(n\.label\)\+'<span>'\+esc\(/);
  assert.doesNotMatch(code, /setAttribute\('on|\.on[a-z]+\s*=\s*[^f(]/, 'no handler attributes');
  assert.doesNotMatch(code, /\beval\(|new Function|document\.write/);
});

test('graph.html: 3D library is pinned, loaded lazily with SRI and crossorigin, and matches the published file', () => {
  const h = renderHtml(hostile());
  assert.match(FG3D.url, /^https:\/\/cdn\.jsdelivr\.net\/npm\/3d-force-graph@\d+\.\d+\.\d+\/dist\/3d-force-graph\.min\.js$/);
  assert.match(FG3D.integrity, /^sha384-[A-Za-z0-9+/]{64}$/);
  const { json, code } = scripts(h);
  const d = JSON.parse(json);
  assert.equal(d.fg3d.url, FG3D.url);
  assert.equal(d.fg3d.integrity, FG3D.integrity);
  assert.match(code, /sc\.integrity=D\.fg3d\.integrity;sc\.crossOrigin='anonymous'/);
  assert.doesNotMatch(h, /<script[^>]+src=/, 'no script element with src in the markup: the 3D library loads only on demand');
  assert.doesNotMatch(h, /<link[^>]+href=/);
  assert.match(code, /needs internet/);
  // If a copy of the library is available locally (TRACEGRID_FG3D_FILE), check the hash against it.
  const f = process.env.TRACEGRID_FG3D_FILE;
  if (f && fs.existsSync(f)) assert.equal(FG3D.integrity, 'sha384-' + crypto.createHash('sha384').update(fs.readFileSync(f)).digest('base64'));
});

test('graph.html from the demo: findings carry tiers and the page lists Fix first', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tracegrid-html-'));
  const r = spawnSync(process.execPath, [bin, '--demo', '--out', tmp], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const h = fs.readFileSync(path.join(tmp, 'graph.html'), 'utf8');
  const d = JSON.parse(scripts(h).json);
  assert.ok(d.findings.length && d.findings.every((f) => ['fix', 'review', 'info'].includes(f.tier)));
  assert.deepEqual(Object.keys(d.tiers), ['fix', 'review', 'info']);
  const g = JSON.parse(fs.readFileSync(path.join(tmp, 'graph.json'), 'utf8'));
  assert.ok(g.findings.every((f) => f.tier && !f.fingerprint.includes(f.tier + ':')), 'tier is not part of the fingerprint');
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('graph.html: dashboard by default, arrowed and labelled edges, and the look in one THEME block', () => {
  const h = renderHtml(hostile(), { baseline: { file: 'tracegrid.baseline.json', fresh: ['r:a'], fixed: ['r:b', 'r:c'] } });
  const { json, code } = scripts(h);
  const d = JSON.parse(json);
  assert.deepEqual(d.baseline, { file: 'tracegrid.baseline.json', fresh: 1, fixed: 2 });
  assert.equal(typeof d.coverage.partial, 'number');
  assert.match(h, /data-view="dash" class="on">Dashboard/);
  assert.match(h, /<marker id="ar"[^>]*orient="auto"/);
  const css = /<style>([\s\S]*?)<\/style>/.exec(h)[1];
  const theme = css.slice(css.indexOf('THEME'), css.indexOf('end THEME'));
  for (const v of ['--font', '--edge', '--edge-w', '--arrow', '--fix', '--review', '--info', '--radius', '--box-w', '--3d-bg', '--3d-node']) assert.ok(theme.includes(v + ':'), v);
  assert.doesNotMatch(css.slice(css.indexOf('end THEME')), /#[0-9a-f]{3,6}\b/i, 'no colour outside the THEME block');
  assert.doesNotMatch(code, /'#[0-9a-f]{3,8}'/i, 'the script reads colours from THEME');
  for (const p of ['Exposure', 'Reach matrix', 'Biggest holes', 'Findings by rule', 'Top folders by database touchpoints', 'Supabase 2026-10-30 change', 'Coverage']) assert.ok(code.includes(p), p);
  assert.match(code, /'marker-end':'url\(#'/);
  for (const w of ["'calls'", "'invokes'", "'policy uses'", "'triggers'", "'EXECUTE'"]) assert.ok(code.includes(w), w);
  assert.match(code, /linkDirectionalArrowLength/);
  assert.match(code, /nodeThreeObject/);
});
