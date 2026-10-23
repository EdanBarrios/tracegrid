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
import { renderHtml, FG3D, truncLeft } from '../src/html.js';
import { COLORWAYS, DEFAULT_COLORWAY } from '../src/colorways.js';

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
  for (const p of ['Exposure', 'To do \u00b7 fix', 'Reach matrix', 'Findings by rule', 'Top folders', 'Supabase 2026-10-30 change', 'Coverage', 'Since baseline', 'show path', 'Info (']) assert.ok(code.includes(p), p);
  assert.match(code, /'marker-end':'url\(#'/);
  for (const w of ["'calls'", "'invokes'", "'policy uses'", "'triggers'", "'EXECUTE'"]) assert.ok(code.includes(w), w);
  assert.match(code, /linkDirectionalArrowLength/);
  assert.match(code, /nodeThreeObject/);
});

test('3D tab has an overview button, an Esc handler and a breadcrumb', () => {
  const h = renderHtml(hostile());
  assert.match(h, /id="ov3d"[^>]*>\\u25c1 overview|id="ov3d"[^>]*>◁ overview/);
  assert.match(h, /ev\.key!=='Escape'\|\|state\.view!=='3d'/);
  assert.match(h, /id="three-crumb"/);
  assert.match(h, /addEventListener\('dblclick'/);
});

test('colourways: signal is the default, all four are defined with a light variant, and the 3D palette follows them', () => {
  assert.equal(DEFAULT_COLORWAY, 'signal');
  assert.deepEqual(COLORWAYS, ['graphite-amber', 'signal', 'mono', 'mint']);
  const h = renderHtml(hostile());
  assert.match(h, /<html lang="en" data-colorway="signal" data-theme="dark">/);
  const d = JSON.parse(scripts(h).json);
  assert.equal(d.colorway, 'signal');
  assert.deepEqual(d.colorways, COLORWAYS);
  const css = /<style>([\s\S]*?)<\/style>/.exec(h)[1];
  const theme = css.slice(css.indexOf('THEME'), css.indexOf('end THEME'));
  for (const c of COLORWAYS) {
    assert.ok(theme.includes(`:root[data-colorway=${c}]{`), `${c} dark block`);
    assert.ok(theme.includes(`:root[data-colorway=${c}][data-theme=light]{`), `${c} light block`);
  }
  assert.match(theme, /--fix:#e3b867;--review:#9fb0c2/);
  assert.match(theme, /--fix:#ff3b30;--review:#ffb020/);
  assert.match(theme, /--fix:#ffffff[^}]*--fix-w:700/);
  assert.match(theme, /--fix:#72e0b0;--review:#8fa6b8/);
  assert.equal(JSON.parse(scripts(renderHtml(hostile(), { colorway: 'signal' })).json).colorway, 'signal');
  assert.match(renderHtml(hostile(), { colorway: 'mint' }), /data-colorway="mint"/);
  assert.throws(() => renderHtml(hostile(), { colorway: 'x"><script>' }), /unknown colourway/);
  // Severity glyphs stay next to the colour.
  const { code } = scripts(h);
  assert.match(code, /GLY=\{fix:'\\u25c6',review:'\\u25c7',info:'\\u00b7'\}/);
  // The 3D view reads the palette from the active colourway and re-applies it when it changes.
  assert.match(code, /function recolor3d\(\)\{[^]*pal\(\);G3\.backgroundColor\(P3\.bg\)/);
  assert.match(code, /function applyLook\(\)\{[^]*recolor3d\(\)/);
});

test('colourways: ?colorway= beats storage beats the baked-in default, and every storage access is wrapped', () => {
  const { code } = scripts(renderHtml(hostile()));
  assert.match(code, /new URLSearchParams\(location\.search\)\.get\('colorway'\)/);
  assert.match(code, /colorway:okCw\(urlColorway\(\)\)\?urlColorway\(\):okCw\(sget\('colorway'\)\)\?sget\('colorway'\):D\.colorway/);
  assert.match(code, /function sget\(k\)\{try\{return window\.localStorage\.getItem\(LS\+k\)\}catch\(e\)\{return null\}\}/);
  assert.match(code, /function sset\(k,v\)\{try\{window\.localStorage\.setItem\(LS\+k,v\)\}catch\(e\)\{\}\}/);
  assert.equal((code.match(/localStorage/g) || []).length, 2, 'only the two wrapped accessors touch storage');
  assert.doesNotMatch(code, /sessionStorage|indexedDB/);
  // Run the parsing and storage helpers against a storage that throws and a hostile URL.
  const start = code.indexOf('var LS=');
  const end = code.indexOf('var mq=null');
  const body = code.slice(start, end);
  const run = (search, store) => new Function('window', 'location', 'D', `${body}; return look;`)(
    { localStorage: store }, { search }, { colorways: COLORWAYS, colorway: 'signal' });
  const boom = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); } };
  assert.equal(run('', boom).colorway, 'signal');
  assert.equal(run('?colorway=signal', boom).colorway, 'signal');
  assert.equal(run('?colorway=nope', boom).colorway, 'signal');
  assert.equal(run('?colorway=<script>', boom).colorway, 'signal');
  const mem = { m: { 'tracegrid.colorway': 'mint', 'tracegrid.rotate': '0' }, getItem(k) { return this.m[k] ?? null; }, setItem() {} };
  const l = run('', mem);
  assert.equal(l.colorway, 'mint');
  assert.equal(l.rot, false);
  assert.equal(run('?colorway=mono', mem).colorway, 'mono', 'the URL beats the stored choice');
});

test('settings popover: gear next to the theme toggle with colourway, mode and auto-rotate', () => {
  const h = renderHtml(hostile());
  assert.match(h, /id="gear"[^>]*>[^<]*<\/button><button id="theme"/);
  for (const id of ['cw', 'mode', 'rot']) assert.match(h, new RegExp(`id="${id}"`));
  assert.match(h, /Auto-rotate 3D/);
  assert.match(h, /<option value="auto">Auto/);
});

test('truncLeft keeps the file name and line, cuts from the left, and is embedded in the page', () => {
  const p = 'supabase/migrations/20240201000000_billing.sql:29';
  assert.equal(truncLeft(p, 100), p);
  assert.equal(truncLeft(p, p.length), p);
  const t = truncLeft(p, 34);
  assert.equal(t, '\u2026/20240201000000_billing.sql:29');
  assert.ok(t.length <= 34 && t.endsWith('billing.sql:29'));
  assert.equal(truncLeft(p, 20), '\u2026' + p.slice(-19));
  assert.equal(truncLeft(null, 5), '');
  assert.equal(truncLeft('abc', 1), 'abc');
  const h = renderHtml(hostile());
  assert.ok(h.includes('function truncLeft'), 'helper shipped in the client script');
  assert.ok(h.includes("title:text"), 'full path goes through the title attribute');
});
