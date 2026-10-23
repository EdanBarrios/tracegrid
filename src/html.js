// graph.html: one self-contained page. The dashboard and the 2D views (path view and full map) are
// plain DOM and SVG and work offline. The optional 3D view lazy-loads one pinned library from
// jsDelivr, with a Subresource Integrity hash, only when the user asks for it; no data ever leaves
// the page.
//
// Every name in the data comes from the scanned project (a fork pull request controls it), so:
// the data is embedded as JSON with `<`, U+2028 and U+2029 escaped; the page builds its DOM with
// textContent, and the few places that assign innerHTML (the 3D hover tooltip) pass esc() output;
// no event handler attribute is ever built from data.
//
// The look lives in one place: the THEME block of CSS variables at the top of CSS below (colours,
// strokes, radii, sizes, fonts, and the 3D palette, which the script reads from the same variables).

import { COLORWAYS, DEFAULT_COLORWAY, checkColorway } from './colorways.js';

/** The pinned 3D library (bundles three.js). Checked with `curl -sI`; the hash is of the fetched file. */
export const FG3D = {
  url: 'https://cdn.jsdelivr.net/npm/3d-force-graph@1.80.1/dist/3d-force-graph.min.js',
  integrity: 'sha384-i98VDQKdpyVrtyuFn0fjUWJBLBmxnqHqOANcvYe9HLJUgT2wPixa4ZkLd7Dh3VEk',
};

/** JSON safe inside a <script> element: no `</script>`, no `<!--`, no JS line terminators. */
export const embedJson = (v) => JSON.stringify(v).replace(/</g, '\\u003c').replace(/[\u2028\u2029]/g, (c) => '\\u' + c.charCodeAt(0).toString(16));

/**
 * @param {object} r the analysis result
 * @param {{ baseline?: { file: string, fresh: string[], fixed: string[] } | null, colorway?: string }} [opts]
 */
/**
 * Shorten a path-like string to at most `max` characters by cutting from the left, keeping the end
 * (file name and :line) and marking the cut with an ellipsis. Prefers to cut at a "/" so the result
 * reads as "…/20240201000000_billing.sql:29". Pure ES5 so the page embeds it via toString().
 */
export function truncLeft(str, max) {
  var s = String(str == null ? '' : str);
  max = Math.floor(max);
  if (!(max >= 2) || s.length <= max) return s;
  var tail = s.slice(s.length - (max - 1));
  var slash = tail.indexOf('/');
  if (slash > 0 && tail.slice(slash).length >= 12) tail = tail.slice(slash);
  else if (slash === 0) tail = tail;
  return '…' + tail;
}

export function renderHtml(r, opts = {}) {
  const colorway = opts.colorway == null ? DEFAULT_COLORWAY : checkColorway(opts.colorway, 'renderHtml');
  const info = r.info || {};
  const unreadable = info.unreadable_files || [];
  const s = r.stats || {};
  const data = {
    root: r.root, generated_at: r.generated_at, source: r.source || null,
    tiers: r.tiers || null, notices: r.notices || [], stats: r.stats || null,
    coverage: {
      files: s.files_scanned, call_sites: s.call_sites, unresolved: s.unresolved, migrations: s.migrations, sql_statements: s.sql_statements,
      sql_unparsed: s.sql_unparsed, partial: unreadable.filter((f) => f.partial).length, unreadable: unreadable.filter((f) => !f.partial).length,
    },
    baseline: opts.baseline ? { file: opts.baseline.file, fresh: opts.baseline.fresh.length, fixed: opts.baseline.fixed.length } : null,
    nodes: r.nodes,
    links: r.links.map(({ source, target, relation, confidence, ops, at, count }) => ({ source, target, relation, confidence, ops: ops || [], at: (at || []).slice(0, 10), count: count || 1 })),
    findings: r.findings.map((f) => ({ rule: f.rule, id: f.id, node: f.node, tier: f.tier, level: f.level, at: f.at, note: f.note, message: f.message, roles: f.roles, usedBy: f.usedBy, securityDefiner: f.securityDefiner, sites: f.sites, confidence: f.confidence })),
    rules: r.rules.map(({ id, level, tier, title, why }) => ({ id, level, tier, title, why })),
    fg3d: FG3D,
    colorway, colorways: COLORWAYS,
  };
  return `<!doctype html>
<html lang="en" data-colorway="${colorway}" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>tracegrid: ${escapeHtml(r.root)}</title>
<style>${CSS}</style></head><body>
<div id="app">
<aside id="side">
  <header>
    <div class="brand"><span class="mark"></span><h1>TRACEGRID <span class="muted" id="rootname"></span></h1><button id="gear" class="ghost" title="Settings" aria-label="Settings" aria-haspopup="true" aria-expanded="false">&#9881;&#xFE0E;</button><button id="theme" class="ghost" title="Toggle light / dark" aria-label="Toggle light / dark">&#9680;</button>
      <div id="settings" role="dialog" aria-label="Settings" hidden>
        <label><span class="lbl">Colourway</span><select id="cw"></select></label>
        <label><span class="lbl">Mode</span><select id="mode"><option value="auto">Auto (system)</option><option value="dark">Dark</option><option value="light">Light</option></select></label>
        <label class="chk"><input type="checkbox" id="rot"> Auto-rotate 3D</label>
      </div></div>
    <nav id="tabs" role="tablist">
      <button role="tab" data-view="dash" class="on">Dashboard</button>
      <button role="tab" data-view="path">Path</button>
      <button role="tab" data-view="map">Map</button>
      <button role="tab" data-view="3d" title="Showcase mode: loads a pinned 3D library from jsDelivr">3D</button>
    </nav>
    <input id="q" type="search" placeholder="search findings and objects" autocomplete="off" spellcheck="false">
    <div id="chips"></div>
    <div id="filter" hidden></div>
  </header>
  <div id="list"></div>
</aside>
<main id="main">
  <div id="bar"><span id="crumb"></span><span class="sp"></span><button id="ov3d" class="ghost" hidden title="Back to the overview (Esc)">\u25c1 overview</button><button id="fit" class="ghost" title="Fit to view">FIT</button></div>
  <div id="stage">
    <svg id="svg" xmlns="http://www.w3.org/2000/svg"><defs>
      <marker id="ar" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" markerUnits="userSpaceOnUse" orient="auto"><path d="M0,0.5 L10,5 L0,9.5 z"/></marker>
      <marker id="ar-hi" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="8" markerHeight="8" markerUnits="userSpaceOnUse" orient="auto"><path d="M0,0.5 L10,5 L0,9.5 z"/></marker>
    </defs><g id="vp"></g></svg>
    <div id="dash"></div>
    <div id="card" hidden></div>
    <div id="three" hidden><div id="three-canvas"></div><div id="three-labels"></div><div id="three-msg" hidden></div><div id="three-crumb" hidden></div></div>
  </div>
</main>
</div>
<script type="application/json" id="data">${embedJson(data)}</script>
<script>${CLIENT}</script>
</body></html>
`;
}

function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

const CSS = String.raw`
/* ===== THEME: every colour, stroke, radius, size and font, for the 2D views and the 3D view. Swap this block to restyle. =====
   Structure (fonts, sizes, strokes) is in :root. Colour comes from the active colourway, set as data-colorway on <html>
   (default signal), in a dark and a light variant (data-theme). Severity never rests on colour alone: the
   glyphs ◆ Fix, ◇ Review and · Info always accompany it. The script reads the 3D palette from the same variables. */
:root{
--font:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
--fs:12px;--fs-small:11px;--fs-label:10px;--fs-big:30px;--track:.16em;
--radius:0;--hair:1px;--pad:10px;--grid-size:24px;--fix-w:400;
--arrow:7;--node-w:1.25;--edge-w:1.5;--edge-w-hi:2;
--box-w:200;--box-h:36;--box-gap:14;--gutter:104;--map-r:5;--map-role-r:8;--map-group-r:20;
}
/* graphite-amber (also the CSS fallback when no data-colorway is set) */
:root,:root[data-colorway=graphite-amber]{
--bg:#0a0a0b;--grid:rgba(255,255,255,.03);--panel:#111113;--panel2:#18181b;--fg:#e9e7e2;--muted:#9a978f;--line:#26262a;--line2:#3a3a40;
--node:#cfcdc7;--node-fill:#0f0f11;--edge:#7d7b76;--edge-hi:#f2f0ea;--edge-label:#a8a59d;
--fix:#e3b867;--review:#9fb0c2;--info:#9a978f;--sel:#f2f0ea;--bar:#5f5d58;--accent:#9fb0c2;--fix-w:400;
--3d-bg:#050506;--3d-node:#d8d6d0;--3d-link:#8f8d87;--3d-link-hi:#ffffff;--3d-label:#d8d6d0;--3d-star:#8f8d87;--3d-glow:.55;
}
:root[data-colorway=graphite-amber][data-theme=light]{
--bg:#f6f5f1;--grid:rgba(0,0,0,.04);--panel:#fbfaf7;--panel2:#efede7;--fg:#1a1916;--muted:#5e5b53;--line:#dcd9d0;--line2:#bcb8ac;
--node:#2a2925;--node-fill:#fbfaf7;--edge:#6d6a62;--edge-hi:#14130f;--edge-label:#55524a;
--fix:#865700;--review:#3a5877;--info:#5e5b53;--sel:#14130f;--bar:#8d897e;--accent:#3a5877;
--3d-bg:#ebe9e2;--3d-node:#2a2925;--3d-link:#6d6a62;--3d-link-hi:#14130f;--3d-label:#2a2925;--3d-star:#8d897e;--3d-glow:.2;
}
/* signal: the previous palette */
:root[data-colorway=signal]{
--bg:#050607;--grid:rgba(255,255,255,.04);--panel:#07080a;--panel2:#0f1113;--fg:#e6e8ea;--muted:#8d949b;--line:#25292d;--line2:#3c4248;
--node:#d6dade;--node-fill:#0a0b0d;--edge:#808993;--edge-hi:#f4f5f6;--edge-label:#aab1b8;
--fix:#ff3b30;--review:#ffb020;--info:#8d949b;--sel:#f4f5f6;--bar:#5f666e;--accent:#ffb020;--fix-w:400;
--3d-bg:#020203;--3d-node:#dfe3e7;--3d-link:#9aa2ab;--3d-link-hi:#ffffff;--3d-label:#d9dde1;--3d-star:#9aa2ab;--3d-glow:.55;
}
:root[data-colorway=signal][data-theme=light]{
--bg:#f6f6f4;--grid:rgba(0,0,0,.05);--panel:#fbfbfa;--panel2:#efefec;--fg:#111315;--muted:#575d63;--line:#d6d7d4;--line2:#b5b8b9;
--node:#202326;--node-fill:#fbfbfa;--edge:#6b737c;--edge-hi:#0b0c0d;--edge-label:#4a5056;
--fix:#c8001a;--review:#8f5400;--info:#575d63;--sel:#0b0c0d;--bar:#8c9298;--accent:#8f5400;
--3d-bg:#eceeee;--3d-node:#202326;--3d-link:#6b737c;--3d-link-hi:#0b0c0d;--3d-label:#202326;--3d-star:#8c9298;--3d-glow:.2;
}
/* mono: greys, Fix told apart by white and weight */
:root[data-colorway=mono]{
--bg:#0a0a0a;--grid:rgba(255,255,255,.03);--panel:#111111;--panel2:#191919;--fg:#e8e8e8;--muted:#9a9a9a;--line:#262626;--line2:#3d3d3d;
--node:#cccccc;--node-fill:#0f0f0f;--edge:#7a7a7a;--edge-hi:#ffffff;--edge-label:#a6a6a6;
--fix:#ffffff;--review:#a8a8a8;--info:#8c8c8c;--sel:#ffffff;--bar:#5c5c5c;--accent:#ffffff;--fix-w:700;
--3d-bg:#050505;--3d-node:#d0d0d0;--3d-link:#8a8a8a;--3d-link-hi:#ffffff;--3d-label:#d0d0d0;--3d-star:#8a8a8a;--3d-glow:.45;
}
:root[data-colorway=mono][data-theme=light]{
--bg:#f4f4f4;--grid:rgba(0,0,0,.04);--panel:#fafafa;--panel2:#ececec;--fg:#111111;--muted:#555555;--line:#d8d8d8;--line2:#b8b8b8;
--node:#222222;--node-fill:#fafafa;--edge:#6a6a6a;--edge-hi:#000000;--edge-label:#4d4d4d;
--fix:#000000;--review:#505050;--info:#5a5a5a;--sel:#000000;--bar:#8a8a8a;--accent:#000000;
--3d-bg:#e9e9e9;--3d-node:#222222;--3d-link:#6a6a6a;--3d-link-hi:#000000;--3d-label:#222222;--3d-star:#8a8a8a;--3d-glow:.15;
}
/* mint: graphite with a mint Fix */
:root[data-colorway=mint]{
--bg:#0a0a0b;--grid:rgba(255,255,255,.03);--panel:#111113;--panel2:#18181b;--fg:#e9e7e2;--muted:#9a978f;--line:#26262a;--line2:#3a3a40;
--node:#cfcdc7;--node-fill:#0f0f11;--edge:#7d7b76;--edge-hi:#f2f0ea;--edge-label:#a8a59d;
--fix:#72e0b0;--review:#8fa6b8;--info:#9a978f;--sel:#f2f0ea;--bar:#5f5d58;--accent:#8fa6b8;--fix-w:400;
--3d-bg:#050506;--3d-node:#d8d6d0;--3d-link:#8f8d87;--3d-link-hi:#ffffff;--3d-label:#d8d6d0;--3d-star:#8f8d87;--3d-glow:.55;
}
:root[data-colorway=mint][data-theme=light]{
--bg:#f6f5f1;--grid:rgba(0,0,0,.04);--panel:#fbfaf7;--panel2:#efede7;--fg:#1a1916;--muted:#5e5b53;--line:#dcd9d0;--line2:#bcb8ac;
--node:#2a2925;--node-fill:#fbfaf7;--edge:#6d6a62;--edge-hi:#14130f;--edge-label:#55524a;
--fix:#006a47;--review:#3a5877;--info:#5e5b53;--sel:#14130f;--bar:#8d897e;--accent:#3a5877;
--3d-bg:#ebe9e2;--3d-node:#2a2925;--3d-link:#6d6a62;--3d-link-hi:#14130f;--3d-label:#2a2925;--3d-star:#8d897e;--3d-glow:.2;
}
/* ===== end THEME ===== */
*{box-sizing:border-box;border-radius:var(--radius)}
html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);font:var(--fs)/1.4 var(--font)}
button{font:inherit;color:inherit;background:transparent;border:var(--hair) solid var(--line2);padding:2px 8px;cursor:pointer}
button:hover{border-color:var(--fg)}button.ghost{border-color:transparent}button.ghost:hover{border-color:var(--line2)}
button:focus-visible,input:focus-visible{outline:var(--hair) solid var(--sel);outline-offset:1px}
.muted{color:var(--muted)}.mono{font-family:var(--font)}
.lbl{font-size:var(--fs-label);letter-spacing:var(--track);text-transform:uppercase;color:var(--muted)}
#app{display:flex;height:100%}
#side{width:340px;min-width:280px;max-width:42vw;display:flex;flex-direction:column;background:var(--panel);border-right:var(--hair) solid var(--line)}
#side.compact #chips{display:none}.sum{display:flex;justify-content:space-between;align-items:center;width:100%;text-align:left;border:0;border-left:3px solid var(--line2);border-bottom:var(--hair) solid var(--line);padding:9px 12px;font-weight:700}.sum:hover{background:var(--panel2)}.sum.t-fix{border-left-color:var(--fix)}.sum.t-review{border-left-color:var(--review)}
#side header{padding:10px 10px 8px;border-bottom:var(--hair) solid var(--line);display:flex;flex-direction:column;gap:7px}
.brand{display:flex;align-items:center;gap:8px}.brand h1{font-size:var(--fs);letter-spacing:var(--track);font-weight:700;margin:0;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.brand h1 .muted{font-weight:400;letter-spacing:0}
.mark{width:9px;height:9px;border:var(--hair) solid var(--fg);box-shadow:3px 3px 0 -1px var(--fix)}
#tabs{display:flex;border:var(--hair) solid var(--line2)}#tabs button{flex:1;border:0;border-right:var(--hair) solid var(--line2);padding:4px 0;font-size:var(--fs-label);letter-spacing:var(--track);text-transform:uppercase;color:var(--muted)}
#tabs button:last-child{border-right:0}#tabs button.on{background:var(--fg);color:var(--bg)}
input[type=search]{width:100%;padding:5px 8px;border:var(--hair) solid var(--line2);background:var(--bg);color:var(--fg);font:inherit}
#chips{display:flex;flex-wrap:wrap;gap:4px}
.chip{font-size:var(--fs-label);letter-spacing:.08em;text-transform:uppercase;padding:1px 6px;color:var(--muted);border-color:var(--line)}.chip.on{color:var(--fg);border-color:var(--line2)}
.chip .dot{display:inline-block;margin-right:5px}
#filter[hidden]{display:none}#filter{display:flex;align-items:center;gap:6px;font-size:var(--fs-small);border:var(--hair) solid var(--fg);padding:3px 6px}#filter span{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#list{overflow:auto;flex:1;padding:0 0 16px}
.grp{position:sticky;top:0;background:var(--panel);padding:9px 10px 4px;display:flex;justify-content:space-between;z-index:1;border-bottom:var(--hair) solid var(--line)}
.item{display:block;width:100%;text-align:left;border:0;border-left:2px solid transparent;border-bottom:var(--hair) solid var(--line);padding:5px 10px 6px 9px}
.item:hover{background:var(--panel2)}.item.on{background:var(--panel2);border-left-color:var(--sel)}
.item.t-fix{border-left-color:var(--fix)}.item.t-review{border-left-color:var(--review)}.item.t-info{border-left-color:var(--line2)}
.item .r{font-size:var(--fs-label);color:var(--muted)}.item .n{font-weight:700;word-break:break-all}.item .w{color:var(--muted);font-size:var(--fs-small);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.empty{padding:9px 10px;color:var(--muted)}
#main{flex:1;display:flex;flex-direction:column;min-width:0}
#bar{display:flex;align-items:center;gap:8px;padding:6px 12px;border-bottom:var(--hair) solid var(--line);min-height:35px;font-size:var(--fs-small)}#bar .sp{flex:1}
#bar button{font-size:var(--fs-label);letter-spacing:var(--track)}
#crumb{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#stage{position:relative;flex:1;min-height:0;overflow:hidden;background-color:var(--bg);background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);background-size:var(--grid-size) var(--grid-size)}
#svg{width:100%;height:100%;display:block;cursor:grab;user-select:none}#svg.drag{cursor:grabbing}
#card{position:absolute;left:12px;top:12px;max-width:min(440px,calc(100% - 24px));max-height:calc(100% - 24px);overflow:auto;background:var(--panel);border:var(--hair) solid var(--line2);padding:9px 11px}
#card h3{margin:2px 0 4px;font-size:var(--fs);word-break:break-all}#card .why{color:var(--muted);margin:6px 0 0}#card dl{margin:6px 0 0;display:grid;grid-template-columns:auto 1fr;gap:1px 10px;font-size:var(--fs-small)}#card dt{color:var(--muted);text-transform:uppercase;letter-spacing:.08em;font-size:var(--fs-label);padding-top:1px}#card dd{margin:0;word-break:break-all}
#card .x{float:right;margin:-3px -5px 0 8px;padding:0 6px;border-color:var(--line2)}
.badge{display:inline-block;font-size:var(--fs-label);font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:0 5px;margin-right:6px;border:var(--hair) solid currentColor}
.badge.fix{color:var(--fix)}.badge.review{color:var(--review)}.badge.info{color:var(--info)}
svg text{fill:var(--fg);font:var(--fs-small) var(--font)}
svg .colh{fill:var(--muted);font-size:var(--fs-label);letter-spacing:var(--track);text-transform:uppercase}
svg .box rect.bg{fill:var(--panel);stroke:var(--line2);stroke-width:var(--hair)}svg .box.hi rect.bg{stroke:var(--sel);stroke-width:1.5}
svg .box.fix rect.bg{stroke:var(--fix);stroke-width:1.5}svg .box.review rect.bg{stroke:var(--review)}
svg .box .sub{fill:var(--muted);font-size:var(--fs-label)}svg .box{cursor:pointer}
svg .ghostbox rect{fill:none;stroke:var(--line2)}svg .ghostbox text{fill:var(--muted)}
.sym *{fill:var(--node-fill);stroke:var(--node);stroke-width:var(--node-w)}.sym .solid{fill:var(--node)}
.sym.fix *{stroke:var(--fix)}.sym.fix .solid{fill:var(--fix)}.sym.review *{stroke:var(--review)}.sym.review .solid{fill:var(--review)}
.sym.ghost *{stroke:var(--muted)}.sym.grp *{fill-opacity:.35}
path.e{fill:none;stroke:var(--edge);stroke-width:var(--edge-w)}path.e.inf{stroke-dasharray:5 4}
path.e.hi{stroke:var(--edge-hi);stroke-width:var(--edge-w-hi)}path.e.dim{opacity:.12}
#ar path{fill:var(--edge)}#ar-hi path{fill:var(--edge-hi)}
svg .elabel text{fill:var(--edge-label);font-size:var(--fs-label)}svg .elabel rect{fill:var(--bg)}svg .elabel.hi text{fill:var(--fg)}
svg .dimmed{opacity:.15}
svg .mlabel{font-size:var(--fs-label);paint-order:stroke;stroke:var(--bg);stroke-width:3px}
/* settings popover */
.brand{position:relative}
#settings{position:absolute;right:0;top:100%;margin-top:6px;z-index:20;background:var(--panel);border:var(--hair) solid var(--line2);padding:10px 12px;display:flex;flex-direction:column;gap:9px;min-width:210px}
#settings[hidden]{display:none}#settings label{display:flex;flex-direction:column;gap:3px}#settings label.chk{flex-direction:row;align-items:center;gap:7px}
#settings select{font:inherit;color:var(--fg);background:var(--bg);border:var(--hair) solid var(--line2);padding:3px 4px}
/* dashboard */
#dash{position:absolute;inset:0;overflow:auto;display:none}
.dg{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));border-bottom:var(--hair) solid var(--line)}
.pn{grid-column:span 6;border-right:var(--hair) solid var(--line);border-top:var(--hair) solid var(--line);padding:10px 12px 12px;min-width:0;background:color-mix(in srgb,var(--bg) 82%,transparent)}
.pn.w12{grid-column:span 12}
.note{font-size:var(--fs-small);color:var(--muted);margin:0 0 8px;max-width:760px}
.card>h2,.pn>h2{margin:0;font-size:var(--fs-label);font-weight:400;letter-spacing:var(--track);text-transform:uppercase;color:var(--muted);padding:9px 14px;border-bottom:var(--hair) solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:8px}
.card{border:var(--hair) solid var(--line);background:var(--panel);min-width:0}
.q{display:inline-flex;align-items:center;justify-content:center;width:17px;height:17px;border:var(--hair) solid var(--line2);color:var(--muted);font-size:var(--fs-small);letter-spacing:0;position:relative;cursor:help;margin-left:8px;text-transform:none;font-weight:400}
.q:hover,.q:focus{color:var(--accent);border-color:var(--accent);outline:none}
.q::after{content:attr(data-tip);position:absolute;top:24px;left:-8px;width:290px;background:var(--bg);border:var(--hair) solid var(--accent);color:var(--fg);padding:8px 10px;font-size:var(--fs);line-height:1.4;letter-spacing:0;text-transform:none;display:none;z-index:9;text-align:left}
.q:hover::after,.q:focus::after{display:block}.q.r::after{left:auto;right:-8px}
.strip{display:flex;flex-wrap:wrap;border-bottom:var(--hair) solid var(--line);background:var(--panel)}
.strip>div{padding:10px 20px;border-right:var(--hair) solid var(--line);display:flex;gap:12px;align-items:baseline}
.strip .big{font-size:var(--fs-big);color:var(--fg);font-weight:700;font-variant-numeric:tabular-nums;line-height:1}
.strip .fix{color:var(--fix);font-weight:var(--fix-w)}.strip .review{color:var(--review)}.strip .info{color:var(--info)}
.strip .bl b{font-size:16px}
.cols{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,1fr);gap:14px;padding:14px 18px;align-items:start}
.col{display:flex;flex-direction:column;gap:12px;min-width:0}
.todo{display:grid;grid-template-columns:30px minmax(0,1fr) auto;gap:10px;align-items:center;padding:14px 16px;border-top:var(--hair) solid var(--line);border-left:3px solid var(--fix)}
.todo .g{color:var(--fix);font-size:22px}.todo .tt{font-size:15px;font-weight:var(--fix-w)}.todo .mut{color:var(--muted);word-break:break-all}.pth{display:block;white-space:nowrap;overflow:hidden;text-overflow:clip;word-break:normal}table.t td:last-child .pth{max-width:38ch;margin-left:auto}.todo .mut .pth{margin-top:1px}.todo .ob{color:var(--fg);font-weight:700}
.todo button{border-color:var(--fix);color:var(--fix)}.todo button:hover{background:var(--fix);color:var(--bg)}
.none{padding:14px 16px;color:var(--muted);border-top:var(--hair) solid var(--line)}
details{border:var(--hair) solid var(--line);background:var(--panel)}
details>summary{list-style:none;cursor:pointer;padding:9px 14px;display:flex;align-items:center;color:var(--muted);letter-spacing:.14em;text-transform:uppercase;font-size:var(--fs-label)}
details>summary::-webkit-details-marker{display:none}
details>summary::before{content:"+";width:16px;color:var(--accent)}details[open]>summary::before{content:"\2212"}
details>summary>span:first-of-type{flex:1}details>summary em{font-style:normal;letter-spacing:0;text-transform:none}
details>summary:hover,details>summary:focus-visible{color:var(--fg)}
details .body{padding:10px 14px 14px;border-top:var(--hair) solid var(--line);overflow-x:auto}
.gr{display:flex;flex-direction:column;gap:6px}
table.t{width:100%;border-collapse:collapse;font-size:var(--fs-small)}table.t td{padding:6px 8px;border-top:var(--hair) solid var(--line);vertical-align:top}table.t tr:first-child td{border-top:0}
table.t td:last-child{color:var(--muted);text-align:right;word-break:break-all}
table.t td.gl{white-space:nowrap}.gl.fix{color:var(--fix)}.gl.review{color:var(--review)}.gl.info{color:var(--info)}
table.t button.ghost{padding:0 2px;font-weight:700;text-align:left}
table.mx{border-collapse:collapse;width:100%}
table.mx th{font-weight:400;font-size:var(--fs-label);letter-spacing:.1em;text-transform:uppercase;color:var(--muted);text-align:center;padding:8px 6px;border:var(--hair) solid var(--line)}
table.mx th.rh{text-align:left;padding-left:14px;color:var(--fg);letter-spacing:0;text-transform:none}
table.mx td{border:var(--hair) solid var(--line);text-align:center;padding:0;height:52px}
table.mx td button{display:flex;align-items:baseline;justify-content:center;gap:1px;width:100%;height:100%;border:0;padding:0 4px}
table.mx td b{font-size:20px;font-variant-numeric:tabular-nums}table.mx td small{font-size:var(--fs);color:var(--muted)}
table.mx td.hot{background:color-mix(in srgb,var(--fix) 14%,transparent)}table.mx td.hot b{color:var(--fix);text-decoration:underline}
table.mx td button:hover,table.mx td button.on{outline:var(--hair) solid var(--fg);outline-offset:-1px}
table.mx .na{color:var(--line2);display:block}
.legend{padding:8px 14px;color:var(--muted);border-top:var(--hair) solid var(--line)}.legend b{color:var(--fg)}
.cov{display:grid;grid-template-columns:repeat(4,minmax(0,1fr))}.cov div{padding:10px 14px;border-right:var(--hair) solid var(--line)}.cov div:last-child{border-right:0}
.cov b{display:block;font-size:24px;font-variant-numeric:tabular-nums}.cov .warn b{color:var(--fix)}.cov .warn .lbl::after{content:" \25b2"}
.bar{display:grid;grid-template-columns:minmax(120px,290px) minmax(0,1fr) 34px;gap:12px;align-items:center;padding:3px 0}
.bar .k{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-align:left;border:0;padding:0}.bar .k:hover:not(:disabled){text-decoration:underline}.bar .k:disabled{cursor:default;opacity:1}
.bar .t{display:flex;height:6px;background:var(--line)}.bar .t span{display:block;height:100%}.bar .n{text-align:right;font-variant-numeric:tabular-nums;color:var(--muted)}
.mono-s{color:var(--fg);text-align:left!important}
/* 3D */
#three{position:absolute;inset:0;background:var(--3d-bg)}#three-canvas{position:absolute;inset:0}
#three-labels{position:absolute;inset:0;pointer-events:none;overflow:hidden;z-index:2}
#three-crumb{position:absolute;left:12px;top:10px;z-index:2;font:var(--fs-small) var(--font);color:var(--3d-label);background:var(--3d-bg);border:var(--hair) solid var(--line2);padding:3px 8px;max-width:70%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}#three-crumb a{cursor:pointer;text-decoration:underline}
#three-labels div{position:absolute;left:0;top:0;will-change:transform;visibility:hidden;font:var(--fs-label) var(--font);color:var(--3d-label);white-space:nowrap;text-shadow:0 0 6px var(--3d-bg),0 0 2px var(--3d-bg);opacity:.9}
#three-labels div.fix{color:var(--fix)}#three-labels div.review{color:var(--review)}
#three-msg{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);color:var(--3d-label);background:var(--3d-bg);border:var(--hair) solid var(--line2);padding:12px 16px;z-index:3;max-width:80%;text-align:center}
.scene-tooltip .tip{font:var(--fs-small) var(--font);color:var(--3d-label);background:var(--3d-bg);border:var(--hair) solid var(--line2);padding:3px 8px}
.scene-tooltip .tip span{color:var(--muted);margin-left:6px}
@media (max-width:1100px){.pn{grid-column:span 12}.cols{grid-template-columns:minmax(0,1fr)}}
@media (max-width:760px){#app{flex-direction:column}#side{width:100%;max-width:none;height:46%;border-right:0;border-bottom:var(--hair) solid var(--line)}#main{min-height:0}}
`;

// The client script avoids backticks and `${` (it lives inside a template literal) and never puts
// data into innerHTML except through esc().
const CLIENT = String.raw`
(function(){
"use strict";
var D=JSON.parse(document.getElementById('data').textContent);
var SVGNS='http://www.w3.org/2000/svg';
${truncLeft.toString()}
var esc=function(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})};
function h(tag,attrs){var el=document.createElement(tag);if(attrs)for(var k in attrs){if(k==='text')el.textContent=attrs[k];else if(k==='cls')el.className=attrs[k];else el.setAttribute(k,attrs[k])}for(var i=2;i<arguments.length;i++){var c=arguments[i];if(c==null)continue;el.appendChild(typeof c==='string'?document.createTextNode(c):c)}return el}
function s(tag,attrs){var el=document.createElementNS(SVGNS,tag);if(attrs)for(var k in attrs){if(k==='text')el.textContent=attrs[k];else el.setAttribute(k,attrs[k])}return el}
var $=function(id){return document.getElementById(id)};
$('rootname').textContent=D.root;
var cssVar=function(n){return getComputedStyle(document.documentElement).getPropertyValue(n).trim()};
var cssNum=function(n,d){var v=parseFloat(cssVar(n));return isNaN(v)?d:v};

/* ---------- model ---------- */
var byId=new Map(),inc=new Map(),out=new Map();
D.nodes.forEach(function(n){byId.set(n.id,n);inc.set(n.id,[]);out.set(n.id,[])});
D.links.forEach(function(e){if(!byId.has(e.source)||!byId.has(e.target))return;out.get(e.source).push(e);inc.get(e.target).push(e)});
var rules=new Map(D.rules.map(function(r){return[r.id,r]}));
var TIER_OF={error:'fix',warning:'review',note:'info'};
D.findings.forEach(function(f){if(!f.tier)f.tier=TIER_OF[f.level]||'review'});
var byNode=new Map();D.findings.forEach(function(f){if(!f.node)return;if(!byNode.has(f.node))byNode.set(f.node,[]);byNode.get(f.node).push(f)});
var RANK={fix:0,review:1,info:2};
/* Severity is never colour alone: a glyph always goes with it. */
var GLY={fix:'\u25c6',review:'\u25c7',info:'\u00b7'};
var worst=function(id){var fs=byNode.get(id);if(!fs)return null;return fs.slice().sort(function(a,b){return RANK[a.tier]-RANK[b.tier]})[0].tier};
var COLNAME=['Code','Entry points','Database','Roles'];
var COL={file:0,folder:0,nocaller:0,edge_function:1,bucket:1,external:1,api:1,table:2,view:2,'function':2,cron:2,policy:2,group:2,role:3,more:-1};
var KINDNAME={api:'Data API',file:'file',folder:'folder',edge_function:'edge function',bucket:'storage bucket',external:'external caller',table:'table',view:'view','function':'function',cron:'cron / SQL',policy:'policies',role:'role',nocaller:'',group:'group'};
var folderOf=function(l){var p=String(l).split('/');return p.length>2?p.slice(0,2).join('/'):p.length>1?p[0]:'(root)'};
var short=function(x,n){x=String(x);return x.length>n?x.slice(0,n-1)+'\u2026':x};
var shortPath=function(x,n){x=String(x);return x.length>n?'\u2026'+x.slice(-(n-1)):x};
var bare=function(l){return String(l).split('.').pop()};
/* Relations a code or outside caller uses; SQL-internal references (sql-call, policy-uses...) and service-role calls do not count as callers. */
var CALLREL=/^(rpc|from|from-weak|invoke|storage|entry-point|auth-hook|http|webhook|cron)$/;
var callers=function(id){return (inc.get(id)||[]).filter(function(e){return CALLREL.test(e.relation)})};
var WRITE=/^(insert|update|delete|upsert|upload|remove|move|copy|update_bucket)$/;
/* One word per relation for edge labels: calls, invokes, reads, writes, EXECUTE, policy uses, triggers. */
function relLabel(rel,ops){rel=String(rel||'');var svc=/-service$/.test(rel);var b=rel.replace(/-service$/,'');var t;ops=ops||[];
  if(/^(rpc|sql-call|cron|default-uses|index-uses|dynamic-sql|auth-hook)$/.test(b))t='calls';
  else if(/^(invoke|http|entry-point)$/.test(b))t='invokes';
  else if(/^(from|from-weak|storage|view-uses)$/.test(b)){var w=ops.some(function(o){return WRITE.test(o)}),r=!ops.length||ops.some(function(o){return !WRITE.test(o)});t=w&&r?'reads, writes':w?'writes':'reads'}
  else if(/policy-uses$/.test(b))t='policy uses';
  else if(b==='trigger'||b==='webhook')t='triggers';
  else if(b==='can execute')t='EXECUTE';
  else if(b.indexOf('privileges: ')===0)t=b.slice(12).toUpperCase();
  else if(b==='policies')t='RLS';
  else if(b==='none')t='no caller';
  else t=b;
  return t+(svc?' (service)':'')}

/* ---------- schematic symbols: the node kind is the shape, not the colour ---------- */
function sym(t,r,cls){var g=s('g',{'class':'sym'+(cls?' '+cls:'')});var R=r*1.35,e;
  if(t==='table'||t==='view'||t==='policy'||t==='api'){g.appendChild(s('rect',{x:-r,y:-r,width:2*r,height:2*r}));
    if(t==='view')g.appendChild(s('line',{x1:-r,y1:0,x2:r,y2:0}));if(t==='policy')g.appendChild(s('line',{x1:-r,y1:r,x2:r,y2:-r}));if(t==='api')g.appendChild(s('rect',{x:-r*0.35,y:-r*0.35,width:r*0.7,height:r*0.7,'class':'solid'}))}
  else if(t==='function')g.appendChild(s('path',{d:'M0,'+(-R)+' L'+R+',0 L0,'+R+' L'+(-R)+',0 Z'}));
  else if(t==='edge_function')g.appendChild(s('path',{d:'M0,'+(-R)+' L'+(R*0.95)+','+(R*0.7)+' L'+(-R*0.95)+','+(R*0.7)+' Z'}));
  else if(t==='external')g.appendChild(s('path',{d:'M'+(R*0.8)+',0 L'+(-R*0.6)+','+(-R*0.85)+' L'+(-R*0.6)+','+(R*0.85)+' Z'}));
  else if(t==='bucket'){var p=[];for(var i=0;i<6;i++){var a=Math.PI/3*i;p.push((R*Math.cos(a)).toFixed(2)+','+(R*Math.sin(a)).toFixed(2))}g.appendChild(s('path',{d:'M'+p.join(' L')+' Z'}))}
  else if(t==='role')g.appendChild(s('circle',{r:r,'class':'solid'}));
  else{g.appendChild(s('circle',{r:r}));
    if(t==='folder')g.appendChild(s('circle',{r:r*0.45}));
    if(t==='cron')g.appendChild(s('line',{x1:0,y1:0,x2:0,y2:-r*0.75}));
    if(t==='nocaller'){e=r*0.6;g.appendChild(s('line',{x1:-e,y1:-e,x2:e,y2:e}));g.appendChild(s('line',{x1:-e,y1:e,x2:e,y2:-e}))}}
  return g}

/* ---------- state ---------- */
var state={view:'dash',sel:null,node:null,q:'',tiers:{fix:true,review:true,info:true},kinds:{functions:true,tables:true,edge:true,other:true},expanded:new Set(),mapSel:null,filter:null};
var kindOfFinding=function(f){var n=f.node&&byId.get(f.node);var t=n?n.type:'';return t==='function'?'functions':t==='table'||t==='view'?'tables':t==='edge_function'?'edge':'other'};

/* ---------- sidebar ---------- */
var chips=$('chips');
function chip(label,on,cls,onClick){var b=h('button',{cls:'chip'+(on?' on':''),type:'button'});if(cls)b.appendChild(h('span',{cls:'dot',style:'color:var('+cls[0]+')',text:cls[1]}));b.appendChild(document.createTextNode(label));b.addEventListener('click',onClick);return b}
function renderChips(){chips.textContent='';
  [['fix','Fix',['--fix',GLY.fix]],['review','Review',['--review',GLY.review]],['info','Info',['--info',GLY.info]]].forEach(function(t){chips.appendChild(chip(t[1],state.tiers[t[0]],t[2],function(){state.tiers[t[0]]=!state.tiers[t[0]];renderChips();renderList()}))});
  [['functions','Functions'],['tables','Tables'],['edge','Edge'],['other','Other']].forEach(function(k){chips.appendChild(chip(k[1],state.kinds[k[0]],null,function(){state.kinds[k[0]]=!state.kinds[k[0]];renderChips();renderList()}))})}
function renderFilter(){var el=$('filter');el.textContent='';if(!state.filter){el.hidden=true;return}el.hidden=false;
  el.appendChild(h('span',{text:'FILTER \u00b7 '+state.filter.label}));var x=h('button',{type:'button',title:'Clear filter'},'\u00d7');x.addEventListener('click',function(){setFilter(null)});el.appendChild(x)}
function setFilter(f){state.filter=f;renderFilter();renderList();if(state.view==='dash'){drawDash();fitAll()}}
var list=$('list');
var matchQ=function(f,q){if(!q)return true;return [f.rule,f.id,f.at,f.note,f.message].some(function(x){return x&&String(x).toLowerCase().indexOf(q)>=0})};
var whyOf=function(f){var r=rules.get(f.rule);return f.note||f.message||(r?r.title:'')};
function renderList(){list.textContent='';var q=state.q;var flt=state.filter;
  $('side').classList.toggle('compact',state.view==='dash');
  if(state.view==='dash'&&D.nodes.length){
    /* Dashboard tab: three summary rows; the to-do column already lists the findings. */
    [['fix','Fix'],['review','Review'],['info','Info']].forEach(function(x){
      var n=D.findings.filter(function(f){return f.tier===x[0]&&matchQ(f,q)&&(!flt||(f.node&&flt.ids.has(f.node)))}).length;
      var b=h('button',{type:'button',cls:'sum t-'+x[0],title:'Show '+x[1]+' findings on the Path tab'},h('span',{text:GLY[x[0]]+' '+x[1]}),h('span',{text:String(n)}));
      b.addEventListener('click',function(){state.tiers={fix:false,review:false,info:false};state.tiers[x[0]]=true;renderChips();setView('path')});
      list.appendChild(b)});
    return}
  ['fix','review','info'].forEach(function(t){
    var all=D.findings.filter(function(f){return f.tier===t});
    var items=all.filter(function(f){return state.tiers[t]&&state.kinds[kindOfFinding(f)]&&matchQ(f,q)&&(!flt||(f.node&&flt.ids.has(f.node)))});
    var g=h('div',{cls:'grp lbl'},h('span',{text:GLY[t]+' '+(t==='fix'?'Fix':t==='review'?'Review':'Info')}),h('span',{text:(items.length!==all.length?items.length+' / ':'')+all.length}));
    list.appendChild(g);
    if(!items.length){list.appendChild(h('div',{cls:'empty',text:all.length?'Hidden by filters.':'Nothing in this tier.'}));return}
    items.slice(0,600).forEach(function(f){
      var b=h('button',{cls:'item t-'+t+(state.sel===f?' on':''),type:'button'},h('div',{cls:'r',text:GLY[t]+' '+f.rule}),h('div',{cls:'n',text:f.id}),h('div',{cls:'w',text:whyOf(f)}));
      b.addEventListener('click',function(){selectFinding(f)});list.appendChild(b)});
    if(items.length>600)list.appendChild(h('div',{cls:'empty',text:(items.length-600)+' more: narrow the search.'}));
  });
  var objs=null;
  if(flt)objs=[...flt.ids].map(function(id){return byId.get(id)}).filter(Boolean).filter(function(n){return !q||String(n.label).toLowerCase().indexOf(q)>=0});
  else if(q.length>=2)objs=D.nodes.filter(function(n){return String(n.label).toLowerCase().indexOf(q)>=0});
  if(objs){var shown=objs.slice(0,flt?200:30);
    list.appendChild(h('div',{cls:'grp lbl'},h('span',{text:flt?'Objects in this cell':'Objects'}),h('span',{text:String(objs.length)})));
    if(!objs.length)list.appendChild(h('div',{cls:'empty',text:'No object matches.'}));
    shown.forEach(function(n){var cc=callers(n.id).length;var b=h('button',{cls:'item'+(state.node===n.id&&!state.sel?' on':''),type:'button'},h('div',{cls:'r',text:(KINDNAME[n.type]||n.type)+(cc?'':' \u00b7 no caller in code')}),h('div',{cls:'n',text:n.label}));b.addEventListener('click',function(){selectNode(n.id)});list.appendChild(b)})}
  if(!D.nodes.length){list.textContent='';list.appendChild(h('div',{cls:'empty',text:'The graph is empty: no code call sites and no schema objects were found. Check the warnings printed by the CLI (0 files scanned, 0 migrations) and set include / supabaseDir in tracegrid.config.json.'}))}
}
$('q').addEventListener('input',function(ev){state.q=ev.target.value.trim().toLowerCase();renderList()});
$('q').addEventListener('keydown',function(ev){if(ev.key==='Enter'){var f=D.findings.find(function(x){return state.tiers[x.tier]&&matchQ(x,state.q)});if(f)selectFinding(f)}if(ev.key==='Escape'){ev.target.value='';state.q='';renderList()}});

function selectFinding(f){state.sel=f;state.node=f.node||null;renderList();renderCard();if(state.view==='dash'){setView('path');return}if(state.view==='3d')fly3d(f.node);else{if(state.view==='map'){state.mapSel=f.node;}draw()}}
function selectNode(id){state.sel=null;state.node=id;renderList();renderCard();if(state.view==='dash'){setView('path');return}if(state.view==='3d')fly3d(id);else draw()}
function clearSel(){state.sel=null;state.node=null;state.mapSel=null;renderList();renderCard();if(state.view==='3d')reset3d();else draw()}

/* ---------- detail card ---------- */
var card=$('card');
function row(dl,k,v){if(v==null||v===''||(Array.isArray(v)&&!v.length))return;dl.appendChild(h('dt',{text:k}));dl.appendChild(h('dd',{text:Array.isArray(v)?v.join(', '):String(v)}))}
function renderCard(){card.textContent='';var f=state.sel,n=state.node&&byId.get(state.node);if((!f&&!n)||state.view==='dash'){card.hidden=true;return}card.hidden=false;
  var x=h('button',{cls:'x',type:'button',title:'Close'},'\u00d7');x.addEventListener('click',clearSel);card.appendChild(x);
  if(f){var r=rules.get(f.rule)||{};card.appendChild(h('div',null,h('span',{cls:'badge '+f.tier,text:GLY[f.tier]+' '+f.tier}),h('span',{cls:'muted',text:f.rule})));
    card.appendChild(h('h3',{text:f.id}));var dl=h('dl');row(dl,'Where',f.at);row(dl,'Callable by',f.roles);row(dl,'Used by',f.usedBy);if(f.securityDefiner)row(dl,'Runs as','owner (SECURITY DEFINER)');row(dl,'Call sites',f.sites);row(dl,'Confidence',f.confidence);row(dl,'Note',f.note||f.message);card.appendChild(dl);
    if(r.title)card.appendChild(h('p',{cls:'why'},h('strong',{text:r.title+'. '}),document.createTextNode(String(r.why||'').replace(/\x60/g,''))))}
  else{card.appendChild(h('div',null,h('span',{cls:'lbl',text:KINDNAME[n.type]||n.type})));card.appendChild(h('h3',{text:n.label}));var dl2=h('dl');row(dl2,'Where',n.at);
    ['rls','policies','securityDefiner','anon','authenticated','returns','verifyJwt','entryPoint','schedule','securityInvoker','defaultGrants'].forEach(function(a){if(n[a]!==undefined&&n[a]!==null)row(dl2,a,String(n[a]))});
    row(dl2,'Callers',String((inc.get(n.id)||[]).length));row(dl2,'Uses',String((out.get(n.id)||[]).length));card.appendChild(dl2);
    var fs=byNode.get(n.id)||[];fs.forEach(function(ff){var b=h('button',{type:'button',cls:'ghost'},h('span',{cls:'badge '+ff.tier,text:GLY[ff.tier]+' '+ff.tier}),document.createTextNode(ff.rule));b.style.marginTop='6px';b.addEventListener('click',function(){selectFinding(ff)});card.appendChild(h('div',null,b))})}
}

/* ---------- path view: a finding's neighbourhood in columns ---------- */
var MAXN=25;
function exposedOf(n){return n.type==='function'?(n.anon||n.authenticated):(n.type==='table'||n.type==='view')&&(!Array.isArray(n.clientPrivs)||n.clientPrivs.length>0)}
function neighbourhood(id,f){
  var V=new Map(),E=[],over=[0,0,0,0];
  var add=function(v){if(V.has(v.id))return true;if(V.size>=MAXN){var c=COL[v.type];if(c>=0)over[c]++;return false}V.set(v.id,v);return true};
  var real=function(nid){var n=byId.get(nid);return n?{id:n.id,type:n.type,label:n.label,n:n}:null};
  var c=real(id);if(!c)return null;add(c);
  var n=c.n;var ins=(inc.get(id)||[]).slice(),outs=(out.get(id)||[]).slice();
  var pri=function(e){return /^(rpc|from|invoke|storage)/.test(e.relation)?0:/policy/.test(e.relation)?1:2};
  ins.sort(function(a,b){return pri(a)-pri(b)});
  var files=ins.filter(function(e){var s=byId.get(e.source);return s&&s.type==='file'});
  var foldered=files.length>8;
  var ncallers=0;
  /* The Data API doorway: /rpc/<fn> for functions anon/authenticated can execute, /<table> for client-read tables. */
  var apiId=null;var viaApi=function(rel){return /^(rpc|from)/.test(rel)};
  if(exposedOf(n)&&!n.missing){var ops=[];ins.forEach(function(e){if(viaApi(e.relation))(e.ops||[]).forEach(function(o){ops.push(o)})});
    apiId='api:'+id;add({id:apiId,type:'api',label:(n.type==='function'?'/rpc/':'/')+bare(n.label),sub:'Data API (PostgREST)'});E.push({s:apiId,t:id,rel:n.type==='function'?'rpc':'from',ops:ops,conf:'extracted'})}
  var link=function(src,e){var to=apiId&&viaApi(e.relation)?apiId:id;E.push({s:src,t:to,rel:e.relation,ops:e.ops,conf:e.confidence,at:e.at})};
  ins.forEach(function(e){var sN=byId.get(e.source);if(!sN)return;ncallers++;
    if(foldered&&sN.type==='file'){var fid='folder:'+folderOf(sN.label);if(add({id:fid,type:'folder',label:folderOf(sN.label)+'/'}))link(fid,e);return}
    if(add({id:sN.id,type:sN.type,label:sN.label,n:sN}))link(sN.id,e)});
  outs.slice(0,10).forEach(function(e){var tN=byId.get(e.target);if(!tN)return;if(add({id:tN.id,type:tN.type,label:tN.label,n:tN}))E.push({s:id,t:tN.id,rel:e.relation,ops:e.ops,conf:e.confidence,at:e.at})});
  var roles=[];
  if(n.type==='function'){if(n.anon)roles.push('anon');if(n.authenticated)roles.push('authenticated')}
  if((n.type==='table'||n.type==='view')&&Array.isArray(n.clientPrivs)&&n.clientPrivs.length){if(n.privsByRole){['anon','authenticated'].forEach(function(r){if((n.privsByRole[r]||[]).length)roles.push(r)})}else roles.push('anon / authenticated')}
  if(f&&f.roles&&f.roles.length&&!roles.length)roles=f.roles.slice();
  roles.forEach(function(r){var rid='role:'+r;var pr=n.privsByRole&&n.privsByRole[r]?n.privsByRole[r]:(n.clientPrivs||[]);
    if(add({id:rid,type:'role',label:r,sub:n.type==='function'?'EXECUTE':pr.join(', ').toUpperCase()}))E.push({s:rid,t:id,rel:n.type==='function'?'can execute':'privileges: '+pr.join(', '),conf:'extracted'})});
  if(n.type==='table'){var pid='policy:'+id;if(add({id:pid,type:'policy',label:(n.policies||0)+' polic'+(n.policies===1?'y':'ies'),sub:n.rls?'RLS on':'RLS off'}))E.push({s:id,t:pid,rel:'policies',conf:'extracted'})}
  var codeCallers=ins.filter(function(e){var sN=byId.get(e.source);return sN&&(sN.type==='file'||sN.type==='edge_function'||sN.type==='external'||sN.type==='cron')}).length;
  if(!ncallers||(f&&/uncalled/.test(f.rule)&&!codeCallers)){var nid='none:'+id;add({id:nid,type:'nocaller',label:'no caller in code',ghost:true});E.push({s:nid,t:apiId||id,rel:'none',conf:'ambiguous',ghost:true})}
  over.forEach(function(k,ci){if(k){var mid='more:'+ci;V.set(mid,{id:mid,type:'more',col:ci,label:'+'+k+' more',ghost:true})}});
  return{V:V,E:E,center:id};
}

/* ---------- SVG plumbing: pan / zoom ---------- */
var svg=$('svg'),vp=$('vp');var T={x:0,y:0,k:1};
var applyT=function(){vp.setAttribute('transform','translate('+T.x+','+T.y+') scale('+T.k+')')};
var dragging=null,moved=false;
svg.addEventListener('pointerdown',function(ev){if(ev.button!==0)return;dragging={x:ev.clientX-T.x,y:ev.clientY-T.y};moved=false;svg.classList.add('drag')});
window.addEventListener('pointermove',function(ev){if(!dragging)return;var nx=ev.clientX-dragging.x,ny=ev.clientY-dragging.y;if(Math.abs(nx-T.x)+Math.abs(ny-T.y)>2)moved=true;T.x=nx;T.y=ny;applyT()});
window.addEventListener('pointerup',function(){dragging=null;svg.classList.remove('drag')});
svg.addEventListener('wheel',function(ev){ev.preventDefault();var b=svg.getBoundingClientRect();var mx=ev.clientX-b.left,my=ev.clientY-b.top;var f=Math.exp(-ev.deltaY*0.0015);var k=Math.min(4,Math.max(0.15,T.k*f));f=k/T.k;T.x=mx-(mx-T.x)*f;T.y=my-(my-T.y)*f;T.k=k;applyT()},{passive:false});
var bounds=null;
function fit(){if(!bounds)return;var W=svg.clientWidth,H=svg.clientHeight;var top=0;
  /* Keep the drawing clear of the detail card when there is room below it. */
  if(!card.hidden){var ch=card.offsetHeight+24;if(H-ch>Math.min(bounds.h*0.8,H*0.45))top=ch}
  var k=Math.min(1.25,Math.min((W-40)/Math.max(1,bounds.w),(H-top-40)/Math.max(1,bounds.h)));T.k=k;T.x=(W-bounds.w*k)/2-bounds.x*k;T.y=top+(H-top-bounds.h*k)/2-bounds.y*k;applyT()}
$('ov3d').addEventListener('click',overview3d);
document.addEventListener('keydown',function(ev){if(ev.key!=='Escape'||state.view!=='3d')return;var t=ev.target;if(t&&(t.tagName==='INPUT'||t.tagName==='TEXTAREA'))return;overview3d()});
$('fit').addEventListener('click',function(){if(state.view==='3d')reset3d();else fit()});
window.addEventListener('resize',function(){if(state.view==='path'||state.view==='map')fit()});
var onBox=function(el,fn){el.addEventListener('click',function(ev){if(moved)return;ev.stopPropagation();fn()})};
svg.addEventListener('click',function(){if(!moved&&state.view==='map'&&state.mapSel){state.mapSel=null;draw()}});
function syncMarkers(){var a=cssNum('--arrow',7);$('ar').setAttribute('markerWidth',a);$('ar').setAttribute('markerHeight',a);$('ar-hi').setAttribute('markerWidth',a+1);$('ar-hi').setAttribute('markerHeight',a+1)}

function textW(t,px){return String(t).length*(px||11)*0.6}
/* A cubic segment from the current point (no M), horizontal tangents at both ends. */
function cseg(x1,y1,x2,y2){var dx=Math.max(24,Math.abs(x2-x1)*0.45);if(x2<x1)dx=-dx;return' C'+(x1+dx)+','+y1+' '+(x2-dx)+','+y2+' '+x2+','+y2}
/*
 * Route an edge between two columns without passing under the objects in the columns it crosses:
 * for each skipped column, cross at the free y (a gap between stacked objects, or above / below
 * the stack) nearest to the straight line. slots(ci) lists [y0,y1] of the occupied spans per column;
 * xspan(ci) is the [left,right] extent of the column's objects. Returns { d, lx, ly } (label point).
 */
function route(a,b,ca,cb,slots,xspan,pad){
  if(ca===cb){var lx=Math.max(a.x1,b.x1);var d='M'+a.x1+','+a.y+' C'+(lx+40)+','+a.y+' '+(lx+40)+','+b.y+' '+b.x1+','+b.y;return{d:d,lx:lx+30,ly:(a.y+b.y)/2}}
  var dir=cb>ca?1:-1;var px=dir>0?a.x1:a.x0,py=a.y,ex=dir>0?b.x0:b.x1,ey=b.y;var d2='M'+px+','+py;var first=null;
  for(var c=ca+dir;c!==cb;c+=dir){var sp=xspan(c);if(!sp)continue;var inX=dir>0?sp[0]-pad:sp[1]+pad,outX=dir>0?sp[1]+pad:sp[0]-pad;
    var t=(inX-px)/((ex-px)||1);var want=py+(ey-py)*Math.max(0,Math.min(1,t));var yf=freeY(slots(c),want,pad);
    d2+=cseg(px,py,inX,yf)+' L'+outX+','+yf;if(!first)first={x:(px+inX)/2,y:(py+yf)/2};px=outX;py=yf}
  d2+=cseg(px,py,ex,ey);if(!first)first={x:(px+ex)/2,y:(py+ey)/2};return{d:d2,lx:first.x,ly:first.y}}
function freeY(sl,want,pad){if(!sl||!sl.length)return want;var c=[sl[0][0]-pad];for(var i=0;i<sl.length-1;i++)c.push((sl[i][1]+sl[i+1][0])/2);c.push(sl[sl.length-1][1]+pad);
  var best=c[0];c.forEach(function(y){if(Math.abs(y-want)<Math.abs(best-want))best=y});
  /* inside a free stretch above or below the stack, keep the straight line */
  if(want<sl[0][0]-pad||want>sl[sl.length-1][1]+pad)return want;return best}
/* Edge labels: small mono text on a background chip, nudged vertically so they never overlap. */
function placeLabel(lg,placed,x,y,text,hi){var w=textW(text,cssNum('--fs-label',10))+6,hh=12;var tries=[0,13,-13,26,-26,39,-39,52,-52];
  for(var i=0;i<tries.length;i++){var yy=y+tries[i];var bx={x0:x-w/2,x1:x+w/2,y0:yy-hh/2,y1:yy+hh/2};if(!placed.some(function(p){return bx.x0<p.x1&&bx.x1>p.x0&&bx.y0<p.y1&&bx.y1>p.y0})){placed.push(bx);
    var g=s('g',{'class':'elabel'+(hi?' hi':''),transform:'translate('+x+','+yy+')'});g.appendChild(s('rect',{x:-w/2,y:-hh/2,width:w,height:hh}));g.appendChild(s('text',{x:0,y:3.5,'text-anchor':'middle',text:text}));lg.appendChild(g);return}}}

/* path view layout: four columns, stacked boxes (no overlap by construction), edges routed through the gutters */
function drawPath(){vp.textContent='';var id=state.node;var nb=neighbourhood(id,state.sel);if(!nb){emptyPath();return}
  $('dash').style.display='none';svg.style.display='block';syncMarkers();
  var W=Math.max(1200,svg.clientWidth);var colW=W/4;var gut=cssNum('--gutter',104);var boxW=Math.min(cssNum('--box-w',200),colW-gut);var boxH=cssNum('--box-h',36);var rowH=boxH+cssNum('--box-gap',14),top=56;
  var cols=[[],[],[],[]];nb.V.forEach(function(v){var c=v.type==='more'?v.col:COL[v.type];if(c==null||c<0)c=2;v.c=c;cols[c].push(v)});
  cols.forEach(function(arr){arr.sort(function(a,b){if(a.id===id)return -1;if(b.id===id)return 1;if(a.type==='more')return 1;if(b.type==='more')return -1;return String(a.label).localeCompare(String(b.label))})});
  var maxRows=Math.max.apply(null,cols.map(function(a){return a.length}).concat([1]));
  var H=top+maxRows*rowH+20;var pos=new Map();
  cols.forEach(function(arr,ci){var x=ci*colW+(colW-boxW)/2;var y0=top+(maxRows-arr.length)*rowH/2;
    vp.appendChild(s('text',{x:ci*colW+colW/2,y:28,'text-anchor':'middle','class':'colh',text:COLNAME[ci]}));
    arr.forEach(function(v,i){pos.set(v.id,{x:x,y:y0+i*rowH,w:boxW,h:boxH,c:ci})})});
  vp.insertBefore(s('line',{x1:0,y1:38,x2:W,y2:38,stroke:'var(--line)'}),vp.firstChild);
  var slots=function(ci){return cols[ci].map(function(v){var p=pos.get(v.id);return[p.y,p.y+p.h]})};
  var xspan=function(ci){if(!cols[ci].length)return null;var x=ci*colW+(colW-boxW)/2;return[x,x+boxW]};
  var eg=s('g'),lg=s('g');vp.appendChild(eg);vp.appendChild(lg);var placed=[];
  nb.E.forEach(function(e){var a=pos.get(e.s),b=pos.get(e.t);if(!a||!b)return;
    var A={x0:a.x,x1:a.x+a.w,y:a.y+a.h/2},B={x0:b.x,x1:b.x+b.w,y:b.y+b.h/2};var rt=route(A,B,a.c,b.c,slots,xspan,7);
    var hi=e.s===id||e.t===id||(e.t&&e.t.indexOf('api:')===0);var dashed=e.conf==='inferred'||e.conf==='ambiguous';
    var el=s('path',{d:rt.d,'class':'e'+(dashed?' inf':'')+(hi?' hi':''),'marker-end':'url(#'+(hi?'ar-hi':'ar')+')'});
    var lab=relLabel(e.rel,e.ops);
    el.appendChild(s('title',{text:lab+(e.at&&e.at.length?' \u2014 '+e.at.slice(0,3).join(', '):'')}));eg.appendChild(el);placeLabel(lg,placed,rt.lx,rt.ly,lab,hi)});
  nb.V.forEach(function(v){var p=pos.get(v.id);if(!p)return;var t=v.id===id?(state.sel?state.sel.tier:worst(v.id)):worst(v.id);
    var g=s('g',{'class':(v.ghost?'ghostbox':'box')+(v.id===id?' hi':'')+(t==='fix'?' fix':t==='review'?' review':''),transform:'translate('+p.x+','+p.y+')'});
    g.appendChild(s('rect',{'class':'bg',width:p.w,height:p.h}));
    var sg=sym(v.type==='more'?'file':v.type,5,v.ghost?'ghost':t==='fix'?'fix':t==='review'?'review':'');sg.setAttribute('transform','translate(14,'+(p.h/2)+')');g.appendChild(sg);
    var maxC=Math.floor((p.w-34)/(cssNum('--fs',12)*0.55));var label=v.type==='file'||v.type==='folder'?shortPath(v.label,maxC):short(v.label,maxC);
    g.appendChild(s('text',{x:27,y:v.ghost||!(KINDNAME[v.type]||v.sub)?p.h/2+4:15,text:label}));
    if(!v.ghost){var sub=v.sub||KINDNAME[v.type]||'';if(t)sub+=(sub?' \u00b7 ':'')+t;g.appendChild(s('text',{x:27,y:28,'class':'sub',text:short(sub,maxC+4)}))}
    g.appendChild(s('title',{text:v.label}));
    if(!v.ghost&&byId.has(v.id)&&v.id!==id)onBox(g,function(){selectNode(v.id)});
    vp.appendChild(g)});
  bounds={x:0,y:0,w:W,h:H};fit();
  var n=byId.get(id);$('crumb').textContent='';$('crumb').appendChild(h('span',{cls:'lbl',text:'Path \u00b7 '}));$('crumb').appendChild(document.createTextNode(n?n.label:id));
}
function emptyPath(){svg.style.display='none';var o=$('dash');o.style.display='block';o.textContent='';
  $('crumb').textContent='';$('crumb').appendChild(h('span',{cls:'lbl',text:'Path'}));
  var p=h('div',{cls:'dg'},h('div',{cls:'pn w12'},h('h2',null,h('span',{text:'Nothing selected'})),h('p',{cls:'note',text:'Pick a finding on the left, or a hole on the dashboard, to see its path: the code that reaches it (or that nothing does), the entry point, the database object and the roles that can call it.'})));o.appendChild(p)}

/* ---------- full map: same columns, folders and schema+kind groups collapsed ---------- */
function mapModel(){var rep=new Map(),V=new Map();
  var groupOf=function(n){if(n.type==='file')return{id:'folder:'+folderOf(n.label),type:'folder',label:folderOf(n.label)+'/'};
    if(n.type==='table'||n.type==='view'||n.type==='function'||n.type==='cron'){var sc=n.schema||(String(n.label).indexOf('.')>0?String(n.label).split('.')[0]:'public');var key='grp:'+sc+':'+n.type;return{id:key,type:'group',kind:n.type,label:sc+' \u00b7 '+(n.type==='function'?'functions':n.type==='cron'?'cron / SQL':n.type+'s')}}return null};
  D.nodes.forEach(function(n){var g=groupOf(n);var v;
    if(g&&!state.expanded.has(g.id)){v=V.get(g.id);if(!v){v=Object.assign({members:0,fix:0,review:0},g);V.set(g.id,v)}v.members++;var w=worst(n.id);if(w==='fix')v.fix++;else if(w==='review')v.review++}
    else{v=V.get(n.id);if(!v){v={id:n.id,type:n.type,label:n.label,n:n,parent:g&&g.id};V.set(n.id,v)}}
    rep.set(n.id,v.id)});
  ['anon','authenticated'].forEach(function(r){V.set('role:'+r,{id:'role:'+r,type:'role',label:r})});
  var E=new Map();var addE=function(a,b,rel,conf){if(a===b)return;var k=a+'|'+b;var e=E.get(k);if(!e){e={s:a,t:b,count:0,rels:new Set(),firm:false};E.set(k,e)}e.count++;e.rels.add(rel);if(conf==='extracted')e.firm=true};
  D.links.forEach(function(e){var a=rep.get(e.source),b=rep.get(e.target);if(a&&b)addE(a,b,relLabel(e.relation,e.ops),e.confidence)});
  D.nodes.forEach(function(n){var b=rep.get(n.id);if(n.type==='function'){if(n.anon)addE('role:anon',b,'EXECUTE','extracted');if(n.authenticated)addE('role:authenticated',b,'EXECUTE','extracted')}
    if((n.type==='table'||n.type==='view')&&Array.isArray(n.clientPrivs)&&n.clientPrivs.length){['anon','authenticated'].forEach(function(r){var pr=n.privsByRole?n.privsByRole[r]||[]:n.clientPrivs;if(pr.length)addE('role:'+r,b,pr.join(', ').toUpperCase(),'extracted')})}});
  return{V:V,E:[...E.values()]}}
function drawMap(){vp.textContent='';$('dash').style.display='none';svg.style.display='block';syncMarkers();
  var m=mapModel();var W=Math.max(1000,svg.clientWidth);var colW=W/4;
  var cols=[[],[],[],[]];m.V.forEach(function(v){var c=v.type==='group'?2:COL[v.type];if(c==null||c<0)c=2;v.c=c;cols[c].push(v)});
  cols.forEach(function(arr){arr.sort(function(a,b){return (b.fix||0)-(a.fix||0)||String(a.label).localeCompare(String(b.label))})});
  var pos=new Map();var maxH=0;var avail=Math.max(400,svg.clientHeight-80);var r0=cssNum('--map-r',5),rr=cssNum('--map-role-r',8),rg=cssNum('--map-group-r',20);
  cols.forEach(function(arr,ci){var y=60;var cx=ci*colW+colW*0.3;vp.appendChild(s('text',{x:cx,y:28,'text-anchor':'middle','class':'colh',text:COLNAME[ci]+' ('+arr.length+')'}));
    var gap=Math.max(4,Math.min(22,avail/Math.max(1,arr.length)-10));
    arr.forEach(function(v){var r=v.type==='group'||v.type==='folder'?Math.min(rg,r0+Math.sqrt(v.members||1)*1.4):v.type==='role'?rr:r0;pos.set(v.id,{x:cx,y:y+r,r:r,c:ci});y+=r*2+(v.type==='group'||v.type==='role'?Math.max(gap,26):gap)});maxH=Math.max(maxH,y)});
  var sel=state.mapSel;var near=null;if(sel){near=new Set([sel]);m.E.forEach(function(e){if(e.s===sel)near.add(e.t);if(e.t===sel)near.add(e.s)})}
  var slots=function(ci){return cols[ci].map(function(v){var p=pos.get(v.id);return[p.y-p.r-2,p.y+p.r+2]})};
  var xspan=function(ci){if(!cols[ci].length)return null;var cx=ci*colW+colW*0.3;var mr=0;cols[ci].forEach(function(v){mr=Math.max(mr,pos.get(v.id).r)});return[cx-mr-2,cx+mr+2]};
  var eg=s('g');vp.appendChild(eg);
  m.E.forEach(function(e){var a=pos.get(e.s),b=pos.get(e.t);if(!a||!b)return;var on=sel&&(e.s===sel||e.t===sel);
    var A={x0:a.x-a.r-2,x1:a.x+a.r+2,y:a.y},B={x0:b.x-b.r-3,x1:b.x+b.r+3,y:b.y};var rt=route(A,B,a.c,b.c,slots,xspan,4);
    var el=s('path',{d:rt.d,'class':'e'+(e.firm?'':' inf')+(on?' hi':sel?' dim':''),'marker-end':'url(#'+(on?'ar-hi':'ar')+')','stroke-width':String(Math.min(5,cssNum('--edge-w',1.5)+Math.log2(e.count)*0.6))});
    el.appendChild(s('title',{text:[...e.rels].join(', ')+' \u00d7'+e.count}));eg.appendChild(el)});
  m.V.forEach(function(v){var p=pos.get(v.id);var g=s('g',{transform:'translate('+p.x+','+p.y+')','class':sel&&!near.has(v.id)?'dimmed':''});
    var t=v.type==='group'?(v.fix?'fix':v.review?'review':null):worst(v.id);
    g.appendChild(sym(v.type==='group'?v.kind:v.type,p.r,(t||'')+(v.type==='group'||v.type==='folder'?' grp':'')));
    var ci=v.c;var showLabel=v.type==='group'||v.type==='role'||(cols[ci]&&cols[ci].length<=25)||(v.type==='folder'&&cols[0].length<=40)||v.id===sel||(near&&near.has(v.id));
    var lab=s('text',{x:0,y:p.r+12,'text-anchor':'middle','class':'mlabel',text:(v.type==='group'||v.type==='folder'?short(v.label,34)+' ('+v.members+')':short(v.label,40))+(v.fix?' \u00b7 '+v.fix+' fix':'')});
    if(!showLabel)lab.setAttribute('visibility','hidden');g.appendChild(lab);
    g.addEventListener('mouseenter',function(){lab.setAttribute('visibility','visible')});g.addEventListener('mouseleave',function(){if(!showLabel)lab.setAttribute('visibility','hidden')});
    g.style.cursor='pointer';g.appendChild(s('title',{text:v.label+(v.type==='group'||v.type==='folder'?' \u2014 click to expand':'')}));
    onBox(g,function(){if(v.type==='group'||v.type==='folder'){state.expanded.add(v.id);draw()}else if(v.parent&&state.mapSel===v.id){state.expanded.delete(v.parent);state.mapSel=null;draw()}else{state.mapSel=v.id;if(byId.has(v.id)){state.node=v.id;state.sel=null;renderCard();renderList()}draw()}});
    vp.appendChild(g)});
  bounds={x:0,y:0,w:W,h:maxH+20};fit();
  $('crumb').textContent='';$('crumb').appendChild(h('span',{cls:'lbl',text:'Map \u00b7 '}));$('crumb').appendChild(document.createTextNode(m.V.size+' nodes; click a group to expand it, click an expanded object twice to collapse its group'));
}

/* ---------- dashboard ---------- */
var SURF=[['tables','Tables'],['rpc','RPC functions'],['views','Views'],['edge','Edge functions'],['buckets','Storage buckets'],['realtime','Realtime']];
var ROLES=[['anon','anon'],['authenticated','authenticated'],['public','public (no key)']];
var NA_NOTE={public:'Every Data API and Realtime request needs at least the anon key.',buckets:'Storage access is decided by policies on storage.objects, which tracegrid does not model.'};
function reach(){var live=D.nodes.filter(function(n){return !n.missing});
  var privs=function(n,r){if(n.privsByRole)return n.privsByRole[r]||[];return Array.isArray(n.clientPrivs)?n.clientPrivs:[]};
  var rt=new Set();D.links.forEach(function(e){if((e.ops||[]).indexOf('realtime')>=0)rt.add(e.target)});
  var M={};ROLES.forEach(function(ro){var r=ro[0];M[r]={};SURF.forEach(function(su){var k=su[0],ids=null,note=null,unc=true;
    if(k==='tables'||k==='views'){if(r!=='public')ids=live.filter(function(n){return n.type===(k==='tables'?'table':'view')&&privs(n,r).length})}
    else if(k==='rpc'){if(r!=='public')ids=live.filter(function(n){return n.type==='function'&&!n.triggerOnly&&n[r]})}
    else if(k==='edge'){ids=live.filter(function(n){return n.type==='edge_function'&&(r!=='public'||n.verifyJwt===false)});note=r==='public'?'verify_jwt = false':'The anon key is a valid JWT, so verify_jwt alone does not keep anon out.'}
    else if(k==='buckets'){if(r==='public')ids=live.filter(function(n){return n.type==='bucket'&&n.public===true});note=r==='public'?'public buckets: objects readable by URL':null}
    else if(k==='realtime'){if(r!=='public')ids=live.filter(function(n){return rt.has(n.id)&&privs(n,r).indexOf('select')>=0});unc=false;note='tables the code subscribes to that the role can SELECT'}
    if(ids===null){M[r][k]={na:true,note:NA_NOTE[r]||NA_NOTE[k]||''};return}
    M[r][k]={ids:ids.map(function(n){return n.id}),uncalled:unc?ids.filter(function(n){return !callers(n.id).length}).map(function(n){return n.id}):null,note:note}})});
  return M}
function exposure(M){var t=D.tiers||{fix:0,review:0,info:0};var u=new Set();['tables','views','rpc'].forEach(function(k){var c=M.anon[k];if(c&&c.uncalled)c.uncalled.forEach(function(id){u.add(id)})});
  return{score:10*(t.fix||0)+3*(t.review||0)+u.size,anonUncalled:u.size}}
/* Plain-English titles, built from the rule and what the finding says about its object. */
function who(roles){roles=roles||[];var a=roles.indexOf('anon')>=0,u=roles.indexOf('authenticated')>=0;return a&&u?'anon and signed-in users':a?'anon users':u?'signed-in users':'client roles'}
var hasWrite=function(n){return !n||!Array.isArray(n.clientPrivs)||n.clientPrivs.some(function(p){return WRITE.test(p)})};
var TITLES={
'exposed-uncalled-function':function(f){return 'Function nothing calls, open to '+who(f.roles)+(f.securityDefiner?' (security definer)':'')},
'granted-helper-function':function(f){return 'Helper function only SQL uses, still callable by '+who(f.roles)},
'client-table-without-rls':function(f,n){return 'Table '+(hasWrite(n)?'readable and writable':'readable')+' with row security off'},
'client-table-not-granted':function(){return 'Table the browser code uses, but no client role may touch it'},
'client-view-without-security-invoker':function(){return 'View that skips row security (runs with its owner’s rights)'},
'client-table-without-policies':function(){return 'Table with row security on but no policy'},
'auth-hook-function-exposed':function(f){return 'Auth hook function callable by '+who(f.roles)},
'missing-rpc':function(){return 'Code calls a function the schema does not define'},
'unknown-table':function(){return 'Code uses a table or view the schema does not define'},
'uncalled-edge-function':function(){return 'Edge function nothing calls'},
'missing-edge-function':function(){return 'Code invokes an edge function that does not exist'},
'edge-service-role-before-auth':function(){return 'Edge function uses the service key before checking who is calling'},
'edge-request-controlled-fetch':function(){return 'Edge function fetches a URL taken from the request'},
'demo/client-writes-protected-table':function(){return 'Browser code writes a table only the server should write'}};
function plainTitle(f){var fn=Object.prototype.hasOwnProperty.call(TITLES,f.rule)?TITLES[f.rule]:null;if(fn)return fn(f,f.node&&byId.get(f.node));var r=rules.get(f.rule);return (r&&r.title)||f.rule}
var inFilter=function(f){return !state.filter||(f.node&&state.filter.ids.has(f.node))};
function tip(text,right){return h('span',{cls:'q'+(right?' r':''),tabindex:'0',role:'img','aria-label':text,'data-tip':text,text:'?'})}
function det(title,count,tipText,body){var d=h('details');var sm=h('summary',null,h('span',{text:title}));if(count!=null)sm.appendChild(h('em',{text:String(count)}));
  if(tipText){var q=tip(tipText,true);q.addEventListener('click',function(ev){ev.preventDefault();ev.stopPropagation()});sm.appendChild(q)}
  d.appendChild(sm);d.appendChild(h('div',{cls:'body'},body));return d}
function objBtn(f){var b=h('button',{type:'button',cls:'ghost',text:f.id,title:'Show path'});b.addEventListener('click',function(){selectFinding(f)});return b}
function findingTable(list){var t=h('table',{cls:'t'});list.forEach(function(f){t.appendChild(h('tr',null,h('td',{cls:'gl '+f.tier,text:GLY[f.tier]}),h('td',{text:plainTitle(f)}),h('td',{cls:'mono-s'},objBtn(f)),h('td',null,f.at?pth(f.at):null)))});return t}
/* Path text on one line, cut from the left to fit; the full text lives in title (set via setAttribute, so escaped). */
var CHARW=0;
function charW(el){if(CHARW)return CHARW;var p=h('span',{text:'abcdefgh/_.0123456789'});p.style.cssText='position:absolute;visibility:hidden;white-space:nowrap';el.appendChild(p);CHARW=(p.getBoundingClientRect().width/20)||7;el.removeChild(p);return CHARW}
function fitPth(el){var full=el.getAttribute('data-full')||'';var w=el.clientWidth;if(!w){el.textContent=full;return}el.textContent=truncLeft(full,Math.floor(w/charW(el))-1)}
function pth(text){var el=h('span',{cls:'pth',title:text,'data-full':text,text:text});return el}
function fitAll(){CHARW=0;document.querySelectorAll('.pth').forEach(function(el){el.textContent=el.getAttribute('data-full');fitPth(el)})}
var fitT=0;window.addEventListener('resize',function(){clearTimeout(fitT);fitT=setTimeout(fitAll,60)});
function todoRow(f){var row=h('div',{cls:'todo'},h('span',{cls:'g',text:GLY.fix}),
    h('div',null,h('div',{cls:'tt',text:plainTitle(f)}),h('div',{cls:'mut'},h('b',{cls:'ob',text:f.id}),f.at?pth(f.at):null)));
  var b=h('button',{type:'button',text:'show path'});b.addEventListener('click',function(){selectFinding(f)});row.appendChild(b);return row}
function barRows(rows,max,onClick){var g=h('div');rows.forEach(function(r){var k=h('button',{cls:'k ghost',type:'button',title:r.key,text:r.label||r.key});if(onClick)k.addEventListener('click',function(){onClick(r)});else k.disabled=true;
    var t=h('div',{cls:'t'});r.parts.forEach(function(p){if(p[1])t.appendChild(h('span',{style:'width:'+(100*p[1]/Math.max(1,max)).toFixed(2)+'%;background:var('+p[0]+')'}))});
    g.appendChild(h('div',{cls:'bar'},k,t,h('span',{cls:'n',text:String(r.total)})))});return g}
function drawDash(){svg.style.display='none';var o=$('dash');o.style.display='block';o.textContent='';card.hidden=true;
  $('crumb').textContent='';$('crumb').appendChild(h('span',{cls:'lbl',text:'Dashboard · '}));$('crumb').appendChild(document.createTextNode(D.root+(D.generated_at?' · '+String(D.generated_at).slice(0,16).replace('T',' '):'')));
  if(!D.nodes.length){emptyPath();return}
  var M=reach();var ex=exposure(M);var t=D.tiers||{fix:0,review:0,info:0};
  /* header strip */
  var st=h('div',{cls:'strip'});
  st.appendChild(h('div',null,h('span',{cls:'lbl',text:'Exposure'}),h('span',{cls:'big',text:String(ex.score)}),tip('10 × Fix + 3 × Review + 1 per object anon can reach that no code calls ('+ex.anonUncalled+'). Lower is better; 0 means nothing to act on.')));
  [['fix','fix'],['review','review'],['info','info']].forEach(function(x){st.appendChild(h('div',null,h('span',{cls:x[0],text:GLY[x[0]]+' '+(t[x[0]]||0)+' '+x[1]})))});
  if(D.baseline)st.appendChild(h('div',{cls:'bl'},h('span',{cls:'lbl',text:'Since baseline'}),h('span',null,h('b',{text:'+'+D.baseline.fresh}),document.createTextNode(' new')),h('span',null,h('b',{text:'−'+D.baseline.fixed}),document.createTextNode(' fixed')),tip('Compared with '+D.baseline.file+'. New findings are not in the baseline; fixed ones were in it and are gone.')));
  o.appendChild(st);
  var cols=h('div',{cls:'cols'});o.appendChild(cols);var L=h('div',{cls:'col'}),R=h('div',{cls:'col'});cols.appendChild(L);cols.appendChild(R);
  /* left: to do, then review */
  var allFix=D.findings.filter(function(f){return f.tier==='fix'}),fixes=allFix.filter(inFilter);
  var todo=h('div',{cls:'card'},h('h2',null,h('span',null,document.createTextNode('To do · fix'),tip('Each item is a hole an outsider could use. Show path opens the code-to-database route for that finding.')),h('span',{text:(fixes.length!==allFix.length?fixes.length+' of ':'')+allFix.length+' item'+(allFix.length===1?'':'s')})));
  if(!fixes.length)todo.appendChild(h('div',{cls:'none',text:allFix.length?'No fix items in the selected cell.':'Nothing to fix.'}));
  fixes.slice(0,200).forEach(function(f){todo.appendChild(todoRow(f))});
  if(fixes.length>200)todo.appendChild(h('div',{cls:'none',text:(fixes.length-200)+' more: click Fix in the sidebar.'}));
  L.appendChild(todo);
  var rv=D.findings.filter(function(f){return f.tier==='review'&&inFilter(f)});
  L.appendChild(det('Review ('+rv.length+')','not urgent',null,rv.length?findingTable(rv.slice(0,200)):h('span',{cls:'muted',text:'Nothing to review.'})));
  /* right: reach matrix */
  var mx=h('div',{cls:'card'},h('h2',null,h('span',null,document.createTextNode('Reach matrix'),tip('Each cell is the number of objects nothing calls, then the number the role can reach. Highlighted cells have something nothing calls. Click a cell to filter the findings to its objects; click again to clear. A dash means not applicable.')),h('span',{text:'role × surface'})));
  var tb=h('table',{cls:'mx'});var hr=h('tr',null,h('th',{cls:'rh'}));SURF.forEach(function(su){hr.appendChild(h('th',{text:su[1]}))});tb.appendChild(hr);
  ROLES.forEach(function(ro){var tr=h('tr',null,h('th',{cls:'rh',text:ro[1]}));SURF.forEach(function(su){var c=M[ro[0]][su[0]];var td=h('td');
      if(c.na){var sp=h('span',{cls:'na',text:'—'});if(c.note)sp.setAttribute('title',c.note);td.appendChild(sp)}
      else{var lbl=ro[1]+' × '+su[1];var nu=c.uncalled?c.uncalled.length:0;
        var b=h('button',{type:'button',cls:state.filter&&state.filter.label===lbl?'on':'','aria-pressed':state.filter&&state.filter.label===lbl?'true':'false'});
        if(c.uncalled){b.appendChild(h('b',{text:String(nu)}));b.appendChild(h('small',{text:'/'+c.ids.length}));if(nu)td.className='hot'}else b.appendChild(h('b',{text:String(c.ids.length)}));
        b.setAttribute('title',lbl+': '+(c.uncalled?nu+' not called of '+c.ids.length+' reachable':c.ids.length+' reachable')+(c.note?'. '+c.note:''));
        b.addEventListener('click',function(){if(state.filter&&state.filter.label===lbl)setFilter(null);else setFilter({label:lbl,ids:new Set(c.ids)})});td.appendChild(b)}
      tr.appendChild(td)});tb.appendChild(tr)});
  mx.appendChild(tb);mx.appendChild(h('div',{cls:'legend'},document.createTextNode('cell = '),h('b',{text:'not called'}),document.createTextNode(' / reachable  ·  — n/a')));R.appendChild(mx);
  /* coverage: four stat cells */
  var cv=D.coverage||{};var unp=(cv.sql_unparsed||0)+(cv.partial||0)+(cv.unreadable||0);
  var cvp=h('div',{cls:'card'},h('h2',null,h('span',null,document.createTextNode('Coverage'),tip('How much of the project the scan understood. Unresolved calls use dynamic names it cannot read. Unparsed counts SQL statements not understood plus partly parsed and unreadable files. Anything above 0 means the findings may miss something.')),h('span',{text:D.source==='catalog'?'live catalog':'migrations'})));
  var stat=function(k,v,warn){return h('div',{cls:warn?'warn':''},h('span',{cls:'lbl',text:k}),h('b',{text:v==null?'—':String(v)}))};
  cvp.appendChild(h('div',{cls:'cov'},stat('Files',cv.files,!cv.files),stat('Calls',cv.call_sites,!cv.call_sites),stat('Unresolved',cv.unresolved,cv.unresolved>0),stat('Unparsed',unp,unp>0)));R.appendChild(cvp);
  /* right: collapsed sections */
  var gr=h('div',{cls:'gr'});R.appendChild(gr);
  var rows=D.rules.map(function(r){var mine=D.findings.filter(function(f){return f.rule===r.id&&inFilter(f)});var tc=function(x){return mine.filter(function(f){return f.tier===x}).length};var w=tc('fix')?'fix':tc('review')?'review':'info';return{key:r.id,label:GLY[w]+' '+r.id,total:mine.length,parts:[['--fix',tc('fix')],['--review',tc('review')],['--info',tc('info')]]}}).filter(function(r){return r.total}).sort(function(a,b){return b.total-a.total});
  gr.appendChild(det('Findings by rule',rows.reduce(function(a,r){return a+r.total},0),'Click a rule to search the list on the left for it.',rows.length?barRows(rows,rows[0].total,function(r){$('q').value=r.key;state.q=r.key.toLowerCase();renderList()}):h('span',{cls:'muted',text:'No findings.'})));
  var fm=new Map();
  D.links.forEach(function(e){var sN=byId.get(e.source);if(!sN||!/^(rpc|from|invoke|storage)/.test(e.relation))return;var k=sN.type==='file'?folderOf(sN.label)+'/':sN.type==='edge_function'?'functions/'+sN.label:null;if(!k)return;fm.set(k,(fm.get(k)||0)+(e.count||1))});
  var frows=[...fm].sort(function(a,b){return b[1]-a[1]}).slice(0,8).map(function(x){return{key:x[0],total:x[1],parts:[['--bar',x[1]]]}});
  gr.appendChild(det('Top folders',frows.length,'Folders ranked by how many database calls their code makes.',frows.length?barRows(frows,frows[0].total,null):h('span',{cls:'muted',text:'No call sites.'})));
  var dg=D.nodes.filter(function(n){return(n.type==='table'||n.type==='view')&&n.defaultGrants&&n.defaultGrants.length&&(inc.get(n.id)||[]).some(function(e){return /^(from|from-weak)$/.test(e.relation)})});
  if(dg.length){var tl=h('table',{cls:'t'});dg.slice(0,40).forEach(function(n){var site=(inc.get(n.id)||[]).filter(function(e){return /^(from|from-weak)$/.test(e.relation)})[0];var nm=h('button',{type:'button',cls:'ghost',text:n.label});nm.addEventListener('click',function(){selectNode(n.id)});
      tl.appendChild(h('tr',null,h('td',null,nm),h('td',{cls:'mono-s',text:n.defaultGrants.join(', ').toUpperCase()}),h('td',{text:site&&site.at&&site.at[0]?site.at[0]:''})))});
    var bd=h('div',null,tl);if(dg.length>40)bd.appendChild(h('div',{cls:'muted',text:(dg.length-40)+' more in graph.json (nodes with defaultGrants).'}));
    gr.appendChild(det('Supabase 2026-10-30 change',dg.length+' table'+(dg.length>1?'s':''),'The client uses these tables, and anon / authenticated hold the privileges below only through Supabase’s legacy default grants. Existing tables keep them; a table dropped and recreated after 2026-10-30, or a project rebuilt from these migrations, loses them until a migration GRANTs them explicitly.',bd))}
  var inf=D.findings.filter(function(f){return f.tier==='info'&&inFilter(f)});
  gr.appendChild(det('Info ('+inf.length+')',null,null,inf.length?findingTable(inf.slice(0,200)):h('span',{cls:'muted',text:'Nothing in this tier.'})));
  if((D.notices||[]).length)gr.appendChild(det('Scan notices',D.notices.length,null,h.apply(null,['div',null].concat(D.notices.map(function(n){return h('div',{text:n})})))));
}

function draw(){if(state.view==='dash'){drawDash();fitAll()}else if(state.view==='path'){if(state.node&&byId.has(state.node))drawPath();else emptyPath()}else if(state.view==='map')drawMap()}

/* ---------- tabs and theme ---------- */
document.querySelectorAll('#tabs button').forEach(function(b){b.addEventListener('click',function(){setView(b.getAttribute('data-view'))})});
function setView(v){state.view=v;renderList();document.querySelectorAll('#tabs button').forEach(function(b){b.classList.toggle('on',b.getAttribute('data-view')===v)});
  var three=$('three');$('ov3d').hidden=v!=='3d';if(v==='3d'){three.hidden=false;svg.style.display='none';$('dash').style.display='none';renderCard();$('crumb').textContent='';$('crumb').appendChild(h('span',{cls:'lbl',text:'3D \u00b7 '}));$('crumb').appendChild(document.createTextNode('drag to spin, scroll to zoom, click a finding to fly to it'));open3d()}else{three.hidden=true;pause3d();renderCard();draw()}}
/* ---------- look: colourway and mode (settings popover); every storage access is wrapped, the page works without it ---------- */
var LS='tracegrid.';
function sget(k){try{return window.localStorage.getItem(LS+k)}catch(e){return null}}
function sset(k,v){try{window.localStorage.setItem(LS+k,v)}catch(e){}}
var okCw=function(c){return typeof c==='string'&&D.colorways.indexOf(c)>=0};
var MODES=['auto','dark','light'];
/* ?colorway=<name> beats the stored choice, which beats the default baked in at generation time. */
function urlColorway(){try{return new URLSearchParams(location.search).get('colorway')}catch(e){return null}}
var look={colorway:okCw(urlColorway())?urlColorway():okCw(sget('colorway'))?sget('colorway'):D.colorway,mode:MODES.indexOf(sget('mode'))>=0?sget('mode'):'dark',rot:sget('rotate')!=='0'};
var mq=null;try{mq=window.matchMedia('(prefers-color-scheme: light)')}catch(e){}
function resolvedTheme(){return look.mode==='auto'?(mq&&mq.matches?'light':'dark'):look.mode}
function applyLook(){var r=document.documentElement;r.dataset.colorway=look.colorway;r.dataset.theme=resolvedTheme();recolor3d()}
if(mq&&mq.addEventListener)mq.addEventListener('change',function(){if(look.mode==='auto')applyLook()});
var cwSel=$('cw'),modeSel=$('mode'),rotBox=$('rot'),gear=$('gear'),pop=$('settings');
D.colorways.forEach(function(c){cwSel.appendChild(h('option',{value:c,text:c}))});
cwSel.value=look.colorway;modeSel.value=look.mode;rotBox.checked=look.rot;
cwSel.addEventListener('change',function(){if(!okCw(cwSel.value))return;look.colorway=cwSel.value;sset('colorway',look.colorway);applyLook()});
modeSel.addEventListener('change',function(){if(MODES.indexOf(modeSel.value)<0)return;look.mode=modeSel.value;sset('mode',look.mode);applyLook()});
rotBox.addEventListener('change',function(){look.rot=rotBox.checked;sset('rotate',look.rot?'1':'0');var c=G3&&G3.controls();if(c)c.autoRotate=look.rot&&!hl});
$('theme').addEventListener('click',function(){look.mode=resolvedTheme()==='light'?'dark':'light';modeSel.value=look.mode;sset('mode',look.mode);applyLook()});
function closePop(){pop.hidden=true;gear.setAttribute('aria-expanded','false')}
gear.addEventListener('click',function(ev){ev.stopPropagation();pop.hidden=!pop.hidden;gear.setAttribute('aria-expanded',pop.hidden?'false':'true');if(!pop.hidden)cwSel.focus()});
pop.addEventListener('click',function(ev){ev.stopPropagation()});
document.addEventListener('click',closePop);
document.addEventListener('keydown',function(ev){if(ev.key==='Escape'&&!pop.hidden){closePop();gear.focus()}});
/* The 3D scene keeps its own materials: re-read the palette and push it into them. */
function recolor3d(){if(!G3||!nodes3)return;pal();G3.backgroundColor(P3.bg);
  if(starMat){starMat.color.set(P3.star);if(starMat.emissive)starMat.emissive.set(P3.star)}
  haloList.forEach(function(x){var c=base3(x.n);x.m.color.set(c);if(x.m.emissive)x.m.emissive.set(c)});
  nodes3.forEach(function(n){var o=n.__threeObj;if(!o||!o.material||!o.material.emissive)return;o.material.emissive.set(base3(n));o.material.emissiveIntensity=P3.glow});
  refresh3d()}

/* ---------- 3D showcase (lazy, pinned, SRI) ---------- */
var starMat=null,haloList=[];
var G3=null,loading=false,nodes3=null,links3=null,hl=null,hlId=null,labelled=[],raf=0,lastPatch=0,interacted=false,K=null,shaped=false;
var P3=null;function pal(){P3={bg:cssVar('--3d-bg'),node:cssVar('--3d-node'),link:cssVar('--3d-link'),hi:cssVar('--3d-link-hi'),star:cssVar('--3d-star'),fix:cssVar('--fix'),review:cssVar('--review'),glow:cssNum('--3d-glow',0.55)};return P3}
var msg=function(t){var m=$('three-msg');if(t==null){m.hidden=true;return}m.hidden=false;m.textContent=t};
function open3d(){if(G3){resume3d();return}if(loading)return;loading=true;msg('Loading the 3D library from jsDelivr\u2026');
  if(typeof window.ForceGraph3D==='function'){loading=false;start3d();return}
  var sc=document.createElement('script');sc.src=D.fg3d.url;sc.integrity=D.fg3d.integrity;sc.crossOrigin='anonymous';sc.async=true;
  var fail=function(){loading=false;msg('3D view needs internet (it loads one pinned library from jsDelivr); the 2D views work offline.')};
  var timer=setTimeout(fail,20000);
  sc.onload=function(){clearTimeout(timer);loading=false;if(typeof window.ForceGraph3D!=='function'){fail();return}start3d()};
  sc.onerror=function(){clearTimeout(timer);fail()};document.head.appendChild(sc)}
function build3d(){var big=D.nodes.length>1500;var rep=new Map(),N=new Map();
  D.nodes.forEach(function(n){var v;if(big&&n.type==='file'){var id='folder:'+folderOf(n.label);v=N.get(id);if(!v){v={id:id,type:'folder',label:folderOf(n.label)+'/',deg:0,members:0};N.set(id,v)}v.members++}else{v={id:n.id,type:n.type,label:n.label,deg:0,tier:worst(n.id)};N.set(n.id,v)}rep.set(n.id,v.id)});
  var L=new Map();D.links.forEach(function(e){var a=rep.get(e.source),b=rep.get(e.target);if(!a||!b||a===b)return;var k=a+'|'+b;if(!L.has(k)){L.set(k,{source:a,target:b,rel:e.relation});N.get(a).deg++;N.get(b).deg++}});
  nodes3=[...N.values()];links3=[...L.values()];
  var hubs=nodes3.filter(function(n){return !n.tier}).sort(function(a,b){return b.deg-a.deg}).slice(0,Math.max(3,Math.min(12,Math.round(nodes3.length/25))));
  labelled=nodes3.filter(function(n){return n.tier==='fix'}).slice(0,40).concat(hubs)}
/* Size by degree, with a floor so leaves stay visible. */
function val3(n){var v=n.type==='folder'?2+Math.sqrt(n.members||1):1.6+Math.min(12,Math.sqrt(n.deg)*1.5);return Math.max(n.tier==='fix'?6:2,v)}
function base3(n){return n.tier==='fix'?P3.fix:n.tier==='review'?P3.review:P3.node}
function col3(n){var c=base3(n);if(!hl||hl.has(n.id))return c;return hexA(c,0.1)}
function hexA(hex,a){var x=parseInt(String(hex).replace('#','').slice(0,6),16);return'rgba('+(x>>16&255)+','+(x>>8&255)+','+(x&255)+','+a+')'}
var sid=function(x){return typeof x==='object'?x.id:x};
var isFix=function(x){var n=typeof x==='object'?x:null;return n?n.tier==='fix':false};
var lit=function(l){return !!hlId&&(sid(l.source)===hlId||sid(l.target)===hlId)};
function linkCol(l){if(!hl)return hexA(P3.link,0.7);return lit(l)?hexA(P3.hi,1):hexA(P3.link,0.05)}
function start3d(){msg(null);pal();build3d();var el=$('three-canvas');
  try{
  G3=window.ForceGraph3D({controlType:'orbit'})(el).backgroundColor(P3.bg).showNavInfo(false).width(el.clientWidth).height(el.clientHeight)
    .nodeId('id').nodeVal(val3).nodeRelSize(3).nodeResolution(nodes3.length>1000?6:10)
    .nodeColor(col3).nodeOpacity(0.92).nodeLabel(function(n){return'<div class="tip">'+esc(n.label)+'<span>'+esc(KINDNAME[n.type]||n.type)+(n.tier?' \u00b7 '+esc(n.tier):'')+'<\/span><\/div>'})
    .linkColor(linkCol).linkOpacity(1).linkWidth(function(l){return lit(l)?1.6:0.8}).linkResolution(4)
    .linkDirectionalArrowLength(function(l){return lit(l)?6:3.5}).linkDirectionalArrowRelPos(1).linkDirectionalArrowResolution(6).linkDirectionalArrowColor(linkCol)
    .linkDirectionalParticles(function(l){if(hl)return lit(l)?2:0;return links3.length<=700?1:(isFix(l.source)||isFix(l.target))?1:0})
    .linkDirectionalParticleSpeed(0.0035).linkDirectionalParticleWidth(1.3).linkDirectionalParticleColor(function(){return P3.hi})
    .warmupTicks(nodes3.length>800?40:20).cooldownTicks(nodes3.length>800?150:300)
    .onNodeHover(function(n){hover3=n||null}).onEngineStop(function(){if(!interacted&&!hl)fit3d(900)})
    .onNodeClick(function(n){var fs=byNode.get(n.id);if(fs)selectFinding(fs[0]);else if(byId.has(n.id))selectNode(n.id);else fly3d(n.id)})
    .graphData({nodes:nodes3,links:links3});
  }catch(e){msg('3D view could not start ('+String(e&&e.message||e)+'); the 2D views still work.');G3=null;return}
  var ctl=G3.controls();if(ctl){ctl.autoRotate=look.rot;ctl.autoRotateSpeed=0.45;if(ctl.addEventListener)ctl.addEventListener('change',updateLabels)}
  ['pointerdown','wheel','touchstart'].forEach(function(t){el.addEventListener(t,function(){interacted=true;var c=G3&&G3.controls();if(c)c.autoRotate=false;idle3()},{passive:true})});
  el.addEventListener('dblclick',function(){if(!hover3)overview3d()});
  window.addEventListener('resize',function(){if(G3&&state.view==='3d')G3.width(el.clientWidth).height(el.clientHeight)});
  setTimeout(function(){shapes();setTimeout(function(){stars();halos()},400)},600);[2500,5000,8000].forEach(function(ms){setTimeout(function(){if(G3&&!interacted&&!hl)fit3d(900)},ms)});resume3d();if(state.node)setTimeout(function(){fly3d(state.node)},1200)}
/* The library does not expose three.js, so the classes come from objects it has already built:
   a node mesh (Mesh, SphereGeometry, material), a link cylinder (CylinderGeometry) and an arrow (ConeGeometry). */
function grab(){if(K)return K;var o=null,lo=null,ao=null,i;for(i=0;i<nodes3.length&&!o;i++)o=nodes3[i].__threeObj;
  for(i=0;i<links3.length&&(!lo||!ao);i++){var l=links3[i];if(!lo&&l.__lineObj&&l.__lineObj.geometry&&/^Cylinder/.test(l.__lineObj.geometry.type))lo=l.__lineObj;if(!ao&&l.__arrowObj&&l.__arrowObj.geometry)ao=l.__arrowObj}
  if(!o||!o.geometry||!o.material)return null;K={Mesh:o.constructor,Sphere:o.geometry.constructor,Mat:o.material.constructor,Cyl:lo?lo.geometry.constructor:null,Cone:ao?ao.geometry.constructor:null};return K}
/* One shape per kind, as in the 2D symbols: sphere = code, box = table / view, octahedron = function, cone = edge function, hexagonal prism = storage. */
var GEO={};
function geoFor(t){if(GEO[t])return GEO[t];var g;
  if((t==='table'||t==='view')&&K.Cyl){g=new K.Cyl(1.05,1.05,1.5,4,1);g.rotateY(Math.PI/4)}
  else if(t==='function')g=new K.Sphere(1.3,4,2);
  else if(t==='edge_function'&&K.Cone){g=new K.Cone(1.05,1.9,24);g.translate(0,-0.15,0)}
  else if(t==='bucket'&&K.Cyl)g=new K.Cyl(1.1,1.1,1,6,1);
  else g=GEO.sphere||(GEO.sphere=new K.Sphere(1,16,12));
  GEO[t]=g;return g}
function glowMat(c){var m=new K.Mat({color:c,transparent:true,opacity:0.92,depthWrite:false});m.blending=2;if(m.emissive){m.emissive.set(c);m.emissiveIntensity=P3.glow}m.__sr=true;return m}
function shapes(){try{if(!G3||!grab())return;
  G3.nodeThreeObject(function(n){var m=new K.Mesh(geoFor(n.type),glowMat(base3(n)));n.__s=Math.cbrt(val3(n))*3;m.scale.set(n.__s,n.__s,n.__s);return m});shaped=true;setTimeout(recolor,50)}catch(e){shaped=false/* keep the default spheres: size and colour still tell kinds apart */}}
function recolor(){if(!shaped||!nodes3)return;nodes3.forEach(function(n){var o=n.__threeObj;if(!o||!o.material||!o.material.color)return;var c=base3(n);o.material.color.set(c);if(o.material.emissive)o.material.emissive.set(c);o.material.opacity=!hl||hl.has(n.id)?0.92:0.08})}
/* Glow on the default node materials, before the shapes replace them. */
function patch(){if(!nodes3||shaped)return;nodes3.forEach(function(n){var o=n.__threeObj;if(!o||!o.material||o.material.__sr)return;var m=o.material;m.__sr=true;m.transparent=true;m.depthWrite=false;m.blending=2;if(m.emissive&&m.color){m.emissive.copy(m.color);m.emissiveIntensity=P3.glow}})}
/* A sparse starfield, built from the same classes. */
function stars(){try{if(!grab())return;var geo=new K.Sphere(1.2,4,3);var mat=new K.Mat({color:P3.star,transparent:true,opacity:0.5,depthWrite:false});if(mat.emissive)mat.emissive.set(P3.star);mat.__sr=true;starMat=mat;
  var sc=G3.scene();for(var j=0;j<260;j++){var r=1400+Math.random()*1800,t=Math.random()*Math.PI*2,p=Math.acos(2*Math.random()-1);var m=new K.Mesh(geo,mat);m.position.set(r*Math.sin(p)*Math.cos(t),r*Math.sin(p)*Math.sin(t),r*Math.cos(p));var k=0.5+Math.random()*1.4;m.scale.set(k,k,k);sc.add(m)}}catch(e){/* decorative only */}}
/* Soft halos (additive, translucent) around fix-tier nodes and hubs: the glow. */
function halos(){try{if(!grab())return;var geo=new K.Sphere(1,16,12);var mats={};
  labelled.forEach(function(n){var obj=n.__threeObj;if(!obj)return;var c=base3(n);var m=mats[c];if(!m){m=new K.Mat({color:c,transparent:true,opacity:0.2,depthWrite:false});if(m.emissive)m.emissive.set(c);m.blending=2;m.__sr=true;mats[c]=m}
    haloList.push({n:n,m:m});var halo=new K.Mesh(geo,m);var r=shaped?2.4:Math.cbrt(val3(n))*3*2.4;halo.scale.set(r,r,r);halo.__halo=true;obj.add(halo)})}catch(e){/* decorative only */}}
var labelEls=new Map(),labelPos=[],shown3=new Set();
/* Overlay labels: one pass per rendered frame and on every orbit-control change, so they never lag the canvas.
   Each label is one integer-pixel translate3d (no left/top reflow); hidden when behind the camera or outside the view. */
function updateLabels(){
  if(!G3||!nodes3)return;var box=$('three-labels');var cam=G3.camera(),ctl=G3.controls();if(!cam)return;var tgt=ctl&&ctl.target?ctl.target:{x:0,y:0,z:0};
  var W=box.clientWidth,H=box.clientHeight;
  var fx=tgt.x-cam.position.x,fy=tgt.y-cam.position.y,fz=tgt.z-cam.position.z;var fl=Math.hypot(fx,fy,fz)||1;
  var show=labelled;if(hl)show=nodes3.filter(function(n){return hl.has(n.id)}).slice(0,30);
  /* findings first, then the rest; within a rank, labels shown last frame keep their slot so overlaps do not flip-flop */
  var rank=function(n){return (n.tier==='fix'?0:2)+(shown3.has(n.id)?0:1)};
  show=show.map(function(n,i){return{n:n,i:i}}).sort(function(a,b){return rank(a.n)-rank(b.n)||a.i-b.i}).map(function(o){return o.n});
  var keep=new Set(),placed=[],out=[];
  show.forEach(function(n){if(n.x==null||!isFinite(n.x+n.y+n.z))return;
    var d=((n.x-cam.position.x)*fx+(n.y-cam.position.y)*fy+(n.z-cam.position.z)*fz)/fl;if(d<=1)return; /* behind (or on) the camera plane */
    var p=G3.graph2ScreenCoords(n.x,n.y,n.z);if(!p||!isFinite(p.x)||!isFinite(p.y))return;
    var x=Math.round(p.x),y=Math.round(p.y);if(x<0||y<0||x>W||y>H)return; /* off-screen */
    var fade=Math.max(0,Math.min(1,(2.6-d/fl)/1.6)); /* far labels fade out instead of popping; nothing is hidden by distance alone until they are invisible */
    if(fade<=0.02)return;
    var w=Math.min(36,String(n.label).length)*6.2,bx={x0:x-w/2,x1:x+w/2,y0:y-24,y1:y-8};
    if(placed.some(function(b){return bx.x0<b.x1&&bx.x1>b.x0&&bx.y0<b.y1&&bx.y1>b.y0}))return;placed.push(bx);
    var el=labelEls.get(n.id);if(!el){el=document.createElement('div');el.textContent=(GLY[n.tier]?GLY[n.tier]+' ':'')+short(n.label,36);if(n.tier==='fix'||n.tier==='review')el.className=n.tier;el.style.display='block';box.appendChild(el);el._w=el.offsetWidth;el._h=el.offsetHeight;el._hid=true;labelEls.set(n.id,el)}
    var tx=Math.round(x-el._w/2),ty=Math.round(y-el._h-6),op=(0.9*fade).toFixed(2);
    el.style.transform='translate3d('+tx+'px,'+ty+'px,0)';if(el._op!==op){el.style.opacity=op;el._op=op}if(el._hid){el.style.visibility='visible';el._hid=false}
    keep.add(n.id);out.push({id:n.id,x:tx,y:ty,opacity:+op})});
  labelEls.forEach(function(el,id){if(!keep.has(id)&&!el._hid){el.style.visibility='hidden';el._hid=true}});
  shown3=keep;labelPos=out}
function frame(ts){raf=requestAnimationFrame(frame);if(!G3)return;if(ts-lastPatch>500){patch();lastPatch=ts}
  var pulse=1+0.22*Math.sin(ts/420);nodes3.forEach(function(n){if(n.tier==='fix'&&n.__threeObj){var k=(shaped&&n.__s?n.__s:1)*pulse;n.__threeObj.scale.set(k,k,k)}});
  updateLabels()}
document.addEventListener('visibilitychange',function(){if(document.hidden){if(raf){cancelAnimationFrame(raf);raf=0}}else if(G3&&state.view==='3d')resume3d()});
function resume3d(){if(!raf)raf=requestAnimationFrame(frame);if(G3&&G3.resumeAnimation)G3.resumeAnimation()}
function pause3d(){if(raf){cancelAnimationFrame(raf);raf=0}if(G3&&G3.pauseAnimation)G3.pauseAnimation()}
var hover3=null,idleT=0;
/* Auto-rotate stays off while something is selected; on the overview it resumes after 5s without input. */
function idle3(){clearTimeout(idleT);idleT=setTimeout(function(){var c=G3&&G3.controls();if(c&&!hl&&look.rot&&state.view==='3d')c.autoRotate=true},5000)}
function crumb3(){var b=$('three-crumb');b.textContent='';if(!hl||!hlId){b.hidden=true;return}var n=nodes3.find(function(x){return x.id===hlId});var a=h('a',{text:'overview'});a.addEventListener('click',overview3d);b.appendChild(a);b.appendChild(document.createTextNode(' \u203a '+(n?n.label:hlId)));b.hidden=false}
function overview3d(){if(state.view!=='3d')return;state.sel=null;state.node=null;state.mapSel=null;renderList();renderCard();reset3d()}
function fly3d(id){if(!G3||!nodes3)return;var n=nodes3.find(function(x){return x.id===id});if(!n){var b=byId.get(id);if(b&&b.type==='file')n=nodes3.find(function(x){return x.id==='folder:'+folderOf(b.label)})}if(!n||n.x==null)return;
  hlId=n.id;hl=new Set([n.id]);links3.forEach(function(l){var a=sid(l.source),b=sid(l.target);if(a===n.id)hl.add(b);if(b===n.id)hl.add(a)});
  refresh3d();crumb3();var c=G3.controls();if(c){c.autoRotate=false;c.enabled=true}clearTimeout(idleT);var dist=170,r=Math.hypot(n.x,n.y,n.z)||1,k=1+dist/r;G3.cameraPosition({x:n.x*k,y:n.y*k,z:n.z*k},{x:n.x,y:n.y,z:n.z},1000);settle3(function(){return{x:n.x,y:n.y,z:n.z}},1050)}
/* After a transition, make sure the orbit controls are live and orbit the given point. */
function settle3(pt,ms){setTimeout(function(){var c=G3&&G3.controls();if(!c)return;c.enabled=true;if(c.target&&c.target.set){var p=pt();c.target.set(p.x,p.y,p.z)}if(c.update)c.update()},ms)}
if(/[?&]debug\b/.test(location.search))window.__tg3d={cameraDistance:function(){var c=G3.camera(),t=G3.controls().target;return Math.hypot(c.position.x-t.x,c.position.y-t.y,c.position.z-t.z)},target:function(){var t=G3.controls().target;return[t.x,t.y,t.z]},enabled:function(){return G3.controls().enabled},autoRotate:function(){return G3.controls().autoRotate},selected:function(){return hlId},select:function(i){selectFinding(D.findings[i||0])},zoom:function(d){var c=G3.controls();c.dollyIn?c.dollyIn(d):0;c.update()},labels:function(){return labelPos.slice()},orbit:function(a){var c=G3.camera(),t=G3.controls().target,dx=c.position.x-t.x,dz=c.position.z-t.z,co=Math.cos(a),si=Math.sin(a);c.position.x=t.x+dx*co-dz*si;c.position.z=t.z+dx*si+dz*co;c.lookAt(t.x,t.y,t.z);G3.controls().update();updateLabels();return labelPos.slice()},ready:function(){return !!G3&&nodes3.some(function(n){return n.x!=null})}};
function reset3d(){if(!G3)return;hl=null;hlId=null;refresh3d();crumb3();fit3d(800);idle3()}
/* Fit the camera to the densest 90% of nodes: a few far-flung ones would otherwise shrink everything else. */
function fit3d(ms){var pts=nodes3.filter(function(n){return n.x!=null});if(!pts.length)return;var c={x:0,y:0,z:0};pts.forEach(function(n){c.x+=n.x;c.y+=n.y;c.z+=n.z});c.x/=pts.length;c.y/=pts.length;c.z/=pts.length;
  var d=pts.map(function(n){return Math.hypot(n.x-c.x,n.y-c.y,n.z-c.z)}).sort(function(a,b){return a-b});var R=Math.max(40,d[Math.floor((d.length-1)*(pts.length<60?1:0.9))]);
  var cam=G3.camera();var fov=(cam&&cam.fov?cam.fov:40)*Math.PI/180;var dist=R/Math.tan(fov/2)*1.08;G3.cameraPosition({x:c.x,y:c.y,z:c.z+dist},c,ms);settle3(function(){return c},ms+50)}
function refresh3d(){if(!shaped)G3.nodeColor(col3);recolor();G3.linkColor(G3.linkColor()).linkWidth(G3.linkWidth()).linkDirectionalArrowLength(G3.linkDirectionalArrowLength()).linkDirectionalArrowColor(G3.linkDirectionalArrowColor()).linkDirectionalParticles(G3.linkDirectionalParticles());lastPatch=0}

/* Deep links: #f=<rule>:<subject> (or f=first) selects a finding and opens the path view; view=dash|path|map|3d opens that view. */
var hp=new URLSearchParams(location.hash.slice(1));var hf=hp.get('f');
if(hf){var order=D.findings.slice().sort(function(a,b){return RANK[a.tier]-RANK[b.tier]});var ff=hf==='first'?order[0]:D.findings.find(function(x){return x.rule+':'+x.id===hf});if(ff){state.sel=ff;state.node=ff.node||null;state.view='path'}}
var hv=hp.get('view');if(hv==='dash'||hv==='path'||hv==='map'||hv==='3d')state.view=hv;
applyLook();
renderChips();renderFilter();renderList();
if(state.view==='3d')setView('3d');else setView(state.view);
})();
`;
