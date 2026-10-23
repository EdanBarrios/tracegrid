// graph.html: one self-contained page. The 2D views (path view and full map) are plain SVG built
// with DOM calls and work offline. The optional 3D view lazy-loads one pinned library from jsDelivr,
// with a Subresource Integrity hash, only when the user asks for it; no data ever leaves the page.
//
// Every name in the data comes from the scanned project (a fork pull request controls it), so:
// the data is embedded as JSON with `<`, U+2028 and U+2029 escaped; the page builds its DOM with
// textContent, and the few places that assign innerHTML (the 3D hover tooltip) pass esc() output;
// no event handler attribute is ever built from data.

/** The pinned 3D library (bundles three.js). Checked with `curl -sI`; the hash is of the fetched file. */
export const FG3D = {
  url: 'https://cdn.jsdelivr.net/npm/3d-force-graph@1.80.1/dist/3d-force-graph.min.js',
  integrity: 'sha384-i98VDQKdpyVrtyuFn0fjUWJBLBmxnqHqOANcvYe9HLJUgT2wPixa4ZkLd7Dh3VEk',
};

/** JSON safe inside a <script> element: no `</script>`, no `<!--`, no JS line terminators. */
export const embedJson = (v) => JSON.stringify(v).replace(/</g, '\\u003c').replace(/[\u2028\u2029]/g, (c) => '\\u' + c.charCodeAt(0).toString(16));

export function renderHtml(r) {
  const data = {
    root: r.root, generated_at: r.generated_at, source: r.source || null,
    tiers: r.tiers || null, notices: r.notices || [], stats: r.stats || null,
    nodes: r.nodes,
    links: r.links.map(({ source, target, relation, confidence, ops, at }) => ({ source, target, relation, confidence, ops: ops || [], at: (at || []).slice(0, 10) })),
    findings: r.findings.map((f) => ({ rule: f.rule, id: f.id, node: f.node, tier: f.tier, level: f.level, at: f.at, note: f.note, message: f.message, roles: f.roles, usedBy: f.usedBy, securityDefiner: f.securityDefiner, sites: f.sites, confidence: f.confidence })),
    rules: r.rules.map(({ id, level, tier, title, why }) => ({ id, level, tier, title, why })),
    fg3d: FG3D,
  };
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>supareach: ${escapeHtml(r.root)}</title>
<style>${CSS}</style></head><body>
<div id="app">
<aside id="side">
  <header>
    <div class="brand"><span class="mark"></span><h1>supareach <span class="muted" id="rootname"></span></h1><button id="theme" class="ghost" title="Toggle light / dark">◐</button></div>
    <nav id="tabs" role="tablist">
      <button role="tab" data-view="path" class="on">Path</button>
      <button role="tab" data-view="map">Full map</button>
      <button role="tab" data-view="3d" title="Showcase mode: loads a pinned 3D library from jsDelivr">3D</button>
    </nav>
    <input id="q" type="search" placeholder="Search findings and objects" autocomplete="off" spellcheck="false">
    <div id="chips"></div>
  </header>
  <div id="list"></div>
</aside>
<main id="main">
  <div id="bar"><span id="crumb"></span><span class="sp"></span><button id="fit" class="ghost" title="Fit to view">fit</button></div>
  <div id="stage">
    <svg id="svg" xmlns="http://www.w3.org/2000/svg"><g id="vp"></g></svg>
    <div id="overview"></div>
    <div id="card" hidden></div>
    <div id="three" hidden><div id="three-canvas"></div><div id="three-labels"></div><div id="three-msg" hidden></div></div>
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
:root{--bg:#0b0e14;--panel:#10141c;--panel2:#151a24;--fg:#dfe6ef;--muted:#8792a2;--line:#232a36;--edge:rgba(150,170,200,.28);--edgehi:#e6edf6;
--code:#4fb8b0;--entry:#e0953c;--db:#b9c8de;--fn:#8fb0e0;--pol:#9aa7b8;--role:#d6dde7;--fix:#e5534b;--review:#d4a72c;--info:#7d8796;--sel:#5cc8d8;--chip:#1b2130}
:root[data-theme=light]{--bg:#f6f7f9;--panel:#ffffff;--panel2:#f0f2f5;--fg:#1d232b;--muted:#5d6775;--line:#dde1e7;--edge:rgba(60,75,95,.28);--edgehi:#1d232b;
--code:#16867e;--entry:#b5651d;--db:#3d5a80;--fn:#2f5fa7;--pol:#5f6b7a;--role:#39424e;--fix:#c93c37;--review:#a77b06;--info:#6b7480;--sel:#0f7c8c;--chip:#eceff3}
@media (prefers-color-scheme:light){:root:not([data-theme=dark]){--bg:#f6f7f9;--panel:#ffffff;--panel2:#f0f2f5;--fg:#1d232b;--muted:#5d6775;--line:#dde1e7;--edge:rgba(60,75,95,.28);--edgehi:#1d232b;
--code:#16867e;--entry:#b5651d;--db:#3d5a80;--fn:#2f5fa7;--pol:#5f6b7a;--role:#39424e;--fix:#c93c37;--review:#a77b06;--info:#6b7480;--sel:#0f7c8c;--chip:#eceff3}}
*{box-sizing:border-box}html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);font:13px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
button{font:inherit;color:inherit;background:var(--chip);border:1px solid var(--line);border-radius:6px;padding:3px 9px;cursor:pointer}
button.ghost{background:transparent}button:focus-visible,input:focus-visible{outline:2px solid var(--sel);outline-offset:1px}
.muted{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
#app{display:flex;height:100%}
#side{width:360px;min-width:280px;max-width:42vw;display:flex;flex-direction:column;background:var(--panel);border-right:1px solid var(--line)}
#side header{padding:12px 12px 8px;border-bottom:1px solid var(--line);display:flex;flex-direction:column;gap:8px}
.brand{display:flex;align-items:center;gap:8px}.brand h1{font-size:14px;font-weight:600;margin:0;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.mark{width:10px;height:10px;border-radius:2px;background:var(--code);box-shadow:5px 5px 0 -1px var(--entry)}
#tabs{display:flex;gap:4px}#tabs button{flex:1;background:transparent}#tabs button.on{background:var(--chip);border-color:var(--sel);color:var(--fg)}
input[type=search]{width:100%;padding:6px 9px;border:1px solid var(--line);border-radius:6px;background:var(--panel2);color:var(--fg);font:inherit}
#chips{display:flex;flex-wrap:wrap;gap:5px}
.chip{font-size:12px;padding:1px 8px;border-radius:999px;background:transparent;color:var(--muted)}.chip.on{background:var(--chip);color:var(--fg);border-color:var(--muted)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:0}
#list{overflow:auto;flex:1;padding:4px 0 16px}
.grp{position:sticky;top:0;background:var(--panel);padding:10px 12px 4px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);display:flex;justify-content:space-between;z-index:1}
.item{display:block;width:100%;text-align:left;border:0;border-left:3px solid transparent;border-radius:0;background:transparent;padding:6px 12px 7px 10px}
.item:hover{background:var(--panel2)}.item.on{background:var(--panel2);border-left-color:var(--sel)}
.item .r{font-size:11px;color:var(--muted)}.item .n{font-weight:600;word-break:break-all}.item .w{color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.item.t-fix .n::before,.item.t-review .n::before,.item.t-info .n::before{content:"";display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px;vertical-align:1px}
.item.t-fix .n::before{background:var(--fix)}.item.t-review .n::before{background:var(--review)}.item.t-info .n::before{background:var(--info)}
.empty{padding:10px 12px;color:var(--muted)}
#main{flex:1;display:flex;flex-direction:column;min-width:0}
#bar{display:flex;align-items:center;gap:8px;padding:8px 12px;border-bottom:1px solid var(--line);min-height:41px}#bar .sp{flex:1}
#crumb{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#stage{position:relative;flex:1;min-height:0;overflow:hidden}
#svg{width:100%;height:100%;display:block;cursor:grab;user-select:none}#svg.drag{cursor:grabbing}
#overview{position:absolute;inset:0;overflow:auto;padding:28px;display:none}
#overview .cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;max-width:900px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
.card .k{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}.card .v{font-size:26px;font-weight:600;font-variant-numeric:tabular-nums}
.card.fix .v{color:var(--fix)}.card.review .v{color:var(--review)}.card.info .v{color:var(--info)}
#overview h2{font-size:13px;margin:22px 0 8px;color:var(--muted);font-weight:600}
#overview p{max-width:640px}
#card{position:absolute;left:12px;top:12px;max-width:min(440px,calc(100% - 24px));max-height:calc(100% - 24px);overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px;box-shadow:0 6px 24px rgba(0,0,0,.25)}
#card h3{margin:0 0 4px;font-size:14px;word-break:break-all}#card .why{color:var(--muted);margin:6px 0 0}#card dl{margin:6px 0 0;display:grid;grid-template-columns:auto 1fr;gap:2px 10px}#card dt{color:var(--muted)}#card dd{margin:0;word-break:break-all}
#card .x{float:right;margin:-2px -4px 0 8px}
.badge{display:inline-block;font-size:11px;font-weight:600;padding:0 7px;border-radius:999px;margin-right:6px;color:#0b0e14}
.badge.fix{background:var(--fix)}.badge.review{background:var(--review)}.badge.info{background:var(--info)}
svg text{fill:var(--fg);font:12px ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
svg .colh{fill:var(--muted);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
svg .box rect{fill:var(--panel);stroke:var(--line)}svg .box .stripe{stroke:none}svg .box.hi rect.bg{stroke:var(--sel);stroke-width:2}
svg .box.fix rect.bg{stroke:var(--fix);stroke-width:1.5}svg .box.review rect.bg{stroke:var(--review)}
svg .box .sub{fill:var(--muted);font-size:10.5px}svg .box{cursor:pointer}
svg .ghostbox rect{fill:none;stroke:var(--muted);stroke-dasharray:4 3}svg .ghostbox text{fill:var(--muted);font-style:italic}
svg path.e{fill:none;stroke:var(--edge);stroke-width:1.4}svg path.e.inf{stroke-dasharray:5 4}svg path.e.amb{stroke-dasharray:1.5 3.5}
svg path.e.hi{stroke:var(--edgehi);stroke-width:1.8}svg path.e.dim{opacity:.15}
svg .dot2{stroke:var(--panel);stroke-width:1.5}svg .dimmed{opacity:.18}
svg .mlabel{font-size:11px;paint-order:stroke;stroke:var(--bg);stroke-width:3px}
#three{position:absolute;inset:0;background:#05070d}#three-canvas{position:absolute;inset:0}
#three-labels{position:absolute;inset:0;pointer-events:none;overflow:hidden;z-index:2}
#three-labels div{position:absolute;transform:translate(-50%,-150%);font:11px ui-sans-serif,system-ui,sans-serif;color:#cfe3f5;white-space:nowrap;text-shadow:0 0 6px #05070d,0 0 2px #05070d;opacity:.85}
#three-labels div.fix{color:#ff9a92}
#three-msg{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);color:#cfe3f5;background:rgba(16,20,28,.9);border:1px solid #2a3240;border-radius:8px;padding:12px 16px;z-index:3;max-width:80%;text-align:center}
.scene-tooltip .tip{font:12px ui-sans-serif,system-ui,sans-serif;color:#e6edf6;background:rgba(10,14,22,.88);border:1px solid #2a3240;border-radius:6px;padding:3px 8px}
.scene-tooltip .tip span{color:#8792a2;margin-left:6px}
@media (max-width:760px){#app{flex-direction:column}#side{width:100%;max-width:none;height:46%;border-right:0;border-bottom:1px solid var(--line)}#main{min-height:0}}
`;

// The client script avoids backticks and `${` (it lives inside a template literal) and never puts
// data into innerHTML except through esc().
const CLIENT = String.raw`
(function(){
"use strict";
var D=JSON.parse(document.getElementById('data').textContent);
var SVGNS='http://www.w3.org/2000/svg';
var esc=function(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})};
function h(tag,attrs){var el=document.createElement(tag);if(attrs)for(var k in attrs){if(k==='text')el.textContent=attrs[k];else if(k==='cls')el.className=attrs[k];else el.setAttribute(k,attrs[k])}for(var i=2;i<arguments.length;i++){var c=arguments[i];if(c==null)continue;el.appendChild(typeof c==='string'?document.createTextNode(c):c)}return el}
function s(tag,attrs){var el=document.createElementNS(SVGNS,tag);if(attrs)for(var k in attrs){if(k==='text')el.textContent=attrs[k];else el.setAttribute(k,attrs[k])}return el}
var $=function(id){return document.getElementById(id)};
$('rootname').textContent=D.root;

/* ---------- model ---------- */
var byId=new Map(),inc=new Map(),out=new Map();
D.nodes.forEach(function(n){byId.set(n.id,n);inc.set(n.id,[]);out.set(n.id,[])});
D.links.forEach(function(e){if(!byId.has(e.source)||!byId.has(e.target))return;out.get(e.source).push(e);inc.get(e.target).push(e)});
var rules=new Map(D.rules.map(function(r){return[r.id,r]}));
var TIER_OF={error:'fix',warning:'review',note:'info'};
D.findings.forEach(function(f){if(!f.tier)f.tier=TIER_OF[f.level]||'review'});
var byNode=new Map();D.findings.forEach(function(f){if(!f.node)return;if(!byNode.has(f.node))byNode.set(f.node,[]);byNode.get(f.node).push(f)});
var RANK={fix:0,review:1,info:2};
var worst=function(id){var fs=byNode.get(id);if(!fs)return null;return fs.slice().sort(function(a,b){return RANK[a.tier]-RANK[b.tier]})[0].tier};
var COLNAME=['Code','Entry points','Database','Roles'];
var COL={file:0,folder:0,nocaller:0,edge_function:1,bucket:1,external:1,api:1,table:2,view:2,'function':2,cron:2,policy:2,group:2,role:3,more:-1};
var KINDNAME={api:'Data API',file:'file',folder:'folder',edge_function:'edge function',bucket:'storage bucket',external:'external caller',table:'table',view:'view','function':'function',cron:'cron / SQL',policy:'policies',role:'role',nocaller:'',group:'group'};
var PLURAL={file:'code files',edge_function:'edge functions',bucket:'storage buckets',table:'tables',view:'views','function':'functions',cron:'cron / SQL',external:'external callers'};
var cssVar=function(n){return getComputedStyle(document.documentElement).getPropertyValue(n).trim()};
var kindVar=function(t){return t==='file'||t==='folder'?'--code':t==='edge_function'||t==='bucket'||t==='external'||t==='api'?'--entry':t==='function'?'--fn':t==='policy'?'--pol':t==='role'?'--role':'--db'};
var folderOf=function(l){var p=String(l).split('/');return p.length>2?p.slice(0,2).join('/'):p.length>1?p[0]:'(root)'};
var short=function(x,n){x=String(x);return x.length>n?x.slice(0,n-1)+'\u2026':x};
var shortPath=function(x,n){x=String(x);return x.length>n?'\u2026'+x.slice(-(n-1)):x};

/* ---------- state ---------- */
var state={view:'path',sel:null,node:null,q:'',tiers:{fix:true,review:true,info:true},kinds:{functions:true,tables:true,edge:true,other:true},expanded:new Set(),mapSel:null};
var kindOfFinding=function(f){var n=f.node&&byId.get(f.node);var t=n?n.type:'';return t==='function'?'functions':t==='table'||t==='view'?'tables':t==='edge_function'?'edge':'other'};

/* ---------- sidebar ---------- */
var chips=$('chips');
function chip(label,on,cls,onClick){var b=h('button',{cls:'chip'+(on?' on':''),type:'button'});if(cls)b.appendChild(h('span',{cls:'dot',style:'background:var('+cls+')'}));b.appendChild(document.createTextNode(label));b.addEventListener('click',onClick);return b}
function renderChips(){chips.textContent='';
  [['fix','Fix','--fix'],['review','Review','--review'],['info','Info','--info']].forEach(function(t){chips.appendChild(chip(t[1],state.tiers[t[0]],t[2],function(){state.tiers[t[0]]=!state.tiers[t[0]];renderChips();renderList()}))});
  [['functions','Functions'],['tables','Tables'],['edge','Edge'],['other','Other']].forEach(function(k){chips.appendChild(chip(k[1],state.kinds[k[0]],null,function(){state.kinds[k[0]]=!state.kinds[k[0]];renderChips();renderList()}))})}
var list=$('list');
var matchQ=function(f,q){if(!q)return true;return [f.rule,f.id,f.at,f.note,f.message].some(function(x){return x&&String(x).toLowerCase().indexOf(q)>=0})};
var whyOf=function(f){var r=rules.get(f.rule);return f.note||f.message||(r?r.title:'')};
function renderList(){list.textContent='';var q=state.q;var any=false;
  ['fix','review','info'].forEach(function(t){
    var all=D.findings.filter(function(f){return f.tier===t});
    var items=all.filter(function(f){return state.tiers[t]&&state.kinds[kindOfFinding(f)]&&matchQ(f,q)});
    var g=h('div',{cls:'grp'},h('span',{text:t==='fix'?'Fix':t==='review'?'Review':'Info'}),h('span',{text:(items.length!==all.length?items.length+' / ':'')+all.length}));
    list.appendChild(g);
    if(!items.length){list.appendChild(h('div',{cls:'empty',text:all.length?'Hidden by filters.':'Nothing in this tier.'}));return}
    any=true;
    items.slice(0,600).forEach(function(f){
      var b=h('button',{cls:'item t-'+t+(state.sel===f?' on':''),type:'button'},h('div',{cls:'r mono',text:f.rule}),h('div',{cls:'n',text:f.id}),h('div',{cls:'w',text:whyOf(f)}));
      b.addEventListener('click',function(){selectFinding(f)});list.appendChild(b)});
    if(items.length>600)list.appendChild(h('div',{cls:'empty',text:(items.length-600)+' more: narrow the search.'}));
  });
  if(q.length>=2){var objs=D.nodes.filter(function(n){return String(n.label).toLowerCase().indexOf(q)>=0}).slice(0,30);
    list.appendChild(h('div',{cls:'grp'},h('span',{text:'Objects'}),h('span',{text:String(objs.length)})));
    if(!objs.length)list.appendChild(h('div',{cls:'empty',text:'No object matches.'}));
    objs.forEach(function(n){var b=h('button',{cls:'item'+(state.node===n.id&&!state.sel?' on':''),type:'button'},h('div',{cls:'r',text:KINDNAME[n.type]||n.type}),h('div',{cls:'n',text:n.label}));b.addEventListener('click',function(){selectNode(n.id)});list.appendChild(b)})}
  if(!D.nodes.length){list.textContent='';list.appendChild(h('div',{cls:'empty',text:'The graph is empty: no code call sites and no schema objects were found. Check the warnings printed by the CLI (0 files scanned, 0 migrations) and set include / supabaseDir in supareach.config.json.'}))}
}
$('q').addEventListener('input',function(ev){state.q=ev.target.value.trim().toLowerCase();renderList()});
$('q').addEventListener('keydown',function(ev){if(ev.key==='Enter'){var f=D.findings.find(function(x){return state.tiers[x.tier]&&matchQ(x,state.q)});if(f)selectFinding(f)}if(ev.key==='Escape'){ev.target.value='';state.q='';renderList()}});

function selectFinding(f){state.sel=f;state.node=f.node||null;renderList();renderCard();if(state.view==='3d')fly3d(f.node);else{if(state.view==='map'){state.mapSel=f.node;}draw()}}
function selectNode(id){state.sel=null;state.node=id;renderList();renderCard();if(state.view==='3d')fly3d(id);else draw()}
function clearSel(){state.sel=null;state.node=null;state.mapSel=null;renderList();renderCard();if(state.view==='3d')reset3d();else draw()}

/* ---------- detail card ---------- */
var card=$('card');
function row(dl,k,v){if(v==null||v===''||(Array.isArray(v)&&!v.length))return;dl.appendChild(h('dt',{text:k}));dl.appendChild(h('dd',{text:Array.isArray(v)?v.join(', '):String(v)}))}
function renderCard(){card.textContent='';var f=state.sel,n=state.node&&byId.get(state.node);if(!f&&!n){card.hidden=true;return}card.hidden=false;
  var x=h('button',{cls:'ghost x',type:'button',title:'Close'},'\u00d7');x.addEventListener('click',clearSel);card.appendChild(x);
  if(f){var r=rules.get(f.rule)||{};card.appendChild(h('div',null,h('span',{cls:'badge '+f.tier,text:f.tier}),h('span',{cls:'mono muted',text:f.rule})));
    card.appendChild(h('h3',{text:f.id}));var dl=h('dl');row(dl,'Where',f.at);row(dl,'Callable by',f.roles);row(dl,'Used by',f.usedBy);if(f.securityDefiner)row(dl,'Runs as','owner (SECURITY DEFINER)');row(dl,'Call sites',f.sites);row(dl,'Confidence',f.confidence);row(dl,'Note',f.note||f.message);card.appendChild(dl);
    if(r.title)card.appendChild(h('p',{cls:'why'},h('strong',{text:r.title+'. '}),document.createTextNode(String(r.why||'').replace(/\x60/g,''))))}
  else{card.appendChild(h('div',null,h('span',{cls:'mono muted',text:KINDNAME[n.type]||n.type})));card.appendChild(h('h3',{text:n.label}));var dl2=h('dl');row(dl2,'Where',n.at);
    ['rls','policies','securityDefiner','anon','authenticated','returns','verifyJwt','entryPoint','schedule','securityInvoker'].forEach(function(a){if(n[a]!==undefined&&n[a]!==null)row(dl2,a,String(n[a]))});
    row(dl2,'Callers',String((inc.get(n.id)||[]).length));row(dl2,'Uses',String((out.get(n.id)||[]).length));card.appendChild(dl2);
    var fs=byNode.get(n.id)||[];fs.forEach(function(ff){var b=h('button',{type:'button',cls:'ghost'},h('span',{cls:'badge '+ff.tier,text:ff.tier}),document.createTextNode(ff.rule));b.style.marginTop='6px';b.addEventListener('click',function(){selectFinding(ff)});card.appendChild(h('div',null,b))})}
}

/* ---------- path view: a finding's neighbourhood in columns ---------- */
var MAXN=25;
function neighbourhood(id,f){
  var V=new Map(),E=[],over=[0,0,0,0];
  var add=function(v){if(V.has(v.id))return true;if(V.size>=MAXN){var c=COL[v.type];if(c>=0)over[c]++;return false}V.set(v.id,v);return true};
  var real=function(nid){var n=byId.get(nid);return n?{id:n.id,type:n.type,label:n.label,n:n}:null};
  var c=real(id);if(!c)return null;add(c);
  var n=c.n;var ins=(inc.get(id)||[]).slice(),outs=(out.get(id)||[]).slice();
  var pri=function(e){return /^(rpc|from|invoke|storage)/.test(e.relation)?0:/policy/.test(e.relation)?1:2};
  ins.sort(function(a,b){return pri(a)-pri(b)});
  /* many files: collapse to folders */
  var files=ins.filter(function(e){var s=byId.get(e.source);return s&&s.type==='file'});
  var foldered=files.length>8;
  var callers=0;
  /* The Data API doorway: /rpc/<fn> for functions anon/authenticated can execute, /<table> for client-read tables. */
  var apiId=null;var viaApi=function(rel){return /^(rpc|from)/.test(rel)};
  var exposed=n.type==='function'?(n.anon||n.authenticated):(n.type==='table'||n.type==='view')&&(!Array.isArray(n.clientPrivs)||n.clientPrivs.length>0);
  if(exposed&&!n.missing){apiId='api:'+id;add({id:apiId,type:'api',label:(n.type==='function'?'/rpc/':'/')+String(n.label).split('.').pop(),sub:'Data API (PostgREST)'});E.push({s:apiId,t:id,rel:'Data API',conf:'extracted'})}
  var link=function(src,e){var to=apiId&&viaApi(e.relation)?apiId:id;E.push({s:src,t:to,rel:e.relation,conf:e.confidence,at:e.at})};
  ins.forEach(function(e){var sN=byId.get(e.source);if(!sN)return;callers++;
    if(foldered&&sN.type==='file'){var fid='folder:'+folderOf(sN.label);if(add({id:fid,type:'folder',label:folderOf(sN.label)+'/'}))link(fid,e);return}
    if(add({id:sN.id,type:sN.type,label:sN.label,n:sN}))link(sN.id,e)});
  outs.slice(0,10).forEach(function(e){var tN=byId.get(e.target);if(!tN)return;if(add({id:tN.id,type:tN.type,label:tN.label,n:tN}))E.push({s:id,t:tN.id,rel:e.relation,conf:e.confidence,at:e.at})});
  /* roles */
  var roles=[];
  if(n.type==='function'){if(n.anon)roles.push('anon');if(n.authenticated)roles.push('authenticated')}
  if((n.type==='table'||n.type==='view')&&Array.isArray(n.clientPrivs)&&n.clientPrivs.length)roles.push('anon / authenticated');
  if(f&&f.roles&&f.roles.length&&!roles.length)roles=f.roles.slice();
  roles.forEach(function(r){var rid='role:'+r;if(add({id:rid,type:'role',label:r,sub:n.type==='function'?'EXECUTE':(n.clientPrivs||[]).join(', ')}))E.push({s:rid,t:id,rel:n.type==='function'?'can execute':'privileges: '+(n.clientPrivs||[]).join(', '),conf:'extracted',rev:true})});
  /* policies / RLS */
  if(n.type==='table'){var pid='policy:'+id;if(add({id:pid,type:'policy',label:(n.policies||0)+' polic'+(n.policies===1?'y':'ies'),sub:n.rls?'RLS on':'RLS off'}))E.push({s:id,t:pid,rel:'policies',conf:'extracted'})}
  /* nobody calls it */
  var codeCallers=ins.filter(function(e){var sN=byId.get(e.source);return sN&&(sN.type==='file'||sN.type==='edge_function'||sN.type==='external'||sN.type==='cron')}).length;
  if(!callers||(f&&/uncalled/.test(f.rule)&&!codeCallers)){var nid='none:'+id;add({id:nid,type:'nocaller',label:'no caller in code',ghost:true});E.push({s:nid,t:apiId||id,rel:'none',conf:'ambiguous',ghost:true})}
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
$('fit').addEventListener('click',function(){if(state.view==='3d')reset3d();else fit()});
window.addEventListener('resize',function(){if(state.view!=='3d')fit()});
var onBox=function(el,fn){el.addEventListener('click',function(ev){if(moved)return;ev.stopPropagation();fn()})};
svg.addEventListener('click',function(){if(!moved&&state.view==='map'&&state.mapSel){state.mapSel=null;draw()}});

function textW(t,px){return String(t).length*(px||12)*0.58}
function curve(x1,y1,x2,y2){var dx=Math.max(40,Math.abs(x2-x1)*0.45);if(x2<x1)dx=-dx;return'M'+x1+','+y1+' C'+(x1+dx)+','+y1+' '+(x2-dx)+','+y2+' '+x2+','+y2}

/* path view layout: four columns, stacked boxes (no overlap by construction) */
function drawPath(){vp.textContent='';var id=state.node;var nb=neighbourhood(id,state.sel);if(!nb){showOverview();return}
  $('overview').style.display='none';svg.style.display='block';
  var W=Math.max(760,svg.clientWidth);var colW=W/4;var boxW=Math.min(230,colW-36);var rowH=46,top=56;
  var cols=[[],[],[],[]];nb.V.forEach(function(v){var c=v.type==='more'?v.col:COL[v.type];if(c==null||c<0)c=2;cols[c].push(v)});
  cols.forEach(function(arr){arr.sort(function(a,b){if(a.id===id)return -1;if(b.id===id)return 1;if(a.type==='more')return 1;if(b.type==='more')return -1;return String(a.label).localeCompare(String(b.label))})});
  var maxRows=Math.max.apply(null,cols.map(function(a){return a.length}).concat([1]));
  var H=top+maxRows*rowH+20;var pos=new Map();
  cols.forEach(function(arr,ci){var x=ci*colW+(colW-boxW)/2;var y0=top+(maxRows-arr.length)*rowH/2;
    vp.appendChild(s('text',{x:ci*colW+colW/2,y:28,'text-anchor':'middle','class':'colh',text:COLNAME[ci]}));
    arr.forEach(function(v,i){pos.set(v.id,{x:x,y:y0+i*rowH,w:boxW,h:rowH-12})})});
  vp.insertBefore(s('line',{x1:0,y1:38,x2:W,y2:38,stroke:'var(--line)'}),vp.firstChild);
  var eg=s('g');vp.appendChild(eg);
  nb.E.forEach(function(e){var a=pos.get(e.s),b=pos.get(e.t);if(!a||!b)return;var p;
    if(a.x<b.x)p=curve(a.x+a.w,a.y+a.h/2,b.x,b.y+b.h/2);else if(a.x>b.x)p=curve(a.x,a.y+a.h/2,b.x+b.w,b.y+b.h/2);else p='M'+(a.x+a.w)+','+(a.y+a.h/2)+' C'+(a.x+a.w+50)+','+(a.y+a.h/2)+' '+(b.x+b.w+50)+','+(b.y+b.h/2)+' '+(b.x+b.w)+','+(b.y+b.h/2);
    var el=s('path',{d:p,'class':'e'+(e.conf==='inferred'?' inf':e.conf==='ambiguous'?' amb':'')+(e.s===id||e.t===id?' hi':'')});
    el.appendChild(s('title',{text:e.rel+(e.at&&e.at.length?' \u2014 '+e.at.slice(0,3).join(', '):'')}));eg.appendChild(el)});
  nb.V.forEach(function(v){var p=pos.get(v.id);if(!p)return;var t=v.id===id?(state.sel?state.sel.tier:worst(v.id)):worst(v.id);
    var g=s('g',{'class':(v.ghost?'ghostbox':'box')+(v.id===id?' hi':'')+(t==='fix'?' fix':t==='review'?' review':''),transform:'translate('+p.x+','+p.y+')'});
    g.appendChild(s('rect',{'class':'bg',width:p.w,height:p.h,rx:6}));
    if(!v.ghost)g.appendChild(s('rect',{'class':'stripe',width:4,height:p.h,rx:2,fill:'var('+kindVar(v.type)+')'}));
    var maxC=Math.floor((p.w-18)/7);var label=v.type==='file'||v.type==='folder'?shortPath(v.label,maxC):short(v.label,maxC);
    g.appendChild(s('text',{x:12,y:v.ghost||!(KINDNAME[v.type]||v.sub)?p.h/2+4:15,text:label}));
    if(!v.ghost){var sub=v.sub||KINDNAME[v.type]||'';if(t)sub+=(sub?' \u00b7 ':'')+t;g.appendChild(s('text',{x:12,y:29,'class':'sub',text:short(sub,maxC+4)}))}
    g.appendChild(s('title',{text:v.label}));
    if(!v.ghost&&byId.has(v.id)&&v.id!==id)onBox(g,function(){selectNode(v.id)});
    vp.appendChild(g)});
  bounds={x:0,y:0,w:W,h:H};fit();
  var n=byId.get(id);$('crumb').textContent='';$('crumb').appendChild(h('span',{cls:'muted',text:'Path \u00b7 '}));$('crumb').appendChild(document.createTextNode(n?n.label:id));
}

/* ---------- full map: same columns, folders and schema+kind groups collapsed ---------- */
function mapModel(){var rep=new Map(),V=new Map();
  var groupOf=function(n){if(n.type==='file')return{id:'folder:'+folderOf(n.label),type:'folder',label:folderOf(n.label)+'/'};
    if(n.type==='table'||n.type==='view'||n.type==='function'||n.type==='cron'){var sc=n.schema||(String(n.label).indexOf('.')>0?String(n.label).split('.')[0]:'public');var key='grp:'+sc+':'+n.type;return{id:key,type:'group',kind:n.type,label:sc+' \u00b7 '+(n.type==='function'?'functions':n.type==='cron'?'cron / SQL':n.type+'s')}}return null};
  D.nodes.forEach(function(n){var g=groupOf(n);var v;
    if(g&&!state.expanded.has(g.id)){v=V.get(g.id);if(!v){v=Object.assign({members:0,fix:0,review:0},g);V.set(g.id,v)}v.members++;var w=worst(n.id);if(w==='fix')v.fix++;else if(w==='review')v.review++}
    else{v=V.get(n.id);if(!v){v={id:n.id,type:n.type,label:n.label,n:n,parent:g&&g.id};V.set(n.id,v)}}
    rep.set(n.id,v.id)});
  ['anon','authenticated'].forEach(function(r){V.set('role:'+r,{id:'role:'+r,type:'role',label:r})});
  var E=new Map();var addE=function(a,b,rel){if(a===b)return;var k=a+'|'+b;var e=E.get(k);if(!e){e={s:a,t:b,count:0,rels:new Set()};E.set(k,e)}e.count++;e.rels.add(rel)};
  D.links.forEach(function(e){var a=rep.get(e.source),b=rep.get(e.target);if(a&&b)addE(a,b,e.relation)});
  D.nodes.forEach(function(n){var b=rep.get(n.id);if(n.type==='function'){if(n.anon)addE('role:anon',b,'execute');if(n.authenticated)addE('role:authenticated',b,'execute')}
    if((n.type==='table'||n.type==='view')&&Array.isArray(n.clientPrivs)&&n.clientPrivs.length){addE('role:anon',b,'privileges');addE('role:authenticated',b,'privileges')}});
  return{V:V,E:[...E.values()]}}
function drawMap(){vp.textContent='';$('overview').style.display='none';svg.style.display='block';
  var m=mapModel();var W=Math.max(900,svg.clientWidth);var colW=W/4;
  var cols=[[],[],[],[]];m.V.forEach(function(v){var c=v.type==='group'?2:COL[v.type];if(c==null||c<0)c=2;cols[c].push(v)});
  cols.forEach(function(arr){arr.sort(function(a,b){return (b.fix||0)-(a.fix||0)||String(a.label).localeCompare(String(b.label))})});
  var pos=new Map();var maxH=0;
  var avail=Math.max(400,svg.clientHeight-80);
  cols.forEach(function(arr,ci){var y=60;var cx=ci*colW+colW/2;vp.appendChild(s('text',{x:cx,y:28,'text-anchor':'middle','class':'colh',text:COLNAME[ci]+' ('+arr.length+')'}));
    var gap=Math.max(3,Math.min(22,avail/Math.max(1,arr.length)-9));
    arr.forEach(function(v){var r=v.type==='group'||v.type==='folder'?Math.min(22,5+Math.sqrt(v.members||1)*1.6):v.type==='role'?9:4.5;pos.set(v.id,{x:cx,y:y+r,r:r});y+=r*2+(v.type==='group'||v.type==='role'?Math.max(gap,26):gap)});maxH=Math.max(maxH,y)});
  var sel=state.mapSel;var near=null;if(sel){near=new Set([sel]);m.E.forEach(function(e){if(e.s===sel)near.add(e.t);if(e.t===sel)near.add(e.s)})}
  var eg=s('g');vp.appendChild(eg);
  m.E.forEach(function(e){var a=pos.get(e.s),b=pos.get(e.t);if(!a||!b)return;var on=sel&&(e.s===sel||e.t===sel);
    var el=s('path',{d:a.x===b.x?'M'+a.x+','+a.y+' C'+(a.x+80)+','+a.y+' '+(b.x+80)+','+b.y+' '+b.x+','+b.y:curve(a.x+(a.x<b.x?a.r:-a.r),a.y,b.x+(a.x<b.x?-b.r:b.r),b.y),'class':'e'+(on?' hi':sel?' dim':''),'stroke-width':String(Math.min(6,1+Math.log2(e.count)))});
    el.appendChild(s('title',{text:[...e.rels].join(', ')+' \u00d7'+e.count}));eg.appendChild(el)});
  m.V.forEach(function(v){var p=pos.get(v.id);var g=s('g',{transform:'translate('+p.x+','+p.y+')','class':sel&&!near.has(v.id)?'dimmed':''});
    var t=v.type==='group'?(v.fix?'fix':v.review?'review':null):worst(v.id);
    g.appendChild(s('circle',{r:p.r,fill:'var('+kindVar(v.type==='group'?v.kind:v.type)+')','class':'dot2','fill-opacity':v.type==='group'||v.type==='folder'?0.55:0.95}));
    if(t)g.appendChild(s('circle',{r:p.r+3,fill:'none',stroke:'var(--'+t+')','stroke-width':1.8}));
    var ci=v.type==='group'?2:COL[v.type];var showLabel=v.type==='group'||v.type==='role'||(cols[ci]&&cols[ci].length<=25)||(v.type==='folder'&&cols[0].length<=40)||v.id===sel||(near&&near.has(v.id));
    var lab=s('text',{x:p.r+6,y:4,'class':'mlabel',text:(v.type==='group'||v.type==='folder'?short(v.label,34)+' ('+v.members+')':short(v.label,40))+(v.fix?' \u00b7 '+v.fix+' fix':'')});
    if(!showLabel)lab.setAttribute('visibility','hidden');g.appendChild(lab);
    g.addEventListener('mouseenter',function(){lab.setAttribute('visibility','visible')});g.addEventListener('mouseleave',function(){if(!showLabel)lab.setAttribute('visibility','hidden')});
    g.style.cursor='pointer';g.appendChild(s('title',{text:v.label+(v.type==='group'||v.type==='folder'?' \u2014 click to expand':'')}));
    onBox(g,function(){if(v.type==='group'||v.type==='folder'){state.expanded.add(v.id);draw()}else if(v.parent&&state.mapSel===v.id){state.expanded.delete(v.parent);state.mapSel=null;draw()}else{state.mapSel=v.id;if(byId.has(v.id)){state.node=v.id;state.sel=null;renderCard();renderList()}draw()}});
    vp.appendChild(g)});
  bounds={x:0,y:0,w:W,h:maxH+20};fit();
  $('crumb').textContent='';$('crumb').appendChild(h('span',{cls:'muted',text:'Full map \u00b7 '}));$('crumb').appendChild(document.createTextNode(m.V.size+' nodes; click a group to expand it, click an expanded object twice to collapse its group'));
}

/* ---------- overview (nothing selected) ---------- */
function showOverview(){svg.style.display='none';var o=$('overview');o.style.display='block';o.textContent='';
  $('crumb').textContent='';$('crumb').appendChild(h('span',{cls:'muted',text:'Overview'}));
  var t=D.tiers||{fix:0,review:0,info:0};var c=h('div',{cls:'cards'});
  [['fix','Fix'],['review','Review'],['info','Info']].forEach(function(x){c.appendChild(h('div',{cls:'card '+x[0]},h('div',{cls:'k',text:x[1]}),h('div',{cls:'v',text:String(t[x[0]]||0)})))});
  o.appendChild(c);
  o.appendChild(h('p',{cls:'muted',text:'Select a finding on the left to see its path: the code that reaches it (or that nothing does), the entry point, the database object and the roles that can call it. Fix first: high confidence. Review: same kinds of problem with a caveat. Info: intended patterns.'}));
  o.appendChild(h('h2',{text:'Objects'}));var c2=h('div',{cls:'cards'});
  var cnt={};D.nodes.forEach(function(n){cnt[n.type]=(cnt[n.type]||0)+1});
  ['file','edge_function','bucket','table','view','function','cron','external'].forEach(function(k){if(cnt[k])c2.appendChild(h('div',{cls:'card'},h('div',{cls:'k',text:PLURAL[k]}),h('div',{cls:'v',text:String(cnt[k])})))});
  o.appendChild(c2);
  (D.notices||[]).forEach(function(n){o.appendChild(h('p',{cls:'muted',text:n}))});
}

function draw(){if(state.view==='path'){if(state.node&&byId.has(state.node))drawPath();else showOverview()}else if(state.view==='map')drawMap()}

/* ---------- tabs and theme ---------- */
document.querySelectorAll('#tabs button').forEach(function(b){b.addEventListener('click',function(){setView(b.getAttribute('data-view'))})});
function setView(v){state.view=v;document.querySelectorAll('#tabs button').forEach(function(b){b.classList.toggle('on',b.getAttribute('data-view')===v)});
  var three=$('three');if(v==='3d'){three.hidden=false;svg.style.display='none';$('overview').style.display='none';$('crumb').textContent='';$('crumb').appendChild(h('span',{cls:'muted',text:'3D · '}));$('crumb').appendChild(document.createTextNode('drag to spin, scroll to zoom, click a finding to fly to it'));open3d()}else{three.hidden=true;pause3d();draw()}}
$('theme').addEventListener('click',function(){var r=document.documentElement;var dark=r.dataset.theme?r.dataset.theme==='dark':!matchMedia('(prefers-color-scheme: light)').matches;r.dataset.theme=dark?'light':'dark';draw()});

/* ---------- 3D showcase (lazy, pinned, SRI) ---------- */
var G3=null,loading=false,nodes3=null,links3=null,hl=null,labelled=[],raf=0,lastPatch=0,interacted=false;
var msg=function(t){var m=$('three-msg');if(t==null){m.hidden=true;return}m.hidden=false;m.textContent=t};
function open3d(){if(G3){resume3d();return}if(loading)return;loading=true;msg('Loading the 3D library from jsDelivr\u2026');
  if(typeof window.ForceGraph3D==='function'){loading=false;start3d();return}
  var sc=document.createElement('script');sc.src=D.fg3d.url;sc.integrity=D.fg3d.integrity;sc.crossOrigin='anonymous';sc.async=true;
  var fail=function(){loading=false;msg('3D view needs internet (it loads one pinned library from jsDelivr); the 2D views work offline.')};
  var timer=setTimeout(fail,20000);
  sc.onload=function(){clearTimeout(timer);loading=false;if(typeof window.ForceGraph3D!=='function'){fail();return}start3d()};
  sc.onerror=function(){clearTimeout(timer);fail()};document.head.appendChild(sc)}
var C3={file:'#3fb8b0',folder:'#3fb8b0',edge_function:'#f0a04b',bucket:'#e8b04a',external:'#f2c46d',table:'#dfe8f5',view:'#c3d3ea','function':'#8fb4ee',cron:'#a9b8cf'};
function build3d(){var big=D.nodes.length>1500;var rep=new Map(),N=new Map();
  D.nodes.forEach(function(n){var v;if(big&&n.type==='file'){var id='folder:'+folderOf(n.label);v=N.get(id);if(!v){v={id:id,type:'folder',label:folderOf(n.label)+'/',deg:0,members:0};N.set(id,v)}v.members++}else{v={id:n.id,type:n.type,label:n.label,deg:0,tier:worst(n.id)};N.set(n.id,v)}rep.set(n.id,v.id)});
  var L=new Map();D.links.forEach(function(e){var a=rep.get(e.source),b=rep.get(e.target);if(!a||!b||a===b)return;var k=a+'|'+b;if(!L.has(k)){L.set(k,{source:a,target:b,rel:e.relation});N.get(a).deg++;N.get(b).deg++}});
  nodes3=[...N.values()];links3=[...L.values()];
  var hubs=nodes3.filter(function(n){return !n.tier}).sort(function(a,b){return b.deg-a.deg}).slice(0,Math.max(3,Math.min(12,Math.round(nodes3.length/25))));
  labelled=nodes3.filter(function(n){return n.tier==='fix'}).slice(0,40).concat(hubs)}
function val3(n){return n.tier==='fix'?6:n.type==='folder'?2+Math.sqrt(n.members||1):1+Math.min(6,Math.sqrt(n.deg))}
function col3(n){var base=n.tier==='fix'?'#ff5a4f':(C3[n.type]||'#cfd8e6');if(!hl||hl.has(n.id))return base;return hexA(base,0.1)}
function hexA(hex,a){var x=parseInt(hex.slice(1),16);return'rgba('+(x>>16&255)+','+(x>>8&255)+','+(x&255)+','+a+')'}
function start3d(){msg(null);build3d();var el=$('three-canvas');
  try{
  G3=window.ForceGraph3D({controlType:'orbit'})(el).backgroundColor('#05070d').showNavInfo(false).width(el.clientWidth).height(el.clientHeight)
    .nodeId('id').nodeVal(val3).nodeRelSize(3).nodeResolution(nodes3.length>1000?6:10)
    .nodeColor(col3).nodeOpacity(0.92).nodeLabel(function(n){return'<div class="tip">'+esc(n.label)+'<span>'+esc(KINDNAME[n.type]||n.type)+(n.tier?' \u00b7 '+esc(n.tier):'')+'<\/span><\/div>'})
    .linkColor(function(l){var on=!hl||(hl.has(sid(l.source))&&hl.has(sid(l.target)));return on?'rgba(130,170,215,0.55)':'rgba(130,170,215,0.04)'}).linkOpacity(0.35).linkWidth(0)
    .linkDirectionalParticles(function(l){if(hl)return hl.has(sid(l.source))&&hl.has(sid(l.target))?2:0;return links3.length<=700?1:(isFix(l.source)||isFix(l.target))?1:0})
    .linkDirectionalParticleSpeed(0.0035).linkDirectionalParticleWidth(1.3).linkDirectionalParticleColor(function(){return'#7fd8ff'})
    .warmupTicks(nodes3.length>800?40:20).cooldownTicks(nodes3.length>800?150:300)
    .onEngineStop(function(){if(!interacted&&!hl)G3.zoomToFit(900,60)})
    .onNodeClick(function(n){var fs=byNode.get(n.id);if(fs)selectFinding(fs[0]);else if(byId.has(n.id))selectNode(n.id);else fly3d(n.id)})
    .graphData({nodes:nodes3,links:links3});
  }catch(e){msg('3D view could not start ('+String(e&&e.message||e)+'); the 2D views still work.');G3=null;return}
  var ctl=G3.controls();if(ctl){ctl.autoRotate=true;ctl.autoRotateSpeed=0.45}
  ['pointerdown','wheel','touchstart'].forEach(function(t){el.addEventListener(t,function(){interacted=true;var c=G3&&G3.controls();if(c)c.autoRotate=false},{passive:true})});
  window.addEventListener('resize',function(){if(G3&&state.view==='3d')G3.width(el.clientWidth).height(el.clientHeight)});
  setTimeout(function(){stars();halos()},600);setTimeout(function(){if(G3&&!interacted&&!hl)G3.zoomToFit(900,60)},2500);resume3d();if(state.node)setTimeout(function(){fly3d(state.node)},900)}
var sid=function(x){return typeof x==='object'?x.id:x};
var isFix=function(x){var n=typeof x==='object'?x:null;return n?n.tier==='fix':false};
/* Glow: additive blending and emissive colour on the node materials the library creates. */
function patch(){if(!nodes3)return;nodes3.forEach(function(n){var o=n.__threeObj;if(!o||!o.material||o.material.__sr)return;var m=o.material;m.__sr=true;m.transparent=true;m.depthWrite=false;m.blending=2;if(m.emissive&&m.color){m.emissive.copy(m.color);m.emissiveIntensity=0.55}})}
/* A sparse starfield, built from the same classes the library uses (it does not expose three.js). */
function stars(){try{var o=null;for(var i=0;i<nodes3.length&&!o;i++)o=nodes3[i].__threeObj;if(!o)return;
  var Mesh=o.constructor,Geo=o.geometry.constructor,Mat=o.material.constructor;var geo=new Geo(1.2,4,3);var mat=new Mat({color:0xbfcbe0,emissive:0x8796b0,transparent:true,opacity:0.55,depthWrite:false});mat.__sr=true;
  var sc=G3.scene();for(var j=0;j<260;j++){var r=1400+Math.random()*1800,t=Math.random()*Math.PI*2,p=Math.acos(2*Math.random()-1);var m=new Mesh(geo,mat);m.position.set(r*Math.sin(p)*Math.cos(t),r*Math.sin(p)*Math.sin(t),r*Math.cos(p));var k=0.5+Math.random()*1.4;m.scale.set(k,k,k);sc.add(m)}}catch(e){/* decorative only */}}
/* Soft halos (additive, translucent) around fix-tier nodes and hubs: the glow. */
var haloSet=[];
function halos(){try{var o=null;for(var i=0;i<nodes3.length&&!o;i++)o=nodes3[i].__threeObj;if(!o)return;var Mesh=o.constructor,Geo=o.geometry.constructor,Mat=o.material.constructor;var geo=new Geo(1,16,12);var mats={};
  labelled.forEach(function(n){var obj=n.__threeObj;if(!obj)return;var c=n.tier==='fix'?'#ff5a4f':(C3[n.type]||'#cfd8e6');var m=mats[c];if(!m){m=new Mat({color:c,emissive:c,transparent:true,opacity:0.22,depthWrite:false});m.blending=2;m.__sr=true;mats[c]=m}
    var halo=new Mesh(geo,m);var r=Math.cbrt(val3(n))*3*2.6;halo.scale.set(r,r,r);halo.__halo=true;obj.add(halo);haloSet.push({n:n,h:halo})})}catch(e){/* decorative only */}}
var labelEls=new Map();
function frame(ts){raf=requestAnimationFrame(frame);if(!G3)return;if(ts-lastPatch>500){patch();lastPatch=ts}
  var pulse=1+0.22*Math.sin(ts/420);nodes3.forEach(function(n){if(n.tier==='fix'&&n.__threeObj)n.__threeObj.scale.set(pulse,pulse,pulse)});
  var box=$('three-labels');var cam=G3.camera(),ctl=G3.controls();var tgt=ctl&&ctl.target?ctl.target:{x:0,y:0,z:0};
  var fx=tgt.x-cam.position.x,fy=tgt.y-cam.position.y,fz=tgt.z-cam.position.z;
  var show=labelled;if(hl)show=nodes3.filter(function(n){return hl.has(n.id)}).slice(0,30);
  var keep=new Set(),placed=[];
  show.forEach(function(n){if(n.x==null)return;var d=(n.x-cam.position.x)*fx+(n.y-cam.position.y)*fy+(n.z-cam.position.z)*fz;if(d<=0)return;var p=G3.graph2ScreenCoords(n.x,n.y,n.z);
    /* greedy collision avoidance: findings first (they come first in the list), then hubs */
    var w=Math.min(36,String(n.label).length)*6.2,bx={x0:p.x-w/2,x1:p.x+w/2,y0:p.y-24,y1:p.y-8};
    if(placed.some(function(b){return bx.x0<b.x1&&bx.x1>b.x0&&bx.y0<b.y1&&bx.y1>b.y0}))return;placed.push(bx);
    var el=labelEls.get(n.id);if(!el){el=document.createElement('div');el.textContent=short(n.label,36);if(n.tier==='fix')el.className='fix';box.appendChild(el);labelEls.set(n.id,el)}
    el.style.left=p.x+'px';el.style.top=p.y+'px';el.style.display='block';keep.add(n.id)});
  labelEls.forEach(function(el,id){if(!keep.has(id))el.style.display='none'})}
function resume3d(){if(!raf)raf=requestAnimationFrame(frame);if(G3&&G3.resumeAnimation)G3.resumeAnimation()}
function pause3d(){if(raf){cancelAnimationFrame(raf);raf=0}if(G3&&G3.pauseAnimation)G3.pauseAnimation()}
function fly3d(id){if(!G3||!nodes3)return;var n=nodes3.find(function(x){return x.id===id});if(!n){var b=byId.get(id);if(b&&b.type==='file')n=nodes3.find(function(x){return x.id==='folder:'+folderOf(b.label)})}if(!n||n.x==null)return;
  hl=new Set([n.id]);links3.forEach(function(l){var a=sid(l.source),b=sid(l.target);if(a===n.id)hl.add(b);if(b===n.id)hl.add(a)});
  refresh3d();var c=G3.controls();if(c)c.autoRotate=false;var dist=170,r=Math.hypot(n.x,n.y,n.z)||1,k=1+dist/r;G3.cameraPosition({x:n.x*k,y:n.y*k,z:n.z*k},{x:n.x,y:n.y,z:n.z},1000)}
function reset3d(){if(!G3)return;hl=null;refresh3d();G3.zoomToFit(800,40)}
function refresh3d(){G3.nodeColor(col3).linkColor(G3.linkColor()).linkDirectionalParticles(G3.linkDirectionalParticles());lastPatch=0}

/* Deep links: #f=<rule>:<subject> (or f=first) selects a finding; view=map|3d opens that view. */
var hp=new URLSearchParams(location.hash.slice(1));var hf=hp.get('f');
if(hf){var order=D.findings.slice().sort(function(a,b){return RANK[a.tier]-RANK[b.tier]});var ff=hf==='first'?order[0]:D.findings.find(function(x){return x.rule+':'+x.id===hf});if(ff){state.sel=ff;state.node=ff.node||null}}
renderChips();renderList();renderCard();draw();
var hv=hp.get('view');if(hv==='map'||hv==='3d')setView(hv);
})();
`;
