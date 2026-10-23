// Single self-contained graph.html: no CDN, canvas force layout, search, click for edges, dark/light.
export function renderHtml(r) {
  const data = { root: r.root, generated_at: r.generated_at, nodes: r.nodes, links: r.links.map(({ source, target, relation, confidence, ops, at }) => ({ source, target, relation, confidence, ops, at: at.slice(0, 10) })), findings: r.findings, rules: r.rules };
  const json = JSON.stringify(data).replace(/</g, '\\u003c').replace(/[\u2028\u2029]/g, (c) => '\\u' + c.charCodeAt(0).toString(16));
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>supareach: ${escapeHtml(r.root)}</title>
<style>
:root{--bg:#fbfbfa;--fg:#1c1c1c;--muted:#6b6b6b;--panel:#ffffff;--line:#d9d9d6;--edge:rgba(60,60,60,.18);--hi:#d9480f;
--table:#2f7d32;--view:#5c9e5f;--function:#1f5fbf;--edge_function:#8a3ffc;--file:#9a9a9a;--bucket:#b7791f;--cron:#c2185b;--external:#0b7285;--folder:#9a9a9a;--bad:#e03131}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#141414;--fg:#e8e8e6;--muted:#9a9a98;--panel:#1d1d1d;--line:#333;--edge:rgba(220,220,220,.14);--hi:#ff8a3d;
--table:#5fbf63;--view:#8fcf91;--function:#6ea8ff;--edge_function:#b38bff;--file:#777;--bucket:#e0a84a;--cron:#f06292;--external:#3bc9db;--bad:#ff6b6b}}
:root[data-theme=dark]{--bg:#141414;--fg:#e8e8e6;--muted:#9a9a98;--panel:#1d1d1d;--line:#333;--edge:rgba(220,220,220,.14);--hi:#ff8a3d;
--table:#5fbf63;--view:#8fcf91;--function:#6ea8ff;--edge_function:#b38bff;--file:#777;--bucket:#e0a84a;--cron:#f06292;--external:#3bc9db;--bad:#ff6b6b}
*{box-sizing:border-box}html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);font:13px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
#app{display:flex;height:100%}#side{width:340px;max-width:45vw;border-right:1px solid var(--line);background:var(--panel);display:flex;flex-direction:column}
#side header{padding:12px;border-bottom:1px solid var(--line)}#side h1{font-size:14px;margin:0 0 8px}
input[type=search]{width:100%;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
#types{display:flex;flex-wrap:wrap;gap:6px 10px;margin-top:8px}#types label{display:flex;gap:4px;align-items:center;cursor:pointer}
.sw{width:10px;height:10px;border-radius:50%;display:inline-block}#info{overflow:auto;padding:12px;flex:1}
#info h2{font-size:13px;margin:12px 0 4px}#info ul{margin:0;padding-left:16px}#info li{margin:2px 0;word-break:break-all}
a.n{color:var(--fg);text-decoration:underline dotted;cursor:pointer}.muted{color:var(--muted)}.bad{color:var(--bad)}
#modes{margin-top:6px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}#c{flex:1;display:block;cursor:grab;min-width:0}button{background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:3px 8px;cursor:pointer}
@media (max-width:700px){#app{flex-direction:column}#side{width:100%;max-width:none;height:45%}}
</style></head><body><div id="app"><aside id="side"><header>
<h1>supareach: ${escapeHtml(r.root)} <button id="fit" title="Fit graph to view">fit</button> <button id="theme" title="Toggle theme">theme</button></h1>
<div id="modes"><button id="all" title="Show every node">show all</button> <label title="One node per top-level folder instead of one per file"><input type="checkbox" id="grp"> group files by folder</label></div>
<input id="q" type="search" placeholder="Search nodes (Enter to jump)"><div id="types"></div></header><div id="info"></div></aside>
<canvas id="c"></canvas></div>
<script type="application/json" id="data">${json}</script>
<script>
(function(){
const D=JSON.parse(document.getElementById('data').textContent);
const css=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const TYPES=['table','view','function','edge_function','cron','bucket','external','file','folder'];
const RAW={nodes:D.nodes,links:D.links};
const BIG=RAW.nodes.length>200;
/* Folder of a file node: the first two path segments (src/features, apps/web), or the first one. */
const folderOf=l=>{const p=l.split('/');return p.length>2?p.slice(0,2).join('/'):p.length>1?p[0]:'(root)'};
let NODES,E,adj,byId,flagged;
function build(group){
  const map=new Map(),nodes=[];
  for(const n of RAW.nodes){if(group&&n.type==='file'){const id='folder:'+folderOf(n.label);if(!map.has(id)){const g={id,type:'folder',label:folderOf(n.label)+'/',files:0,side:n.side};map.set(id,g);nodes.push(g)}map.get(id).files++;map.set(n.id,map.get(id))}else{map.set(n.id,n);nodes.push(n)}}
  const seen=new Map();
  for(const e of RAW.links){const s=map.get(e.source),t=map.get(e.target);if(!s||!t||s===t)continue;const key=s.id+'|'+t.id+'|'+e.relation;let x=seen.get(key);
    if(!x){x={...e,source:s.id,target:t.id,s,t,ops:[...e.ops],at:[...e.at]};seen.set(key,x)}else{for(const o of e.ops)if(!x.ops.includes(o))x.ops.push(o);x.at.push(...e.at.slice(0,5-x.at.length>0?5-x.at.length:0))}}
  NODES=nodes;E=[...seen.values()];byId=new Map();adj=new Map();
  NODES.forEach((n,i)=>{n.i=i;n.deg=0;if(n.x===undefined){n.x=Math.cos(i)*300*Math.random();n.y=Math.sin(i)*300*Math.random();n.vx=0;n.vy=0}byId.set(n.id,n);adj.set(n.id,[])});
  E.forEach(e=>{e.s.deg++;e.t.deg++;adj.get(e.source).push(e);adj.get(e.target).push(e)});
  flagged=new Map();for(const it of D.findings){const n=it.node&&map.get(it.node);if(n)flagged.set(n.id,it.rule)}
}
/* Focus set: findings and their neighbours (null = show everything). Clicking a node adds its neighbourhood. */
let focus=null;
function focusFindings(){focus=new Set();for(const id of flagged.keys()){focus.add(id);for(const e of adj.get(id))focus.add(e.source),focus.add(e.target)}if(!focus.size)focus=null}
function expand(n){if(!focus)return;focus.add(n.id);for(const e of adj.get(n.id))focus.add(e.source),focus.add(e.target);alpha=Math.max(alpha,.3)}
build(BIG);if(BIG){document.getElementById('grp').checked=true;focusFindings()}
const shown=new Set(TYPES);let sel=null,match=new Set(),q='';
const tbox=document.getElementById('types');
function legend(){tbox.innerHTML='';TYPES.forEach(t=>{const c=NODES.filter(n=>n.type===t).length;if(!c)return;const l=document.createElement('label');
l.innerHTML='<input type=checkbox '+(shown.has(t)?'checked':'')+'><span class=sw style="background:var(--'+(t==='folder'?'file':t)+')"></span>'+t.replace('_',' ')+' <span class=muted>'+c+'</span>';
l.querySelector('input').onchange=ev=>{ev.target.checked?shown.add(t):shown.delete(t);alpha=Math.max(alpha,.3)};tbox.appendChild(l)})}
legend();
const allBtn=document.getElementById('all');
const syncAll=()=>{allBtn.textContent=focus?'show all':'focus on findings';allBtn.title=focus?'Show every node':'Show findings and their neighbours only'};syncAll();
allBtn.onclick=()=>{if(focus)focus=null;else focusFindings();syncAll();alpha=Math.max(alpha,.5);render();setTimeout(fit,400)};
document.getElementById('grp').onchange=ev=>{const keep=sel&&sel.id;build(ev.target.checked);if(focus)focusFindings();sel=keep&&byId.get(keep)||null;legend();alpha=1;render();setTimeout(fit,400)};
const vis=n=>shown.has(n.type)&&(!focus||focus.has(n.id));
const cv=document.getElementById('c'),ctx=cv.getContext('2d');let W=0,H=0,dpr=1;
function resize(){dpr=window.devicePixelRatio||1;W=cv.clientWidth;H=cv.clientHeight;cv.width=W*dpr;cv.height=H*dpr}
window.addEventListener('resize',()=>{resize();draw()});
let tx=0,ty=0,k=.6,alpha=1;
const rad=n=>3+Math.min(10,Math.sqrt(n.deg)*1.4);
function step(){const N=NODES.filter(vis),cell=60,grid=new Map();
for(const n of N){const key=Math.floor(n.x/cell)+','+Math.floor(n.y/cell);let a=grid.get(key);if(!a)grid.set(key,a=[]);a.push(n)}
for(const n of N){const gx=Math.floor(n.x/cell),gy=Math.floor(n.y/cell);
for(let dx=-2;dx<=2;dx++)for(let dy=-2;dy<=2;dy++){const a=grid.get((gx+dx)+','+(gy+dy));if(!a)continue;
for(const m of a){if(m.i<=n.i)continue;let x=n.x-m.x,y=n.y-m.y,d2=Math.max(x*x+y*y,25);if(d2>14400)continue;const f=900/d2*alpha;n.vx+=x*f/Math.sqrt(d2);n.vy+=y*f/Math.sqrt(d2);m.vx-=x*f/Math.sqrt(d2);m.vy-=y*f/Math.sqrt(d2)}}}
for(const e of E){if(!vis(e.s)||!vis(e.t))continue;const x=e.t.x-e.s.x,y=e.t.y-e.s.y,d=Math.sqrt(x*x+y*y)||1,f=(d-50)*.04*alpha;
const fx=x/d*f,fy=y/d*f;e.s.vx+=fx;e.s.vy+=fy;e.t.vx-=fx;e.t.vy-=fy}
for(const n of N){n.vx-=n.x*.004*alpha;n.vy-=n.y*.004*alpha;const v=Math.hypot(n.vx,n.vy);if(v>40){n.vx*=40/v;n.vy*=40/v}if(n!==drag){n.x+=n.vx;n.y+=n.vy}n.vx*=.55;n.vy*=.55}
alpha*=.985}
function draw(){ctx.setTransform(dpr,0,0,dpr,0,0);ctx.fillStyle=css('--bg');ctx.fillRect(0,0,W,H);
ctx.translate(W/2+tx,H/2+ty);ctx.scale(k,k);
const near=sel&&adj.has(sel.id)?new Set(adj.get(sel.id).flatMap(e=>[e.source,e.target])):null;
ctx.lineWidth=1/k;
for(const e of E){if(!vis(e.s)||!vis(e.t))continue;const on=sel&&(e.s===sel||e.t===sel);
ctx.strokeStyle=on?css('--hi'):css('--edge');if(sel&&!on)ctx.globalAlpha=.25;if(e.confidence!=='extracted')ctx.setLineDash(e.confidence==='ambiguous'?[1.5/k,3/k]:[4/k,3/k]);
ctx.beginPath();ctx.moveTo(e.s.x,e.s.y);ctx.lineTo(e.t.x,e.t.y);ctx.stroke();ctx.setLineDash([]);ctx.globalAlpha=1}
for(const n of NODES){if(!vis(n))continue;const r=rad(n);const dim=(sel&&!near.has(n.id))||(q&&!match.has(n.id));
ctx.globalAlpha=dim?.2:1;ctx.fillStyle=css('--'+n.type);ctx.beginPath();ctx.arc(n.x,n.y,r,0,7);ctx.fill();
if(flagged.has(n.id)||n.missing){ctx.strokeStyle=css('--bad');ctx.lineWidth=2/k;ctx.stroke();ctx.lineWidth=1/k}
if(n===sel||match.has(n.id)&&q){ctx.strokeStyle=css('--hi');ctx.lineWidth=3/k;ctx.stroke();ctx.lineWidth=1/k}
if(!dim&&(focus||NODES.length<150||k>1.1||n.type!=='file'&&n.type!=='folder'&&n.deg>6||n===sel||(near&&near.has(n.id))||(q&&match.has(n.id)))){ctx.fillStyle=css('--fg');ctx.font=(11/k)+'px system-ui';ctx.fillText(short(n.label),n.x+r+2/k,n.y+3/k)}
ctx.globalAlpha=1}}
const short=s=>s.length>40?'…'+s.slice(-39):s;
let refit=NODES.length>800;
function loop(){if(alpha>.02)step();if(refit&&alpha<.05){refit=false;fit()}draw();requestAnimationFrame(loop)}
function toWorld(ev){const b=cv.getBoundingClientRect();return{x:(ev.clientX-b.left-W/2-tx)/k,y:(ev.clientY-b.top-H/2-ty)/k}}
function hit(p){let best=null,bd=1e9;for(const n of NODES){if(!vis(n))continue;const d=(n.x-p.x)**2+(n.y-p.y)**2,r=rad(n)+4/k;if(d<r*r&&d<bd){bd=d;best=n}}return best}
let drag=null,pan=null,moved=false;
cv.addEventListener('mousedown',ev=>{const p=toWorld(ev);drag=hit(p);moved=false;if(!drag)pan={x:ev.clientX-tx,y:ev.clientY-ty}});
window.addEventListener('mousemove',ev=>{if(drag){const p=toWorld(ev);drag.x=p.x;drag.y=p.y;moved=true;alpha=Math.max(alpha,.1)}else if(pan){tx=ev.clientX-pan.x;ty=ev.clientY-pan.y;moved=true}});
window.addEventListener('mouseup',ev=>{if(!moved&&ev.target===cv){select(drag)}drag=null;pan=null});
cv.addEventListener('wheel',ev=>{ev.preventDefault();const f=Math.exp(-ev.deltaY*.0015),b=cv.getBoundingClientRect(),mx=ev.clientX-b.left-W/2,my=ev.clientY-b.top-H/2;
tx=mx-(mx-tx)*f;ty=my-(my-ty)*f;k*=f},{passive:false});
const info=document.getElementById('info');
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const link=id=>{const n=byId.get(id);return '<a class=n data-id="'+esc(id)+'">'+esc(n?n.label:id)+'</a> <span class=muted>'+esc(n?n.type:'')+'</span>'};
info.addEventListener('click',ev=>{const a=ev.target.closest('a.n');if(a){const n=byId.get(a.dataset.id);if(n){shown.add(n.type);if(focus)focus.add(n.id);select(n);center(n)}}});
function center(n){tx=-n.x*k;ty=-n.y*k}
function select(n){sel=n;if(n)expand(n);render()}
function render(){if(!sel){if(!RAW.nodes.length){info.innerHTML='<p class=bad>The graph is empty: no code call sites and no schema objects were found. Check the warnings printed by the CLI (0 files scanned, 0 migrations) and set include / supabaseDir in supareach.config.json.</p>';return}
let h='<p class=muted>'+NODES.length+' nodes, '+E.length+' edges'+(focus?' ('+NODES.filter(vis).length+' shown: findings and their neighbours; click a node to expand it, or use show all)':'')+'. Click a node to see its edges. Dashed links are inferred, dotted are ambiguous. Red rings are findings or missing objects.</p>';
for(const ru of D.rules){const items=D.findings.filter(f=>f.rule===ru.id);if(!items.length)continue;h+='<h2>'+esc(ru.title)+' ('+items.length+')</h2><ul>';
for(const it of items.slice(0,200)){h+='<li>'+(it.node&&byId.has(it.node)?link(it.node):esc(it.id))+'</li>'}h+='</ul>'}
info.innerHTML=h;return}
const n=sel;let h='<h2>'+esc(n.label)+'</h2><div class=muted>'+esc(n.type)+(n.at?' · '+esc(n.at):'')+'</div>';
if(flagged.has(n.id))h+='<p class=bad>Finding: '+esc(flagged.get(n.id))+'</p>';if(n.missing)h+='<p class=bad>Not defined in migrations / functions dir.</p>';
const attrs=['files','rls','policies','securityDefiner','anon','authenticated','returns','verifyJwt','entryPoint','schedule','securityInvoker','overloads'].filter(a=>n[a]!==undefined&&n[a]!==null);
if(attrs.length)h+='<ul>'+attrs.map(a=>'<li>'+a+': '+esc(n[a])+'</li>').join('')+'</ul>';
const out=adj.get(n.id).filter(e=>e.source===n.id),inn=adj.get(n.id).filter(e=>e.target===n.id);
const row=(e,o)=>'<li>'+link(o)+' <span class=muted>'+esc(e.relation)+(e.ops.length?' '+esc(e.ops.join(',')):'')+(e.confidence!=='extracted'?' ('+esc(e.confidence)+')':'')+'</span><br><span class=muted>'+e.at.slice(0,5).map(esc).join('<br>')+'</span></li>';
h+='<h2>Calls / uses ('+out.length+')</h2><ul>'+out.map(e=>row(e,e.target)).join('')+'</ul>';
h+='<h2>Called / used by ('+inn.length+')</h2><ul>'+inn.map(e=>row(e,e.source)).join('')+'</ul><p><button id=clr>Back to findings</button></p>';
info.innerHTML=h;document.getElementById('clr').onclick=()=>select(null)}
const qi=document.getElementById('q');
qi.addEventListener('input',()=>{q=qi.value.trim().toLowerCase();match=new Set(q?NODES.filter(n=>n.label.toLowerCase().includes(q)).map(n=>n.id):[])});
qi.addEventListener('keydown',ev=>{if(ev.key==='Enter'&&match.size){const n=byId.get([...match][0]);shown.add(n.type);if(focus)focus.add(n.id);select(n);center(n)}});
document.getElementById('theme').onclick=()=>{const r=document.documentElement,dark=r.dataset.theme?r.dataset.theme==='dark':matchMedia('(prefers-color-scheme: dark)').matches;r.dataset.theme=dark?'light':'dark'};
function fit(){const N=NODES.filter(vis);if(!N.length)return;const xs=N.map(n=>n.x).sort((a,b)=>a-b),ys=N.map(n=>n.y).sort((a,b)=>a-b),q=f=>Math.floor((N.length-1)*f);
const x0=xs[q(.02)],x1=xs[q(.98)],y0=ys[q(.02)],y1=ys[q(.98)];
k=Math.min(W/(x1-x0+120),H/(y1-y0+120),2.5);tx=-(x0+x1)/2*k;ty=-(y0+y1)/2*k}
document.getElementById('fit').onclick=fit;
resize();render();for(let i=0;i<(NODES.length>800?30:300);i++)step();fit();loop();
})();
</script></body></html>
`;
}

function escapeHtml(s) { return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
