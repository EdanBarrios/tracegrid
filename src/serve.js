// `tracegrid --serve`: graph.html on localhost, with a Refresh button that re-scans the project.
//
// A static graph.html cannot re-run the scan, so this is the one place tracegrid opens a socket. It is
// kept small and closed: it binds 127.0.0.1 only, answers only the five routes below, never takes a path
// or a command from the request, and the one route that does work (POST /refresh) needs a same-origin
// request carrying a custom header (a cross-site page cannot send either). The Host header must be the
// loopback name the server was started on, which is what stops DNS rebinding. It makes no outbound calls.
//
//   GET  /            graph.html with the Refresh button (the file on disk has none)
//   GET  /graph.json  the latest graph, for agents that would rather curl than read a file
//   GET  /report.md   the latest report
//   GET  /status      { generated_at, running, error } (what the page polls under --watch)
//   POST /refresh     re-scan now; concurrent requests share one scan
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

export const DEFAULT_PORT = 4777;
const WATCH_IGNORE = new Set(['node_modules', '.git', '.tracegrid', 'tracegrid-out', '.wrangler']);
const DEBOUNCE_MS = 500;

/**
 * Start the server. `build()` runs one scan and resolves { html, json, report, generated_at, tiers }.
 * `watch` is null or { root, ignore: [absolute paths] }: a change under root triggers a rebuild.
 * Resolves { url, port, close() } once listening; rejects if the first build or the bind fails.
 */
export async function startServer({ build, port = DEFAULT_PORT, watch = null, log = () => {} }) {
  let state = null;
  let error = null;
  let inflight = null;

  const refresh = () => {
    if (!inflight) {
      inflight = build().then((s) => { state = s; error = null; log(`refreshed: Fix ${s.tiers.fix}  Review ${s.tiers.review}  Info ${s.tiers.info}`); },
        (e) => { error = String((e && e.message) || e).split('\n')[0].slice(0, 300); log(`refresh failed: ${error}`); })
        .finally(() => { inflight = null; });
    }
    return inflight;
  };

  await refresh();
  if (!state) throw new Error(error || 'the first scan failed');

  let allowed = new Set();
  const send = (res, code, type, body) => {
    res.writeHead(code, { 'Content-Type': `${type}; charset=utf-8`, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
    res.end(body);
  };
  const sendJson = (res, code, obj) => send(res, code, 'application/json', JSON.stringify(obj));

  const server = http.createServer((req, res) => {
    if (!allowed.has(req.headers.host)) return sendJson(res, 403, { error: 'unexpected Host header' });
    const route = (req.url || '').split('?')[0];
    if (req.method === 'GET') {
      if (route === '/' || route === '/graph.html') return send(res, 200, 'text/html', state.html);
      if (route === '/graph.json') return send(res, 200, 'application/json', state.json);
      if (route === '/report.md') return send(res, 200, 'text/markdown', state.report);
      if (route === '/status') return sendJson(res, 200, { generated_at: state.generated_at, running: !!inflight, error });
      return sendJson(res, 404, { error: 'not found' });
    }
    if (req.method === 'POST' && route === '/refresh') {
      if (req.headers.origin !== `http://${req.headers.host}` || req.headers['x-tracegrid'] !== '1') return sendJson(res, 403, { error: 'refresh needs a same-origin request' });
      req.resume();
      return refresh().then(() => (error ? sendJson(res, 500, { error }) : sendJson(res, 200, { generated_at: state.generated_at, tiers: state.tiers })));
    }
    return sendJson(res, 405, { error: 'method not allowed' });
  });

  await new Promise((resolve, reject) => {
    server.once('error', (e) => reject(e.code === 'EADDRINUSE' ? new Error(`port ${port} is in use; pick another with --port`) : e));
    server.listen(port, '127.0.0.1', resolve);
  });
  const bound = server.address().port;
  allowed = new Set([`127.0.0.1:${bound}`, `localhost:${bound}`]);

  let watcher = null;
  if (watch) {
    let timer = null;
    const ignore = (watch.ignore || []).map((p) => path.resolve(p));
    try {
      watcher = fs.watch(watch.root, { recursive: true }, (_ev, name) => {
        if (name) {
          if (name.split(path.sep).some((seg) => WATCH_IGNORE.has(seg))) return;
          const abs = path.resolve(watch.root, name);
          if (ignore.some((p) => abs === p || abs.startsWith(p + path.sep))) return;
        }
        clearTimeout(timer);
        timer = setTimeout(refresh, DEBOUNCE_MS);
      });
      watcher.on('error', (e) => log(`watch stopped: ${e.message}`));
    } catch (e) { log(`watch unavailable: ${e.message}; use the Refresh button`); }
  }

  return { url: `http://127.0.0.1:${bound}/`, port: bound, close: () => new Promise((resolve) => { if (watcher) watcher.close(); server.close(() => resolve()); server.closeAllConnections?.(); }) };
}
