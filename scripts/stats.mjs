#!/usr/bin/env node
// Adoption numbers from public sources only (tracegrid itself sends nothing anywhere):
// npm downloads, GitHub stars, and public repositories that run tracegrid in CI or commit its files.
// GitHub code search needs a token: GITHUB_TOKEN, or `gh auth token` when the gh CLI is signed in.
// Usage: node scripts/stats.mjs [--json]
import { execFileSync } from 'node:child_process';

const PKG = 'tracegrid';
const REPO = 'EdanBarrios/tracegrid';
const MAX_BASELINES = 100; // baseline files fetched to count findings (each is one API call)

function token() {
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN;
  try { return execFileSync('gh', ['auth', 'token'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return null; }
}
const gh = token();

async function get(url, { auth = false, accept = 'application/vnd.github+json' } = {}) {
  const headers = { accept, 'user-agent': 'tracegrid-stats' };
  if (auth && gh) headers.authorization = `Bearer ${gh}`;
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`${res.status} ${url}`);
  return res.json();
}

async function npm() {
  const out = {};
  for (const [k, range] of [['lastWeek', 'last-week'], ['lastMonth', 'last-month'], ['total', `2026-10-01:${new Date().toISOString().slice(0, 10)}`]]) {
    try { out[k] = (await get(`https://api.npmjs.org/downloads/point/${range}/${PKG}`)).downloads ?? 0; } catch { out[k] = null; }
  }
  return out;
}

async function repo() {
  try {
    const r = await get(`https://api.github.com/repos/${REPO}`, { auth: true });
    return { stars: r.stargazers_count, forks: r.forks_count, openIssues: r.open_issues_count };
  } catch { return null; }
}

/**
 * Public repositories (other than tracegrid's own) matching code searches, with the matching file paths.
 * Code search is fuzzy, so a hit counts only when its file name or a matched fragment contains `must`.
 */
async function codeSearch(queries, must) {
  const repos = new Map();
  for (const q of queries) for (let page = 1; page <= 10; page++) {
    const r = await get(`https://api.github.com/search/code?per_page=100&page=${page}&q=${encodeURIComponent(`${q} -repo:${REPO}`)}`, { auth: true, accept: 'application/vnd.github.text-match+json' });
    for (const it of r.items) {
      if (!must.test(it.name) && !(it.text_matches || []).some((m) => must.test(m.fragment))) continue;
      const name = it.repository.full_name;
      if (!repos.has(name)) repos.set(name, []);
      if (!repos.get(name).includes(it.path)) repos.get(name).push(it.path);
    }
    if (r.items.length < 100) break;
  }
  return repos;
}

/** Fingerprints recorded in public baselines: findings teams reviewed and are tracking. */
async function baselineFindings(repos) {
  let files = 0, findings = 0;
  for (const [name, paths] of repos) {
    for (const p of paths) {
      if (files >= MAX_BASELINES) return { files, findings, truncated: true };
      try {
        const f = await get(`https://api.github.com/repos/${name}/contents/${p.split('/').map(encodeURIComponent).join('/')}`, { auth: true });
        const json = JSON.parse(Buffer.from(f.content, 'base64').toString('utf8'));
        if (json.tool === 'tracegrid' && Array.isArray(json.findings)) { findings += json.findings.length; files++; }
      } catch { /* unreadable or not a tracegrid baseline: skip */ }
    }
  }
  return { files, findings, truncated: false };
}

const stats = { at: new Date().toISOString(), npm: await npm(), github: await repo() };
if (gh) {
  try {
    const ci = await codeSearch(['"tracegrid@" path:.github/workflows', '"EdanBarrios/tracegrid" path:.github/workflows', '"npx tracegrid" path:.github/workflows'], /\btracegrid@|EdanBarrios\/tracegrid|npx (?:--yes )?tracegrid\b/);
    const baselines = await codeSearch(['filename:tracegrid.baseline.json'], /^tracegrid\.baseline\.json$/);
    const configs = await codeSearch(['filename:tracegrid.config.json'], /^tracegrid\.config\.json$/);
    stats.publicRepos = {
      ci: ci.size,
      baseline: baselines.size,
      config: configs.size,
      any: new Set([...ci.keys(), ...baselines.keys(), ...configs.keys()]).size,
    };
    stats.baselineFindings = await baselineFindings(baselines);
    stats.ciRepos = [...ci.keys()].sort();
  } catch (e) { stats.codeSearchError = e.message; }
} else stats.codeSearchError = 'no token: set GITHUB_TOKEN or sign in with gh';

if (process.argv.includes('--json')) { console.log(JSON.stringify(stats, null, 2)); process.exit(0); }
const n = (v) => (v == null ? 'n/a' : v.toLocaleString('en-US'));
console.log(`tracegrid adoption, ${stats.at.slice(0, 10)}`);
console.log(`npm downloads       week ${n(stats.npm.lastWeek)} · month ${n(stats.npm.lastMonth)} · since launch ${n(stats.npm.total)}  (includes CI runs)`);
if (stats.github) console.log(`GitHub              ${n(stats.github.stars)} stars · ${n(stats.github.forks)} forks · ${n(stats.github.openIssues)} open issues/PRs`);
if (stats.publicRepos) {
  const p = stats.publicRepos, b = stats.baselineFindings;
  console.log(`Public repos        ${n(p.any)} total · ${n(p.ci)} in CI · ${n(p.baseline)} with a baseline · ${n(p.config)} with a config`);
  console.log(`Baseline findings   ${n(b.findings)} across ${n(b.files)} files${b.truncated ? ` (first ${MAX_BASELINES} files)` : ''}`);
  for (const r of stats.ciRepos.slice(0, 20)) console.log(`  ci: ${r}`);
} else console.log(`Code search skipped: ${stats.codeSearchError}`);
console.log('\nPublic repositories only; private use is invisible by design. Downloads are not users.');
