// Rule contract and runner. Core rules and plugin rules go through the same path.
//
// A rule is { id, level, title, why, run({ graph, catalog, config, root }) => Finding[] }.
// A finding is { id, at?, node?, message?, ...extra }: `id` names the subject (a function, table,
// edge function...) and must be stable across runs; the runner adds `rule`, `level` and
// `fingerprint` (`<rule>:<id>`), which is what the baseline stores.
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { isInside } from './safe.js';

export const LEVELS = ['error', 'warning', 'note'];
const RULE_ID = /^[a-z0-9][a-z0-9_.\/-]*$/;

export class RuleError extends Error {}

/** Throw a RuleError if `r` does not satisfy the rule contract. */
export function validateRule(r, origin = 'rule') {
  const where = `${origin}${r && r.id ? ` (${r.id})` : ''}`;
  if (!r || typeof r !== 'object') throw new RuleError(`${origin}: a rule must be an object`);
  if (typeof r.id !== 'string' || !RULE_ID.test(r.id)) throw new RuleError(`${where}: id must match ${RULE_ID}`);
  if (!LEVELS.includes(r.level)) throw new RuleError(`${where}: level must be one of ${LEVELS.join(', ')}`);
  for (const k of ['title', 'why']) if (typeof r[k] !== 'string' || !r[k].trim()) throw new RuleError(`${where}: ${k} must be a non-empty string`);
  if (typeof r.run !== 'function') throw new RuleError(`${where}: run must be a function`);
}

/** GitHub Actions events that run code from a fork (or with fork-controlled inputs). */
const UNTRUSTED_EVENTS = new Set(['pull_request', 'pull_request_target']);

/**
 * Why plugins may not run in this environment, or null. Plugins are arbitrary code from the
 * repository; on a pull_request event that repository is the PR author's.
 */
export function pluginRefusal(env = process.env) {
  if (env.GITHUB_ACTIONS === 'true' && UNTRUSTED_EVENTS.has(env.GITHUB_EVENT_NAME)) {
    return `plugins are refused on GitHub "${env.GITHUB_EVENT_NAME}" events: the plugin code would come from the pull request. Run without --allow-plugins (or with --no-plugins) on pull requests.`;
  }
  return null;
}

/**
 * Import plugin modules listed in config.plugins (paths relative to the config's directory).
 * Every path must resolve inside `root`.
 */
export async function loadPlugins(baseDir, paths = [], { root } = {}) {
  const out = [];
  for (const p of paths) {
    if (typeof p !== 'string' || !p) throw new RuleError('plugins must be an array of paths');
    const abs = path.resolve(baseDir, p);
    if (root && !isInside(root, abs)) throw new RuleError(`plugin ${p}: resolves outside the project root; plugins must live inside the project`);
    let mod;
    try { mod = await import(pathToFileURL(abs).href); } catch (e) { throw new RuleError(`plugin ${p}: ${e.message}`); }
    const rules = mod.rules || (mod.default && mod.default.rules) || mod.default;
    if (!Array.isArray(rules)) throw new RuleError(`plugin ${p}: must export \`rules\` (an array)`);
    for (const r of rules) { validateRule(r, `plugin ${p}`); out.push({ ...r, plugin: p }); }
  }
  return out;
}

/** Run rules; returns { findings, suppressed, rules } with findings stamped and sorted. */
export function runRules(rules, ctx, suppress = () => null) {
  const seen = new Set();
  const findings = [];
  const suppressed = [];
  for (const r of rules) {
    if (seen.has(r.id)) throw new RuleError(`duplicate rule id ${r.id}`);
    seen.add(r.id);
    let res;
    try { res = r.run(ctx) || []; } catch (e) { throw new RuleError(`rule ${r.id} threw: ${e.message}`); }
    if (!Array.isArray(res)) throw new RuleError(`rule ${r.id}: run() must return an array`);
    const ids = new Set();
    for (const f of res) {
      if (!f || typeof f.id !== 'string' || !f.id) throw new RuleError(`rule ${r.id}: every finding needs a string id`);
      if (ids.has(f.id)) continue; // one finding per subject
      ids.add(f.id);
      const out = { rule: r.id, level: f.level && LEVELS.includes(f.level) ? f.level : r.level, ...f, fingerprint: `${r.id}:${f.id}` };
      out.rule = r.id;
      const why = suppress(out);
      if (why) suppressed.push({ ...out, suppressed: why });
      else findings.push(out);
    }
  }
  const order = (a, b) => (a.rule === b.rule ? a.id.localeCompare(b.id) : 0);
  findings.sort(order);
  suppressed.sort(order);
  return { findings, suppressed, rules: rules.map(({ id, level, title, why, plugin }) => ({ id, level, title, why, ...(plugin ? { plugin } : {}) })) };
}

/**
 * Read-only view over the graph for rules: `nodes`, `links` (each { source, target, relation,
 * confidence, ops, at, count }), and `node(id)`, `incoming(id)`, `outgoing(id)`.
 */
export function makeGraph(nodes, links) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const inc = new Map();
  const out = new Map();
  const push = (m, k, v) => { if (!m.has(k)) m.set(k, []); m.get(k).push(v); };
  for (const e of links) { push(inc, e.target, e); push(out, e.source, e); }
  return {
    nodes, links,
    node: (id) => byId.get(id),
    incoming: (id) => inc.get(id) || [],
    outgoing: (id) => out.get(id) || [],
  };
}
