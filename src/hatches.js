// In-source hatches: greppable comments that feed facts to supareach or silence a finding.
//
//   // supareach: names a,b,c                 resolve a dynamic name on this/next line (or in this wrapper)
//   // supareach: ignore <rule> <reason>      silence <rule> for the call(s) on this or the next line
//   -- supareach: ignore <rule> <reason>      (SQL) silence <rule> for the object created by the next statement
//   // supareach: entry-point <reason>        (edge function) called from outside the codebase
//
// `ignore` and `entry-point` silence findings, so they need a reason. `names` only adds facts.

const RE = /(?:\/\/|--|\/\*|^\s*\*)\s*supareach:\s*([a-z-]+)(?:[ \t]+(.*?))?\s*(?:\*\/\s*)?$/;
export const DIRECTIVES = ['names', 'ignore', 'entry-point'];

/** @returns {{ line: number, directive: string, args: string, error?: string, rule?: string, reason?: string, names?: string[] }[]} */
export function parseHatches(text) {
  const out = [];
  if (!text.includes('supareach:')) return out;
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = RE.exec(lines[i]);
    if (!m) continue;
    const h = { line: i + 1, directive: m[1], args: (m[2] || '').trim() };
    if (!DIRECTIVES.includes(h.directive)) h.error = `unknown directive "${h.directive}" (expected ${DIRECTIVES.join(', ')})`;
    else if (h.directive === 'names') {
      h.names = h.args.split(/[\s,]+/).filter(Boolean);
      if (!h.names.length) h.error = 'names: list at least one name';
    } else if (h.directive === 'ignore') {
      const p = /^(\S+)\s+(.+)$/.exec(h.args);
      if (!p) h.error = 'ignore: needs a rule id and a reason, e.g. `supareach: ignore missing-rpc created by the billing service`';
      else { h.rule = p[1]; h.reason = p[2]; }
    } else if (h.directive === 'entry-point') {
      if (!h.args) h.error = 'entry-point: needs a reason, e.g. `supareach: entry-point Stripe webhook`';
      else h.reason = h.args;
    }
    out.push(h);
  }
  return out;
}
