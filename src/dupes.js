// Near-duplicate function bodies: the same endpoint written twice, usually by sessions that did not
// know about each other. Bodies are tokenized with local names and literals normalized away (member
// names and keywords kept), then compared as sets of 5-token shingles.

const KEYWORDS = new Set(('async await function return if else for while do switch case break continue try catch finally throw new const let var '
  + 'typeof instanceof in of class extends this super null undefined true false import export from default yield delete void '
  + 'select insert update delete from where join left right inner on and or not as into values set returning begin end declare '
  + 'language plpgsql sql security definer invoker create replace returns table perform raise exception notice is exists group by order limit having union').split(' '));

/** Tokens of a function body: identifiers -> `I` (except after `.` and keywords), strings -> `S`, numbers -> `N`. */
export function tokens(body) {
  const out = [];
  const re = /\/\/[^\n]*|\/\*[\s\S]*?\*\/|--[^\n]*|(['"`])(?:\\.|(?!\1)[^\\])*\1|\d+(?:\.\d+)?|[A-Za-z_$][\w$]*|[^\s\w]/g;
  let m;
  let prevDot = false;
  while ((m = re.exec(body))) {
    const t = m[0];
    if (t.startsWith('//') || t.startsWith('/*') || t.startsWith('--')) continue;
    if (m[1]) out.push('S');
    else if (/^\d/.test(t)) out.push('N');
    else if (/^[A-Za-z_$]/.test(t)) out.push(prevDot || KEYWORDS.has(t.toLowerCase()) ? t.toLowerCase() : 'I');
    else out.push(t);
    prevDot = t === '.';
  }
  return out;
}

function shingles(toks, k = 5) {
  const s = new Set();
  for (let i = 0; i + k <= toks.length; i++) s.add(toks.slice(i, i + k).join(' '));
  return s;
}

/**
 * Groups of near-duplicate items: [{ names: [..], similarity }]. `items` is [{ name, body }]; bodies
 * under `minTokens` tokens are skipped (one-liners look alike without being duplicates).
 */
export function duplicateGroups(items, { threshold = 0.85, minTokens = 60 } = {}) {
  const prepared = items.map((it) => ({ ...it, toks: tokens(it.body || '') })).filter((it) => it.toks.length >= minTokens)
    .map((it) => ({ ...it, sh: shingles(it.toks) }));
  const parent = prepared.map((_, i) => i);
  const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const best = new Map();
  for (let i = 0; i < prepared.length; i++) {
    for (let j = i + 1; j < prepared.length; j++) {
      const a = prepared[i];
      const b = prepared[j];
      // Lengths far apart cannot reach the threshold.
      if (Math.min(a.sh.size, b.sh.size) / Math.max(a.sh.size, b.sh.size) < threshold) continue;
      let inter = 0;
      for (const x of a.sh) if (b.sh.has(x)) inter++;
      const sim = inter / (a.sh.size + b.sh.size - inter);
      if (sim >= threshold) {
        parent[find(i)] = find(j);
        for (const k of [i, j]) best.set(k, Math.max(best.get(k) || 0, sim));
      }
    }
  }
  const groups = new Map();
  prepared.forEach((it, i) => { const r = find(i); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(i); });
  return [...groups.values()].filter((g) => g.length > 1)
    .map((g) => ({ names: g.map((i) => prepared[i].name).sort(), similarity: Math.round(Math.min(...g.map((i) => best.get(i))) * 100) / 100 }))
    .sort((a, b) => a.names[0].localeCompare(b.names[0]));
}
