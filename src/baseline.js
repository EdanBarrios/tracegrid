// Baseline: the set of finding fingerprints (`<rule>:<subject>`) accepted today.
// --check fails on any gated finding whose fingerprint is not in the set; counts are display only,
// so fixing one finding and adding another still fails.
import fs from 'node:fs';
import { SCHEMA_VERSION } from './analyze.js';

/** Findings that gate: errors and warnings. Notes are informational. */
export const gated = (r) => r.findings.filter((f) => f.level !== 'note');

export class BaselineError extends Error {}

export function readBaseline(file) {
  let b;
  try { b = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { throw new BaselineError(`baseline ${file}: ${e.message}`); }
  if (!b || !Array.isArray(b.findings)) throw new BaselineError(`baseline ${file}: expected { "findings": [...] }; regenerate it with --update-baseline --force`);
  return new Set(b.findings);
}

export function compareBaseline(known, r) {
  const now = gated(r);
  const nowSet = new Set(now.map((f) => f.fingerprint));
  return {
    fresh: now.filter((f) => !known.has(f.fingerprint)),
    fixed: [...known].filter((fp) => !nowSet.has(fp)).sort(),
  };
}

/** Write the baseline. With an existing one, refuses to add entries unless force. */
export function writeBaseline(file, r, prev, { force = false } = {}) {
  const next = [...new Set(gated(r).map((f) => f.fingerprint))].sort();
  const added = prev ? next.filter((fp) => !prev.has(fp)) : next;
  const removed = prev ? [...prev].filter((fp) => !next.includes(fp)).sort() : [];
  if (prev && added.length && !force) return { refused: true, added, removed, total: next.length };
  fs.writeFileSync(file, JSON.stringify({ schema_version: SCHEMA_VERSION, tool: 'supareach', findings: next }, null, 2) + '\n');
  return { refused: false, added, removed, total: next.length };
}
