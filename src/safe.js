// Output escaping and path containment. Everything tracegrid prints or writes can contain names
// that came from the scanned project (a fork PR controls those), so it is treated as untrusted data.
import fs from 'node:fs';
import path from 'node:path';

/** One console line: control characters escaped, so data can never start a new line (and a workflow command). */
export function oneLine(s) {
  const t = String(s ?? '').replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, (c) => {
    if (c === '\n') return '\\n';
    if (c === '\r') return '\\r';
    if (c === '\t') return ' ';
    return '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0');
  });
  // A line starting with `::` is a GitHub Actions workflow command.
  return t.startsWith('::') ? ' ' + t : t;
}

/** Inline Markdown code span for untrusted text: one line, no backticks, never empty. */
export function mdCode(s) {
  const t = oneLine(s).replace(/`/g, "'");
  return '`' + (t.trim() ? t : ' ') + '`';
}

/** Untrusted text in Markdown prose or a table cell: one line, Markdown and HTML metacharacters escaped. */
export function mdText(s) {
  return oneLine(s).replace(/[\\`*_[\]<>|#!~{}]/g, (c) => (c === '<' ? '&lt;' : c === '>' ? '&gt;' : '\\' + c));
}

/** Real path; for a path that does not exist (yet), the real path of its nearest existing ancestor plus the rest. */
export function realOr(p) {
  const abs = path.resolve(p);
  try { return fs.realpathSync.native(abs); } catch { /* fall through */ }
  const parent = path.dirname(abs);
  return parent === abs ? abs : path.join(realOr(parent), path.basename(abs));
}

/** True when `p` is `root` or inside it (both compared as real paths, so symlinks cannot escape). */
export function isInside(root, p) {
  const r = realOr(root);
  const x = realOr(p);
  const rel = path.relative(r, x);
  return rel === '' || (!!rel && !rel.startsWith('..') && !path.isAbsolute(rel));
}
