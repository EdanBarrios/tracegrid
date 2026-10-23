// Shared test helpers. Fixtures are synthetic and generated in temp dirs.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** Write { relpath: text | Buffer } into a fresh temp dir; returns the dir. */
export function project(files, prefix = 'supareach-test-') {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  for (const [p, t] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(d, p)), { recursive: true });
    fs.writeFileSync(path.join(d, p), t);
  }
  return d;
}
export const rm = (d) => fs.rmSync(d, { recursive: true, force: true });
