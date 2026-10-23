// Locate the Supabase project inside the scanned directory and read the parts of
// supabase/config.toml that matter: functions (verify_jwt, entrypoint), auth hooks, API schemas.
import fs from 'node:fs';
import path from 'node:path';
import { ConfigError } from './config.js';
import { isInside } from './safe.js';

const SKIP = new Set(['node_modules']);

/** Directories (relative, forward slashes) named `supabase` that contain `marker`, at most `depth` deep. */
function findSupabaseDirs(root, marker, depth = 6) {
  const out = [];
  const walk = (dir, d) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (!e.isDirectory() || SKIP.has(e.name) || e.name.startsWith('.')) continue;
      const full = path.join(dir, e.name);
      if (e.name === 'supabase' && fs.existsSync(path.join(full, marker))) out.push(path.relative(root, full).split(path.sep).join('/'));
      if (d < depth) walk(full, d + 1);
    }
  };
  walk(root, 0);
  return out.sort();
}

/**
 * Resolve { supabaseDir, migrations, functionsDir, configToml, how } for a config.
 * Several Supabase projects in one tree is an error unless the config names one.
 */
export function resolveProject(root, cfg) {
  let dir = cfg.supabaseDir;
  let how = 'config';
  if (!dir) {
    if (cfg.migrations) dir = path.posix.dirname(cfg.migrations);
    else {
      let found = findSupabaseDirs(root, 'config.toml');
      if (!found.length) found = findSupabaseDirs(root, 'migrations');
      if (found.length > 1) {
        throw new ConfigError(`found ${found.length} Supabase projects (${found.join(', ')}); set "supabaseDir" in supareach.config.json to the one to check`);
      }
      dir = found[0] || 'supabase';
      how = found.length ? 'auto-detected' : 'default (not found)';
    }
  }
  dir = dir.replace(/\/+$/, '') || '.';
  const project = {
    supabaseDir: dir,
    migrations: cfg.migrations || `${dir}/migrations`.replace(/^\.\//, ''),
    functionsDir: cfg.functionsDir || `${dir}/functions`.replace(/^\.\//, ''),
    configToml: `${dir}/config.toml`.replace(/^\.\//, ''),
    how,
  };
  for (const k of ['migrations', 'functionsDir', 'configToml']) {
    if (!isInside(root, path.join(root, project[k]))) throw new ConfigError(`${k} resolves outside the project root`);
  }
  project.toml = readToml(path.join(root, project.configToml));
  return project;
}

/** Minimal TOML: [section.sub] headers and key = string | bool | number | [strings]. Enough for config.toml. */
export function readToml(file) {
  const out = {};
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return null; }
  let cur = out;
  for (const raw of text.split(/\r\n|\r|\n/)) {
    const line = raw.replace(/^\s+/, '');
    if (!line || line.startsWith('#')) continue;
    const sec = /^\[([^\]]+)\]\s*(#.*)?$/.exec(line);
    if (sec) {
      cur = out;
      for (const part of sec[1].match(/"[^"]*"|[^.\s]+/g) || []) {
        const k = part.replace(/^"|"$/g, '');
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') { cur = {}; break; }
        if (!Object.prototype.hasOwnProperty.call(cur, k) || typeof cur[k] !== 'object') cur[k] = {};
        cur = cur[k];
      }
      continue;
    }
    const kv = /^("?)([\w.-]+)\1\s*=\s*(.*)$/.exec(line);
    if (!kv || kv[2] === '__proto__') continue;
    cur[kv[2]] = tomlValue(kv[3].trim());
  }
  return out;
}

function tomlValue(v) {
  let m;
  if ((m = /^"((?:[^"\\]|\\.)*)"/.exec(v))) return m[1].replace(/\\(.)/g, '$1');
  if ((m = /^'([^']*)'/.exec(v))) return m[1];
  if (/^true\b/.test(v)) return true;
  if (/^false\b/.test(v)) return false;
  if ((m = /^-?\d+(\.\d+)?/.exec(v))) return Number(m[0]);
  if (v.startsWith('[')) return [...v.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)].map((x) => x[1] ?? x[2]);
  return v;
}
