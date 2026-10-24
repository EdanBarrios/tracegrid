// Locate a Firebase project: firebase.json and the rules files and functions codebases it names.
import fs from 'node:fs';
import path from 'node:path';
import { ConfigError } from '../config.js';
import { isInside } from '../safe.js';

export const FIREBASE_JSON = 'firebase.json';

export const hasFirebaseJson = (root, cfg = {}) => fs.existsSync(path.join(root, cfg.firebaseJson || FIREBASE_JSON));

const list = (v) => (Array.isArray(v) ? v : v && typeof v === 'object' ? [v] : []);

/**
 * { configFile, firestore: [{ rules, database }], storage: [{ rules, bucket }], database: [{ rules, instance }],
 *   functions: [{ dir, codebase }], missing: [file] }. Paths are relative to root, forward slashes.
 */
export function resolveFirebase(root, cfg = {}) {
  const configFile = cfg.firebaseJson || FIREBASE_JSON;
  let json = {};
  try { json = JSON.parse(fs.readFileSync(path.join(root, configFile), 'utf8')); } catch (e) {
    if (e.code !== 'ENOENT') throw new ConfigError(`${configFile}: ${e.message}`);
  }
  const base = path.posix.dirname(configFile) === '.' ? '' : path.posix.dirname(configFile) + '/';
  const rel = (p) => path.posix.normalize(base + String(p).replace(/^\.\//, ''));
  const missing = [];
  const keep = (p) => {
    if (!isInside(root, path.join(root, p))) throw new ConfigError(`${configFile}: ${p} resolves outside the project root`);
    if (!fs.existsSync(path.join(root, p))) { missing.push(p); return false; }
    return true;
  };
  const firestore = list(json.firestore).filter((x) => typeof x.rules === 'string').map((x) => ({ rules: rel(x.rules), database: x.database || '(default)' })).filter((x) => keep(x.rules));
  const storage = list(json.storage).filter((x) => typeof x.rules === 'string').map((x) => ({ rules: rel(x.rules), bucket: x.bucket || null })).filter((x) => keep(x.rules));
  const database = list(json.database).filter((x) => typeof x.rules === 'string').map((x) => ({ rules: rel(x.rules), instance: x.instance || null })).filter((x) => keep(x.rules));
  // Conventional names when firebase.json does not list them (the CLI's defaults).
  const fallback = (key, arr, file, extra) => { if (!json[key] && fs.existsSync(path.join(root, base + file))) arr.push({ rules: base + file, ...extra, how: 'conventional name' }); };
  fallback('firestore', firestore, 'firestore.rules', { database: '(default)' });
  fallback('storage', storage, 'storage.rules', { bucket: null });
  fallback('database', database, 'database.rules.json', { instance: null });
  let functions = list(json.functions).map((x) => ({ dir: rel(x.source || 'functions'), codebase: x.codebase || 'default' }));
  if (!json.functions && fs.existsSync(path.join(root, base + 'functions', 'package.json'))) functions = [{ dir: rel('functions'), codebase: 'default' }];
  functions = functions.filter((f) => { if (!isInside(root, path.join(root, f.dir))) throw new ConfigError(`${configFile}: functions source ${f.dir} resolves outside the project root`); return fs.existsSync(path.join(root, f.dir)); });
  return { configFile, firestore, storage, database, functions, missing };
}
