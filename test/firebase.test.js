import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classify, parseRulesFile, parseDatabaseRules, pathMatches } from '../src/firebase/rules.js';
import { scanFirebaseFile } from '../src/firebase/scan.js';
import { listCloudFunctions, missingAuthCheck } from '../src/firebase/functions.js';
import { analyze } from '../src/analyze.js';
import { renderReport } from '../src/report.js';
import { renderHtml } from '../src/html.js';
import { toSarif } from '../src/ci.js';
import path from 'node:path';
import { project, rm } from './helpers.js';

const NOW = new Date('2026-10-23T00:00:00Z');

test('classify: literals, sign-in checks, && / || and rule functions', () => {
  const fns = new Map([
    ['signedIn', { lets: new Map(), ret: 'request.auth != null' }],
    ['isOwner', { lets: new Map(), ret: 'request.auth.uid == uid' }],
    ['viaLet', { lets: new Map([['ok', 'request.auth != null']]), ret: 'ok' }],
    ['loop', { lets: new Map(), ret: 'loop()' }],
  ]);
  const c = (e) => classify(e, (n) => fns.get(n) || null, { now: NOW }).cls;
  assert.equal(c('true'), 'public');
  assert.equal(c(''), 'public');
  assert.equal(c('false'), 'closed');
  assert.equal(c('request.auth != null'), 'signed-in');
  assert.equal(c('(null != request.auth)'), 'signed-in');
  assert.equal(c('signedIn()'), 'signed-in');
  assert.equal(c('viaLet()'), 'signed-in');
  assert.equal(c('signedIn() && isOwner()'), 'conditional');
  assert.equal(c('isOwner() || signedIn()'), 'signed-in');
  assert.equal(c('isOwner() || true'), 'public');
  assert.equal(c('signedIn() && false'), 'closed');
  assert.equal(c('!signedIn()'), 'conditional');
  assert.equal(c('signedIn() ? true : false'), 'conditional');
  assert.equal(c('signedIn() == isOwner()'), 'conditional');
  assert.equal(c('loop()'), 'conditional');
  assert.equal(c('unknownFn()'), 'conditional');
  const open = classify('request.time < timestamp.date(2027, 1, 5)', () => null, { now: NOW });
  assert.equal(open.cls, 'public');
  assert.match(open.notes[0], /until 2027-01-05/);
  assert.equal(classify('request.time < timestamp.date(2026, 1, 5)', () => null, { now: NOW }).cls, 'closed');
});

test('parseRulesFile: nested matches, prefixes, op groups, functions defined after use', () => {
  const src = `rules_version = '2';
// a comment with { braces } and allow write: if true;
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{uid} {
      allow read: if isOwner(uid);
      allow create, update: if signedIn()
      allow delete;
      match /posts/{postId} {
        allow read, write: if request.auth != null && request.resource.data.title is string;
      }
    }
    match /{document=**} { allow read, write: if false; }
    function signedIn() { return request.auth != null; }
    function isOwner(u) { return signedIn() && request.auth.uid == u; }
  }
}`;
  const r = parseRulesFile(src, { now: NOW });
  assert.equal(r.service, 'cloud.firestore');
  assert.deepEqual(r.errors, []);
  const by = (p) => r.allows.filter((a) => a.path.join('/') === p).map((a) => [a.ops.join(','), a.cls]);
  assert.deepEqual(by('users/{uid}'), [['get,list', 'conditional'], ['create,update', 'signed-in'], ['delete', 'public']]);
  assert.deepEqual(by('users/{uid}/posts/{postId}'), [['get,list,create,update,delete', 'conditional']]);
  assert.deepEqual(by('{document=**}'), [['get,list,create,update,delete', 'closed']]);
  assert.equal(r.allows.find((a) => a.cls === 'signed-in').line, 7);
  const st = parseRulesFile("service firebase.storage { match /b/{bucket}/o { match /avatars/{uid}/{file} { allow read: if true; allow write: if request.auth.uid == uid; } } }");
  assert.deepEqual(st.allows.map((a) => [a.path.join('/'), a.cls]), [['avatars/{uid}/{file}', 'public'], ['avatars/{uid}/{file}', 'conditional']]);
});

test('pathMatches: wildcards, recursive wildcards, unknown parents', () => {
  const R = (s) => s.split('/');
  assert.ok(pathMatches(R('users/{uid}'), ['users', '*']));
  assert.ok(pathMatches(R('users/{uid}'), ['users', 'abc']));
  assert.ok(!pathMatches(R('users/{uid}'), ['users', '*', 'posts', '*']));
  assert.ok(pathMatches(R('users/{uid}/{rest=**}'), ['users', '*', 'posts', '*']));
  assert.ok(pathMatches(R('{document=**}'), ['anything', '*']));
  assert.ok(pathMatches(R('config/app'), ['config', '*']));
  assert.ok(!pathMatches(R('config/app'), ['config', 'other']));
  // Unknown parent: aligned on the collection name, never swallowed by a trailing recursive wildcard.
  assert.ok(pathMatches(R('users/{uid}/posts/{p}'), ['posts', '*'], true));
  assert.ok(!pathMatches(R('users/{uid}/streak/{doc=**}'), ['posts', '*'], true));
  assert.ok(pathMatches(R('users/{uid}/streak/{doc=**}'), ['streak', '*'], true));
  assert.ok(pathMatches(R('{path=**}/posts/{p}'), ['posts', '*'], true));
  assert.ok(!pathMatches(R('users/{uid}'), ['posts', '*'], true));
});

test('parseDatabaseRules: cascading paths, $wildcards, boolean and string conditions', () => {
  const r = parseDatabaseRules(`{
  // comments are allowed
  "rules": {
    ".read": false,
    "public": { ".read": true, ".write": "auth != null" },
    "users": { "$uid": { ".read": "auth.uid === $uid", ".write": "auth.uid === $uid" } }
  }
}`, { now: NOW });
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.allows.map((a) => [a.path.join('/'), a.ops[0], a.cls]), [
    ['', 'get', 'closed'], ['public', 'get', 'public'], ['public', 'create', 'signed-in'],
    ['users/{uid}', 'get', 'conditional'], ['users/{uid}', 'create', 'conditional']]);
  assert.equal(r.allows[1].line, 5);
  assert.match(parseDatabaseRules('{').errors[0].error, /not valid JSON/);
});

test('scanFirebaseFile: Dart chains, path strings, variables, constants, callables', () => {
  const dart = `import 'package:cloud_firestore/cloud_firestore.dart';
class Repo {
  final _firestore = FirebaseFirestore.instance;
  late final CollectionReference _tasks = _firestore.collection('users').doc(uid).collection('tasks');
  Future<void> a(String uid) async {
    await _firestore
        .collection('users')
        .doc(uid)
        .collection('plants')
        .get();
    await FirebaseFirestore.instance.doc('users/$uid/profile/data').snapshots();
    await _tasks.doc(id).set({});
    await (await _ref(x)).collection('care').add({});
    await FirebaseFirestore.instance.collection(kShopCollection).doc('current').get();
    await FirebaseFirestore.instance.collection(name).get();
    // FirebaseFirestore.instance.collection('commented').get();
    await FirebaseFunctions.instance.httpsCallable('doThing').call();
    await _call('viaWrapper', {});
  }
  Future<void> _call(String name, Map<String, Object?> payload) async {
    await FirebaseFunctions.instance.httpsCallable(name).call(payload);
  }
}`;
  const consts = new Map([['kShopCollection', 'shop']]);
  const first = scanFirebaseFile('lib/repo.dart', dart, { consts });
  const docs = first.calls.filter((c) => c.kind === 'doc').map((c) => `${c.anyPrefix ? '~' : ''}${c.path.join('/')}${c.op ? ` ${c.op}` : ''}`);
  assert.deepEqual(docs, ['users/*/tasks/*', 'users/*/plants/* read', 'users/*/profile/data read', 'users/*/tasks/* write', '~care/* write', 'shop/current read']);
  assert.deepEqual(first.unresolved.map((u) => [u.kind, u.line]), [['firestore', 15]]);
  assert.deepEqual(first.calls.filter((c) => c.kind === 'invoke').map((c) => c.name), ['doThing']);
  assert.deepEqual(first.wrappers.map((w) => [w.name, w.arg, w.local]), [['_call', 0, true]]);
  const second = scanFirebaseFile('lib/repo.dart', dart, { consts, invokeWrappers: first.wrappers });
  assert.deepEqual(second.calls.filter((c) => c.kind === 'invoke').map((c) => [c.name, c.confidence]), [['doThing', 'extracted'], ['viaWrapper', 'inferred']]);
  assert.ok(!second.unresolved.some((u) => u.kind === 'invoke'));
});

test('scanFirebaseFile: JS modular and namespaced SDKs, Admin SDK is privileged', () => {
  const web = `import { getFirestore, collection, doc, getDoc, collectionGroup } from 'firebase/firestore';
import { getFunctions, httpsCallable } from 'firebase/functions';
const db = getFirestore();
getDoc(doc(db, 'users', uid));
getDocs(collection(db, \`users/\${uid}/orders\`));
getDocs(collectionGroup(db, 'comments'));
getDocs(collection(doc(db, 'teams', t), 'members'));
getDocs(collection(db, someName));
httpsCallable(getFunctions(), 'checkout');`;
  const r = scanFirebaseFile('src/app.ts', web);
  assert.deepEqual(r.calls.filter((c) => c.kind === 'doc').map((c) => `${c.anyPrefix ? '~' : ''}${c.path.join('/')}`), ['users/*', 'users/*/orders/*', '~comments/*', 'teams/*/members/*']);
  assert.equal(r.unresolved.length, 1);
  assert.deepEqual(r.calls.filter((c) => c.kind === 'invoke').map((c) => c.name), ['checkout']);
  assert.ok(r.calls.every((c) => !c.privileged));
  const admin = scanFirebaseFile('scripts/seed.js', "const admin = require('firebase-admin');\nadmin.firestore().collection('plans').doc('pro').set({});");
  assert.deepEqual(admin.calls.map((c) => [c.path.join('/'), c.privileged]), [['plans/pro', true]]);
});

test('listCloudFunctions follows the entry module; missingAuthCheck reads the handler', () => {
  const d = project({
    'functions/package.json': JSON.stringify({ main: 'lib/index.js' }),
    'functions/src/index.ts': `import { onCall, onRequest } from 'firebase-functions/v2/https';
import { onDocumentCreated } from 'firebase-functions/v2/firestore';
export * from './more';
export { renamed as exportedName } from './other';
export const secured = onCall(async (request) => { if (!request.auth) throw new Error(); return 1; });
export const open = onCall({ region: 'us-central1' }, async (request) => { return request.data.x; });
export const hook = onRequest((req, res) => { res.send('ok'); });
export const onUser = onDocumentCreated('users/{uid}', async (event) => {});
export const helper = 3;`,
    'functions/src/more.ts': "import * as functions from 'firebase-functions';\nexport const legacy = functions.https.onCall((data, context) => { return context.auth.uid; });",
    'functions/src/other.ts': "export const renamed = onCall(async (req) => gate(req));\nexport const notExported = onCall(async () => 1);",
    'functions/src/unused.ts': 'export const orphan = onCall(async () => 1);',
  });
  try {
    const fns = listCloudFunctions(d, [{ dir: 'functions', codebase: 'default' }]);
    assert.deepEqual(fns.map((f) => [f.name, f.kind]), [['exportedName', 'callable'], ['hook', 'http'], ['legacy', 'callable'], ['onUser', 'trigger'], ['open', 'callable'], ['secured', 'callable']]);
    assert.equal(fns.find((f) => f.name === 'onUser').trigger, 'users/{uid}');
    const noAuth = Object.fromEntries(fns.filter((f) => f.kind === 'callable').map((f) => [f.name, !!missingAuthCheck(f.body)]));
    assert.deepEqual(noAuth, { exportedName: false, legacy: false, open: true, secured: false });
  } finally { rm(d); }
});

/** A small synthetic Firebase app with one of each finding. */
const APP = {
  'firebase.json': JSON.stringify({ firestore: { rules: 'firestore.rules' }, storage: { rules: 'storage.rules' }, database: { rules: 'database.rules.json' }, functions: { source: 'functions' } }),
  'firestore.rules': `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function signedIn() { return request.auth != null; }
    match /users/{uid} { allow read, write: if signedIn() && request.auth.uid == uid; }
    match /posts/{id} { allow read: if true; allow write: if signedIn(); }
    match /guestbook/{id} { allow create: if true; }
    match /secrets/{id} { allow read: if signedIn(); }
    match /archive/{id} { allow read: if request.auth.uid == resource.data.owner; }
    match /serverOnly/{id} { allow read, write: if false; }
  }
}`,
  'storage.rules': 'service firebase.storage { match /b/{bucket}/o { match /{all=**} { allow read: if true; allow write: if request.auth != null; } } }',
  'database.rules.json': '{ "rules": { ".read": true, ".write": false } }',
  'lib/main.dart': `import 'package:cloud_firestore/cloud_firestore.dart';
void main() async {
  final db = FirebaseFirestore.instance;
  await db.collection('users').doc(uid).get();
  await db.collection('posts').add({});
  await db.collection('guestbook').add({});
  await db.collection('typo').get();
  await FirebaseFunctions.instance.httpsCallable('checkout').call();
  await FirebaseFunctions.instance.httpsCallable('ghost').call();
}`,
  'lib/test_helper_test.dart': "void t() { FirebaseFirestore.instance.collection('secrets').get(); }",
  'functions/package.json': JSON.stringify({ main: 'lib/index.js' }),
  'functions/src/index.ts': `import { onCall, onRequest } from 'firebase-functions/v2/https';
import * as admin from 'firebase-admin';
export const checkout = onCall(async (request) => { if (!request.auth) throw new Error('no'); await admin.firestore().collection('serverOnly').add({}); });
export const forgotten = onCall(async (request) => { return admin.firestore().collection('archive').get(); });
export const webhook = onRequest(async (req, res) => { res.send('ok'); });`,
  'functions/lib/index.js': "exports.checkout = 1; db.collection('secrets').get();",
};

test('analyze: a Firebase project gets Firebase findings, tiers and a rendered report', async () => {
  const d = project(APP);
  try {
    const r = await analyze(d);
    assert.equal(r.platform, 'firebase');
    assert.deepEqual(r.scope_problems, []);
    const got = r.findings.map((f) => `${f.tier} ${f.rule} ${f.id}`).sort();
    assert.deepEqual(got, [
      'fix firebase-rules-open-catch-all rtdb:/',
      'review firebase-rules-public-write /guestbook/{id}',
      'fix firestore-rule-unused /secrets/{id}',
      'review callable-without-auth-check forgotten',
      'review firebase-rules-public-read /posts/{id}',
      'review firebase-rules-public-read storage:/{all=**}',
      'review firebase-rules-signed-in-write /posts/{id}',
      'review firebase-rules-signed-in-write storage:/{all=**}',
      'review firestore-path-without-rule /typo/*',
      'review firestore-rule-unused /archive/{id}',
      'review missing-callable-function ghost',
      'review uncalled-callable-function forgotten',
    ].sort());
    // The Admin SDK reading /archive does not count as a client caller.
    assert.match(r.findings.find((f) => f.rule === 'firestore-rule-unused' && f.id === '/archive/{id}').note, /Admin SDK/);
    // HTTP functions are entry points; tests and built output are not scanned.
    assert.deepEqual(r.info.external_entry_points.map((e) => e.id), ['webhook']);
    assert.ok(!r.nodes.some((n) => n.id === 'file:lib/test_helper_test.dart' || n.id === 'file:functions/lib/index.js'));
    const md = renderReport(r);
    assert.match(md, /Firebase project: `firebase.json`/);
    assert.match(md, /Distinct Firestore paths used: 4 from client code/);
    assert.ok(renderHtml(r).length > 1000);
    assert.ok(toSarif(r, { version: '0', prefix: '', fallbackUri: 'firebase.json' }).runs[0].results.length >= 10);
  } finally { rm(d); }
});

test('analyze: dynamic Firestore references downgrade unused-path Fix to Review; ignores apply', async () => {
  const d = project({ ...APP, 'lib/dyn.dart': "void f(String name) { FirebaseFirestore.instance.collection(name).get(); }",
    'tracegrid.config.json': JSON.stringify({ ignore: { tables: [{ name: '/guestbook/{id}', reason: 'public guestbook by design' }], edgeFunctions: [{ name: 'forgotten', reason: 'admin tool' }] } }) });
  try {
    const r = await analyze(d);
    const s = r.findings.find((f) => f.rule === 'firestore-rule-unused' && f.id === '/secrets/{id}');
    assert.equal(s.tier, 'review');
    assert.match(s.note, /unresolved Firestore reference/);
    assert.ok(!r.findings.some((f) => f.id === '/guestbook/{id}' || f.id === 'forgotten'));
    assert.ok(r.suppressed.some((f) => f.fingerprint === 'firebase-rules-public-write:/guestbook/{id}'));
  } finally { rm(d); }
});

test('platform: Supabase wins when both exist; "firebase" forces it; --db-url is refused on Firebase', async () => {
  const both = project({ ...APP, 'supabase/config.toml': '[api]\n', 'supabase/migrations/1_init.sql': 'create table t (id int);' });
  try {
    assert.notEqual((await analyze(both)).platform, 'firebase');
    const forced = await analyze(both, { config: { ...(await import('../src/config.js')).loadConfig(both), platform: 'firebase' } });
    assert.equal(forced.platform, 'firebase');
  } finally { rm(both); }
  const fb = project(APP);
  try {
    await assert.rejects(analyze(fb, { dbUrl: 'postgres://x' }), /Firebase project/);
  } finally { rm(fb); }
});

test('analyze: a test-mode catch-all is a Fix while its date has not passed', async () => {
  const d = project({
    'firebase.json': '{}',
    'firestore.rules': "service cloud.firestore { match /databases/{db}/documents { match /{document=**} { allow read, write: if request.time < timestamp.date(2099, 1, 1); } } }",
    'web/app.js': "import { getFirestore, collection } from 'firebase/firestore';\ngetDocs(collection(getFirestore(), 'items'));",
  });
  try {
    const r = await analyze(d);
    const f = r.findings.filter((x) => x.tier === 'fix').map((x) => [x.rule, x.id]);
    assert.deepEqual(f.sort(), [['firebase-rules-open-catch-all', '/{document=**}'], ['firebase-rules-public-write', '/{document=**}']]);
    assert.match(r.findings[0].note || r.findings[1].note, /test-mode rule: open to everyone until 2099-01-01/);
  } finally { rm(d); }
});

test('listCloudFunctions: local consts exported later, and grouped functions', () => {
  const d = project({
    'functions/index.js': `const functions = require('firebase-functions');
const customToken = functions.https.onCall((data, context) => context.auth);
const internal = functions.https.onCall(() => 1);
module.exports = { customToken, renamedHook: hook };
exports.billing = require('./billing');`,
    'functions/billing.js': "exports.charge = require('firebase-functions').https.onCall((d, c) => c.auth);",
    'functions/package.json': '{}',
    'functions/src/index.ts': "export * as production from './production';\nconst local = onCall(async (r) => r.auth);\nexport { local as exposed };",
    'functions/src/production.ts': "export const createOrder = onCall(async (request) => request.auth);",
  });
  try {
    assert.deepEqual(listCloudFunctions(d, [{ dir: 'functions', codebase: 'default' }]).map((f) => f.name), ['exposed', 'production-createOrder']);
    rm(path.join(d, 'functions/src'));
    assert.deepEqual(listCloudFunctions(d, [{ dir: 'functions', codebase: 'default' }]).map((f) => f.name), ['billing-charge', 'customToken']);
  } finally { rm(d); }
});
