// edge-service-role-before-auth: recognised gates, and what must still be flagged. Synthetic fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../src/analyze.js';
import { project, rm } from './helpers.js';

const SQL = `create table public.items (id bigint primary key, owner uuid);
create function public.claim_login_attempt(k text) returns boolean language sql as $$ select true $$;
create function public.redeem(t text) returns int language sql as $$ select 1 $$;`;
const rule = 'edge-service-role-before-auth';

async function scan(fn, { verifyJwt, files = {} } = {}) {
  const dir = project({
    'supabase/migrations/20240101000000_init.sql': SQL,
    ...(verifyJwt === undefined ? {} : { 'supabase/config.toml': `[functions.fn-under-test]\nverify_jwt = ${verifyJwt}\n` }),
    'supabase/functions/fn-under-test/index.ts': fn,
    ...files,
  });
  try {
    const r = await analyze(dir);
    return r.findings.filter((f) => f.rule === rule);
  } finally { rm(dir); }
}
const HEAD = `import { createClient } from 'npm:@supabase/supabase-js';\nconst url = Deno.env.get('SUPABASE_URL')!;\nconst serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;\n`;

test('G1 a caller-scoped RLS read that returns when the row is missing is the gate', async () => {
  const f = await scan(HEAD + `const admin = createClient(url, serviceKey);
Deno.serve(async (req) => {
  const user = createClient(url, Deno.env.get('SUPABASE_ANON_KEY')!, { global: { headers: { Authorization: req.headers.get('Authorization')! } } });
  const { data: row } = await user.from('items').select('id').eq('id', 1).maybeSingle();
  if (!row) return new Response('no', { status: 403 });
  await admin.from('items').update({ owner: null }).eq('id', row.id);
  return new Response('ok');
});`, { verifyJwt: false });
  assert.deepEqual(f.map((x) => x.fingerprint), []);
});

test('G1b the same through a helper that returns the scoped client', async () => {
  const f = await scan(HEAD + `function clientFor(req: Request) {
  return createClient(url, Deno.env.get('SUPABASE_ANON_KEY')!, { global: { headers: { Authorization: req.headers.get('Authorization')! } } });
}
const admin = createClient(url, serviceKey);
Deno.serve(async (req) => {
  const { data, error } = await clientFor(req).from('items').select('id').single();
  if (error) throw error;
  await admin.from('items').delete().eq('id', data.id);
  return new Response('ok');
});`, { verifyJwt: false });
  assert.deepEqual(f.map((x) => x.fingerprint), []);
});

test('G2 lazy service-role factories are judged by first use, not definition', async () => {
  const f = await scan(HEAD + `const svc = () => createClient(url, serviceKey);
const ctx = { service: () => createClient(url, serviceKey) };
Deno.serve(async (req) => {
  const { data: { user } } = await createClient(url, Deno.env.get('SUPABASE_ANON_KEY')!).auth.getUser(req.headers.get('Authorization')!.slice(7));
  if (!user) return new Response('no', { status: 401 });
  await svc().from('items').insert({ owner: user.id });
  return new Response('ok');
});`, { verifyJwt: false });
  assert.deepEqual(f.map((x) => x.fingerprint), []);
});

test('G3 webhook verifiers under any name, svix headers and constant-time compares are gates', async () => {
  const body = (gate) => HEAD + `declare function verifyAcmeSignature(r: Request, b: string): boolean; declare function timingSafeEqual(a: string, b: string): boolean;
const admin = createClient(url, serviceKey);
Deno.serve(async (req) => {
  const raw = await req.text();
  ${gate}
  await admin.from('items').insert({ owner: null });
  return new Response('ok');
});`;
  for (const gate of [
    `if (!verifyAcmeSignature(req, raw)) return new Response('no', { status: 401 });`,
    `const sig = req.headers.get('svix-signature'); if (!sig) return new Response('no', { status: 401 });`,
    `if (!timingSafeEqual(req.headers.get('x-secret') ?? '', Deno.env.get('HOOK_SECRET')!)) return new Response('no', { status: 401 });`,
  ]) assert.deepEqual((await scan(body(gate), { verifyJwt: false })).map((x) => x.fingerprint), [], gate);
});

test('G4 an opaque token is hashed with sha-256 and compared in constant time', async () => {
  const f = await scan(HEAD + `declare function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
const admin = createClient(url, serviceKey);
Deno.serve(async (req) => {
  const token = new URL(req.url).searchParams.get('t') ?? '';
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
  const { data } = await admin.from('items').select('id').limit(1).single();
  if (!timingSafeEqual(hash, new Uint8Array(data.id))) return new Response('no', { status: 403 });
  return new Response('ok');
});`, { verifyJwt: false });
  assert.deepEqual(f.map((x) => x.fingerprint), []);
});

test('G4b a hashed token passed as the only credential to an RPC', async () => {
  const f = await scan(HEAD + `const admin = createClient(url, serviceKey);
Deno.serve(async (req) => {
  const token = req.headers.get('x-link-token') ?? '';
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)))).map((b) => b.toString(16)).join('');
  const { data } = await admin.rpc('redeem', { t: hash });
  return new Response(JSON.stringify(data));
});`, { verifyJwt: false });
  assert.deepEqual(f.map((x) => x.fingerprint), []);
});

test('G5 a rate-limit RPC whose failure returns early is a gate', async () => {
  const f = await scan(HEAD + `const admin = createClient(url, serviceKey);
Deno.serve(async (req) => {
  const { data: ok, error } = await admin
    .rpc('claim_login_attempt', { k: 'a' });
  if (error || !ok) return new Response('slow down', { status: 429 });
  await admin.from('items').insert({ owner: null });
  return new Response('ok');
});`, { verifyJwt: false });
  assert.deepEqual(f.map((x) => x.fingerprint), []);
});

test('G6 an endpoint whose only service-role use is a head/count request is at most an info note', async () => {
  const f = await scan(HEAD + `const admin = createClient(url, serviceKey);
Deno.serve(async () => {
  const { error } = await admin.from('items').select('id', { count: 'exact', head: true });
  return new Response(error ? 'down' : 'up', { status: error ? 503 : 200 });
});`, { verifyJwt: false });
  assert.equal(f.length, 1);
  assert.equal(f[0].tier, 'info');
});

test('G7 still flagged: verify_jwt = false and no gate', async () => {
  const f = await scan(HEAD + `const admin = createClient(url, serviceKey);
Deno.serve(async (req) => {
  const { id } = await req.json();
  const { data } = await admin.from('items').select('*').eq('id', id);
  return new Response(JSON.stringify(data));
});`, { verifyJwt: false });
  assert.equal(f.length, 1);
  assert.equal(f[0].tier, 'review');
  assert.match(f[0].message, /verify this function authorizes callers/);
});

test('G8 still flagged: the gate comes after a write', async () => {
  const f = await scan(HEAD + `const admin = createClient(url, serviceKey);
Deno.serve(async (req) => {
  await admin.from('items').insert({ owner: null });
  const { data: { user } } = await admin.auth.getUser(req.headers.get('Authorization')!.slice(7));
  if (!user) return new Response('no', { status: 401 });
  return new Response('ok');
});`, { verifyJwt: true });
  assert.equal(f.length, 1);
  assert.equal(f[0].tier, 'review');
  assert.notEqual(f[0].confidence, 'low');
});

test('G9 no gate with verify_jwt = true is review at low confidence, never fix', async () => {
  const f = await scan(HEAD + `const admin = createClient(url, serviceKey);
Deno.serve(async () => new Response(JSON.stringify((await admin.from('items').select('id')).data)));`, { verifyJwt: true });
  assert.equal(f.length, 1);
  assert.equal(f[0].tier, 'review');
  assert.equal(f[0].confidence, 'low');
});

test('G4c a secret-looking URL key passed as the only argument of an RPC is a capability', async () => {
  const f = await scan(HEAD + `const admin = createClient(url, serviceKey);
Deno.serve(async (req) => {
  const accessKey = new URL(req.url).searchParams.get('k');
  if (!accessKey) return new Response('no', { status: 400 });
  const { data } = await admin.rpc('redeem', { t: accessKey });
  return new Response(JSON.stringify(data));
});`, { verifyJwt: false });
  assert.deepEqual(f.map((x) => x.fingerprint), []);
});

test('G10 service-role use inside a helper defined above the handler counts where the handler calls it', async () => {
  const gated = (call) => HEAD + `declare function requireSession(r: Request): Promise<{ userId: string }>;
async function load(id: number) {
  const admin = createClient(url, serviceKey);
  return (await admin.from('items').select('id').eq('id', id)).data;
}
Deno.serve(async (req) => {
  ${call}
  return new Response(JSON.stringify(await load(1)));
});`;
  assert.deepEqual((await scan(gated(`await requireSession(req);`), { verifyJwt: false })).map((x) => x.fingerprint), []);
  assert.equal((await scan(gated(``), { verifyJwt: false })).length, 1);
});

test('G11 token verification in an imported helper (sha-256 + constant-time) makes the function a capability endpoint', async () => {
  const f = await scan(HEAD + `import { parts } from './parts.ts';
const admin = createClient(url, serviceKey);
Deno.serve(async (req) => {
  const p = parts(req);
  const { data } = await admin.from('items').select('id').eq('id', p.id).maybeSingle();
  return new Response(JSON.stringify(data));
});`, { verifyJwt: false, files: {
    'supabase/functions/fn-under-test/parts.ts': `import { check } from '../_shared/token.ts';\nexport const parts = (r: Request) => ({ id: new URL(r.url).searchParams.get('id'), token: r.headers.get('x-t'), check });`,
    'supabase/functions/_shared/token.ts': `export async function hash(t: string) { return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t))); }\nfunction constantTimeEqual(a: Uint8Array, b: Uint8Array) { let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }\nexport const check = (a: Uint8Array, b: Uint8Array) => constantTimeEqual(a, b);`,
  } });
  assert.deepEqual(f.map((x) => x.fingerprint), []);
});
