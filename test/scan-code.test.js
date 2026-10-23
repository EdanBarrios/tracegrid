import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSource } from '../src/scan-code.js';

const names = (r, kind) => r.calls.filter((c) => c.kind === kind).map((c) => c.name).sort();

test('tables with chained operation', () => {
  const r = scanSource(`supabase.from('tasks').insert({}); supabase.from("projects").select('*');`, 'a.ts');
  assert.deepEqual(r.calls.map((c) => [c.name, c.op]), [['tasks', 'insert'], ['projects', 'select']]);
});

test('rpc through casts, parentheses, non-null and multi-line', () => {
  const r = scanSource(`
    (supabase.rpc as any)('a');
    (supabase as any).rpc('b');
    (<any>supabase.rpc)('c');
    supabase!.rpc(
      'd' as const,
      {});
  `, 'a.ts');
  assert.deepEqual(names(r, 'rpc'), ['a', 'b', 'c', 'd']);
});

test('ternary and || of literals resolve to both names, ambiguous', () => {
  const r = scanSource(`supabase.rpc(x ? 'one' : 'two'); supabase.rpc(y || 'three' ? 'four' : 'five');`, 'a.ts');
  assert.deepEqual(names(r, 'rpc'), ['five', 'four', 'one', 'two']);
  assert.ok(r.calls.every((c) => c.confidence === 'ambiguous'));
});

test('same-file const and literal-union parameter', () => {
  const r = scanSource(`
    const FN = 'from_const';
    supabase.rpc(FN);
    const flag = async (fn: 'p' | 'q', id: string) => supabase.rpc(fn, { id });
  `, 'a.ts');
  assert.deepEqual(names(r, 'rpc'), ['from_const', 'p', 'q']);
});

test('local wrappers are inferred transitively and their call sites resolved', () => {
  const r = scanSource(`
    const rpc = (name: string, args?: object) => (supabase as any).rpc(name, args);
    async function call<T>(name: string, args?: object): Promise<T> { const { data } = await rpc(name, args); return data; }
    call('via_call'); rpc('via_rpc');
  `, 'a.ts');
  assert.deepEqual(names(r, 'rpc'), ['via_call', 'via_rpc']);
  // Every call site of both local wrappers passes a literal: nothing is left unresolved.
  assert.equal(r.unresolved.length, 0);
});

test('configured cross-file wrapper', () => {
  const r = scanSource(`callRpc('x');`, 'a.ts', { rpc: ['callRpc'], from: [], invoke: [] });
  assert.deepEqual(names(r, 'rpc'), ['x']);
});

test('dynamic names are counted, never dropped', () => {
  const r = scanSource(`supabase.from(tableName).select(); supabase.rpc(getName());`, 'a.ts');
  assert.equal(r.calls.length, 0);
  assert.deepEqual(r.unresolved.map((u) => u.kind), ['table', 'rpc']);
});

test('Array.from and other non-Supabase from() are ignored', () => {
  const r = scanSource(`Array.from(items); Buffer.from('abc'); Array.from(new Set(['a']));`, 'a.ts');
  assert.equal(r.calls.length + r.unresolved.length, 0);
});

test('storage buckets, functions.invoke and /functions/v1 URLs', () => {
  const r = scanSource(`
    supabase.storage.from('avatars').upload('x', f);
    supabase.functions.invoke('send-mail', { body: {} });
    fetch(\`\${url}/functions/v1/report-gen?x=1\`, {});
    const u = 'https://x.supabase.co/functions/v1/other-fn';
    fetch(\`\${url}/functions/v1/\${name}\`);
  `, 'a.tsx');
  assert.deepEqual(names(r, 'bucket'), ['avatars']);
  assert.deepEqual(r.calls.find((c) => c.kind === 'bucket').op, 'upload');
  assert.deepEqual(names(r, 'invoke'), ['other-fn', 'report-gen', 'send-mail']);
  assert.equal(r.calls.find((c) => c.name === 'report-gen').confidence, 'extracted');
  assert.equal(r.calls.find((c) => c.name === 'other-fn').confidence, 'inferred');
  assert.deepEqual(r.unresolved.map((u) => u.kind), ['invoke']);
});

test('JSX files parse', () => {
  const r = scanSource(`export const A = () => <div onClick={() => supabase.rpc('clicked')}>hi</div>;`, 'a.jsx');
  assert.deepEqual(names(r, 'rpc'), ['clicked']);
});

test('.schema(x) qualifies table and rpc names; public stays bare', () => {
  const r = scanSource(`
    supabase.schema('billing').from('invoices').select();
    supabase.schema("billing").rpc('close_month');
    supabase.schema('public').from('tasks').select();
    const S = 'ops'; db.schema(S).from('jobs').insert({});
  `, 'a.ts');
  assert.deepEqual(r.calls.map((c) => [c.kind, c.name, c.schema]), [
    ['table', 'billing.invoices', 'billing'], ['rpc', 'billing.close_month', 'billing'], ['table', 'tasks', 'public'], ['table', 'ops.jobs', 'ops'],
  ]);
});

test('R4 local wrappers whose call sites all pass literals leave no unresolved site; literal-union types resolve', () => {
  const cases = {
    typed: `declare const db: any; const call = (fn: string, args?: object) => db.rpc(fn, args); call('a', {}); call('b');`,
    generic: `declare const db: any; const call = async <T,>(fn: string, args?: Record<string, unknown>): Promise<T> => { const { data, error } = await db.rpc(fn, args); if (error) throw error; return data as T; }; call<number>('a', {}); call('b');`,
    alias: `declare const db: any; type Fn = 'a' | 'b'; const call = (fn: Fn, args?: object) => db.rpc(fn, args);`,
    keyofTypeof: `declare const db: any; const FNS = { a: 1, b: 2 } as const; const call = (fn: keyof typeof FNS) => db.rpc(fn);`,
    arrayIndex: `declare const db: any; const FNS = ['a', 'b'] as const; const call = (fn: (typeof FNS)[number]) => db.rpc(fn);`,
    chained: `import { supabase } from './c'; const rpc = (name: string, args?: object) => (supabase as any).rpc(name, args); async function call<T>(name: string, args?: object): Promise<T> { const { data, error } = await rpc(name, args); if (error) throw error; return data as T; } export const x = () => call<number>('a'); export const y = (k: boolean) => call<number>(k ? 'b' : 'a', {});`,
    typeofMember: `import { supabase } from './c'; async function rpc<T extends Parameters<typeof supabase.rpc>[0]>(fn: T, args: Record<string, unknown>) { const { error } = await (supabase.rpc as any)(fn, args); if (error) throw error; } export const a = () => rpc('a', {}); export const b = () => rpc('b', {});`,
    useCallback: `declare const supabase: any; declare const useCallback: any; export function C() { const call = useCallback((fn: string) => supabase.rpc(fn), []); call('a'); call('b'); }`,
  };
  for (const [k, src] of Object.entries(cases)) {
    const r = scanSource(src, 'a.ts');
    assert.deepEqual([...new Set(names(r, 'rpc'))], ['a', 'b'], k);
    assert.equal(r.unresolved.length, 0, k);
  }
  // Still reported: a call site with a dynamic name, an exported wrapper, a wrapper passed as a value.
  for (const src of [
    `declare const db: any; declare const x: string; const call = (fn: string) => db.rpc(fn); call('a'); call(x);`,
    `declare const db: any; export const call = (fn: string) => db.rpc(fn); call('a');`,
    `declare const db: any; declare const use: any; const call = (fn: string) => db.rpc(fn); call('a'); use(call);`,
  ]) assert.ok(scanSource(src, 'a.ts').unresolved.some((u) => u.wrapper === 'call'), src);
});

test('a URL name with a runtime suffix is a pattern, not a name', () => {
  for (const [src, kind, pattern] of [
    ['declare const run: string; const t = `forms_local_${run}`; fetch(`/rest/v1/${t}?select=id`);', 'table', '^forms_local_.*$'],
    ['declare const k: string; fetch(`${u}/rest/v1/rpc/get_${k}`);', 'rpc', '^get_.*$'],
    ['declare const kind: string; fetch(base + "/functions/v1/report-" + kind);', 'invoke', '^report-.*$'],
  ]) {
    const r = scanSource(src, 'a.ts');
    assert.deepEqual(r.calls, [], src);
    assert.deepEqual(r.unresolved.map((u) => [u.kind, u.pattern]), [[kind, pattern]], src);
  }
});
