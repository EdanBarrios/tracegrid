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

test('ternary and || of literals resolve to both names, inferred', () => {
  const r = scanSource(`supabase.rpc(x ? 'one' : 'two'); supabase.rpc(y || 'three' ? 'four' : 'five');`, 'a.ts');
  assert.deepEqual(names(r, 'rpc'), ['five', 'four', 'one', 'two']);
  assert.ok(r.calls.every((c) => c.confidence === 'inferred'));
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
  assert.equal(r.unresolved.length, 2);
  assert.ok(r.unresolved.every((u) => u.wrapper));
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
