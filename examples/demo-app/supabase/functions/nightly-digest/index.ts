import { admin } from '../_shared/client.ts';
Deno.serve(async () => {
  const { data } = await admin().from('tasks').select('id').eq('done', false);
  return new Response(JSON.stringify({ open: data?.length ?? 0 }));
});
