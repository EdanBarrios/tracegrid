import { admin } from '../_shared/client.ts';
Deno.serve(async (req) => {
  const { id } = await req.json();
  const db = admin();
  const { data } = await db.from('invoices').select('*').eq('id', id).single();
  await db.storage.from('invoice-pdfs').upload(`${id}.pdf`, new Blob([JSON.stringify(data)]));
  return new Response('ok');
});
