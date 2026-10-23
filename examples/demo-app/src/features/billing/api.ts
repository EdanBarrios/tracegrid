import { supabase } from '@/lib/supabase';

const AUDIT = 'audit_log';

export async function listInvoices() {
  return supabase.from('invoices').select('*');
}

export async function logAction(action: string) {
  return supabase.from(AUDIT).insert({ action });
}

export async function comments() {
  return supabase.from('comments').select();
}

export async function sendInvoice(id: string) {
  return supabase.functions.invoke('send-invoice', { body: { id } });
}

export async function sendInvoiceRaw(id: string, token: string) {
  return fetch(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/send-invoice`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: JSON.stringify({ id }),
  });
}

export async function invoicePdf(path: string) {
  return supabase.storage.from('invoice-pdfs').createSignedUrl(path, 60);
}
