create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  project_id uuid references public.projects(id),
  amount_cents integer not null,
  currency text not null default 'usd'
);
-- RLS on but no policy yet: the client read in billing/api.ts gets nothing back.
alter table public.invoices enable row level security;

create table public.audit_log (id bigserial primary key, action text, at timestamptz default now());

create or replace function public.create_project(p_name text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare v uuid;
begin
  insert into public.projects(owner_id, name) values (auth.uid(), p_name) returning id into v;
  insert into public.project_members values (v, auth.uid());
  return v;
end $$;
revoke execute on function public.create_project(text) from public, anon, authenticated;
grant execute on function public.create_project(text) to authenticated;

-- Granted to signed-in users, but nothing in the app calls it.
create function public.next_invoice_number(p_project uuid) returns bigint
language sql security definer as $$ select count(*) + 1 from public.invoices where project_id = p_project $$;
revoke all on function public.next_invoice_number(uuid) from public, anon;

-- Revoked from PUBLIC only: Supabase's default grants to anon/authenticated still apply.
create function public.internal_cleanup() returns void language sql as $$ delete from public.audit_log $$;
revoke execute on function public.internal_cleanup() from public;

create function public.old_stats(p uuid) returns json language sql as $$ select '{}'::json $$;
create function public.legacy_report() returns void language sql as $$ select 1 $$;
