alter function public.old_stats(uuid) rename to project_stats;
create or replace function public.project_stats_v2(p uuid) returns json language sql as $$ select public.project_stats(p) $$;
drop function if exists public.legacy_report();

alter table public.notes rename to comments;
alter table public.comments enable row level security;
create policy "anyone signed in" on public.comments for all to authenticated using (true);

create or replace function public.archive_old_tasks() returns void language sql security definer as $$
  update public.tasks set done = true where updated_at < now() - interval '90 days';
$$;
revoke execute on function public.archive_old_tasks() from public, anon, authenticated;

select cron.schedule('archive-tasks', '0 3 * * *', $$ select public.archive_old_tasks() $$);
select cron.schedule('nightly-digest', '0 6 * * *', $$
  select net.http_post(
    url := 'https://example.supabase.co/functions/v1/nightly-digest',
    headers := '{"Content-Type":"application/json"}'::jsonb
  );
$$);
select cron.schedule('old-job', '* * * * *', 'select 1');
select cron.unschedule('old-job');

do $$
begin
  if not exists (select 1 from pg_policies where policyname = 'members read invoices later') then
    create policy "owner reads audit" on public.audit_log for select to authenticated using (false);
  end if;
end $$;
drop policy if exists "owner reads audit" on public.audit_log;
