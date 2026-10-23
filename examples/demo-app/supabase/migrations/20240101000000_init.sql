-- Demo schema: projects, tasks, invoices. Synthetic, for supagraph tests.
create table public.projects (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  name text not null
);
alter table public.projects enable row level security;

create table public.project_members (
  project_id uuid references public.projects(id) on delete cascade,
  user_id uuid not null,
  primary key (project_id, user_id)
);
alter table public.project_members enable row level security;

create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid references public.projects(id),
  title text not null,
  done boolean default false,
  updated_at timestamptz default now()
);
alter table public.tasks enable row level security;

create table public.notes (id bigint generated always as identity primary key, body text);

create or replace function public.is_project_member(p uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (select 1 from public.project_members m where m.project_id = p and m.user_id = auth.uid());
$$;
revoke execute on function public.is_project_member(uuid) from public, anon;

create policy "members read projects" on public.projects for select to authenticated
  using (public.is_project_member(id));
create policy "members read tasks" on public.tasks for select to authenticated
  using (public.is_project_member(project_id));
create policy "members write tasks" on public.tasks for insert to authenticated
  with check (public.is_project_member(project_id));
create policy "self" on public.project_members for select to authenticated using (user_id = auth.uid());

create function public.touch_updated_at() returns trigger language plpgsql as $$
begin new.updated_at := now(); return new; end $$;
create trigger tasks_touch before update on public.tasks for each row execute function public.touch_updated_at();
