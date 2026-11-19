-- English Battle: Supabase SQL setup
-- Run this in Supabase Dashboard > SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  nickname text not null default '플레이어',
  role text not null default 'member' check (role in ('member','admin')),
  status text not null default 'active' check (status in ('active','suspended')),
  created_at timestamptz not null default now(),
  last_seen timestamptz
);

create table if not exists public.announcements (
  id bigint generated always as identity primary key,
  title text not null check (char_length(title) between 1 and 100),
  body text not null check (char_length(body) between 1 and 2000),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.admin_logs (
  id bigint generated always as identity primary key,
  actor uuid not null references auth.users(id),
  action text not null,
  target_user_id uuid,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public
as $$ select exists (select 1 from public.profiles where id = auth.uid() and role='admin' and status='active'); $$;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles(id,email,nickname)
  values(new.id, coalesce(new.email,''), left(coalesce(new.raw_user_meta_data->>'nickname','플레이어'),8));
  return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.announcements enable row level security;
alter table public.admin_logs enable row level security;

drop policy if exists "profile self or admin read" on public.profiles;
create policy "profile self or admin read" on public.profiles for select to authenticated
using (id=auth.uid() or public.is_admin());
drop policy if exists "profile self nickname update" on public.profiles;
create policy "profile self nickname update" on public.profiles for update to authenticated
using (id=auth.uid()) with check (id=auth.uid());
-- Do not grant direct role/status edits from the browser.
revoke update on public.profiles from authenticated;
grant update(nickname) on public.profiles to authenticated;
drop policy if exists "announcements read" on public.announcements;
create policy "announcements read" on public.announcements for select to authenticated using (true);
drop policy if exists "admin create announcements" on public.announcements;
create policy "admin create announcements" on public.announcements for insert to authenticated with check (public.is_admin() and created_by=auth.uid());
drop policy if exists "admin read logs" on public.admin_logs;
create policy "admin read logs" on public.admin_logs for select to authenticated using (public.is_admin());

create or replace function public.admin_set_member_status(target_user_id uuid,new_status text,reason text default '')
returns void language plpgsql security definer set search_path = public
as $$
begin
  if not public.is_admin() then raise exception '관리자 권한이 필요합니다.'; end if;
  if new_status not in ('active','suspended') then raise exception '잘못된 상태입니다.'; end if;
  if target_user_id=auth.uid() then raise exception '자기 계정은 변경할 수 없습니다.'; end if;
  update public.profiles set status=new_status where id=target_user_id;
  if not found then raise exception '회원을 찾을 수 없습니다.'; end if;
  insert into public.admin_logs(actor,action,target_user_id,details)
  values(auth.uid(),'member_status',target_user_id,jsonb_build_object('status',new_status,'reason',left(reason,300)));
end; $$;

create or replace function public.admin_set_member_role(target_user_id uuid,new_role text)
returns void language plpgsql security definer set search_path = public
as $$
begin
  if not public.is_admin() then raise exception '관리자 권한이 필요합니다.'; end if;
  if new_role not in ('member','admin') then raise exception '잘못된 권한입니다.'; end if;
  if target_user_id=auth.uid() then raise exception '자기 권한은 변경할 수 없습니다.'; end if;
  update public.profiles set role=new_role where id=target_user_id;
  if not found then raise exception '회원을 찾을 수 없습니다.'; end if;
  insert into public.admin_logs(actor,action,target_user_id,details)
  values(auth.uid(),'member_role',target_user_id,jsonb_build_object('role',new_role));
end; $$;
revoke all on function public.admin_set_member_status(uuid,text,text) from public;
revoke all on function public.admin_set_member_role(uuid,text) from public;
grant execute on function public.admin_set_member_status(uuid,text,text) to authenticated;
grant execute on function public.admin_set_member_role(uuid,text) to authenticated;

-- 최초 관리자 지정: 회원가입 후 아래 쿼리의 이메일을 실제 관리자 이메일로 바꿔 실행.
-- update public.profiles set role='admin' where email='YOUR_ADMIN_EMAIL';
