-- SILSILA: Supabase/PostgreSQL starter schema
-- Apply only after creating a Supabase project and reviewing the policies with your intended sharing model.
create extension if not exists pgcrypto;

create table if not exists public.families (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 120),
  description text not null default '',
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.family_memberships (
  family_id uuid not null references public.families(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner','admin','member','viewer')),
  status text not null default 'active' check (status in ('invited','active','suspended')),
  joined_at timestamptz not null default now(),
  primary key (family_id, user_id)
);

create table if not exists public.people (
  id uuid primary key default gen_random_uuid(),
  family_id uuid not null references public.families(id) on delete cascade,
  linked_user_id uuid references auth.users(id) on delete set null,
  full_name text not null check (char_length(full_name) between 1 and 120),
  display_name text not null default '',
  relation_label text not null default '',
  birth_date date,
  life_status text not null default 'unknown' check (life_status in ('living','deceased','unknown')),
  membership_status text not null default 'not_joined' check (membership_status in ('not_joined','active','pending')),
  bio text not null default '',
  photo_path text,
  visibility text not null default 'family' check (visibility in ('private','family','admins_only')),
  created_by uuid references auth.users(id) on delete set null,
  updated_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (family_id, linked_user_id, id)
);

create table if not exists public.relationships (
  id uuid primary key default gen_random_uuid(),
  family_id uuid not null references public.families(id) on delete cascade,
  person_id uuid not null references public.people(id) on delete cascade,
  related_person_id uuid not null references public.people(id) on delete cascade,
  relationship_type text not null check (relationship_type in ('parent','spouse')),
  parent_kind text check (parent_kind in ('father','mother')),
  approval_status text not null default 'pending' check (approval_status in ('pending','approved','rejected')),
  proposed_by uuid references auth.users(id) on delete set null,
  reviewed_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  check (person_id <> related_person_id),
  check ((relationship_type = 'parent' and parent_kind is not null) or (relationship_type = 'spouse' and parent_kind is null))
);

create table if not exists public.family_stories (
  id uuid primary key default gen_random_uuid(),
  family_id uuid not null references public.families(id) on delete cascade,
  person_id uuid references public.people(id) on delete set null,
  title text not null check (char_length(title) between 1 and 160),
  body text not null,
  visibility text not null default 'family' check (visibility in ('private','family','admins_only')),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.family_invitations (
  id uuid primary key default gen_random_uuid(),
  family_id uuid not null references public.families(id) on delete cascade,
  invited_email text,
  invited_person_id uuid references public.people(id) on delete set null,
  token_hash text not null unique,
  role text not null default 'member' check (role in ('admin','member','viewer')),
  expires_at timestamptz not null,
  accepted_at timestamptz,
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now()
);

create table if not exists public.change_requests (
  id uuid primary key default gen_random_uuid(),
  family_id uuid not null references public.families(id) on delete cascade,
  target_person_id uuid references public.people(id) on delete cascade,
  change_type text not null check (change_type in ('profile_edit','relationship_add','relationship_remove')),
  payload jsonb not null,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  proposed_by uuid not null references auth.users(id) on delete restrict,
  reviewed_by uuid references auth.users(id) on delete set null,
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.audit_log (
  id bigint generated always as identity primary key,
  family_id uuid not null references public.families(id) on delete cascade,
  actor_user_id uuid references auth.users(id) on delete set null,
  action text not null,
  table_name text not null,
  record_id uuid,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists people_family_name_idx on public.people(family_id, full_name);
create index if not exists relationships_family_person_idx on public.relationships(family_id, person_id);
create index if not exists stories_family_created_idx on public.family_stories(family_id, created_at desc);
create index if not exists memberships_user_idx on public.family_memberships(user_id);

-- Helper: membership check for RLS policies. SECURITY DEFINER avoids recursive membership RLS checks.
create or replace function public.is_family_member(target_family uuid)
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.family_memberships fm where fm.family_id = target_family and fm.user_id = auth.uid() and fm.status = 'active') $$;

create or replace function public.has_family_role(target_family uuid, allowed_roles text[])
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.family_memberships fm where fm.family_id = target_family and fm.user_id = auth.uid() and fm.status = 'active' and fm.role = any(allowed_roles)) $$;

alter table public.families enable row level security;
alter table public.family_memberships enable row level security;
alter table public.people enable row level security;
alter table public.relationships enable row level security;
alter table public.family_stories enable row level security;
alter table public.family_invitations enable row level security;
alter table public.change_requests enable row level security;
alter table public.audit_log enable row level security;

-- Families: members can read; owner/admin can update.
drop policy if exists families_read_member on public.families;
create policy families_read_member on public.families for select to authenticated using (public.is_family_member(id));
drop policy if exists families_update_admin on public.families;
create policy families_update_admin on public.families for update to authenticated using (public.has_family_role(id, array['owner','admin'])) with check (public.has_family_role(id, array['owner','admin']));
drop policy if exists families_create_authenticated on public.families;
create policy families_create_authenticated on public.families for insert to authenticated with check (created_by = auth.uid());

-- Memberships: members can view fellow memberships; only admins manage them.
drop policy if exists memberships_read_family on public.family_memberships;
create policy memberships_read_family on public.family_memberships for select to authenticated using (public.is_family_member(family_id));
drop policy if exists memberships_admin_insert on public.family_memberships;
create policy memberships_admin_insert on public.family_memberships for insert to authenticated with check (public.has_family_role(family_id, array['owner','admin']) or (user_id = auth.uid() and role = 'owner' and exists(select 1 from public.families f where f.id = family_id and f.created_by = auth.uid())));
drop policy if exists memberships_admin_update on public.family_memberships;
create policy memberships_admin_update on public.family_memberships for update to authenticated using (public.has_family_role(family_id, array['owner','admin'])) with check (public.has_family_role(family_id, array['owner','admin']));
drop policy if exists memberships_admin_delete on public.family_memberships;
create policy memberships_admin_delete on public.family_memberships for delete to authenticated using (public.has_family_role(family_id, array['owner','admin']) and user_id <> auth.uid());

-- People: members read family-visible profiles; admins edit all; linked users may edit their own profile.
drop policy if exists people_read_family on public.people;
create policy people_read_family on public.people for select to authenticated using (public.is_family_member(family_id) and (visibility = 'family' or (visibility = 'private' and linked_user_id = auth.uid()) or (visibility = 'admins_only' and public.has_family_role(family_id, array['owner','admin']))));
drop policy if exists people_insert_admin on public.people;
create policy people_insert_admin on public.people for insert to authenticated with check (public.has_family_role(family_id, array['owner','admin']) and (created_by is null or created_by = auth.uid()));
drop policy if exists people_update_self_or_admin on public.people;
create policy people_update_self_or_admin on public.people for update to authenticated using (public.has_family_role(family_id, array['owner','admin']) or linked_user_id = auth.uid()) with check (public.has_family_role(family_id, array['owner','admin']) or linked_user_id = auth.uid());
drop policy if exists people_delete_admin on public.people;
create policy people_delete_admin on public.people for delete to authenticated using (public.has_family_role(family_id, array['owner','admin']));

-- Relationships: members read approved links; proposer/admin can manage pending requests.
drop policy if exists relationships_read_member on public.relationships;
create policy relationships_read_member on public.relationships for select to authenticated using (public.is_family_member(family_id) and (approval_status = 'approved' or proposed_by = auth.uid() or public.has_family_role(family_id, array['owner','admin'])));
drop policy if exists relationships_insert_member on public.relationships;
create policy relationships_insert_member on public.relationships for insert to authenticated with check (public.is_family_member(family_id) and proposed_by = auth.uid() and (approval_status = 'pending' or public.has_family_role(family_id, array['owner','admin'])));
drop policy if exists relationships_update_admin on public.relationships;
create policy relationships_update_admin on public.relationships for update to authenticated using (public.has_family_role(family_id, array['owner','admin'])) with check (public.has_family_role(family_id, array['owner','admin']));
drop policy if exists relationships_delete_admin on public.relationships;
create policy relationships_delete_admin on public.relationships for delete to authenticated using (public.has_family_role(family_id, array['owner','admin']));

-- Stories: respect visibility; author may insert; author/admin can update or delete.
drop policy if exists stories_read_family on public.family_stories;
create policy stories_read_family on public.family_stories for select to authenticated using (public.is_family_member(family_id) and (visibility = 'family' or (visibility = 'private' and created_by = auth.uid()) or (visibility = 'admins_only' and public.has_family_role(family_id, array['owner','admin']))));
drop policy if exists stories_insert_member on public.family_stories;
create policy stories_insert_member on public.family_stories for insert to authenticated with check (public.is_family_member(family_id) and created_by = auth.uid());
drop policy if exists stories_update_author_admin on public.family_stories;
create policy stories_update_author_admin on public.family_stories for update to authenticated using (created_by = auth.uid() or public.has_family_role(family_id, array['owner','admin'])) with check (created_by = auth.uid() or public.has_family_role(family_id, array['owner','admin']));
drop policy if exists stories_delete_author_admin on public.family_stories;
create policy stories_delete_author_admin on public.family_stories for delete to authenticated using (created_by = auth.uid() or public.has_family_role(family_id, array['owner','admin']));

-- Invitations and audit log are admin-only; change requests are visible to proposer and admins.
drop policy if exists invitations_admin_all on public.family_invitations;
create policy invitations_admin_all on public.family_invitations for all to authenticated using (public.has_family_role(family_id, array['owner','admin'])) with check (public.has_family_role(family_id, array['owner','admin']) and created_by = auth.uid());
drop policy if exists changes_read_proposer_admin on public.change_requests;
create policy changes_read_proposer_admin on public.change_requests for select to authenticated using (public.is_family_member(family_id) and (proposed_by = auth.uid() or public.has_family_role(family_id, array['owner','admin'])));
drop policy if exists changes_insert_member on public.change_requests;
create policy changes_insert_member on public.change_requests for insert to authenticated with check (public.is_family_member(family_id) and proposed_by = auth.uid());
drop policy if exists changes_update_admin on public.change_requests;
create policy changes_update_admin on public.change_requests for update to authenticated using (public.has_family_role(family_id, array['owner','admin'])) with check (public.has_family_role(family_id, array['owner','admin']));
drop policy if exists audit_read_admin on public.audit_log;
create policy audit_read_admin on public.audit_log for select to authenticated using (public.has_family_role(family_id, array['owner','admin']));
drop policy if exists audit_insert_member on public.audit_log;
create policy audit_insert_member on public.audit_log for insert to authenticated with check (public.is_family_member(family_id) and actor_user_id = auth.uid());

-- IMPORTANT IMPLEMENTATION NOTES:
-- 1. Configure Supabase Auth and create a trusted signup/onboarding flow.
-- 2. On family creation, use a trusted server-side function/transaction to create the family and owner membership.
-- 3. Invitation tokens must be generated/hashed server-side; never expose service_role keys in the browser.
-- 4. Storage bucket policies must scope photo paths to the family and check membership/visibility.
-- 5. Consider adding triggers to validate both relationship endpoints belong to the same family, prevent cycles,
--    maintain updated_at, and record audit events. Those rules should be implemented before production use.
-- 6. Review every RLS policy with tests for cross-family access before real family data is uploaded.
