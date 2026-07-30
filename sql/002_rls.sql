-- Layer 1: row-level security.
--
-- This is the layer everyone implements, and on its own it is not enough.
-- It answers "which ROWS may this caller touch". It says nothing about which
-- COLUMNS, which is the gap 003 closes.

alter table tenants  enable row level security;
alter table profiles enable row level security;
alter table releases enable row level security;

-- Force RLS for table owners too. Without this, the role that owns the table
-- silently bypasses every policy, which is a very easy way to believe you are
-- protected when you are not.
alter table tenants  force row level security;
alter table profiles force row level security;
alter table releases force row level security;

-- ---------------------------------------------------------------- profiles

create policy profiles_select_own
  on profiles for select
  using (id = auth.uid());

create policy profiles_update_own
  on profiles for update
  using (id = auth.uid())
  with check (id = auth.uid());

-- ---------------------------------------------------------------- releases
--
-- Scoped to the caller's tenant, resolved through their own profile row.

create policy releases_select_own_tenant
  on releases for select
  using (
    tenant_id = (select p.tenant_id from profiles p where p.id = auth.uid())
  );

create policy releases_insert_own_tenant
  on releases for insert
  with check (
    created_by = auth.uid()
    and tenant_id = (select p.tenant_id from profiles p where p.id = auth.uid())
  );

create policy releases_delete_own
  on releases for delete
  using (created_by = auth.uid());

-- ---------------------------------------------------------------- tenants

create policy tenants_select_own
  on tenants for select
  using (
    id = (select p.tenant_id from profiles p where p.id = auth.uid())
  );

-- Trusted server-side callers bypass row scoping entirely. Webhook handlers
-- and cron jobs act on behalf of no user, so they cannot satisfy auth.uid().
create policy profiles_service_all
  on profiles for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

create policy releases_service_all
  on releases for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

create policy tenants_service_all
  on tenants for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');
