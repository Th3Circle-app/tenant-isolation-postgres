-- Multi-tenant schema with a Supabase-shaped auth surface.
--
-- Supabase exposes the caller's identity through JWT claims. We reproduce that
-- with a session GUC so these patterns can be tested against plain Postgres and
-- run identically in CI, with no vendor dependency.

create schema if not exists auth;

-- The caller's user id, read from the request JWT claims.
create or replace function auth.uid()
returns uuid
language sql
stable
as $$
  select nullif(
    current_setting('request.jwt.claims', true)::jsonb ->> 'sub',
    ''
  )::uuid;
$$;

-- The caller's role: 'authenticated' for end users, 'service_role' for trusted
-- server-side callers (webhook handlers, cron jobs).
create or replace function auth.role()
returns text
language sql
stable
as $$
  select coalesce(
    nullif(current_setting('request.jwt.claims', true)::jsonb ->> 'role', ''),
    'anon'
  );
$$;

-- ---------------------------------------------------------------- tables

create table tenants (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  created_at  timestamptz not null default now()
);

-- One row per end user.
--
-- plan, is_admin and releases_used are PRIVILEGED: the owning user may read
-- them but must never write them. Row-level security alone cannot express
-- that, because RLS grants or denies a whole row. See 003_privileged_columns.
create table profiles (
  id             uuid primary key,
  tenant_id      uuid not null references tenants(id) on delete cascade,
  email          text not null,
  display_name   text,
  plan           text not null default 'free'
                 check (plan in ('free', 'pro')),
  is_admin       boolean not null default false,
  releases_used  integer not null default 0 check (releases_used >= 0),
  created_at     timestamptz not null default now()
);

create table releases (
  id          uuid primary key default gen_random_uuid(),
  tenant_id   uuid not null references tenants(id) on delete cascade,
  created_by  uuid not null references profiles(id) on delete cascade,
  title       text not null,
  created_at  timestamptz not null default now()
);

-- Stripe delivers webhooks at least once, so the same event id can arrive
-- twice. The primary key is the idempotency guarantee.
create table processed_webhook_events (
  event_id     text primary key,
  processed_at timestamptz not null default now()
);

create index releases_tenant_idx on releases (tenant_id);
create index profiles_tenant_idx on profiles (tenant_id);
