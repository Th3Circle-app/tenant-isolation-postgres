-- Layer 2: privileged-column protection.
--
-- THE GAP THIS CLOSES
--
-- Row-level security is row-shaped. `profiles_update_own` says "you may update
-- the row where id = auth.uid()", and that is exactly what it enforces. It does
-- not, and cannot, say "...but not the plan column".
--
-- So this passes RLS cleanly and is a privilege escalation:
--
--     update profiles set plan = 'pro' where id = auth.uid();
--
-- The row is theirs. The policy is satisfied. They just upgraded themselves.
--
-- People usually patch this in application code by filtering the request body.
-- That works right up until a second code path forgets to, and there is always
-- a second code path eventually. The database is the only place where the rule
-- cannot be routed around.

create or replace function protect_privileged_columns()
returns trigger
language plpgsql
as $$
begin
  -- Trusted server-side callers may write these columns. That is the whole
  -- point of the service role: Stripe webhooks must be able to set plan.
  if auth.role() = 'service_role' then
    return new;
  end if;

  -- security definer functions in 004 mark the transaction before writing.
  -- This is deliberately a transaction-local GUC, not a session one, so it
  -- cannot leak into a later statement on a pooled connection.
  if coalesce(current_setting('app.internal_write', true), '') = 'on' then
    return new;
  end if;

  if new.plan is distinct from old.plan then
    raise exception 'plan is not user-writable'
      using errcode = 'insufficient_privilege';
  end if;

  if new.is_admin is distinct from old.is_admin then
    raise exception 'is_admin is not user-writable'
      using errcode = 'insufficient_privilege';
  end if;

  if new.releases_used is distinct from old.releases_used then
    raise exception 'releases_used is not user-writable'
      using errcode = 'insufficient_privilege';
  end if;

  -- Re-parenting yourself into another tenant would be a lateral move across
  -- the isolation boundary, so it is privileged too.
  if new.tenant_id is distinct from old.tenant_id then
    raise exception 'tenant_id is not user-writable'
      using errcode = 'insufficient_privilege';
  end if;

  return new;
end;
$$;

create trigger profiles_protect_privileged
  before update on profiles
  for each row
  execute function protect_privileged_columns();
