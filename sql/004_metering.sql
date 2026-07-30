-- Layer 3: metering the client cannot lie about.
--
-- If your free-tier limit is enforced in the browser, you do not have a limit,
-- you have a suggestion. The counter has to be incremented by the database, in
-- the same transaction as the work it is counting.

create or replace function consume_release_slot(p_title text)
returns releases
language plpgsql
security definer            -- runs as the function owner, not the caller
set search_path = public, auth, pg_temp   -- never resolve names from the caller's path
as $$
declare
  me       profiles;
  limit_n  integer;
  created  releases;
begin
  select * into me from profiles where id = auth.uid();
  if not found then
    raise exception 'no profile for caller' using errcode = 'insufficient_privilege';
  end if;

  limit_n := case me.plan when 'pro' then 2147483647 else 1 end;

  if me.releases_used >= limit_n then
    raise exception 'free plan allows % release(s)', limit_n
      using errcode = 'check_violation';
  end if;

  -- Authorize the privileged write for this transaction only. `true` scopes the
  -- setting to the transaction, so it cannot survive onto the next request that
  -- reuses this pooled connection.
  perform set_config('app.internal_write', 'on', true);

  insert into releases (tenant_id, created_by, title)
  values (me.tenant_id, me.id, p_title)
  returning * into created;

  update profiles
     set releases_used = releases_used + 1
   where id = me.id;

  perform set_config('app.internal_write', 'off', true);

  return created;
end;
$$;

-- Stripe delivers at least once. Insert-or-conflict on the event id is the
-- idempotency guarantee: the second delivery is a no-op, not a double upgrade.
create or replace function apply_subscription_event(
  p_event_id text,
  p_user_id  uuid,
  p_plan     text
)
returns boolean
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
begin
  if auth.role() is distinct from 'service_role' then
    raise exception 'only the service role may apply subscription events'
      using errcode = 'insufficient_privilege';
  end if;

  insert into processed_webhook_events (event_id) values (p_event_id)
  on conflict (event_id) do nothing;

  if not found then
    return false;   -- already processed; do nothing
  end if;

  update profiles set plan = p_plan where id = p_user_id;
  return true;
end;
$$;

revoke all on function consume_release_slot(text) from public;
revoke all on function apply_subscription_event(text, uuid, text) from public;
