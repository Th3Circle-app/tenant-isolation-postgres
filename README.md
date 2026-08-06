# Multi-tenant isolation in PostgreSQL

[![tests](https://github.com/Th3Circle-app/tenant-isolation-postgres/actions/workflows/test.yml/badge.svg)](https://github.com/Th3Circle-app/tenant-isolation-postgres/actions/workflows/test.yml)

Three layers of tenant isolation, and **16 integration tests that execute the attacks
and assert they fail**. Runs against real Postgres in Docker. No mocks.

```bash
npm install
npm run verify     # starts Postgres, applies migrations, runs the suite
```

```
▶ row isolation
  ✔ a tenant sees only its own releases
  ✔ a tenant cannot read another tenant's profile
  ✔ a tenant cannot delete another tenant's release
  ✔ a tenant cannot insert a release into another tenant
▶ privileged columns: the gap RLS alone does not close
  ✔ a user cannot upgrade their own plan
  ✔ a user cannot make themselves an admin
  ✔ a user cannot reset their own usage counter
  ✔ a user cannot move themselves into another tenant
  ✔ non-privileged columns on your own row still update normally
▶ metering the client cannot lie about
  ✔ the free plan allows exactly one release, enforced in the database
  ✔ the counter is incremented by the database, not the caller
  ✔ the internal-write flag does not leak past the transaction
  ✔ a caller cannot hijack the function body by shadowing a table
  ✔ upgrading via the service role lifts the limit
▶ webhook idempotency
  ✔ replaying the same Stripe event is a no-op
  ✔ an end user cannot call the subscription applier directly

ℹ pass 16   ℹ fail 0
```

Every test above performs the attack. A pass means Postgres refused it.

![npm run verify: 16 tests across 4 suites against real Postgres in Docker, 16 passing in
503ms](docs/verify.png)

These patterns are extracted from two multi-tenant products I built and operate:
[th3circle.app](https://th3circle.app) (live, paying subscriptions) and
[rollout](https://github.com/Th3Circle-app/rollout).

---

## The bug that motivated this

Row-level security is **row-shaped**. A policy like this is the one nearly every
Supabase tutorial gives you:

```sql
create policy profiles_update_own
  on profiles for update
  using (id = auth.uid())
  with check (id = auth.uid());
```

It says: *you may update the row where the id is yours.* That is exactly, and only,
what it enforces. So this statement **passes the policy cleanly**:

```sql
update profiles set plan = 'pro' where id = auth.uid();
```

The row is theirs. The check is satisfied. They just upgraded themselves to the paid
plan from the browser console.

RLS has no opinion about columns. It cannot express "this row is yours, but the `plan`
column is not." I found this in production on my own platform, which is why the fix here
is three layers rather than one.

## The three layers

### Layer 1 · Row scope ([`002_rls.sql`](sql/002_rls.sql))

Standard RLS policies scoping every table to the caller's tenant, resolved through their
own profile row.

One detail that matters more than the policies: **`force row level security`**. Without
it, the role that owns the table bypasses every policy silently. That is an easy way to
believe you are protected while you are not, because your tests probably connect as the
owner. The harness here deliberately connects as a separate unprivileged `app_user` role,
the same way PostgREST does, so the tests exercise the real path.

### Layer 2 · Privileged columns ([`003_privileged_columns.sql`](sql/003_privileged_columns.sql))

A `before update` trigger that rejects any change to `plan`, `is_admin`, `releases_used`,
or `tenant_id` unless the caller is the service role or the write was authorized by a
`security definer` function.

The usual fix for this is an allowlist in application code that strips unknown fields from
the request body. That works, right up until a second code path forgets to, and there is
always a second code path eventually. The database is the only place the rule cannot be
routed around.

Two subtleties the tests pin down:

- The trigger compares `old` to `new`, so a **no-op write is not an attack** and is
  allowed. My first version of the "cannot reset the counter" test set the value to what
  it already was, and passed for the wrong reason. The test now spends a slot first so
  the reset is a real change.
- The authorization flag is a **transaction-local** GUC (`set_config(..., true)`), not a
  session one. On a pooled connection a session-scoped flag would leak into the next
  request and quietly disable the trigger. There is a test for exactly that.

### Layer 3 · Metering ([`004_metering.sql`](sql/004_metering.sql))

If your free-tier limit is enforced in the browser, it is not a limit, it is a
suggestion. `consume_release_slot()` is `security definer`: it checks the plan, creates
the record, and increments the counter **in one transaction**, and the client cannot
increment the counter any other way.

It sets an explicit `search_path`. A `security definer` function without one is a
privilege-escalation vector, because the caller can prepend a schema and hijack the
names the function body resolves.

Webhook handling is idempotent by primary key: Stripe delivers at least once, so the same
event id arriving twice must not apply the upgrade twice.

## What this maps to in the OWASP Top 10

Every row below is a test in this repo, not an aspiration. Run `npm run verify` and watch
each one attempt the attack against real Postgres.

| OWASP 2021 | The attack this repo runs | Where |
|---|---|---|
| **A01 · Broken Access Control** | Read, update, delete and insert across a tenant boundary | `row isolation` |
| **A01 · Broken Access Control** | Grant yourself admin, move yourself into another tenant | `privileged columns` |
| **A03 · Injection** | Shadow `profiles` in `pg_temp` so an elevated function reads the attacker's table | `metering` |
| **A04 · Insecure Design** | Exceed the free-tier limit by calling the API directly instead of the UI | `metering` |
| **A05 · Security Misconfiguration** | Disable the protection trigger from an ordinary session | `privileged columns` |
| **A08 · Data Integrity Failures** | Replay a Stripe webhook to apply the same upgrade twice | `webhook idempotency` |

Two of these are worth singling out.

**A01 is the reason this repo exists.** Row-level security is the control most teams reach
for, and on its own it closes row scope while leaving column scope wide open. The
`privileged columns` suite is four attacks that all pass RLS and should still fail.

**A03 does not look like injection.** No user string is concatenated into SQL anywhere in
this repo. The vector is name resolution: Postgres searches `pg_temp` *first* by default,
so a caller can `create temp table profiles`, call `consume_release_slot()`, and have the
elevated function body read their forged plan instead of the real one. `004_metering.sql`
pins `search_path = public, auth, pg_temp` — one line, and it closes the hole.

That test earns its place. Delete the `search_path` line and re-run: 15 pass, 1 fails.
A security test that passes whether or not the control exists is decoration, so this one
was verified by removing the defense and watching it catch it.

## How the auth surface is faked

Supabase exposes identity through JWT claims. This repo reproduces that with a session
GUC and two functions (`auth.uid()`, `auth.role()`), so the patterns are testable against
plain Postgres, run identically in CI, and carry no vendor dependency. Swap the shim for
real Supabase and nothing else changes.

```js
// tests/harness.js
await c.query("set role app_user");                       // drop to an unprivileged role
await c.query("select set_config('request.jwt.claims', $1, false)",
              [JSON.stringify({ sub: userId, role: "authenticated" })]);
```

## Layout

```
sql/001_schema.sql              tenants, profiles, releases, webhook ledger
sql/002_rls.sql                 row scope + force RLS + service-role bypass
sql/003_privileged_columns.sql  the trigger that closes the column gap
sql/004_metering.sql            security definer metering + idempotent webhooks
tests/harness.js                migrate, seed, and impersonate callers
tests/isolation.test.js         the 15 attacks
```

MIT. Written by [Harrison C. Songolo](https://xkaii.studio).
