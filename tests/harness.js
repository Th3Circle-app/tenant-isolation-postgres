import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const HERE = dirname(fileURLToPath(import.meta.url));
const SQL_DIR = join(HERE, "..", "sql");

export const CONN =
  process.env.DATABASE_URL ||
  "postgres://postgres:postgres@localhost:55432/postgres";

/**
 * Applies every migration in order against a fresh schema.
 * Runs as the superuser, which is the only place we ever do so.
 */
export async function migrate() {
  const admin = new pg.Client({ connectionString: CONN });
  await admin.connect();
  await admin.query("drop schema if exists public cascade");
  await admin.query("drop schema if exists auth cascade");
  await admin.query("create schema public");

  for (const f of readdirSync(SQL_DIR).filter((f) => f.endsWith(".sql")).sort()) {
    await admin.query(readFileSync(join(SQL_DIR, f), "utf8"));
  }

  // The role end users connect as. It owns nothing, so `force row level
  // security` and the trigger both apply to it.
  await admin.query(`
    do $$ begin
      if not exists (select 1 from pg_roles where rolname = 'app_user') then
        create role app_user nologin;
      end if;
    end $$;
  `);
  await admin.query("grant usage on schema public, auth to app_user");
  await admin.query(
    "grant select, insert, update, delete on all tables in schema public to app_user"
  );
  await admin.query(
    "grant execute on all functions in schema public, auth to app_user"
  );

  await admin.end();
}

/** Seeds two tenants with one user each, plus a release owned by each. */
export async function seed() {
  const admin = new pg.Client({ connectionString: CONN });
  await admin.connect();
  const { rows } = await admin.query(`
    with t as (
      insert into tenants (name) values ('Acme Records'), ('Rival Records')
      returning id, name
    ),
    p as (
      insert into profiles (id, tenant_id, email, display_name)
      select gen_random_uuid(), t.id, lower(replace(t.name,' ','')) || '@example.com', t.name
      from t
      returning id, tenant_id, email
    )
    select p.id as user_id, p.tenant_id, p.email from p order by p.email;
  `);
  const [acme, rival] = rows;

  await admin.query(
    `insert into releases (tenant_id, created_by, title)
     values ($1,$2,'Acme Single'), ($3,$4,'Rival Single')`,
    [acme.tenant_id, acme.user_id, rival.tenant_id, rival.user_id]
  );
  await admin.end();
  return { acme, rival };
}

/**
 * A connection that impersonates one caller, the way PostgREST does:
 * assume the low-privilege role, then attach the JWT claims.
 */
export async function as(userId, role = "authenticated") {
  const c = new pg.Client({ connectionString: CONN });
  await c.connect();
  await c.query("set role app_user");
  await c.query("select set_config('request.jwt.claims', $1, false)", [
    JSON.stringify({ sub: userId, role }),
  ]);
  return c;
}

/** Service-role connection: trusted server-side caller (webhooks, cron). */
export async function asService() {
  const c = new pg.Client({ connectionString: CONN });
  await c.connect();
  await c.query("set role app_user");
  await c.query("select set_config('request.jwt.claims', $1, false)", [
    JSON.stringify({ sub: null, role: "service_role" }),
  ]);
  return c;
}
