import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import { migrate, seed, as, asService } from "./harness.js";

let acme, rival, acmeConn, rivalConn, service;

before(async () => {
  await migrate();
  ({ acme, rival } = await seed());
  acmeConn = await as(acme.user_id);
  rivalConn = await as(rival.user_id);
  service = await asService();
});

after(async () => {
  await Promise.all([acmeConn?.end(), rivalConn?.end(), service?.end()]);
});

describe("row isolation", () => {
  test("a tenant sees only its own releases", async () => {
    const { rows } = await acmeConn.query("select title from releases");
    assert.deepEqual(rows.map((r) => r.title), ["Acme Single"]);
  });

  test("a tenant cannot read another tenant's profile", async () => {
    const { rows } = await acmeConn.query(
      "select id from profiles where id = $1",
      [rival.user_id]
    );
    assert.equal(rows.length, 0, "rival profile must be invisible");
  });

  test("a tenant cannot delete another tenant's release", async () => {
    const { rowCount } = await acmeConn.query(
      "delete from releases where title = 'Rival Single'"
    );
    assert.equal(rowCount, 0, "delete must affect zero rows");

    const { rows } = await service.query(
      "select 1 from releases where title = 'Rival Single'"
    );
    assert.equal(rows.length, 1, "rival release must still exist");
  });

  test("a tenant cannot insert a release into another tenant", async () => {
    await assert.rejects(
      () =>
        acmeConn.query(
          "insert into releases (tenant_id, created_by, title) values ($1,$2,'Smuggled')",
          [rival.tenant_id, acme.user_id]
        ),
      /row-level security/i
    );
  });
});

describe("privileged columns: the gap RLS alone does not close", () => {
  // This is the important one. The row belongs to the caller, so the RLS
  // policy is satisfied. Only the trigger stops it.
  test("a user cannot upgrade their own plan", async () => {
    await assert.rejects(
      () => acmeConn.query("update profiles set plan = 'pro' where id = $1", [acme.user_id]),
      /plan is not user-writable/
    );

    const { rows } = await acmeConn.query("select plan from profiles where id = $1", [
      acme.user_id,
    ]);
    assert.equal(rows[0].plan, "free", "plan must be unchanged");
  });

  test("a user cannot make themselves an admin", async () => {
    await assert.rejects(
      () => acmeConn.query("update profiles set is_admin = true where id = $1", [acme.user_id]),
      /is_admin is not user-writable/
    );
  });

  test("a user cannot reset their own usage counter", async () => {
    // Spend a slot first, so "reset to zero" is a real change rather than a
    // no-op. A trigger comparing old vs new correctly ignores no-op writes.
    await service.query("update profiles set releases_used = 1 where id = $1", [
      acme.user_id,
    ]);

    await assert.rejects(
      () => acmeConn.query("update profiles set releases_used = 0 where id = $1", [acme.user_id]),
      /releases_used is not user-writable/
    );

    // ...and cannot inflate it either.
    await assert.rejects(
      () => acmeConn.query("update profiles set releases_used = 999 where id = $1", [acme.user_id]),
      /releases_used is not user-writable/
    );

    // Put it back so the metering suite starts from a known state.
    await service.query("update profiles set releases_used = 0 where id = $1", [
      acme.user_id,
    ]);
  });

  test("a user cannot move themselves into another tenant", async () => {
    await assert.rejects(
      () =>
        acmeConn.query("update profiles set tenant_id = $1 where id = $2", [
          rival.tenant_id,
          acme.user_id,
        ]),
      /tenant_id is not user-writable/
    );
  });

  test("non-privileged columns on your own row still update normally", async () => {
    await acmeConn.query("update profiles set display_name = 'Acme A&R' where id = $1", [
      acme.user_id,
    ]);
    const { rows } = await acmeConn.query(
      "select display_name from profiles where id = $1",
      [acme.user_id]
    );
    assert.equal(rows[0].display_name, "Acme A&R");
  });
});

describe("metering the client cannot lie about", () => {
  test("the free plan allows exactly one release, enforced in the database", async () => {
    // Seeded usage is 0 and the seeded release was inserted server-side, so the
    // first call succeeds and the second is refused by the function.
    const first = await acmeConn.query("select * from consume_release_slot($1)", [
      "First Real Release",
    ]);
    assert.equal(first.rows[0].title, "First Real Release");

    await assert.rejects(
      () => acmeConn.query("select * from consume_release_slot($1)", ["Second Release"]),
      /free plan allows/
    );
  });

  test("the counter is incremented by the database, not the caller", async () => {
    const { rows } = await acmeConn.query(
      "select releases_used from profiles where id = $1",
      [acme.user_id]
    );
    assert.equal(rows[0].releases_used, 1);
  });

  test("the internal-write flag does not leak past the transaction", async () => {
    // consume_release_slot set app.internal_write inside its own transaction.
    // If that leaked, this direct update would now succeed. It must not.
    await assert.rejects(
      () => acmeConn.query("update profiles set plan = 'pro' where id = $1", [acme.user_id]),
      /plan is not user-writable/
    );
  });

  test("upgrading via the service role lifts the limit", async () => {
    await service.query("select apply_subscription_event($1,$2,$3)", [
      "evt_upgrade_1",
      acme.user_id,
      "pro",
    ]);
    const ok = await acmeConn.query("select * from consume_release_slot($1)", [
      "Now Allowed",
    ]);
    assert.equal(ok.rows[0].title, "Now Allowed");
  });
});

describe("webhook idempotency", () => {
  test("replaying the same Stripe event is a no-op", async () => {
    const first = await service.query("select apply_subscription_event($1,$2,$3) as applied", [
      "evt_replay_1",
      rival.user_id,
      "pro",
    ]);
    const second = await service.query("select apply_subscription_event($1,$2,$3) as applied", [
      "evt_replay_1",
      rival.user_id,
      "pro",
    ]);
    assert.equal(first.rows[0].applied, true, "first delivery applies");
    assert.equal(second.rows[0].applied, false, "replay must not re-apply");
  });

  test("an end user cannot call the subscription applier directly", async () => {
    await assert.rejects(
      () =>
        acmeConn.query("select apply_subscription_event($1,$2,$3)", [
          "evt_forged",
          acme.user_id,
          "pro",
        ]),
      /only the service role/
    );
  });
});
