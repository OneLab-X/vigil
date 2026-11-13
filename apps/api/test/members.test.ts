import { describe, it, expect, beforeAll } from "vitest";
import { eq } from "drizzle-orm";
import { users } from "@vigil/db";
import { getDb } from "../src/db.js";
import { as, Client, clearSessions, resetDb, seedTenant } from "./helpers.js";

let A: Awaited<ReturnType<typeof seedTenant>>;
let B: Awaited<ReturnType<typeof seedTenant>>;
const ownerA = () => as("owner@alpha.test", "pw-owner-123456");

beforeAll(async () => {
  await resetDb();
  A = await seedTenant("alpha");
  B = await seedTenant("bravo");
});

describe("member management", () => {
  it("only owners can add, change or remove members", async () => {
    const body = { email: "nope@alpha.test", displayName: "Nope", role: "viewer" };
    for (const [email, pw] of [["analyst@alpha.test", "pw-analyst-123456"], ["viewer@alpha.test", "pw-viewer-123456"]] as const) {
      const c = await as(email, pw);
      expect((await c.post("/members", body)).status).toBe(403);
      expect((await c.patch(`/members/${A.viewer}`, { role: "analyst" })).status).toBe(403);
      expect((await c.req("DELETE", `/members/${A.viewer}`)).status).toBe(403);
    }
  });

  it("adding a new person creates an account with a one-time password that must be changed", async () => {
    const o = await ownerA();
    const r = await o.post("/members", { email: "  New.Person@Alpha.test ", displayName: "New Person", role: "analyst" });
    expect(r.status).toBe(200);
    expect(r.json.newAccount).toBe(true);
    expect(r.json.email).toBe("new.person@alpha.test");
    const otp: string = r.json.oneTimePassword;
    expect(otp.length).toBeGreaterThanOrEqual(20);

    const [u] = await getDb().select().from(users).where(eq(users.email, "new.person@alpha.test"));
    expect(u!.mustChangePassword).toBe(true);
    expect(u!.passwordHash).not.toContain(otp);

    const list = (await o.get("/members")).json.items;
    expect(list.find((m: any) => m.email === "new.person@alpha.test")).toMatchObject({ role: "analyst", mustChangePassword: true });

    const c = await new Client().login("new.person@alpha.test", otp);
    expect((await c.get("/incidents")).json.error.code).toBe("password_change_required");
    expect((await c.post("/auth/change-password", { currentPassword: otp, newPassword: "a-much-better-password" })).status).toBe(200);
    expect((await c.get("/incidents")).status).toBe(200);
    expect((await c.get("/auth/me")).json.role).toBe("analyst");

    const audit = (await o.get("/audit-logs?action=member.")).json.items;
    expect(audit.some((e: any) => e.action === "member.added" && e.targetId === r.json.id)).toBe(true);
    expect(JSON.stringify(audit)).not.toContain(otp);
  });

  it("adding someone who already has an account keeps their password and gives them the tenant", async () => {
    const o = await ownerA();
    const r = await o.post("/members", { email: "viewer@bravo.test", displayName: "ignored", role: "viewer" });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ newAccount: false, oneTimePassword: null });
    const v = await new Client().login("viewer@bravo.test", "pw-viewer-123456");
    expect((await v.get("/auth/me")).json.tenants.map((t: any) => t.id).sort()).toEqual([A.tenantId, B.tenantId].sort());
  });

  it("rejects duplicates and bad input", async () => {
    const o = await ownerA();
    expect((await o.post("/members", { email: "analyst@alpha.test", displayName: "x", role: "viewer" })).status).toBe(409);
    expect((await o.post("/members", { email: "not-an-email", displayName: "x", role: "viewer" })).status).toBe(400);
    expect((await o.post("/members", { email: "ok@alpha.test", displayName: "x", role: "superuser" })).status).toBe(400);
  });

  it("changes roles, effective on the member's next request", async () => {
    const o = await ownerA();
    const v = await as("viewer@alpha.test", "pw-viewer-123456");
    expect((await v.get("/auth/me")).json.role).toBe("viewer");
    expect((await o.patch(`/members/${A.viewer}`, { role: "analyst" })).status).toBe(200);
    expect((await v.get("/auth/me")).json.role).toBe("analyst");
    expect((await o.patch(`/members/${A.viewer}`, { role: "viewer" })).status).toBe(200);
  });

  it("cannot touch members of another tenant", async () => {
    const o = await ownerA();
    expect((await o.patch(`/members/${B.analyst}`, { role: "viewer" })).status).toBe(404);
    expect((await o.req("DELETE", `/members/${B.analyst}`)).status).toBe(404);
    const b = await as("analyst@bravo.test", "pw-analyst-123456");
    expect((await b.get("/auth/me")).json.role).toBe("analyst");
  });

  it("owners cannot demote or remove themselves, and the last owner is protected", async () => {
    const o = await ownerA();
    expect((await o.patch(`/members/${A.owner}`, { role: "viewer" })).status).toBe(400);
    expect((await o.req("DELETE", `/members/${A.owner}`)).status).toBe(400);
    // a second owner can step the first one down, but not leave zero owners
    expect((await o.patch(`/members/${A.analyst2}`, { role: "owner" })).status).toBe(200);
    const o2 = await as("reviewer@alpha.test", "pw-reviewer-123456");
    expect((await o2.patch(`/members/${A.owner}`, { role: "admin" })).status).toBe(200);
    expect((await o.patch(`/members/${A.analyst2}`, { role: "analyst" })).status).toBe(403);
    expect((await o2.get("/auth/me")).json.role).toBe("owner");
    // restore
    expect((await o2.patch(`/members/${A.owner}`, { role: "owner" })).status).toBe(200);
    expect((await o.patch(`/members/${A.analyst2}`, { role: "analyst" })).status).toBe(200);
  });

  it("removing a member revokes access to that tenant immediately", async () => {
    const o = await ownerA();
    const v = await as("viewer@alpha.test", "pw-viewer-123456");
    expect((await v.get("/incidents")).status).toBe(200);
    expect((await o.req("DELETE", `/members/${A.viewer}`)).status).toBe(200);
    expect((await v.get("/incidents")).status).toBe(403);
    expect((await o.get("/members")).json.items.some((m: any) => m.id === A.viewer)).toBe(false);
    expect((await o.req("DELETE", `/members/${A.viewer}`)).status).toBe(404);
    clearSessions();
  });
});
