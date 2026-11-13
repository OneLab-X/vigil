import { describe, it, expect, beforeAll } from "vitest";
import { sql, eq } from "drizzle-orm";
import { cloudConnections, securityEvents, withTenant, auditLogs } from "@vigil/db";
import { buildScenarios, normalizeGcpEntry } from "@vigil/core";
import { getDb } from "../src/db.js";
import { storeRawPage } from "../src/services/ingestion.js";
import { as, app, resetDb, seedTenant, internal } from "./helpers.js";
import { resetRateLimits } from "../src/lib/ratelimit.js";
import { signToken } from "../src/lib/crypto.js";

/** Drizzle wraps driver errors; assert on the underlying Postgres message. */
async function pgError(p: Promise<unknown>): Promise<string> {
  try { await p; } catch (e: any) { return `${e.message} ${e.cause?.message ?? ""}`; }
  return "no error";
}

let A: Awaited<ReturnType<typeof seedTenant>>;
let B: Awaited<ReturnType<typeof seedTenant>>;

beforeAll(async () => {
  await resetDb();
  A = await seedTenant("alpha");
  B = await seedTenant("bravo");
  const db = getDb();
  const s = buildScenarios()[0]!;
  await withTenant(db, { tenantId: A.tenantId }, (tx) => storeRawPage(tx, { tenantId: A.tenantId, cloudAccountId: null, logSourceId: null, sourceType: "gcp_gae_app" }, s.gcp!, (r) => normalizeGcpEntry(r as any, { projectId: "example-project", sourceType: "gcp_gae_app" })));
});

describe("tenant isolation (RLS)", () => {
  it("tenant B cannot see tenant A events, even with no WHERE clause", async () => {
    const db = getDb();
    const a = await withTenant(db, { tenantId: A.tenantId }, (tx) => tx.select({ n: sql<number>`count(*)::int` }).from(securityEvents));
    const b = await withTenant(db, { tenantId: B.tenantId }, (tx) => tx.select({ n: sql<number>`count(*)::int` }).from(securityEvents));
    expect(a[0]!.n).toBeGreaterThan(0);
    expect(b[0]!.n).toBe(0);
  });

  it("no tenant context → no rows", async () => {
    const rows = await getDb().select({ n: sql<number>`count(*)::int` }).from(securityEvents);
    expect(rows[0]!.n).toBe(0);
  });

  it("cannot insert a row for another tenant", async () => {
    expect(await pgError(withTenant(getDb(), { tenantId: B.tenantId }, (tx) => tx.insert(cloudConnections).values({ tenantId: A.tenantId, provider: "gcp", displayName: "evil", config: {} })))).toMatch(/row-level security/);
  });

  it("cannot read another tenant's event by id via the API", async () => {
    const [ev] = await withTenant(getDb(), { tenantId: A.tenantId }, (tx) => tx.select({ id: securityEvents.id }).from(securityEvents).limit(1));
    const b = await as("owner@bravo.test", "pw-owner-123456");
    expect((await b.get(`/events/${ev!.id}`)).status).toBe(404);
    const a = await as("owner@alpha.test", "pw-owner-123456");
    expect((await a.get(`/events/${ev!.id}`)).status).toBe(200);
  });

  it("cannot switch into a tenant without membership", async () => {
    const b = await as("owner@bravo.test", "pw-owner-123456");
    expect((await b.post("/auth/switch-tenant", { tenantId: A.tenantId })).status).toBe(403);
  });

  it("raw evidence and normalized events are immutable for the app role", async () => {
    expect(await pgError(withTenant(getDb(), { tenantId: A.tenantId }, (tx) => tx.update(securityEvents).set({ action: "tampered" })))).toMatch(/permission denied/);
    expect(await pgError(withTenant(getDb(), { tenantId: A.tenantId }, (tx) => tx.execute(sql`update raw_event_references set sha256 = 'x'`)))).toMatch(/permission denied/);
  });

  it("audit log is append-only for the app role and the hash chain verifies", async () => {
    expect(await pgError(withTenant(getDb(), { tenantId: A.tenantId }, (tx) => tx.execute(sql`delete from audit_logs`)))).toMatch(/permission denied/);
    expect(await pgError(withTenant(getDb(), { tenantId: A.tenantId }, (tx) => tx.update(auditLogs).set({ action: "x" })))).toMatch(/permission denied/);
    const a = await as("owner@alpha.test", "pw-owner-123456");
    const v = await a.get("/audit-logs/verify");
    expect(v.json.ok).toBe(true);
    expect(v.json.entries).toBeGreaterThan(0);
  });
});

describe("authentication, CSRF, RBAC", () => {
  it("rejects bad passwords with a generic error", async () => {
    const res = await app.request("/api/v1/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "owner@alpha.test", password: "wrong" }) });
    expect(res.status).toBe(401);
    const res2 = await app.request("/api/v1/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "nobody@alpha.test", password: "wrong" }) });
    expect(res2.status).toBe(401);
    expect(await res.json()).toEqual(expect.objectContaining({ error: expect.objectContaining({ code: "invalid_credentials" }) }));
  });

  it("rate-limits repeated login attempts", async () => {
    resetRateLimits();
    const codes: number[] = [];
    for (let i = 0; i < 12; i++) codes.push((await app.request("/api/v1/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "viewer@alpha.test", password: "nope" }) })).status);
    expect(codes).toContain(429);
    resetRateLimits();
  });

  it("requires auth for data endpoints", async () => {
    expect((await app.request("/api/v1/events")).status).toBe(401);
  });

  it("requires the CSRF header on mutations", async () => {
    const c = await as("owner@alpha.test", "pw-owner-123456");
    const r = await c.req("POST", "/cloud-connections", { provider: "gcp", displayName: "x", projectId: "example-project" }, { csrf: false });
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe("csrf");
  });

  it("viewer can read but cannot write; analyst cannot manage connections", async () => {
    const v = await as("viewer@alpha.test", "pw-viewer-123456");
    expect((await v.get("/incidents")).status).toBe(200);
    expect((await v.post("/cloud-connections", { provider: "gcp", displayName: "x", projectId: "example-project" })).status).toBe(403);
    const an = await as("analyst@alpha.test", "pw-analyst-123456");
    expect((await an.post("/cloud-connections", { provider: "gcp", displayName: "x", projectId: "example-project" })).status).toBe(403);
    expect((await an.post("/detection-rules", { ruleId: "X-TEST" })).status).toBe(403);
  });

  it("validates input with Zod", async () => {
    const c = await as("owner@alpha.test", "pw-owner-123456");
    const r = await c.post("/cloud-connections", { provider: "gcp", displayName: "x", projectId: "NOT VALID" });
    expect(r.status).toBe(400);
    expect(r.json.error.code).toBe("validation_error");
  });

  it("refuses WIF configs that are service-account keys", async () => {
    const c = await as("owner@alpha.test", "pw-owner-123456");
    const r = await c.post("/cloud-connections", { provider: "gcp", displayName: "x", projectId: "example-project", authMode: "wif", wifCredentialConfig: { type: "service_account", private_key: "-----BEGIN PRIVATE KEY-----" } });
    expect(r.status).toBe(400);
  });

  it("serves an OpenAPI document", async () => {
    const res = await app.request("/api/v1/openapi.json");
    const doc = (await res.json()) as any;
    expect(doc.openapi).toBe("3.1.0");
    expect(Object.keys(doc.paths)).toEqual(expect.arrayContaining(["/api/v1/incidents/{id}/investigate", "/api/v1/cloud-connections/{id}/test", "/api/v1/events"]));
  });
});

describe("tool broker hardening", () => {
  it("rejects forged and expired run tokens", async () => {
    expect((await internal("/broker/tools/search_events", "garbage.token", {})).status).toBe(401);
    const forged = Buffer.from(JSON.stringify({ run_id: crypto.randomUUID(), tenant_id: A.tenantId, role: "investigation_analyst", tools: ["search_events"], exp: 9e9 })).toString("base64url") + ".AAAA";
    expect((await internal("/broker/tools/search_events", forged, {})).status).toBe(401);
    const expired = signToken({ run_id: crypto.randomUUID(), tenant_id: A.tenantId, role: "investigation_analyst", tools: ["search_events"], exp: 1 });
    expect((await internal("/broker/tools/search_events", expired, {})).status).toBe(401);
  });
  it("rejects valid-signature tokens for runs that are not active", async () => {
    const t = signToken({ run_id: crypto.randomUUID(), tenant_id: A.tenantId, role: "investigation_analyst", tools: ["search_events"], exp: Math.floor(Date.now() / 1000) + 60 });
    expect((await internal("/broker/tools/search_events", t, {})).status).toBe(409);
  });
});
