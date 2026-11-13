import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { eq, sql } from "drizzle-orm";
import { incidents, modelProviders, users, vigilSecrets, withTenant } from "@vigil/db";
import { getDb } from "../src/db.js";
import { hashPassword } from "../src/lib/crypto.js";
import { app, as, Client, resetDb, seedTenant, startAgentStub } from "./helpers.js";

let A: Awaited<ReturnType<typeof seedTenant>>;
let B: Awaited<ReturnType<typeof seedTenant>>;
let stub: Awaited<ReturnType<typeof startAgentStub>>;
const KEY = "sk-test-SECRET-provider-key-123456";
const ownerA = () => as("owner@alpha.test", "pw-owner-123456");

async function newIncident(tenantId: string) {
  return withTenant(getDb(), { tenantId }, async (tx) => {
    const [{ n }] = (await tx.execute(sql`select vigil_next_case_number(${tenantId}::uuid) as n`)) as unknown as Array<{ n: number }>;
    const [i] = await tx.insert(incidents).values({ tenantId, caseNumber: n, title: "test", severity: "medium", correlationKey: `k${n}`, firstSeen: new Date(), lastSeen: new Date() }).returning();
    return i!.id;
  });
}

beforeAll(async () => {
  await resetDb();
  A = await seedTenant("alpha");
  B = await seedTenant("bravo");
  stub = await startAgentStub();
});
afterAll(async () => { await stub.close(); });

describe("customer-configured AI model providers", () => {
  let providerId = "";

  it("admin can add a customer-hosted provider; the API key is stored encrypted and never returned", async () => {
    const o = await ownerA();
    const r = await o.post("/model-providers", { name: "Local Ollama", kind: "openai_compatible", baseUrl: "http://host.docker.internal:11434/v1", apiKey: KEY, hosting: "customer_hosted", priceInputPerMtok: 0, priceOutputPerMtok: 0 });
    expect(r.status).toBe(200);
    providerId = r.json.provider.id;
    expect(r.json.provider.hasApiKey).toBe(true);
    expect(JSON.stringify(r.json)).not.toContain(KEY);
    const list = await o.get("/model-providers");
    expect(JSON.stringify(list.json)).not.toContain(KEY);
    expect(JSON.stringify(list.json)).not.toContain("secretRef");
    const rows = await withTenant(getDb(), { tenantId: A.tenantId }, (tx) => tx.select().from(vigilSecrets));
    expect(rows.length).toBe(1);
    expect(rows[0]!.ciphertext).not.toContain(KEY);
    const audit = await o.get("/audit-logs?limit=20");
    expect(JSON.stringify(audit.json)).not.toContain(KEY);
  });

  it("analysts and viewers cannot manage providers", async () => {
    const an = await as("analyst@alpha.test", "pw-analyst-123456");
    expect((await an.post("/model-providers", { name: "x", kind: "openai", hosting: "external", priceInputPerMtok: 1, priceOutputPerMtok: 1 })).status).toBe(403);
    expect((await an.req("PUT", "/settings/ai", { dataPolicy: "disabled" })).status).toBe(403);
  });

  it("rejects metadata / link-local endpoints and unpriced external providers", async () => {
    const o = await ownerA();
    for (const baseUrl of ["http://169.254.169.254/v1", "http://metadata.google.internal/v1", "http://[fe80::1]/v1", "file:///etc/passwd", "http://user:pw@10.0.0.1/v1"]) {
      const r = await o.post("/model-providers", { name: `bad ${baseUrl}`, kind: "openai_compatible", baseUrl, hosting: "customer_hosted", priceInputPerMtok: 0, priceOutputPerMtok: 0 });
      expect(r.status, baseUrl).toBe(400);
    }
    const free = await o.post("/model-providers", { name: "free external", kind: "openai", hosting: "external", priceInputPerMtok: 0, priceOutputPerMtok: 0 });
    expect(free.status).toBe(400);
  });

  it("tenant B cannot see tenant A's providers or secrets (RLS)", async () => {
    const b = await as("owner@bravo.test", "pw-owner-123456");
    expect((await b.get("/model-providers")).json.items).toEqual([]);
    expect((await b.req("PATCH", `/model-providers/${providerId}`, { enabled: false })).status).toBe(404);
    const n = await withTenant(getDb(), { tenantId: B.tenantId }, (tx) => tx.select({ n: sql<number>`count(*)::int` }).from(vigilSecrets));
    expect(n[0]!.n).toBe(0);
  });

  it("an agent version can use the provider; the run dispatch carries endpoint, key and price to the worker only", async () => {
    const o = await ownerA();
    const defs = (await o.get("/agents")).json.definitions;
    const inv = defs.find((d: any) => d.role === "investigation_analyst" && d.enabled);
    const v = await o.post(`/agents/${inv.id}/versions`, { modelProvider: "openai_compatible", modelProviderId: providerId, modelName: "llama3.1:8b", allowedTools: inv.allowedTools,
      maxSteps: 10, timeoutSeconds: 120, tokenBudget: 100000, costBudgetUsd: 1 });
    expect(v.status).toBe(200);
    expect(v.json.definition.modelProvider).toBe("openai_compatible");
    const incidentId = await newIncident(A.tenantId);
    const r = await o.post(`/incidents/${incidentId}/investigate`, { role: "investigation_analyst" });
    expect(r.status).toBe(200);
    const sent = stub.runs[stub.runs.length - 1];
    expect(sent.model).toMatchObject({ provider: "openai_compatible", name: "llama3.1:8b", endpoint: "http://host.docker.internal:11434/v1", api_key: KEY, price_input_per_mtok: 0 });
    // key is not persisted on the run or in the audit log
    const ws = await o.get(`/incidents/${incidentId}`);
    expect(JSON.stringify(ws.json)).not.toContain(KEY);
  });

  it("data policy: customer_hosted_only blocks external models, disabled blocks all AI runs", async () => {
    const o = await ownerA();
    expect((await o.req("PUT", "/settings/ai", { dataPolicy: "customer_hosted_only" })).status).toBe(200);
    const defs = (await o.get("/agents")).json.definitions;
    const tri = defs.find((d: any) => d.role === "detection_analyst" && d.enabled); // still env-mode gemini = external
    expect(tri.modelProviderId).toBeNull();
    const i1 = await newIncident(A.tenantId);
    const blocked = await o.post(`/incidents/${i1}/investigate`, { role: "detection_analyst" });
    expect(blocked.status).toBe(409);
    expect(blocked.json.error.code).toBe("ai_policy_violation");
    const allowed = await o.post(`/incidents/${i1}/investigate`, { role: "investigation_analyst" }); // customer-hosted provider
    expect(allowed.status).toBe(200);
    expect((await o.req("PUT", "/settings/ai", { dataPolicy: "disabled" })).status).toBe(200);
    const i2 = await newIncident(A.tenantId);
    const off = await o.post(`/incidents/${i2}/investigate`, { role: "investigation_analyst" });
    expect(off.json.error.code).toBe("ai_disabled");
    await o.req("PUT", "/settings/ai", { dataPolicy: "any" });
  });

  it("a provider referenced by an agent version cannot be deleted", async () => {
    const o = await ownerA();
    expect((await o.req("DELETE", `/model-providers/${providerId}`)).status).toBe(409);
  });
});

describe("first administrator / one-time password", () => {
  it("a must-change-password user can only reach me/logout/change-password until the password is changed", async () => {
    const db = getDb();
    await db.update(users).set({ passwordHash: await hashPassword("one-time-pw-123456"), mustChangePassword: true }).where(eq(users.email, "viewer@alpha.test"));
    const c = await new Client().login("viewer@alpha.test", "one-time-pw-123456");
    expect((await c.get("/auth/me")).json.user.mustChangePassword).toBe(true);
    const blocked = await c.get("/incidents");
    expect(blocked.status).toBe(403);
    expect(blocked.json.error.code).toBe("password_change_required");
    expect((await c.post("/auth/change-password", { currentPassword: "wrong", newPassword: "a-much-better-password" })).status).toBe(400);
    expect((await c.post("/auth/change-password", { currentPassword: "one-time-pw-123456", newPassword: "short" })).status).toBe(400);
    expect((await c.post("/auth/change-password", { currentPassword: "one-time-pw-123456", newPassword: "a-much-better-password" })).status).toBe(200);
    expect((await c.get("/incidents")).status).toBe(200);
    await new Client().login("viewer@alpha.test", "a-much-better-password");
  });
});

describe("readiness", () => {
  it("/readyz reports database, schema and evidence store", async () => {
    const r = await app.request("/readyz");
    const j = (await r.json()) as any;
    expect(j.components.database.ok).toBe(true);
    expect(j.components.schema.ok).toBe(true);
    expect(j.components.evidenceStore.ok).toBe(true);
    expect(r.status).toBe(200);
    expect(JSON.stringify(j)).not.toMatch(/postgres:\/\//);
  });
});

void modelProviders;
