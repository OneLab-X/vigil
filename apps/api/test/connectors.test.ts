/**
 * Connector registry API contract: GET /connectors, generic create body, legacy body compatibility, RBAC,
 * tenant isolation and secret handling. Connector-specific suites (no live calls) live further down.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { sql } from "drizzle-orm";
import { getDb } from "../src/db.js";
import { setConnectorFetch } from "../src/services/connectors.js";
import { drainOnce } from "../src/worker.js";
import { AZ_SUB, AZ_TENANT, buildConnectorScenarios } from "@vigil/core";
import { as, app, ownerDb, resetDb, seedTenant } from "./helpers.js";

let A: Awaited<ReturnType<typeof seedTenant>>;
let B: Awaited<ReturnType<typeof seedTenant>>;
const owner = () => as("owner@conn-a.test", "pw-owner-123456");
const ownerB = () => as("owner@conn-b.test", "pw-owner-123456");

beforeAll(async () => {
  await resetDb();
  A = await seedTenant("conn-a");
  B = await seedTenant("conn-b");
});
afterAll(() => setConnectorFetch(undefined));

/** Everything the API ever returned or audited for tenant A, as one string, for "secret never leaks" assertions. */
async function everythingVisible(): Promise<string> {
  const o = await owner();
  const list = await o.get("/cloud-connections");
  const own = await ownerDb();
  const audit = await own.db.execute(sql`select details::text as d from audit_logs where tenant_id = ${A.tenantId}`);
  await own.close();
  return JSON.stringify(list.json) + JSON.stringify(audit);
}

describe("connector registry API", () => {
  it("GET /connectors lists registered connectors with field schemas and no secrets", async () => {
    const r = await (await owner()).get("/connectors");
    expect(r.status).toBe(200);
    const ids = r.json.items.map((c: any) => c.id);
    expect(ids).toEqual(expect.arrayContaining(["gcp", "aws"]));
    const gcp = r.json.items.find((c: any) => c.id === "gcp");
    expect(gcp).toMatchObject({ kind: "cloud", displayName: "Google Cloud" });
    expect(gcp.fields.find((f: any) => f.name === "projectId")).toMatchObject({ kind: "text", required: true });
    expect(gcp.configSchema.type).toBe("object");
    for (const c of r.json.items) for (const f of c.fields) if (f.secret) expect(f.default).toBeUndefined();
  });

  it("GET /connectors requires authentication", async () => {
    const res = await app.request("/api/v1/connectors");
    expect(res.status).toBe(401);
  });

  it("unknown provider → 400", async () => {
    const r = await (await owner()).post("/cloud-connections", { provider: "oracle", displayName: "x", config: {} });
    expect(r.status).toBe(400);
    expect(r.json.error.message).toMatch(/unknown provider/);
  });

  it("accepts the generic { provider, displayName, config, credentials } body", async () => {
    const o = await owner();
    const g = await o.post("/cloud-connections", { provider: "gcp", displayName: "generic gcp", config: { projectId: "generic-proj-1" } });
    expect(g.status).toBe(200);
    expect(g.json.connection).toMatchObject({ provider: "gcp", accountRef: "generic-proj-1", authMode: "adc", kind: "cloud", config: { projectId: "generic-proj-1", authMode: "adc" } });
    const a = await o.post("/cloud-connections", { provider: "aws", displayName: "generic aws", config: { accountId: "111122223333", roleArn: "arn:aws:iam::111122223333:role/vigil-reader" } });
    expect(a.status).toBe(200);
    expect(a.json.connection).toMatchObject({ accountRef: "111122223333", config: { regions: ["us-east-1"] }, secretRef: "[stored]" });
    expect(a.json.onboarding.trustPolicy.Statement[0].Condition.StringEquals["sts:ExternalId"]).toMatch(/^vigil-/);
  });

  it("still accepts the legacy flat GCP/AWS body", async () => {
    const o = await owner();
    const r = await o.post("/cloud-connections", { provider: "aws", displayName: "legacy", accountId: "444455556666", roleArn: "arn:aws:iam::444455556666:role/vigil-reader", regions: ["eu-west-1"] });
    expect(r.status).toBe(200);
    expect(r.json.connection.config).toEqual({ accountId: "444455556666", roleArn: "arn:aws:iam::444455556666:role/vigil-reader", regions: ["eu-west-1"] });
  });

  it("rejects credentials for connectors that take none, and invalid config", async () => {
    const o = await owner();
    expect((await o.post("/cloud-connections", { provider: "aws", displayName: "x", config: { accountId: "111122223333", roleArn: "arn:aws:iam::111122223333:role/r" }, credentials: { accessKey: "AKIA..." } })).status).toBe(400);
    const bad = await o.post("/cloud-connections", { provider: "gcp", displayName: "x", config: { projectId: "NOT VALID" } });
    expect(bad.status).toBe(400);
    expect(bad.json.error.code).toBe("validation_error");
  });

  it("stores GCP WIF config only in the secret store — never returned or audited", async () => {
    const o = await owner();
    const wif = { type: "external_account", audience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/MARKER-WIF-AUDIENCE" };
    const r = await o.post("/cloud-connections", { provider: "gcp", displayName: "wif", config: { projectId: "wif-proj-123", authMode: "wif" }, credentials: { wifCredentialConfig: wif } });
    expect(r.status).toBe(200);
    expect(r.json.connection.secretRef).toBe("[stored]");
    expect(await everythingVisible()).not.toContain("MARKER-WIF-AUDIENCE");
  });

  it("only connections:write may create connections", async () => {
    for (const email of ["analyst@conn-a.test", "viewer@conn-a.test"]) {
      const c = await as(email, email.startsWith("analyst") ? "pw-analyst-123456" : "pw-viewer-123456");
      expect((await c.post("/cloud-connections", { provider: "gcp", displayName: "x", config: { projectId: "rbac-proj-1" } })).status).toBe(403);
    }
  });

  it("tenant B cannot see, test or discover tenant A's connections", async () => {
    const list = await (await owner()).get("/cloud-connections");
    const id = list.json.items[0].id;
    const b = await ownerB();
    expect((await b.get("/cloud-connections")).json.items).toEqual([]);
    expect((await b.post(`/cloud-connections/${id}/test`)).status).toBe(404);
    expect((await b.get(`/cloud-connections/${id}/sources`)).status).toBe(404);
    expect((await b.req("DELETE", `/cloud-connections/${id}`)).status).toBe(404);
  });

  it("provider filters are validated against the registry", async () => {
    const o = await owner();
    expect((await o.get("/events?provider=gcp")).status).toBe(200);
    expect((await o.get("/events?provider=oracle")).status).toBe(400);
  });

  it("blocks a second active connection to the same account; allows it after disconnect", async () => {
    const o = await owner();
    const first = await o.post("/cloud-connections", { provider: "gcp", displayName: "dup A", config: { projectId: "dup-proj-123" } });
    expect(first.status).toBe(200);
    const again = await o.post("/cloud-connections", { provider: "gcp", displayName: "dup B", config: { projectId: "dup-proj-123" } });
    expect(again.status).toBe(409);
    expect(again.json.error.message).toMatch(/already exists \("dup A"\)/);
    expect((await o.req("DELETE", `/cloud-connections/${first.json.connection.id}`)).status).toBe(200);
    expect((await o.post("/cloud-connections", { provider: "gcp", displayName: "dup B", config: { projectId: "dup-proj-123" } })).status).toBe(200);
  });

  it("enabling a source works even when another connection to the same project owns the cloud account", async () => {
    // Regression: the account row is shared per project; a later connection re-linked it and enable crashed (acct undefined).
    const o = await owner();
    const list = (await o.get("/cloud-connections")).json.items;
    const a = list.find((c: any) => c.displayName === "dup A");
    const r = await o.post(`/cloud-connections/${a.id}/sources`, { sourceType: "gcp_audit_admin_activity", name: "Admin Activity audit logs", filter: 'logName="projects/dup-proj-123/logs/cloudaudit.googleapis.com%2Factivity"' });
    expect(r.status).toBe(200);
    expect(r.json.source.cloudAccountId).toBeTruthy();
  });

  it("provider columns are plain text (registry-validated) after migration 0008", async () => {
    const rows = await getDb().execute(sql`select table_name, data_type from information_schema.columns where (table_name, column_name) in (('cloud_connections','provider'),('cloud_accounts','provider'),('security_events','cloud_provider'))`);
    expect((rows as any[]).map((r) => r.data_type)).toEqual(["text", "text", "text"]);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// Per-connector contract: RBAC, tenant isolation, secrets never returned, test → over-privileged, ingest → events →
// detections. Each connector supplies a fake vendor (recorded/synthetic responses; no live calls).
// ---------------------------------------------------------------------------------------------------------------

interface ContractSpec {
  provider: string;
  config: Record<string, unknown>;
  credentials?: Record<string, unknown>;
  /** values that must never appear in any API response or audit row */
  secrets: string[];
  /** fake vendor; `privileged` switches the permission probe to an over-privileged identity */
  fakeFetch(state: { privileged: boolean; records: unknown[] }): typeof fetch;
  sourceType: string;
  sourceFilter?: string | null;
  records: () => unknown[];
  expectRules: string[];
}

export function connectorContract(name: string, spec: ContractSpec) {
  describe(`${name} connector API contract`, () => {
    const state = { privileged: false, records: [] as unknown[] };
    let connId = "";
    beforeAll(() => setConnectorFetch(spec.fakeFetch(state)));
    afterAll(() => setConnectorFetch(undefined));

    it("only connections:write may create", async () => {
      const an = await as("analyst@conn-a.test", "pw-analyst-123456");
      expect((await an.post("/cloud-connections", { provider: spec.provider, displayName: name, config: spec.config, credentials: spec.credentials })).status).toBe(403);
    });

    it("creates the connection; credentials go to the secret store only", async () => {
      const r = await (await owner()).post("/cloud-connections", { provider: spec.provider, displayName: name, config: spec.config, credentials: spec.credentials });
      expect(r.status).toBe(200);
      connId = r.json.connection.id;
      expect(r.json.connection.provider).toBe(spec.provider);
      if (spec.credentials) expect(r.json.connection.secretRef).toBe("[stored]");
      for (const s of spec.secrets) expect(JSON.stringify(r.json)).not.toContain(s);
    });

    it("Test reports OK + read-only, then over-privileged for a broader credential", async () => {
      const o = await owner();
      const ok = await o.post(`/cloud-connections/${connId}/test`);
      expect(ok.json).toMatchObject({ ok: true, readOnly: true });
      state.privileged = true;
      const over = await o.post(`/cloud-connections/${connId}/test`);
      state.privileged = false;
      expect(over.json).toMatchObject({ ok: true, readOnly: false });
      expect((await o.get("/cloud-connections")).json.items.find((c: any) => c.id === connId).status).toBe("degraded");
      await o.post(`/cloud-connections/${connId}/test`);
    });

    it("Sources lists presets; enabling one ingests events that reach Event Explorer and detections", async () => {
      const o = await owner();
      const disc = await o.get(`/cloud-connections/${connId}/sources`);
      expect(disc.status).toBe(200);
      const preset = disc.json.discovered.find((s: any) => s.sourceType === spec.sourceType);
      expect(preset).toBeTruthy();
      const src = await o.post(`/cloud-connections/${connId}/sources`, { sourceType: preset.sourceType, name: preset.name, filter: spec.sourceFilter === undefined ? preset.filter : spec.sourceFilter });
      expect(src.status).toBe(200);
      state.records = spec.records();
      const end = new Date(), start = new Date(end.getTime() - 6 * 3600_000);
      const job = await o.post("/ingestion/jobs", { logSourceId: src.json.source.id, start: start.toISOString(), end: end.toISOString() });
      expect(job.status).toBe(200);
      await drainOnce(getDb());
      const jobs = await o.get(`/ingestion/jobs?logSourceId=${src.json.source.id}`);
      expect(jobs.json.items[0]).toMatchObject({ status: "succeeded" });
      expect(jobs.json.items[0].eventsInserted).toBeGreaterThan(0);
      const evs = await o.get(`/events?start=${start.toISOString()}&limit=200`);
      expect(evs.json.total).toBeGreaterThan(0);
      const f = await o.get("/findings?limit=200");
      const fired = new Set(f.json.items.map((x: any) => x.rule.ruleId));
      for (const r of spec.expectRules) expect(fired, `${r} should fire`).toContain(r);
      // re-ingest is idempotent
      await o.post("/ingestion/jobs", { logSourceId: src.json.source.id, start: start.toISOString(), end: end.toISOString() });
      await drainOnce(getDb());
      expect((await o.get(`/ingestion/jobs?logSourceId=${src.json.source.id}`)).json.items[0]).toMatchObject({ status: "succeeded", eventsInserted: 0 });
    });

    it("tenant B cannot see, test or ingest from it", async () => {
      const b = await ownerB();
      expect((await b.get("/cloud-connections")).json.items.find((c: any) => c.id === connId)).toBeUndefined();
      expect((await b.post(`/cloud-connections/${connId}/test`)).status).toBe(404);
      expect((await b.get(`/cloud-connections/${connId}/sources`)).status).toBe(404);
      expect((await b.get(`/events?provider=${spec.provider}`)).json.total).toBe(0);
    });

    it("secrets never appear in responses, test results or audit logs", async () => {
      const o = await owner();
      const t = await o.post(`/cloud-connections/${connId}/test`);
      const visible = await everythingVisible() + JSON.stringify(t.json);
      for (const s of spec.secrets) expect(visible).not.toContain(s);
    });
  });
}

// ---------- Azure ----------
const AZ_SECRET = "azSecret~API-TEST-0123456789abcdef";
const jwt = (claims: Record<string, unknown>) => `eyJhbGciOiJub25lIn0.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.sig`;
const jres = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

connectorContract("Azure", {
  provider: "azure",
  config: { tenantId: AZ_TENANT, subscriptionId: AZ_SUB, clientId: "99999999-8888-7777-6666-555555555555", authMode: "client_secret", entraSource: "graph" },
  credentials: { clientSecret: AZ_SECRET },
  secrets: [AZ_SECRET],
  sourceType: "azure_activity_log",
  sourceFilter: null,
  records: () => {
    const s = buildConnectorScenarios(new Date(Date.now() - 2 * 3600_000)).find((x) => x.id === "azure-privesc-tamper")!;
    return s.records.map((r) => r.raw);
  },
  expectRules: ["VGL-AZ-001", "VGL-CFG-002", "VGL-CFG-001"],
  fakeFetch: (state) => (async (input: any, init?: RequestInit) => {
    const u = new URL(String(input));
    if (u.host === "login.microsoftonline.com") {
      // echo the secret in an error-ish field to prove scrubbing never lets it through
      if (new URLSearchParams(String(init?.body)).get("client_secret") !== AZ_SECRET) return new Response(`invalid secret`, { status: 401 });
      const graph = (new URLSearchParams(String(init?.body)).get("scope") ?? "").includes("graph");
      return jres({ access_token: jwt({ tid: AZ_TENANT, appid: "app", idtyp: "app", app_displayname: "vigil-reader", ...(graph ? { roles: ["AuditLog.Read.All"] } : {}) }), expires_in: 3600 });
    }
    if (u.pathname.endsWith("/providers/Microsoft.Authorization/permissions")) return jres({ value: [state.privileged ? { actions: ["*"], notActions: [] } : { actions: ["*/read"], notActions: [] }] });
    if (u.pathname.toLowerCase().endsWith("/eventtypes/management/values")) return jres({ value: state.records });
    if (u.host === "graph.microsoft.com") return jres({ value: [] });
    if (u.pathname.includes("Microsoft.Security/alerts")) return jres({ value: [] });
    return jres({ error: `unexpected ${u}`, echoed: AZ_SECRET }, 404);
  }) as typeof fetch,
});

// ---------- Datadog ----------
const DD_API = "c".repeat(28) + "DDAK";
const DD_APP = "d".repeat(36) + "DDA9";

connectorContract("Datadog", {
  provider: "datadog",
  config: { site: "datadoghq.com", orgName: "acme-prod", indexes: ["main"] },
  credentials: { apiKey: DD_API, appKey: DD_APP },
  secrets: [DD_API, DD_APP],
  sourceType: "datadog_logs",
  records: () => buildConnectorScenarios(new Date(Date.now() - 2 * 3600_000)).find((x) => x.id === "datadog-cloudtrail-persistence")!.records.map((r) => r.raw),
  expectRules: ["VGL-IAM-002", "VGL-CFG-002"],
  fakeFetch: (state) => (async (input: any, init?: RequestInit) => {
    const u = new URL(String(input));
    const h = new Headers(init?.headers);
    if (u.host !== "api.datadoghq.com" || h.get("dd-api-key") !== DD_API || h.get("dd-application-key") !== DD_APP) return jres({ errors: [`Forbidden for ${h.get("dd-api-key")}`] }, 403);
    if (u.pathname === "/api/v1/validate") return jres({ valid: true });
    if (u.pathname === "/api/v2/current_user/application_keys") return state.privileged ? jres({ data: [{ id: "k", attributes: { name: "vigil", last4: "DDA9", scopes: null } }] }) : jres({ errors: ["Forbidden"] }, 403);
    if (u.pathname === "/api/v2/logs/events/search") {
      const body = JSON.parse(String(init?.body));
      return jres(body.page.cursor ? { data: [], meta: { page: {} } } : { data: body.filter.from.startsWith("now") ? state.records.slice(0, 1) : state.records, meta: { page: { after: "next" } } });
    }
    if (u.pathname.endsWith("/search")) return jres({ data: [], meta: { page: {} } });
    return jres({ errors: ["not found"] }, 404);
  }) as typeof fetch,
});

// ---------- New Relic ----------
const NR_KEY = "NRAK-" + "APITESTKEY0123456789ABCDE";

connectorContract("New Relic", {
  provider: "newrelic",
  config: { region: "US", accountId: 7654321 },
  credentials: { userApiKey: NR_KEY },
  secrets: [NR_KEY],
  sourceType: "newrelic_logs",
  records: () => buildConnectorScenarios(new Date(Date.now() - 2 * 3600_000)).find((x) => x.id === "newrelic-cloudtrail")!.records.map((r) => r.raw),
  expectRules: ["VGL-IAM-002", "VGL-CFG-002"],
  fakeFetch: (state) => (async (input: any, init?: RequestInit) => {
    if (String(input) !== "https://api.newrelic.com/graphql") return jres({ errors: [{ message: "wrong endpoint" }] }, 404);
    if (new Headers(init?.headers).get("api-key") !== NR_KEY) return jres({ errors: [{ message: `bad key ${new Headers(init?.headers).get("api-key")}` }] }, 401);
    const { query, variables } = JSON.parse(String(init?.body));
    if (query.includes("user { id email name }")) return jres({ data: { actor: { user: { id: 7, email: "vigil-reader@example.com" }, account: { id: 7654321 } } } });
    if (query.includes("userManagement")) return jres({ data: { actor: { organization: { userManagement: { authenticationDomains: { authenticationDomains: [{ users: { users: [{ groups: { groups: [{ displayName: state.privileged ? "Admin" : "Read Only" }] } }] } }] } } } } } });
    const nrql = String(variables.nrql);
    if (nrql.startsWith("SELECT count(*)")) return jres({ data: { actor: { account: { nrql: { results: [{ count: 3 }] } } } } });
    return jres({ data: { actor: { account: { nrql: { results: nrql.startsWith("SELECT * FROM Log") ? state.records : [] } } } } });
  }) as typeof fetch,
});
