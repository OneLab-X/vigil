import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import {
  DatadogConnector, datadogConnectorDefinition, normalizeDatadog, buildConnectorScenarios, normalizeScenario, runRules, SEED_RULES,
  ddLog, ddNginx, ddAuth, ddCloudTrail, ddSignal, ddAudit, ddGcp, cloudTrail, gcpAudit, normalizeCloudTrail, deduplicationKey,
  describeConnector, unflatten, getPath, type DetectableEvent,
} from "../src/index.js";

const API_KEY = "a".repeat(28) + "K3Y1";
const APP_KEY = "b".repeat(36) + "APP9";
const json = (body: unknown, status = 200, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
const cfg = datadogConnectorDefinition.configSchema.parse({ site: "datadoghq.eu", orgName: "acme", indexes: ["main"], baseQuery: "env:prod" });

interface Fake { scopes?: string[] | null | "forbidden"; validate?: number; onSearch?: (path: string, body: any) => Response | undefined }
function fakeDatadog(o: Fake = {}) {
  const calls: Array<{ path: string; body: any; headers: Headers }> = [];
  const f = (async (input: any, init?: RequestInit) => {
    const u = new URL(String(input));
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ path: u.pathname, body, headers: new Headers(init?.headers) });
    expect(u.origin).toBe("https://api.datadoghq.eu");
    if (u.pathname === "/api/v1/validate") return o.validate ? json({ errors: ["Forbidden"] }, o.validate) : json({ valid: true });
    if (u.pathname === "/api/v2/current_user/application_keys") {
      if (o.scopes === "forbidden" || o.scopes === undefined) return json({ errors: ["Forbidden"] }, 403);
      return json({ data: [{ id: "k1", attributes: { name: "other", last4: "zzzz", scopes: null } }, { id: "k2", attributes: { name: "vigil-reader", last4: "APP9", scopes: o.scopes } }] });
    }
    const custom = o.onSearch?.(u.pathname, body);
    if (custom) return custom;
    if (u.pathname.endsWith("/search")) return json({ data: [], meta: { page: {} } });
    return json({ errors: ["not found"] }, 404);
  }) as typeof fetch;
  return { f, calls };
}
const conn = (f: typeof fetch, sleeps: number[] = []) => new DatadogConnector(cfg, { apiKey: API_KEY, appKey: APP_KEY }, undefined, { fetch: f }, { sleep: async (ms) => { sleeps.push(ms); } });

describe("Datadog permission probe", () => {
  it("scoped key that cannot list app keys → OK, read-only", async () => {
    const { f, calls } = fakeDatadog();
    const r = await conn(f).testConnection();
    expect(r).toMatchObject({ ok: true, readOnly: true, provider: "datadog", accountRef: "acme@datadoghq.eu", sampleReadOk: true });
    expect(r.checks.find((c) => c.permission === "logs_read_data")).toMatchObject({ granted: true, required: true });
    expect(calls[0]!.headers.get("dd-api-key")).toBe(API_KEY);
    expect(calls.every((c) => c.path === "/api/v1/validate" || c.path.startsWith("/api/v2/current_user") || c.path.endsWith("/search"))).toBe(true); // read-only endpoints only
  });
  it("key scoped exactly to logs_read_data (+ optional reads) → read-only", async () => {
    const r = await conn(fakeDatadog({ scopes: ["logs_read_data", "security_monitoring_signals_read", "audit_logs_read"] }).f).testConnection();
    expect(r.readOnly).toBe(true);
    expect(r.principal).toBe('application key "vigil-reader"');
  });
  it("broader scopes → over-privileged, each flagged", async () => {
    const r = await conn(fakeDatadog({ scopes: ["logs_read_data", "logs_write_pipelines", "user_access_manage"] }).f).testConnection();
    expect(r).toMatchObject({ ok: true, readOnly: false });
    expect(r.checks.filter((c) => c.excessive).map((c) => c.permission)).toEqual(["logs_write_pipelines", "user_access_manage"]);
  });
  it("unscoped key → over-privileged", async () => {
    const r = await conn(fakeDatadog({ scopes: null }).f).testConnection();
    expect(r.readOnly).toBe(false);
    expect(r.checks.find((c) => c.excessive)!.permission).toMatch(/unscoped/);
  });
  it("invalid API key → error, keys never echoed", async () => {
    const { f } = fakeDatadog({ validate: 403, onSearch: () => undefined });
    const f2 = (async (i: any, init?: RequestInit) => (String(i).endsWith("/api/v1/validate") ? new Response(`{"errors":["Forbidden: key ${API_KEY} / ${APP_KEY}"]}`, { status: 403 }) : f(i, init))) as typeof fetch;
    const r = await conn(f2).testConnection();
    expect(r.ok).toBe(false);
    const s = JSON.stringify(r);
    expect(s).not.toContain(API_KEY);
    expect(s).not.toContain(APP_KEY);
    expect(r.errors[0]).toContain("[REDACTED]");
  });
});

describe("Datadog paging, checkpoints and rate limits", () => {
  const start = new Date("2026-11-11T00:00:00Z"), end = new Date("2026-11-11T01:00:00Z");
  it("builds the search body (base query AND source filter, indexes, explicit bounds) and pages by cursor", async () => {
    const { f, calls } = fakeDatadog({ onSearch: (_p, body) => json(body.page.cursor === "c2" ? { data: [ddLog({ ts: start, source: "nginx" })], meta: { page: {} } } : { data: [ddLog({ ts: start, source: "nginx" })], meta: { page: { after: "c2" } } }) });
    const c = conn(f);
    const p1 = await c.listEvents({ sourceType: "datadog_logs", filter: "source:nginx", start, end });
    expect(calls[0]!.path).toBe("/api/v2/logs/events/search");
    expect(calls[0]!.body).toEqual({ filter: { query: "(env:prod) (source:nginx)", from: start.toISOString(), to: end.toISOString(), indexes: ["main"] }, sort: "timestamp", page: { limit: 1000 } });
    expect(p1.nextPageToken).toBe("c2");
    const p2 = await c.listEvents({ sourceType: "datadog_logs", filter: "source:nginx", start, end, pageToken: p1.nextPageToken });
    expect(calls[1]!.body.page).toEqual({ limit: 1000, cursor: "c2" });
    expect(p2.nextPageToken).toBeNull();
  });
  it("stops on an empty page even if a cursor is returned", async () => {
    const { f } = fakeDatadog({ onSearch: () => json({ data: [], meta: { page: { after: "zzz" } } }) });
    expect((await conn(f).listEvents({ sourceType: "datadog_siem_signals", filter: "*", start, end })).nextPageToken).toBeNull();
  });
  it("retries 429 using X-RateLimit-Reset and pauses when the window is exhausted", async () => {
    let n = 0;
    const sleeps: number[] = [];
    const { f } = fakeDatadog({ onSearch: () => (++n === 1 ? json({ errors: ["Too many requests"] }, 429, { "x-ratelimit-remaining": "0", "x-ratelimit-reset": "7" }) : json({ data: [ddLog({ ts: start, source: "x" })], meta: { page: {} } }, 200, { "x-ratelimit-remaining": "0", "x-ratelimit-reset": "3" })) });
    const c = conn(f, sleeps);
    await c.listEvents({ sourceType: "datadog_logs", filter: null, start, end });
    expect(n).toBe(2);
    expect(sleeps[0]).toBe(7000); // Retry-After derived from x-ratelimit-reset
    await c.listEvents({ sourceType: "datadog_logs", filter: null, start, end });
    expect(sleeps.at(-1)).toBeGreaterThan(2000); // proactive pause after remaining=0
  });
  it("discovery lists editable presets and marks availability", async () => {
    const { f } = fakeDatadog({ onSearch: (p, b) => json({ data: p.includes("logs") && b.filter.query.includes("cloudtrail") ? [ddLog({ ts: start, source: "cloudtrail" })] : [], meta: { page: {} } }) });
    const d = await conn(f).discoverSources();
    expect(d.map((s) => s.sourceType)).toEqual(expect.arrayContaining(["datadog_siem_signals", "datadog_audit", "datadog_logs"]));
    expect(d.find((s) => s.filter === "source:cloudtrail")).toMatchObject({ available: true, meta: { editableFilter: true } });
    expect(d.find((s) => s.filter === "source:(nginx OR apache OR haproxy OR traefik)")!.available).toBe(false);
  });
});

describe("Datadog normalization (golden)", () => {
  const ts = new Date("2026-11-11T10:00:00Z");
  it("maps Datadog standard attributes; never invents fields", () => {
    const e = normalizeDatadog(ddNginx({ ts, ip: "203.0.113.5", method: "post", path: "/login?password=hunter2", status: 401 }), "datadog_logs", "acme@datadoghq.com");
    expect(e).toMatchObject({
      cloudProvider: "datadog", projectOrAccountReference: "acme@datadoghq.com", sourceType: "datadog_logs", sourceName: "nginx",
      sourceIp: "203.0.113.5", httpStatus: 401, httpMethod: "POST", urlPath: "/login", status: "failure", principal: null, destinationIp: null, region: null,
      resourceType: "host", resourceId: "web-01", serviceName: "storefront", severity: "medium", normalizedEventType: "auth.failure",
    });
    expect(e.categories).toEqual(expect.arrayContaining(["http.request", "http.client_error", "auth.failure"]));
    expect(JSON.stringify(e.normalized)).not.toContain("hunter2");
  });
  it("evt.outcome drives auth success/failure", () => {
    expect(normalizeDatadog(ddAuth({ ts, ip: "192.0.2.1", user: "u@x.example", outcome: "failure" }), "datadog_logs", null)).toMatchObject({ categories: ["auth.failure"], principal: "u@x.example", status: "failure" });
    expect(normalizeDatadog(ddAuth({ ts, ip: "192.0.2.1", user: "u@x.example", outcome: "success" }), "datadog_logs", null).categories).toEqual(["auth.success"]);
  });
  it("delegates forwarded CloudTrail to the AWS normalizer (same dedup key as direct ingestion)", () => {
    const ct = cloudTrail({ ts, name: "CreateAccessKey", source: "iam.amazonaws.com", arn: "arn:aws:iam::111122223333:user/x", ip: "203.0.113.150" });
    const viaDd = normalizeDatadog(ddCloudTrail(ct), "datadog_logs", "acme@datadoghq.com");
    const direct = normalizeCloudTrail(ct, { sourceType: "aws_cloudtrail_management" });
    const { normalized: n1, ...a } = viaDd; const { normalized: n2, ...b } = direct;
    expect(a).toEqual(b);
    expect((n1 as any).via).toMatchObject({ platform: "datadog", source: "cloudtrail" });
    expect(deduplicationKey(viaDd, "x")).toBe(deduplicationKey(direct, "y"));
  });
  it("delegates forwarded GCP LogEntries to the GCP normalizer", () => {
    const e = normalizeDatadog(ddGcp(gcpAudit({ ts, method: "google.logging.v2.ConfigServiceV2.DeleteSink", service: "logging.googleapis.com", principal: "c@example.com", ip: "203.0.113.99", resource: "projects/example-project/sinks/s" })), "datadog_logs", null);
    expect(e).toMatchObject({ cloudProvider: "gcp", projectOrAccountReference: "example-project", sourceType: "gcp_audit_admin_activity", normalizedEventType: "logging.config_change", principal: "c@example.com" });
  });
  it("delegates forwarded Azure Activity (diagnostic schema) and Entra sign-ins", () => {
    const az = normalizeDatadog(ddLog({ ts, source: "azure.network", attributes: { time: ts.toISOString(), resourceId: "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n", operationName: "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE", resultType: "Success", callerIpAddress: "203.0.113.1", category: "Administrative" } }), "datadog_logs", null);
    expect(az).toMatchObject({ cloudProvider: "azure", normalizedEventType: "firewall.change", projectOrAccountReference: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" });
    const si = normalizeDatadog(ddLog({ ts, source: "azure.active_directory", attributes: { time: ts.toISOString(), category: "SignInLogs", tenantId: "t-1", properties: { id: "s1", userPrincipalName: "u@x.example", ipAddress: "192.0.2.4", status: { errorCode: 50126 } } } }), "datadog_logs", null);
    expect(si).toMatchObject({ cloudProvider: "azure", categories: ["auth.failure"], providerEventId: "s1", projectOrAccountReference: "t-1" });
  });
  it("unknown shapes → app.log with nulls", () => {
    const e = normalizeDatadog(ddLog({ ts, source: "custom", message: "hello Bearer abc.def.ghi", attributes: { foo: { bar: 1 } } }), "datadog_logs", "acme@datadoghq.com");
    expect(e).toMatchObject({ normalizedEventType: "app.log", categories: ["app.log"], sourceIp: null, principal: null, httpStatus: null, action: null, status: null });
    expect((e.normalized as any).message).toBe("hello Bearer [REDACTED]");
    expect(() => normalizeDatadog({ id: "x", attributes: { message: "no ts" } }, "datadog_logs", null)).toThrow(/timestamp/);
  });
  it("SIEM signals → security.finding; audit trail → org tampering categories", () => {
    expect(normalizeDatadog(ddSignal({ ts, title: "Brute force on admin", severity: "high", ip: "198.51.100.1" }), "datadog_siem_signals", null)).toMatchObject({ categories: ["security.finding"], severity: "high", sourceIp: "198.51.100.1", action: "Brute force on admin" });
    expect(normalizeDatadog(ddAudit({ ts, user: "a@x.example", ip: "192.0.2.2", assetType: "api_key", assetName: "k", action: "created" }), "datadog_audit", null)).toMatchObject({ normalizedEventType: "iam.credential_create", status: "success", principal: "a@x.example" });
    expect(normalizeDatadog(ddAudit({ ts, user: "a@x.example", ip: "192.0.2.2", assetType: "logs_pipeline", assetName: "p", action: "deleted" }), "datadog_audit", null).categories).toContain("logging.config_change");
  });
  it("unflatten / getPath handle dotted and nested attributes safely", () => {
    expect(unflatten({ "http.status_code": 404, "http.method": "GET", "__proto__.x": 1 })).toEqual({ http: { status_code: 404, method: "GET" } });
    expect(getPath({ "network.client.ip": "1.2.3.4" }, "network.client.ip")).toBe("1.2.3.4");
    expect(getPath({ network: { "client.ip": "1.2.3.4" } }, "network.client.ip")).toBe("1.2.3.4");
  });
});

describe("Datadog detections + registry", () => {
  for (const s of buildConnectorScenarios().filter((x) => x.connector === "datadog")) {
    it(`scenario ${s.id} fires ${s.expectedRules.join(", ")}`, () => {
      const evs: DetectableEvent[] = normalizeScenario(s).map((e) => ({ ...e, id: randomUUID() }));
      const fired = new Set(runRules(SEED_RULES, evs).map((h) => h.ruleId));
      for (const r of s.expectedRules) expect(fired, `${r} should fire`).toContain(r);
    });
  }
  it("describes keys as secret fields and validates their shape", () => {
    const d = describeConnector(datadogConnectorDefinition, { production: true });
    expect(d.kind).toBe("log_platform");
    expect(d.fields.filter((f) => f.secret).map((f) => f.name)).toEqual(["apiKey", "appKey"]);
    expect(datadogConnectorDefinition.credentialSchema!.safeParse({ apiKey: "short", appKey: APP_KEY }).success).toBe(false);
    expect(datadogConnectorDefinition.accountRefOf(cfg)).toBe("acme@datadoghq.eu");
  });
});
