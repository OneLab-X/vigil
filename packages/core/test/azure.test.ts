import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import {
  AzureConnector, azureConnectorDefinition, azureActionAllowed, buildConnectorScenarios, normalizeScenario, runRules, SEED_RULES,
  normalizeAzureActivity, normalizeEntraSignIn, normalizeEntraAudit, normalizeDefenderAlert, azureActivity, entraSignIn, entraAudit, defenderAlert,
  AZ_SUB, AZ_TENANT, describeConnector, RuleDefinitionSchema, sigmaToRule, type DetectableEvent,
} from "../src/index.js";

const SECRET = "azSecret~0123456789abcdefGHIJ";
const jwt = (claims: Record<string, unknown>) => `eyJhbGciOiJub25lIn0.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.sig`;
const json = (body: unknown, status = 200, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

const READER = [{ actions: ["*/read"], notActions: [] }];
const CONTRIBUTOR = [{ actions: ["*"], notActions: ["Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write", "Microsoft.Authorization/elevateAccess/Action"] }];
const OWNER = [{ actions: ["*"], notActions: [] }];
const UAA = [{ actions: ["*/read", "Microsoft.Authorization/*", "Microsoft.Support/*"], notActions: [] }];

interface FakeOpts { perms?: unknown[]; graphRoles?: string[]; tokenStatus?: number; tokenBody?: string; onUrl?: (u: URL, init?: RequestInit) => Response | undefined }
function fakeAzure(o: FakeOpts = {}) {
  const calls: string[] = [];
  const f = (async (input: any, init?: RequestInit) => {
    const u = new URL(String(input));
    calls.push(`${init?.method ?? "GET"} ${u.host}${u.pathname}`);
    const custom = o.onUrl?.(u, init);
    if (custom) return custom;
    if (u.host === "login.microsoftonline.com") {
      if (o.tokenStatus) return new Response(o.tokenBody ?? "{}", { status: o.tokenStatus });
      const scope = new URLSearchParams(String(init?.body)).get("scope") ?? "";
      const claims = scope.includes("graph") ? { tid: AZ_TENANT, appid: "app", idtyp: "app", roles: o.graphRoles ?? ["AuditLog.Read.All"] } : { tid: AZ_TENANT, appid: "app", idtyp: "app", app_displayname: "vigil-reader" };
      return json({ access_token: jwt(claims), expires_in: 3600 });
    }
    if (u.pathname.endsWith("/providers/Microsoft.Authorization/permissions")) return json({ value: o.perms ?? READER });
    if (u.pathname.toLowerCase().endsWith("/eventtypes/management/values")) return json({ value: [] });
    if (u.host === "graph.microsoft.com") return json({ value: [] });
    if (u.host === "api.loganalytics.io") return json({ tables: [{ name: "PrimaryResult", columns: [{ name: "ok", type: "int" }], rows: [[1]] }] });
    if (u.pathname.includes("Microsoft.Security/alerts")) return json({ value: [] });
    return json({ error: "unexpected " + u }, 404);
  }) as typeof fetch;
  return { f, calls };
}

const cfg = (over: Record<string, unknown> = {}) => azureConnectorDefinition.configSchema.parse({ tenantId: AZ_TENANT, subscriptionId: AZ_SUB, clientId: "99999999-8888-7777-6666-555555555555", authMode: "client_secret", ...over });
const connector = (f: typeof fetch, over: Record<string, unknown> = {}, production = false) => new AzureConnector(cfg(over), { clientSecret: SECRET }, undefined, { production, env: {}, fetch: f });

describe("Azure permission probe", () => {
  it("Reader / Monitoring Reader → OK and read-only", async () => {
    const r = await connector(fakeAzure().f).testConnection();
    expect(r).toMatchObject({ ok: true, readOnly: true, provider: "azure", accountRef: AZ_SUB, principal: "vigil-reader", credentialType: "client_secret:app" });
    expect(r.checks.find((c) => c.permission === "Microsoft.Insights/eventtypes/values/read")).toMatchObject({ granted: true, required: true });
    expect(r.checks.find((c) => c.permission === "graph:AuditLog.Read.All")).toMatchObject({ granted: true });
  });

  for (const [name, perms, mustFlag] of [["Owner", OWNER, "Microsoft.Authorization/roleAssignments/write"], ["Contributor", CONTRIBUTOR, "Microsoft.Resources/subscriptions/resourceGroups/write"], ["User Access Administrator", UAA, "Microsoft.Authorization/roleAssignments/write"]] as const) {
    it(`${name} → over-privileged`, async () => {
      const r = await connector(fakeAzure({ perms: perms as unknown[] }).f).testConnection();
      expect(r.ok).toBe(true);
      expect(r.readOnly).toBe(false);
      expect(r.checks.find((c) => c.permission === mustFlag)).toMatchObject({ granted: true, excessive: true });
      expect(r.warnings.join(" ")).toMatch(/Owner \/ Contributor \/ User Access Administrator/);
    });
  }

  it("Contributor's notActions exclude role-assignment writes", () => {
    expect(azureActionAllowed(CONTRIBUTOR, "Microsoft.Authorization/roleAssignments/write")).toBe(false);
    expect(azureActionAllowed(CONTRIBUTOR, "Microsoft.Network/networkSecurityGroups/write")).toBe(true);
    expect(azureActionAllowed(READER, "Microsoft.Insights/eventtypes/values/read")).toBe(true);
  });

  it("flags write-capable Graph permissions and missing AuditLog.Read.All", async () => {
    const over = await connector(fakeAzure({ graphRoles: ["AuditLog.Read.All", "Directory.ReadWrite.All"] }).f).testConnection();
    expect(over.readOnly).toBe(false);
    expect(over.checks.find((c) => c.permission === "graph:Directory.ReadWrite.All")).toMatchObject({ excessive: true, granted: true });
    const missing = await connector(fakeAzure({ graphRoles: [] }).f).testConnection();
    expect(missing.ok).toBe(false);
    expect(missing.errors.join(" ")).toMatch(/AuditLog\.Read\.All not granted/);
  });

  it("never leaks the client secret in errors", async () => {
    const { f } = fakeAzure({ tokenStatus: 401, tokenBody: `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided: ${SECRET}"}` });
    const r = await connector(f).testConnection();
    expect(r.ok).toBe(false);
    expect(JSON.stringify(r)).not.toContain(SECRET);
    expect(r.errors[0]).toMatch(/credential error: provider HTTP 401/);
    await expect(connector(f).listEvents({ sourceType: "azure_activity_log", filter: null, start: new Date(Date.now() - 3600_000), end: new Date() })).rejects.toSatisfy((e: Error) => !e.message.includes(SECRET));
  });

  it("refuses azure_cli in production and requires a clientId otherwise", async () => {
    const c = new AzureConnector(cfg({ authMode: "azure_cli" }), null, undefined, { production: true, env: {}, fetch: fakeAzure().f });
    expect((await c.testConnection()).errors[0]).toMatch(/disabled in production/);
    expect(azureConnectorDefinition.validate!(cfg({ authMode: "azure_cli" }), undefined, { production: true, env: {} })).toMatch(/local development only/);
    expect(azureConnectorDefinition.validate!(cfg({ clientId: undefined, authMode: "workload_identity" }), undefined, { production: false, env: {} })).toMatch(/clientId required/);
    expect(azureConnectorDefinition.validate!(cfg(), undefined, { production: false, env: {} })).toMatch(/clientSecret required/);
  });

  it("workload identity reads the federated token from the runtime env, not from tenant config", async () => {
    const fs = await import("node:fs/promises");
    const file = `/tmp/vigil-azure-wi-${randomUUID()}`;
    await fs.writeFile(file, "federated.jwt.value");
    let assertion = "";
    const { f } = fakeAzure({ onUrl: (u, init) => { if (u.host === "login.microsoftonline.com") { assertion = new URLSearchParams(String(init?.body)).get("client_assertion") ?? ""; } return undefined; } });
    const c = new AzureConnector(cfg({ authMode: "workload_identity" }), null, undefined, { production: true, env: { AZURE_FEDERATED_TOKEN_FILE: file }, fetch: f });
    expect((await c.testConnection()).ok).toBe(true);
    expect(assertion).toBe("federated.jwt.value");
    await fs.rm(file);
  });
});

describe("Azure paging, checkpoints and rate limits", () => {
  const start = new Date("2026-11-11T00:00:00Z"), end = new Date("2026-11-11T06:00:00Z");

  it("follows Activity Log nextLink as a resumable page token", async () => {
    const page2 = `https://management.azure.com/subscriptions/${AZ_SUB}/providers/microsoft.insights/eventtypes/management/values?api-version=2015-04-01&$skiptoken=abc`;
    let filter = "";
    const { f } = fakeAzure({ onUrl: (u) => {
      if (!u.pathname.toLowerCase().endsWith("/eventtypes/management/values")) return undefined;
      if (u.searchParams.get("$skiptoken")) return json({ value: [azureActivity({ ts: start, operation: "Microsoft.Compute/virtualMachines/write", caller: "a@b.example", ip: "192.0.2.1" })] });
      filter = u.searchParams.get("$filter") ?? "";
      return json({ value: [azureActivity({ ts: start, operation: "Microsoft.Compute/virtualMachines/write", caller: "a@b.example", ip: "192.0.2.1" })], nextLink: page2 });
    } });
    const c = connector(f);
    const p1 = await c.listEvents({ sourceType: "azure_activity_log", filter: "resourceGroupName eq 'prod-rg'", start, end });
    expect(filter).toBe("eventTimestamp ge '2026-11-11T00:00:00.000Z' and eventTimestamp le '2026-11-11T05:59:59.999Z' and (resourceGroupName eq 'prod-rg')");
    expect(p1.nextPageToken).toBe(page2);
    const p2 = await c.listEvents({ sourceType: "azure_activity_log", filter: null, start, end, pageToken: p1.nextPageToken });
    expect(p2).toMatchObject({ nextPageToken: null });
    expect(p2.raw).toHaveLength(1);
  });

  it("refuses page tokens that point outside the subscription's Activity Log endpoint", async () => {
    const c = connector(fakeAzure().f);
    await expect(c.listEvents({ sourceType: "azure_activity_log", filter: null, start, end, pageToken: "https://evil.example/subscriptions/x" })).rejects.toThrow(/refusing to follow/);
    await expect(c.listEvents({ sourceType: "azure_activity_log", filter: null, start, end, pageToken: `https://management.azure.com/subscriptions/${randomUUID()}/providers/microsoft.insights/eventtypes/management/values` })).rejects.toThrow(/refusing to follow/);
  });

  it("rejects filter injection", async () => {
    const c = connector(fakeAzure().f);
    await expect(c.listEvents({ sourceType: "azure_activity_log", filter: "x eq 'y'&$top=1", start, end })).rejects.toThrow(/unsupported characters/);
    const la = connector(fakeAzure().f, { entraSource: "log_analytics", workspaceId: "12345678-1234-1234-1234-123456789012" });
    await expect(la.listEvents({ sourceType: "azure_entra_signin", filter: "true | union *", start, end })).rejects.toThrow(/single where-predicate/);
  });

  it("honours 429 Retry-After from ARM and Graph", async () => {
    let n = 0;
    const { f } = fakeAzure({ onUrl: (u) => {
      if (u.host !== "graph.microsoft.com") return undefined;
      return ++n < 3 ? new Response("throttled", { status: 429, headers: { "retry-after": "0" } }) : json({ value: [entraSignIn({ ts: start, upn: "u@x.example", ip: "192.0.2.5", errorCode: 0 })], "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=2" });
    } });
    const p = await connector(f).listEvents({ sourceType: "azure_entra_signin", filter: null, start, end });
    expect(n).toBe(3);
    expect(p.raw).toHaveLength(1);
    expect(p.nextPageToken).toContain("$skiptoken=2");
  });

  it("splits Log Analytics windows that hit the row limit (no silent truncation)", async () => {
    const queries: string[] = [];
    const { f } = fakeAzure({ onUrl: (u, init) => {
      if (u.host !== "api.loganalytics.io") return undefined;
      const q = JSON.parse(String(init?.body)).query as string;
      queries.push(q);
      const [, s, e] = /datetime\(([^)]+)\) and TimeGenerated < datetime\(([^)]+)\)/.exec(q)!;
      const hours = (Date.parse(e!) - Date.parse(s!)) / 3600_000;
      const rows = hours > 1.5 ? 5000 : 3; // only small windows fit
      return json({ tables: [{ name: "PrimaryResult", columns: [{ name: "Id", type: "string" }, { name: "TimeGenerated", type: "datetime" }, { name: "Status", type: "dynamic" }], rows: Array.from({ length: rows }, (_, i) => [`id-${i}`, s, '{"errorCode":0}']) }] });
    } });
    const c = connector(f, { entraSource: "log_analytics", workspaceId: "12345678-1234-1234-1234-123456789012" });
    let token: string | null | undefined = null;
    let total = 0;
    const seenWindows: string[] = [];
    do {
      const p = await c.listEvents({ sourceType: "azure_entra_signin", filter: "AppDisplayName == 'Azure Portal'", start, end, pageToken: token });
      total += p.raw.length;
      token = p.nextPageToken;
      seenWindows.push(queries[queries.length - 1]!);
      expect((p.raw[0] as any)?.Status).toEqual({ errorCode: 0 }); // dynamic columns parsed
    } while (token);
    expect(queries[0]).toContain("| where (AppDisplayName == 'Azure Portal') | order by TimeGenerated asc | take 5000");
    expect(total).toBeGreaterThan(0);
    // windows are contiguous: every returned window starts where the previous ended
    const bounds = seenWindows.map((q) => /datetime\(([^)]+)\) and TimeGenerated < datetime\(([^)]+)\)/.exec(q)!.slice(1));
    expect(bounds[0]![0]).toBe(start.toISOString());
    expect(bounds[bounds.length - 1]![1]).toBe(end.toISOString());
    for (let i = 1; i < bounds.length; i++) expect(bounds[i]![0]).toBe(bounds[i - 1]![1]);
  });

  it("filters Defender alerts to the requested window client-side", async () => {
    const inWin = defenderAlert({ ts: new Date("2026-11-11T01:00:00Z"), title: "x", severity: "High", resourceId: `/subscriptions/${AZ_SUB}/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/v` });
    const outWin = defenderAlert({ ts: new Date("2026-11-10T01:00:00Z"), title: "y", severity: "Low", resourceId: `/subscriptions/${AZ_SUB}/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/v` });
    const { f } = fakeAzure({ onUrl: (u) => (u.pathname.includes("Microsoft.Security/alerts") ? json({ value: [inWin, outWin] }) : undefined) });
    const p = await connector(f).listEvents({ sourceType: "azure_defender_alerts", filter: null, start, end });
    expect(p.raw).toEqual([inWin]);
  });
});

describe("Azure normalization (golden)", () => {
  const ts = new Date("2026-11-11T10:00:00Z");
  it("role assignment write → iam.change + iam.privilege_grant with the built-in role name", () => {
    const e = normalizeAzureActivity(azureActivity({ ts, operation: "Microsoft.Authorization/roleAssignments/write", caller: "eve@contoso.example", ip: "203.0.113.7", roleDefinitionId: "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" }));
    expect(e).toMatchObject({
      cloudProvider: "azure", projectOrAccountReference: AZ_SUB, principal: "eve@contoso.example", sourceIp: "203.0.113.7", status: "success",
      action: "Microsoft.Authorization/roleAssignments/write", normalizedEventType: "iam.change", serviceName: "Microsoft.Authorization", region: null, httpStatus: null,
    });
    expect(e.categories).toEqual(["cloud.api_call", "iam.change", "iam.privilege_grant"]);
    expect((e.normalized as any).azure).toMatchObject({ role_name: "Owner", operation: "microsoft.authorization/roleassignments/write" });
  });
  it("NSG write → firewall.change; diagnostic setting delete → logging.config_change; Forbidden → blocked", () => {
    expect(normalizeAzureActivity(azureActivity({ ts, operation: "Microsoft.Network/networkSecurityGroups/securityRules/write", caller: "x", ip: "192.0.2.1" })).normalizedEventType).toBe("firewall.change");
    expect(normalizeAzureActivity(azureActivity({ ts, operation: "Microsoft.Insights/diagnosticSettings/delete", caller: "x", ip: "192.0.2.1" })).categories).toContain("logging.config_change");
    const denied = normalizeAzureActivity(azureActivity({ ts, operation: "Microsoft.Compute/virtualMachines/write", caller: "x", ip: "192.0.2.1", status: "Failed", subStatus: "Forbidden" }));
    expect(denied.status).toBe("blocked");
    expect(denied.categories).toContain("policy.denied");
  });
  it("handles the exported/diagnostic Activity Log schema (no invented ids)", () => {
    const e = normalizeAzureActivity({ time: ts.toISOString(), resourceId: `/SUBSCRIPTIONS/${AZ_SUB.toUpperCase()}/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/NSG1`, operationName: "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE", category: "Administrative", resultType: "Success", callerIpAddress: "203.0.113.9", correlationId: "c-1", identity: { claims: { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "ops@contoso.example" } }, level: "Information", location: "global" });
    expect(e).toMatchObject({ status: "success", principal: "ops@contoso.example", sourceIp: "203.0.113.9", normalizedEventType: "firewall.change", providerEventId: null, region: null, traceId: "c-1", resourceType: "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS" });
  });
  it("Entra sign-ins: success, failure, CA block, MFA interrupt", () => {
    expect(normalizeEntraSignIn(entraSignIn({ ts, upn: "u@x.example", ip: "192.0.2.1", errorCode: 0 }))).toMatchObject({ categories: ["auth.success"], status: "success", principal: "u@x.example", projectOrAccountReference: null });
    expect(normalizeEntraSignIn(entraSignIn({ ts, upn: "u@x.example", ip: "192.0.2.1", errorCode: 50126 }), { tenantId: AZ_TENANT })).toMatchObject({ categories: ["auth.failure"], status: "failure", projectOrAccountReference: AZ_TENANT });
    expect(normalizeEntraSignIn(entraSignIn({ ts, upn: "u@x.example", ip: "192.0.2.1", errorCode: 53003, ca: "failure" }))).toMatchObject({ categories: ["auth.failure", "policy.denied"], status: "blocked" });
    expect(normalizeEntraSignIn(entraSignIn({ ts, upn: "u@x.example", ip: "192.0.2.1", errorCode: 50074 }))).toMatchObject({ categories: [], normalizedEventType: "auth.interrupted" });
    // Log Analytics SigninLogs shape
    expect(normalizeEntraSignIn({ TimeGenerated: ts.toISOString(), Id: "la-1", UserPrincipalName: "u@x.example", IPAddress: "192.0.2.9", ResultType: "50126", AppDisplayName: "Azure Portal", UserAgent: "Mozilla/5.0" })).toMatchObject({ providerEventId: "la-1", sourceIp: "192.0.2.9", status: "failure", userAgent: "Mozilla/5.0" });
  });
  it("Entra audit: role grant and SP credential", () => {
    const g = normalizeEntraAudit(entraAudit({ ts, activity: "Add member to role", category: "RoleManagement", initiator: "a@x.example", ip: "192.0.2.3", roleName: "Global Administrator" }));
    expect(g.categories).toEqual(["cloud.api_call", "iam.change", "iam.privilege_grant"]);
    expect((g.normalized as any).entra.role_name).toBe("Global Administrator");
    const c = normalizeEntraAudit(entraAudit({ ts, activity: "Add service principal credentials", category: "ApplicationManagement", initiator: "a@x.example", ip: "192.0.2.3", target: { type: "ServicePrincipal", displayName: "sp" } }));
    expect(c).toMatchObject({ normalizedEventType: "iam.credential_create", resourceType: "entra_serviceprincipal", status: "success", sourceIp: "192.0.2.3" });
  });
  it("Defender alert → security.finding with mapped severity", () => {
    const e = normalizeDefenderAlert(defenderAlert({ ts, title: "Suspicious", severity: "High", resourceId: `/subscriptions/${AZ_SUB}/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/vm1`, ip: "203.0.113.4", account: "svc@contoso.example" }));
    expect(e).toMatchObject({ categories: ["security.finding"], severity: "high", sourceIp: "203.0.113.4", principal: "svc@contoso.example", resourceType: "Microsoft.Compute/virtualMachines", projectOrAccountReference: AZ_SUB });
  });
  it("throws on records without timestamps instead of inventing one", () => {
    expect(() => normalizeAzureActivity({ operationName: { value: "Microsoft.Compute/virtualMachines/write" } })).toThrow(/timestamp/);
  });
});

describe("Azure detections", () => {
  for (const s of buildConnectorScenarios().filter((x) => x.connector === "azure")) {
    it(`scenario ${s.id} fires ${s.expectedRules.join(", ")}`, () => {
      const evs: DetectableEvent[] = normalizeScenario(s).map((e) => ({ ...e, id: randomUUID() }));
      const fired = new Set(runRules(SEED_RULES, evs).map((h) => h.ruleId));
      for (const r of s.expectedRules) expect(fired, `${r} should fire`).toContain(r);
    });
  }
  it("Azure-specific rules validate and don't fire on other providers", () => {
    for (const r of SEED_RULES.filter((x) => x.provider === "azure")) expect(() => RuleDefinitionSchema.parse(r)).not.toThrow();
    const s = buildConnectorScenarios().find((x) => x.id === "azure-privesc-tamper")!;
    const asGcp = normalizeScenario(s).map((e) => ({ ...e, cloudProvider: "gcp", id: randomUUID() }));
    expect(runRules(SEED_RULES, asGcp).map((h) => h.ruleId)).not.toContain("VGL-AZ-001");
  });
  it("Sigma azure logsource maps to the azure provider", () => {
    expect(sigmaToRule({ title: "Azure thing", logsource: { product: "azure" }, detection: { sel: { eventName: "x" }, condition: "sel" } }, "SIGMA-AZ").provider).toBe("azure");
  });
  it("describes Azure fields for the UI, client secret as a secret field", () => {
    const d = describeConnector(azureConnectorDefinition, { production: true });
    expect(d.fields.find((f) => f.name === "clientSecret")).toMatchObject({ scope: "credentials", kind: "secret", secret: true, showWhen: { authMode: ["client_secret"] } });
    expect(d.fields.find((f) => f.name === "authMode")!.options!.map((o) => o.value)).toEqual(["workload_identity", "client_secret"]);
  });
});

describe("Azure masking", () => {
  it("tokenizes subscription ids (field and inside resource paths) with an azure hint", async () => {
    const { Masker } = await import("../src/masking.js");
    const m = new Masker();
    const out = m.mask({ account: AZ_SUB, message: `deleted /subscriptions/${AZ_SUB.toUpperCase()}/providers/microsoft.insights/diagnosticSettings/x by eve@contoso.example` });
    expect(out.account).toBe("[[ACCOUNT_1:azure]]");
    expect(out.message).toBe("deleted /subscriptions/[[ACCOUNT_1:azure]]/providers/microsoft.insights/diagnosticSettings/x by [[EMAIL_1]]");
  });
});
