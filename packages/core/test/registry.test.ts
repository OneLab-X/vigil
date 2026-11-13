import { describe, it, expect } from "vitest";
import {
  awsConnectorDefinition, connectorIds, describeConnector, gcpConnectorDefinition, getConnector, gaeRequest, cloudTrail, listConnectors,
  normalizeCloudTrail, normalizeGcpEntry, normalizerFor, registerConnector, RuleDefinitionSchema, SEED_RULES, sigmaToRule, splitLegacyBody,
  scrubSecrets, scrubError, ConnectorError, assertSameOriginLink, decodeStoredSecrets, encodeStoredSecrets,
} from "../src/index.js";

const rt = { production: false, env: {} };

describe("connector registry", () => {
  it("registers the built-in GCP and AWS connectors", () => {
    expect(connectorIds()).toEqual(expect.arrayContaining(["gcp", "aws"]));
    expect(getConnector("gcp")).toBe(gcpConnectorDefinition);
    expect(getConnector("nope")).toBeUndefined();
    for (const d of listConnectors()) {
      expect(d.id).toMatch(/^[a-z][a-z0-9_]{1,31}$/);
      expect(["cloud", "log_platform"]).toContain(d.kind);
    }
  });

  it("refuses duplicate, reserved and malformed ids", () => {
    expect(() => registerConnector(gcpConnectorDefinition)).toThrow(/already registered/);
    expect(() => registerConnector({ ...gcpConnectorDefinition, id: "any" })).toThrow();
    expect(() => registerConnector({ ...gcpConnectorDefinition, id: "Bad Id" })).toThrow(/invalid connector id/);
  });

  it("describes connectors as field schemas without secret values", () => {
    const g = describeConnector(gcpConnectorDefinition, rt);
    expect(g.fields.map((f) => f.name)).toEqual(["projectId", "authMode", "quotaProjectId", "wifCredentialConfig"]);
    const auth = g.fields.find((f) => f.name === "authMode")!;
    expect(auth).toMatchObject({ kind: "select", default: "adc", required: false });
    expect(auth.options!.map((o) => o.value)).toEqual(["adc", "wif", "gcloud_cli"]);
    expect(g.fields.find((f) => f.name === "projectId")).toMatchObject({ kind: "text", required: true, pattern: "^[a-z][a-z0-9-]{4,28}[a-z0-9]$" });
    expect(g.fields.find((f) => f.name === "wifCredentialConfig")).toMatchObject({ scope: "credentials", kind: "json", showWhen: { authMode: ["wif"] } });
    const a = describeConnector(awsConnectorDefinition, rt);
    expect(a.fields.find((f) => f.name === "regions")).toMatchObject({ kind: "list", default: ["us-east-1"] });
    expect(a.credentialSchema).toBeNull();
  });

  it("hides dev-only auth modes in production", () => {
    const g = describeConnector(gcpConnectorDefinition, { production: true });
    expect(g.fields.find((f) => f.name === "authMode")!.options!.map((o) => o.value)).not.toContain("gcloud_cli");
    expect(g.authModes.find((m) => m.id === "gcloud_cli")!.available).toBe(false);
  });

  it("splits the legacy flat request body into config and credentials", () => {
    const { config, credentials } = splitLegacyBody(gcpConnectorDefinition, { projectId: "example-project", authMode: "wif", wifCredentialConfig: { type: "external_account" } });
    expect(config).toEqual({ projectId: "example-project", authMode: "wif" });
    expect(credentials).toEqual({ wifCredentialConfig: { type: "external_account" } });
    expect(splitLegacyBody(awsConnectorDefinition, { accountId: "111122223333" }).credentials).toBeUndefined();
  });

  it("validates GCP auth constraints exactly like the previous hardcoded route", () => {
    const v = (cfg: any, cred?: any, production = false) => gcpConnectorDefinition.validate!(gcpConnectorDefinition.configSchema.parse(cfg), cred, { production, env: {} });
    expect(v({ projectId: "example-project", authMode: "gcloud_cli" }, undefined, true)).toMatch(/local development only/);
    expect(v({ projectId: "example-project", authMode: "wif" })).toMatch(/wifCredentialConfig required/);
    expect(v({ projectId: "example-project", authMode: "wif" }, { wifCredentialConfig: { type: "service_account" } })).toMatch(/external_account/);
    expect(v({ projectId: "example-project" })).toBeNull();
  });

  it("keeps the historical secret formats (raw WIF JSON, raw AWS ExternalId)", () => {
    const s = awsConnectorDefinition.prepareSecrets(awsConnectorDefinition.configSchema.parse({ accountId: "111122223333", roleArn: "arn:aws:iam::111122223333:role/r" }), undefined) as { externalId: string };
    expect(s.externalId).toMatch(/^vigil-[0-9a-f]{36}$/);
    expect(encodeStoredSecrets(awsConnectorDefinition, s)).toBe(s.externalId);
    expect(decodeStoredSecrets(awsConnectorDefinition, s.externalId)).toEqual(s);
    const wif = { type: "external_account", audience: "x" };
    expect(JSON.parse(encodeStoredSecrets(gcpConnectorDefinition, wif))).toEqual(wif);
  });

  it("registry normalizers produce the same events as the direct normalizers", () => {
    const g = gaeRequest({ ts: new Date("2026-11-11T10:00:00Z"), ip: "203.0.113.5", path: "/x", status: 404 });
    const cfg = gcpConnectorDefinition.configSchema.parse({ projectId: "example-project" });
    expect(normalizerFor(gcpConnectorDefinition, "gcp_gae_app")(g, { config: cfg, sourceType: "gcp_gae_app" })).toEqual(normalizeGcpEntry(g, { projectId: "example-project", sourceType: "gcp_gae_app" }));
    const ct = cloudTrail({ ts: new Date(), name: "CreateUser", source: "iam.amazonaws.com", arn: "arn:aws:iam::111122223333:user/x", ip: "203.0.113.1" });
    const acfg = awsConnectorDefinition.configSchema.parse({ accountId: "111122223333", roleArn: "arn:aws:iam::111122223333:role/r" });
    expect(normalizerFor(awsConnectorDefinition, "aws_cloudtrail_management")(ct, { config: acfg, sourceType: "aws_cloudtrail_management" }))
      .toEqual(normalizeCloudTrail(ct, { accountId: "111122223333", sourceType: "aws_cloudtrail_management" }));
  });
});

describe("detection DSL provider validation", () => {
  it("accepts any + registered connector ids and rejects unknown providers", () => {
    const base = SEED_RULES[0]!;
    expect(RuleDefinitionSchema.parse({ ...base, provider: "aws" }).provider).toBe("aws");
    expect(RuleDefinitionSchema.parse({ ...base, provider: undefined }).provider).toBe("any");
    expect(() => RuleDefinitionSchema.parse({ ...base, provider: "oracle" })).toThrow(/registered connector id/);
  });
  it("sigma maps logsource.product through the registry", () => {
    const sig = (product: string) => sigmaToRule({ title: "Test rule", logsource: { product }, detection: { sel: { eventName: "x" }, condition: "sel" } }, "SIGMA-T1").provider;
    expect(sig("gcp")).toBe("gcp");
    expect(sig("windows")).toBe("any");
  });
});

describe("connector SDK helpers", () => {
  it("scrubs exact secret values and generic tokens from error text", () => {
    const key = "dd0123456789abcdef0123456789abcd";
    expect(scrubSecrets(`HTTP 403: invalid key ${key} (Bearer abc.def-ghi)`, [key])).toBe("HTTP 403: invalid key [REDACTED] (Bearer [REDACTED])");
    const e = scrubError(new ConnectorError(`bad ${key}`, 429, true, 1000), [key]) as ConnectorError;
    expect(e.message).toBe("bad [REDACTED]");
    expect([e.status, e.retryable, e.retryAfterMs]).toEqual([429, true, 1000]);
  });
  it("only follows pagination links on the expected origin/path", () => {
    expect(assertSameOriginLink("https://management.azure.com/subscriptions/x/providers/a?b=1", "https://management.azure.com", "/subscriptions/x/")).toContain("management.azure.com");
    expect(() => assertSameOriginLink("https://evil.example/subscriptions/x/", "https://management.azure.com", "/subscriptions/x/")).toThrow(/refusing/);
    expect(() => assertSameOriginLink("https://management.azure.com/other", "https://management.azure.com", "/subscriptions/x/")).toThrow(/refusing/);
  });
});

describe("GCP onboarding checklist", () => {
  const onboard = (authMode: string) => gcpConnectorDefinition.onboardingInstructions(gcpConnectorDefinition.configSchema.parse({ projectId: "example-project", authMode }), null, { production: false, env: {} }) as any;
  it("gcloud_cli shows only the login + grant steps, no service-account or federation setup", () => {
    const o = onboard("gcloud_cli");
    expect(o.steps.map((s: any) => s.title)).toEqual([
      "Log in with gcloud on the machine running Vigil",
      "Make sure your account can read logs (skip if you are already Owner, Editor or Logs Viewer)",
      "Click Test on the connection below",
      "Open Sources and enable what you need",
    ]);
    expect(o.commands.join(" ")).not.toMatch(/service-accounts create|workload-identity/);
    expect(o.note).toMatch(/Never create or upload service-account keys/);
  });
  it("adc uses application-default login; wif keeps the service-account + federation setup", () => {
    expect(onboard("adc").commands).toContain("gcloud auth application-default login");
    const w = onboard("wif").commands.join("\n");
    expect(w).toMatch(/service-accounts create vigil-reader --project=example-project/);
    expect(w).toMatch(/workload-identity-pools create/);
  });
});

describe("GCP probe when Cloud Resource Manager is disabled", () => {
  it("does not claim read-only and names the project to enable", async () => {
    const { GcpConnector } = await import("../src/connectors/gcp.js");
    const long = "Cloud Resource Manager API has not been used in project example-quota-project before or it is disabled. Enable it by visiting https://console.developers.google.com/apis/api/cloudresourcemanager.googleapis.com/overview?project=example-quota-project then retry. If you enabled this API recently, wait a few minutes for the action to propagate to our systems and retry.";
    const f = (async (u: any) => String(u).includes("testIamPermissions")
      ? new Response(JSON.stringify({ error: { code: 403, status: "PERMISSION_DENIED", message: long, details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", reason: "SERVICE_DISABLED", metadata: { consumer: "projects/example-quota-project", service: "cloudresourcemanager.googleapis.com" } }] } }, null, 2), { status: 403 })
      : String(u).includes("userinfo") ? new Response('{"email":"dev@example.com"}', { status: 200 })
      : new Response('{"entries":[]}', { status: 200 })) as typeof fetch;
    const c = new GcpConnector({ projectId: "example-project", authMode: "adc" }, undefined, f);
    (c as any).client = { getRequestHeaders: async () => ({}) };
    (c as any).auth = { getCredentials: async () => ({}) };
    const r = await c.testConnection();
    // same project as the connection → no quota-project suggestion
    const f2 = (async (u: any) => String(u).includes("testIamPermissions") ? new Response(JSON.stringify({ error: { code: 403, message: "Cloud Resource Manager API has not been used in project example-project before or it is disabled." } }), { status: 403 }) : new Response("{}", { status: 200 })) as typeof fetch;
    const c2 = new GcpConnector({ projectId: "example-project", authMode: "adc" }, undefined, f2);
    (c2 as any).client = { getRequestHeaders: async () => ({}) }; (c2 as any).auth = { getCredentials: async () => ({}) };
    const w2 = (await c2.testConnection()).warnings[0]!;
    expect(w2).toMatch(/project example-project/);
    expect(w2).not.toMatch(/quota project:/);
    expect(r.ok).toBe(true);
    expect(r.checks).toEqual([]);
    expect(r.warnings[0]).toMatch(/Read-only NOT verified.*project example-quota-project.*services enable cloudresourcemanager\.googleapis\.com --project=example-quota-project \(or make example-project your quota project/);
    expect(r.principal).toBe("dev@example.com");
  });
});

describe("GCP auth client cache", () => {
  it("builds one Google auth client per credential (library deprecation warnings print once, not per job)", async () => {
    const { cachedGoogleAuth, clearGoogleAuthCache } = await import("../src/connectors/gcp.js");
    const { vi } = await import("vitest");
    clearGoogleAuthCache();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const wif = { type: "external_account", audience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x", subject_token_type: "urn:ietf:params:oauth:token-type:jwt", token_url: "https://sts.googleapis.com/v1/token", credential_source: { file: "/nonexistent/token" } };
    const dep = () => warn.mock.calls.filter((c) => /deprecated/.test(String(c[0]))).length;
    const a = await cachedGoogleAuth(wif);
    const afterFirst = dep();
    const b = await cachedGoogleAuth({ ...wif });
    expect(dep()).toBe(afterFirst); // cache hit: credential not re-parsed, no new warnings
    const other = await cachedGoogleAuth({ ...wif, audience: wif.audience + "2" });
    expect(b.client).toBe(a.client);
    expect(other.client).not.toBe(a.client);
    warn.mockRestore();
    clearGoogleAuthCache();
  });
});
