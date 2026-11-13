import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import {
  NewRelicConnector, newRelicConnectorDefinition, newRelicKeyType, validateNrqlWhere, normalizeNewRelic, nrLog, nrAccess, nrCloudTrail, nrCloudTrailUnparsed,
  cloudTrail, normalizeCloudTrail, buildConnectorScenarios, normalizeScenario, runRules, SEED_RULES, describeConnector, ConnectorError, type DetectableEvent,
} from "../src/index.js";

const KEY = "NRAK-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0";
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const cfg = newRelicConnectorDefinition.configSchema.parse({ region: "EU", accountId: "1234567", nrqlWhere: "environment = 'prod'" });

interface Fake { groups?: string[] | "forbidden"; noAccount?: boolean; nrql?: (q: string) => Response | unknown[] | undefined }
function fakeNr(o: Fake = {}) {
  const queries: string[] = [];
  const f = (async (input: any, init?: RequestInit) => {
    expect(String(input)).toBe("https://api.eu.newrelic.com/graphql");
    if (new Headers(init?.headers).get("api-key") !== KEY) return json({ errors: [{ message: "Invalid API key", extensions: { errorClass: "UNAUTHORIZED" } }] });
    const { query, variables } = JSON.parse(String(init?.body));
    if (query.includes("user { id email name }")) return json({ data: { actor: { user: { id: 42, email: "vigil-reader@example.com" }, account: o.noAccount ? null : { id: 1234567, name: "Prod" } } } });
    if (query.includes("userManagement")) {
      if (o.groups === "forbidden" || o.groups === undefined) return json({ data: { actor: { organization: null } }, errors: [{ message: "Forbidden", extensions: { errorClass: "FORBIDDEN" } }] });
      return json({ data: { actor: { organization: { userManagement: { authenticationDomains: { authenticationDomains: [{ users: { users: [{ groups: { groups: o.groups.map((displayName) => ({ displayName })) } }] } }] } } } } } });
    }
    if (query.includes("nrql(")) {
      queries.push(variables.nrql);
      const r = o.nrql?.(variables.nrql);
      if (r instanceof Response) return r;
      return json({ data: { actor: { account: { nrql: { results: r ?? [{ count: 0 }] } } } } });
    }
    return json({ errors: [{ message: "unexpected" }] });
  }) as typeof fetch;
  return { f, queries };
}
const conn = (f: typeof fetch, key = KEY) => new NewRelicConnector(cfg, { userApiKey: key }, undefined, { fetch: f }, { sleep: async () => {} });

describe("New Relic key + permission probe", () => {
  it("classifies key types by prefix", () => {
    expect(newRelicKeyType(KEY)).toBe("user");
    expect(newRelicKeyType("NRAA-" + "0123456789abcdef0123456789a")).toBe("admin");
    expect(newRelicKeyType("0123456789abcdef0123456789abcdef0123NRAL")).toBe("ingest_license");
    expect(newRelicKeyType("NRII-xyz")).toBe("insert");
    expect(newRelicKeyType("NRJS-xyz")).toBe("browser");
    expect(newRelicConnectorDefinition.credentialSchema!.safeParse({ userApiKey: "NRAA-" + "0123456789abcdef0123456789a" }).success).toBe(false);
  });
  it("User key of a read-only user → OK, read-only", async () => {
    const r = await conn(fakeNr({ groups: ["Read Only"] }).f).testConnection();
    expect(r).toMatchObject({ ok: true, readOnly: true, provider: "newrelic", accountRef: "1234567", principal: "vigil-reader@example.com", credentialType: "user_api_key:EU" });
    expect(r.checks.find((c) => c.permission === "NerdGraph access to account 1234567")).toMatchObject({ granted: true });
  });
  it("user management not readable → OK with a verification warning", async () => {
    const r = await conn(fakeNr().f).testConnection();
    expect(r).toMatchObject({ ok: true, readOnly: true });
    expect(r.warnings.join(" ")).toMatch(/expected for read-only users/);
  });
  it("user in admin groups → over-privileged", async () => {
    const r = await conn(fakeNr({ groups: ["Admin", "Read Only"] }).f).testConnection();
    expect(r).toMatchObject({ ok: true, readOnly: false });
    expect(r.checks.find((c) => c.excessive)!.permission).toBe("user group: Admin");
  });
  it("admin / ingest keys are refused before any call", async () => {
    const { f, queries } = fakeNr();
    const admin = await conn(f, "NRAA-" + "0123456789abcdef0123456789a").testConnection();
    expect(admin).toMatchObject({ ok: false, readOnly: false });
    expect(admin.errors[0]).toMatch(/Admin API keys/);
    expect((await conn(f, "0123456789abcdef0123456789abcdef0123NRAL").testConnection()).errors[0]).toMatch(/ingest_license|license/);
    expect(queries).toHaveLength(0);
  });
  it("account not accessible → error; invalid key never echoed", async () => {
    expect((await conn(fakeNr({ noAccount: true }).f).testConnection()).errors[0]).toMatch(/cannot access account/);
    const leaky = (async () => json({ errors: [{ message: `Invalid API key ${KEY}`, extensions: { errorClass: "UNAUTHORIZED" } }] })) as typeof fetch;
    const r = await conn(leaky).testConnection();
    expect(r.ok).toBe(false);
    expect(JSON.stringify(r)).not.toContain(KEY);
  });
});

describe("New Relic NRQL windows, checkpoints and rate limits", () => {
  const start = new Date("2026-11-11T00:00:00Z"), end = new Date("2026-11-11T04:00:00Z");
  it("builds NRQL with base + source predicates, explicit epoch bounds and LIMIT MAX", async () => {
    const { f, queries } = fakeNr({ nrql: () => [nrLog({ ts: start })] });
    const p = await conn(f).listEvents({ sourceType: "newrelic_logs", filter: "logtype = 'nginx'", start, end });
    expect(queries[0]).toBe(`SELECT * FROM Log WHERE (environment = 'prod') AND (logtype = 'nginx') SINCE ${start.getTime()} UNTIL ${end.getTime()} LIMIT MAX`);
    expect(p.raw).toHaveLength(1);
    expect(p.nextPageToken).toBeNull();
  });
  it("splits windows that hit the 5,000-row cap and resumes from the page token without gaps", async () => {
    const { f, queries } = fakeNr({ nrql: (q) => {
      const [, s, e] = /SINCE (\d+) UNTIL (\d+)/.exec(q)!;
      const hours = (Number(e) - Number(s)) / 3600_000;
      return Array.from({ length: hours > 1 ? 5000 : 10 }, () => nrLog({ ts: new Date(Number(s)) }));
    } });
    const c = conn(f);
    const bounds: Array<[number, number]> = [];
    let token: string | null | undefined = null;
    let total = 0;
    do {
      const p = await c.listEvents({ sourceType: "newrelic_logs", filter: null, start, end, pageToken: token });
      const [, s, e] = /SINCE (\d+) UNTIL (\d+)/.exec(queries[queries.length - 1]!)!;
      bounds.push([Number(s), Number(e)]);
      total += p.raw.length;
      token = p.nextPageToken;
    } while (token);
    expect(bounds[0]![0]).toBe(start.getTime());
    expect(bounds.at(-1)![1]).toBe(end.getTime());
    for (let i = 1; i < bounds.length; i++) expect(bounds[i]![0]).toBe(bounds[i - 1]![1]);
    expect(total).toBe(bounds.length * 10);
  });
  it("splits on NRQL timeouts and retries throttling", async () => {
    let calls = 0;
    const { f } = fakeNr({ nrql: (q) => {
      calls++;
      if (calls === 1) return json({ errors: [{ message: "Too many requests", extensions: { errorClass: "TOO_MANY_REQUESTS" } }] });
      const [, s, e] = /SINCE (\d+) UNTIL (\d+)/.exec(q)!;
      if (Number(e) - Number(s) > 3600_000) return json({ errors: [{ message: "NRQL query timed out", extensions: { errorClass: "TIMEOUT" } }] });
      return [nrLog({ ts: start })];
    } });
    const p = await conn(f).listEvents({ sourceType: "newrelic_logs", filter: null, start, end });
    expect(p.raw).toHaveLength(1);
    expect(p.nextPageToken).toBeTruthy();
  });
  it("rejects predicates that change the query shape and forged page tokens", async () => {
    expect(() => validateNrqlWhere("x = 1 SINCE 1 week ago")).toThrow(/WHERE predicate only/);
    expect(() => validateNrqlWhere("x = 1; SELECT * FROM Transaction")).toThrow();
    expect(validateNrqlWhere("message LIKE '%since%' AND `service.name` = 'api'")).toBeTruthy(); // keywords inside quotes are fine
    const c = conn(fakeNr().f);
    await expect(c.listEvents({ sourceType: "newrelic_logs", filter: null, start, end, pageToken: "win1:" + Buffer.from(JSON.stringify({ s: 0, w: 1 })).toString("base64url") })).rejects.toBeInstanceOf(ConnectorError);
  });
  it("discovery reports editable presets with availability from count(*)", async () => {
    const { f } = fakeNr({ nrql: (q) => [{ count: q.includes("cloudtrail") || q.includes("amazonaws") ? 12 : 0 }] });
    const d = await conn(f).discoverSources();
    expect(d.find((s) => s.name === "AWS CloudTrail (forwarded)")).toMatchObject({ available: true, meta: { editableFilter: true } });
    expect(d.find((s) => s.name === "All logs")).toMatchObject({ recommended: false, filter: null });
  });
});

describe("New Relic normalization (golden)", () => {
  const ts = new Date("2026-11-11T10:00:00Z");
  it("maps common attributes from flat NR rows; never invents fields", () => {
    const e = normalizeNewRelic(nrAccess({ ts, ip: "203.0.113.5", path: "/admin/?token=abc", status: 403 }), "newrelic_logs", "1234567");
    expect(e).toMatchObject({ cloudProvider: "newrelic", projectOrAccountReference: "1234567", eventTimestamp: ts.toISOString(), sourceIp: "203.0.113.5", httpStatus: 403, urlPath: "/admin/", sourceName: "nginx", serviceName: "storefront", principal: null, region: null });
    expect(JSON.stringify(e.normalized)).not.toContain("token=abc");
  });
  it("delegates CloudTrail (parsed attributes or raw JSON message) to the AWS normalizer", () => {
    const ct = cloudTrail({ ts, name: "CreateAccessKey", source: "iam.amazonaws.com", arn: "arn:aws:iam::111122223333:user/x", ip: "203.0.113.150", params: { userName: "svc" } });
    const direct = normalizeCloudTrail(ct, { sourceType: "aws_cloudtrail_management" });
    for (const row of [nrCloudTrail(ct), nrCloudTrailUnparsed(ct)]) {
      const e = normalizeNewRelic(row, "newrelic_logs", "1234567");
      expect(e).toMatchObject({ cloudProvider: "aws", providerEventId: direct.providerEventId, normalizedEventType: "iam.credential_create", principal: direct.principal, sourceIp: "203.0.113.150" });
      expect((e.normalized as any).via.platform).toBe("newrelic");
    }
  });
  it("unknown shapes → app.log; missing timestamp throws", () => {
    expect(normalizeNewRelic(nrLog({ ts, message: "worker started" }), "newrelic_logs", "1")).toMatchObject({ normalizedEventType: "app.log", sourceIp: null, action: null });
    expect(() => normalizeNewRelic({ message: "x" }, "newrelic_logs", "1")).toThrow(/timestamp/);
  });
});

describe("New Relic detections + registry", () => {
  for (const s of buildConnectorScenarios().filter((x) => x.connector === "newrelic")) {
    it(`scenario ${s.id} fires ${s.expectedRules.join(", ")}`, () => {
      const evs: DetectableEvent[] = normalizeScenario(s).map((e) => ({ ...e, id: randomUUID() }));
      const fired = new Set(runRules(SEED_RULES, evs).map((h) => h.ruleId));
      for (const r of s.expectedRules) expect(fired, `${r} should fire`).toContain(r);
    });
  }
  it("describes fields; account id accepts a numeric string", () => {
    const d = describeConnector(newRelicConnectorDefinition, { production: true });
    expect(d.fields.map((f) => `${f.name}:${f.kind}`)).toEqual(["region:select", "accountId:number", "nrqlWhere:text", "userApiKey:secret"]);
    expect(cfg.accountId).toBe(1234567);
    expect(newRelicConnectorDefinition.validate!(newRelicConnectorDefinition.configSchema.parse({ accountId: 1, nrqlWhere: "a=1 LIMIT 5" }), { userApiKey: KEY }, { production: false, env: {} })).toMatch(/WHERE predicate/);
  });
});
