import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import {
  normalizeGcpEntry, normalizeCloudTrail, deduplicationKey, stableStringify, buildScenarios, runRules, SEED_RULES,
  RuleDefinitionSchema, validateGrounding, InvestigationContractSchema, sigmaToRule, redactString, redactDeep,
  withRetry, ConnectorError, httpError, gaeRequest, type DetectableEvent, type CanonicalEvent,
} from "../src/index.js";

const toDetectable = (c: CanonicalEvent): DetectableEvent => ({ ...c, id: randomUUID() });

function eventsFor(s: ReturnType<typeof buildScenarios>[number]): DetectableEvent[] {
  const gcp = (s.gcp ?? []).map((e) => normalizeGcpEntry(e, { projectId: "example-project", sourceType: "gcp_gae_app" }));
  const aws = (s.aws ?? []).map((r) => normalizeCloudTrail(r));
  return [...gcp, ...aws].map(toDetectable);
}

describe("GCP normalization", () => {
  it("maps App Engine request logs without fabricating fields", () => {
    const e = normalizeGcpEntry(gaeRequest({ ts: new Date("2026-11-11T10:00:00Z"), ip: "203.0.113.5", method: "POST", path: "/v1/auth/login?password=hunter2", status: 401 }), { projectId: "example-project", sourceType: "gcp_gae_app" });
    expect(e.normalizedEventType).toBe("http.request");
    expect(e.sourceIp).toBe("203.0.113.5");
    expect(e.urlPath).toBe("/v1/auth/login");
    expect(e.httpStatus).toBe(401);
    expect(e.principal).toBeNull();
    expect(e.destinationIp).toBeNull();
    expect(e.region).toBe("asia-south1");
    expect(e.categories).toContain("auth.failure");
    expect(e.traceId).toMatch(/^[0-9a-f]{32}$/);
    expect(JSON.stringify(e.normalized)).not.toContain("hunter2");
  });

  it("maps audit logs to IAM / logging categories", () => {
    const [s] = buildScenarios().filter((x) => x.id === "gcp-logging-tamper");
    const evs = s!.gcp!.map((e) => normalizeGcpEntry(e, { projectId: "example-project", sourceType: "gcp_audit_admin_activity" }));
    expect(evs[0]!.normalizedEventType).toBe("logging.config_change");
    expect(evs[0]!.principal).toBe("contractor@example.com");
    expect(evs[1]!.categories).toContain("firewall.change");
  });

  it("dedup key is stable across re-delivery and differs per event", () => {
    const raw = gaeRequest({ ts: new Date(), ip: "192.0.2.1", path: "/", status: 200 });
    const a = normalizeGcpEntry(raw, { projectId: "p", sourceType: "x" });
    const b = normalizeGcpEntry(JSON.parse(JSON.stringify(raw)), { projectId: "p", sourceType: "x" });
    expect(deduplicationKey(a, stableStringify(raw))).toBe(deduplicationKey(b, stableStringify(raw)));
    const other = gaeRequest({ ts: new Date(), ip: "192.0.2.1", path: "/", status: 200 });
    expect(deduplicationKey(normalizeGcpEntry(other, { projectId: "p", sourceType: "x" }), stableStringify(other))).not.toBe(deduplicationKey(a, stableStringify(raw)));
  });
});

describe("AWS normalization", () => {
  it("never puts AWS service names in source_ip", () => {
    const e = normalizeCloudTrail({ eventTime: new Date().toISOString(), eventName: "AssumeRole", eventSource: "sts.amazonaws.com", sourceIPAddress: "ec2.amazonaws.com" });
    expect(e.sourceIp).toBeNull();
    expect((e.normalized as any).aws.source_ip_address_raw).toBe("ec2.amazonaws.com");
  });
  it("classifies StopLogging as logging tamper and denied calls as blocked", () => {
    expect(normalizeCloudTrail({ eventTime: new Date().toISOString(), eventName: "StopLogging", eventSource: "cloudtrail.amazonaws.com" }).normalizedEventType).toBe("logging.config_change");
    expect(normalizeCloudTrail({ eventTime: new Date().toISOString(), eventName: "CreateUser", eventSource: "iam.amazonaws.com", errorCode: "AccessDenied" }).status).toBe("blocked");
  });
});

describe("detection engine", () => {
  it("seed rules validate against schema", () => {
    for (const r of SEED_RULES) expect(() => RuleDefinitionSchema.parse(r)).not.toThrow();
    expect(SEED_RULES.filter((r) => r.provider === "any")).toHaveLength(10);
  });

  for (const s of buildScenarios()) {
    it(`scenario ${s.id} fires ${s.expectedRules.join(", ")}`, () => {
      const hits = runRules(SEED_RULES, eventsFor(s));
      const fired = new Set(hits.map((h) => h.ruleId));
      for (const r of s.expectedRules) expect(fired, `${r} should fire`).toContain(r);
    });
  }

  it("is deterministic and dedup keys are stable across overlapping runs", () => {
    const s = buildScenarios()[0]!;
    const evs = eventsFor(s);
    const a = runRules(SEED_RULES, evs).map((h) => h.dedupKey).sort();
    const b = runRules(SEED_RULES, [...evs].reverse()).map((h) => h.dedupKey).sort();
    expect(a).toEqual(b);
  });

  it("provider-specific rules do not fire on other providers", () => {
    const root = normalizeCloudTrail({ eventTime: new Date().toISOString(), eventName: "ListBuckets", eventSource: "s3.amazonaws.com", recipientAccountId: "111122223333", userIdentity: { type: "Root" } });
    expect(runRules(SEED_RULES, [toDetectable(root)]).map((h) => h.ruleId)).toContain("VGL-AWS-001");
    const gcp = { ...toDetectable(root), cloudProvider: "gcp" as const };
    expect(runRules(SEED_RULES, [gcp]).map((h) => h.ruleId)).not.toContain("VGL-AWS-001");
  });

  it("does not group events with null keys", () => {
    const evs = Array.from({ length: 50 }, () => toDetectable(normalizeGcpEntry(gaeRequest({ ts: new Date(), ip: "", path: "/x", status: 404 }), { projectId: "p", sourceType: "x" })));
    expect(runRules(SEED_RULES, evs).filter((h) => h.ruleId === "VGL-HTTP-002")).toHaveLength(0);
  });

  it("rejects malformed rule queries", () => {
    expect(() => RuleDefinitionSchema.parse({ ...SEED_RULES[0], detectionQuery: { kind: "match", where: { field: "password", op: "eq", value: 1 } } })).toThrow();
    expect(() => RuleDefinitionSchema.parse({ ...SEED_RULES[0], detectionQuery: { kind: "match", where: { field: "urlPath", op: "regex", value: "(" } } })).toThrow();
  });
});

describe("sigma import", () => {
  it("translates a simple CloudTrail sigma rule", () => {
    const r = sigmaToRule({ title: "AWS StopLogging", level: "high", logsource: { product: "aws", service: "cloudtrail" }, tags: ["attack.t1562.008"], detection: { sel: { eventSource: "cloudtrail.amazonaws.com", eventName: ["StopLogging", "DeleteTrail"] }, condition: "sel" } }, "SIGMA-CT-STOP");
    expect(r.provider).toBe("aws");
    const ev = toDetectable(normalizeCloudTrail({ eventTime: new Date().toISOString(), eventName: "DeleteTrail", eventSource: "cloudtrail.amazonaws.com" }));
    expect(runRules([r], [ev])).toHaveLength(1);
  });
  it("refuses unsupported constructs instead of approximating", () => {
    expect(() => sigmaToRule({ detection: { sel: { eventName: "x" }, condition: "1 of sel*" } }, "SIGMA-X")).toThrow(/not supported/);
    expect(() => sigmaToRule({ detection: { sel: { weirdField: "x" }, condition: "sel" } }, "SIGMA-Y")).toThrow(/not mapped/);
  });
});

describe("grounding validator", () => {
  const ev = { id: randomUUID(), eventTimestamp: "2026-11-11T10:00:00.000Z", sourceIp: "203.0.113.45", destinationIp: null, principal: null, resourceId: null, action: "GET /.env", status: "failure", httpStatus: 404, urlPath: "/.env" };
  const seen = new Map([[ev.id, ev]]);
  const base = {
    case_id: "CASE-0001", verdict: "likely", severity: "medium", confidence: 0.8,
    summary: "Scanner at 203.0.113.45 probed sensitive paths; all returned 404.",
    timeline: [{ timestamp: ev.eventTimestamp, description: "probe", event_id: ev.id }],
    entities: { ips: ["203.0.113.45"], principals: [], resources: [] },
    evidence: [{ event_id: ev.id, claim: "Request for /.env from 203.0.113.45 returned 404", cited_fields: { source_ip: "203.0.113.45", http_status: 404 } }],
    contradictory_evidence: [],
    impact_assessment: { outcome: "failed", scope: "none", data_exposure: "none_observed" },
    recommended_actions: [], requires_human_approval: true,
  };
  it("accepts grounded output", () => {
    expect(validateGrounding(InvestigationContractSchema.parse(base), seen)).toEqual([]);
  });
  it("rejects fabricated event ids, IPs, timestamps and field values", () => {
    const bad = InvestigationContractSchema.parse({
      ...base,
      summary: "Attacker 198.51.100.9 exfiltrated data",
      timeline: [{ timestamp: "2026-11-11T11:00:00Z", description: "x", event_id: ev.id }],
      entities: { ips: ["198.51.100.9"], principals: [], resources: [] },
      evidence: [{ event_id: randomUUID(), claim: "made up" }, { event_id: ev.id, claim: "status was ok", cited_fields: { http_status: 200 } }],
    });
    const problems = validateGrounding(bad, seen).map((i) => i.path);
    expect(problems).toEqual(expect.arrayContaining(["summary", "timeline[0].timestamp", "entities.ips[0]", "evidence[0]", "evidence[1].cited_fields.http_status"]));
  });
  it("requires evidence for strong verdicts and allows evidence-free abstention", () => {
    expect(validateGrounding(InvestigationContractSchema.parse({ ...base, evidence: [], verdict: "confirmed" }), seen).length).toBeGreaterThan(0);
    expect(validateGrounding(InvestigationContractSchema.parse({ ...base, evidence: [], timeline: [], verdict: "needs_more_data", confidence: 0.2 }), seen)).toEqual([]);
  });
  it("contract requires human approval flag", () => {
    expect(() => InvestigationContractSchema.parse({ ...base, requires_human_approval: false })).toThrow();
  });
});

describe("redaction", () => {
  it("redacts tokens, keys and card numbers", () => {
    const s = redactString("GET /cb?access_token=abc123&x=1 Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U key AKIAABCDEFGHIJKLMNOP card 4111 1111 1111 1111");
    expect(s).not.toMatch(/abc123|eyJhbGci|AKIAABCDEFGHIJKLMNOP|4111 1111/);
    expect(redactDeep({ headers: { authorization: "x", ok: "y" } })).toEqual({ headers: { authorization: "[REDACTED]", ok: "y" } });
  });
});

describe("retry", () => {
  it("retries 429/5xx with backoff and gives up on 4xx", async () => {
    let n = 0;
    const out = await withRetry(async () => { if (++n < 3) throw httpError(429, "slow down", "0"); return "ok"; }, { sleep: async () => {} });
    expect(out).toBe("ok");
    expect(n).toBe(3);
    let m = 0;
    await expect(withRetry(async () => { m++; throw httpError(403, "no"); }, { sleep: async () => {} })).rejects.toBeInstanceOf(ConnectorError);
    expect(m).toBe(1);
  });
});

describe("sliding windows", () => {
  it("detects a burst that straddles an aligned window boundary", () => {
    // 12 failures spanning 10:08–10:12 — split across [10:00,10:10) and [10:10,10:20) buckets
    const base = Date.parse("2026-11-11T10:08:00Z");
    const evs = Array.from({ length: 12 }, (_, i) => toDetectable(normalizeGcpEntry(gaeRequest({ ts: new Date(base + i * 20_000), ip: "203.0.113.9", method: "POST", path: "/v1/auth/login", status: 401 }), { projectId: "p", sourceType: "gcp_gae_app" })));
    expect(runRules(SEED_RULES, evs).map((h) => h.ruleId)).toContain("VGL-AUTH-001");
  });
});

describe("cross-language contract compatibility", () => {
  it("accepts the JSON shape Pydantic emits (explicit nulls)", () => {
    const py = { case_id: "CASE-0001", verdict: "needs_more_data", severity: "medium", confidence: 0.3, summary: "Insufficient evidence available.", timeline: [{ timestamp: "2026-11-11T10:00:00Z", description: "x", event_id: null }], entities: { ips: [], principals: [], resources: [] }, evidence: [{ event_id: randomUUID(), claim: "abc", cited_fields: null }], contradictory_evidence: [], impact_assessment: { outcome: "unknown", scope: "u", data_exposure: "unknown" }, recommended_actions: [], requires_human_approval: true, abstention_reason: null };
    expect(() => InvestigationContractSchema.parse(py)).not.toThrow();
  });
});
