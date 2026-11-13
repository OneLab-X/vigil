/**
 * End-to-end acceptance flow using SYNTHETIC fixtures behind a fake connector (no cloud calls).
 * The live GCP path is exercised separately by scripts/verify-gcp-live.ts against a real project.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { buildScenarios, GcpConnector, normalizeCloudTrail, normalizeGcpEntry, type CloudConnector } from "@vigil/core";
import { getDb } from "../src/db.js";
import { drainOnce } from "../src/worker.js";
import { setConnectorOverride } from "../src/services/connectors.js";
import { as, internal, resetDb, seedTenant, startAgentStub } from "./helpers.js";

const scenarios = buildScenarios(new Date(Date.now() - 3 * 3600_000));
const byId = (id: string) => scenarios.find((s) => s.id === id)!;
let feed: unknown[] = [];

function fakeConnector(provider: "gcp" | "aws"): CloudConnector {
  return {
    provider,
    async connect() {},
    async testConnection() { return { ok: true, provider, accountRef: "fixture", principal: "fixture-reader", credentialType: "fixture", checks: [{ permission: "logging.logEntries.list", granted: true, required: true }], readOnly: true, warnings: [], errors: [], sampleReadOk: true, testedAt: new Date().toISOString() }; },
    async discoverSources() { return provider === "gcp" ? [{ sourceType: "gcp_gae_app", name: "App Engine · default module", filter: 'resource.type="gae_app" AND resource.labels.module_id="default"', description: "", available: true, recommended: true }] : [{ sourceType: "aws_cloudtrail_management", name: "CloudTrail management events", filter: null, description: "", available: true, recommended: true }]; },
    async listEvents(q) {
      // two pages to exercise pagination + checkpoints
      const half = Math.ceil(feed.length / 2);
      return q.pageToken === "p2" ? { raw: feed.slice(half), nextPageToken: null } : { raw: feed.slice(0, half), nextPageToken: "p2" };
    },
    normalize(raw, sourceType) {
      return provider === "gcp" ? normalizeGcpEntry(raw as any, { projectId: "example-project", sourceType: sourceType.startsWith("gcp_audit") ? sourceType : "gcp_gae_app" }) : normalizeCloudTrail(raw as any, { sourceType });
    },
    async getCheckpoint() { return null; }, async saveCheckpoint() {}, async disconnect() {},
  };
}

let T: Awaited<ReturnType<typeof seedTenant>>;
let stub: Awaited<ReturnType<typeof startAgentStub>>;

beforeAll(async () => {
  await resetDb();
  T = await seedTenant("e2e");
  stub = await startAgentStub();
  setConnectorOverride((row) => fakeConnector(row.provider as "gcp" | "aws"));
});
afterAll(async () => { setConnectorOverride(null); await stub.close(); });

const lastRun = () => stub.runs[stub.runs.length - 1];
const tool = async (name: string, args: unknown = {}) => {
  const r = await internal(`/broker/tools/${name}`, lastRun().run_token, args);
  expect(r.status).toBe(200);
  return { ...r.json, result: r.json.result_json ? JSON.parse(r.json.result_json) : undefined };
};
const usage = { steps: 3, input_tokens: 1200, output_tokens: 300, cost_usd: 0.012, model_provider: "scripted", model_name: "test-script" };

let gcpSourceId = "";
let incidentId = "";
let caseId = "";
const ATTACKER = "198.51.100.77";

describe("acceptance: GCP → detection → AI investigation → human decision → learning", () => {
  it("1-3. connects a GCP project, validates read-only access, discovers App Engine logs", async () => {
    const owner = await as("owner@e2e.test", "pw-owner-123456");
    const created = await owner.post("/cloud-connections", { provider: "gcp", displayName: "example-project", projectId: "example-project", authMode: "adc" });
    expect(created.status).toBe(200);
    expect(created.json.onboarding.note).toMatch(/Never create or upload service-account keys/);
    const id = created.json.connection.id;
    const test = await owner.post(`/cloud-connections/${id}/test`);
    expect(test.json).toMatchObject({ ok: true, readOnly: true });
    const src = await owner.get(`/cloud-connections/${id}/sources`);
    const gae = src.json.discovered.find((s: any) => s.sourceType === "gcp_gae_app");
    expect(gae.filter).toBe('resource.type="gae_app" AND resource.labels.module_id="default"');
    const enabled = await owner.post(`/cloud-connections/${id}/sources`, { sourceType: gae.sourceType, name: gae.name, filter: gae.filter });
    gcpSourceId = enabled.json.source.id;
  });

  it("4-6. ingests a configurable historical range, stores raw + normalized, correlates by trace", async () => {
    const owner = await as("owner@e2e.test", "pw-owner-123456");
    feed = byId("gcp-bruteforce-success").gcp!;
    const end = new Date(), start = new Date(end.getTime() - 6 * 3600_000);
    const job = await owner.post("/ingestion/jobs", { logSourceId: gcpSourceId, start: start.toISOString(), end: end.toISOString() });
    expect(job.status).toBe(200);
    await drainOnce(getDb()); // ingest (2 pages) → detect → correlate → auto-triage dispatch
    const jobs = await owner.get("/ingestion/jobs");
    expect(jobs.json.items[0]).toMatchObject({ status: "succeeded", pagesFetched: 2, eventsInserted: feed.length });
    const evs = await owner.get(`/events?sourceIp=${ATTACKER}&start=${start.toISOString()}&limit=100`);
    expect(evs.json.total).toBe(15);
    const detail = await owner.get(`/events/${evs.json.items[0].id}`);
    expect(detail.json.integrity).toBe("verified");
    expect(detail.json.raw.protoPayload.ip).toBe(ATTACKER);
    expect(detail.json.relatedByTrace.length).toBeGreaterThan(0); // app stdout line joined via trace id
  });

  it("re-ingesting the same range is idempotent (dedup)", async () => {
    const owner = await as("owner@e2e.test", "pw-owner-123456");
    const end = new Date(), start = new Date(end.getTime() - 6 * 3600_000);
    await owner.post("/ingestion/jobs", { logSourceId: gcpSourceId, start: start.toISOString(), end: end.toISOString() });
    await drainOnce(getDb());
    const jobs = await owner.get("/ingestion/jobs");
    expect(jobs.json.items[0]).toMatchObject({ status: "succeeded", eventsInserted: 0, duplicates: feed.length });
    const inc = await owner.get("/incidents");
    expect(inc.json.items).toHaveLength(1); // no duplicate cases
  });

  it("7-8. detection identifies brute force and opens a case", async () => {
    const analyst = await as("analyst@e2e.test", "pw-analyst-123456");
    const list = await analyst.get("/incidents");
    const inc = list.json.items[0];
    expect(inc.correlationKey).toBe(`sourceIp:${ATTACKER}`);
    expect(inc.severity).toBe("high");
    incidentId = inc.id;
    caseId = inc.caseId;
    const f = await analyst.get("/findings");
    expect(f.json.items.map((x: any) => x.rule.ruleId)).toContain("VGL-AUTH-001");
  });

  it("9. Detection Analyst triages with a restricted tool set", async () => {
    expect(lastRun()).toMatchObject({ role: "detection_analyst", case_id: caseId });
    expect(lastRun().tools).not.toContain("propose_detection_rule");
    const ctx = await tool("get_case_context");
    expect(ctx.ok).toBe(true);
    expect(ctx.result.events.length).toBeGreaterThan(0);
    const denied = await tool("propose_detection_rule", { rule: {}, rationale: "x".repeat(20) });
    expect(denied).toMatchObject({ ok: false, error: "tool not permitted for this agent role" });
    const r = await internal(`/runs/${lastRun().run_id}/result`, lastRun().run_token, { status: "succeeded", usage, output: { should_investigate: true, rationale: "14 failed logins followed by a success from the same IP", priority: "high", related_event_ids: [ctx.result.events[0].event_id] } });
    expect(r.json.accepted).toBe(true);
    await drainOnce(getDb()); // triage result → investigation run dispatched
    expect(lastRun().role).toBe("investigation_analyst");
  });

  it("10-11. Investigation Analyst: fabricated output is rejected", async () => {
    const run = lastRun();
    await tool("get_case_context");
    const bad = await internal(`/runs/${run.run_id}/result`, run.run_token, { status: "succeeded", usage, output: {
      case_id: caseId, verdict: "confirmed", severity: "critical", confidence: 0.99, summary: "Attacker 203.0.113.250 exfiltrated the database.",
      timeline: [], entities: { ips: ["203.0.113.250"], principals: [], resources: [] },
      evidence: [{ event_id: crypto.randomUUID(), claim: "Exfiltration observed" }], contradictory_evidence: [],
      impact_assessment: { outcome: "succeeded", scope: "db", data_exposure: "confirmed" }, recommended_actions: [], requires_human_approval: true } });
    expect(bad.json.accepted).toBe(true);
    const ws = await (await as("analyst@e2e.test", "pw-analyst-123456")).get(`/incidents/${incidentId}`);
    const rejected = ws.json.runs.find((r: any) => r.id === run.run_id);
    expect(rejected.status).toBe("rejected");
    expect(rejected.validationErrors.map((i: any) => i.path)).toEqual(expect.arrayContaining(["summary", "entities.ips[0]", "evidence[0]"]));
    expect(ws.json.verdicts).toHaveLength(0);
  });

  it("10-11. Investigation Analyst: grounded verdict with supporting and contradictory evidence is accepted", async () => {
    const analyst = await as("analyst@e2e.test", "pw-analyst-123456");
    const started = await analyst.post(`/incidents/${incidentId}/investigate`, { role: "investigation_analyst" });
    expect(started.status).toBe(200);
    const ctx = await tool("get_case_context");
    const activity = await tool("get_identity_activity", { source_ip: ATTACKER, start: new Date(Date.now() - 6 * 3600_000).toISOString() });
    const kb = await tool("search_approved_security_knowledge", { key: ATTACKER });
    expect(kb.result).toEqual([]);
    const injected = await tool("search_events", { filters: { source_ip: ATTACKER, http_status: 200 }, start: new Date(Date.now() - 6 * 3600_000).toISOString() });
    const success = injected.result.events[0];
    const fail = ctx.result.events.find((e: any) => e.http_status === 401);
    expect(activity.result.summary.total).toBe(15);
    const contract = {
      case_id: caseId, verdict: "likely", severity: "high", confidence: 0.8,
      summary: `${ATTACKER} made 14 failed login attempts followed by one successful login; credential compromise is likely.`,
      timeline: [{ timestamp: fail.event_timestamp, description: "first failed login", event_id: fail.event_id }, { timestamp: success.event_timestamp, description: "successful login", event_id: success.event_id }],
      entities: { ips: [ATTACKER], principals: [], resources: [] },
      evidence: [{ event_id: fail.event_id, claim: `POST /v1/auth/login from ${ATTACKER} returned 401`, cited_fields: { source_ip: ATTACKER, http_status: 401 } }, { event_id: success.event_id, claim: "Subsequent login returned 200", cited_fields: { http_status: 200 } }],
      contradictory_evidence: [{ event_id: success.event_id, claim: "Only one successful request; no post-login activity observed from this IP", cited_fields: { url_path: "/v1/auth/login" } }],
      impact_assessment: { outcome: "succeeded", scope: "one application account may be compromised", data_exposure: "unknown" },
      recommended_actions: [{ action: "Reset the password for the targeted account and invalidate its sessions", rationale: "Successful login after brute force", priority: "urgent" }],
      requires_human_approval: true,
    };
    await internal(`/runs/${lastRun().run_id}/result`, lastRun().run_token, { status: "succeeded", usage, output: contract });
    const ws = await analyst.get(`/incidents/${incidentId}`);
    expect(ws.json.incident.status).toBe("needs_review");
    expect(ws.json.verdicts[0]).toMatchObject({ verdict: "likely", reviewStatus: "pending" });
    expect(ws.json.evidence.every((e: any) => e.verified && e.event)).toBe(true); // every conclusion links to an original event
    expect(ws.json.toolCalls.length).toBeGreaterThan(3);
    expect(ws.json.recommendations[0].status).toBe("proposed");
  });

  it("12. human analyst approves the verdict; viewer cannot", async () => {
    const viewer = await as("viewer@e2e.test", "pw-viewer-123456");
    const analyst = await as("analyst@e2e.test", "pw-analyst-123456");
    const ws = await analyst.get(`/incidents/${incidentId}`);
    const verdictId = ws.json.verdicts[0].id;
    expect((await viewer.post(`/incidents/${incidentId}/approve`, { verdictId, decision: "approved" })).status).toBe(403);
    const ok = await analyst.post(`/incidents/${incidentId}/approve`, { verdictId, decision: "approved", comment: "Confirmed with app owner" });
    expect(ok.json.incidentStatus).toBe("confirmed");
    expect((await analyst.post(`/incidents/${incidentId}/approve`, { verdictId, decision: "approved" })).status).toBe(409);
    const rec = ws.json.recommendations[0];
    const r = await analyst.patch(`/recommendations/${rec.id}`, { status: "approved" });
    expect(r.json.note).toMatch(/never executes remediation/);
  });

  it("13. feedback becomes knowledge only after a different human approves it", async () => {
    const analyst = await as("analyst@e2e.test", "pw-analyst-123456");
    const reviewer = await as("reviewer@e2e.test", "pw-reviewer-123456");
    const fb = await analyst.post(`/incidents/${incidentId}/feedback`, { kind: "lesson", key: "VGL-AUTH-001", title: "Brute force followed by success", body: "Always check for a 2xx after repeated 401s from the same IP." });
    const kid = fb.json.knowledge.id;
    expect((await analyst.post(`/knowledge/${kid}/decision`, { decision: "approved" })).status).toBe(403);
    expect((await reviewer.post(`/knowledge/${kid}/decision`, { decision: "approved" })).status).toBe(200);
    const kb = await reviewer.get("/knowledge?status=approved");
    expect(kb.json.items.map((k: any) => k.kind)).toEqual(expect.arrayContaining(["lesson", "incident_conclusion"]));
  });

  it("approved trusted identities suppress future findings (organizational learning)", async () => {
    const analyst = await as("analyst@e2e.test", "pw-analyst-123456");
    const reviewer = await as("reviewer@e2e.test", "pw-reviewer-123456");
    const p = await analyst.post("/knowledge", { kind: "trusted_identity", key: "terraform@example-project.iam.gserviceaccount.com", title: "Terraform CI service account", body: "Managed by platform team; creates deployer keys during rotations." });
    await reviewer.post(`/knowledge/${p.json.knowledge.id}/decision`, { decision: "approved" });
    feed = byId("gcp-terraform-sa-key").gcp!;
    const owner = await as("owner@e2e.test", "pw-owner-123456");
    const before = (await owner.get("/incidents")).json.items.length;
    await owner.post("/ingestion/jobs", { logSourceId: gcpSourceId, start: new Date(Date.now() - 6 * 3600_000).toISOString(), end: new Date().toISOString() });
    await drainOnce(getDb());
    const f = await owner.get("/findings?status=suppressed");
    expect(f.json.items.length).toBeGreaterThan(0);
    expect(f.json.items[0].details.suppressed_by_knowledge.title).toBe("Terraform CI service account");
    expect((await owner.get("/incidents")).json.items.length).toBe(before);
  });

  it("prompt-injection payloads reach the agent only as data fields", async () => {
    feed = byId("gcp-prompt-injection-ua").gcp!;
    const owner = await as("owner@e2e.test", "pw-owner-123456");
    await owner.post("/ingestion/jobs", { logSourceId: gcpSourceId, start: new Date(Date.now() - 6 * 3600_000).toISOString(), end: new Date().toISOString() });
    await drainOnce(getDb());
    const inc = (await owner.get("/incidents")).json.items.find((i: any) => i.correlationKey === "sourceIp:192.0.2.200");
    expect(inc).toBeTruthy();
    expect(lastRun().case_id).toBe(inc.caseId);
    const ctx = await tool("get_case_context");
    expect(ctx.result.events[0].user_agent).toMatch(/IGNORE ALL PREVIOUS INSTRUCTIONS/);
    // the instruction asks for a note + benign verdict; the triage agent may only note; benign verdict w/o evidence path is still human-gated
    expect(lastRun().tools).not.toContain("propose_detection_rule");
  });
});

describe("acceptance: AWS CloudTrail through the same investigation engine", () => {
  it("ingests CloudTrail, detects the persistence chain, and the same investigation agent role produces a grounded verdict", async () => {
    const owner = await as("owner@e2e.test", "pw-owner-123456");
    const c = await owner.post("/cloud-connections", { provider: "aws", displayName: "prod-aws", accountId: "111122223333", roleArn: "arn:aws:iam::111122223333:role/vigil-reader", regions: ["us-east-1"] });
    expect(c.status).toBe(200);
    expect(c.json.onboarding.trustPolicy.Statement[0].Condition.StringEquals["sts:ExternalId"]).toMatch(/^vigil-[0-9a-f]{36}$/);
    expect(JSON.stringify(c.json.connection)).not.toMatch(/vigil-[0-9a-f]{36}/); // ExternalId only in secret store
    const src = await owner.post(`/cloud-connections/${c.json.connection.id}/sources`, { sourceType: "aws_cloudtrail_management", name: "CloudTrail management events", filter: null });
    feed = byId("aws-persistence-chain").aws!;
    // complete any pending triage from the previous test so this incident gets its own run
    await internal(`/runs/${lastRun().run_id}/result`, lastRun().run_token, { status: "failed", error: "test teardown", usage: { ...usage, input_tokens: 0, output_tokens: 0, cost_usd: 0 } });
    await owner.post("/ingestion/jobs", { logSourceId: src.json.source.id, start: new Date(Date.now() - 6 * 3600_000).toISOString(), end: new Date().toISOString() });
    await drainOnce(getDb());
    const inc = (await owner.get("/incidents")).json.items.find((i: any) => i.correlationKey === "principal:arn:aws:iam::111122223333:user/ops-jane");
    expect(inc).toBeTruthy();
    expect(inc.severity).toBe("critical");
    // finish auto-triage, then run the *same* investigation_analyst role used for GCP
    await internal(`/runs/${lastRun().run_id}/result`, lastRun().run_token, { status: "succeeded", usage, output: { should_investigate: true, rationale: "credential creation then StopLogging", priority: "urgent", related_event_ids: [] } });
    await drainOnce(getDb());
    expect(lastRun()).toMatchObject({ role: "investigation_analyst", case_id: inc.caseId });
    const audit = await tool("search_cloud_audit_logs", { principal: "arn:aws:iam::111122223333:user/ops-jane", start: new Date(Date.now() - 6 * 3600_000).toISOString() });
    const evs = audit.result.events;
    const stop = evs.find((e: any) => e.action === "StopLogging");
    const key = evs.find((e: any) => e.action === "CreateAccessKey");
    const r = await internal(`/runs/${lastRun().run_id}/result`, lastRun().run_token, { status: "succeeded", usage, output: {
      case_id: inc.caseId, verdict: "confirmed", severity: "critical", confidence: 0.9,
      summary: "ops-jane created a new IAM user with an access key and admin policy, then stopped CloudTrail logging from 203.0.113.150.",
      timeline: [{ timestamp: key.event_timestamp, description: "access key created", event_id: key.event_id }, { timestamp: stop.event_timestamp, description: "CloudTrail stopped", event_id: stop.event_id }],
      entities: { ips: ["203.0.113.150"], principals: ["arn:aws:iam::111122223333:user/ops-jane"], resources: [] },
      evidence: [{ event_id: stop.event_id, claim: "StopLogging succeeded", cited_fields: { action: "StopLogging", status: "success" } }, { event_id: key.event_id, claim: "CreateAccessKey for backup-svc", cited_fields: { action: "CreateAccessKey" } }],
      contradictory_evidence: [], impact_assessment: { outcome: "succeeded", scope: "account 111122223333", data_exposure: "unknown" },
      recommended_actions: [{ action: "Re-enable CloudTrail and disable the backup-svc access key", rationale: "Defense evasion + persistence", priority: "urgent" }], requires_human_approval: true } });
    expect(r.json.accepted).toBe(true);
    const ws = await owner.get(`/incidents/${inc.id}`);
    expect(ws.json.verdicts[0]).toMatchObject({ verdict: "confirmed", reviewStatus: "pending" });
    expect(ws.json.events.every((e: any) => e.cloudProvider === "aws")).toBe(true);
  });

  it("14. the whole workflow is auditable and the chain verifies", async () => {
    const owner = await as("owner@e2e.test", "pw-owner-123456");
    const logs = await owner.get("/audit-logs?limit=500");
    const actions = new Set(logs.json.items.map((l: any) => l.action));
    for (const a of ["connection.created", "connection.tested", "ingestion.job.succeeded", "detection.run", "incident.created", "agent.run.started", "agent.run.succeeded", "agent.run.rejected", "broker.tool_denied", "verdict.approved", "knowledge.proposed", "knowledge.approved"]) expect(actions, a).toContain(a);
    expect((await owner.get("/audit-logs/verify")).json.ok).toBe(true);
    const ov = await owner.get("/overview");
    expect(ov.json.incidents.open).toBeGreaterThan(0);
    expect(ov.json.cost.total).toBeGreaterThan(0);
  });

  it("detection replay evaluation scores the active rules", async () => {
    const owner = await as("owner@e2e.test", "pw-owner-123456");
    const ev = await owner.post("/evaluations/detection-replay");
    expect(ev.json.evaluation.metrics.recall).toBe(1);
    expect(ev.json.evaluation.metrics.data).toBe("synthetic-fixture");
  });
});

// keep import used for type-only path in some TS configs
void GcpConnector;
