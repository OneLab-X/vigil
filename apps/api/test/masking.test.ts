/** Sensitive-data masking for AI runs, end to end through the real broker and result handling (SYNTHETIC fixtures). */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { eq, sql } from "drizzle-orm";
import { buildScenarios, normalizeGcpEntry } from "@vigil/core";
import { cloudAccounts, cloudConnections, incidentEvents, incidents, investigationRuns, investigationVerdicts, securityEvents, withTenant } from "@vigil/db";
import { getDb } from "../src/db.js";
import { storeRawPage } from "../src/services/ingestion.js";
import { as, internal, resetDb, seedTenant, startAgentStub } from "./helpers.js";

let T: Awaited<ReturnType<typeof seedTenant>>;
let stub: Awaited<ReturnType<typeof startAgentStub>>;
let incidentId = "";
let caseId = "";
let evs: Array<typeof securityEvents.$inferSelect> = [];
const PROJECT = "acme-prod-42";
const usage = { steps: 3, input_tokens: 100, output_tokens: 50, cost_usd: 0.001, model_provider: "scripted", model_name: "test-script" };
const owner = () => as("owner@mask.test", "pw-owner-123456");
const lastRun = () => stub.runs[stub.runs.length - 1];
const tool = async (name: string, args: unknown = {}) => {
  const r = await internal(`/broker/tools/${name}`, lastRun().run_token, args);
  return { ...r.json, raw: r.json.result_json as string | undefined, result: r.json.result_json ? JSON.parse(r.json.result_json) : undefined };
};

beforeAll(async () => {
  await resetDb();
  T = await seedTenant("mask");
  stub = await startAgentStub();
  const db = getDb();
  const s = buildScenarios(new Date(Date.now() - 2 * 3600_000)).find((x) => x.id === "gcp-bruteforce-success")!;
  await withTenant(db, { tenantId: T.tenantId }, async (tx) => {
    const [conn] = await tx.insert(cloudConnections).values({ tenantId: T.tenantId, provider: "gcp", displayName: "prod", config: { projectId: PROJECT, authMode: "adc" } }).returning();
    await tx.insert(cloudAccounts).values({ tenantId: T.tenantId, connectionId: conn!.id, provider: "gcp", externalId: PROJECT });
    await storeRawPage(tx, { tenantId: T.tenantId, cloudAccountId: null, logSourceId: null, sourceType: "gcp_gae_app" }, s.gcp!, (r) => normalizeGcpEntry(r as any, { projectId: PROJECT, sourceType: "gcp_gae_app" }));
    evs = await tx.select().from(securityEvents).where(sql`${securityEvents.sourceIp} is not null`).limit(40);
    const ip = evs[0]!.sourceIp!;
    const [{ n }] = (await tx.execute(sql`select vigil_next_case_number(${T.tenantId}::uuid) as n`)) as unknown as Array<{ n: number }>;
    const [inc] = await tx.insert(incidents).values({ tenantId: T.tenantId, caseNumber: n, title: `Brute force from ${ip} against ${PROJECT}`, severity: "high",
      primaryEntity: { field: "sourceIp", value: ip }, correlationKey: `sourceIp:${ip}`, firstSeen: new Date(), lastSeen: new Date() }).returning();
    incidentId = inc!.id;
    caseId = `CASE-${String(n).padStart(4, "0")}`;
    await tx.insert(incidentEvents).values(evs.map((e) => ({ tenantId: T.tenantId, incidentId, eventId: e.id })));
  });
});
afterAll(async () => { await stub.close(); });

const realValues = () => [...new Set(evs.flatMap((e) => [e.sourceIp, e.destinationIp, e.principal, e.projectOrAccountReference]).filter((v): v is string => !!v && v.length > 3)), PROJECT];

describe("AI masking", () => {
  it("is on by default and the org can see the setting", async () => {
    const o = await owner();
    expect((await o.get("/model-providers")).json.masking).toBe("on");
  });

  it("tool results reach the model with no real IPs, identities or project ids — only consistent tokens", async () => {
    const o = await owner();
    const r = await o.post(`/incidents/${incidentId}/investigate`, { role: "investigation_analyst" });
    expect(r.status).toBe(200);
    const ctx = await tool("get_case_context");
    expect(ctx.ok).toBe(true);
    for (const v of realValues()) expect(ctx.raw, `leaked ${v}`).not.toContain(v);
    expect(ctx.result.title).toMatch(/^Brute force from \[\[IP_\d+:[a-z_]+\]\] against \[\[ACCOUNT_1:gcp\]\]$/);
    expect(ctx.result.primary_entity.value).toMatch(/^\[\[IP_\d+/);
    const detail = await tool("get_event_details", { event_id: evs[0]!.id });
    for (const v of realValues()) expect(detail.raw, `raw leaked ${v}`).not.toContain(v);
    expect(detail.result.event.event_id).toBe(evs[0]!.id); // ids are not masked (needed for grounding)
    // consistent: the same IP has the same token in both calls
    expect(detail.result.event.source_ip).toBe(ctx.result.events.find((e: any) => e.event_id === evs[0]!.id).source_ip);
  });

  it("the model can pivot with tokens; invented tokens are refused", async () => {
    const ctx = await tool("get_case_context");
    const ipTok = ctx.result.primary_entity.value;
    const s = await tool("search_events", { filters: { source_ip: ipTok }, start: new Date(Date.now() - 6 * 3600_000).toISOString() });
    expect(s.ok).toBe(true);
    expect(s.result.total_matching).toBe(evs.filter((e) => e.sourceIp === evs[0]!.sourceIp).length);
    expect(s.result.events[0].source_ip).toBe(ipTok);
    const bad = await tool("search_events", { filters: { source_ip: "[[IP_99:public]]" } });
    expect(bad.ok).toBe(false);
    expect(bad.error).toMatch(/unknown masked value/);
  });

  it("agent notes are stored with real values", async () => {
    const ctx = await tool("get_case_context");
    await tool("create_investigation_note", { body: `Pivoted on ${ctx.result.primary_entity.value}` });
    const o = await owner();
    const ws = await o.get(`/incidents/${incidentId}`);
    expect(ws.json.notes.map((n: any) => n.body)).toContain(`Pivoted on ${evs[0]!.sourceIp}`);
  });

  it("result tokens are restored before grounding; stored verdict has real values; token map never leaves the API", async () => {
    const ctx = await tool("get_case_context");
    const ip = ctx.result.primary_entity.value;
    const e0 = ctx.result.events[0];
    const contract = {
      case_id: caseId, verdict: "likely", severity: "high", confidence: 0.7,
      summary: `Repeated failed logins from ${ip} followed by a success.`,
      timeline: [{ timestamp: e0.event_timestamp, description: `request from ${e0.source_ip}`, event_id: e0.event_id }],
      entities: { ips: [ip], principals: [], resources: [] },
      evidence: [{ event_id: e0.event_id, claim: `source ${ip}`, cited_fields: { source_ip: e0.source_ip } }],
      contradictory_evidence: [], impact_assessment: { outcome: "succeeded", scope: "single account", data_exposure: "unknown" },
      recommended_actions: [{ action: `Block ${ip} at the edge`, rationale: "brute force source", priority: "high" }],
      requires_human_approval: true,
    };
    const res = await internal(`/runs/${lastRun().run_id}/result`, lastRun().run_token, { status: "succeeded", output: contract, usage });
    expect(res.status).toBe(200);
    const db = getDb();
    const [run] = await withTenant(db, { tenantId: T.tenantId }, (tx) => tx.select().from(investigationRuns).where(eq(investigationRuns.id, lastRun().run_id)));
    expect(run!.status, JSON.stringify(run!.validationErrors)).toBe("succeeded");
    expect(run!.masking).toBe("on");
    expect(run!.maskState).toMatch(/^v1\./); // AES-GCM ciphertext
    expect(run!.maskState).not.toContain(evs[0]!.sourceIp!);
    expect((run!.maskStats as any).IP).toBeGreaterThan(0);
    const [v] = await withTenant(db, { tenantId: T.tenantId }, (tx) => tx.select().from(investigationVerdicts).where(eq(investigationVerdicts.runId, run!.id)));
    expect(v!.summary).toBe(`Repeated failed logins from ${evs[0]!.sourceIp} followed by a success.`);
    const ws = await (await owner()).get(`/incidents/${incidentId}`);
    expect(JSON.stringify(ws.json)).not.toContain("maskState");
    expect(ws.json.runs[0].maskStats.IP).toBeGreaterThan(0);
  });

  it("a result citing a token that was never issued is rejected as fabrication", async () => {
    const o = await owner();
    await o.post(`/incidents/${incidentId}/investigate`, { role: "detection_analyst" });
    const ctx = await tool("get_case_context");
    const out = { should_investigate: true, priority: "high", rationale: "activity from [[IP_77:public]]", related_event_ids: [ctx.result.events[0].event_id], enrichment: {} };
    await internal(`/runs/${lastRun().run_id}/result`, lastRun().run_token, { status: "succeeded", output: out, usage });
    const [run] = await withTenant(getDb(), { tenantId: T.tenantId }, (tx) => tx.select().from(investigationRuns).where(eq(investigationRuns.id, lastRun().run_id)));
    expect(run!.status).toBe("rejected");
    expect(JSON.stringify(run!.validationErrors)).toContain("[[IP_77:public]]");
  });

  it("only admins can run without masking; the org default can be turned off", async () => {
    const an = await as("analyst@mask.test", "pw-analyst-123456");
    const denied = await an.post(`/incidents/${incidentId}/investigate`, { role: "detection_analyst", masking: "off" });
    expect(denied.status).toBe(403);
    const o = await owner();
    expect((await o.post(`/incidents/${incidentId}/investigate`, { role: "detection_analyst", masking: "off" })).status).toBe(200);
    const ctx = await tool("get_case_context");
    expect(ctx.raw).toContain(evs[0]!.sourceIp!); // unmasked run sees real values
    await internal(`/runs/${lastRun().run_id}/result`, lastRun().run_token, { status: "failed", error: "test", usage });
    expect((await o.req("PUT", "/settings/ai", { masking: "off" })).json.masking).toBe("off");
    expect((await an.req("PUT", "/settings/ai", { masking: "on" })).status).toBe(403);
    await o.req("PUT", "/settings/ai", { masking: "on" });
  });
});
