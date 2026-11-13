import { z } from "zod";
import { and, desc, eq, inArray, sql } from "drizzle-orm";
import { InvestigationContractSchema, Masker, TriageOutputSchema, validateGrounding, type GroundingEvent } from "@vigil/core";
import {
  agentDefinitions, cloudAccounts, approvalRequests, incidentNotes, incidents, investigationEvidence, investigationRuns, investigationToolCalls,
  investigationVerdicts, modelUsage, recommendations, securityEvents, withTenant, type Db, type Tx,
} from "@vigil/db";
import { env } from "../env.js";
import { signToken, verifyToken } from "../lib/crypto.js";
import { loadMasker, sealMaskState } from "../lib/run-masking.js";
import { ApiError } from "../lib/errors.js";
import { audit } from "../lib/audit.js";
import { pgQueue } from "../lib/queue.js";
import { ROLE_TOOLS, type RunToken } from "./broker.js";
import { getMaskingDefault, resolveRunModel, type MaskingMode } from "./models.js";

export const PROMPT_VERSION = "2026-11-12.1";
export type AgentRole = "detection_analyst" | "investigation_analyst";

const DEFAULT_MODEL = { provider: process.env.VIGIL_DEFAULT_MODEL_PROVIDER ?? "gemini", name: process.env.VIGIL_DEFAULT_MODEL ?? "gemini-4-argon" };

export async function ensureAgentDefinitions(tx: Tx, tenantId: string) {
  for (const role of ["detection_analyst", "investigation_analyst"] as const) {
    await tx.insert(agentDefinitions).values({
      tenantId, role, version: 1, promptVersion: PROMPT_VERSION, modelProvider: DEFAULT_MODEL.provider, modelName: DEFAULT_MODEL.name,
      allowedTools: ROLE_TOOLS[role]!, maxSteps: role === "detection_analyst" ? 6 : 14, timeoutSeconds: role === "detection_analyst" ? 90 : 240,
      tokenBudget: role === "detection_analyst" ? 60_000 : 250_000, costBudgetUsd: role === "detection_analyst" ? "0.50" : "3.00",
    }).onConflictDoNothing();
  }
}

const caseId = (n: number) => `CASE-${String(n).padStart(4, "0")}`;

function taskFor(role: AgentRole, cid: string) {
  return role === "detection_analyst"
    ? `Triage ${cid}. Review the deterministic findings and their events, look for related evidence, and decide whether this case deserves a full investigation. Do not issue a verdict.`
    : `Investigate ${cid}. Establish what happened, whether it succeeded/failed/was blocked, the impact, and produce an evidence-backed verdict with supporting and contradictory evidence.`;
}

/** Create a run row, mint a scoped token, and hand the run to the agent worker. */
export async function startAgentRun(db: Db, tenantId: string, incidentId: string, role: AgentRole, triggeredBy: string | null, opts: { masking?: MaskingMode } = {}) {
  const created = await withTenant(db, { tenantId }, async (tx) => {
    await ensureAgentDefinitions(tx, tenantId);
    const [inc] = await tx.select().from(incidents).where(eq(incidents.id, incidentId));
    if (!inc) throw new ApiError(404, "not_found", "incident not found");
    const [active] = await tx.select({ id: investigationRuns.id }).from(investigationRuns).where(and(eq(investigationRuns.incidentId, incidentId), inArray(investigationRuns.status, ["queued", "running"]))).limit(1);
    if (active) throw new ApiError(409, "run_in_progress", "an agent run is already in progress for this incident");
    const [def] = await tx.select().from(agentDefinitions).where(and(eq(agentDefinitions.role, role), eq(agentDefinitions.enabled, true))).orderBy(desc(agentDefinitions.version)).limit(1);
    if (!def) throw new ApiError(409, "agent_disabled", `no enabled ${role} definition`);
    const model = await resolveRunModel(tx, tenantId, def); // enforces the AI data policy before anything runs
    const cid = caseId(inc.caseNumber);
    const masking = opts.masking ?? await getMaskingDefault(tx, tenantId);
    let maskState: string | null = null;
    if (masking === "on") {
      // Seed with the organization's cloud project/account ids so they are masked wherever they appear in free text.
      const m = new Masker();
      const accts = await tx.select({ provider: cloudAccounts.provider, externalId: cloudAccounts.externalId }).from(cloudAccounts);
      m.seed(accts.map((x) => ({ kind: "ACCOUNT" as const, value: x.externalId, hint: x.provider })));
      maskState = sealMaskState(m);
    }
    const [run] = await tx.insert(investigationRuns).values({
      tenantId, incidentId, agentDefinitionId: def.id, role, status: "running", task: taskFor(role, cid), modelProvider: def.modelProvider,
      modelName: def.modelName, promptVersion: def.promptVersion, triggeredBy, startedAt: new Date(), masking, maskState,
    }).returning();
    if (role === "investigation_analyst" && inc.status === "new") await tx.update(incidents).set({ status: "investigating", updatedAt: new Date() }).where(eq(incidents.id, incidentId));
    await pgQueue.enqueue(tx, tenantId, "run_timeout", { runId: run!.id }, { runAfter: new Date(Date.now() + (def.timeoutSeconds + 60) * 1000), idempotencyKey: `timeout:${run!.id}` });
    await audit(tx, { tenantId, actorType: triggeredBy ? "user" : "system", actorId: triggeredBy ?? "orchestrator", action: "agent.run.started", targetType: "investigation_run", targetId: run!.id, details: { role, incident_id: incidentId, model: `${def.modelProvider}/${def.modelName}`, model_hosting: model.hosting, model_provider_id: def.modelProviderId, masking, prompt_version: def.promptVersion } });
    return { run: run!, def, cid, model };
  });
  const { run, def, cid, model } = created;
  const tools = (def.allowedTools as string[]).filter((t) => ROLE_TOOLS[role]!.includes(t));
  const token = signToken({ run_id: run.id, tenant_id: tenantId, role, tools, exp: Math.floor(Date.now() / 1000) + def.timeoutSeconds + 120 } satisfies RunToken);
  try {
    const res = await fetch(`${env.agentsUrl}/v1/runs`, {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${env.internalToken}` },
      body: JSON.stringify({
        run_id: run.id, role, case_id: cid, task: run.task, run_token: token, broker_url: env.brokerUrl, tools,
        // api_key (if any) travels only to the agent worker on the internal network; the model and the tool broker never see it.
        model: { provider: model.provider, name: model.name, endpoint: model.endpoint, api_key: model.api_key, timeout_seconds: model.timeout_seconds,
          price_input_per_mtok: model.price_input_per_mtok, price_output_per_mtok: model.price_output_per_mtok }, prompt_version: def.promptVersion,
        limits: { max_steps: def.maxSteps, timeout_seconds: def.timeoutSeconds, token_budget: def.tokenBudget, cost_budget_usd: Number(def.costBudgetUsd) },
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) throw new Error(`agent worker HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
  } catch (e) {
    await withTenant(db, { tenantId }, async (tx) => {
      await tx.update(investigationRuns).set({ status: "failed", error: `dispatch failed: ${(e as Error).message}`, finishedAt: new Date() }).where(eq(investigationRuns.id, run.id));
      await audit(tx, { tenantId, actorType: "system", actorId: "orchestrator", action: "agent.run.dispatch_failed", targetType: "investigation_run", targetId: run.id, details: { error: (e as Error).message.slice(0, 300) } });
    });
  }
  return { runId: run.id };
}

const UsageSchema = z.object({
  steps: z.number().int().min(0).max(1000), input_tokens: z.number().int().min(0), output_tokens: z.number().int().min(0),
  cost_usd: z.number().min(0), model_provider: z.string().max(64), model_name: z.string().max(128),
});
export const RunResultSchema = z.object({
  status: z.enum(["succeeded", "failed", "timeout"]),
  output: z.unknown().optional(),
  error: z.string().max(4000).optional(),
  usage: UsageSchema,
});

/**
 * Accept an agent's final output. The control plane re-validates everything: schema, grounding
 * against the events this run actually retrieved, and role boundaries. Invalid output is
 * rejected and recorded — never silently accepted.
 */
export async function submitRunResult(db: Db, bearer: string | undefined, runId: string, body: z.infer<typeof RunResultSchema>) {
  const tok = bearer ? verifyToken<RunToken>(bearer) : null;
  if (!tok || tok.run_id !== runId) throw new ApiError(401, "invalid_run_token", "invalid run token");
  const next = await withTenant(db, { tenantId: tok.tenant_id }, async (tx) => {
    const [run] = await tx.select().from(investigationRuns).where(eq(investigationRuns.id, runId));
    if (!run || run.status !== "running") throw new ApiError(409, "run_not_active", "run is not active");
    const [inc] = await tx.select().from(incidents).where(eq(incidents.id, run.incidentId));
    const u = body.usage;
    const base = { steps: u.steps, inputTokens: u.input_tokens, outputTokens: u.output_tokens, costUsd: u.cost_usd.toFixed(4), modelProvider: u.model_provider, modelName: u.model_name, finishedAt: new Date() };
    if (u.input_tokens + u.output_tokens > 0) await tx.insert(modelUsage).values({ tenantId: tok.tenant_id, runId, provider: u.model_provider, model: u.model_name, inputTokens: u.input_tokens, outputTokens: u.output_tokens, costUsd: u.cost_usd.toFixed(6) });
    const finish = async (status: "succeeded" | "failed" | "rejected" | "timeout", extra: Partial<typeof investigationRuns.$inferInsert>) => {
      await tx.update(investigationRuns).set({ ...base, status, ...extra }).where(eq(investigationRuns.id, runId));
      await audit(tx, { tenantId: tok.tenant_id, actorType: "agent", actorId: runId, action: `agent.run.${status}`, targetType: "investigation_run", targetId: runId, details: { role: run.role, steps: u.steps, cost_usd: u.cost_usd, ...(extra.validationErrors ? { validation_errors: extra.validationErrors } : {}) } });
    };
    if (body.status !== "succeeded") { await finish(body.status, { error: body.error ?? "agent failed" }); return null; }

    // Masked run: restore real values before validation/grounding. A token the run never issued is a fabrication.
    let output: unknown = body.output;
    const masker = loadMasker(run);
    if (masker) {
      const u = masker.unmask(body.output);
      if (u.unknownTokens.length) {
        await finish("rejected", { output: body.output as object, validationErrors: u.unknownTokens.slice(0, 20).map((t) => ({ path: "output", problem: `masked value ${t} was never issued in this run` })) });
        return null;
      }
      output = u.value;
    }

    if (run.role === "detection_analyst") {
      const parsed = TriageOutputSchema.safeParse(output);
      if (!parsed.success) { await finish("rejected", { output: output as object, validationErrors: parsed.error.issues.slice(0, 20) }); return null; }
      const seen = await seenEventIds(tx, runId);
      const unknown = parsed.data.related_event_ids.filter((id) => !seen.has(id));
      if (unknown.length) { await finish("rejected", { output: parsed.data, validationErrors: unknown.map((id) => ({ path: "related_event_ids", problem: `event ${id} not retrieved in this run` })) }); return null; }
      await finish("succeeded", { output: parsed.data });
      await tx.insert(incidentNotes).values({ tenantId: tok.tenant_id, incidentId: run.incidentId, authorRunId: runId, body: `Detection Analyst triage (${parsed.data.priority}): ${parsed.data.should_investigate ? "investigation warranted" : "investigation not warranted"} — ${parsed.data.rationale}` });
      return parsed.data.should_investigate ? { tenantId: tok.tenant_id, incidentId: run.incidentId } : null;
    }

    const parsed = InvestigationContractSchema.safeParse(output);
    if (!parsed.success) { await finish("rejected", { output: output as object, validationErrors: parsed.error.issues.slice(0, 20) }); return null; }
    const c = parsed.data;
    const issues: Array<{ path: string; problem: string }> = [];
    if (c.case_id !== caseId(inc!.caseNumber)) issues.push({ path: "case_id", problem: `expected ${caseId(inc!.caseNumber)}` });
    const seenIds = await seenEventIds(tx, runId);
    const seen = new Map<string, GroundingEvent>();
    if (seenIds.size) {
      const rows = await tx.select().from(securityEvents).where(inArray(securityEvents.id, [...seenIds]));
      for (const r of rows) seen.set(r.id, { id: r.id, eventTimestamp: r.eventTimestamp.toISOString(), sourceIp: r.sourceIp, destinationIp: r.destinationIp, principal: r.principal, resourceId: r.resourceId, action: r.action, status: r.status, httpStatus: r.httpStatus, urlPath: r.urlPath });
    }
    issues.push(...validateGrounding(c, seen));
    if (issues.length) { await finish("rejected", { output: c, validationErrors: issues }); return null; }

    await finish("succeeded", { output: c });
    const [v] = await tx.insert(investigationVerdicts).values({ tenantId: tok.tenant_id, runId, incidentId: run.incidentId, verdict: c.verdict, severity: c.severity, confidence: c.confidence, summary: c.summary, contract: c }).returning({ id: investigationVerdicts.id });
    const ev = [...c.evidence.map((e) => ({ ...e, kind: "supporting" })), ...c.contradictory_evidence.map((e) => ({ ...e, kind: "contradictory" }))];
    if (ev.length) await tx.insert(investigationEvidence).values(ev.map((e) => ({ tenantId: tok.tenant_id, runId, incidentId: run.incidentId, eventId: e.event_id, kind: e.kind, claim: e.claim, verified: true })));
    if (c.recommended_actions.length) await tx.insert(recommendations).values(c.recommended_actions.map((r) => ({ tenantId: tok.tenant_id, incidentId: run.incidentId, verdictId: v!.id, action: r.action, rationale: r.rationale, priority: r.priority })));
    await tx.insert(approvalRequests).values({ tenantId: tok.tenant_id, subjectType: "verdict", subjectId: v!.id, requestedByRunId: runId });
    await tx.update(incidents).set({ status: "needs_review", currentVerdictId: v!.id, summary: c.summary, updatedAt: new Date() }).where(eq(incidents.id, run.incidentId));
    return null;
  });
  if (next) await withTenant(db, { tenantId: next.tenantId }, (tx) => pgQueue.enqueue(tx, next.tenantId, "agent_run", { incidentId: next.incidentId, role: "investigation_analyst", trigger: "triage" }, { idempotencyKey: `investigate:${runId}` }));
  return { accepted: true };
}

async function seenEventIds(tx: Tx, runId: string): Promise<Set<string>> {
  const calls = await tx.select({ ids: investigationToolCalls.returnedEventIds }).from(investigationToolCalls).where(and(eq(investigationToolCalls.runId, runId), eq(investigationToolCalls.allowed, true)));
  return new Set(calls.flatMap((c) => c.ids as string[]));
}

/** Fired by a delayed job: mark the run timed out if the agent never reported back. */
export async function handleRunTimeout(db: Db, tenantId: string, runId: string) {
  await withTenant(db, { tenantId }, async (tx) => {
    const updated = await tx.update(investigationRuns).set({ status: "timeout", error: "agent did not report within its time budget", finishedAt: new Date() })
      .where(and(eq(investigationRuns.id, runId), eq(investigationRuns.status, "running"))).returning({ id: investigationRuns.id });
    if (updated.length) await audit(tx, { tenantId, actorType: "system", actorId: "orchestrator", action: "agent.run.timeout", targetType: "investigation_run", targetId: runId });
  });
}
