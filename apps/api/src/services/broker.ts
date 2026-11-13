import { z } from "zod";
import { and, desc, eq, gte, ilike, inArray, isNull, lte, or, sql, gt, type SQL } from "drizzle-orm";
import { RuleDefinitionSchema, redactDeep, isConnectorId, listConnectors } from "@vigil/core";
import {
  approvalRequests, cloudResources, detectionRules, findings, incidentEvents, incidentNotes, incidents, investigationRuns,
  investigationToolCalls, investigationVerdicts, rawEventReferences, securityEvents, securityKnowledge, withTenant, type Db, type Tx,
} from "@vigil/db";
import { verifyToken } from "../lib/crypto.js";
import { ApiError } from "../lib/errors.js";
import { audit } from "../lib/audit.js";
import { blobStore } from "../lib/blobstore.js";
import { loadMasker, sealMaskState } from "../lib/run-masking.js";

export interface RunToken { run_id: string; tenant_id: string; role: string; tools: string[]; exp: number }

const isoTs = z.string().datetime({ offset: true });
const MAX_WINDOW_MS = 30 * 24 * 3600_000;

/** Compact, agent-facing event view. Attacker-controllable fields are marked by the agent worker. */
export function agentEventView(e: typeof securityEvents.$inferSelect) {
  return {
    event_id: e.id, event_timestamp: e.eventTimestamp.toISOString(), provider: e.cloudProvider, account: e.projectOrAccountReference,
    source_type: e.sourceType, event_type: e.normalizedEventType, categories: e.categories, source_ip: e.sourceIp, destination_ip: e.destinationIp,
    principal: e.principal, action: e.action, status: e.status, http_status: e.httpStatus, http_method: e.httpMethod, url_path: e.urlPath,
    user_agent: e.userAgent, trace_id: e.traceId, request_id: e.requestId, resource_type: e.resourceType, resource_id: e.resourceId, service: e.serviceName, region: e.region,
  };
}

function boundedRange(start?: string, end?: string, defaultHours = 24) {
  const e = end ? new Date(end) : new Date();
  const s = start ? new Date(start) : new Date(e.getTime() - defaultHours * 3600_000);
  if (e.getTime() - s.getTime() > MAX_WINDOW_MS) throw new ApiError(400, "window_too_large", "time window may not exceed 30 days");
  if (s > e) throw new ApiError(400, "bad_window", "start after end");
  return { s, e };
}

interface ToolCtx { tx: Tx; tenantId: string; runId: string; incidentId: string }
interface ToolResult { data: unknown; eventIds: string[] }
interface ToolDef { schema: z.ZodType; run: (ctx: ToolCtx, args: any) => Promise<ToolResult> }

const eventFilters = z.object({
  source_ip: z.string().max(64).optional(),
  destination_ip: z.string().max(64).optional(),
  principal: z.string().max(512).optional(),
  trace_id: z.string().max(128).optional(),
  request_id: z.string().max(256).optional(),
  resource_id: z.string().max(1024).optional(),
  event_type: z.string().max(64).optional(),
  category: z.string().max(64).optional(),
  http_status: z.number().int().optional(),
  url_path_contains: z.string().max(256).optional(),
  action_contains: z.string().max(256).optional(),
  provider: z.string().max(32).refine(isConnectorId, { message: "unknown provider" }).optional(),
}).strict();

function whereFromFilters(f: z.infer<typeof eventFilters>): SQL[] {
  const w: SQL[] = [];
  const like = (s: string) => `%${s.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;
  if (f.source_ip) w.push(eq(securityEvents.sourceIp, f.source_ip));
  if (f.destination_ip) w.push(eq(securityEvents.destinationIp, f.destination_ip));
  if (f.principal) w.push(eq(securityEvents.principal, f.principal));
  if (f.trace_id) w.push(eq(securityEvents.traceId, f.trace_id));
  if (f.request_id) w.push(eq(securityEvents.requestId, f.request_id));
  if (f.resource_id) w.push(eq(securityEvents.resourceId, f.resource_id));
  if (f.event_type) w.push(eq(securityEvents.normalizedEventType, f.event_type));
  if (f.category) w.push(sql`${securityEvents.categories} @> array[${f.category}]::text[]`);
  if (f.http_status !== undefined) w.push(eq(securityEvents.httpStatus, f.http_status));
  if (f.url_path_contains) w.push(ilike(securityEvents.urlPath, like(f.url_path_contains)));
  if (f.action_contains) w.push(ilike(securityEvents.action, like(f.action_contains)));
  if (f.provider) w.push(eq(securityEvents.cloudProvider, f.provider));
  return w;
}

export const TOOLS: Record<string, ToolDef> = {
  get_case_context: {
    schema: z.object({}).strict(),
    async run({ tx, incidentId }) {
      const [inc] = await tx.select().from(incidents).where(eq(incidents.id, incidentId));
      if (!inc) throw new ApiError(404, "not_found", "incident not found");
      const fs = await tx.select().from(findings).where(eq(findings.incidentId, incidentId)).limit(50);
      const evs = await tx.select({ e: securityEvents }).from(incidentEvents).innerJoin(securityEvents, eq(securityEvents.id, incidentEvents.eventId))
        .where(eq(incidentEvents.incidentId, incidentId)).orderBy(securityEvents.eventTimestamp).limit(60);
      return {
        data: {
          case_id: `CASE-${String(inc.caseNumber).padStart(4, "0")}`, title: inc.title, status: inc.status, severity: inc.severity,
          primary_entity: inc.primaryEntity, first_seen: inc.firstSeen.toISOString(), last_seen: inc.lastSeen.toISOString(),
          findings: fs.map((f) => ({ finding_id: f.id, title: f.title, severity: f.severity, rule_confidence: f.confidence, event_count: f.eventCount, group_key: f.groupKey, details: f.details, first_seen: f.firstSeen.toISOString(), last_seen: f.lastSeen.toISOString() })),
          events: evs.map((r) => agentEventView(r.e)),
          note: evs.length >= 60 ? "event list truncated to 60; use search_events for more" : undefined,
        },
        eventIds: evs.map((r) => r.e.id),
      };
    },
  },
  search_events: {
    schema: z.object({ filters: eventFilters.default({}), start: isoTs.optional(), end: isoTs.optional(), limit: z.number().int().min(1).max(100).default(50) }).strict(),
    async run({ tx }, a) {
      const { s, e } = boundedRange(a.start, a.end);
      const w = whereFromFilters(a.filters);
      if (!w.length) throw new ApiError(400, "filter_required", "at least one filter is required");
      const rows = await tx.select().from(securityEvents).where(and(gte(securityEvents.eventTimestamp, s), lte(securityEvents.eventTimestamp, e), ...w)).orderBy(securityEvents.eventTimestamp).limit(a.limit);
      const [{ count }] = (await tx.select({ count: sql<number>`count(*)::int` }).from(securityEvents).where(and(gte(securityEvents.eventTimestamp, s), lte(securityEvents.eventTimestamp, e), ...w)));
      return { data: { total_matching: count, returned: rows.length, events: rows.map(agentEventView) }, eventIds: rows.map((r) => r.id) };
    },
  },
  get_event_details: {
    schema: z.object({ event_id: z.string().uuid() }).strict(),
    async run({ tx }, a) {
      const [row] = await tx.select().from(securityEvents).where(eq(securityEvents.id, a.event_id));
      if (!row) return { data: { error: "event not found" }, eventIds: [] };
      let raw: unknown = null;
      let rawSha: string | null = null;
      if (row.originalPayloadReference) {
        const [ref] = await tx.select().from(rawEventReferences).where(eq(rawEventReferences.id, row.originalPayloadReference));
        if (ref) { rawSha = ref.sha256; try { raw = redactDeep(JSON.parse(await blobStore.get(ref.storageUri))); } catch { raw = null; } }
      }
      return { data: { event: agentEventView(row), normalized: row.normalizedPayload, raw_sha256: rawSha, raw_redacted: raw }, eventIds: [row.id] };
    },
  },
  search_cloud_audit_logs: {
    schema: z.object({ principal: z.string().max(512).optional(), action_contains: z.string().max(256).optional(), source_ip: z.string().max(64).optional(), start: isoTs.optional(), end: isoTs.optional(), limit: z.number().int().min(1).max(100).default(50) }).strict(),
    async run({ tx }, a) {
      const { s, e } = boundedRange(a.start, a.end, 72);
      const w = whereFromFilters({ principal: a.principal, action_contains: a.action_contains, source_ip: a.source_ip });
      const rows = await tx.select().from(securityEvents).where(and(gte(securityEvents.eventTimestamp, s), lte(securityEvents.eventTimestamp, e),
        or(...listConnectors().flatMap((d) => d.auditSourcePrefixes).map((p) => ilike(securityEvents.sourceType, `${p}%`))), ...w)).orderBy(desc(securityEvents.eventTimestamp)).limit(a.limit);
      return { data: { returned: rows.length, events: rows.map(agentEventView) }, eventIds: rows.map((r) => r.id) };
    },
  },
  get_resource_details: {
    schema: z.object({ resource_id: z.string().max(1024) }).strict(),
    async run({ tx }, a) {
      const [res] = await tx.select().from(cloudResources).where(eq(cloudResources.resourceId, a.resource_id)).limit(1);
      const stats = await tx.select({ type: securityEvents.normalizedEventType, n: sql<number>`count(*)::int` }).from(securityEvents).where(eq(securityEvents.resourceId, a.resource_id)).groupBy(securityEvents.normalizedEventType);
      return { data: { resource: res ? { type: res.resourceType, id: res.resourceId, labels: res.labels, first_seen: res.firstSeenAt, last_seen: res.lastSeenAt } : null, event_counts_by_type: stats }, eventIds: [] };
    },
  },
  get_identity_activity: {
    schema: z.object({ principal: z.string().max(512).optional(), source_ip: z.string().max(64).optional(), start: isoTs.optional(), end: isoTs.optional() }).strict()
      .refine((a) => !!a.principal !== !!a.source_ip, { message: "provide exactly one of principal or source_ip" }),
    async run({ tx }, a) {
      const { s, e } = boundedRange(a.start, a.end, 24 * 7);
      const key = a.principal ? eq(securityEvents.principal, a.principal) : eq(securityEvents.sourceIp, a.source_ip);
      const base = and(key, gte(securityEvents.eventTimestamp, s), lte(securityEvents.eventTimestamp, e));
      const [agg] = await tx.select({ total: sql<number>`count(*)::int`, first: sql<string>`min(event_timestamp)`, last: sql<string>`max(event_timestamp)`, distinct_paths: sql<number>`count(distinct url_path)::int`, distinct_ips: sql<number>`count(distinct source_ip)::int` }).from(securityEvents).where(base);
      const byStatus = await tx.select({ http_status: securityEvents.httpStatus, status: securityEvents.status, n: sql<number>`count(*)::int` }).from(securityEvents).where(base).groupBy(securityEvents.httpStatus, securityEvents.status).orderBy(sql`count(*) desc`).limit(20);
      const byAction = await tx.select({ action: securityEvents.action, n: sql<number>`count(*)::int` }).from(securityEvents).where(base).groupBy(securityEvents.action).orderBy(sql`count(*) desc`).limit(25);
      const successes = await tx.select().from(securityEvents).where(and(base, or(eq(securityEvents.status, "success"), and(gte(securityEvents.httpStatus, 200), lte(securityEvents.httpStatus, 399))))).orderBy(desc(securityEvents.eventTimestamp)).limit(15);
      return { data: { summary: agg, by_status: byStatus, top_actions: byAction, recent_successful_events: successes.map(agentEventView) }, eventIds: successes.map((r) => r.id) };
    },
  },
  get_related_incidents: {
    schema: z.object({ entity_value: z.string().max(512), limit: z.number().int().min(1).max(20).default(10) }).strict(),
    async run({ tx, incidentId }, a) {
      const rows = await tx.select().from(incidents).where(and(sql`${incidents.correlationKey} like ${"%:" + a.entity_value}`, sql`${incidents.id} <> ${incidentId}`)).orderBy(desc(incidents.createdAt)).limit(a.limit);
      const ids = rows.map((r) => r.id);
      const verdicts = ids.length ? await tx.select().from(investigationVerdicts).where(and(inArray(investigationVerdicts.incidentId, ids), eq(investigationVerdicts.reviewStatus, "approved"))) : [];
      return { data: rows.map((r) => ({ case_id: `CASE-${String(r.caseNumber).padStart(4, "0")}`, title: r.title, status: r.status, severity: r.severity, created_at: r.createdAt, approved_verdict: verdicts.find((v) => v.incidentId === r.id)?.verdict ?? null, approved_summary: verdicts.find((v) => v.incidentId === r.id)?.summary ?? null })), eventIds: [] };
    },
  },
  search_approved_security_knowledge: {
    schema: z.object({ kind: z.enum(["trusted_identity", "trusted_ip", "false_positive", "policy", "lesson", "incident_conclusion"]).optional(), key: z.string().max(512).optional(), text: z.string().max(200).optional(), limit: z.number().int().min(1).max(30).default(15) }).strict(),
    async run({ tx }, a) {
      const w: SQL[] = [eq(securityKnowledge.status, "approved"), or(isNull(securityKnowledge.expiresAt), gt(securityKnowledge.expiresAt, new Date()))!];
      if (a.kind) w.push(eq(securityKnowledge.kind, a.kind));
      if (a.key) w.push(eq(securityKnowledge.key, a.key));
      if (a.text) w.push(or(ilike(securityKnowledge.title, `%${a.text}%`), ilike(securityKnowledge.body, `%${a.text}%`))!);
      const rows = await tx.select().from(securityKnowledge).where(and(...w)).orderBy(desc(securityKnowledge.createdAt)).limit(a.limit);
      return { data: rows.map((k) => ({ knowledge_id: k.id, kind: k.kind, key: k.key, title: k.title, body: k.body, version: k.version, owner: k.owner, expires_at: k.expiresAt })), eventIds: [] };
    },
  },
  create_investigation_note: {
    schema: z.object({ body: z.string().min(1).max(4000) }).strict(),
    async run({ tx, tenantId, incidentId, runId }, a) {
      const [n] = await tx.insert(incidentNotes).values({ tenantId, incidentId, authorRunId: runId, body: a.body }).returning({ id: incidentNotes.id });
      return { data: { note_id: n!.id }, eventIds: [] };
    },
  },
  propose_detection_rule: {
    schema: z.object({ rule: RuleDefinitionSchema, rationale: z.string().min(10).max(2000) }).strict(),
    async run({ tx, tenantId, runId }, a) {
      // Proposed rules are disabled and pending until a human approves them. The agent can't approve.
      const ruleId = a.rule.ruleId.startsWith("PROP-") ? a.rule.ruleId : `PROP-${a.rule.ruleId}`.slice(0, 64);
      const [{ v }] = (await tx.execute(sql`select coalesce(max(version),0)+1 as v from detection_rules where rule_id = ${ruleId}`)) as unknown as Array<{ v: number }>;
      const [r] = await tx.insert(detectionRules).values({
        tenantId, ruleId, name: a.rule.name, description: `${a.rule.description}\n\nAgent rationale: ${a.rationale}`, provider: a.rule.provider, eventSources: a.rule.eventSources,
        detectionQuery: a.rule.detectionQuery, conditions: { ...a.rule.conditions, confidence: a.rule.confidence }, severity: a.rule.severity, mitre: a.rule.mitre,
        enabled: false, version: v, owner: "agent-proposal", approvalStatus: "pending", proposedByRunId: runId,
      }).returning({ id: detectionRules.id });
      await tx.insert(approvalRequests).values({ tenantId, subjectType: "rule", subjectId: r!.id, requestedByRunId: runId });
      return { data: { proposed_rule_id: ruleId, status: "pending_human_approval" }, eventIds: [] };
    },
  },
};

export const ROLE_TOOLS: Record<string, string[]> = {
  detection_analyst: ["get_case_context", "search_events", "get_event_details", "get_identity_activity", "search_approved_security_knowledge", "create_investigation_note"],
  investigation_analyst: Object.keys(TOOLS),
};

const RESULT_CHAR_CAP = 60_000;

/**
 * Single choke point for agent data access. Authorization comes only from the signed run token,
 * never from arguments: the tenant is fixed, the run must be live, the tool must be allowed.
 */
export async function invokeTool(db: Db, bearer: string | undefined, tool: string, args: unknown) {
  const tok = bearer ? verifyToken<RunToken>(bearer) : null;
  if (!tok) throw new ApiError(401, "invalid_run_token", "invalid run token");
  if (tok.exp < Date.now() / 1000) throw new ApiError(401, "run_token_expired", "run token expired");
  return withTenant(db, { tenantId: tok.tenant_id }, async (tx) => {
    const [run] = await tx.select().from(investigationRuns).where(eq(investigationRuns.id, tok.run_id));
    if (!run || run.status !== "running") throw new ApiError(409, "run_not_active", "run is not active");
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${"toolseq:" + run.id}))`);
    const [{ seq }] = (await tx.execute(sql`select coalesce(max(seq),0)+1 as seq from investigation_tool_calls where run_id = ${run.id}`)) as unknown as Array<{ seq: number }>;
    const record = async (allowed: boolean, extra: Partial<typeof investigationToolCalls.$inferInsert>) =>
      tx.insert(investigationToolCalls).values({ tenantId: tok.tenant_id, runId: run.id, seq, tool: tool.slice(0, 64), arguments: (args ?? {}) as object, allowed, ...extra });

    const def = TOOLS[tool];
    const allowedForRole = ROLE_TOOLS[run.role]?.includes(tool) && tok.tools.includes(tool);
    if (!def || !allowedForRole) {
      await record(false, { denialReason: def ? "tool not allowed for this agent" : "unknown tool" });
      await audit(tx, { tenantId: tok.tenant_id, actorType: "agent", actorId: run.id, action: "broker.tool_denied", targetType: "investigation_run", targetId: run.id, details: { tool } });
      return { ok: false, error: def ? "tool not permitted for this agent role" : "unknown tool" };
    }
    // Masked runs: the model only knows tokens like [[IP_3:public]]. Restore real values for the query;
    // a token this run never issued is refused rather than guessed.
    const masker = loadMasker(run);
    let realArgs: unknown = args ?? {};
    if (masker) {
      const u = masker.unmask(realArgs);
      if (u.unknownTokens.length) {
        await record(false, { denialReason: "unknown masked token" });
        return { ok: false, error: `unknown masked value(s): ${u.unknownTokens.slice(0, 5).join(", ")} — use tokens exactly as returned by tools` };
      }
      realArgs = u.value;
    }
    const parsed = def.schema.safeParse(realArgs);
    if (!parsed.success) {
      await record(false, { denialReason: "invalid arguments" });
      return { ok: false, error: "invalid arguments", issues: parsed.error.issues.slice(0, 10).map((i) => ({ path: i.path.join("."), message: i.message })) };
    }
    const t0 = Date.now();
    try {
      // Savepoint: a failing tool must not abort the transaction that records the call.
      const out = await tx.transaction((sp) => def.run({ tx: sp, tenantId: tok.tenant_id, runId: run.id, incidentId: run.incidentId }, parsed.data));
      let data = out.data;
      if (masker) {
        data = masker.mask(data);
        await tx.update(investigationRuns).set({ maskState: sealMaskState(masker), maskStats: masker.stats() }).where(eq(investigationRuns.id, run.id));
      }
      let json = JSON.stringify(data);
      let truncated = false;
      if (json.length > RESULT_CHAR_CAP) { json = json.slice(0, RESULT_CHAR_CAP); truncated = true; }
      await record(true, { returnedEventIds: out.eventIds, durationMs: Date.now() - t0, resultSummary: { chars: json.length, events: out.eventIds.length, truncated, masked: !!masker } });
      return { ok: true, truncated, result_json: json };
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "tool execution failed";
      await record(true, { durationMs: Date.now() - t0, resultSummary: { error: msg } });
      return { ok: false, error: msg };
    }
  });
}
