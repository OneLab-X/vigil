import { z } from "zod";
import { and, desc, eq, gte, ilike, lte, or, sql, type SQL, inArray } from "drizzle-orm";
import { RuleDefinitionSchema, sigmaToRule, redactDeep, isConnectorId } from "@vigil/core";
import {
  approvalRequests, cloudConnections, detectionRules, detectionRuns, findings, incidents, ingestionJobs, investigationRuns, logSources,
  modelUsage, rawEventReferences, securityEvents,
} from "@vigil/db";
import { IdParam, newApp, Pagination, route, tenantTx } from "../lib/context.js";
import { badRequest, forbidden, notFound } from "../lib/errors.js";
import { blobStore } from "../lib/blobstore.js";
import { pgQueue } from "../lib/queue.js";

export const dataRoutes = newApp();

const EventQuery = Pagination.extend({
  q: z.string().max(200).optional(),
  provider: z.string().max(32).refine(isConnectorId, { message: "unknown provider" }).optional(),
  account: z.string().max(128).optional(),
  severity: z.enum(["info", "low", "medium", "high", "critical"]).optional(),
  sourceType: z.string().max(64).optional(),
  eventType: z.string().max(64).optional(),
  category: z.string().max(64).optional(),
  sourceIp: z.string().max(64).optional(),
  principal: z.string().max(512).optional(),
  resourceId: z.string().max(1024).optional(),
  traceId: z.string().max(128).optional(),
  httpStatus: z.coerce.number().int().optional(),
  start: z.string().datetime({ offset: true }).optional(),
  end: z.string().datetime({ offset: true }).optional(),
});

route(dataRoutes, "get", "/events", { summary: "Search normalized security events", tags: ["events"], query: EventQuery }, async (c, { query: q }) =>
  tenantTx(c, "read", async (tx) => {
    const w: SQL[] = [];
    const end = q.end ? new Date(q.end) : new Date();
    const start = q.start ? new Date(q.start) : new Date(end.getTime() - 24 * 3600_000);
    w.push(gte(securityEvents.eventTimestamp, start), lte(securityEvents.eventTimestamp, end));
    if (q.provider) w.push(eq(securityEvents.cloudProvider, q.provider));
    if (q.account) w.push(eq(securityEvents.projectOrAccountReference, q.account));
    if (q.severity) w.push(eq(securityEvents.severity, q.severity));
    if (q.sourceType) w.push(eq(securityEvents.sourceType, q.sourceType));
    if (q.eventType) w.push(eq(securityEvents.normalizedEventType, q.eventType));
    if (q.category) w.push(sql`${securityEvents.categories} @> array[${q.category}]::text[]`);
    if (q.sourceIp) w.push(eq(securityEvents.sourceIp, q.sourceIp));
    if (q.principal) w.push(eq(securityEvents.principal, q.principal));
    if (q.resourceId) w.push(eq(securityEvents.resourceId, q.resourceId));
    if (q.traceId) w.push(eq(securityEvents.traceId, q.traceId));
    if (q.httpStatus) w.push(eq(securityEvents.httpStatus, q.httpStatus));
    if (q.q) { const like = `%${q.q.replace(/[\\%_]/g, (m) => `\\${m}`)}%`; w.push(or(ilike(securityEvents.action, like), ilike(securityEvents.urlPath, like), ilike(securityEvents.principal, like), ilike(securityEvents.sourceIp, like), sql`${securityEvents.normalizedPayload}->>'message' ilike ${like}`)!); }
    const items = await tx.select({
      id: securityEvents.id, eventTimestamp: securityEvents.eventTimestamp, cloudProvider: securityEvents.cloudProvider, projectOrAccountReference: securityEvents.projectOrAccountReference,
      sourceType: securityEvents.sourceType, normalizedEventType: securityEvents.normalizedEventType, categories: securityEvents.categories, severity: securityEvents.severity,
      sourceIp: securityEvents.sourceIp, principal: securityEvents.principal, action: securityEvents.action, status: securityEvents.status, httpStatus: securityEvents.httpStatus,
      urlPath: securityEvents.urlPath, resourceId: securityEvents.resourceId, traceId: securityEvents.traceId, message: sql<string | null>`left(${securityEvents.normalizedPayload}->>'message', 300)`,
    }).from(securityEvents).where(and(...w)).orderBy(desc(securityEvents.eventTimestamp)).limit(q.limit).offset(q.offset);
    const [{ total }] = await tx.select({ total: sql<number>`count(*)::int` }).from(securityEvents).where(and(...w));
    return c.json({ items, total, start, end });
  }));

route(dataRoutes, "get", "/events/{id}", { summary: "Event details: normalized + original raw payload + related events", tags: ["events"], params: IdParam }, async (c, { params }) =>
  tenantTx(c, "read", async (tx) => {
    const [e] = await tx.select().from(securityEvents).where(eq(securityEvents.id, params.id));
    if (!e) throw notFound("event");
    let raw: unknown = null; let ref = null; let integrity: "verified" | "mismatch" | "unavailable" = "unavailable";
    if (e.originalPayloadReference) {
      [ref] = await tx.select().from(rawEventReferences).where(eq(rawEventReferences.id, e.originalPayloadReference));
      if (ref) try {
        const body = await blobStore.get(ref.storageUri);
        const { createHash } = await import("node:crypto");
        integrity = createHash("sha256").update(body).digest("hex") === ref.sha256 ? "verified" : "mismatch";
        raw = redactDeep(JSON.parse(body)); // raw is shown redacted in UI; hashes prove integrity of the stored original
      } catch { integrity = "unavailable"; }
    }
    const related = e.traceId ? await tx.select({ id: securityEvents.id, eventTimestamp: securityEvents.eventTimestamp, normalizedEventType: securityEvents.normalizedEventType, action: securityEvents.action, httpStatus: securityEvents.httpStatus, sourceName: securityEvents.sourceName, message: sql<string | null>`left(${securityEvents.normalizedPayload}->>'message', 300)` })
      .from(securityEvents).where(and(eq(securityEvents.traceId, e.traceId), sql`${securityEvents.id} <> ${e.id}`)).orderBy(securityEvents.eventTimestamp).limit(100) : [];
    const incs = await tx.execute(sql`select i.id, i.case_number, i.title, i.status from incident_events ie join incidents i on i.id = ie.incident_id where ie.event_id = ${e.id}`);
    return c.json({ event: e, raw, rawReference: ref ? { sha256: ref.sha256, sizeBytes: ref.sizeBytes, storageUri: ref.storageUri.replace(/^file:\/\/.*\/evidence\//, "evidence://") } : null, integrity, relatedByTrace: related, incidents: incs });
  }));

route(dataRoutes, "get", "/findings", { summary: "List detection findings", tags: ["detection"], query: Pagination.extend({ status: z.string().max(32).optional() }) }, async (c, { query }) =>
  tenantTx(c, "read", async (tx) => {
    const rows = await tx.select({ f: findings, ruleId: detectionRules.ruleId, ruleName: detectionRules.name }).from(findings).innerJoin(detectionRules, eq(detectionRules.id, findings.ruleId))
      .where(query.status ? eq(findings.status, query.status) : undefined).orderBy(desc(findings.createdAt)).limit(query.limit).offset(query.offset);
    return c.json({ items: rows.map((r) => ({ ...r.f, rule: { ruleId: r.ruleId, name: r.ruleName } })) });
  }));

// ---------- rules ----------
route(dataRoutes, "get", "/detection-rules", { summary: "List detection rules (all versions)", tags: ["detection"], query: Pagination.extend({ limit: z.coerce.number().int().min(1).max(500).default(200) }) }, async (c, { query }) =>
  tenantTx(c, "read", async (tx) => {
    const rows = await tx.select().from(detectionRules).orderBy(detectionRules.ruleId, desc(detectionRules.version)).limit(query.limit).offset(query.offset);
    const counts = await tx.select({ ruleId: findings.ruleId, n: sql<number>`count(*)::int` }).from(findings).groupBy(findings.ruleId);
    return c.json({ items: rows.map((r) => ({ ...r, findings: counts.find((x) => x.ruleId === r.id)?.n ?? 0 })) });
  }));

// The rule DSL is recursive; it is validated in the handler (OpenAPI generators can't expand recursive schemas).
route(dataRoutes, "post", "/detection-rules", { summary: "Create a rule or a new version of an existing rule (body: RuleDefinition DSL)", tags: ["detection"], body: z.record(z.string(), z.unknown()) }, async (c, { body: raw }) =>
  tenantTx(c, "rules:write", async (tx, a) => {
    const parsed = RuleDefinitionSchema.safeParse(raw);
    if (!parsed.success) throw badRequest("invalid rule definition", z.treeifyError(parsed.error));
    const body = parsed.data;
    const [{ v }] = (await tx.execute(sql`select coalesce(max(version),0)+1 as v from detection_rules where rule_id = ${body.ruleId}`)) as unknown as Array<{ v: number }>;
    const [r] = await tx.insert(detectionRules).values({ tenantId: a.tenantId, ruleId: body.ruleId, name: body.name, description: body.description, provider: body.provider, eventSources: body.eventSources, detectionQuery: body.detectionQuery, conditions: { ...body.conditions, confidence: body.confidence }, severity: body.severity, mitre: body.mitre, enabled: body.enabled, version: v, owner: a.user.email, approvalStatus: "approved" }).returning();
    await a.audit({ action: "rule.version_created", targetType: "detection_rule", targetId: r!.id, details: { ruleId: body.ruleId, version: v } });
    return c.json({ rule: r });
  }));

route(dataRoutes, "post", "/detection-rules/import-sigma", { summary: "Import a Sigma rule (supported subset)", tags: ["detection"], body: z.object({ ruleId: z.string().regex(/^[A-Z0-9][A-Z0-9-]{2,63}$/), sigma: z.record(z.string(), z.unknown()) }) }, async (c, { body }) =>
  tenantTx(c, "rules:write", async (tx, a) => {
    let def;
    try { def = sigmaToRule(body.sigma, body.ruleId); } catch (e) { throw badRequest(`sigma import failed: ${(e as Error).message}`); }
    const [r] = await tx.insert(detectionRules).values({ tenantId: a.tenantId, ruleId: def.ruleId, name: def.name, description: def.description, provider: def.provider, eventSources: def.eventSources, detectionQuery: def.detectionQuery, conditions: { ...def.conditions, confidence: def.confidence }, severity: def.severity, mitre: def.mitre, enabled: true, version: 1, owner: a.user.email }).returning();
    await a.audit({ action: "rule.sigma_imported", targetType: "detection_rule", targetId: r!.id });
    return c.json({ rule: r });
  }));

route(dataRoutes, "post", "/detection-rules/{id}/decision", { summary: "Approve or reject an agent-proposed rule", tags: ["detection"], params: IdParam, body: z.object({ decision: z.enum(["approved", "rejected"]), comment: z.string().max(2000).optional(), enable: z.boolean().default(false) }) }, async (c, { params, body }) =>
  tenantTx(c, "rules:write", async (tx, a) => {
    const [r] = await tx.select().from(detectionRules).where(eq(detectionRules.id, params.id));
    if (!r) throw notFound("rule");
    if (r.approvalStatus !== "pending") throw badRequest("rule is not pending approval");
    await tx.update(detectionRules).set({ approvalStatus: body.decision, enabled: body.decision === "approved" && body.enable, owner: a.user.email, lastUpdated: new Date() }).where(eq(detectionRules.id, r.id));
    await tx.update(approvalRequests).set({ status: body.decision, decidedBy: a.user.id, decidedAt: new Date(), comment: body.comment ?? null }).where(and(eq(approvalRequests.subjectType, "rule"), eq(approvalRequests.subjectId, r.id)));
    await a.audit({ action: `rule.${body.decision}`, targetType: "detection_rule", targetId: r.id, details: { comment: body.comment } });
    return c.json({ ok: true });
  }));

route(dataRoutes, "patch", "/detection-rules/{id}", { summary: "Enable/disable a rule version", tags: ["detection"], params: IdParam, body: z.object({ enabled: z.boolean() }) }, async (c, { params, body }) =>
  tenantTx(c, "rules:write", async (tx, a) => {
    const [r] = await tx.select().from(detectionRules).where(eq(detectionRules.id, params.id));
    if (!r) throw notFound("rule");
    if (r.approvalStatus !== "approved" && body.enabled) throw forbidden("rule must be approved before enabling");
    await tx.update(detectionRules).set({ enabled: body.enabled, lastUpdated: new Date() }).where(eq(detectionRules.id, r.id));
    await a.audit({ action: body.enabled ? "rule.enabled" : "rule.disabled", targetType: "detection_rule", targetId: r.id });
    return c.json({ ok: true });
  }));

route(dataRoutes, "post", "/detection-runs", { summary: "Run detection over a time window now", tags: ["detection"], body: z.object({ start: z.string().datetime({ offset: true }), end: z.string().datetime({ offset: true }) }) }, async (c, { body }) =>
  tenantTx(c, "rules:write", async (tx, a) => {
    await pgQueue.enqueue(tx, a.tenantId, "detect", body);
    await a.audit({ action: "detection.run_requested", details: body });
    return c.json({ queued: true });
  }));

route(dataRoutes, "get", "/detection-runs", { summary: "Recent detection runs", tags: ["detection"], query: Pagination }, async (c, { query }) =>
  tenantTx(c, "read", async (tx) => c.json({ items: await tx.select().from(detectionRuns).orderBy(desc(detectionRuns.startedAt)).limit(query.limit).offset(query.offset) })));

// ---------- overview ----------
route(dataRoutes, "get", "/overview", { summary: "Dashboard metrics", tags: ["overview"] }, async (c) =>
  tenantTx(c, "read", async (tx) => {
    const one = async <T>(q: SQL) => ((await tx.execute(q)) as unknown as T[])[0]!;
    const conns = await tx.select({ provider: cloudConnections.provider, status: cloudConnections.status, last: cloudConnections.lastSuccessfulIngestAt, name: cloudConnections.displayName }).from(cloudConnections);
    const sources = await tx.select({ n: sql<number>`count(*)::int` }).from(logSources).where(eq(logSources.enabled, true));
    const ev = await one<{ total: number; last24h: number }>(sql`select count(*)::int as total, count(*) filter (where event_timestamp > now() - interval '24 hours')::int as last24h from security_events`);
    const fnd = await one<{ new24h: number; open: number }>(sql`select count(*) filter (where created_at > now() - interval '24 hours')::int as new24h, count(*) filter (where status = 'open')::int as open from findings`);
    const inc = await one<{ open: number; high: number }>(sql`select count(*) filter (where status not in ('resolved','closed','false_positive'))::int as open, count(*) filter (where status not in ('resolved','closed','false_positive') and severity in ('high','critical'))::int as high from incidents`);
    const runs = await one<{ ok: number; failed: number; rejected: number; p50: number | null; p95: number | null }>(sql`select count(*) filter (where status='succeeded')::int as ok, count(*) filter (where status in ('failed','timeout'))::int as failed, count(*) filter (where status='rejected')::int as rejected,
      percentile_cont(0.5) within group (order by extract(epoch from finished_at-started_at)) filter (where finished_at is not null) as p50,
      percentile_cont(0.95) within group (order by extract(epoch from finished_at-started_at)) filter (where finished_at is not null) as p95 from investigation_runs`);
    const cost = await one<{ total: number; d30: number }>(sql`select coalesce(sum(cost_usd),0)::float as total, coalesce(sum(cost_usd) filter (where created_at > now() - interval '30 days'),0)::float as d30 from model_usage`);
    const trend = await tx.execute(sql`select date_trunc('hour', created_at) as bucket, severity, count(*)::int as n from findings where created_at > now() - interval '7 days' group by 1,2 order by 1`);
    const evTrend = await tx.execute(sql`select date_trunc('hour', event_timestamp) as bucket, count(*)::int as n from security_events where event_timestamp > now() - interval '48 hours' group by 1 order by 1`);
    const jobs = await tx.select({ status: ingestionJobs.status, n: sql<number>`count(*)::int` }).from(ingestionJobs).where(gte(ingestionJobs.createdAt, new Date(Date.now() - 7 * 86_400_000))).groupBy(ingestionJobs.status);
    const activeRuns = await tx.select({ n: sql<number>`count(*)::int` }).from(investigationRuns).where(inArray(investigationRuns.status, ["queued", "running"]));
    return c.json({
      connections: conns, monitoredSources: sources[0]?.n ?? 0, events: ev, findings: fnd, incidents: inc,
      investigations: { ...runs, active: activeRuns[0]?.n ?? 0 }, cost, findingTrend: trend, eventTrend: evTrend, ingestionJobs: jobs,
    });
  }));
