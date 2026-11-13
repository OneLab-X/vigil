import { and, eq, gte, inArray, lt, or, sql, isNull, gt } from "drizzle-orm";
import { enqueueIncidentAlert } from "./notifications.js";
import { RuleDefinitionSchema, runRules, maxSeverity, type DetectableEvent, type RuleDefinition, type RuleHit, type Severity } from "@vigil/core";
import { detectionRules, detectionRuns, findings, incidentEvents, incidents, securityEvents, securityKnowledge, withTenant, type Db, type Tx } from "@vigil/db";
import { audit } from "../lib/audit.js";
import { pgQueue } from "../lib/queue.js";

const MAX_EVENTS_PER_RUN = 100_000;

export function rowToRule(r: typeof detectionRules.$inferSelect): RuleDefinition & { dbId: string } {
  const def = RuleDefinitionSchema.parse({
    ruleId: r.ruleId, name: r.name, description: r.description, provider: r.provider, eventSources: r.eventSources,
    detectionQuery: r.detectionQuery, conditions: r.conditions, severity: r.severity, mitre: r.mitre, enabled: r.enabled,
    confidence: (r.conditions as any)?.confidence ?? 0.7,
  });
  return { ...def, dbId: r.id };
}

/** Latest approved, enabled, non-expired version of each rule. */
export async function activeRules(tx: Tx) {
  const rows = await tx.execute(sql`select distinct on (rule_id) * from detection_rules
    where approval_status = 'approved' and (expires_at is null or expires_at > now()) order by rule_id, version desc`);
  return (rows as unknown as any[]).filter((r) => r.enabled).map((r) => rowToRule({
    id: r.id, tenantId: r.tenant_id, ruleId: r.rule_id, name: r.name, description: r.description, provider: r.provider, eventSources: r.event_sources,
    detectionQuery: r.detection_query, conditions: r.conditions, severity: r.severity, mitre: r.mitre, enabled: r.enabled, version: r.version,
    owner: r.owner, approvalStatus: r.approval_status, proposedByRunId: r.proposed_by_run_id, expiresAt: r.expires_at, lastUpdated: r.last_updated,
  }));
}

function primaryEntity(groupKey: Record<string, unknown>): { field: string; value: string } | null {
  for (const f of ["sourceIp", "principal", "resourceId", "destinationIp", "serviceName", "projectOrAccountReference"]) {
    const v = groupKey[f];
    if (typeof v === "string" && v) return { field: f, value: v };
  }
  return null;
}

/** Approved knowledge that says this entity/rule is expected (trusted identity/IP or known FP). */
async function suppressionFor(tx: Tx, hit: RuleHit): Promise<{ id: string; title: string } | null> {
  const keys = Object.values(hit.groupKey).filter((v): v is string => typeof v === "string");
  if (!keys.length) return null;
  const rows = await tx.select({ id: securityKnowledge.id, title: securityKnowledge.title, kind: securityKnowledge.kind, attributes: securityKnowledge.attributes }).from(securityKnowledge).where(and(
    eq(securityKnowledge.status, "approved"),
    inArray(securityKnowledge.kind, ["trusted_identity", "trusted_ip", "false_positive"]),
    inArray(securityKnowledge.key, keys),
    or(isNull(securityKnowledge.expiresAt), gt(securityKnowledge.expiresAt, new Date())),
  ));
  // false_positive entries may be scoped to specific rules via attributes.rule_ids
  const match = rows.find((r) => r.kind !== "false_positive" || !(r.attributes as any)?.rule_ids || ((r.attributes as any).rule_ids as string[]).includes(hit.ruleId));
  return match ? { id: match.id, title: match.title } : null;
}

export async function runDetection(db: Db, tenantId: string, window: { start: Date; end: Date }) {
  return withTenant(db, { tenantId }, async (tx) => {
    const [run] = await tx.insert(detectionRuns).values({ tenantId, windowStart: window.start, windowEnd: window.end }).returning();
    const rules = await activeRules(tx);
    const evRows = await tx.select().from(securityEvents)
      .where(and(gte(securityEvents.eventTimestamp, window.start), lt(securityEvents.eventTimestamp, window.end)))
      .orderBy(securityEvents.eventTimestamp).limit(MAX_EVENTS_PER_RUN);
    const events: DetectableEvent[] = evRows.map((e) => ({
      id: e.id, cloudProvider: e.cloudProvider, projectOrAccountReference: e.projectOrAccountReference, region: e.region, sourceType: e.sourceType,
      sourceName: e.sourceName, eventTimestamp: e.eventTimestamp.toISOString(), resourceType: e.resourceType, resourceId: e.resourceId,
      serviceName: e.serviceName, severity: e.severity, principal: e.principal, sourceIp: e.sourceIp, destinationIp: e.destinationIp, action: e.action,
      status: e.status, httpStatus: e.httpStatus, httpMethod: e.httpMethod, urlPath: e.urlPath, userAgent: e.userAgent, traceId: e.traceId,
      requestId: e.requestId, normalizedEventType: e.normalizedEventType, categories: e.categories, normalized: e.normalizedPayload as Record<string, unknown>,
    }));
    const hits = runRules(rules, events);
    const ruleDbId = new Map(rules.map((r) => [r.ruleId, r.dbId]));
    let created = 0;
    const newFindingIds: string[] = [];
    for (const h of hits) {
      const suppressed = await suppressionFor(tx, h);
      const [f] = await tx.insert(findings).values({
        tenantId, ruleId: ruleDbId.get(h.ruleId)!, detectionRunId: run!.id, title: h.title, severity: h.severity, confidence: h.confidence,
        groupKey: h.groupKey, eventIds: h.eventIds, eventCount: h.eventCount, firstSeen: new Date(h.firstSeen), lastSeen: new Date(h.lastSeen),
        dedupKey: h.dedupKey, details: { ...h.details, ...(suppressed ? { suppressed_by_knowledge: suppressed } : {}) }, status: suppressed ? "suppressed" : "open",
      }).onConflictDoUpdate({
        target: [findings.tenantId, findings.dedupKey],
        // Late-arriving events grow an existing finding instead of creating a duplicate.
        set: { eventCount: sql`greatest(${findings.eventCount}, excluded.event_count)`, lastSeen: sql`greatest(${findings.lastSeen}, excluded.last_seen)`, eventIds: sql`excluded.event_ids` },
      }).returning({ id: findings.id, createdAt: findings.createdAt, incidentId: findings.incidentId, status: findings.status });
      if (f && f.createdAt.getTime() >= run!.startedAt.getTime()) created++;
      if (f && !f.incidentId && f.status === "open") newFindingIds.push(f.id);
    }
    const incidentIds = await correlate(tx, tenantId, newFindingIds);
    await tx.update(detectionRuns).set({ status: "succeeded", rulesEvaluated: rules.length, findingsCreated: created, finishedAt: new Date() }).where(eq(detectionRuns.id, run!.id));
    await audit(tx, { tenantId, actorType: "system", actorId: "detection-engine", action: "detection.run", targetType: "detection_run", targetId: run!.id, details: { events: events.length, rules: rules.length, hits: hits.length, created, incidents: incidentIds.length } });
    return { runId: run!.id, events: events.length, rules: rules.length, hits: hits.length, findingsCreated: created, incidentIds };
  });
}

/**
 * Entity-based correlation: findings sharing a primary entity (IP, principal, resource) within
 * 24h attach to the same open incident; otherwise a new incident (case) is opened.
 */
export async function correlate(tx: Tx, tenantId: string, findingIds: string[]): Promise<string[]> {
  if (!findingIds.length) return [];
  const rows = await tx.select().from(findings).where(inArray(findings.id, findingIds));
  const touched = new Set<string>();
  for (const f of rows) {
    const ent = primaryEntity(f.groupKey as Record<string, unknown>);
    const corr = ent ? `${ent.field}:${ent.value}` : `rule:${f.ruleId}`;
    const [open] = await tx.select().from(incidents).where(and(
      eq(incidents.correlationKey, corr),
      inArray(incidents.status, ["new", "investigating", "needs_review", "confirmed", "remediation_pending"]),
      gte(incidents.lastSeen, new Date(f.firstSeen.getTime() - 24 * 3600_000)),
    )).limit(1);
    let incidentId: string;
    let isNew = false;
    let raisedTo: Severity | null = null;
    if (open) {
      incidentId = open.id;
      const sev = maxSeverity(open.severity as Severity, f.severity as Severity);
      if (sev !== open.severity) raisedTo = sev;
      await tx.update(incidents).set({
        severity: sev,
        lastSeen: f.lastSeen > open.lastSeen ? f.lastSeen : open.lastSeen,
        firstSeen: f.firstSeen < open.firstSeen ? f.firstSeen : open.firstSeen, updatedAt: new Date(),
      }).where(eq(incidents.id, open.id));
    } else {
      const [{ n }] = (await tx.execute(sql`select vigil_next_case_number(${tenantId}::uuid) as n`)) as unknown as Array<{ n: number }>;
      const [inc] = await tx.insert(incidents).values({
        tenantId, caseNumber: n, title: f.title, severity: f.severity, primaryEntity: ent ?? {}, correlationKey: corr,
        firstSeen: f.firstSeen, lastSeen: f.lastSeen, summary: null,
      }).returning({ id: incidents.id });
      incidentId = inc!.id;
      isNew = true;
    }
    await tx.update(findings).set({ incidentId }).where(eq(findings.id, f.id));
    const evIds = (f.eventIds as string[]).slice(0, 200);
    if (evIds.length) await tx.insert(incidentEvents).values(evIds.map((eventId) => ({ tenantId, incidentId, eventId, findingId: f.id }))).onConflictDoNothing();
    await audit(tx, { tenantId, actorType: "system", actorId: "correlator", action: isNew ? "incident.created" : "incident.finding_attached", targetType: "incident", targetId: incidentId, details: { finding_id: f.id, correlation_key: corr } });
    if (isNew) await pgQueue.enqueue(tx, tenantId, "agent_run", { incidentId, role: "detection_analyst", trigger: "auto" }, { idempotencyKey: `triage:${incidentId}` });
    if (isNew) await enqueueIncidentAlert(tx, tenantId, incidentId, "incident.created", f.severity as Severity);
    else if (raisedTo) await enqueueIncidentAlert(tx, tenantId, incidentId, "incident.severity_raised", raisedTo);
    touched.add(incidentId);
  }
  return [...touched];
}
