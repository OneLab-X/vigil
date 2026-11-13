import { z } from "zod";
import { and, asc, desc, eq, inArray, sql } from "drizzle-orm";
import {
  approvalRequests, auditLogs, detectionRules, findings, incidentEvents, incidentNotes, incidents, investigationEvidence, investigationRuns,
  investigationToolCalls, investigationVerdicts, memberships, recommendations, securityEvents, securityKnowledge, users,
} from "@vigil/db";
import { IdParam, newApp, Pagination, route, tenantTx } from "../lib/context.js";
import { badRequest, conflict, forbidden, notFound } from "../lib/errors.js";
import { can } from "../lib/rbac.js";
import { publicRun } from "../lib/run-masking.js";
import { pgQueue } from "../lib/queue.js";
import { getDb } from "../db.js";
import { startAgentRun } from "../services/investigation.js";

export const incidentRoutes = newApp();

type Status = typeof incidents.$inferSelect["status"];
export const TRANSITIONS: Record<Status, Status[]> = {
  new: ["investigating", "needs_review", "false_positive", "closed"],
  investigating: ["needs_review", "new", "false_positive"],
  needs_review: ["confirmed", "false_positive", "investigating"],
  confirmed: ["remediation_pending", "resolved"],
  false_positive: ["closed", "needs_review"],
  remediation_pending: ["resolved"],
  resolved: ["closed", "investigating"],
  closed: ["investigating"],
};

route(incidentRoutes, "get", "/incidents", {
  summary: "List incidents", tags: ["incidents"],
  query: Pagination.extend({ status: z.string().max(32).optional(), severity: z.string().max(16).optional(), open: z.coerce.boolean().optional() }),
}, async (c, { query }) =>
  tenantTx(c, "read", async (tx) => {
    const w = [];
    if (query.status) w.push(eq(incidents.status, query.status as Status));
    if (query.severity) w.push(eq(incidents.severity, query.severity as any));
    if (query.open) w.push(inArray(incidents.status, ["new", "investigating", "needs_review", "confirmed", "remediation_pending"]));
    const rows = await tx.select({ i: incidents, verdict: investigationVerdicts.verdict, confidence: investigationVerdicts.confidence, reviewStatus: investigationVerdicts.reviewStatus, assignee: users.displayName })
      .from(incidents).leftJoin(investigationVerdicts, eq(investigationVerdicts.id, incidents.currentVerdictId)).leftJoin(users, eq(users.id, incidents.assigneeId))
      .where(w.length ? and(...w) : undefined).orderBy(desc(incidents.lastSeen)).limit(query.limit).offset(query.offset);
    const counts = await tx.select({ incidentId: incidentEvents.incidentId, n: sql<number>`count(*)::int` }).from(incidentEvents).groupBy(incidentEvents.incidentId);
    return c.json({ items: rows.map((r) => ({ ...r.i, caseId: `CASE-${String(r.i.caseNumber).padStart(4, "0")}`, verdict: r.verdict, confidence: r.confidence, reviewStatus: r.reviewStatus, assignee: r.assignee, eventCount: counts.find((x) => x.incidentId === r.i.id)?.n ?? 0 })) });
  }));

route(incidentRoutes, "get", "/incidents/{id}", { summary: "Incident workspace: case, evidence, verdicts, runs, notes, audit", tags: ["incidents"], params: IdParam }, async (c, { params }) =>
  tenantTx(c, "read", async (tx) => {
    const [inc] = await tx.select().from(incidents).where(eq(incidents.id, params.id));
    if (!inc) throw notFound("incident");
    const fnd = await tx.select({ f: findings, rule: { ruleId: detectionRules.ruleId, name: detectionRules.name, mitre: detectionRules.mitre, version: detectionRules.version } })
      .from(findings).innerJoin(detectionRules, eq(detectionRules.id, findings.ruleId)).where(eq(findings.incidentId, inc.id)).orderBy(asc(findings.firstSeen));
    const events = await tx.select({ e: securityEvents, findingId: incidentEvents.findingId, addedBy: incidentEvents.addedBy }).from(incidentEvents).innerJoin(securityEvents, eq(securityEvents.id, incidentEvents.eventId))
      .where(eq(incidentEvents.incidentId, inc.id)).orderBy(asc(securityEvents.eventTimestamp)).limit(500);
    const verdicts = await tx.select().from(investigationVerdicts).where(eq(investigationVerdicts.incidentId, inc.id)).orderBy(desc(investigationVerdicts.createdAt));
    const evidence = await tx.select({ ev: investigationEvidence, e: securityEvents }).from(investigationEvidence).leftJoin(securityEvents, eq(securityEvents.id, investigationEvidence.eventId)).where(eq(investigationEvidence.incidentId, inc.id));
    const runs = await tx.select().from(investigationRuns).where(eq(investigationRuns.incidentId, inc.id)).orderBy(desc(investigationRuns.createdAt));
    const runIds = runs.map((r) => r.id);
    const calls = runIds.length ? await tx.select().from(investigationToolCalls).where(inArray(investigationToolCalls.runId, runIds)).orderBy(asc(investigationToolCalls.seq)) : [];
    const recs = await tx.select().from(recommendations).where(eq(recommendations.incidentId, inc.id)).orderBy(asc(recommendations.createdAt));
    const notes = await tx.select({ n: incidentNotes, author: users.displayName }).from(incidentNotes).leftJoin(users, eq(users.id, incidentNotes.authorUserId)).where(eq(incidentNotes.incidentId, inc.id)).orderBy(asc(incidentNotes.createdAt));
    const knowledge = await tx.select().from(securityKnowledge).where(eq(securityKnowledge.sourceIncidentId, inc.id));
    const auditTrail = await tx.select().from(auditLogs).where(inArray(auditLogs.targetId, [inc.id, ...runIds, ...verdicts.map((v) => v.id), ...recs.map((r) => r.id)])).orderBy(asc(auditLogs.id)).limit(500);
    const members = await tx.select({ id: users.id, displayName: users.displayName, role: memberships.role }).from(memberships).innerJoin(users, eq(users.id, memberships.userId));
    return c.json({
      incident: { ...inc, caseId: `CASE-${String(inc.caseNumber).padStart(4, "0")}` }, allowedTransitions: TRANSITIONS[inc.status],
      findings: fnd.map((r) => ({ ...r.f, rule: r.rule })), events: events.map((r) => ({ ...r.e, findingId: r.findingId, addedBy: r.addedBy })),
      verdicts, evidence: evidence.map((r) => ({ ...r.ev, event: r.e })), runs: runs.map(publicRun), toolCalls: calls, recommendations: recs,
      notes: notes.map((r) => ({ ...r.n, author: r.author ?? (r.n.authorRunId ? "AI agent" : "system") })), knowledge, audit: auditTrail, members,
    });
  }));

route(incidentRoutes, "patch", "/incidents/{id}", {
  summary: "Update status, severity or assignee", tags: ["incidents"], params: IdParam,
  body: z.object({ status: z.enum(["new", "investigating", "needs_review", "confirmed", "false_positive", "remediation_pending", "resolved", "closed"]).optional(), severity: z.enum(["info", "low", "medium", "high", "critical"]).optional(), assigneeId: z.string().uuid().nullable().optional(), reason: z.string().max(2000).optional() }),
}, async (c, { params, body }) =>
  tenantTx(c, "incidents:write", async (tx, a) => {
    const [inc] = await tx.select().from(incidents).where(eq(incidents.id, params.id));
    if (!inc) throw notFound("incident");
    if (body.status && body.status !== inc.status && !TRANSITIONS[inc.status].includes(body.status)) throw badRequest(`transition ${inc.status} → ${body.status} not allowed`);
    if (body.assigneeId) {
      const [m] = await tx.select().from(memberships).where(eq(memberships.userId, body.assigneeId));
      if (!m) throw badRequest("assignee is not a member of this tenant");
    }
    await tx.update(incidents).set({ ...(body.status ? { status: body.status } : {}), ...(body.severity ? { severity: body.severity } : {}), ...(body.assigneeId !== undefined ? { assigneeId: body.assigneeId } : {}), updatedAt: new Date() }).where(eq(incidents.id, inc.id));
    await a.audit({ action: "incident.updated", targetType: "incident", targetId: inc.id, details: { from: { status: inc.status, severity: inc.severity, assigneeId: inc.assigneeId }, to: body } });
    return c.json({ ok: true });
  }));

route(incidentRoutes, "post", "/incidents/{id}/notes", { summary: "Add an analyst note", tags: ["incidents"], params: IdParam, body: z.object({ body: z.string().min(1).max(10_000) }) }, async (c, { params, body }) =>
  tenantTx(c, "incidents:write", async (tx, a) => {
    const [n] = await tx.insert(incidentNotes).values({ tenantId: a.tenantId, incidentId: params.id, authorUserId: a.user.id, body: body.body }).returning();
    await a.audit({ action: "incident.note_added", targetType: "incident", targetId: params.id, details: { note_id: n!.id } });
    return c.json({ note: n });
  }));

route(incidentRoutes, "post", "/incidents/{id}/investigate", { summary: "Start an AI investigation run", tags: ["incidents"], params: IdParam, body: z.object({ role: z.enum(["detection_analyst", "investigation_analyst"]).default("investigation_analyst"), masking: z.enum(["on", "off"]).optional() }) }, async (c, { params, body }) => {
  const { user, tenantId } = await tenantTx(c, "investigations:run", async (tx, a) => {
    const [inc] = await tx.select({ id: incidents.id }).from(incidents).where(eq(incidents.id, params.id));
    if (!inc) throw notFound("incident");
    // Turning masking OFF for a run is an admin decision; turning it ON is always allowed.
    if (body.masking === "off" && !can(a.role, "agents:write")) throw forbidden("only admins can run an investigation without masking");
    await a.audit({ action: "investigation.requested", targetType: "incident", targetId: params.id, details: { role: body.role, masking_override: body.masking ?? null } });
    return a;
  });
  const r = await startAgentRun(getDb(), tenantId, params.id, body.role, user.id, { masking: body.masking });
  return c.json(r);
});

route(incidentRoutes, "post", "/incidents/{id}/approve", {
  summary: "Human decision on an AI verdict (approve or reject)", tags: ["incidents"], params: IdParam,
  body: z.object({ verdictId: z.string().uuid(), decision: z.enum(["approved", "rejected"]), comment: z.string().max(4000).optional(), overrideVerdict: z.enum(["confirmed", "likely", "benign", "inconclusive", "needs_more_data"]).optional() }),
}, async (c, { params, body }) =>
  tenantTx(c, "verdicts:review", async (tx, a) => {
    const [v] = await tx.select().from(investigationVerdicts).where(and(eq(investigationVerdicts.id, body.verdictId), eq(investigationVerdicts.incidentId, params.id)));
    if (!v) throw notFound("verdict");
    if (v.reviewStatus !== "pending") throw conflict("verdict already reviewed");
    const [inc] = await tx.select().from(incidents).where(eq(incidents.id, params.id));
    await tx.update(investigationVerdicts).set({ reviewStatus: body.decision, reviewedBy: a.user.id, reviewedAt: new Date(), reviewComment: body.comment ?? null }).where(eq(investigationVerdicts.id, v.id));
    await tx.update(approvalRequests).set({ status: body.decision, decidedBy: a.user.id, decidedAt: new Date(), comment: body.comment ?? null }).where(and(eq(approvalRequests.subjectType, "verdict"), eq(approvalRequests.subjectId, v.id)));
    const effective = body.decision === "approved" ? (body.overrideVerdict ?? v.verdict) : null;
    const nextStatus: Status = !effective ? "investigating" : effective === "benign" ? "false_positive" : effective === "confirmed" || effective === "likely" ? "confirmed" : "needs_review";
    if (inc!.status !== nextStatus) await tx.update(incidents).set({ status: nextStatus, updatedAt: new Date() }).where(eq(incidents.id, params.id));
    // Approved conclusions become organizational knowledge immediately (a human has just reviewed them).
    if (effective) {
      await tx.insert(securityKnowledge).values({ tenantId: a.tenantId, kind: "incident_conclusion", key: inc!.correlationKey.split(":").slice(1).join(":") || inc!.correlationKey, title: `CASE-${String(inc!.caseNumber).padStart(4, "0")}: ${effective}`, body: v.summary, attributes: { verdict: effective, ai_verdict: v.verdict, confidence: v.confidence }, owner: a.user.email, status: "approved", sourceIncidentId: inc!.id, proposedByUserId: a.user.id });
    }
    await a.audit({ action: `verdict.${body.decision}`, targetType: "investigation_verdict", targetId: v.id, details: { incident_id: params.id, ai_verdict: v.verdict, effective_verdict: effective, comment: body.comment, status_change: [inc!.status, nextStatus] } });
    return c.json({ ok: true, incidentStatus: nextStatus });
  }));

route(incidentRoutes, "post", "/incidents/{id}/feedback", {
  summary: "Record analyst feedback as a knowledge proposal (requires approval by another analyst)", tags: ["incidents"], params: IdParam,
  body: z.object({ kind: z.enum(["false_positive", "lesson", "trusted_identity", "trusted_ip", "policy"]), key: z.string().min(1).max(512), title: z.string().min(3).max(300), body: z.string().min(3).max(10_000), ruleIds: z.array(z.string()).max(20).optional(), expiresAt: z.string().datetime({ offset: true }).optional() }),
}, async (c, { params, body }) =>
  tenantTx(c, "knowledge:propose", async (tx, a) => {
    const [k] = await tx.insert(securityKnowledge).values({ tenantId: a.tenantId, kind: body.kind, key: body.key, title: body.title, body: body.body, attributes: body.ruleIds ? { rule_ids: body.ruleIds } : {}, owner: a.user.email, status: "pending", sourceIncidentId: params.id, proposedByUserId: a.user.id, expiresAt: body.expiresAt ? new Date(body.expiresAt) : null }).returning();
    await tx.insert(approvalRequests).values({ tenantId: a.tenantId, subjectType: "knowledge", subjectId: k!.id, requestedByUserId: a.user.id });
    await a.audit({ action: "knowledge.proposed", targetType: "security_knowledge", targetId: k!.id, details: { kind: body.kind, key: body.key, incident_id: params.id } });
    return c.json({ knowledge: k });
  }));

route(incidentRoutes, "patch", "/recommendations/{id}", {
  summary: "Approve/reject a recommendation, attach a ticket, or record the final action", tags: ["incidents"], params: IdParam,
  body: z.object({ status: z.enum(["approved", "rejected", "ticketed", "done"]), ticketRef: z.string().max(200).optional(), finalActionNote: z.string().max(4000).optional() }),
}, async (c, { params, body }) =>
  tenantTx(c, "verdicts:review", async (tx, a) => {
    const [r] = await tx.select().from(recommendations).where(eq(recommendations.id, params.id));
    if (!r) throw notFound("recommendation");
    await tx.update(recommendations).set({ status: body.status, ticketRef: body.ticketRef ?? r.ticketRef, finalActionNote: body.finalActionNote ?? r.finalActionNote }).where(eq(recommendations.id, r.id));
    if (body.status === "approved") {
      const [inc] = await tx.select().from(incidents).where(eq(incidents.id, r.incidentId));
      if (inc?.status === "confirmed") await tx.update(incidents).set({ status: "remediation_pending", updatedAt: new Date() }).where(eq(incidents.id, inc.id));
    }
    await a.audit({ action: `recommendation.${body.status}`, targetType: "recommendation", targetId: r.id, details: body });
    return c.json({ ok: true, note: "Vigil never executes remediation itself; approved actions are carried out by your team / ticketing system." });
  }));

route(incidentRoutes, "post", "/incidents/{id}/triage", { summary: "Queue Detection Analyst triage", tags: ["incidents"], params: IdParam }, async (c, { params }) =>
  tenantTx(c, "investigations:run", async (tx, a) => {
    await pgQueue.enqueue(tx, a.tenantId, "agent_run", { incidentId: params.id, role: "detection_analyst", triggeredBy: a.user.id });
    return c.json({ queued: true });
  }));
