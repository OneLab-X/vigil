import { z } from "zod";
import { and, asc, desc, eq, sql } from "drizzle-orm";
import { randomUUID } from "node:crypto";
import { buildScenarios, normalizeCloudTrail, normalizeGcpEntry, runRules, SEED_RULES } from "@vigil/core";
import {
  agentDefinitions, agentEvaluations, approvalRequests, auditLogs, investigationRuns, investigationToolCalls, knowledgeApprovals, memberships,
  modelProviders, modelUsage, securityKnowledge, users,
} from "@vigil/db";
import { IdParam, newApp, Pagination, route, tenantTx } from "../lib/context.js";
import { badRequest, forbidden, notFound } from "../lib/errors.js";
import { verifyChain } from "../lib/audit.js";
import { publicRun } from "../lib/run-masking.js";
import { ROLE_TOOLS } from "../services/broker.js";
import { activeRules, rowToRule } from "../services/detection.js";
import { ensureAgentDefinitions } from "../services/investigation.js";
import { changeMemberRole, inviteMember, removeMember } from "../services/tenancy.js";

export const governanceRoutes = newApp();

route(governanceRoutes, "get", "/agents", { summary: "Agent definitions, permissions, usage and failure stats", tags: ["agents"] }, async (c) =>
  tenantTx(c, "read", async (tx, a) => {
    await ensureAgentDefinitions(tx, a.tenantId);
    const defs = await tx.select().from(agentDefinitions).orderBy(agentDefinitions.role, desc(agentDefinitions.version));
    const stats = await tx.execute(sql`select role, status, count(*)::int as n, coalesce(sum(cost_usd),0)::float as cost, coalesce(avg(cost_usd),0)::float as avg_cost,
      coalesce(sum(input_tokens+output_tokens),0)::int as tokens, avg(extract(epoch from finished_at-started_at))::float as avg_seconds from investigation_runs group by role, status`);
    const usage = await tx.select({ provider: modelUsage.provider, model: modelUsage.model, input: sql<number>`sum(input_tokens)::int`, output: sql<number>`sum(output_tokens)::int`, cost: sql<number>`sum(cost_usd)::float` }).from(modelUsage).groupBy(modelUsage.provider, modelUsage.model);
    const providers = { anthropic: !!process.env.ANTHROPIC_API_KEY, openai: !!process.env.OPENAI_API_KEY, gemini: !!(process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY) };
    return c.json({ definitions: defs.map((d) => ({ ...d, toolCatalog: ROLE_TOOLS[d.role] })), stats, usage, providerKeysVisibleToApi: providers });
  }));

route(governanceRoutes, "post", "/agents/{id}/versions", {
  summary: "Create a new agent definition version (model, budgets, tool subset)", tags: ["agents"], params: IdParam,
  body: z.object({ modelProvider: z.enum(["anthropic", "openai", "gemini", "openai_compatible", "scripted"]), modelProviderId: z.string().uuid().nullish(), modelName: z.string().min(1).max(128), allowedTools: z.array(z.string()).min(1), maxSteps: z.number().int().min(1).max(40), timeoutSeconds: z.number().int().min(10).max(1800), tokenBudget: z.number().int().min(1000).max(2_000_000), costBudgetUsd: z.number().min(0.01).max(50), enabled: z.boolean().default(true) }),
}, async (c, { params, body }) =>
  tenantTx(c, "agents:write", async (tx, a) => {
    const [cur] = await tx.select().from(agentDefinitions).where(eq(agentDefinitions.id, params.id));
    if (!cur) throw notFound("agent definition");
    const allowed = ROLE_TOOLS[cur.role] ?? [];
    const bad = body.allowedTools.filter((t) => !allowed.includes(t));
    if (bad.length) throw badRequest(`tools not permitted for role ${cur.role}: ${bad.join(", ")}`);
    if (body.modelProvider === "scripted" && process.env.NODE_ENV === "production") throw badRequest("scripted provider is test-only");
    let modelProvider = body.modelProvider;
    if (body.modelProviderId) {
      const [p] = await tx.select().from(modelProviders).where(eq(modelProviders.id, body.modelProviderId));
      if (!p || !p.enabled) throw badRequest("model provider not found or disabled");
      modelProvider = p.kind as typeof modelProvider;
    } else if (body.modelProvider === "openai_compatible") throw badRequest("openai_compatible needs a configured model provider (Settings → AI models)");
    const [{ v }] = (await tx.execute(sql`select coalesce(max(version),0)+1 as v from agent_definitions where role = ${cur.role}`)) as unknown as Array<{ v: number }>;
    await tx.update(agentDefinitions).set({ enabled: false }).where(eq(agentDefinitions.role, cur.role));
    const [d] = await tx.insert(agentDefinitions).values({ tenantId: a.tenantId, role: cur.role, version: v, promptVersion: cur.promptVersion, modelProvider, modelProviderId: body.modelProviderId ?? null, modelName: body.modelName, allowedTools: body.allowedTools, maxSteps: body.maxSteps, timeoutSeconds: body.timeoutSeconds, tokenBudget: body.tokenBudget, costBudgetUsd: body.costBudgetUsd.toFixed(4), enabled: body.enabled }).returning();
    await a.audit({ action: "agent.definition_versioned", targetType: "agent_definition", targetId: d!.id, details: { role: cur.role, version: v, ...body } });
    return c.json({ definition: d });
  }));

route(governanceRoutes, "get", "/agents/runs", { summary: "Agent run history", tags: ["agents"], query: Pagination.extend({ status: z.string().max(16).optional() }) }, async (c, { query }) =>
  tenantTx(c, "read", async (tx) => {
    const rows = await tx.select().from(investigationRuns).where(query.status ? eq(investigationRuns.status, query.status as any) : undefined).orderBy(desc(investigationRuns.createdAt)).limit(query.limit).offset(query.offset);
    return c.json({ items: rows.map(publicRun) });
  }));

route(governanceRoutes, "get", "/agents/runs/{id}", { summary: "Run detail with full tool-call trace", tags: ["agents"], params: IdParam }, async (c, { params }) =>
  tenantTx(c, "read", async (tx) => {
    const [run] = await tx.select().from(investigationRuns).where(eq(investigationRuns.id, params.id));
    if (!run) throw notFound("run");
    const calls = await tx.select().from(investigationToolCalls).where(eq(investigationToolCalls.runId, run.id)).orderBy(asc(investigationToolCalls.seq));
    return c.json({ run: publicRun(run), toolCalls: calls });
  }));

// ---------- knowledge ----------
route(governanceRoutes, "get", "/knowledge", { summary: "Security knowledge base", tags: ["knowledge"], query: Pagination.extend({ status: z.enum(["pending", "approved", "rejected", "expired"]).optional(), kind: z.string().max(32).optional() }) }, async (c, { query }) =>
  tenantTx(c, "read", async (tx) => {
    const w = [];
    if (query.status) w.push(eq(securityKnowledge.status, query.status));
    if (query.kind) w.push(eq(securityKnowledge.kind, query.kind));
    const rows = await tx.select({ k: securityKnowledge, proposer: users.displayName }).from(securityKnowledge).leftJoin(users, eq(users.id, securityKnowledge.proposedByUserId)).where(w.length ? and(...w) : undefined).orderBy(desc(securityKnowledge.createdAt)).limit(query.limit).offset(query.offset);
    return c.json({ items: rows.map((r) => ({ ...r.k, embedding: undefined, proposer: r.proposer ?? (r.k.proposedByRunId ? "AI agent" : null) })) });
  }));

route(governanceRoutes, "post", "/knowledge", {
  summary: "Propose a knowledge entry", tags: ["knowledge"],
  body: z.object({ kind: z.enum(["trusted_identity", "trusted_ip", "false_positive", "policy", "lesson"]), key: z.string().min(1).max(512), title: z.string().min(3).max(300), body: z.string().min(3).max(10_000), expiresAt: z.string().datetime({ offset: true }).optional() }),
}, async (c, { body }) =>
  tenantTx(c, "knowledge:propose", async (tx, a) => {
    const [k] = await tx.insert(securityKnowledge).values({ tenantId: a.tenantId, ...body, expiresAt: body.expiresAt ? new Date(body.expiresAt) : null, owner: a.user.email, status: "pending", proposedByUserId: a.user.id }).returning();
    await tx.insert(approvalRequests).values({ tenantId: a.tenantId, subjectType: "knowledge", subjectId: k!.id, requestedByUserId: a.user.id });
    await a.audit({ action: "knowledge.proposed", targetType: "security_knowledge", targetId: k!.id, details: { kind: body.kind, key: body.key } });
    return c.json({ knowledge: { ...k, embedding: undefined } });
  }));

route(governanceRoutes, "post", "/knowledge/{id}/decision", {
  summary: "Approve or reject a knowledge proposal (four-eyes: approver ≠ proposer)", tags: ["knowledge"], params: IdParam,
  body: z.object({ decision: z.enum(["approved", "rejected"]), comment: z.string().max(2000).optional() }),
}, async (c, { params, body }) =>
  tenantTx(c, "knowledge:approve", async (tx, a) => {
    const [k] = await tx.select().from(securityKnowledge).where(eq(securityKnowledge.id, params.id));
    if (!k) throw notFound("knowledge");
    if (k.status !== "pending") throw badRequest("not pending");
    if (k.proposedByUserId === a.user.id) throw forbidden("you cannot approve your own proposal");
    await tx.update(securityKnowledge).set({ status: body.decision }).where(eq(securityKnowledge.id, k.id));
    await tx.insert(knowledgeApprovals).values({ tenantId: a.tenantId, knowledgeId: k.id, decision: body.decision, decidedBy: a.user.id, comment: body.comment ?? null });
    await tx.update(approvalRequests).set({ status: body.decision, decidedBy: a.user.id, decidedAt: new Date(), comment: body.comment ?? null }).where(and(eq(approvalRequests.subjectType, "knowledge"), eq(approvalRequests.subjectId, k.id)));
    await a.audit({ action: `knowledge.${body.decision}`, targetType: "security_knowledge", targetId: k.id, details: { comment: body.comment } });
    return c.json({ ok: true });
  }));

route(governanceRoutes, "get", "/approvals", { summary: "Pending approval requests", tags: ["knowledge"], query: Pagination }, async (c, { query }) =>
  tenantTx(c, "read", async (tx) => c.json({ items: await tx.select().from(approvalRequests).where(eq(approvalRequests.status, "pending")).orderBy(desc(approvalRequests.createdAt)).limit(query.limit).offset(query.offset) })));

// ---------- evaluation ----------
route(governanceRoutes, "get", "/evaluations", { summary: "Evaluation results", tags: ["evaluation"], query: Pagination }, async (c, { query }) =>
  tenantTx(c, "read", async (tx) => c.json({ items: await tx.select().from(agentEvaluations).orderBy(desc(agentEvaluations.createdAt)).limit(query.limit).offset(query.offset) })));

route(governanceRoutes, "post", "/evaluations/detection-replay", { summary: "Replay synthetic scenarios through the tenant's active rules and score precision/recall", tags: ["evaluation"] }, async (c) =>
  tenantTx(c, "rules:write", async (tx, a) => {
    const rules = await activeRules(tx);
    const effective = rules.length ? rules : SEED_RULES;
    const cases = buildScenarios().map((s) => {
      const evs = [...(s.gcp ?? []).map((e) => normalizeGcpEntry(e, { projectId: "example-project", sourceType: "gcp_gae_app" })), ...(s.aws ?? []).map((r) => normalizeCloudTrail(r))].map((e) => ({ ...e, id: randomUUID() }));
      const fired = [...new Set(runRules(effective, evs).map((h) => h.ruleId))];
      const tp = s.expectedRules.filter((r) => fired.includes(r));
      const fp = fired.filter((r) => !s.expectedRules.includes(r));
      const fn = s.expectedRules.filter((r) => !fired.includes(r));
      return { scenario: s.id, provider: s.provider, adversarial: !!s.adversarial, expected: s.expectedRules, fired, tp: tp.length, fp: fp.length, fn: fn.length, false_positive_rules: fp, missed_rules: fn };
    });
    const tp = cases.reduce((n, x) => n + x.tp, 0), fp = cases.reduce((n, x) => n + x.fp, 0), fn = cases.reduce((n, x) => n + x.fn, 0);
    const metrics = { precision: tp + fp ? tp / (tp + fp) : null, recall: tp + fn ? tp / (tp + fn) : null, true_positives: tp, false_positives: fp, false_negatives: fn, scenarios: cases.length, data: "synthetic-fixture" };
    const [row] = await tx.insert(agentEvaluations).values({ tenantId: a.tenantId, suite: "detection-replay", agentRole: "detection_engine", modelProvider: "deterministic", modelName: "rules", promptVersion: `rules:${effective.length}`, metrics, cases }).returning();
    await a.audit({ action: "evaluation.run", targetType: "agent_evaluation", targetId: row!.id, details: metrics });
    return c.json({ evaluation: row });
  }));

route(governanceRoutes, "post", "/evaluations/import", {
  summary: "Store an agent evaluation report produced by the agent eval harness", tags: ["evaluation"],
  body: z.object({ suite: z.string().max(100), agentRole: z.string().max(64), modelProvider: z.string().max(64), modelName: z.string().max(128), promptVersion: z.string().max(64), metrics: z.record(z.string(), z.unknown()), cases: z.array(z.record(z.string(), z.unknown())).max(1000) }),
}, async (c, { body }) =>
  tenantTx(c, "agents:write", async (tx, a) => {
    const [row] = await tx.insert(agentEvaluations).values({ tenantId: a.tenantId, ...body }).returning();
    await a.audit({ action: "evaluation.imported", targetType: "agent_evaluation", targetId: row!.id, details: { suite: body.suite } });
    return c.json({ evaluation: row });
  }));

// ---------- audit ----------
route(governanceRoutes, "get", "/audit-logs", { summary: "Tenant audit log", tags: ["audit"], query: Pagination.extend({ action: z.string().max(64).optional(), targetId: z.string().max(64).optional() }) }, async (c, { query }) =>
  tenantTx(c, "read", async (tx) => {
    const w = [];
    if (query.action) w.push(sql`${auditLogs.action} like ${query.action.replace(/[%_]/g, "") + "%"}`);
    if (query.targetId) w.push(eq(auditLogs.targetId, query.targetId));
    const rows = await tx.select({ l: auditLogs, actorName: users.displayName }).from(auditLogs).leftJoin(users, sql`${users.id}::text = ${auditLogs.actorId}`).where(w.length ? and(...w) : undefined).orderBy(desc(auditLogs.id)).limit(query.limit).offset(query.offset);
    return c.json({ items: rows.map((r) => ({ ...r.l, actorName: r.actorName })) });
  }));

route(governanceRoutes, "get", "/audit-logs/verify", { summary: "Verify the tenant audit hash chain", tags: ["audit"] }, async (c) =>
  tenantTx(c, "audit:read", async (tx) => {
    const rows = await tx.select().from(auditLogs).orderBy(asc(auditLogs.id));
    return c.json({ entries: rows.length, ...verifyChain(rows) });
  }));

route(governanceRoutes, "get", "/members", { summary: "Tenant members", tags: ["settings"] }, async (c) =>
  tenantTx(c, "read", async (tx) => c.json({ items: await tx.select({ id: users.id, email: users.email, displayName: users.displayName, role: memberships.role, mustChangePassword: users.mustChangePassword, joinedAt: memberships.createdAt })
    .from(memberships).innerJoin(users, eq(users.id, memberships.userId)).orderBy(asc(memberships.createdAt)) })));

const RoleBody = z.enum(["owner", "admin", "analyst", "viewer"]);

route(governanceRoutes, "post", "/members", {
  summary: "Add a member (new accounts get a one-time password, returned once)", tags: ["settings"],
  body: z.object({ email: z.string().trim().min(3).max(254), displayName: z.string().trim().min(1).max(120), role: RoleBody }),
}, async (c, { body }) =>
  tenantTx(c, "members:write", async (tx, a) => {
    const r = await inviteMember(tx, a.tenantId, body);
    await a.audit({ action: "member.added", targetType: "user", targetId: r.userId, details: { email: body.email.trim().toLowerCase(), role: body.role, newAccount: r.created } });
    return c.json({ id: r.userId, email: body.email.trim().toLowerCase(), role: body.role, newAccount: r.created, oneTimePassword: r.oneTimePassword });
  }));

route(governanceRoutes, "patch", "/members/{id}", { summary: "Change a member's role", tags: ["settings"], params: IdParam, body: z.object({ role: RoleBody }) }, async (c, { params, body }) =>
  tenantTx(c, "members:write", async (tx, a) => {
    if (params.id === a.user.id) throw badRequest("you cannot change your own role");
    const r = await changeMemberRole(tx, a.tenantId, params.id, body.role);
    if (r.from !== r.to) await a.audit({ action: "member.role_changed", targetType: "user", targetId: params.id, details: r });
    return c.json({ id: params.id, role: r.to });
  }));

route(governanceRoutes, "delete", "/members/{id}", { summary: "Remove a member from this organization", tags: ["settings"], params: IdParam }, async (c, { params }) =>
  tenantTx(c, "members:write", async (tx, a) => {
    if (params.id === a.user.id) throw badRequest("you cannot remove yourself");
    const r = await removeMember(tx, a.tenantId, params.id);
    await a.audit({ action: "member.removed", targetType: "user", targetId: params.id, details: r });
    return c.json({ ok: true });
  }));

export { rowToRule };
