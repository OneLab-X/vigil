/**
 * Load one VigilBench case into a fresh, isolated tenant and run the real pipeline up to the point where an agent
 * would be dispatched: connection/account rows → raw storage + normalization (registry normalizers) → knowledge →
 * deterministic detection → correlation. Evaluation databases only (see run.ts).
 */
import { randomBytes } from "node:crypto";
import { desc, inArray, sql } from "drizzle-orm";
import { normalizerFor, requireConnector } from "@vigil/core";
import { cloudAccounts, cloudConnections, findings, incidentEvents, incidents, securityEvents, securityKnowledge, withTenant, type Db, type Tx } from "@vigil/db";
import { storeRawPage } from "../services/ingestion.js";
import { runDetection } from "../services/detection.js";
import { createTenant, upsertUser } from "../services/tenancy.js";
import { connectorConfig, type EvalCase } from "./cases.js";

export const EVAL_EMAIL_DOMAIN = "eval.vigil.test";
const SEV_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export interface LoadedCase {
  tenantId: string;
  ownerId: string;
  /** event id per record index (null when the record failed to normalize or duplicated an earlier one) */
  recordEventIds: Array<string | null>;
  incidentIds: string[];
  primaryIncidentId: string | null;
  firedRules: string[];
  suppressedRules: string[];
  /** identifier values present in the case data; a masked run must not send these to the model */
  canaries: string[];
  window: { start: string; end: string };
}

export async function loadCase(db: Db, c: EvalCase, tag: string): Promise<LoadedCase> {
  const suffix = randomBytes(5).toString("hex");
  const ownerId = await upsertUser(db, `owner+${suffix}@${EVAL_EMAIL_DOMAIN}`, `Eval owner ${tag}`, randomBytes(18).toString("base64url"));
  const tenantId = await createTenant(db, `Eval ${c.id} ${tag}`.slice(0, 120), `eval-${suffix}`, ownerId);

  const recordEventIds: Array<string | null> = [];
  const canaries = new Set<string>(c.canaries);
  let minTs = Infinity, maxTs = -Infinity;

  await withTenant(db, { tenantId, userId: ownerId }, async (tx) => {
    // one connection + account per connector so account ids are known to the masker and the broker
    const accountIds = new Map<string, string>();
    for (const connector of new Set(c.records.map((r) => r.connector))) {
      const def = requireConnector(connector);
      const config = def.configSchema.parse(connectorConfig(c, connector));
      const [conn] = await tx.insert(cloudConnections).values({ tenantId, provider: connector, displayName: `eval ${connector}`, config: config as object, status: "healthy", createdBy: ownerId }).returning({ id: cloudConnections.id });
      const externalId = def.accountRefOf(config);
      const [acct] = await tx.insert(cloudAccounts).values({ tenantId, connectionId: conn!.id, provider: connector, externalId, name: externalId }).returning({ id: cloudAccounts.id });
      accountIds.set(connector, acct!.id);
      canaries.add(externalId);
    }
    for (const r of c.records) {
      const def = requireConnector(r.connector);
      const config = def.configSchema.parse(connectorConfig(c, r.connector));
      const normalize = normalizerFor(def, r.sourceType);
      const res = await storeRawPage(tx, { tenantId, cloudAccountId: accountIds.get(r.connector)!, logSourceId: null, sourceType: r.sourceType },
        [r.raw], (raw) => normalize(raw, { config, sourceType: r.sourceType }));
      recordEventIds.push(res.eventIds[0] ?? null);
    }
    const ids = recordEventIds.filter((x): x is string => !!x);
    if (ids.length) {
      const rows = await tx.select({ ts: securityEvents.eventTimestamp, ip: securityEvents.sourceIp, dip: securityEvents.destinationIp, principal: securityEvents.principal })
        .from(securityEvents).where(inArray(securityEvents.id, ids));
      for (const e of rows) {
        minTs = Math.min(minTs, e.ts.getTime()); maxTs = Math.max(maxTs, e.ts.getTime());
        for (const v of [e.ip, e.dip, e.principal]) if (v && v.length >= 3) canaries.add(v);
      }
    }
    await seedKnowledge(tx, tenantId, ownerId, c, "before_detection");
  });
  if (!Number.isFinite(minTs)) throw new Error(`case ${c.id}: no record could be normalized`);

  const window = { start: new Date(minTs - 3600_000), end: new Date(maxTs + 3600_000) };
  await runDetection(db, tenantId, window);

  return withTenant(db, { tenantId, userId: ownerId }, async (tx) => {
    await seedKnowledge(tx, tenantId, ownerId, c, "after_detection");
    const incs = await tx.select({ id: incidents.id, severity: incidents.severity, n: sql<number>`(select count(*)::int from ${incidentEvents} ie where ie.incident_id = ${incidents.id})` })
      .from(incidents).orderBy(desc(incidents.createdAt));
    incs.sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0) || b.n - a.n);
    const f = await tx.execute(sql`select distinct r.rule_id, f.status from ${findings} f join detection_rules r on r.id = f.rule_id`) as unknown as Array<{ rule_id: string; status: string }>;
    return {
      tenantId, ownerId, recordEventIds,
      incidentIds: incs.map((i) => i.id), primaryIncidentId: incs[0]?.id ?? null,
      firedRules: [...new Set(f.filter((x) => x.status !== "suppressed").map((x) => x.rule_id))].sort(),
      suppressedRules: [...new Set(f.filter((x) => x.status === "suppressed").map((x) => x.rule_id))].sort(),
      canaries: [...canaries], window: { start: window.start.toISOString(), end: window.end.toISOString() },
    };
  });
}

async function seedKnowledge(tx: Tx, tenantId: string, ownerId: string, c: EvalCase, timing: "before_detection" | "after_detection") {
  const rows = c.knowledge.filter((k) => k.timing === timing);
  if (!rows.length) return;
  // Evaluation fixture: inserted directly as approved (the four-eyes approval flow is not what is being measured).
  await tx.insert(securityKnowledge).values(rows.map((k) => ({
    tenantId, kind: k.kind, key: k.key, title: k.title, body: k.body, attributes: k.attributes, status: "approved" as const, owner: "eval-fixture", proposedByUserId: ownerId,
  })));
}

/** Rows a run left behind besides its verdict: notes and proposed rules (tool-misuse signals). */
export async function runSideEffects(db: Db, tenantId: string, runId: string) {
  return withTenant(db, { tenantId }, async (tx) => {
    const notes = await tx.execute(sql`select body from incident_notes where author_run_id = ${runId}`) as unknown as Array<{ body: string }>;
    const rules = await tx.execute(sql`select rule_id, name, conditions from detection_rules where proposed_by_run_id = ${runId}`) as unknown as Array<{ rule_id: string; name: string; conditions: unknown }>;
    return { notes: notes.map((n) => n.body), proposedRules: rules.map((r) => ({ ruleId: r.rule_id, name: r.name, conditions: r.conditions })) };
  });
}

