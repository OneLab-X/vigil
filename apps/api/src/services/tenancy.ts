import { eq, sql } from "drizzle-orm";
import { SEED_RULES } from "@vigil/core";
import { detectionRules, memberships, users, withTenant, type Db } from "@vigil/db";
import { hashPassword } from "../lib/crypto.js";
import { audit } from "../lib/audit.js";
import { ensureAgentDefinitions } from "./investigation.js";
import type { Role } from "../lib/rbac.js";

export async function upsertUser(db: Db, email: string, displayName: string, password: string): Promise<string> {
  const [existing] = await db.select().from(users).where(eq(users.email, email.toLowerCase()));
  if (existing) { await db.update(users).set({ passwordHash: await hashPassword(password) }).where(eq(users.id, existing.id)); return existing.id; }
  const [u] = await db.insert(users).values({ email: email.toLowerCase(), displayName, passwordHash: await hashPassword(password) }).returning({ id: users.id });
  return u!.id;
}

export async function createTenant(db: Db, name: string, slug: string, ownerId: string): Promise<string> {
  const [{ id }] = (await db.execute(sql`select vigil_create_tenant(${name}, ${slug}, ${ownerId}::uuid) as id`)) as unknown as Array<{ id: string }>;
  await withTenant(db, { tenantId: id, userId: ownerId }, async (tx) => {
    await tx.insert(detectionRules).values(SEED_RULES.map((r) => ({
      tenantId: id, ruleId: r.ruleId, name: r.name, description: r.description, provider: r.provider, eventSources: r.eventSources,
      detectionQuery: r.detectionQuery, conditions: { ...r.conditions, confidence: r.confidence }, severity: r.severity, mitre: r.mitre,
      enabled: r.enabled, version: 1, owner: "vigil-content", approvalStatus: "approved" as const,
    }))).onConflictDoNothing();
    await ensureAgentDefinitions(tx, id);
    await audit(tx, { tenantId: id, actorType: "system", actorId: "provisioning", action: "tenant.created", targetType: "tenant", targetId: id, details: { name, slug } });
  });
  return id;
}

export async function addMember(db: Db, tenantId: string, userId: string, role: Role) {
  await withTenant(db, { tenantId }, (tx) => tx.insert(memberships).values({ tenantId, userId, role }).onConflictDoNothing());
}
