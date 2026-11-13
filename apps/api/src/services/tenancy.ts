import { and, eq, sql } from "drizzle-orm";
import { SEED_RULES } from "@vigil/core";
import { detectionRules, memberships, sessions, users, withTenant, type Db, type Tx } from "@vigil/db";
import { hashPassword, randomToken } from "../lib/crypto.js";
import { badRequest, conflict, notFound } from "../lib/errors.js";
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

export const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export interface InviteResult { userId: string; created: boolean; oneTimePassword: string | null }

/**
 * Add a person to the tenant inside an existing tenant-scoped transaction.
 * New accounts get a random one-time password (must be changed at first sign-in); it is returned
 * to the caller exactly once and only its hash is stored. Existing accounts keep their password.
 */
export async function inviteMember(tx: Tx, tenantId: string, input: { email: string; displayName: string; role: Role }): Promise<InviteResult> {
  const email = input.email.trim().toLowerCase();
  if (!EMAIL_RE.test(email)) throw badRequest("invalid email");
  const [existing] = await tx.select({ id: users.id }).from(users).where(eq(users.email, email));
  let userId: string, oneTimePassword: string | null = null;
  if (existing) {
    userId = existing.id;
    const [m] = await tx.select({ role: memberships.role }).from(memberships).where(and(eq(memberships.tenantId, tenantId), eq(memberships.userId, userId)));
    if (m) throw conflict(`${email} is already a member (${m.role})`);
  } else {
    oneTimePassword = randomToken(18);
    const [u] = await tx.insert(users).values({ email, displayName: input.displayName.trim(), passwordHash: await hashPassword(oneTimePassword), mustChangePassword: true }).returning({ id: users.id });
    userId = u!.id;
  }
  await tx.insert(memberships).values({ tenantId, userId, role: input.role });
  return { userId, created: !existing, oneTimePassword };
}

/** Owners currently in the tenant, row-locked so concurrent demotions/removals cannot leave zero. */
async function lockedOwners(tx: Tx, tenantId: string): Promise<string[]> {
  const rows = await tx.select({ userId: memberships.userId }).from(memberships)
    .where(and(eq(memberships.tenantId, tenantId), eq(memberships.role, "owner"))).for("update");
  return rows.map((r) => r.userId);
}

async function currentRole(tx: Tx, tenantId: string, userId: string): Promise<Role> {
  const [m] = await tx.select({ role: memberships.role }).from(memberships).where(and(eq(memberships.tenantId, tenantId), eq(memberships.userId, userId)));
  if (!m) throw notFound("member");
  return m.role;
}

export async function changeMemberRole(tx: Tx, tenantId: string, userId: string, role: Role): Promise<{ from: Role; to: Role }> {
  const owners = await lockedOwners(tx, tenantId);
  const from = await currentRole(tx, tenantId, userId);
  if (from === "owner" && role !== "owner" && owners.length <= 1) throw badRequest("an organization needs at least one owner; promote someone else first");
  if (from !== role) await tx.update(memberships).set({ role }).where(and(eq(memberships.tenantId, tenantId), eq(memberships.userId, userId)));
  return { from, to: role };
}

export async function removeMember(tx: Tx, tenantId: string, userId: string): Promise<{ role: Role }> {
  const owners = await lockedOwners(tx, tenantId);
  const role = await currentRole(tx, tenantId, userId);
  if (role === "owner" && owners.length <= 1) throw badRequest("cannot remove the last owner");
  await tx.delete(memberships).where(and(eq(memberships.tenantId, tenantId), eq(memberships.userId, userId)));
  // Sessions parked on this tenant lose it immediately (role is re-read per request anyway).
  await tx.update(sessions).set({ activeTenantId: null }).where(and(eq(sessions.userId, userId), eq(sessions.activeTenantId, tenantId)));
  return { role };
}
