import { sql } from "drizzle-orm";
import { auditLogs, type Tx } from "@vigil/db";
import { stableStringify } from "@vigil/core";
import { sha256 } from "./crypto.js";

export interface AuditEntry {
  tenantId: string | null;
  actorType: "user" | "agent" | "system";
  actorId: string | null;
  action: string;
  targetType?: string;
  targetId?: string;
  details?: Record<string, unknown>;
  requestId?: string;
  ip?: string | null;
}

/**
 * Append-only, per-tenant hash-chained audit log. The app role has INSERT/SELECT only; the
 * chain lets an auditor detect deletion or modification by anyone with owner rights.
 */
export async function audit(tx: Tx, e: AuditEntry): Promise<void> {
  const lockKey = `audit:${e.tenantId ?? "system"}`;
  await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${lockKey}))`);
  const prev = await tx.execute<{ hash: string }>(
    e.tenantId
      ? sql`select hash from audit_logs where tenant_id = ${e.tenantId} order by id desc limit 1`
      : sql`select hash from audit_logs where tenant_id is null order by id desc limit 1`,
  );
  const prevHash = (prev as unknown as Array<{ hash: string }>)[0]?.hash ?? null;
  const createdAt = new Date();
  // Canonical (sorted-key) JSON: jsonb reorders keys, so plain JSON.stringify would not re-verify.
  const material = stableStringify([prevHash, e.tenantId, e.actorType, e.actorId, e.action, e.targetType ?? null, e.targetId ?? null, JSON.parse(JSON.stringify(e.details ?? {})), createdAt.toISOString()]);
  await tx.insert(auditLogs).values({
    tenantId: e.tenantId, actorType: e.actorType, actorId: e.actorId, action: e.action,
    targetType: e.targetType ?? null, targetId: e.targetId ?? null, details: e.details ?? {},
    requestId: e.requestId ?? null, ip: e.ip ?? null, prevHash, hash: sha256(material), createdAt,
  });
}

export function verifyChain(rows: Array<{ prevHash: string | null; hash: string; tenantId: string | null; actorType: string; actorId: string | null; action: string; targetType: string | null; targetId: string | null; details: unknown; createdAt: Date }>): { ok: boolean; brokenAt?: number } {
  let prev: string | null = null;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i]!;
    if (r.prevHash !== prev) return { ok: false, brokenAt: i };
    const material = stableStringify([r.prevHash, r.tenantId, r.actorType, r.actorId, r.action, r.targetType, r.targetId, r.details, r.createdAt.toISOString()]);
    if (sha256(material) !== r.hash) return { ok: false, brokenAt: i };
    prev = r.hash;
  }
  return { ok: true };
}
