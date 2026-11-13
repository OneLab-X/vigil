import { sql } from "drizzle-orm";
import { jobs, type Db, type Tx } from "@vigil/db";

export type JobType = "ingest" | "detect" | "agent_run" | "run_timeout" | "retention";

/**
 * Durable job queue on Postgres (FOR UPDATE SKIP LOCKED). Interface kept small so a Redis,
 * SQS or Pub/Sub adapter can replace it.
 */
export interface JobQueue {
  enqueue(tx: Tx | Db, tenantId: string, type: JobType, payload: Record<string, unknown>, opts?: { idempotencyKey?: string; runAfter?: Date; maxAttempts?: number }): Promise<void>;
  claim(db: Db, limit: number): Promise<Array<{ id: string; tenantId: string; type: JobType; payload: any; attempts: number; maxAttempts: number }>>;
  complete(db: Db, id: string): Promise<void>;
  fail(db: Db, id: string, err: string, attempts: number, maxAttempts: number): Promise<void>;
}

export const pgQueue: JobQueue = {
  async enqueue(tx, tenantId, type, payload, opts = {}) {
    await tx.insert(jobs).values({
      tenantId, type, payload, idempotencyKey: opts.idempotencyKey ?? null,
      runAfter: opts.runAfter ?? new Date(), maxAttempts: opts.maxAttempts ?? 5,
    }).onConflictDoNothing();
  },
  async claim(db, limit) {
    const rows = await db.execute(sql`
      update jobs set status = 'running', locked_at = now(), updated_at = now(), attempts = attempts + 1
      where id in (
        select id from jobs
        where (status = 'queued' and run_after <= now())
           or (status = 'running' and locked_at < now() - interval '10 minutes')
        order by run_after
        limit ${limit}
        for update skip locked
      )
      returning id, tenant_id, type, payload, attempts, max_attempts`);
    return (rows as unknown as any[]).map((r) => ({ id: r.id, tenantId: r.tenant_id, type: r.type, payload: r.payload, attempts: r.attempts, maxAttempts: r.max_attempts }));
  },
  async complete(db, id) {
    await db.execute(sql`update jobs set status = 'done', locked_at = null, updated_at = now() where id = ${id}`);
  },
  async fail(db, id, err, attempts, maxAttempts) {
    const dead = attempts >= maxAttempts;
    const backoffSec = Math.min(3600, 2 ** attempts * 5);
    await db.execute(sql`update jobs set status = ${dead ? "failed" : "queued"}, locked_at = null, updated_at = now(), last_error = ${err.slice(0, 2000)},
      run_after = now() + make_interval(secs => ${backoffSec}) where id = ${id}`);
  },
};
