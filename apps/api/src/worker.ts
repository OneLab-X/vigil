import { randomUUID } from "node:crypto";
import { sql } from "drizzle-orm";
import { tenants, withTenant, type Db } from "@vigil/db";
import { pgQueue } from "./lib/queue.js";
import { pruneLatency } from "./lib/latency.js";
import { runIngestionJob, scheduleIncremental } from "./services/ingestion.js";
import { runDetection } from "./services/detection.js";
import { handleRunTimeout, startAgentRun } from "./services/investigation.js";

export async function processJob(db: Db, job: { id: string; tenantId: string; type: string; payload: any }) {
  switch (job.type) {
    case "ingest": return runIngestionJob(db, job.tenantId, job.payload.jobId);
    case "detect": return void (await runDetection(db, job.tenantId, { start: new Date(job.payload.start), end: new Date(job.payload.end) }));
    case "agent_run": {
      try { await startAgentRun(db, job.tenantId, job.payload.incidentId, job.payload.role, job.payload.triggeredBy ?? null); }
      catch (e: any) { if (e?.code !== "run_in_progress") throw e; }
      return;
    }
    case "run_timeout": return handleRunTimeout(db, job.tenantId, job.payload.runId);
    case "retention": return withTenant(db, { tenantId: job.tenantId }, async (tx) => {
      const [t] = await tx.select({ days: tenants.retentionDays }).from(tenants).where(sql`id = ${job.tenantId}`);
      if (t) await tx.execute(sql`select vigil_purge_expired_events(${job.tenantId}::uuid, ${t.days})`);
      await pruneLatency(tx);
    });
    default: throw new Error(`unknown job type ${job.type}`);
  }
}

/** Drain whatever is runnable now (used by tests and the dev loop). */
export async function drainOnce(db: Db, max = 50): Promise<number> {
  let n = 0;
  for (;;) {
    const batch = await pgQueue.claim(db, 5);
    if (!batch.length || n >= max) return n;
    for (const j of batch) {
      n++;
      try { await processJob(db, j); await pgQueue.complete(db, j.id); }
      catch (e: any) {
        const err = `${e?.message ?? e}${e?.cause?.message ? ` | cause: ${e.cause.message}` : ""}`.slice(0, 2000);
        console.error(JSON.stringify({ level: "error", msg: "job failed", job: j.id, type: j.type, err }));
        await pgQueue.fail(db, j.id, err, j.attempts, j.maxAttempts);
      }
    }
  }
}

/** Liveness row for the Operations page. Random id per process; no hostnames. Stale rows (> 1 day) are pruned. */
export async function workerHeartbeat(db: Db, workerId: string) {
  await db.execute(sql`insert into worker_heartbeats (worker_id) values (${workerId}) on conflict (worker_id) do update set last_seen_at = now()`);
  await db.execute(sql`delete from worker_heartbeats where last_seen_at < now() - interval '1 day'`);
}

export function startWorker(db: Db, onTick?: () => void) {
  let stopped = false;
  let lastTick = 0;
  let lastBeat = 0;
  const workerId = randomUUID();
  const loop = async () => {
    while (!stopped) {
      onTick?.();
      if (Date.now() - lastBeat > 30_000) { lastBeat = Date.now(); await workerHeartbeat(db, workerId).catch(() => { /* best effort */ }); }
      try {
        if (Date.now() - lastTick > 60_000) { lastTick = Date.now(); const n = await scheduleIncremental(db); if (n) console.log(JSON.stringify({ level: "info", msg: "scheduled incremental ingestion", sources: n })); }
        const n = await drainOnce(db, 20);
        if (!n) await new Promise((r) => setTimeout(r, 2000));
      } catch (e) {
        console.error(JSON.stringify({ level: "error", msg: "worker loop error", err: (e as Error).message }));
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
  };
  void loop();
  return () => { stopped = true; };
}
