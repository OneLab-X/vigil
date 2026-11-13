import { and, eq, sql } from "drizzle-orm";
import { deduplicationKey, sha256, stableStringify, type CanonicalEvent } from "@vigil/core";
import {
  cloudAccounts, cloudConnections, cloudResources, ingestionJobs, logSources, rawEventReferences, securityEvents, withTenant, type Db, type Tx,
} from "@vigil/db";
import { blobStore } from "../lib/blobstore.js";
import { pgQueue } from "../lib/queue.js";
import { audit } from "../lib/audit.js";
import { env } from "../env.js";
import { checkpointStore, connectorFor } from "./connectors.js";

export interface StoreResult { inserted: number; duplicates: number; failed: number; eventIds: string[] }

/**
 * Persist a page of raw provider records: immutable raw blob + reference, then normalized
 * event. Idempotent: duplicates collapse on (tenant_id, deduplication_key).
 */
export async function storeRawPage(
  tx: Tx, ctx: { tenantId: string; cloudAccountId: string | null; logSourceId: string | null; sourceType: string },
  raws: unknown[], normalize: (raw: unknown) => CanonicalEvent,
): Promise<StoreResult> {
  const res: StoreResult = { inserted: 0, duplicates: 0, failed: 0, eventIds: [] };
  const rows: Array<typeof securityEvents.$inferInsert> = [];
  const resources = new Map<string, { type: string; id: string }>();
  for (const raw of raws) {
    let ev: CanonicalEvent;
    const json = stableStringify(raw);
    try { ev = normalize(raw); } catch { res.failed++; continue; }
    const digest = sha256(json);
    const uri = await blobStore.putImmutable(ctx.tenantId, digest, json);
    const [ref] = await tx.insert(rawEventReferences).values({ tenantId: ctx.tenantId, storageUri: uri, sha256: digest, sizeBytes: Buffer.byteLength(json), providerEventId: ev.providerEventId })
      .onConflictDoNothing().returning({ id: rawEventReferences.id });
    const refId = ref?.id ?? (await tx.select({ id: rawEventReferences.id }).from(rawEventReferences).where(and(eq(rawEventReferences.tenantId, ctx.tenantId), eq(rawEventReferences.sha256, digest))).limit(1))[0]?.id;
    if (ev.resourceType && ev.resourceId) resources.set(`${ev.resourceType}|${ev.resourceId}`, { type: ev.resourceType, id: ev.resourceId });
    rows.push({
      tenantId: ctx.tenantId, cloudProvider: ev.cloudProvider, cloudAccountId: ctx.cloudAccountId, projectOrAccountReference: ev.projectOrAccountReference,
      logSourceId: ctx.logSourceId, region: ev.region, sourceType: ev.sourceType, sourceName: ev.sourceName, eventTimestamp: new Date(ev.eventTimestamp),
      resourceType: ev.resourceType, resourceId: ev.resourceId, serviceName: ev.serviceName, severity: ev.severity, principal: ev.principal,
      sourceIp: ev.sourceIp, destinationIp: ev.destinationIp, action: ev.action?.slice(0, 2000) ?? null, status: ev.status, httpStatus: ev.httpStatus,
      httpMethod: ev.httpMethod, urlPath: ev.urlPath?.slice(0, 2000) ?? null, userAgent: ev.userAgent?.slice(0, 1000) ?? null, traceId: ev.traceId,
      requestId: ev.requestId, normalizedEventType: ev.normalizedEventType, categories: ev.categories, originalPayloadReference: refId ?? null,
      normalizedPayload: ev.normalized, deduplicationKey: deduplicationKey(ev, json),
    });
  }
  for (let i = 0; i < rows.length; i += 500) {
    const chunk = rows.slice(i, i + 500);
    const ins = await tx.insert(securityEvents).values(chunk).onConflictDoNothing().returning({ id: securityEvents.id });
    res.inserted += ins.length;
    res.duplicates += chunk.length - ins.length;
    res.eventIds.push(...ins.map((r) => r.id));
  }
  if (ctx.cloudAccountId && resources.size) {
    await tx.insert(cloudResources).values([...resources.values()].slice(0, 500).map((r) => ({ tenantId: ctx.tenantId, cloudAccountId: ctx.cloudAccountId!, resourceType: r.type, resourceId: r.id })))
      .onConflictDoUpdate({ target: [cloudResources.tenantId, cloudResources.cloudAccountId, cloudResources.resourceType, cloudResources.resourceId], set: { lastSeenAt: new Date() } });
  }
  return res;
}

/** Execute one ingestion job end-to-end. Each page commits separately so progress survives crashes. */
export async function runIngestionJob(db: Db, tenantId: string, jobId: string): Promise<void> {
  const loaded = await withTenant(db, { tenantId }, async (tx) => {
    const [job] = await tx.select().from(ingestionJobs).where(eq(ingestionJobs.id, jobId)).limit(1);
    if (!job || job.status === "succeeded") return null;
    const [src] = await tx.select().from(logSources).where(eq(logSources.id, job.logSourceId)).limit(1);
    const [conn] = await tx.select().from(cloudConnections).where(eq(cloudConnections.id, src!.connectionId)).limit(1);
    await tx.update(ingestionJobs).set({ status: "running", startedAt: job.startedAt ?? new Date(), error: null }).where(eq(ingestionJobs.id, jobId));
    return { job, src: src!, conn: conn! };
  });
  if (!loaded) return;
  const { job, src, conn } = loaded;
  try {
    const connector = await connectorFor(conn);
    // Resume from a saved page token if this exact job was interrupted mid-way.
    let pageToken = await withTenant(db, { tenantId }, async (tx) => {
      const cp = await checkpointStore(tx, tenantId).get(src.id);
      return cp && (await tx.execute(sql`select 1 from ingestion_checkpoints where log_source_id = ${src.id} and job_id = ${jobId}`)).length ? cp.pageToken : null;
    });
    let pages = job.pagesFetched;
    let totals = { seen: job.eventsSeen, inserted: job.eventsInserted, dup: job.duplicates };
    do {
      const page = await connector.listEvents({ sourceType: src.sourceType, filter: src.filter, start: job.rangeStart, end: job.rangeEnd, pageToken, pageSize: 1000 });
      pages++;
      await withTenant(db, { tenantId }, async (tx) => {
        const r = await storeRawPage(tx, { tenantId, cloudAccountId: src.cloudAccountId, logSourceId: src.id, sourceType: src.sourceType }, page.raw, (raw) => connector.normalize(raw, src.sourceType));
        totals = { seen: totals.seen + page.raw.length, inserted: totals.inserted + r.inserted, dup: totals.dup + r.duplicates };
        await tx.update(ingestionJobs).set({ pagesFetched: pages, eventsSeen: totals.seen, eventsInserted: totals.inserted, duplicates: totals.dup }).where(eq(ingestionJobs.id, jobId));
        await tx.execute(sql`insert into ingestion_checkpoints (tenant_id, log_source_id, page_token, job_id, updated_at) values (${tenantId}, ${src.id}, ${page.nextPageToken}, ${jobId}, now())
          on conflict (tenant_id, log_source_id) do update set page_token = excluded.page_token, job_id = excluded.job_id, updated_at = now()`);
      });
      pageToken = page.nextPageToken;
    } while (pageToken && pages < env.maxPagesPerJob);

    const truncated = !!pageToken;
    await withTenant(db, { tenantId }, async (tx) => {
      await tx.update(ingestionJobs).set({ status: "succeeded", finishedAt: new Date(), error: truncated ? `stopped after ${pages} pages (VIGIL_MAX_PAGES_PER_JOB); remaining range will be picked up by the next job` : null }).where(eq(ingestionJobs.id, jobId));
      // Advance watermark only when the full range was consumed; never move it backwards.
      if (!truncated) {
        await tx.execute(sql`insert into ingestion_checkpoints (tenant_id, log_source_id, watermark, page_token, job_id, updated_at) values (${tenantId}, ${src.id}, ${job.rangeEnd.toISOString()}::timestamptz, null, null, now())
          on conflict (tenant_id, log_source_id) do update set watermark = greatest(coalesce(ingestion_checkpoints.watermark, excluded.watermark), excluded.watermark), page_token = null, job_id = null, updated_at = now()`);
      } else {
        await tx.execute(sql`update ingestion_checkpoints set page_token = null, job_id = null where log_source_id = ${src.id}`);
      }
      await tx.update(cloudConnections).set({ lastSuccessfulIngestAt: new Date(), status: "healthy" }).where(eq(cloudConnections.id, conn.id));
      await audit(tx, { tenantId, actorType: "system", actorId: "ingestion-worker", action: "ingestion.job.succeeded", targetType: "ingestion_job", targetId: jobId, details: { pages, ...totals, truncated } });
      // Detect over the ingested range, widened by 1h for windowed rules.
      await pgQueue.enqueue(tx, tenantId, "detect", { start: new Date(job.rangeStart.getTime() - 3600_000).toISOString(), end: job.rangeEnd.toISOString() });
    });
  } catch (err) {
    const msg = (err as Error).message.slice(0, 1000);
    await withTenant(db, { tenantId }, async (tx) => {
      await tx.update(ingestionJobs).set({ status: "failed", finishedAt: new Date(), error: msg }).where(eq(ingestionJobs.id, jobId));
      await tx.update(cloudConnections).set({ status: "degraded" }).where(eq(cloudConnections.id, conn.id));
      await audit(tx, { tenantId, actorType: "system", actorId: "ingestion-worker", action: "ingestion.job.failed", targetType: "ingestion_job", targetId: jobId, details: { error: msg } });
    });
    throw err;
  }
}

/** Scheduler: create incremental jobs for sources that are due (overlap by lag; dedup absorbs repeats). */
export async function scheduleIncremental(db: Db): Promise<number> {
  const due = (await db.execute(sql`select tenant_id, log_source_id from vigil_due_log_sources()`)) as unknown as Array<{ tenant_id: string; log_source_id: string }>;
  for (const d of due) {
    await withTenant(db, { tenantId: d.tenant_id }, async (tx) => {
      const cp = await checkpointStore(tx, d.tenant_id).get(d.log_source_id);
      const end = new Date();
      const start = cp?.watermark ? new Date(new Date(cp.watermark).getTime() - env.ingestLagMinutes * 60_000) : new Date(end.getTime() - 3600_000);
      const [job] = await tx.insert(ingestionJobs).values({ tenantId: d.tenant_id, logSourceId: d.log_source_id, kind: "incremental", rangeStart: start, rangeEnd: end }).returning();
      await pgQueue.enqueue(tx, d.tenant_id, "ingest", { jobId: job!.id }, { idempotencyKey: `ingest:${job!.id}` });
    });
  }
  return due.length;
}

export async function ensureCloudAccount(tx: Tx, tenantId: string, connectionId: string, provider: string, externalId: string): Promise<string> {
  const [row] = await tx.insert(cloudAccounts).values({ tenantId, connectionId, provider, externalId, name: externalId })
    .onConflictDoUpdate({ target: [cloudAccounts.tenantId, cloudAccounts.provider, cloudAccounts.externalId], set: { connectionId } }).returning({ id: cloudAccounts.id });
  return row!.id;
}
