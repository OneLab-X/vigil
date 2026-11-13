import { sql } from "drizzle-orm";
import type { Tx } from "@vigil/db";
import { getDb } from "../db.js";
import { HIST_LEN, histQuantile, LATENCY_RETENTION_DAYS } from "../lib/latency.js";
import { sanitizeError } from "../lib/sanitize.js";
import { readiness } from "./health.js";

/**
 * Operations page data. Everything tenant-specific runs inside the caller's tenant transaction (RLS);
 * the `jobs` table is a system table without RLS, so every jobs query filters on tenant_id explicitly.
 * Every query is bounded by a time window and/or LIMIT.
 */

export const WINDOWS = { "1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30 } as const;
export type OpsWindow = keyof typeof WINDOWS;

/** A job that has held its lock longer than this is "stuck" — matches the reclaim rule in lib/queue.ts. */
export const STUCK_AFTER_MINUTES = 10;
/** Worker is stale when no heartbeat arrived within this many minutes (heartbeat every 30 s). */
export const WORKER_STALE_MINUTES = 5;
const RECENT_LIMIT = 10;

type Rows<T> = T[];
const q = async <T>(tx: Tx, query: ReturnType<typeof sql>) => (await tx.execute(query)) as unknown as Rows<T>;
const iso = (d: Date | string | null | undefined) => (d ? new Date(d).toISOString() : null);

// ---------- component health ----------
export type ComponentStatus = "ok" | "down" | "stale" | "unknown";
export interface ComponentHealth { id: string; label: string; required: boolean; status: ComponentStatus; detail: string | null; lastSeenAt?: string | null }

/** Reuses the readiness probe (which never echoes connection strings or hostnames) and sanitizes again on the way out. */
export async function componentHealth(): Promise<ComponentHealth[]> {
  const r = await readiness();
  const c = r.components;
  const comp = (id: string, label: string, required: boolean, x: { ok: boolean; error?: string }): ComponentHealth =>
    ({ id, label, required, status: x.ok ? "ok" : "down", detail: x.ok ? null : sanitizeError(x.error, 120) });
  return [
    comp("database", "Database", true, c.database),
    comp("schema", "Schema / migrations", true, c.schema),
    comp("evidenceStore", "Evidence store", true, c.evidenceStore),
    comp("agents", "AI agents service", false, c.agents),
  ];
}

export async function workerHealth(tx: Tx, tenantId: string): Promise<ComponentHealth> {
  const [hb] = await q<{ last_seen: Date | null; live: number }>(tx, sql`select max(last_seen_at) as last_seen,
    count(*) filter (where last_seen_at > now() - make_interval(mins => ${WORKER_STALE_MINUTES}))::int as live from worker_heartbeats`);
  const [act] = await q<{ last: Date | null }>(tx, sql`select max(updated_at) as last from jobs where tenant_id = ${tenantId} and status in ('done','failed')`);
  const lastSeen = iso(hb?.last_seen);
  if (hb?.live) return { id: "worker", label: "Background worker", required: true, status: "ok", detail: `${hb.live} worker${hb.live > 1 ? "s" : ""} alive`, lastSeenAt: lastSeen };
  return {
    id: "worker", label: "Background worker", required: true, status: lastSeen ? "stale" : "unknown",
    detail: lastSeen ? `no heartbeat for over ${WORKER_STALE_MINUTES} min` : "no worker heartbeat recorded yet",
    lastSeenAt: lastSeen ?? iso(act?.last),
  };
}

// ---------- ingestion ----------
export type SourceStatus = "healthy" | "lagging" | "failing" | "never_run" | "disabled";
export function classifySource(s: { enabled: boolean; watermark: Date | null; lastFinishedStatus: string | null }, now: Date, thresholdMinutes: number): SourceStatus {
  if (!s.enabled) return "disabled";
  if (s.lastFinishedStatus === "failed") return "failing";
  if (!s.lastFinishedStatus && !s.watermark) return "never_run";
  if (!s.watermark || now.getTime() - s.watermark.getTime() > thresholdMinutes * 60_000) return "lagging";
  return "healthy";
}

export async function ingestionLag(tx: Tx, thresholdMinutes: number) {
  const rows = await q<any>(tx, sql`
    select s.id, s.name, s.source_type, s.enabled, s.poll_interval_seconds, c.watermark, now() as now,
      ls.finished_at as last_success_at, lf.status as last_status, lf.error as last_error, lf.finished_at as last_finished_at,
      (select count(*)::int from ingestion_jobs a where a.log_source_id = s.id and a.status in ('queued','running')) as active_jobs
    from log_sources s
    left join ingestion_checkpoints c on c.log_source_id = s.id
    left join lateral (select finished_at from ingestion_jobs j where j.log_source_id = s.id and j.status = 'succeeded' order by j.created_at desc limit 1) ls on true
    left join lateral (select status, error, finished_at from ingestion_jobs j where j.log_source_id = s.id and j.status in ('succeeded','failed') order by j.created_at desc limit 1) lf on true
    order by s.name limit 200`);
  const sources = rows.map((r) => {
    const now = new Date(r.now);
    const watermark = r.watermark ? new Date(r.watermark) : null;
    const status = classifySource({ enabled: r.enabled, watermark, lastFinishedStatus: r.last_status ?? null }, now, thresholdMinutes);
    return {
      id: r.id as string, name: r.name as string, sourceType: r.source_type as string, enabled: r.enabled as boolean, pollIntervalSeconds: r.poll_interval_seconds as number,
      watermark: iso(watermark), lagSeconds: watermark ? Math.max(0, Math.round((now.getTime() - watermark.getTime()) / 1000)) : null,
      lastSuccessAt: iso(r.last_success_at), lastFinishedAt: iso(r.last_finished_at),
      lastError: r.last_status === "failed" ? sanitizeError(r.last_error) : null, activeJobs: r.active_jobs as number, status,
    };
  });
  const counts = { healthy: 0, lagging: 0, failing: 0, never_run: 0, disabled: 0 } as Record<SourceStatus, number>;
  for (const s of sources) counts[s.status]++;
  return { thresholdMinutes, counts, sources };
}

// ---------- queue ----------
export async function queueDepth(tx: Tx, tenantId: string, hours: number) {
  const byTypeStatus = await q<{ type: string; status: string; n: number }>(tx, sql`
    select type, status, count(*)::int as n from jobs
    where tenant_id = ${tenantId} and (status <> 'done' or updated_at >= now() - make_interval(hours => ${hours}))
    group by type, status order by type, status`);
  const [s] = await q<any>(tx, sql`
    select extract(epoch from now() - min(run_after) filter (where status = 'queued' and run_after <= now()))::float8 as oldest_queued_s,
      count(*) filter (where status = 'queued' and run_after <= now())::int as runnable,
      count(*) filter (where status = 'queued' and run_after > now())::int as scheduled,
      count(*) filter (where status = 'queued' and attempts > 0)::int as retrying,
      count(*) filter (where status = 'running')::int as running,
      count(*) filter (where status = 'running' and locked_at < now() - make_interval(mins => ${STUCK_AFTER_MINUTES}))::int as stuck,
      count(*) filter (where status = 'failed')::int as dead_lettered
    from jobs where tenant_id = ${tenantId} and status in ('queued','running','failed')`);
  const stuck = await q<any>(tx, sql`select id, type, attempts, max_attempts, locked_at from jobs
    where tenant_id = ${tenantId} and status = 'running' and locked_at < now() - make_interval(mins => ${STUCK_AFTER_MINUTES})
    order by locked_at limit ${RECENT_LIMIT}`);
  return {
    windowHours: hours, stuckAfterMinutes: STUCK_AFTER_MINUTES,
    oldestQueuedSeconds: s?.oldest_queued_s === null || s?.oldest_queued_s === undefined ? null : Math.round(s.oldest_queued_s),
    runnable: s?.runnable ?? 0, scheduled: s?.scheduled ?? 0, retrying: s?.retrying ?? 0, running: s?.running ?? 0, stuck: s?.stuck ?? 0, deadLettered: s?.dead_lettered ?? 0,
    byTypeStatus,
    stuckJobs: stuck.map((j) => ({ id: j.id, type: j.type, attempts: j.attempts, maxAttempts: j.max_attempts, lockedAt: iso(j.locked_at) })),
  };
}

// ---------- failures ----------
export async function failures(tx: Tx, tenantId: string) {
  const [c] = await q<any>(tx, sql`select
    (select count(*) filter (where updated_at >= now() - interval '24 hours') from jobs where tenant_id = ${tenantId} and status = 'failed' and updated_at >= now() - interval '7 days')::int as jobs_24h,
    (select count(*) from jobs where tenant_id = ${tenantId} and status = 'failed' and updated_at >= now() - interval '7 days')::int as jobs_7d,
    (select count(*) from ingestion_jobs where status = 'failed' and created_at >= now() - interval '24 hours')::int as ingest_24h,
    (select count(*) from ingestion_jobs where status = 'failed' and created_at >= now() - interval '7 days')::int as ingest_7d,
    (select count(*) from investigation_runs where status in ('failed','timeout','rejected') and created_at >= now() - interval '24 hours')::int as runs_24h,
    (select count(*) from investigation_runs where status in ('failed','timeout','rejected') and created_at >= now() - interval '7 days')::int as runs_7d`);
  const recent = await q<any>(tx, sql`
    (select 'job' as kind, id::text as id, type as label, status, last_error as error, updated_at as at from jobs
      where tenant_id = ${tenantId} and status = 'failed' and updated_at >= now() - interval '7 days' order by updated_at desc limit ${RECENT_LIMIT})
    union all
    (select 'ingestion', j.id::text, coalesce(s.name, 'log source'), j.status, j.error, coalesce(j.finished_at, j.created_at) from ingestion_jobs j left join log_sources s on s.id = j.log_source_id
      where j.status = 'failed' and j.created_at >= now() - interval '7 days' order by j.created_at desc limit ${RECENT_LIMIT})
    union all
    (select 'investigation', id::text, role, status::text, error, coalesce(finished_at, created_at) from investigation_runs
      where status in ('failed','timeout','rejected') and created_at >= now() - interval '7 days' order by created_at desc limit ${RECENT_LIMIT})
    order by at desc limit 20`);
  return {
    counts: {
      jobs: { "24h": c?.jobs_24h ?? 0, "7d": c?.jobs_7d ?? 0 },
      ingestion: { "24h": c?.ingest_24h ?? 0, "7d": c?.ingest_7d ?? 0 },
      investigations: { "24h": c?.runs_24h ?? 0, "7d": c?.runs_7d ?? 0 },
    },
    recent: recent.map((r) => ({ kind: r.kind as string, id: r.id as string, label: r.label as string, status: r.status as string, error: sanitizeError(r.error), at: iso(r.at) })),
  };
}

// ---------- latency ----------
const latencyBin = (hours: number) => (hours <= 1 ? "5 minutes" : hours <= 24 ? "1 hour" : "6 hours");

interface LatAgg { count: number; s4: number; s5: number; sumMs: number; maxMs: number; hist: number[] }
const emptyAgg = (): LatAgg => ({ count: 0, s4: 0, s5: 0, sumMs: 0, maxMs: 0, hist: new Array(HIST_LEN).fill(0) });
const addHist = (a: LatAgg, i: number, n: number) => { if (i >= 0 && i < HIST_LEN) a.hist[i]! += n; };
const summarize = (a: LatAgg) => ({
  requests: a.count,
  errorRate: a.count ? a.s5 / a.count : null,
  clientErrorRate: a.count ? a.s4 / a.count : null,
  avgMs: a.count ? Math.round((a.sumMs / a.count) * 10) / 10 : null,
  p50Ms: histQuantile(a.hist, 0.5, a.maxMs), p95Ms: histQuantile(a.hist, 0.95, a.maxMs), p99Ms: histQuantile(a.hist, 0.99, a.maxMs),
  maxMs: a.count ? Math.round(a.maxMs * 10) / 10 : null,
});
export const routeGroup = (route: string) => (route.startsWith("/") ? route.split("/")[1] || "/" : route);

export async function latency(tx: Tx, requestedHours: number) {
  const hours = Math.min(requestedHours, LATENCY_RETENTION_DAYS * 24);
  const since = sql`now() - make_interval(hours => ${hours})`;
  const totals = await q<any>(tx, sql`select method, route, sum(count)::float8 as n, sum(status_4xx)::float8 as s4, sum(status_5xx)::float8 as s5,
      sum(sum_ms)::float8 as sum_ms, max(max_ms)::float8 as max_ms
    from api_latency_rollups where bucket >= ${since} group by method, route order by n desc limit 200`);
  const hist = await q<any>(tx, sql`select method, route, h.i::int as i, sum(h.v)::float8 as n
    from api_latency_rollups r, unnest(r.hist) with ordinality as h(v, i) where r.bucket >= ${since} group by method, route, h.i`);
  const bin = latencyBin(hours);
  const seriesTotals = await q<any>(tx, sql`select date_bin(${bin}::interval, bucket, timestamptz '2000-01-01') as t, sum(count)::float8 as n,
      sum(status_5xx)::float8 as s5, sum(sum_ms)::float8 as sum_ms, max(max_ms)::float8 as max_ms
    from api_latency_rollups where bucket >= ${since} group by 1 order by 1`);
  const seriesHist = await q<any>(tx, sql`select date_bin(${bin}::interval, r.bucket, timestamptz '2000-01-01') as t, h.i::int as i, sum(h.v)::float8 as n
    from api_latency_rollups r, unnest(r.hist) with ordinality as h(v, i) where r.bucket >= ${since} group by 1, 2`);

  const routes = new Map<string, LatAgg & { method: string; route: string }>();
  for (const r of totals) routes.set(`${r.method} ${r.route}`, { method: r.method, route: r.route, count: r.n, s4: r.s4, s5: r.s5, sumMs: r.sum_ms, maxMs: r.max_ms, hist: new Array(HIST_LEN).fill(0) });
  for (const h of hist) { const a = routes.get(`${h.method} ${h.route}`); if (a) addHist(a, h.i - 1, h.n); }

  const groups = new Map<string, LatAgg>();
  const overall = emptyAgg();
  for (const a of routes.values()) {
    const g = groups.get(routeGroup(a.route)) ?? emptyAgg();
    for (const t of [g, overall]) {
      t.count += a.count; t.s4 += a.s4; t.s5 += a.s5; t.sumMs += a.sumMs; t.maxMs = Math.max(t.maxMs, a.maxMs);
      a.hist.forEach((n, i) => (t.hist[i]! += n));
    }
    groups.set(routeGroup(a.route), g);
  }
  const series = new Map<string, LatAgg>();
  for (const s of seriesTotals) series.set(iso(s.t)!, { count: s.n, s4: 0, s5: s.s5, sumMs: s.sum_ms, maxMs: s.max_ms, hist: new Array(HIST_LEN).fill(0) });
  for (const h of seriesHist) { const a = series.get(iso(h.t)!); if (a) addHist(a, h.i - 1, h.n); }

  return {
    windowHours: hours, retentionDays: LATENCY_RETENTION_DAYS, binSize: bin,
    overall: summarize(overall),
    groups: [...groups.entries()].map(([group, a]) => ({ group, ...summarize(a) })).sort((x, y) => y.requests - x.requests),
    routes: [...routes.values()].slice(0, 25).map((a) => ({ method: a.method, route: a.route, ...summarize(a) })),
    series: [...series.entries()].map(([t, a]) => { const s = summarize(a); return { t, requests: s.requests, p50Ms: s.p50Ms, p95Ms: s.p95Ms, p99Ms: s.p99Ms, errorRate: s.errorRate }; }),
  };
}

// ---------- cost ----------
/** All money math is numeric in SQL; USD values are returned as fixed 6-decimal strings. */
export async function cost(tx: Tx, hours: number) {
  const since = sql`now() - make_interval(hours => ${hours})`;
  const [t] = await q<any>(tx, sql`select round(coalesce(sum(cost_usd), 0), 6)::text as total, coalesce(sum(input_tokens), 0)::float8 as input_tokens,
      coalesce(sum(output_tokens), 0)::float8 as output_tokens, count(*)::int as calls
    from model_usage where created_at >= ${since}`);
  const [r] = await q<any>(tx, sql`with r as (
      select ir.id, coalesce(sum(mu.cost_usd), 0) as c, coalesce(sum(mu.input_tokens + mu.output_tokens), 0) as tok
      from investigation_runs ir left join model_usage mu on mu.run_id = ir.id
      where ir.status = 'succeeded' and ir.created_at >= ${since} group by ir.id)
    select count(*)::int as runs, round(coalesce(avg(c), 0), 6)::text as avg, round(coalesce(percentile_disc(0.95) within group (order by c), 0), 6)::text as p95,
      round(coalesce(sum(c), 0), 6)::text as total, coalesce(round(avg(tok)), 0)::float8 as avg_tokens from r`);
  const breakdown = await q<any>(tx, sql`select provider, model, count(*)::int as calls, count(distinct run_id)::int as runs,
      sum(input_tokens)::float8 as input_tokens, sum(output_tokens)::float8 as output_tokens, round(sum(cost_usd), 6)::text as cost
    from model_usage where created_at >= ${since} group by provider, model order by sum(cost_usd) desc limit 20`);
  const [all] = await q<{ n: number }>(tx, sql`select count(*)::int as n from investigation_runs`);
  return {
    windowHours: hours, currency: "USD",
    totalUsd: t?.total ?? "0.000000", inputTokens: t?.input_tokens ?? 0, outputTokens: t?.output_tokens ?? 0, modelCalls: t?.calls ?? 0,
    perInvestigation: { completedRuns: r?.runs ?? 0, avgUsd: r?.avg ?? "0.000000", p95Usd: r?.p95 ?? "0.000000", totalUsd: r?.total ?? "0.000000", avgTokens: r?.avg_tokens ?? 0 },
    byModel: breakdown.map((b) => ({ provider: b.provider, model: b.model, calls: b.calls, runs: b.runs, inputTokens: b.input_tokens, outputTokens: b.output_tokens, costUsd: b.cost })),
    hasInvestigations: (all?.n ?? 0) > 0,
  };
}

// ---------- storage ----------
export async function storage(tx: Tx) {
  const [s] = await q<any>(tx, sql`select (select count(*) from security_events)::float8 as events,
    (select count(*) from raw_event_references)::float8 as raw_objects,
    (select coalesce(sum(size_bytes), 0) from raw_event_references)::float8 as raw_bytes`);
  return { securityEvents: s?.events ?? 0, rawEvidenceObjects: s?.raw_objects ?? 0, rawEvidenceBytes: s?.raw_bytes ?? 0 };
}

/** Whole-database size (shared by all tenants). Needs CONNECT on the database; degrades to null if not permitted. */
export async function databaseSize(): Promise<{ bytes: number | null; note: string | null }> {
  try {
    const [r] = (await getDb().execute(sql`select pg_database_size(current_database())::float8 as b`)) as unknown as Array<{ b: number }>;
    return { bytes: r?.b ?? null, note: "whole database, shared by all tenants" };
  } catch {
    return { bytes: null, note: "not permitted for the application database role" };
  }
}

export async function tenantOverview(tx: Tx, tenantId: string, window: OpsWindow, lagThresholdMinutes: number) {
  const hours = WINDOWS[window];
  const worker = await workerHealth(tx, tenantId);
  const ingestion = await ingestionLag(tx, lagThresholdMinutes);
  const queue = await queueDepth(tx, tenantId, hours);
  const fails = await failures(tx, tenantId);
  const lat = await latency(tx, hours);
  const costs = await cost(tx, hours);
  const store = await storage(tx);
  return { worker, ingestion, queue, failures: fails, latency: lat, cost: costs, storage: store };
}
