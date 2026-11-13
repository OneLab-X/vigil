import type { MiddlewareHandler } from "hono";
import { matchedRoutes } from "hono/route";
import { sql } from "drizzle-orm";
import { apiLatencyRollups, withTenant, type Db } from "@vigil/db";
import type { AppEnv } from "./context.js";

/**
 * API latency recording. Requests are aggregated in memory into per-minute buckets keyed by
 * (tenant, method, route template) and flushed as rollup rows. No per-request rows, IPs, query
 * strings, raw paths or bodies are ever stored. Kept small so a Prometheus/OTel exporter can be
 * added later by reading the same aggregates.
 */

/** Upper bounds (ms) of the histogram buckets; one extra overflow bucket follows. Must match the migration comment. */
export const LATENCY_BOUNDS_MS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000] as const;
export const HIST_LEN = LATENCY_BOUNDS_MS.length + 1;
export const LATENCY_RETENTION_DAYS = 7;
const MAX_KEYS = 20_000; // hard cap on buffered aggregates between flushes

interface Agg { tenantId: string; bucket: number; method: string; route: string; count: number; s4: number; s5: number; sum: number; max: number; hist: number[] }

const API_PREFIX = "/api/v1";

/** Route template for a request (e.g. "/incidents/:id"), never the raw path. */
export function routeTemplate(c: Parameters<MiddlewareHandler<AppEnv>>[0]): string {
  let routes: Array<{ path: string; method: string }> = [];
  try { routes = matchedRoutes(c) as any; } catch { /* no match result */ }
  // Middleware is registered with method ALL; the endpoint handler is the last method-specific match.
  const handler = [...routes].reverse().find((r) => r.method !== "ALL");
  if (!handler) return "unmatched";
  const p = handler.path.startsWith(API_PREFIX) ? handler.path.slice(API_PREFIX.length) || "/" : handler.path;
  return p.slice(0, 200);
}

export const bucketIndex = (ms: number) => {
  const i = LATENCY_BOUNDS_MS.findIndex((b) => ms <= b);
  return i === -1 ? LATENCY_BOUNDS_MS.length : i;
};

export class LatencyRecorder {
  private buf = new Map<string, Agg>();
  private lastPrune = 0;
  dropped = 0;

  record(tenantId: string, method: string, route: string, status: number, ms: number, at = Date.now()) {
    const bucket = Math.floor(at / 60_000) * 60_000;
    const key = `${tenantId}|${bucket}|${method}|${route}`;
    let a = this.buf.get(key);
    if (!a) {
      if (this.buf.size >= MAX_KEYS) { this.dropped++; return; }
      a = { tenantId, bucket, method, route, count: 0, s4: 0, s5: 0, sum: 0, max: 0, hist: new Array(HIST_LEN).fill(0) };
      this.buf.set(key, a);
    }
    a.count++;
    if (status >= 500) a.s5++; else if (status >= 400) a.s4++;
    a.sum += ms;
    if (ms > a.max) a.max = ms;
    a.hist[bucketIndex(ms)]!++;
  }

  get pending() { return this.buf.size; }

  /** Write buffered aggregates (additive upsert, per tenant under RLS) and prune rollups older than the retention window. */
  async flush(db: Db) {
    const items = [...this.buf.values()];
    this.buf.clear();
    const byTenant = new Map<string, Agg[]>();
    for (const a of items) byTenant.set(a.tenantId, [...(byTenant.get(a.tenantId) ?? []), a]);
    const prune = Date.now() - this.lastPrune > 3_600_000;
    if (prune) this.lastPrune = Date.now();
    for (const [tenantId, rows] of byTenant) {
      try {
        await withTenant(db, { tenantId }, async (tx) => {
          const t = apiLatencyRollups;
          await tx.insert(t).values(rows.map((r) => ({
            tenantId, bucket: new Date(r.bucket), method: r.method, route: r.route, count: r.count, status4xx: r.s4, status5xx: r.s5,
            sumMs: r.sum, maxMs: r.max, hist: r.hist,
          }))).onConflictDoUpdate({
            target: [t.tenantId, t.bucket, t.method, t.route],
            set: {
              count: sql`${t.count} + excluded.count`,
              status4xx: sql`${t.status4xx} + excluded.status_4xx`,
              status5xx: sql`${t.status5xx} + excluded.status_5xx`,
              sumMs: sql`${t.sumMs} + excluded.sum_ms`,
              maxMs: sql`greatest(${t.maxMs}, excluded.max_ms)`,
              hist: sql`(select array_agg(coalesce(x.a, 0) + coalesce(x.b, 0) order by x.i) from unnest(${t.hist}, excluded.hist) with ordinality as x(a, b, i))`,
            },
          });
          if (prune) await pruneLatency(tx as any);
        });
      } catch (e) {
        // tenant deleted between request and flush, or DB unavailable: metrics are best-effort
        console.error(JSON.stringify({ level: "warn", msg: "latency flush failed", err: (e as Error).message.slice(0, 200) }));
      }
    }
  }
}

/** Delete rollups older than the retention window for the current tenant context. */
export async function pruneLatency(tx: { execute: Db["execute"] }) {
  await tx.execute(sql`delete from api_latency_rollups where bucket < now() - make_interval(days => ${LATENCY_RETENTION_DAYS})`);
}

export const latencyRecorder = new LatencyRecorder();

/** Hono middleware: records method, route template, status class and duration for tenant-bound API requests. */
export function latencyMiddleware(rec: LatencyRecorder = latencyRecorder): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const t0 = performance.now();
    try {
      await next();
    } finally {
      const tenantId = c.get("tenantId");
      // Only tenant-bound requests are attributable; unauthenticated traffic is not recorded.
      if (tenantId && c.req.method !== "OPTIONS") {
        rec.record(tenantId, c.req.method, routeTemplate(c), c.res?.status ?? 500, performance.now() - t0);
      }
    }
  };
}

export function startLatencyFlusher(db: Db, rec: LatencyRecorder = latencyRecorder, everyMs = 10_000) {
  const t = setInterval(() => { void rec.flush(db); }, everyMs);
  t.unref?.();
  return () => clearInterval(t);
}

/** Approximate quantile from a fixed-bound histogram (linear interpolation inside the bucket). */
export function histQuantile(hist: number[], q: number, maxMs: number): number | null {
  const total = hist.reduce((n, v) => n + v, 0);
  if (!total) return null;
  const target = q * total;
  let cum = 0;
  for (let i = 0; i < hist.length; i++) {
    const n = hist[i] ?? 0;
    if (n && cum + n >= target) {
      const lo = i === 0 ? 0 : LATENCY_BOUNDS_MS[i - 1]!;
      const hi = i < LATENCY_BOUNDS_MS.length ? Math.min(LATENCY_BOUNDS_MS[i]!, Math.max(maxMs, lo)) : Math.max(maxMs, lo);
      return Math.round((lo + ((target - cum) / n) * (hi - lo)) * 10) / 10;
    }
    cum += n;
  }
  return Math.round(maxMs * 10) / 10;
}
