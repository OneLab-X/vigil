import { z } from "zod";
import { newApp, requirePerm, route, tenantTx } from "../lib/context.js";
import { env } from "../env.js";
import { componentHealth, databaseSize, tenantOverview, WINDOWS, type OpsWindow } from "../services/operations.js";

export const operationsRoutes = newApp();

const OverviewQuery = z.object({
  window: z.enum(Object.keys(WINDOWS) as [OpsWindow, ...OpsWindow[]]).default("24h"),
  lagThresholdMinutes: z.coerce.number().int().min(5).max(1440).optional(),
});

route(operationsRoutes, "get", "/operations/overview", {
  summary: "System health for the active tenant: components, ingestion lag, queue depth, failures, API latency, cost per investigation, storage",
  tags: ["operations"], query: OverviewQuery,
}, async (c, { query }) => {
  requirePerm(c, "operations:read"); // check before probing dependencies
  const t0 = performance.now();
  const lag = query.lagThresholdMinutes ?? env.opsLagThresholdMinutes;
  const [components, dbSize, data] = await Promise.all([
    componentHealth(),
    databaseSize(),
    tenantTx(c, "operations:read", (tx, a) => tenantOverview(tx, a.tenantId, query.window, lag)),
  ]);
  return c.json({
    generatedAt: new Date().toISOString(), window: query.window,
    components: [...components, data.worker],
    ingestion: data.ingestion, queue: data.queue, failures: data.failures, latency: data.latency, cost: data.cost,
    storage: { ...data.storage, databaseBytes: dbSize.bytes, databaseNote: dbSize.note },
    queryMs: Math.round(performance.now() - t0),
  });
});
