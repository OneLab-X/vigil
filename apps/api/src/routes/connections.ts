import { z } from "zod";
import { and, desc, eq, ne } from "drizzle-orm";
import { describeConnector, encodeStoredSecrets, getConnector, listConnectors, splitLegacyBody } from "@vigil/core";
import { cloudConnections, ingestionCheckpoints, ingestionJobs, logSources } from "@vigil/db";
import { IdParam, newApp, Pagination, requirePerm, route, tenantTx } from "../lib/context.js";
import { ApiError, badRequest, conflict, notFound } from "../lib/errors.js";
import { secretStore } from "../lib/secrets.js";
import { pgQueue } from "../lib/queue.js";
import { connectorFor, connectionConfig, connectorRuntime } from "../services/connectors.js";
import { ensureCloudAccount } from "../services/ingestion.js";

export const connectionRoutes = newApp();

route(connectionRoutes, "get", "/connectors", { summary: "Connector registry: available connector types, their config fields and auth modes (no secrets)", tags: ["connections"] }, async (c) => {
  requirePerm(c, "read");
  const rt = connectorRuntime();
  return c.json({ items: listConnectors().map((d) => describeConnector(d, rt)) });
});

/**
 * `{ provider, displayName, config, credentials? }`, validated by the provider's registry definition.
 * Backward compatible: the pre-registry flat GCP/AWS shape (`{ provider, displayName, projectId, … }`) is accepted
 * and split into config/credentials using the definition's credential schema.
 */
const CreateConnection = z.object({
  provider: z.string().min(1).max(32),
  displayName: z.string().min(1).max(200),
  config: z.record(z.string(), z.unknown()).optional(),
  credentials: z.record(z.string(), z.unknown()).optional(),
}).catchall(z.unknown());

type ConnRow = typeof cloudConnections.$inferSelect;
const publicConn = (r: ConnRow) => {
  const def = getConnector(r.provider);
  const cfg = def ? connectionConfig(def, r) : r.config;
  let accountRef: string | null = null;
  try { accountRef = def ? def.accountRefOf(cfg) : null; } catch { /* legacy/malformed config */ }
  return { ...r, secretRef: r.secretRef ? "[stored]" : null, kind: def?.kind ?? null, connectorName: def?.displayName ?? r.provider, accountRef, authMode: def ? def.authModeOf(cfg) : null };
};

route(connectionRoutes, "post", "/cloud-connections", { summary: "Add a connection (any registered connector: GET /connectors)", tags: ["connections"], body: CreateConnection }, async (c, { body }) =>
  tenantTx(c, "connections:write", async (tx, a) => {
    const def = getConnector(body.provider);
    if (!def) throw badRequest(`unknown provider "${body.provider.slice(0, 32)}"`);
    const { provider: _p, displayName, config: cfgIn, credentials: credIn, ...flat } = body;
    const split = cfgIn ? { config: cfgIn, credentials: credIn } : splitLegacyBody(def, flat);
    const cfg = def.configSchema.safeParse(split.config);
    if (!cfg.success) throw new ApiError(400, "validation_error", "request validation failed", z.treeifyError(cfg.error));
    let creds: unknown;
    if (split.credentials !== undefined) {
      if (!def.credentialSchema) throw badRequest(`${def.id} connections take no credentials`);
      const parsed = def.credentialSchema.safeParse(split.credentials);
      // Never echo credential values back: report only which fields failed.
      if (!parsed.success) throw new ApiError(400, "validation_error", "invalid credentials", { fields: [...new Set(parsed.error.issues.map((i) => String(i.path[0] ?? "")))] });
      creds = parsed.data;
    }
    const rt = connectorRuntime();
    const problem = def.validate?.(cfg.data, creds as never, rt);
    if (problem) throw badRequest(problem);
    const accountRef = def.accountRefOf(cfg.data);
    const dupes = await tx.select({ id: cloudConnections.id, displayName: cloudConnections.displayName, config: cloudConnections.config }).from(cloudConnections)
      .where(and(eq(cloudConnections.provider, def.id), ne(cloudConnections.status, "disconnected")));
    const dupe = dupes.find((d) => { try { return def.accountRefOf(connectionConfig(def, d)) === accountRef; } catch { return false; } });
    if (dupe) throw conflict(`an active ${def.displayName} connection for ${accountRef} already exists ("${dupe.displayName}") — use it, or disconnect it first`);
    const toStore = def.prepareSecrets(cfg.data, creds as never);
    const secretRef = toStore ? await secretStore.put(a.tenantId, encodeStoredSecrets(def, toStore)) : null;
    const config = JSON.parse(JSON.stringify(cfg.data)) as Record<string, unknown>;
    const onboarding = def.onboardingInstructions(cfg.data, toStore, rt);
    const [row] = await tx.insert(cloudConnections).values({ tenantId: a.tenantId, provider: def.id, displayName, config, secretRef, createdBy: a.user.id }).returning();
    await ensureCloudAccount(tx, a.tenantId, row!.id, def.id, accountRef);
    await a.audit({ action: "connection.created", targetType: "cloud_connection", targetId: row!.id, details: { provider: def.id, config } });
    return c.json({ connection: publicConn(row!), onboarding }, 200);
  }));

route(connectionRoutes, "get", "/cloud-connections", { summary: "List cloud connections", tags: ["connections"], query: Pagination }, async (c, { query }) =>
  tenantTx(c, "read", async (tx) => {
    const rows = await tx.select().from(cloudConnections).orderBy(desc(cloudConnections.createdAt)).limit(query.limit).offset(query.offset);
    const srcs = await tx.select().from(logSources);
    const cps = await tx.select().from(ingestionCheckpoints);
    return c.json({ items: rows.map((r) => ({ ...publicConn(r), sources: srcs.filter((s) => s.connectionId === r.id).map((s) => ({ ...s, watermark: cps.find((cp) => cp.logSourceId === s.id)?.watermark ?? null })) })) });
  }));

async function loadConn(tx: any, id: string) {
  const [row] = await tx.select().from(cloudConnections).where(eq(cloudConnections.id, id));
  if (!row) throw notFound("connection");
  return row as typeof cloudConnections.$inferSelect;
}

route(connectionRoutes, "post", "/cloud-connections/{id}/test", { summary: "Validate credentials and read-only permissions", tags: ["connections"], params: IdParam }, async (c, { params }) =>
  tenantTx(c, "connections:write", async (tx, a) => {
    const row = await loadConn(tx, params.id);
    const connector = await connectorFor(row);
    const result = await connector.testConnection().catch((e) => ({ ok: false, errors: [(e as Error).message], warnings: [], checks: [], readOnly: true }));
    await tx.update(cloudConnections).set({ lastTestedAt: new Date(), lastTestResult: result as object, status: result.ok ? (result.readOnly ? "healthy" : "degraded") : "error", updatedAt: new Date() }).where(eq(cloudConnections.id, row.id));
    await a.audit({ action: "connection.tested", targetType: "cloud_connection", targetId: row.id, details: { ok: result.ok, readOnly: result.readOnly } });
    return c.json(result);
  }));

route(connectionRoutes, "get", "/cloud-connections/{id}/sources", { summary: "Discover log sources", tags: ["connections"], params: IdParam }, async (c, { params }) =>
  tenantTx(c, "read", async (tx) => {
    const row = await loadConn(tx, params.id);
    const connector = await connectorFor(row);
    let discovered;
    try { discovered = await connector.discoverSources(); }
    catch (e) {
      const def = getConnector(row.provider);
      discovered = def ? def.knownSources(connectionConfig(def, row)).map((s) => ({ ...s, available: false })) : [];
      return c.json({ discovered, error: (e as Error).message.slice(0, 300) });
    }
    const configured = await tx.select().from(logSources).where(eq(logSources.connectionId, row.id));
    return c.json({ discovered, configured });
  }));

const EnableSource = z.object({
  sourceType: z.string().min(2).max(64), name: z.string().min(1).max(200), filter: z.string().max(4000).nullable(),
  enabled: z.boolean().default(true), ingestionMode: z.enum(["poll", "stream"]).default("poll"),
  pollIntervalSeconds: z.number().int().min(60).max(86_400).default(300),
});

route(connectionRoutes, "post", "/cloud-connections/{id}/sources", { summary: "Enable / configure a log source", tags: ["connections"], params: IdParam, body: EnableSource }, async (c, { params, body }) =>
  tenantTx(c, "connections:write", async (tx, a) => {
    const row = await loadConn(tx, params.id);
    if (body.ingestionMode === "stream") throw badRequest("streaming ingestion requires the customer-admin Pub/Sub sink setup; not yet available");
    // The cloud account is shared per (provider, account ref): resolve it by ref, not by connection — another
    // connection to the same project may have been created later and now be linked to it.
    const def = getConnector(row.provider);
    if (!def) throw badRequest(`unknown provider "${row.provider}"`);
    const cloudAccountId = await ensureCloudAccount(tx, a.tenantId, row.id, row.provider, def.accountRefOf(connectionConfig(def, row)));
    const [src] = await tx.insert(logSources).values({ tenantId: a.tenantId, connectionId: row.id, cloudAccountId, ...body })
      .onConflictDoUpdate({ target: [logSources.tenantId, logSources.connectionId, logSources.sourceType, logSources.name], set: { filter: body.filter, enabled: body.enabled, ingestionMode: body.ingestionMode, pollIntervalSeconds: body.pollIntervalSeconds } }).returning();
    await a.audit({ action: "log_source.configured", targetType: "log_source", targetId: src!.id, details: body });
    const streaming = def.sourceSetupInstructions?.(connectionConfig(def, row), { sourceType: body.sourceType, filter: body.filter });
    return c.json({ source: src, streamingSetupForCustomerAdmin: streaming });
  }));

route(connectionRoutes, "delete", "/cloud-connections/{id}", { summary: "Disconnect: revoke stored credentials and stop ingestion (data retained per policy)", tags: ["connections"], params: IdParam }, async (c, { params }) =>
  tenantTx(c, "connections:write", async (tx, a) => {
    const row = await loadConn(tx, params.id);
    if (row.secretRef) await secretStore.delete(a.tenantId, row.secretRef).catch(() => {});
    await tx.update(logSources).set({ enabled: false }).where(eq(logSources.connectionId, row.id));
    await tx.update(cloudConnections).set({ status: "disconnected", secretRef: null, updatedAt: new Date() }).where(eq(cloudConnections.id, row.id));
    await a.audit({ action: "connection.disconnected", targetType: "cloud_connection", targetId: row.id });
    return c.json({ ok: true });
  }));

route(connectionRoutes, "post", "/ingestion/jobs", {
  summary: "Start a historical ingestion job for a log source", tags: ["ingestion"],
  body: z.object({ logSourceId: z.string().uuid(), start: z.string().datetime({ offset: true }), end: z.string().datetime({ offset: true }) }),
}, async (c, { body }) =>
  tenantTx(c, "ingestion:run", async (tx, a) => {
    const start = new Date(body.start), end = new Date(body.end);
    if (!(start < end)) throw badRequest("start must be before end");
    if (end.getTime() - start.getTime() > 90 * 86_400_000) throw badRequest("range may not exceed 90 days per job");
    const [src] = await tx.select().from(logSources).where(eq(logSources.id, body.logSourceId));
    if (!src) throw notFound("log source");
    const [job] = await tx.insert(ingestionJobs).values({ tenantId: a.tenantId, logSourceId: src.id, kind: "historical", rangeStart: start, rangeEnd: end, requestedBy: a.user.id }).returning();
    await pgQueue.enqueue(tx, a.tenantId, "ingest", { jobId: job!.id }, { idempotencyKey: `ingest:${job!.id}` });
    await a.audit({ action: "ingestion.job.requested", targetType: "ingestion_job", targetId: job!.id, details: { start: body.start, end: body.end, source: src.sourceType } });
    return c.json({ job });
  }));

route(connectionRoutes, "get", "/ingestion/jobs", { summary: "List ingestion jobs", tags: ["ingestion"], query: Pagination.extend({ logSourceId: z.string().uuid().optional() }) }, async (c, { query }) =>
  tenantTx(c, "read", async (tx) => {
    const rows = await tx.select().from(ingestionJobs).where(query.logSourceId ? eq(ingestionJobs.logSourceId, query.logSourceId) : undefined).orderBy(desc(ingestionJobs.createdAt)).limit(query.limit).offset(query.offset);
    return c.json({ items: rows });
  }));
