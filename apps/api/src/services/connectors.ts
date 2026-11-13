import { and, eq } from "drizzle-orm";
import { decodeStoredSecrets, requireConnector, type CheckpointStore, type CloudConnector, type ConnectorDefinition, type ConnectorRuntime } from "@vigil/core";
import { cloudConnections, ingestionCheckpoints, type Tx } from "@vigil/db";
import { secretStore } from "../lib/secrets.js";
import { env } from "../env.js";

type ConnRow = typeof cloudConnections.$inferSelect;

/** DB-backed checkpoint store bound to the current tenant transaction. */
export function checkpointStore(tx: Tx, tenantId: string): CheckpointStore {
  return {
    async get(sourceId) {
      const [r] = await tx.select().from(ingestionCheckpoints).where(and(eq(ingestionCheckpoints.tenantId, tenantId), eq(ingestionCheckpoints.logSourceId, sourceId))).limit(1);
      return r ? { watermark: r.watermark?.toISOString() ?? null, pageToken: r.pageToken } : null;
    },
    async save(sourceId, cp) {
      await tx.insert(ingestionCheckpoints).values({ tenantId, logSourceId: sourceId, watermark: cp.watermark ? new Date(cp.watermark) : null, pageToken: cp.pageToken, updatedAt: new Date() })
        .onConflictDoUpdate({ target: [ingestionCheckpoints.tenantId, ingestionCheckpoints.logSourceId], set: { watermark: cp.watermark ? new Date(cp.watermark) : null, pageToken: cp.pageToken, updatedAt: new Date() } });
    },
  };
}

/** Test seam: lets integration tests inject a fake connector without touching cloud APIs. */
let override: ((row: ConnRow) => CloudConnector) | null = null;
export function setConnectorOverride(f: typeof override) { override = f; }

/** Test seam: route real connector HTTP through a fake fetch (recorded fixtures, no live calls). */
let fetchOverride: typeof fetch | undefined;
export function setConnectorFetch(f: typeof fetch | undefined) { fetchOverride = f; }

/** Process-level runtime facts handed to connector definitions. Never tenant-controlled. */
export function connectorRuntime(): ConnectorRuntime {
  return { production: env.nodeEnv === "production", env: process.env, fetch: fetchOverride };
}

/** Stored config parsed through the definition (defaults applied); falls back to the raw row for legacy shapes. */
export function connectionConfig(def: ConnectorDefinition, row: Pick<ConnRow, "config">): any {
  const parsed = def.configSchema.safeParse(row.config);
  return parsed.success ? parsed.data : row.config;
}

export async function connectorFor(row: ConnRow, cps?: CheckpointStore): Promise<CloudConnector> {
  if (override) return override(row);
  const def = requireConnector(row.provider);
  const secrets = row.secretRef ? decodeStoredSecrets(def, await secretStore.get(row.tenantId, row.secretRef)) : null;
  return def.create(connectionConfig(def, row), secrets, cps, connectorRuntime());
}
