import postgres from "postgres";
import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import { sql } from "drizzle-orm";
import * as schema from "./schema.js";

export type Db = PostgresJsDatabase<typeof schema>;
export type Tx = Parameters<Parameters<Db["transaction"]>[0]>[0];

export function createDb(url: string, opts: { max?: number } = {}) {
  const client = postgres(url, { max: opts.max ?? 10, prepare: true, onnotice: () => {} });
  const db = drizzle(client, { schema });
  return { db, client, close: () => client.end({ timeout: 5 }) };
}

export interface TenantContext {
  tenantId: string;
  userId?: string | null;
}

/**
 * Run fn inside a transaction bound to a tenant. RLS policies read app.tenant_id, so every
 * query issued through `tx` is confined to that tenant regardless of the WHERE clauses used.
 */
export async function withTenant<T>(db: Db, ctx: TenantContext, fn: (tx: Tx) => Promise<T>): Promise<T> {
  if (!/^[0-9a-f-]{36}$/i.test(ctx.tenantId)) throw new Error("invalid tenant id");
  return db.transaction(async (tx) => {
    await tx.execute(sql`select set_config('app.tenant_id', ${ctx.tenantId}, true), set_config('app.user_id', ${ctx.userId ?? ""}, true)`);
    return fn(tx);
  });
}

/** Identity-only context (no tenant) – used for login and tenant listing. */
export async function withUser<T>(db: Db, userId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`select set_config('app.user_id', ${userId}, true)`);
    return fn(tx);
  });
}
