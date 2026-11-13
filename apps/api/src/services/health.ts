import { sql } from "drizzle-orm";
import { getDb } from "../db.js";
import { env } from "../env.js";
import { blobStore } from "../lib/blobstore.js";

type Component = { ok: boolean; error?: string };
const timed = async (fn: () => Promise<unknown>, ms = 3000): Promise<Component> => {
  try {
    await Promise.race([fn(), new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))]);
    return { ok: true };
  } catch (e) {
    // error class only — never echo connection strings or hostnames
    return { ok: false, error: (e as Error).name === "Error" ? (e as Error).message.slice(0, 80).replace(/\/\/[^\s]+/g, "//…") : (e as Error).name };
  }
};

/** Required: database (with current schema) + evidence store. Agents are reported but optional (AI can be disabled). */
export async function readiness() {
  const [database, schema, evidenceStore, agents] = await Promise.all([
    timed(() => getDb().execute(sql`select 1`)),
    timed(async () => { const r = await getDb().execute(sql`select to_regclass('public.model_providers') as t`) as unknown as Array<{ t: string | null }>; if (!r[0]?.t) throw new Error("migrations pending"); }),
    timed(() => blobStore.check()),
    timed(async () => { const r = await fetch(`${env.agentsUrl}/healthz`); if (!r.ok) throw new Error(`agents ${r.status}`); }),
  ]);
  return { ok: database.ok && schema.ok && evidenceStore.ok, version: env.version, components: { database, schema, evidenceStore, agents } };
}
