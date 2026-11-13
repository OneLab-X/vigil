import { z } from "zod";
import { and, eq, sql } from "drizzle-orm";
import { agentDefinitions, modelProviders, tenants } from "@vigil/db";
import { IdParam, newApp, route, tenantTx } from "../lib/context.js";
import { badRequest, conflict, notFound } from "../lib/errors.js";
import { secretStore } from "../lib/secrets.js";
import { assertSafeModelEndpoint, DATA_POLICIES, getDataPolicy, getMaskingDefault, probeProvider, type DataPolicy } from "../services/models.js";

export const modelRoutes = newApp();

type Row = typeof modelProviders.$inferSelect;
/** API keys are write-only: responses say whether one is stored, never what it is. */
const publicProvider = (r: Row) => ({ ...r, secretRef: undefined, hasApiKey: !!r.secretRef, priceInputPerMtok: Number(r.priceInputPerMtok), priceOutputPerMtok: Number(r.priceOutputPerMtok) });

const Kind = z.enum(["anthropic", "openai", "gemini", "openai_compatible"]);
const Hosting = z.enum(["external", "customer_hosted"]);
const Base = z.object({
  name: z.string().trim().min(1).max(80),
  kind: Kind,
  baseUrl: z.string().max(500).nullish(),
  apiKey: z.string().min(1).max(4000).nullish(),
  hosting: Hosting,
  timeoutSeconds: z.number().int().min(5).max(1800).default(120),
  priceInputPerMtok: z.number().min(0).max(1000),
  priceOutputPerMtok: z.number().min(0).max(1000),
  enabled: z.boolean().default(true),
});

function validate(b: { kind: string; baseUrl?: string | null; hosting: string; priceInputPerMtok: number; priceOutputPerMtok: number }) {
  if (b.kind === "openai_compatible" && !b.baseUrl) throw badRequest("an OpenAI-compatible provider needs a base URL (e.g. http://host.docker.internal:11434/v1 for Ollama)");
  if (b.hosting === "external" && (b.priceInputPerMtok <= 0 || b.priceOutputPerMtok <= 0)) throw badRequest("external providers need prices > 0 so the per-run cost budget can be enforced");
  return b.baseUrl ? assertSafeModelEndpoint(b.baseUrl) : null;
}

route(modelRoutes, "get", "/model-providers", { summary: "Configured AI model providers (keys never returned)", tags: ["ai"] }, async (c) =>
  tenantTx(c, "read", async (tx, a) => {
    const rows = await tx.select().from(modelProviders).orderBy(modelProviders.name);
    return c.json({ items: rows.map(publicProvider), dataPolicy: await getDataPolicy(tx, a.tenantId), masking: await getMaskingDefault(tx, a.tenantId) });
  }));

route(modelRoutes, "post", "/model-providers", { summary: "Add an AI model provider", tags: ["ai"], body: Base }, async (c, { body }) =>
  tenantTx(c, "agents:write", async (tx, a) => {
    const baseUrl = validate(body);
    const [dupe] = await tx.select({ id: modelProviders.id }).from(modelProviders).where(eq(modelProviders.name, body.name));
    if (dupe) throw conflict("a provider with that name already exists");
    const secretRef = body.apiKey ? await secretStore.put(a.tenantId, body.apiKey) : null;
    const [row] = await tx.insert(modelProviders).values({ tenantId: a.tenantId, name: body.name, kind: body.kind, baseUrl, secretRef, hosting: body.hosting,
      timeoutSeconds: body.timeoutSeconds, priceInputPerMtok: body.priceInputPerMtok.toFixed(4), priceOutputPerMtok: body.priceOutputPerMtok.toFixed(4), enabled: body.enabled, createdBy: a.user.id }).returning();
    await a.audit({ action: "ai.provider_created", targetType: "model_provider", targetId: row!.id, details: { name: body.name, kind: body.kind, hosting: body.hosting, baseUrl, apiKey: body.apiKey ? "[set]" : null } });
    return c.json({ provider: publicProvider(row!) });
  }));

route(modelRoutes, "patch", "/model-providers/{id}", { summary: "Update an AI model provider (send apiKey to rotate, null to remove)", tags: ["ai"], params: IdParam, body: Base.partial() }, async (c, { params, body }) =>
  tenantTx(c, "agents:write", async (tx, a) => {
    const [cur] = await tx.select().from(modelProviders).where(eq(modelProviders.id, params.id));
    if (!cur) throw notFound("model provider");
    const merged = { kind: body.kind ?? cur.kind, baseUrl: body.baseUrl === undefined ? cur.baseUrl : body.baseUrl, hosting: body.hosting ?? cur.hosting,
      priceInputPerMtok: body.priceInputPerMtok ?? Number(cur.priceInputPerMtok), priceOutputPerMtok: body.priceOutputPerMtok ?? Number(cur.priceOutputPerMtok) };
    const baseUrl = validate(merged);
    let secretRef = cur.secretRef;
    if (body.apiKey !== undefined) {
      if (cur.secretRef) await secretStore.delete(a.tenantId, cur.secretRef).catch(() => {});
      secretRef = body.apiKey ? await secretStore.put(a.tenantId, body.apiKey) : null;
    }
    const [row] = await tx.update(modelProviders).set({ name: body.name ?? cur.name, kind: merged.kind, baseUrl, secretRef, hosting: merged.hosting, timeoutSeconds: body.timeoutSeconds ?? cur.timeoutSeconds,
      priceInputPerMtok: merged.priceInputPerMtok.toFixed(4), priceOutputPerMtok: merged.priceOutputPerMtok.toFixed(4), enabled: body.enabled ?? cur.enabled, updatedAt: new Date() })
      .where(eq(modelProviders.id, cur.id)).returning();
    await a.audit({ action: "ai.provider_updated", targetType: "model_provider", targetId: cur.id, details: { ...body, apiKey: body.apiKey === undefined ? undefined : body.apiKey ? "[rotated]" : "[removed]" } });
    return c.json({ provider: publicProvider(row!) });
  }));

route(modelRoutes, "delete", "/model-providers/{id}", { summary: "Delete an AI model provider not used by any agent version", tags: ["ai"], params: IdParam }, async (c, { params }) =>
  tenantTx(c, "agents:write", async (tx, a) => {
    const [cur] = await tx.select().from(modelProviders).where(eq(modelProviders.id, params.id));
    if (!cur) throw notFound("model provider");
    const [used] = await tx.select({ n: sql<number>`count(*)::int` }).from(agentDefinitions).where(eq(agentDefinitions.modelProviderId, cur.id));
    if (used!.n > 0) throw conflict("agent versions reference this provider; disable it instead (history must stay traceable)");
    await tx.delete(modelProviders).where(eq(modelProviders.id, cur.id));
    if (cur.secretRef) await secretStore.delete(a.tenantId, cur.secretRef).catch(() => {});
    await a.audit({ action: "ai.provider_deleted", targetType: "model_provider", targetId: cur.id, details: { name: cur.name } });
    return c.json({ ok: true });
  }));

route(modelRoutes, "post", "/model-providers/{id}/test", { summary: "Probe a provider from the agent worker (lists the model / tiny request)", tags: ["ai"], params: IdParam,
  body: z.object({ model: z.string().min(1).max(128) }) }, async (c, { params, body }) => {
  const cfg = await tenantTx(c, "agents:write", async (tx, a) => {
    const [p] = await tx.select().from(modelProviders).where(eq(modelProviders.id, params.id));
    if (!p) throw notFound("model provider");
    return { provider: p.kind, name: body.model, endpoint: p.baseUrl ?? undefined, timeout_seconds: Math.min(p.timeoutSeconds, 60), hosting: p.hosting as "external" | "customer_hosted",
      price_input_per_mtok: Number(p.priceInputPerMtok), price_output_per_mtok: Number(p.priceOutputPerMtok), api_key: p.secretRef ? await secretStore.get(a.tenantId, p.secretRef) : undefined };
  });
  return c.json(await probeProvider(cfg));
});

route(modelRoutes, "put", "/settings/ai", { summary: "Set the organization's AI data policy and default masking", tags: ["ai"],
  body: z.object({ dataPolicy: z.enum(DATA_POLICIES as [DataPolicy, ...DataPolicy[]]).optional(), masking: z.enum(["on", "off"]).optional() })
    .refine((b) => b.dataPolicy || b.masking, { message: "nothing to change" }) }, async (c, { body }) =>
  tenantTx(c, "agents:write", async (tx, a) => {
    const before = { dataPolicy: await getDataPolicy(tx, a.tenantId), masking: await getMaskingDefault(tx, a.tenantId) };
    const patch: Record<string, string> = {};
    if (body.dataPolicy) patch.aiDataPolicy = body.dataPolicy;
    if (body.masking) patch.aiMasking = body.masking;
    await tx.update(tenants).set({ settings: sql`${tenants.settings} || ${JSON.stringify(patch)}::jsonb` }).where(and(eq(tenants.id, a.tenantId)));
    const after = { dataPolicy: body.dataPolicy ?? before.dataPolicy, masking: body.masking ?? before.masking };
    if (body.dataPolicy) await a.audit({ action: "ai.data_policy_changed", targetType: "tenant", targetId: a.tenantId, details: { before: before.dataPolicy, after: after.dataPolicy } });
    if (body.masking) await a.audit({ action: "ai.masking_default_changed", targetType: "tenant", targetId: a.tenantId, details: { before: before.masking, after: after.masking } });
    return c.json(after);
  }));
