/** Evaluation helpers around a single Investigation Analyst run: model config, waiting, collection. */
import { and, asc, desc, eq } from "drizzle-orm";
import { agentDefinitions, investigationRuns, investigationToolCalls, modelProviders, withTenant, type Db } from "@vigil/db";
import { secretStore } from "../lib/secrets.js";
import type { ModelSpec, Plan } from "./run.js";

/** Point the tenant's Investigation Analyst at the model under test (new definition version, as the governance API does). */
export async function configureInvestigator(db: Db, tenantId: string, model: ModelSpec, limits: Plan["limits"]) {
  await withTenant(db, { tenantId }, async (tx) => {
    const [cur] = await tx.select().from(agentDefinitions).where(eq(agentDefinitions.role, "investigation_analyst")).orderBy(desc(agentDefinitions.version)).limit(1);
    if (!cur) throw new Error("tenant has no investigation_analyst definition");
    let modelProviderId: string | null = null;
    if (model.endpoint || model.price || model.apiKeyEnv) {
      if (model.provider === "scripted") throw new Error("scripted models take no endpoint/price/apiKeyEnv");
      const key = model.apiKeyEnv ? process.env[model.apiKeyEnv] : undefined;
      if (model.apiKeyEnv && !key) throw new Error(`env ${model.apiKeyEnv} is not set`);
      const [p] = await tx.insert(modelProviders).values({
        tenantId, name: `eval-${model.id}`, kind: model.provider, baseUrl: model.endpoint ?? null,
        secretRef: key ? await secretStore.put(tenantId, key) : null,
        hosting: model.hosting ?? (model.provider === "openai_compatible" ? "customer_hosted" : "external"),
        priceInputPerMtok: (model.price?.input ?? 0).toFixed(4), priceOutputPerMtok: (model.price?.output ?? 0).toFixed(4),
      }).returning({ id: modelProviders.id });
      modelProviderId = p!.id;
    }
    await tx.insert(agentDefinitions).values({
      tenantId, role: cur.role, version: cur.version + 1, promptVersion: cur.promptVersion, modelProvider: model.provider, modelProviderId, modelName: model.name,
      allowedTools: cur.allowedTools, maxSteps: limits.maxSteps, timeoutSeconds: limits.timeoutSeconds, tokenBudget: limits.tokenBudget,
      costBudgetUsd: limits.costBudgetUsd.toFixed(4), enabled: true,
    });
  });
}

/** Poll until the run leaves "running". Returns false on deadline. */
export async function waitForRun(db: Db, tenantId: string, runId: string, deadlineMs: number, pollMs = 1500): Promise<boolean> {
  const until = Date.now() + deadlineMs;
  while (Date.now() < until) {
    const [r] = await withTenant(db, { tenantId }, (tx) => tx.select({ status: investigationRuns.status }).from(investigationRuns).where(eq(investigationRuns.id, runId)));
    if (r && r.status !== "running" && r.status !== "queued") return true;
    await new Promise((res) => setTimeout(res, pollMs));
  }
  return false;
}

export async function collectRun(db: Db, tenantId: string, runId: string) {
  return withTenant(db, { tenantId }, async (tx) => {
    const [r] = await tx.select().from(investigationRuns).where(eq(investigationRuns.id, runId));
    if (!r) throw new Error(`run ${runId} vanished`);
    const calls = await tx.select().from(investigationToolCalls).where(and(eq(investigationToolCalls.runId, runId))).orderBy(asc(investigationToolCalls.seq));
    return {
      run: {
        id: r.id, status: r.status, error: r.error, promptVersion: r.promptVersion, masking: r.masking, maskStats: r.maskStats,
        modelProvider: r.modelProvider, modelName: r.modelName, steps: r.steps, inputTokens: r.inputTokens, outputTokens: r.outputTokens,
        costUsd: Number(r.costUsd), output: r.output as Record<string, any> | null, validationErrors: (r.validationErrors as Array<{ path: string; code?: string; problem?: string; message?: string }> | null) ?? null,
      },
      toolCalls: calls.map((c) => ({ seq: c.seq, tool: c.tool, allowed: c.allowed, denialReason: c.denialReason, args: c.arguments, returnedEventIds: c.returnedEventIds as string[], durationMs: c.durationMs })),
    };
  });
}
