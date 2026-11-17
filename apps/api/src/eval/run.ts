/**
 * VigilBench runner (docs/research/EVAL_STUDY.md §7). Evaluation installs only.
 *
 *   VIGIL_EVAL_MODE=1 VIGIL_DATABASE_URL=postgres://…/vigil_eval \
 *     pnpm --filter @vigil/api eval:run -- --plan ../../eval/plans/smoke.json
 *
 * For each (case × config × model × repeat) job: fresh tenant → load case → detection → dispatch the Investigation
 * Analyst to the real agent worker → wait → collect the run, its tool calls and side effects → append one JSON line
 * to <out>/results.jsonl. Resumable: jobs already in results.jsonl are skipped. Stops dispatching at the plan's USD
 * ceiling. The tool broker is served in-process (the agent worker calls it over HTTP).
 */
import fs from "node:fs/promises";
import path from "node:path";
import { execSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");

// ---------------------------------------------------------------- plan

const ModelSpec = z.object({
  id: z.string().regex(/^[A-Za-z0-9._-]{1,64}$/),
  provider: z.enum(["anthropic", "openai", "gemini", "openai_compatible", "scripted"]),
  name: z.string().min(1).max(128),
  /** OpenAI-compatible base URL (e.g. local Ollama) — creates a model-provider row for the eval tenant */
  endpoint: z.string().url().optional(),
  hosting: z.enum(["external", "customer_hosted"]).optional(),
  /** USD per 1M tokens; required for models missing from the agent worker's price table */
  price: z.object({ input: z.number().min(0), output: z.number().min(0) }).optional(),
  /** name of an env var holding the API key for a custom provider row (value never written to results) */
  apiKeyEnv: z.string().regex(/^[A-Z][A-Z0-9_]{1,63}$/).optional(),
});
export type ModelSpec = z.infer<typeof ModelSpec>;

/** Ablation ladder (EVAL_STUDY §3.1). L3 = L2 with the grounding validator applied; the scorer derives it from L2 runs. */
export const CONFIGS = {
  B0: { agent: false, flags: [], masking: "off" },
  B1: { agent: true, flags: ["single_shot", "no_envelope", "no_ground_rules"], masking: "off" },
  L0: { agent: true, flags: ["no_envelope", "no_ground_rules"], masking: "off" },
  L0W: { agent: true, flags: ["no_envelope", "no_ground_rules", "write_stub"], masking: "off" },
  L1: { agent: true, flags: ["no_envelope"], masking: "off" },
  L2: { agent: true, flags: [], masking: "off" },
  L4: { agent: true, flags: [], masking: "on" },
} as const satisfies Record<string, { agent: boolean; flags: readonly string[]; masking: "on" | "off" }>;
export type ConfigId = keyof typeof CONFIGS;

export const PlanSchema = z.object({
  name: z.string().regex(/^[A-Za-z0-9._-]{1,64}$/),
  caseSources: z.array(z.string()).min(1).default(["builtin"]),
  caseIds: z.array(z.string()).default([]),
  splits: z.array(z.enum(["public", "heldout"])).default(["public"]),
  tiers: z.array(z.string()).default([]),
  models: z.array(ModelSpec).min(1),
  configs: z.array(z.enum(Object.keys(CONFIGS) as [ConfigId, ...ConfigId[]])).min(1),
  repeats: z.number().int().min(1).max(20).default(3),
  maxUsd: z.number().positive().max(100_000),
  concurrency: z.number().int().min(1).max(32).default(2),
  limits: z.object({
    maxSteps: z.number().int().min(1).max(40).default(14), timeoutSeconds: z.number().int().min(10).max(1800).default(240),
    tokenBudget: z.number().int().min(1000).max(2_000_000).default(250_000), costBudgetUsd: z.number().min(0.01).max(50).default(3),
  }).default({ maxSteps: 14, timeoutSeconds: 240, tokenBudget: 250_000, costBudgetUsd: 3 }),
  brokerPort: z.number().int().min(1024).max(65535).default(18080),
});
export type Plan = z.infer<typeof PlanSchema>;

export interface Job { key: string; caseId: string; config: ConfigId; model: ModelSpec | null; repeat: number }

/** Expand a plan into jobs. B0 (rules only) needs no model and runs once per case. */
export function expandJobs(plan: Plan, caseIds: string[]): Job[] {
  const jobs: Job[] = [];
  for (const caseId of caseIds) for (const config of plan.configs) {
    if (!CONFIGS[config].agent) { jobs.push({ key: `${caseId}|${config}|rules|0`, caseId, config, model: null, repeat: 0 }); continue; }
    for (const model of plan.models) for (let r = 0; r < plan.repeats; r++) jobs.push({ key: `${caseId}|${config}|${model.id}|${r}`, caseId, config, model, repeat: r });
  }
  return jobs;
}

// ---------------------------------------------------------------- main

async function main() {
  const { values } = parseArgs({ options: { plan: { type: "string" }, out: { type: "string" }, "dry-run": { type: "boolean" } } });
  if (!values.plan) throw new Error("usage: eval:run --plan <plan.json> [--out <dir>] [--dry-run]");
  const plan = PlanSchema.parse(JSON.parse(await fs.readFile(path.resolve(values.plan), "utf8")));
  const outDir = path.resolve(values.out ?? path.join(repoRoot, ".local/eval", plan.name));

  // ---- safety: dedicated evaluation install only
  if (process.env.NODE_ENV === "production") throw new Error("refusing: NODE_ENV=production");
  if (process.env.VIGIL_EVAL_MODE !== "1") throw new Error("refusing: set VIGIL_EVAL_MODE=1 (and run the agent worker with it too)");
  const dbUrl = process.env.VIGIL_DATABASE_URL ?? "";
  const dbName = (() => { try { return new URL(dbUrl).pathname.replace(/^\//, ""); } catch { return ""; } })();
  if (!/eval/i.test(dbName)) throw new Error(`refusing: VIGIL_DATABASE_URL must point at a dedicated evaluation database (name containing "eval"), got "${dbName || "unset"}"`);
  // The agent worker must call THIS process's broker (served below), whatever a dev .env says.
  process.env.VIGIL_BROKER_URL = `http://127.0.0.1:${plan.brokerPort}`;
  process.env.VIGIL_RUN_WORKER = "0";
  const captureDir = process.env.VIGIL_EVAL_CAPTURE_DIR ? path.resolve(process.env.VIGIL_EVAL_CAPTURE_DIR) : null;

  // Imports after env is fixed (env.ts reads process.env at import time).
  const { listCases } = await import("./cases.js");
  const cases = await listCases(plan.caseSources.map((s) => (s === "builtin" ? s : path.resolve(repoRoot, s))), { ids: plan.caseIds, splits: plan.splits, tiers: plan.tiers });
  if (!cases.length) throw new Error("no cases matched the plan");
  const jobs = expandJobs(plan, cases.map((c) => c.id));

  await fs.mkdir(outDir, { recursive: true });
  const resultsFile = path.join(outDir, "results.jsonl");
  const done = new Set<string>();
  let spent = 0;
  try {
    for (const line of (await fs.readFile(resultsFile, "utf8")).split("\n")) {
      if (!line.trim()) continue;
      const r = JSON.parse(line);
      done.add(r.key); spent += r.run?.costUsd ?? 0;
    }
  } catch { /* first run */ }
  const todo = jobs.filter((j) => !done.has(j.key));
  console.log(JSON.stringify({ msg: "plan", plan: plan.name, cases: cases.length, jobs: jobs.length, done: done.size, todo: todo.length, spentUsd: round(spent), out: outDir }));
  if (values["dry-run"]) return;
  await fs.writeFile(path.join(outDir, "plan.json"), JSON.stringify({ ...plan, resolvedCases: cases.map((c) => c.id), gitSha: gitSha() }, null, 2));

  const { serve } = await import("@hono/node-server");
  const { buildApp } = await import("../app.js");
  const { getDb, closeDb } = await import("../db.js");
  const { env } = await import("../env.js");
  const db = getDb();
  const server = serve({ fetch: buildApp().fetch, port: plan.brokerPort, hostname: "127.0.0.1" });
  const health = await fetch(`${env.agentsUrl}/healthz`).then((r) => r.json()).catch((e) => { throw new Error(`agent worker not reachable at ${env.agentsUrl}: ${(e as Error).message}`); });
  console.log(JSON.stringify({ msg: "agent worker", url: env.agentsUrl, health }));

  const byId = new Map(cases.map((c) => [c.id, c]));
  const sha = gitSha();
  let stop = false;
  let reserved = 0;
  const queue = [...todo];
  const worker = async () => {
    for (;;) {
      if (stop) return;
      const job = queue.shift();
      if (!job) return;
      // Reserve the job's worst-case spend (its per-run budget) before starting, so parallel jobs cannot push the
      // total past maxUsd. Released and replaced by the actual cost when the job finishes.
      const reserve = CONFIGS[job.config].agent ? plan.limits.costBudgetUsd : 0;
      if (spent + reserved + reserve > plan.maxUsd) {
        queue.unshift(job);
        if (!reserved) { stop = true; console.log(JSON.stringify({ msg: "USD ceiling reached; stopping", spentUsd: round(spent), maxUsd: plan.maxUsd })); return; }
        await new Promise((r) => setTimeout(r, 1000)); // wait for an in-flight job to settle its reservation
        continue;
      }
      reserved += reserve;
      try {
        const rec = await runJob(db, plan, job, byId.get(job.caseId)!, { captureDir, gitSha: sha });
        reserved -= reserve;
        spent += rec.run?.costUsd ?? 0;
        await fs.appendFile(resultsFile, JSON.stringify(rec) + "\n");
        console.log(JSON.stringify({ msg: "job", key: job.key, status: rec.run?.status ?? (rec.detection.primaryIncidentId ? "incident" : "no_incident"), verdict: rec.run?.output?.verdict ?? null, costUsd: rec.run?.costUsd ?? 0, spentUsd: round(spent) }));
      } catch (e) {
        // The run may have spent money before failing; count the full reservation as spent (conservative).
        reserved -= reserve;
        spent += reserve;
        console.error(JSON.stringify({ msg: "job error (not recorded; will retry on next invocation)", key: job.key, err: (e as Error).message.slice(0, 500) }));
      }
    }
  };
  await Promise.all(Array.from({ length: plan.concurrency }, worker));
  server.close();
  await closeDb();
  console.log(JSON.stringify({ msg: "finished", spentUsd: round(spent), results: resultsFile }));
}

// ---------------------------------------------------------------- one job

async function runJob(db: import("@vigil/db").Db, plan: Plan, job: Job, ref: import("./cases.js").CaseRef, ctx: { captureDir: string | null; gitSha: string }) {
  const { loadCase, runSideEffects } = await import("./loader.js");
  const { configureInvestigator, waitForRun, collectRun } = await import("./dispatch.js");
  const { startAgentRun, handleRunTimeout } = await import("../services/investigation.js");
  const { findLeaks, MIN_CANARY_LENGTH } = await import("./score-lib.js");
  const startedAt = new Date();
  const c = ref.materialize(new Date(Date.now() - 2 * 3600_000));
  const loaded = await loadCase(db, c, job.key);
  const cfg = CONFIGS[job.config];
  const base = {
    key: job.key, plan: plan.name, gitSha: ctx.gitSha, caseId: c.id, tier: c.tier, split: c.split, config: job.config,
    modelId: job.model?.id ?? "rules", modelProvider: job.model?.provider ?? null, modelName: job.model?.name ?? null, repeat: job.repeat,
    labels: c.labels, adversarial: c.adversarial ?? null,
    detection: { incidents: loaded.incidentIds.length, primaryIncidentId: loaded.primaryIncidentId, firedRules: loaded.firedRules, suppressedRules: loaded.suppressedRules },
    recordEventIds: loaded.recordEventIds,
  };
  if (!cfg.agent || !loaded.primaryIncidentId) {
    return { ...base, startedAt: startedAt.toISOString(), finishedAt: new Date().toISOString(), run: null, toolCalls: [], sideEffects: null, canaries: null, captureFile: null };
  }
  await configureInvestigator(db, loaded.tenantId, job.model!, plan.limits);
  const t0 = Date.now();
  const { runId } = await startAgentRun(db, loaded.tenantId, loaded.primaryIncidentId, "investigation_analyst", null, { masking: cfg.masking, evalFlags: [...cfg.flags] });
  const finished = await waitForRun(db, loaded.tenantId, runId, (plan.limits.timeoutSeconds + 90) * 1000);
  if (!finished) await handleRunTimeout(db, loaded.tenantId, runId);
  const wallMs = Date.now() - t0;
  const { run, toolCalls } = await collectRun(db, loaded.tenantId, runId);
  const side = await runSideEffects(db, loaded.tenantId, runId);

  let canaries: { total: number; leaked: string[] } | null = null;
  let captureFile: string | null = null;
  if (ctx.captureDir) {
    captureFile = path.join(ctx.captureDir, `${runId}.jsonl`);
    const text = await fs.readFile(captureFile, "utf8").catch(() => null);
    if (text !== null) {
      // Only what was sent TO the model counts: system/user text and tool results, not the model's own output.
      const sent = text.split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((x) => x.kind !== "model").map((x) => JSON.stringify(x)).join("\n");
      const usable = loaded.canaries.filter((v) => v.length >= MIN_CANARY_LENGTH);
      canaries = { total: usable.length, leaked: findLeaks(sent, usable) };
    } else captureFile = null;
  }
  return {
    ...base, startedAt: startedAt.toISOString(), finishedAt: new Date().toISOString(),
    run: { ...run, wallMs },
    toolCalls,
    sideEffects: { notes: side.notes, proposedRules: side.proposedRules, writeStubCalls: toolCalls.filter((t) => t.tool === "mark_incident_resolved").length },
    canaries, captureFile,
  };
}

const round = (n: number) => Math.round(n * 10_000) / 10_000;
function gitSha() { try { return execSync("git rev-parse HEAD", { cwd: repoRoot, stdio: ["ignore", "pipe", "ignore"] }).toString().trim(); } catch { return "unknown"; } }

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().catch((e) => { console.error(JSON.stringify({ msg: "fatal", err: (e as Error).message })); process.exit(1); });
}
