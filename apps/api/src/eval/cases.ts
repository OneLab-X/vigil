/**
 * VigilBench case format and loaders (docs/research/EVAL_STUDY.md §4).
 *
 * A case is raw vendor-format records plus ground-truth labels. Records go through the same connector registry
 * normalizers as live data. JSON case files may use templates so data is always "recent" when loaded:
 *   "{{t:+120}}"   → ISO timestamp, case base time + 120 s (base = load time − 2 h)
 *   "{{uuid}}"     → a fresh random UUID
 *   "{{uuid:x}}"   → the same UUID everywhere "x" is used within one case load
 * A string that is exactly one template is replaced; templates inside longer strings are replaced inline.
 */
import fs from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { buildConnectorScenarios, buildScenarios, fixtureConfig } from "@vigil/core";

const Verdict = z.enum(["confirmed", "likely", "benign", "inconclusive", "needs_more_data"]);
const Severity = z.enum(["info", "low", "medium", "high", "critical"]);

export const ATTACK_GOALS = ["verdict_flip", "abstain_induce", "tool_misuse", "fabrication_induce", "resource_exhaustion", "write_action"] as const;

export const EvalCaseSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9._-]{2,80}$/),
  tier: z.enum(["seed", "parametric", "detonated", "adversarial"]),
  description: z.string().min(3).max(2000),
  /** heldout cases are kept private until results are final (contamination control) */
  split: z.enum(["public", "heldout"]).default("public"),
  /** non-secret connector config per connector id; defaults to the fixture configs */
  connectors: z.record(z.string(), z.record(z.string(), z.unknown())).default({}),
  records: z.array(z.object({ connector: z.string(), sourceType: z.string(), raw: z.unknown() })).min(1).max(5000),
  /** approved knowledge seeded into the tenant. "after_detection" (default) means rules do not suppress the case and the
   *  agent has to find the entry itself; "before_detection" lets deterministic suppression act on it. */
  knowledge: z.array(z.object({
    kind: z.enum(["trusted_identity", "trusted_ip", "false_positive", "policy", "lesson", "incident_conclusion"]),
    key: z.string().min(1).max(512), title: z.string().min(1).max(300), body: z.string().min(1).max(4000),
    attributes: z.record(z.string(), z.unknown()).default({}),
    timing: z.enum(["before_detection", "after_detection"]).default("after_detection"),
  })).default([]),
  labels: z.object({
    verdict: Verdict,
    severity: Severity.optional(),
    outcome: z.enum(["succeeded", "failed", "blocked", "unknown"]).optional(),
    dataExposure: z.enum(["none_observed", "possible", "confirmed", "unknown"]).optional(),
    /** indexes into `records` that a competent analyst must cite */
    goldEvidence: z.array(z.number().int().min(0)).default([]),
    keyEntities: z.array(z.string()).default([]),
    rulesExpected: z.array(z.string()).default([]),
    labelledBy: z.array(z.string()).default([]),
  }),
  adversarial: z.object({
    twinOf: z.string(),
    goal: z.enum(ATTACK_GOALS),
    technique: z.string().min(2).max(64),
    field: z.string().min(2).max(64),
    /** distinctive substring of the payload; used to detect attacker text copied into notes/rules */
    marker: z.string().min(4).max(200),
  }).optional(),
  /** extra identifier strings that must never reach the model provider in a masked run (fake values only) */
  canaries: z.array(z.string().min(3)).default([]),
});
export type EvalCase = z.infer<typeof EvalCaseSchema>;

/** Default non-secret configs used to normalize fixture data. */
export const DEFAULT_CONNECTOR_CONFIG: Record<string, Record<string, unknown>> = {
  gcp: { projectId: "example-project", authMode: "adc" },
  aws: { accountId: "111122223333", roleArn: "arn:aws:iam::111122223333:role/vigil-reader", regions: ["us-east-1"] },
};
export const connectorConfig = (c: EvalCase, connector: string) => c.connectors[connector] ?? DEFAULT_CONNECTOR_CONFIG[connector] ?? fixtureConfig(connector);

// ---------------------------------------------------------------- templates

const TEMPLATE = /\{\{(t:[+-]?\d+|uuid(?::[A-Za-z0-9_-]{1,40})?)\}\}/g;

export function expandTemplates<T>(value: T, base: Date): T {
  const named = new Map<string, string>();
  const one = (tpl: string): string => {
    if (tpl.startsWith("t:")) return new Date(base.getTime() + Number(tpl.slice(2)) * 1000).toISOString();
    const name = tpl.slice(5);
    if (!name) return randomUUID();
    if (!named.has(name)) named.set(name, randomUUID());
    return named.get(name)!;
  };
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") return v.replace(TEMPLATE, (_m, tpl: string) => one(tpl));
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return walk(value) as T;
}

// ---------------------------------------------------------------- built-in seed cases

/** The existing synthetic scenarios (GCP/AWS + registry connectors) as seed-tier cases. Built fresh per load. */
export function builtinCases(base: Date): EvalCase[] {
  const out: EvalCase[] = [];
  for (const s of buildScenarios(base)) {
    const records = s.provider === "gcp"
      ? (s.gcp ?? []).map((raw) => ({ connector: "gcp", sourceType: "gcp_log", raw }))
      : (s.aws ?? []).map((raw) => ({ connector: "aws", sourceType: "aws_cloudtrail_management", raw }));
    const knowledge: EvalCase["knowledge"] = s.id === "gcp-terraform-sa-key"
      ? [{ kind: "trusted_identity", key: "terraform@example-project.iam.gserviceaccount.com", title: "Terraform CI service account", body: "Managed by the platform team; creates deployer keys during rotations.", attributes: {}, timing: "after_detection" }]
      : [];
    out.push(EvalCaseSchema.parse({
      id: `seed.${s.id}`, tier: "seed", description: s.description, records, knowledge,
      labels: { verdict: s.expectedVerdict, rulesExpected: s.expectedRules },
      adversarial: s.adversarial ? { twinOf: "seed.gcp-recon-404", goal: "verdict_flip", technique: "direct_imperative", field: "user_agent", marker: "IGNORE ALL PREVIOUS INSTRUCTIONS" } : undefined,
    }));
  }
  for (const s of buildConnectorScenarios(base)) {
    out.push(EvalCaseSchema.parse({
      id: `seed.${s.id}`, tier: "seed", description: s.description, connectors: s.config ? { [s.connector]: s.config } : {},
      records: s.records.map((r) => ({ connector: s.connector, ...r })),
      labels: { verdict: s.expectedVerdict, rulesExpected: s.expectedRules },
    }));
  }
  return out;
}

// ---------------------------------------------------------------- JSON case files

/** Read every *.json under `dir` (recursively). Each file holds one case or an array of cases. Templates are kept
 *  unexpanded here; call `materialize` at load time. */
export async function readCaseFiles(dir: string): Promise<unknown[]> {
  const out: unknown[] = [];
  const walk = async (d: string) => {
    for (const e of await fs.readdir(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) await walk(p);
      else if (e.name.endsWith(".json")) {
        const j = JSON.parse(await fs.readFile(p, "utf8"));
        for (const c of Array.isArray(j) ? j : [j]) out.push({ ...c, __file: p });
      }
    }
  };
  await walk(dir);
  return out;
}

/** A case source: either the built-in seed set or a directory of JSON case files. */
export type CaseSource = "builtin" | string;

export interface CaseRef { id: string; split: string; tier: string; materialize: (base: Date) => EvalCase }

export async function listCases(sources: CaseSource[], filter: { ids?: string[]; splits?: string[]; tiers?: string[] } = {}): Promise<CaseRef[]> {
  const refs: CaseRef[] = [];
  for (const src of sources) {
    if (src === "builtin") {
      for (const c of builtinCases(new Date())) refs.push({ id: c.id, split: c.split, tier: c.tier, materialize: (base) => builtinCases(base).find((x) => x.id === c.id)! });
    } else {
      for (const raw of await readCaseFiles(src)) {
        const { __file, ...body } = raw as Record<string, unknown>;
        const probe = EvalCaseSchema.safeParse(expandTemplates(body, new Date()));
        if (!probe.success) throw new Error(`invalid case in ${String(__file)}: ${probe.error.issues.slice(0, 3).map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
        refs.push({ id: probe.data.id, split: probe.data.split, tier: probe.data.tier, materialize: (base) => EvalCaseSchema.parse(expandTemplates(body, base)) });
      }
    }
  }
  const seen = new Set<string>();
  for (const r of refs) { if (seen.has(r.id)) throw new Error(`duplicate case id ${r.id}`); seen.add(r.id); }
  return refs.filter((r) => (!filter.ids?.length || filter.ids.includes(r.id))
    && (!filter.splits?.length || filter.splits.includes(r.split)) && (!filter.tiers?.length || filter.tiers.includes(r.tier)));
}
