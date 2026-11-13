import { z } from "zod";
import { connectorIds, isConnectorId } from "../connectors/registry.js";
import "../connectors/builtin.js";

/** Fields a rule may reference. Anything else must go through `normalized.<path>`. */
export const EVENT_FIELDS = [
  "cloudProvider", "projectOrAccountReference", "region", "sourceType", "sourceName", "resourceType",
  "resourceId", "serviceName", "severity", "principal", "sourceIp", "destinationIp", "action", "status",
  "httpStatus", "httpMethod", "urlPath", "userAgent", "traceId", "requestId", "normalizedEventType", "categories",
] as const;

const fieldRef = z.string().refine(
  (f) => (EVENT_FIELDS as readonly string[]).includes(f) || /^normalized(\.[A-Za-z0-9_]+){1,6}$/.test(f),
  { message: "unknown field; use an event field or normalized.<path>" },
);

const Leaf = z.object({
  field: fieldRef,
  op: z.enum(["eq", "neq", "in", "nin", "regex", "gte", "lte", "gt", "lt", "exists", "contains", "startsWith"]),
  value: z.unknown().optional(),
}).superRefine((c, ctx) => {
  if (c.op === "regex") {
    if (typeof c.value !== "string" || c.value.length > 500) ctx.addIssue({ code: "custom", message: "regex must be a string ≤500 chars" });
    else try { new RegExp(c.value.startsWith("(?i)") ? c.value.slice(4) : c.value); } catch { ctx.addIssue({ code: "custom", message: "invalid regex" }); }
  }
});

export type Condition =
  | z.infer<typeof Leaf>
  | { all: Condition[] }
  | { any: Condition[] }
  | { not: Condition };

export const ConditionSchema: z.ZodType<Condition> = z.lazy(() =>
  z.union([Leaf, z.object({ all: z.array(ConditionSchema).min(1) }), z.object({ any: z.array(ConditionSchema).min(1) }), z.object({ not: ConditionSchema })]),
);

const groupBy = z.array(fieldRef).min(1).max(4);
const windowMinutes = z.number().int().min(1).max(7 * 24 * 60);

export const DetectionQuerySchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("match"), where: ConditionSchema, groupBy: groupBy.optional(), windowMinutes: windowMinutes.default(60) }),
  z.object({ kind: z.literal("threshold"), where: ConditionSchema, groupBy, windowMinutes, minCount: z.number().int().min(1) }),
  z.object({ kind: z.literal("distinct"), where: ConditionSchema, groupBy, field: fieldRef, windowMinutes, minDistinct: z.number().int().min(2) }),
  z.object({
    kind: z.literal("rate_spike"), where: ConditionSchema, groupBy: groupBy.optional(),
    bucketMinutes: z.number().int().min(1).max(1440), baselineBuckets: z.number().int().min(2).max(288),
    factor: z.number().min(1), minCount: z.number().int().min(1),
  }),
  z.object({
    kind: z.literal("sequence"), steps: z.array(ConditionSchema).min(2).max(5), groupBy, windowMinutes,
  }),
]);
export type DetectionQuery = z.infer<typeof DetectionQuerySchema>;

export const MitreSchema = z.array(z.object({ tactic: z.string(), technique: z.string(), name: z.string().optional() }));

export const RuleDefinitionSchema = z.object({
  ruleId: z.string().regex(/^[A-Z0-9][A-Z0-9-]{2,63}$/),
  name: z.string().min(3).max(200),
  description: z.string().min(3).max(4000),
  /** "any" or a registered connector id (validated against the connector registry at parse time) */
  provider: z.string().refine((p) => p === "any" || isConnectorId(p), { message: `provider must be "any" or a registered connector id (${["any", ...connectorIds()].join(", ")})` }).default("any"),
  eventSources: z.array(z.string()).default([]),
  detectionQuery: DetectionQuerySchema,
  conditions: z.record(z.string(), z.unknown()).default({}),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  mitre: MitreSchema.default([]),
  enabled: z.boolean().default(true),
  /** base confidence for findings produced by this rule (deterministic metadata, not an AI score) */
  confidence: z.number().min(0).max(1).default(0.7),
});
export type RuleDefinition = z.infer<typeof RuleDefinitionSchema>;
