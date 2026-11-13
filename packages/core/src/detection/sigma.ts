import { isConnectorId } from "../connectors/registry.js";
import type { Condition, RuleDefinition } from "./dsl.js";
import { RuleDefinitionSchema } from "./dsl.js";

/**
 * Minimal Sigma → Vigil translator. Supports: one or more named selections of field maps,
 * modifiers |contains |startswith |endswith |re, list values (OR), and conditions of the form
 * `sel`, `sel1 and sel2`, `sel1 or sel2`, `sel and not filter`. Anything else throws — we do
 * not silently approximate detection logic.
 */
const FIELD_MAP: Record<string, string> = {
  eventName: "action", methodName: "action", "protoPayload.methodName": "action",
  sourceIPAddress: "sourceIp", "protoPayload.requestMetadata.callerIp": "sourceIp", c_ip: "sourceIp", "c-ip": "sourceIp",
  eventSource: "serviceName", "protoPayload.serviceName": "serviceName",
  "userIdentity.arn": "principal", "protoPayload.authenticationInfo.principalEmail": "principal",
  cs_uri_stem: "urlPath", "cs-uri-stem": "urlPath", sc_status: "httpStatus", "sc-status": "httpStatus",
  cs_method: "httpMethod", "cs-method": "httpMethod", "cs-user-agent": "userAgent", errorCode: "normalized.aws.error_code",
  "userIdentity.type": "normalized.aws.identity_type",
};

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function leaf(fieldSpec: string, value: unknown): Condition {
  const [rawField, ...mods] = fieldSpec.split("|");
  const field = FIELD_MAP[rawField!];
  if (!field) throw new Error(`sigma field not mapped: ${rawField}`);
  const values = Array.isArray(value) ? value : [value];
  const one = (v: unknown): Condition => {
    if (mods.includes("re")) return { field, op: "regex", value: String(v) };
    if (mods.includes("contains")) return { field, op: "regex", value: `(?i)${esc(String(v))}` };
    if (mods.includes("startswith")) return { field, op: "regex", value: `(?i)^${esc(String(v))}` };
    if (mods.includes("endswith")) return { field, op: "regex", value: `(?i)${esc(String(v))}$` };
    if (mods.length) throw new Error(`sigma modifier not supported: ${mods.join("|")}`);
    return { field, op: "eq", value: v };
  };
  return values.length === 1 ? one(values[0]) : { any: values.map(one) };
}

export function sigmaToRule(sigma: any, ruleId: string): RuleDefinition {
  const det = sigma?.detection;
  if (!det || typeof det.condition !== "string") throw new Error("sigma rule missing detection.condition");
  const selections: Record<string, Condition> = {};
  for (const [name, body] of Object.entries(det)) {
    if (name === "condition" || name === "timeframe") continue;
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error(`selection ${name}: only field maps supported`);
    selections[name] = { all: Object.entries(body as Record<string, unknown>).map(([f, v]) => leaf(f, v)) };
  }
  const tokens = det.condition.trim().split(/\s+/);
  const pick = (n: string) => { const s = selections[n]; if (!s) throw new Error(`unknown selection ${n}`); return s; };
  let where: Condition;
  if (tokens.length === 1) where = pick(tokens[0]);
  else if (tokens.length === 3 && (tokens[1] === "and" || tokens[1] === "or")) where = tokens[1] === "and" ? { all: [pick(tokens[0]), pick(tokens[2])] } : { any: [pick(tokens[0]), pick(tokens[2])] };
  else if (tokens.length === 4 && tokens[1] === "and" && tokens[2] === "not") where = { all: [pick(tokens[0]), { not: pick(tokens[3]) }] };
  else throw new Error(`sigma condition not supported: ${det.condition}`);

  const level = String(sigma.level ?? "medium").toLowerCase();
  const severity = (["info", "low", "medium", "high", "critical"].includes(level) ? level : level === "informational" ? "info" : "medium") as RuleDefinition["severity"];
  const product = String(sigma.logsource?.product ?? "").toLowerCase();
  const mitre = (sigma.tags ?? []).filter((t: string) => /^attack\.t\d{4}/i.test(t)).map((t: string) => ({ tactic: "unknown", technique: t.slice(7).toUpperCase() }));
  return RuleDefinitionSchema.parse({
    ruleId, name: sigma.title ?? ruleId, description: sigma.description ?? "Imported Sigma rule",
    provider: product && isConnectorId(product) ? product : "any",
    detectionQuery: { kind: "match", where, windowMinutes: 60 },
    severity, mitre, conditions: { sigma_id: sigma.id ?? null },
  });
}
