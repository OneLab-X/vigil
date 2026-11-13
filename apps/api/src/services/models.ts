import net from "node:net";
import { and, eq } from "drizzle-orm";
import { modelProviders, tenants, type Tx } from "@vigil/db";
import { env } from "../env.js";
import { secretStore } from "../lib/secrets.js";
import { ApiError, badRequest } from "../lib/errors.js";

export type ProviderKind = "anthropic" | "openai" | "gemini" | "openai_compatible";
export type DataPolicy = "any" | "customer_hosted_only" | "disabled";
export const DATA_POLICIES: DataPolicy[] = ["any", "customer_hosted_only", "disabled"];
/** Env-key providers are vendor-hosted APIs. */
const ENV_PROVIDER_HOSTING: Record<string, "external" | "customer_hosted"> = { anthropic: "external", openai: "external", gemini: "external", scripted: "customer_hosted" };

export const BLOCKED_HOSTS = new Set(["metadata.google.internal", "metadata", "metadata.azure.com", "instance-data", "instance-data.ec2.internal"]);
/**
 * SSRF guard for customer-supplied model endpoints. Private ranges stay allowed (a customer-hosted model on the LAN is
 * the point), but cloud metadata / link-local addresses never are. The agent worker re-checks the resolved IP at call time.
 */
export function assertSafeModelEndpoint(raw: string): string {
  let u: URL;
  try { u = new URL(raw); } catch { throw badRequest("base URL is not a valid URL"); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw badRequest("base URL must use http or https");
  if (u.username || u.password) throw badRequest("put credentials in the API key field, not the URL");
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (BLOCKED_HOSTS.has(host)) throw badRequest("cloud metadata endpoints are not allowed");
  if (net.isIP(host) && isBlockedIp(host)) throw badRequest("link-local / metadata addresses are not allowed");
  u.hash = ""; u.search = "";
  return u.toString().replace(/\/$/, "");
}
export function isBlockedIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 169 && b === 254 || a === 0 || ip === "100.100.100.200" || ip === "255.255.255.255";
  }
  const v = ip.toLowerCase();
  return v.startsWith("fe8") || v.startsWith("fe9") || v.startsWith("fea") || v.startsWith("feb") || v === "fd00:ec2::254" || v === "::" || v.startsWith("::ffff:169.254.");
}

export async function getDataPolicy(tx: Tx, tenantId: string): Promise<DataPolicy> {
  const [t] = await tx.select({ settings: tenants.settings }).from(tenants).where(eq(tenants.id, tenantId));
  const p = (t?.settings as Record<string, unknown> | undefined)?.aiDataPolicy;
  return DATA_POLICIES.includes(p as DataPolicy) ? (p as DataPolicy) : "any";
}

export type MaskingMode = "on" | "off";
/** Org default for masking sensitive values sent to AI models. Default on. */
export async function getMaskingDefault(tx: Tx, tenantId: string): Promise<MaskingMode> {
  const [t] = await tx.select({ settings: tenants.settings }).from(tenants).where(eq(tenants.id, tenantId));
  return (t?.settings as Record<string, unknown> | undefined)?.aiMasking === "off" ? "off" : "on";
}

export interface RunModelConfig {
  provider: string; name: string; endpoint?: string; api_key?: string; timeout_seconds?: number;
  price_input_per_mtok?: number; price_output_per_mtok?: number; hosting: "external" | "customer_hosted";
}

/** Resolve the model an agent definition will use, enforcing the tenant's AI data policy. Decrypts the key (never logged). */
export async function resolveRunModel(tx: Tx, tenantId: string, def: { modelProvider: string; modelName: string; modelProviderId: string | null }): Promise<RunModelConfig> {
  const policy = await getDataPolicy(tx, tenantId);
  if (policy === "disabled") throw new ApiError(409, "ai_disabled", "AI investigations are disabled by this organization's AI data policy");
  let cfg: RunModelConfig;
  if (def.modelProviderId) {
    const [p] = await tx.select().from(modelProviders).where(and(eq(modelProviders.id, def.modelProviderId), eq(modelProviders.tenantId, tenantId)));
    if (!p || !p.enabled) throw new ApiError(409, "model_provider_disabled", "the agent's model provider is missing or disabled");
    cfg = {
      provider: p.kind, name: def.modelName, endpoint: p.baseUrl ?? undefined, timeout_seconds: p.timeoutSeconds, hosting: p.hosting as RunModelConfig["hosting"],
      price_input_per_mtok: Number(p.priceInputPerMtok), price_output_per_mtok: Number(p.priceOutputPerMtok),
      api_key: p.secretRef ? await secretStore.get(tenantId, p.secretRef) : undefined,
    };
  } else {
    cfg = { provider: def.modelProvider, name: def.modelName, hosting: ENV_PROVIDER_HOSTING[def.modelProvider] ?? "external" };
  }
  if (policy === "customer_hosted_only" && cfg.hosting !== "customer_hosted") {
    throw new ApiError(409, "ai_policy_violation", "this organization only allows customer-hosted models; the agent is configured with an external provider");
  }
  return cfg;
}

/** Ask the agent worker (which is where model calls originate) to probe a provider config. */
export async function probeProvider(cfg: RunModelConfig): Promise<{ ok: boolean; detail: string }> {
  try {
    const r = await fetch(`${env.agentsUrl}/v1/providers/test`, {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${env.internalToken}` },
      body: JSON.stringify(cfg), signal: AbortSignal.timeout(((cfg.timeout_seconds ?? 30) + 5) * 1000),
    });
    const j = await r.json().catch(() => ({})) as { ok?: boolean; detail?: string };
    return { ok: !!j.ok, detail: (j.detail ?? `agent worker HTTP ${r.status}`).slice(0, 500) };
  } catch (e) {
    return { ok: false, detail: `agent worker unreachable: ${(e as Error).message}`.slice(0, 300) };
  }
}
