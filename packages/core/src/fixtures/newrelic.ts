/**
 * SYNTHETIC New Relic `SELECT * FROM Log` rows (flat, dotted attribute names; timestamp in epoch ms) —
 * never used on production paths. Forwarded cloud payloads reuse the GCP/AWS/Azure fixture builders.
 */
import { randomUUID } from "node:crypto";
import { cloudTrail } from "./synthetic.js";
import { entraSignIn } from "./azure.js";
import type { ConnectorScenario } from "./scenarios.js";

/** {a: {b: 1}} → {"a.b": 1} (arrays kept as values), as New Relic stores parsed JSON attributes. */
export function flattenAttributes(o: Record<string, unknown>, prefix = "", out: Record<string, unknown> = {}): Record<string, unknown> {
  for (const [k, v] of Object.entries(o)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) flattenAttributes(v as Record<string, unknown>, key, out);
    else if (v !== undefined && v !== null) out[key] = v;
  }
  return out;
}

export function nrLog(o: { ts: Date; message?: string; logtype?: string; hostname?: string; service?: string; level?: string; attrs?: Record<string, unknown> }) {
  return {
    timestamp: o.ts.getTime(), messageId: randomUUID(), message: o.message ?? "", hostname: o.hostname ?? "web-01",
    ...(o.logtype ? { logtype: o.logtype } : {}), ...(o.service ? { "service.name": o.service } : {}), ...(o.level ? { level: o.level } : {}),
    "newrelic.source": "api.logs", ...flattenAttributes(o.attrs ?? {}),
  };
}

export const nrCloudTrail = (ct: ReturnType<typeof cloudTrail>) => nrLog({ ts: new Date(ct.eventTime!), message: ct.eventName, logtype: "cloudtrail", hostname: ct.eventSource, attrs: ct as Record<string, unknown> });
/** CloudTrail forwarded as a raw JSON string message (not parsed by the forwarder). */
export const nrCloudTrailUnparsed = (ct: ReturnType<typeof cloudTrail>) => nrLog({ ts: new Date(ct.eventTime!), message: JSON.stringify(ct), logtype: "cloudtrail" });

export const nrAccess = (o: { ts: Date; ip: string; method?: string; path: string; status: number }) => nrLog({
  ts: o.ts, logtype: "nginx", service: "storefront", message: `${o.ip} "${o.method ?? "GET"} ${o.path}" ${o.status}`,
  attrs: { network: { client: { ip: o.ip } }, http: { method: o.method ?? "GET", status_code: o.status, url: o.path } },
});

export const nrAuth = (o: { ts: Date; ip: string; user: string; outcome: "success" | "failure" }) => nrLog({
  ts: o.ts, logtype: "auth0", service: "login", level: o.outcome === "failure" ? "warn" : "info", message: `login ${o.outcome}`,
  attrs: { network: { client: { ip: o.ip } }, usr: { email: o.user }, evt: { name: "authentication", category: "authentication", outcome: o.outcome } },
});

const at = (base: Date, s: number) => new Date(base.getTime() + s * 1000);

export function buildNewRelicScenarios(base = new Date(Date.now() - 2 * 3600_000)): ConnectorScenario[] {
  const arn = "arn:aws:iam::111122223333:user/ops-jane";
  const ct = [
    nrCloudTrail(cloudTrail({ ts: at(base, 60), name: "CreateAccessKey", source: "iam.amazonaws.com", arn, ip: "203.0.113.150", params: { userName: "backup-svc" } })),
    nrCloudTrailUnparsed(cloudTrail({ ts: at(base, 120), name: "DeleteTrail", source: "cloudtrail.amazonaws.com", arn, ip: "203.0.113.150", params: { name: "org-trail" } })),
  ];
  const recon = Array.from({ length: 32 }, (_, i) => nrAccess({ ts: at(base, 600 + i * 5), ip: "203.0.113.45", path: i === 0 ? "/.env" : i === 1 ? "/.git/config" : i === 2 ? "/wp-admin/" : `/x-${i}.php`, status: 404 }));
  const brute = [...Array.from({ length: 11 }, (_, i) => nrAuth({ ts: at(base, 900 + i * 10), ip: "198.51.100.77", user: "admin@example.com", outcome: "failure" }))];
  const entra = Array.from({ length: 10 }, (_, i) => nrLog({ ts: at(base, 1200 + i * 10), logtype: "azure", attrs: { time: at(base, 1200 + i * 10).toISOString(), category: "SignInLogs", tenantId: "11111111-2222-3333-4444-555555555555", properties: entraSignIn({ ts: at(base, 1200 + i * 10), upn: "ceo@contoso.example", ip: "192.0.2.66", errorCode: 50126 }) } }));
  return [
    { id: "newrelic-cloudtrail", connector: "newrelic", description: "CloudTrail in New Relic Logs (parsed + raw JSON message): access key created, trail deleted", records: ct.map((raw) => ({ sourceType: "newrelic_logs", raw })), expectedRules: ["VGL-IAM-002", "VGL-CFG-002"], expectedVerdict: "confirmed" },
    { id: "newrelic-nginx-recon", connector: "newrelic", description: "nginx 404 scan from one IP", records: recon.map((raw) => ({ sourceType: "newrelic_logs", raw })), expectedRules: ["VGL-HTTP-001", "VGL-HTTP-002"], expectedVerdict: "likely" },
    { id: "newrelic-auth-bruteforce", connector: "newrelic", description: "11 login failures from one IP", records: brute.map((raw) => ({ sourceType: "newrelic_logs", raw })), expectedRules: ["VGL-AUTH-001"], expectedVerdict: "likely" },
    { id: "newrelic-entra-bruteforce", connector: "newrelic", description: "Entra sign-in failures forwarded to New Relic", records: entra.map((raw) => ({ sourceType: "newrelic_logs", raw })), expectedRules: ["VGL-AUTH-001"], expectedVerdict: "likely" },
  ];
}
