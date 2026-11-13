/**
 * SYNTHETIC Datadog search-API items (`{ id, type, attributes }`) — never used on production paths.
 * Forwarded cloud payloads reuse the GCP/AWS fixture builders so delegation is tested against the same shapes.
 */
import { randomUUID } from "node:crypto";
import { cloudTrail, gcpAudit } from "./synthetic.js";
import type { ConnectorScenario } from "./scenarios.js";

const id = () => `AQAAAY${randomUUID().replace(/-/g, "").slice(0, 26)}`;

export function ddLog(o: { ts: Date; source: string; service?: string; host?: string; status?: string; message?: string; attributes?: Record<string, unknown>; tags?: string[] }) {
  return {
    id: id(), type: "log",
    attributes: {
      timestamp: o.ts.toISOString(), host: o.host ?? "web-01", service: o.service ?? o.source, status: o.status ?? "info", message: o.message ?? "",
      tags: [`source:${o.source}`, "env:prod", ...(o.tags ?? [])],
      attributes: { ddsource: o.source, ...(o.attributes ?? {}) },
    },
  };
}

/** CloudTrail record as Datadog's AWS integration stores it: original fields + standard-attribute remaps. */
export const ddCloudTrail = (ct: ReturnType<typeof cloudTrail>) => ddLog({
  ts: new Date(ct.eventTime!), source: "cloudtrail", service: "cloudtrail", host: ct.eventSource, message: ct.eventName,
  attributes: { ...ct, evt: { name: ct.eventName }, network: { client: { ip: ct.sourceIPAddress } }, usr: { id: ct.userIdentity?.arn } },
});
/** GCP LogEntry as Datadog's GCP Pub/Sub integration stores it (under `data`). */
export const ddGcp = (e: ReturnType<typeof gcpAudit>) => ddLog({ ts: new Date(e.timestamp!), source: "gcp.project", service: "gcp.project", host: "example-project", attributes: { data: e } });

export const ddNginx = (o: { ts: Date; ip: string; method?: string; path: string; status: number; ua?: string }) => ddLog({
  ts: o.ts, source: "nginx", service: "storefront", status: o.status >= 500 ? "error" : o.status >= 400 ? "warn" : "info",
  message: `${o.ip} - - "${o.method ?? "GET"} ${o.path} HTTP/1.1" ${o.status}`,
  attributes: { network: { client: { ip: o.ip } }, http: { method: o.method ?? "GET", status_code: o.status, url: o.path, url_details: { path: o.path.split("?")[0] }, useragent: o.ua ?? "Mozilla/5.0 (synthetic)" } },
});

export const ddAuth = (o: { ts: Date; ip: string; user: string; outcome: "success" | "failure" }) => ddLog({
  ts: o.ts, source: "auth0", service: "login", status: o.outcome === "failure" ? "warn" : "info", message: `login ${o.outcome} for ${o.user}`,
  attributes: { network: { client: { ip: o.ip } }, usr: { email: o.user }, evt: { name: "authentication", category: "authentication", outcome: o.outcome } },
});

export const ddAudit = (o: { ts: Date; user: string; ip: string; assetType: string; assetName: string; action: string; outcome?: string }) => ({
  id: id(), type: "audit",
  attributes: {
    timestamp: o.ts.toISOString(), service: "datadog", message: `${o.user} ${o.action} ${o.assetType} ${o.assetName}`, tags: ["source:audit"],
    attributes: { usr: { email: o.user }, network: { client: { ip: o.ip } }, asset: { type: o.assetType, name: o.assetName }, action: o.action, evt: { name: "Request", outcome: o.outcome ?? "success" } },
  },
});

export const ddSignal = (o: { ts: Date; title: string; severity: "info" | "low" | "medium" | "high" | "critical"; ip?: string; user?: string }) => ({
  id: id(), type: "signal",
  attributes: {
    timestamp: o.ts.toISOString(), message: `${o.title}\nGoal: detect...`, tags: [`severity:${o.severity}`, "source:cloudtrail"],
    custom: { title: o.title, severity: o.severity, workflow: { rule: { id: "abc-def-ghi", name: o.title }, triage: { state: "open" } } },
    attributes: { network: { client: { ip: o.ip } }, usr: { id: o.user } },
  },
});

const at = (base: Date, s: number) => new Date(base.getTime() + s * 1000);

export function buildDatadogScenarios(base = new Date(Date.now() - 2 * 3600_000)): ConnectorScenario[] {
  const arn = "arn:aws:iam::111122223333:user/ops-jane";
  const ct = [
    cloudTrail({ ts: at(base, 60), name: "CreateUser", source: "iam.amazonaws.com", arn, ip: "203.0.113.150", params: { userName: "backup-svc" } }),
    cloudTrail({ ts: at(base, 90), name: "CreateAccessKey", source: "iam.amazonaws.com", arn, ip: "203.0.113.150", params: { userName: "backup-svc" } }),
    cloudTrail({ ts: at(base, 300), name: "StopLogging", source: "cloudtrail.amazonaws.com", arn, ip: "203.0.113.150", params: { name: "org-trail" } }),
  ];
  const paths = ["/.env", "/.git/config", "/wp-admin/", "/phpmyadmin/", "/actuator/env", "/server-status"];
  const recon = Array.from({ length: 35 }, (_, i) => ddNginx({ ts: at(base, 600 + i * 5), ip: "203.0.113.45", path: i < paths.length ? paths[i]! : `/x-${i}.php`, status: 404, ua: "zgrab/0.x" }));
  const brute = [...Array.from({ length: 12 }, (_, i) => ddAuth({ ts: at(base, 900 + i * 10), ip: "198.51.100.77", user: "admin@example.com", outcome: "failure" })), ddAuth({ ts: at(base, 1100), ip: "198.51.100.77", user: "admin@example.com", outcome: "success" })];
  const audit = [ddAudit({ ts: at(base, 1300), user: "contractor@example.com", ip: "203.0.113.99", assetType: "api_key", assetName: "exfil-key", action: "created" }),
    ddAudit({ ts: at(base, 1360), user: "contractor@example.com", ip: "203.0.113.99", assetType: "logs_index", assetName: "main", action: "modified" })];
  const gcp = [ddGcp(gcpAudit({ ts: at(base, 1500), method: "google.logging.v2.ConfigServiceV2.DeleteSink", service: "logging.googleapis.com", principal: "contractor@example.com", ip: "203.0.113.99", resource: "projects/example-project/sinks/siem-export" }))];
  return [
    { id: "datadog-cloudtrail-persistence", connector: "datadog", description: "CloudTrail forwarded to Datadog: new IAM user + key, trail stopped", records: ct.map((r) => ({ sourceType: "datadog_logs", raw: ddCloudTrail(r) })), expectedRules: ["VGL-IAM-002", "VGL-IAM-001", "VGL-CFG-002"], expectedVerdict: "confirmed" },
    { id: "datadog-nginx-recon", connector: "datadog", description: "nginx 404 wordlist scan from one IP", records: recon.map((raw) => ({ sourceType: "datadog_logs", raw })), expectedRules: ["VGL-HTTP-001", "VGL-HTTP-002"], expectedVerdict: "likely" },
    { id: "datadog-auth-bruteforce", connector: "datadog", description: "12 auth0 failures then success from one IP", records: brute.map((raw) => ({ sourceType: "datadog_logs", raw })), expectedRules: ["VGL-AUTH-001"], expectedVerdict: "likely" },
    { id: "datadog-audit-tamper", connector: "datadog", description: "Datadog API key created and main log index modified", records: audit.map((raw) => ({ sourceType: "datadog_audit", raw })), expectedRules: ["VGL-IAM-002", "VGL-CFG-002"], expectedVerdict: "confirmed" },
    { id: "datadog-gcp-sink-delete", connector: "datadog", description: "GCP log sink deletion forwarded via Datadog", records: gcp.map((raw) => ({ sourceType: "datadog_logs", raw })), expectedRules: ["VGL-CFG-002"], expectedVerdict: "confirmed" },
  ];
}
