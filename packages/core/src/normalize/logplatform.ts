import type { CanonicalEvent, EventCategory, Severity } from "../types.js";
import { redactDeep, redactString } from "../redact.js";
import { normalizeCloudTrail, type CloudTrailRecord } from "./aws.js";
import { gcpSourceTypeForLog, httpCategories, normalizeGcpEntry, type GcpLogEntry } from "./gcp.js";
import { ci, looksLikeAzureActivity, normalizeAzureActivity, normalizeEntraAudit, normalizeEntraSignIn } from "./azure.js";

/**
 * Normalization for logs read from log platforms (Datadog, New Relic, …).
 *
 * 1. If the record is a known cloud audit payload that was forwarded to the platform (CloudTrail, GCP LogEntry,
 *    Azure Activity / Entra ID), the existing cloud normalizer runs on the embedded payload, so categories,
 *    provider rules and dedupe keys are identical to direct ingestion (`cloudProvider` stays the origin cloud;
 *    `normalized.via` records the platform).
 * 2. Otherwise common attributes (Datadog standard attributes / OpenTelemetry-style names) are mapped; anything
 *    unknown becomes `app.log` with nulls — fields are never invented.
 */
export interface ForwardedLog {
  platform: string;
  /** platform's own event id */
  id: string | null;
  timestamp: string | number | null;
  message: string | null;
  host: string | null;
  service: string | null;
  /** origin hint: Datadog `source` / New Relic `logtype` */
  source: string | null;
  /** log level */
  level: string | null;
  tags: string[];
  /** structured attributes, nested (dotted keys are also looked up) */
  attributes: Record<string, unknown>;
}

type Obj = Record<string, any>;

/** Read `a.b.c` from a nested object, or from a flat object with a literal "a.b.c" key (New Relic style). */
export function getPath(o: unknown, path: string): unknown {
  if (!o || typeof o !== "object") return undefined;
  const rec = o as Obj;
  if (rec[path] !== undefined) return rec[path];
  const parts = path.split(".");
  for (let i = parts.length - 1; i > 0; i--) {
    const head = parts.slice(0, i).join(".");
    if (rec[head] !== undefined && typeof rec[head] === "object") return getPath(rec[head], parts.slice(i).join("."));
  }
  return undefined;
}

/** {"a.b": 1, "a.c": 2} → {a: {b: 1, c: 2}}; non-conflicting, depth-bounded. Arrays/values are kept as is. */
export function unflatten(flat: Record<string, unknown>, maxDepth = 12): Obj {
  const out: Obj = {};
  for (const [k, v] of Object.entries(flat)) {
    const parts = k.split(".");
    if (parts.length > maxDepth || parts.some((p) => p === "__proto__" || p === "constructor" || p === "prototype")) continue;
    let cur = out;
    for (let i = 0; i < parts.length - 1; i++) {
      const p = parts[i]!;
      if (cur[p] === undefined || typeof cur[p] !== "object" || cur[p] === null) cur[p] = {};
      cur = cur[p];
    }
    const last = parts[parts.length - 1]!;
    if (cur[last] !== undefined && typeof cur[last] === "object" && v !== null && typeof v === "object") Object.assign(cur[last], v);
    else if (cur[last] === undefined || typeof cur[last] !== "object") cur[last] = v;
  }
  return out;
}

const str = (v: unknown): string | null => (typeof v === "string" && v.length > 0 ? v : typeof v === "number" && Number.isFinite(v) ? String(v) : null);
const num = (v: unknown): number | null => { const n = typeof v === "string" && v.trim() !== "" ? Number(v) : v; return typeof n === "number" && Number.isFinite(n) ? n : null; };
const isIp = (s: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) || (/^[0-9a-f:]+$/i.test(s) && s.includes(":"));
const ip = (v: unknown) => { const s = str(v); return s && isIp(s) ? s : null; };
function toIso(v: unknown): string | null {
  if (v === null || v === undefined || v === "") return null;
  const n = num(v);
  const d = n !== null ? new Date(n < 1e12 ? n * 1000 : n) : new Date(String(v));
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

const LEVEL: Record<string, Severity> = {
  emergency: "critical", emerg: "critical", alert: "critical", critical: "critical", crit: "critical", fatal: "critical",
  error: "high", err: "high", warn: "medium", warning: "medium", notice: "low", info: "info", informational: "info", debug: "info", trace: "info", ok: "info",
};

function via(l: ForwardedLog) {
  return { platform: l.platform, event_id: l.id, source: l.source, service: l.service, host: l.host };
}
function withVia(ev: CanonicalEvent, l: ForwardedLog): CanonicalEvent {
  return { ...ev, normalized: { ...ev.normalized, via: via(l) } };
}

/** Which cloud payload (if any) a forwarded record carries. */
export function detectEmbeddedCloud(a: Obj): "aws_cloudtrail" | "gcp_log_entry" | "azure_activity" | "entra_signin" | "entra_audit" | null {
  if (typeof a.eventSource === "string" && typeof a.eventName === "string" && /amazonaws\.com$/.test(a.eventSource) && (a.eventVersion || a.eventID || a.userIdentity)) return "aws_cloudtrail";
  const g = a.data && typeof a.data === "object" ? a.data : a;
  if (typeof g.logName === "string" && /^(projects|organizations|folders|billingAccounts)\//.test(g.logName) && (g.protoPayload || g.jsonPayload || g.textPayload || g.httpRequest)) return "gcp_log_entry";
  const cat = String(ci(a, "category") ?? "");
  const props = ci(a, "properties");
  if (props && typeof props === "object") {
    if (/^(SignInLogs|NonInteractiveUserSignInLogs|ServicePrincipalSignInLogs)$/i.test(cat)) return "entra_signin";
    if (/^AuditLogs$/i.test(cat) && (ci(props, "activityDisplayName") || ci(props, "initiatedBy"))) return "entra_audit";
  }
  if (looksLikeAzureActivity(a)) return "azure_activity";
  return null;
}

export function normalizeForwardedLog(l: ForwardedLog, ctx: { accountRef: string | null; sourceType: string }): CanonicalEvent {
  const a = l.attributes ?? {};
  const ts = toIso(l.timestamp);
  switch (detectEmbeddedCloud(a)) {
    case "aws_cloudtrail": {
      const r = a as CloudTrailRecord;
      return withVia(normalizeCloudTrail(r.eventTime ? r : { ...r, eventTime: ts ?? undefined }, { sourceType: "aws_cloudtrail_management" }), l);
    }
    case "gcp_log_entry": {
      const e = (a.data && typeof a.data === "object" ? a.data : a) as GcpLogEntry;
      const logId = e.logName ? decodeURIComponent(e.logName.split("/logs/")[1] ?? "") : "";
      const project = e.resource?.labels?.project_id ?? /^projects\/([^/]+)/.exec(e.logName ?? "")?.[1] ?? "unknown";
      return withVia(normalizeGcpEntry(e.timestamp || e.receiveTimestamp ? e : { ...e, timestamp: ts ?? undefined }, { projectId: project, sourceType: gcpSourceTypeForLog(logId, e.resource?.type) }), l);
    }
    case "entra_signin": {
      const p = ci(a, "properties");
      return withVia(normalizeEntraSignIn({ ...p, createdDateTime: ci(p, "createdDateTime") ?? ci(a, "time") ?? ts, tenantId: ci(a, "tenantId") ?? ci(p, "tenantId") }, { sourceType: "azure_entra_signin" }), l);
    }
    case "entra_audit": {
      const p = ci(a, "properties");
      return withVia(normalizeEntraAudit({ ...p, activityDateTime: ci(p, "activityDateTime") ?? ci(a, "time") ?? ts, tenantId: ci(a, "tenantId") ?? ci(p, "tenantId") }, { sourceType: "azure_entra_audit" }), l);
    }
    case "azure_activity":
      return withVia(normalizeAzureActivity(ci(a, "eventTimestamp", "time") ? a : { ...a, time: ts }, { sourceType: "azure_activity_log" }), l);
    default:
      return normalizeGenericLog(l, ctx, ts);
  }
}

const AUTH_EVT = /(login|log_in|logon|sign[-_ ]?in|authenticat|sso|mfa|password)/i;

function normalizeGenericLog(l: ForwardedLog, ctx: { accountRef: string | null; sourceType: string }, ts: string | null): CanonicalEvent {
  if (!ts) throw new Error(`${l.platform} log without a valid timestamp`);
  const a = l.attributes ?? {};
  const g = (p: string) => getPath(a, p);
  const httpStatus = num(g("http.status_code")) ?? num(g("http.response.status_code")) ?? num(g("http.statusCode"));
  const method = (str(g("http.method")) ?? str(g("http.request.method")))?.toUpperCase() ?? null;
  const rawUrl = str(g("http.url")) ?? str(g("url.full")) ?? str(g("request.uri")) ?? str(g("http.target"));
  let path = str(g("http.url_details.path")) ?? str(g("url.path"));
  let query: string | null = null;
  if (rawUrl) {
    try { const u = new URL(rawUrl, "http://placeholder.invalid"); path ??= u.pathname; query = u.search ? u.search.slice(1) : null; } catch { path ??= rawUrl.split("?")[0] ?? null; }
  }
  const evtName = str(g("evt.name"));
  const evtCategory = str(g("evt.category"));
  const outcome = (str(g("evt.outcome")) ?? str(g("event.outcome")))?.toLowerCase() ?? null;
  const success = outcome ? /^(success|succeeded|ok|allow|allowed)$/.test(outcome) : null;
  const failed = outcome ? /^(fail|failure|failed|error|deny|denied|blocked)$/.test(outcome) : null;

  const cats: EventCategory[] = [];
  const isHttp = httpStatus !== null || method !== null;
  if (isHttp) cats.push(...httpCategories(httpStatus, path, method));
  const isAuth = /^auth/i.test(evtCategory ?? "") || (!!evtName && AUTH_EVT.test(evtName));
  if (isAuth && success) cats.push("auth.success");
  if (isAuth && failed) cats.push("auth.failure");
  const platformCats = l.platform === "datadog" && ctx.sourceType === "datadog_audit" ? datadogAuditCategories(a, outcome) : [];
  for (const c of platformCats) if (!cats.includes(c)) cats.push(c);
  if (!cats.length) cats.push("app.log");
  const unique = [...new Set(cats)];
  const type = unique.includes("auth.failure") ? "auth.failure" : unique.includes("auth.success") ? "auth.success"
    : (["iam.credential_create", "logging.config_change", "security_policy.change", "iam.change"] as const).find((c) => unique.includes(c))
    ?? (isHttp ? "http.request" : "app.log");
  const status = success ? "success" : failed ? (/deny|denied|blocked/.test(outcome!) ? "blocked" : "failure") : isHttp && httpStatus !== null ? (httpStatus >= 400 ? "failure" : "success") : null;
  const attrsJson = JSON.stringify(a);
  return {
    cloudProvider: l.platform,
    projectOrAccountReference: ctx.accountRef,
    region: null,
    sourceType: ctx.sourceType,
    sourceName: l.source ?? l.service,
    eventTimestamp: ts,
    resourceType: l.host ? "host" : null,
    resourceId: l.host,
    serviceName: l.service,
    severity: l.level ? LEVEL[l.level.toLowerCase()] ?? null : null,
    principal: str(g("usr.email")) ?? str(g("usr.id")) ?? str(g("usr.name")) ?? str(g("user.email")) ?? str(g("user.id")) ?? str(g("enduser.id")),
    sourceIp: ip(g("network.client.ip")) ?? ip(g("client.address")) ?? ip(g("source.ip")),
    destinationIp: ip(g("network.destination.ip")) ?? ip(g("destination.ip")),
    action: evtName ?? (method && path ? `${method} ${path}` : null),
    status,
    httpStatus,
    httpMethod: method,
    urlPath: path,
    userAgent: str(g("http.useragent")) ?? str(g("user_agent.original")) ?? str(g("http.user_agent")),
    traceId: str(g("dd.trace_id")) ?? str(g("trace.id")) ?? str(g("trace_id")) ?? str(g("traceId")),
    requestId: str(g("http.request_id")) ?? str(g("request_id")) ?? str(g("requestId")),
    normalizedEventType: type,
    categories: unique,
    providerEventId: l.id,
    normalized: {
      ocsf: type.startsWith("auth") ? { class_uid: 3002, class_name: "Authentication" } : isHttp ? { class_uid: 4002, class_name: "HTTP Activity" } : { class_uid: 1007, class_name: "Process Activity / application log" },
      message: l.message ? redactString(l.message.slice(0, 8000)) : null,
      http: isHttp ? { status: httpStatus, method, path, query: query ? redactString(query) : null } : null,
      evt: evtName || evtCategory || outcome ? { name: evtName, category: evtCategory, outcome } : null,
      tags: l.tags.slice(0, 50).map((t) => redactString(t)),
      attributes: attrsJson.length <= 16_000 ? redactDeep(a) : { truncated: true, size: attrsJson.length },
      via: via(l),
    },
  };
}

/** Datadog Audit Trail: asset type + action → categories (org-level tampering reuses the generic rules). */
function datadogAuditCategories(a: Obj, outcome: string | null): EventCategory[] {
  const assetType = String(getPath(a, "asset.type") ?? "").toLowerCase();
  const action = String(getPath(a, "action") ?? getPath(a, "evt.actions") ?? "").toLowerCase();
  if (outcome && /fail|error|denied/.test(outcome)) return ["cloud.api_call"];
  const c: EventCategory[] = ["cloud.api_call"];
  const changed = /(created|modified|deleted|updated|revoked|disabled)/.test(action);
  if (/^(api_key|application_key|app_key|service_account)/.test(assetType) && /created/.test(action)) c.push("iam.credential_create", "iam.change");
  else if (/^(user|role|team|authn_mapping|org_setting|saml|login_method|restriction_policy)/.test(assetType) && changed) c.push("iam.change");
  if (/^(role|authn_mapping)/.test(assetType) && /(created|modified)/.test(action)) c.push("iam.privilege_grant");
  if (/^(logs_pipeline|logs_index|logs_archive|logs_exclusion|logs_custom_destination|sensitive_data_scanner)/.test(assetType) && /(deleted|modified|disabled)/.test(action)) c.push("logging.config_change");
  if (/^(security_rule|security_monitoring|monitor|security_filter|suppression)/.test(assetType) && /(deleted|disabled|modified)/.test(action)) c.push("security_policy.change");
  return c;
}
