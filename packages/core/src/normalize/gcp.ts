import type { CanonicalEvent, EventCategory, Severity } from "../types.js";
import { redactDeep, redactString } from "../redact.js";

/** Subset of google.logging.v2.LogEntry we rely on. Everything optional: logs are untrusted. */
export interface GcpLogEntry {
  insertId?: string;
  logName?: string;
  timestamp?: string;
  receiveTimestamp?: string;
  severity?: string;
  resource?: { type?: string; labels?: Record<string, string> };
  labels?: Record<string, string>;
  trace?: string;
  spanId?: string;
  httpRequest?: {
    requestMethod?: string; requestUrl?: string; status?: number; userAgent?: string;
    remoteIp?: string; serverIp?: string; latency?: string; responseSize?: string;
  };
  protoPayload?: Record<string, any>;
  jsonPayload?: Record<string, any>;
  textPayload?: string;
  operation?: { id?: string; producer?: string };
}

const SEV: Record<string, Severity> = {
  DEFAULT: "info", DEBUG: "info", INFO: "info", NOTICE: "low", WARNING: "medium",
  ERROR: "high", CRITICAL: "critical", ALERT: "critical", EMERGENCY: "critical",
};

const str = (v: unknown): string | null => (typeof v === "string" && v.length > 0 ? v : null);
const num = (v: unknown): number | null => {
  const n = typeof v === "string" ? Number(v) : v;
  return typeof n === "number" && Number.isFinite(n) ? n : null;
};

function logIdOf(logName: string | undefined): string | null {
  if (!logName) return null;
  const i = logName.indexOf("/logs/");
  return i >= 0 ? decodeURIComponent(logName.slice(i + 6)) : logName;
}

function regionFromZone(zone: string | undefined): string | null {
  if (!zone) return null;
  const m = /^([a-z]+-[a-z]+\d+)/.exec(zone);
  return m ? m[1]! : null;
}

function traceIdOf(trace: string | undefined, fallback?: unknown): string | null {
  if (trace) {
    const i = trace.lastIndexOf("/traces/");
    return i >= 0 ? trace.slice(i + 8) : trace;
  }
  return str(fallback);
}

function splitUrl(u: string | null): { path: string | null; query: string | null } {
  if (!u) return { path: null, query: null };
  try {
    const parsed = new URL(u, "http://placeholder.invalid");
    return { path: parsed.pathname, query: parsed.search ? parsed.search.slice(1) : null };
  } catch {
    const [p, q] = u.split("?");
    return { path: p ?? null, query: q ?? null };
  }
}

export function httpCategories(status: number | null, path: string | null, method: string | null): EventCategory[] {
  const c: EventCategory[] = ["http.request"];
  if (status !== null) {
    if (status === 404) c.push("http.not_found");
    if (status >= 400 && status < 500) c.push("http.client_error");
    if (status >= 500) c.push("http.server_error");
    if ((status === 401 || status === 403) && path && /(login|signin|sign-in|auth|token|session)/i.test(path)) c.push("auth.failure");
    if (status >= 200 && status < 300 && method === "POST" && path && /(login|signin|sign-in|auth\/token|session)/i.test(path)) c.push("auth.success");
  }
  return c;
}

/** Map audit-log method names to provider-independent categories. */
export function gcpAuditCategories(method: string, service: string): EventCategory[] {
  const c: EventCategory[] = ["cloud.api_call"];
  const m = method.toLowerCase();
  if (/serviceaccounts\.keys\.create|createserviceaccountkey|serviceaccounts\.create|createserviceaccount\b|apikeys.*create/.test(m)) c.push("iam.credential_create", "iam.change");
  else if (/setiampolicy|roles\.(create|update|patch|delete)|serviceaccounts\.(delete|update|patch|enable|disable)|iam\./.test(m) || service === "iam.googleapis.com") c.push("iam.change");
  if (/setiampolicy/.test(m)) c.push("iam.privilege_grant");
  if (/firewalls\.(insert|patch|update|delete)|compute\.firewalls|securitypolicies\.(insert|patch|addrule|patchrule|removerule|delete)/.test(m)) c.push(m.includes("securitypolic") ? "security_policy.change" : "firewall.change");
  if (/(configservicev2|logging\.v2\.).*(deletesink|updatesink|deletelog\b|updatecmeksettings|updatesettings|deleteexclusion|createexclusion|updateexclusion|updatebucket|deletebucket)|auditconfig/.test(m)) c.push("logging.config_change");
  return c;
}

export function normalizeGcpEntry(e: GcpLogEntry, opts: { projectId: string; sourceType: string }): CanonicalEvent {
  const logId = logIdOf(e.logName);
  const resType = e.resource?.type ?? null;
  const labels = e.resource?.labels ?? {};
  const ts = e.timestamp ?? e.receiveTimestamp;
  if (!ts) throw new Error("log entry without timestamp");
  const base = {
    cloudProvider: "gcp" as const,
    projectOrAccountReference: labels.project_id ?? opts.projectId,
    region: regionFromZone(labels.zone ?? labels.location ?? labels.region),
    sourceType: opts.sourceType,
    sourceName: logId,
    eventTimestamp: new Date(ts).toISOString(),
    resourceType: resType,
    severity: e.severity ? SEV[e.severity] ?? null : null,
    providerEventId: e.insertId ? `${e.logName ?? ""}#${e.insertId}` : null,
  };
  const pp = e.protoPayload;
  const ppType = pp?.["@type"] as string | undefined;

  // --- App Engine request log ---
  if (ppType === "type.googleapis.com/google.appengine.logging.v1.RequestLog" && pp) {
    const status = num(pp.status) ?? num(e.httpRequest?.status);
    const method = str(pp.method);
    const { path, query } = splitUrl(str(pp.resource));
    return {
      ...base,
      resourceId: [labels.module_id, labels.version_id].filter(Boolean).join("/") || null,
      serviceName: labels.module_id ?? null,
      principal: null,
      sourceIp: str(pp.ip),
      destinationIp: null,
      action: method && path ? `${method} ${path}` : null,
      status: status === null ? null : status >= 400 ? "failure" : "success",
      httpStatus: status,
      httpMethod: method,
      urlPath: path,
      userAgent: str(pp.userAgent),
      traceId: traceIdOf(e.trace, pp.traceId),
      requestId: str(pp.requestId) ?? e.operation?.id ?? null,
      normalizedEventType: "http.request",
      categories: httpCategories(status, path, method),
      normalized: redactDeep({
        ocsf: { class_uid: 4002, class_name: "HTTP Activity", activity_id: 99 },
        http: { method, path, query, status, host: str(pp.host), referrer: str(pp.referrer), latency: str(pp.latency), response_size: num(pp.responseSize) },
        gae: { module: labels.module_id ?? null, version: labels.version_id ?? null, instance_id: str(pp.instanceId), app_log_lines: Array.isArray(pp.line) ? pp.line.length : 0 },
        span_id: e.spanId ?? str(pp.spanId),
      }),
    };
  }

  // --- Cloud Audit Logs ---
  if (ppType === "type.googleapis.com/google.cloud.audit.AuditLog" && pp) {
    const method = str(pp.methodName) ?? "unknown";
    const service = str(pp.serviceName) ?? "unknown";
    const code = num(pp.status?.code);
    const isPolicyDenied = !!logId?.endsWith("policy");
    const cats = gcpAuditCategories(method, service);
    if (isPolicyDenied || code === 7) cats.push("policy.denied");
    const auditKind = logId?.split("%2F").pop()?.split("/").pop() ?? logId;
    return {
      ...base,
      resourceId: str(pp.resourceName),
      serviceName: service,
      principal: str(pp.authenticationInfo?.principalEmail) ?? str(pp.authenticationInfo?.principalSubject),
      sourceIp: str(pp.requestMetadata?.callerIp),
      destinationIp: null,
      action: method,
      status: isPolicyDenied || code === 7 ? "blocked" : code === null || code === 0 ? "success" : "failure",
      httpStatus: null,
      httpMethod: null,
      urlPath: null,
      userAgent: str(pp.requestMetadata?.callerSuppliedUserAgent),
      traceId: traceIdOf(e.trace),
      requestId: e.operation?.id ?? null,
      normalizedEventType: cats.includes("iam.credential_create") ? "iam.credential_create"
        : cats.includes("logging.config_change") ? "logging.config_change"
        : cats.includes("firewall.change") ? "firewall.change"
        : cats.includes("security_policy.change") ? "security_policy.change"
        : cats.includes("iam.change") ? "iam.change" : "cloud.api_call",
      categories: cats,
      normalized: redactDeep({
        ocsf: { class_uid: 6003, class_name: "API Activity" },
        audit: {
          log: auditKind, method, service, status_code: code, status_message: str(pp.status?.message),
          authorization: Array.isArray(pp.authorizationInfo) ? pp.authorizationInfo.slice(0, 10) : null,
          request: pp.request ?? null,
        },
      }),
    };
  }

  // --- HTTP(S) load balancer / Cloud Armor ---
  if (resType === "http_load_balancer" && e.httpRequest) {
    const hr = e.httpRequest;
    const { path, query } = splitUrl(str(hr.requestUrl));
    const status = num(hr.status);
    const armor = e.jsonPayload?.enforcedSecurityPolicy;
    const blocked = armor?.outcome === "DENY";
    const cats = httpCategories(status, path, str(hr.requestMethod));
    if (blocked) cats.push("policy.denied");
    return {
      ...base,
      resourceId: labels.url_map_name ?? labels.forwarding_rule_name ?? null,
      serviceName: labels.backend_service_name ?? null,
      principal: null,
      sourceIp: str(hr.remoteIp),
      destinationIp: str(hr.serverIp),
      action: hr.requestMethod && path ? `${hr.requestMethod} ${path}` : null,
      status: blocked ? "blocked" : status === null ? null : status >= 400 ? "failure" : "success",
      httpStatus: status,
      httpMethod: str(hr.requestMethod),
      urlPath: path,
      userAgent: str(hr.userAgent),
      traceId: traceIdOf(e.trace),
      requestId: null,
      normalizedEventType: "http.request",
      categories: cats,
      normalized: redactDeep({ ocsf: { class_uid: 4002, class_name: "HTTP Activity" }, http: { query, latency: hr.latency ?? null }, cloud_armor: armor ?? null }),
    };
  }

  // --- VPC flow logs ---
  if (logId?.endsWith("vpc_flows") && e.jsonPayload?.connection) {
    const c = e.jsonPayload.connection;
    const reporter = str(e.jsonPayload.reporter);
    const cats: EventCategory[] = ["network.flow"];
    if (reporter === "SRC" && e.jsonPayload.dest_location) cats.push("network.egress");
    return {
      ...base,
      resourceId: labels.subnetwork_name ?? null,
      serviceName: "vpc",
      principal: null,
      sourceIp: str(c.src_ip),
      destinationIp: str(c.dest_ip),
      action: "flow",
      status: null,
      httpStatus: null, httpMethod: null, urlPath: null, userAgent: null,
      traceId: null, requestId: null,
      normalizedEventType: "network.flow",
      categories: cats,
      normalized: { ocsf: { class_uid: 4001, class_name: "Network Activity" }, network: { src_port: num(c.src_port), dest_port: num(c.dest_port), protocol: num(c.protocol), bytes_sent: num(e.jsonPayload.bytes_sent), packets_sent: num(e.jsonPayload.packets_sent), reporter } },
    };
  }

  // --- Application logs (stdout/stderr/app logs) and anything else ---
  const text = e.textPayload ?? (e.jsonPayload ? (str(e.jsonPayload.message) ?? JSON.stringify(e.jsonPayload)) : null);
  return {
    ...base,
    resourceId: [labels.module_id, labels.version_id].filter(Boolean).join("/") || null,
    serviceName: labels.module_id ?? labels.service_name ?? null,
    principal: null,
    sourceIp: null,
    destinationIp: null,
    action: null,
    status: null,
    httpStatus: null, httpMethod: null, urlPath: null, userAgent: null,
    traceId: traceIdOf(e.trace),
    requestId: e.operation?.id ?? null,
    normalizedEventType: "app.log",
    categories: ["app.log"],
    normalized: {
      ocsf: { class_uid: 1007, class_name: "Process Activity / application log" },
      message: text ? redactString(text.slice(0, 8000)) : null,
      json: e.jsonPayload ? redactDeep(e.jsonPayload) : null,
      labels: e.labels ?? null,
    },
  };
}

/** Classify a GCP log id into a source type key used for log_sources. */
export function gcpSourceTypeForLog(logId: string, resourceType?: string): string {
  if (logId.endsWith("cloudaudit.googleapis.com/activity")) return "gcp_audit_admin_activity";
  if (logId.endsWith("cloudaudit.googleapis.com/system_event")) return "gcp_audit_system_event";
  if (logId.endsWith("cloudaudit.googleapis.com/policy")) return "gcp_audit_policy_denied";
  if (logId.endsWith("cloudaudit.googleapis.com/data_access")) return "gcp_audit_data_access";
  if (logId.endsWith("compute.googleapis.com/vpc_flows")) return "gcp_vpc_flow";
  if (logId.endsWith("requests") && resourceType === "http_load_balancer") return "gcp_load_balancer";
  if (logId.startsWith("appengine.googleapis.com") || resourceType === "gae_app") return "gcp_gae_app";
  return "gcp_log";
}
