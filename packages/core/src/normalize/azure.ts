import type { CanonicalEvent, EventCategory, Severity } from "../types.js";
import { redactDeep } from "../redact.js";

/**
 * Azure / Entra ID normalization. Inputs are untrusted and come in two shapes per source:
 *  - REST/Graph (camelCase: Activity Log `eventtypes/management/values`, Graph `auditLogs/*`, Defender `alerts`);
 *  - exported/diagnostic (Log Analytics tables, Event Hub / storage / Datadog / New Relic forwarding: PascalCase or
 *    `time`/`resultType`/`callerIpAddress`).
 * Field lookup is case-insensitive so one normalizer handles both. Absent values are null — never invented.
 */

type Obj = Record<string, any>;

/** Case-insensitive property access over one or more candidate names. */
export function ci(o: unknown, ...names: string[]): any {
  if (!o || typeof o !== "object") return undefined;
  const rec = o as Obj;
  for (const n of names) if (rec[n] !== undefined && rec[n] !== null) return rec[n];
  const lower = new Map(Object.keys(rec).map((k) => [k.toLowerCase(), k]));
  for (const n of names) { const k = lower.get(n.toLowerCase()); if (k !== undefined && rec[k] !== undefined && rec[k] !== null) return rec[k]; }
  return undefined;
}
const str = (v: unknown): string | null => (typeof v === "string" && v.length > 0 ? v : typeof v === "number" ? String(v) : null);
const num = (v: unknown): number | null => { const n = typeof v === "string" && v.trim() !== "" ? Number(v) : v; return typeof n === "number" && Number.isFinite(n) ? n : null; };
/** REST wraps many values as { value, localizedValue }. */
const val = (v: unknown): string | null => str(v && typeof v === "object" ? (v as Obj).value : v);
/** Log Analytics returns `dynamic` columns as JSON strings. */
const dyn = (v: unknown): any => { if (typeof v === "string" && /^[[{]/.test(v.trim())) { try { return JSON.parse(v); } catch { return v; } } return v; };
const isIp = (s: string | null) => !!s && (/^(\d{1,3}\.){3}\d{1,3}$/.test(s) || (/^[0-9a-f:]+$/i.test(s) && s.includes(":")));
const ip = (v: unknown) => { const s = str(v); return s && isIp(s) ? s : null; };
const iso = (v: unknown): string => {
  const s = str(v);
  const d = s ? new Date(s) : null;
  if (!d || Number.isNaN(d.getTime())) throw new Error("Azure record without a valid timestamp");
  return d.toISOString();
};

const LEVEL: Record<string, Severity> = { critical: "critical", error: "high", warning: "medium", informational: "info", information: "info", verbose: "info" };

/** Well-known built-in Azure RBAC role definition ids (stable across tenants). */
export const AZURE_BUILTIN_ROLES: Record<string, string> = {
  "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
  "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
  "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
  "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
  "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
  "43d0d8ad-25c7-4714-9337-8ba259a9fe05": "Monitoring Reader",
  "73c42c96-874c-492b-b04d-ab87d138a893": "Log Analytics Reader",
};

/** Activity Log operation → categories. Operation names are compared lowercased. */
export function azureActivityCategories(operation: string, opts: { denied: boolean }): EventCategory[] {
  const op = operation.toLowerCase();
  const c: EventCategory[] = ["cloud.api_call"];
  if (/^microsoft\.authorization\/roleassignments\/(write|delete)$/.test(op)) { c.push("iam.change"); if (op.endsWith("/write")) c.push("iam.privilege_grant"); }
  else if (/^microsoft\.authorization\/elevateaccess\/action$/.test(op)) c.push("iam.change", "iam.privilege_grant");
  else if (/^microsoft\.authorization\/roledefinitions\/(write|delete)$/.test(op)) c.push("iam.change");
  if (/^microsoft\.managedidentity\/userassignedidentities\/(write|federatedidentitycredentials\/write)$/.test(op) || /\/regeneratekey\/action$/.test(op)) c.push("iam.credential_create", "iam.change");
  if (/^microsoft\.network\/(networksecuritygroups(\/securityrules)?|azurefirewalls|firewallpolicies(\/rulecollectiongroups)?|applicationsecuritygroups)\/(write|delete)$/.test(op)) c.push("firewall.change");
  if (/^microsoft\.network\/(frontdoorwebapplicationfirewallpolicies|applicationgatewaywebapplicationfirewallpolicies|ddosprotectionplans)\/(write|delete)$/.test(op)
    || /^microsoft\.security\/(pricings|securitycontacts|autoprovisioningsettings|workspacesettings|settings)\/(write|delete)$/.test(op)
    || /^microsoft\.authorization\/(policyassignments|policyexemptions|locks)\/(write|delete)$/.test(op)) c.push("security_policy.change");
  if (/^microsoft\.insights\/(diagnosticsettings|logprofiles|activitylogalerts|datacollectionrules|datacollectionruleassociations)\/(write|delete)$/.test(op)
    || /^microsoft\.aadiam\/diagnosticsettings\/(write|delete)$/.test(op)
    || /^microsoft\.operationalinsights\/workspaces\/(delete|purge\/action|tables\/delete|datasources\/delete)$/.test(op)) c.push("logging.config_change");
  if (opts.denied) c.push("policy.denied");
  return c;
}

const PRIMARY = ["iam.credential_create", "logging.config_change", "firewall.change", "security_policy.change", "iam.change"] as const;
const primaryOf = (cats: EventCategory[], fallback: string) => PRIMARY.find((p) => cats.includes(p)) ?? fallback;

function roleFromRequestBody(body: unknown): { roleDefinitionId: string | null; principalId: string | null; principalType: string | null } {
  const b = dyn(body);
  const props = b && typeof b === "object" ? (b.properties ?? b.Properties ?? {}) : {};
  const rdid = str(props.roleDefinitionId);
  return { roleDefinitionId: rdid ? rdid.split("/").pop()!.toLowerCase() : null, principalId: str(props.principalId), principalType: str(props.principalType) };
}

function resourceTypeFromId(id: string | null): string | null {
  if (!id) return null;
  const m = /\/providers\/([^/]+)\/([^/]+)/i.exec(id);
  return m ? `${m[1]}/${m[2]}` : null;
}
const subscriptionFromId = (id: string | null) => (id ? /\/subscriptions\/([0-9a-f-]{36})/i.exec(id)?.[1] ?? null : null);

/** Azure Activity Log record (REST `eventtypes/management/values` or diagnostic/exported schema). */
export function normalizeAzureActivity(r: Obj, opts: { subscriptionId?: string; sourceType?: string } = {}): CanonicalEvent {
  const operation = val(ci(r, "operationName", "OperationNameValue")) ?? "unknown";
  const statusRaw = val(ci(r, "status", "ActivityStatusValue")) ?? str(ci(r, "resultType"));
  const subStatus = val(ci(r, "subStatus", "ActivitySubstatusValue")) ?? str(ci(r, "resultSignature"));
  const props = dyn(ci(r, "properties", "Properties")) ?? {};
  const http = dyn(ci(r, "httpRequest", "HTTPRequest")) ?? {};
  const category = val(ci(r, "category", "CategoryValue"));
  const denied = /^forbidden$/i.test(subStatus ?? "") || /^forbidden$/i.test(str(props?.statusCode) ?? "")
    || (/policy/i.test(category ?? "") && /\/deny\/action$/i.test(operation));
  const cats = azureActivityCategories(operation, { denied });
  const s = (statusRaw ?? "").toLowerCase();
  const status = denied ? "blocked" : /^(succeeded|success)$/.test(s) ? "success" : /^(failed|failure)$/.test(s) ? "failure" : statusRaw ? "unknown" : null;
  const resourceId = str(ci(r, "resourceId", "ResourceId", "_ResourceId"));
  const claims = dyn(ci(r, "claims")) ?? dyn(ci(ci(r, "identity"), "claims")) ?? {};
  const principal = str(ci(r, "caller", "Caller")) ?? str(claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]) ?? str(claims.oid);
  const role = /roleassignments\/write$/i.test(operation) ? roleFromRequestBody(props?.requestbody ?? props?.requestBody) : null;
  const location = str(ci(r, "location"));
  return {
    cloudProvider: "azure",
    projectOrAccountReference: str(ci(r, "subscriptionId", "SubscriptionId")) ?? subscriptionFromId(resourceId) ?? opts.subscriptionId ?? null,
    region: location && location.toLowerCase() !== "global" ? location.toLowerCase() : null,
    sourceType: opts.sourceType ?? "azure_activity_log",
    sourceName: "activity_log",
    eventTimestamp: iso(ci(r, "eventTimestamp", "time", "TimeGenerated")),
    resourceType: val(ci(r, "resourceType")) ?? resourceTypeFromId(resourceId),
    resourceId,
    serviceName: val(ci(r, "resourceProviderName", "ResourceProviderValue")) ?? operation.split("/")[0] ?? null,
    severity: LEVEL[(str(ci(r, "level", "Level")) ?? "").toLowerCase()] ?? null,
    principal,
    sourceIp: ip(http?.clientIpAddress) ?? ip(ci(r, "callerIpAddress", "CallerIpAddress")),
    destinationIp: null,
    action: operation,
    status,
    httpStatus: null, httpMethod: null, urlPath: null, userAgent: null,
    traceId: str(ci(r, "correlationId", "CorrelationId")),
    requestId: str(http?.clientRequestId),
    normalizedEventType: primaryOf(cats, "cloud.api_call"),
    categories: cats,
    providerEventId: str(ci(r, "eventDataId", "EventDataId")),
    normalized: redactDeep({
      ocsf: { class_uid: 6003, class_name: "API Activity" },
      azure: {
        operation: operation.toLowerCase(), status_raw: statusRaw, sub_status: subStatus, category, http_method: str(http?.method),
        caller_role: str(ci(ci(r, "authorization"), "evidence")?.role),
        role_definition_id: role?.roleDefinitionId ?? null,
        role_name: role?.roleDefinitionId ? AZURE_BUILTIN_ROLES[role.roleDefinitionId] ?? null : null,
        assignee_principal_id: role?.principalId ?? null, assignee_principal_type: role?.principalType ?? null,
        status_code: str(props?.statusCode), message: str(props?.message),
      },
    }),
  };
}

/** Sign-in error codes that are interruptions (MFA/consent prompts), not failed authentications. */
const INTERRUPT_CODES = new Set([50074, 50076, 50079, 50125, 50140, 50158, 50072, 50097, 81010, 81014]);

/** Entra ID sign-in (Graph `auditLogs/signIns` or Log Analytics `SigninLogs`). */
export function normalizeEntraSignIn(r: Obj, opts: { tenantId?: string; sourceType?: string } = {}): CanonicalEvent {
  const st = dyn(ci(r, "status", "Status")) ?? {};
  const code = num(st?.errorCode) ?? num(ci(r, "ResultType"));
  const caStatus = str(ci(r, "conditionalAccessStatus", "ConditionalAccessStatus"));
  const blocked = code === 53003 || caStatus?.toLowerCase() === "failure";
  const cats: EventCategory[] = [];
  let status: string | null;
  let type: string;
  if (code === 0) { cats.push("auth.success"); status = "success"; type = "auth.success"; }
  else if (code !== null && INTERRUPT_CODES.has(code)) { status = "unknown"; type = "auth.interrupted"; }
  else if (code !== null) { cats.push("auth.failure"); status = blocked ? "blocked" : "failure"; type = "auth.failure"; }
  else { status = null; type = "auth.unknown"; }
  if (blocked) cats.push("policy.denied");
  const loc = dyn(ci(r, "location", "LocationDetails")) ?? {};
  const app = str(ci(r, "appDisplayName", "AppDisplayName"));
  return {
    cloudProvider: "azure",
    projectOrAccountReference: str(ci(r, "tenantId", "AADTenantId", "TenantId")) ?? opts.tenantId ?? null,
    region: null,
    sourceType: opts.sourceType ?? "azure_entra_signin",
    sourceName: "entra_signin",
    eventTimestamp: iso(ci(r, "createdDateTime", "CreatedDateTime", "TimeGenerated")),
    resourceType: "entra_application",
    resourceId: str(ci(r, "appId", "AppId")),
    serviceName: "entra_id",
    severity: null,
    principal: str(ci(r, "userPrincipalName", "UserPrincipalName")) ?? str(ci(r, "userId", "UserId")),
    sourceIp: ip(ci(r, "ipAddress", "IPAddress")),
    destinationIp: null,
    action: app ? `SignIn ${app}` : "SignIn",
    status,
    httpStatus: null, httpMethod: null, urlPath: null,
    userAgent: str(ci(r, "userAgent", "UserAgent")),
    traceId: str(ci(r, "correlationId", "CorrelationId")),
    requestId: null,
    normalizedEventType: type,
    categories: cats,
    providerEventId: str(ci(r, "id", "Id")),
    normalized: redactDeep({
      ocsf: { class_uid: 3002, class_name: "Authentication" },
      entra: {
        error_code: code, failure_reason: str(st?.failureReason) ?? str(ci(r, "ResultDescription")),
        app, client_app: str(ci(r, "clientAppUsed", "ClientAppUsed")), resource: str(ci(r, "resourceDisplayName", "ResourceDisplayName")),
        conditional_access_status: caStatus, risk_level: str(ci(r, "riskLevelDuringSignIn", "RiskLevelDuringSignIn")), risk_state: str(ci(r, "riskState", "RiskState")),
        interactive: typeof ci(r, "isInteractive", "IsInteractive") === "boolean" ? ci(r, "isInteractive", "IsInteractive") : null,
        location: { city: str(loc?.city), country: str(loc?.countryOrRegion) },
        user_id: str(ci(r, "userId", "UserId")),
      },
    }),
  };
}

const ROLE_GRANT = /^(add (eligible |scoped )?member to role|add app role assignment (grant )?to (service principal|user|group)|add delegated permission grant|consent to application)/i;
const CRED_CREATE = /^(add service principal credentials|update application – certificates and secrets management|update application - certificates and secrets management|add user)$/i;
const IAM_CATEGORIES = new Set(["rolemanagement", "usermanagement", "applicationmanagement", "groupmanagement", "directorymanagement"]);

function modifiedValue(target: Obj | undefined, name: string): string | null {
  const mods = target ? (ci(target, "modifiedProperties") ?? []) : [];
  for (const m of Array.isArray(mods) ? mods : []) {
    if (String(ci(m, "displayName") ?? "").toLowerCase() === name.toLowerCase()) {
      const v = str(ci(m, "newValue"));
      return v ? v.replace(/^"+|"+$/g, "") : null;
    }
  }
  return null;
}

/** Entra ID directory audit (Graph `auditLogs/directoryAudits` or Log Analytics `AuditLogs`). */
export function normalizeEntraAudit(r: Obj, opts: { tenantId?: string; sourceType?: string } = {}): CanonicalEvent {
  const activity = str(ci(r, "activityDisplayName", "OperationName")) ?? "unknown";
  const category = str(ci(r, "category", "Category"));
  const result = (str(ci(r, "result", "Result")) ?? "").toLowerCase();
  const by = dyn(ci(r, "initiatedBy", "InitiatedBy")) ?? {};
  const targets = dyn(ci(r, "targetResources", "TargetResources"));
  const target: Obj | undefined = Array.isArray(targets) ? targets[0] : undefined;
  const cats: EventCategory[] = ["cloud.api_call"];
  if (CRED_CREATE.test(activity)) cats.push("iam.credential_create", "iam.change");
  else if (category && IAM_CATEGORIES.has(category.toLowerCase())) cats.push("iam.change");
  if (ROLE_GRANT.test(activity)) { if (!cats.includes("iam.change")) cats.push("iam.change"); cats.push("iam.privilege_grant"); }
  if (/conditional access policy|authentication methods policy|security defaults/i.test(activity)) cats.push("security_policy.change");
  const roleName = ROLE_GRANT.test(activity) ? (modifiedValue(target, "Role.DisplayName") ?? (target && /role/i.test(String(ci(target, "type") ?? "")) ? str(ci(target, "displayName")) : null)) : null;
  const user = by?.user ?? by?.User;
  const app = by?.app ?? by?.App;
  return {
    cloudProvider: "azure",
    projectOrAccountReference: str(ci(r, "tenantId", "AADTenantId", "TenantId")) ?? opts.tenantId ?? null,
    region: null,
    sourceType: opts.sourceType ?? "azure_entra_audit",
    sourceName: "entra_audit",
    eventTimestamp: iso(ci(r, "activityDateTime", "ActivityDateTime", "TimeGenerated")),
    resourceType: target ? `entra_${String(ci(target, "type") ?? "object").toLowerCase()}` : null,
    resourceId: target ? str(ci(target, "id")) : null,
    serviceName: str(ci(r, "loggedByService", "LoggedByService")) ?? "entra_id",
    severity: null,
    principal: str(ci(user, "userPrincipalName")) ?? str(ci(app, "displayName")) ?? str(ci(app, "servicePrincipalId")),
    sourceIp: ip(ci(user, "ipAddress")),
    destinationIp: null,
    action: activity,
    status: result === "success" ? "success" : result === "failure" ? "failure" : result ? "unknown" : null,
    httpStatus: null, httpMethod: null, urlPath: null, userAgent: null,
    traceId: str(ci(r, "correlationId", "CorrelationId")),
    requestId: null,
    normalizedEventType: primaryOf(cats, "cloud.api_call"),
    categories: cats,
    providerEventId: str(ci(r, "id", "Id")),
    normalized: redactDeep({
      ocsf: { class_uid: 6003, class_name: "API Activity" },
      entra: {
        activity, category, operation_type: str(ci(r, "operationType", "OperationType")), result: result || null,
        result_reason: str(ci(r, "resultReason", "ResultReason")), role_name: roleName,
        target: target ? { type: str(ci(target, "type")), id: str(ci(target, "id")), display_name: str(ci(target, "displayName")), upn: str(ci(target, "userPrincipalName")) } : null,
        initiated_by_app: str(ci(app, "displayName")),
      },
    }),
  };
}

const ALERT_SEV: Record<string, Severity> = { high: "high", medium: "medium", low: "low", informational: "info", critical: "critical" };

/** Microsoft Defender for Cloud alert (`Microsoft.Security/alerts`). */
export function normalizeDefenderAlert(r: Obj, opts: { subscriptionId?: string; sourceType?: string } = {}): CanonicalEvent {
  const p = ci(r, "properties") ?? r;
  const entities: Obj[] = Array.isArray(ci(p, "entities")) ? ci(p, "entities") : [];
  const ent = (type: string) => entities.find((e) => String(ci(e, "type") ?? "").toLowerCase() === type);
  const acct = ent("account");
  const resIds: Obj[] = Array.isArray(ci(p, "resourceIdentifiers")) ? ci(p, "resourceIdentifiers") : [];
  const resourceId = str(ci(resIds.find((x) => ci(x, "azureResourceId")), "azureResourceId")) ?? str(ci(p, "compromisedEntity"));
  return {
    cloudProvider: "azure",
    projectOrAccountReference: subscriptionFromId(str(ci(r, "id"))) ?? subscriptionFromId(resourceId) ?? opts.subscriptionId ?? null,
    region: null,
    sourceType: opts.sourceType ?? "azure_defender_alerts",
    sourceName: "defender_for_cloud",
    eventTimestamp: iso(ci(p, "timeGeneratedUtc", "startTimeUtc", "TimeGenerated")),
    resourceType: resourceTypeFromId(resourceId),
    resourceId,
    serviceName: str(ci(p, "productName")) ?? "defender_for_cloud",
    severity: ALERT_SEV[(str(ci(p, "severity")) ?? "").toLowerCase()] ?? null,
    principal: acct ? (str(ci(acct, "upn")) ?? (str(ci(acct, "name")) && str(ci(acct, "upnSuffix")) ? `${ci(acct, "name")}@${ci(acct, "upnSuffix")}` : str(ci(acct, "name")))) : null,
    sourceIp: ip(ci(ent("ip"), "address")),
    destinationIp: null,
    action: str(ci(p, "alertType")),
    status: null,
    httpStatus: null, httpMethod: null, urlPath: null, userAgent: null,
    traceId: null, requestId: null,
    normalizedEventType: "security.finding",
    categories: ["security.finding"],
    providerEventId: str(ci(p, "systemAlertId")) ?? str(ci(r, "id")),
    normalized: redactDeep({
      ocsf: { class_uid: 2004, class_name: "Detection Finding" },
      finding: {
        title: str(ci(p, "alertDisplayName")), description: str(ci(p, "description")), alert_status: str(ci(p, "status")),
        intent: str(ci(p, "intent")), compromised_entity: str(ci(p, "compromisedEntity")), product: str(ci(p, "productName")),
        remediation: Array.isArray(ci(p, "remediationSteps")) ? ci(p, "remediationSteps").slice(0, 10) : null,
      },
    }),
  };
}

/** Heuristic shape detection used by log-platform connectors to delegate forwarded Azure records. */
export function looksLikeAzureActivity(r: Obj): boolean {
  const op = val(ci(r, "operationName"));
  return !!op && /^microsoft\.[a-z]+\//i.test(op) && !!(ci(r, "resourceId") || ci(r, "eventDataId")) && !!ci(r, "eventTimestamp", "time");
}
