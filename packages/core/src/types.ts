/**
 * Id of the connector (registry entry) a record originates from: "gcp", "aws", … Validated at runtime against
 * the connector registry (`packages/core/src/connectors/registry.ts`); kept as a string so new connectors need no
 * type or database-enum changes.
 */
export type ConnectorId = string;
/** @deprecated use ConnectorId — kept as an alias for existing call sites. */
export type CloudProvider = ConnectorId;
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export const SEVERITY_ORDER: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const maxSeverity = (a: Severity, b: Severity): Severity => (SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b);

/** Normalized categories used by provider-independent detections. */
export type EventCategory =
  | "http.request" | "http.client_error" | "http.server_error" | "http.not_found"
  | "auth.success" | "auth.failure"
  | "iam.change" | "iam.credential_create" | "iam.privilege_grant"
  | "firewall.change" | "security_policy.change" | "logging.config_change"
  | "network.flow" | "network.egress" | "policy.denied"
  | "cloud.api_call" | "app.log" | "security.finding";

/**
 * Canonical security event. Every field that the source does not provide is null —
 * values are never invented. `normalized` carries the OCSF hint and extra structured fields.
 */
export interface CanonicalEvent {
  cloudProvider: CloudProvider;
  projectOrAccountReference: string | null;
  region: string | null;
  sourceType: string;
  sourceName: string | null;
  eventTimestamp: string; // ISO-8601
  resourceType: string | null;
  resourceId: string | null;
  serviceName: string | null;
  severity: Severity | null;
  principal: string | null;
  sourceIp: string | null;
  destinationIp: string | null;
  action: string | null;
  status: string | null; // success | failure | blocked | unknown
  httpStatus: number | null;
  httpMethod: string | null;
  urlPath: string | null;
  userAgent: string | null;
  traceId: string | null;
  requestId: string | null;
  normalizedEventType: string;
  categories: EventCategory[];
  providerEventId: string | null;
  normalized: Record<string, unknown>;
}

/** Shape the detection engine evaluates (DB row or canonical + id). */
export interface DetectableEvent extends Omit<CanonicalEvent, "categories" | "providerEventId"> {
  id: string;
  categories?: string[];
}
