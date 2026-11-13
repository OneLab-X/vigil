import type { CanonicalEvent, EventCategory } from "../types.js";
import { redactDeep } from "../redact.js";

/** CloudTrail record (management events). All fields optional — untrusted input. */
export interface CloudTrailRecord {
  eventVersion?: string;
  eventID?: string;
  eventTime?: string;
  eventSource?: string;
  eventName?: string;
  awsRegion?: string;
  sourceIPAddress?: string;
  userAgent?: string;
  errorCode?: string;
  errorMessage?: string;
  requestID?: string;
  recipientAccountId?: string;
  readOnly?: boolean;
  eventType?: string;
  userIdentity?: { type?: string; arn?: string; principalId?: string; accountId?: string; userName?: string; invokedBy?: string };
  requestParameters?: Record<string, unknown> | null;
  responseElements?: Record<string, unknown> | null;
  resources?: Array<{ ARN?: string; type?: string }>;
  additionalEventData?: Record<string, unknown>;
}

const CRED_CREATE = new Set(["CreateAccessKey", "CreateUser", "CreateLoginProfile", "CreateServiceSpecificCredential", "CreateRole"]);
const IAM_CHANGE = /^(Attach|Detach|Put|Delete|Update|Create|Add|Remove)(User|Role|Group)?(Policy|PolicyVersion|UserToGroup|RolePolicy|UserPolicy|GroupPolicy|AssumeRolePolicy|Role|User|Group|LoginProfile|AccessKey)/;
const FIREWALL = new Set(["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress", "CreateSecurityGroup", "DeleteSecurityGroup", "ModifySecurityGroupRules", "CreateNetworkAclEntry", "ReplaceNetworkAclEntry", "DeleteNetworkAclEntry"]);
const SEC_POLICY = /^(UpdateWebACL|DeleteWebACL|DisableSecurityHub|DeleteDetector|UpdateDetector|DisassociateFromMasterAccount|StopMonitoringMembers|DeleteMembers|PutBucketPolicy|DeleteBucketPolicy|PutBucketPublicAccessBlock|DeletePublicAccessBlock)$/;
const LOGGING = /^(StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors|DeleteFlowLogs|DeleteLogGroup|DeleteLogStream|PutRetentionPolicy|DeleteConfigurationRecorder|StopConfigurationRecorder|DeleteDeliveryChannel)$/;

export function cloudTrailCategories(r: CloudTrailRecord): EventCategory[] {
  const name = r.eventName ?? "";
  const cats: EventCategory[] = ["cloud.api_call"];
  if (name === "ConsoleLogin") {
    const outcome = (r.responseElements as any)?.ConsoleLogin;
    cats.push(outcome === "Failure" || r.errorMessage ? "auth.failure" : "auth.success");
  }
  if (CRED_CREATE.has(name)) cats.push("iam.credential_create", "iam.change");
  else if (r.eventSource === "iam.amazonaws.com" && IAM_CHANGE.test(name)) cats.push("iam.change");
  if (/^(Attach|Put)(User|Role|Group)Policy$/.test(name)) cats.push("iam.privilege_grant");
  if (FIREWALL.has(name)) cats.push("firewall.change");
  if (SEC_POLICY.test(name)) cats.push("security_policy.change");
  if (LOGGING.test(name)) cats.push("logging.config_change");
  if (r.errorCode === "AccessDenied" || r.errorCode === "UnauthorizedOperation" || r.errorCode === "Client.UnauthorizedOperation") cats.push("policy.denied");
  return cats;
}

const isIp = (s: string | undefined) => !!s && /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+$/i.test(s);

export function normalizeCloudTrail(r: CloudTrailRecord, opts: { accountId?: string; sourceType?: string } = {}): CanonicalEvent {
  if (!r.eventTime) throw new Error("CloudTrail record without eventTime");
  const cats = cloudTrailCategories(r);
  const primary = (["iam.credential_create", "logging.config_change", "firewall.change", "security_policy.change", "iam.change", "auth.failure", "auth.success"] as const)
    .find((c) => cats.includes(c)) ?? "cloud.api_call";
  const denied = cats.includes("policy.denied");
  return {
    cloudProvider: "aws",
    projectOrAccountReference: r.recipientAccountId ?? r.userIdentity?.accountId ?? opts.accountId ?? null,
    region: r.awsRegion ?? null,
    sourceType: opts.sourceType ?? "aws_cloudtrail_management",
    sourceName: "cloudtrail",
    eventTimestamp: new Date(r.eventTime).toISOString(),
    resourceType: r.resources?.[0]?.type ?? null,
    resourceId: r.resources?.[0]?.ARN ?? null,
    serviceName: r.eventSource ?? null,
    severity: null,
    principal: r.userIdentity?.arn ?? r.userIdentity?.principalId ?? null,
    // sourceIPAddress may be an AWS service name (e.g. "ec2.amazonaws.com"): only keep real IPs.
    sourceIp: isIp(r.sourceIPAddress) ? r.sourceIPAddress! : null,
    destinationIp: null,
    action: r.eventName ?? null,
    status: denied ? "blocked" : r.errorCode ? "failure" : "success",
    httpStatus: null, httpMethod: null, urlPath: null,
    userAgent: r.userAgent ?? null,
    traceId: null,
    requestId: r.requestID ?? null,
    normalizedEventType: primary,
    categories: cats,
    providerEventId: r.eventID ?? null,
    normalized: redactDeep({
      ocsf: { class_uid: primary.startsWith("auth") ? 3002 : 6003, class_name: primary.startsWith("auth") ? "Authentication" : "API Activity" },
      aws: {
        event_source: r.eventSource ?? null, event_name: r.eventName ?? null, error_code: r.errorCode ?? null,
        error_message: r.errorMessage ?? null, read_only: r.readOnly ?? null, identity_type: r.userIdentity?.type ?? null,
        invoked_by: r.userIdentity?.invokedBy ?? null, source_ip_address_raw: r.sourceIPAddress ?? null,
        request_parameters: r.requestParameters ?? null,
      },
    }),
  };
}
