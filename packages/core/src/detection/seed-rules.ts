import type { RuleDefinition } from "./dsl.js";

/**
 * Initial detection content. Provider-independent rules work on normalized categories;
 * provider-specific rules set `provider` and never leak into the common set.
 */
export const SEED_RULES: RuleDefinition[] = [
  {
    ruleId: "VGL-IAM-001", name: "Unusual IAM activity",
    description: "IAM policy, role or identity changes. Any such change in a monitored project is surfaced for review; known automation can be suppressed via approved knowledge (trusted_identity).",
    provider: "any", eventSources: [],
    detectionQuery: { kind: "match", where: { field: "categories", op: "contains", value: "iam.change" }, groupBy: ["principal"], windowMinutes: 60 },
    conditions: {}, severity: "medium", confidence: 0.6, enabled: true,
    mitre: [{ tactic: "Persistence", technique: "T1098", name: "Account Manipulation" }],
  },
  {
    ruleId: "VGL-IAM-002", name: "Service account or access key created",
    description: "Creation of long-lived credentials (GCP service account / key, AWS user / access key).",
    provider: "any", eventSources: [],
    detectionQuery: { kind: "match", where: { all: [{ field: "categories", op: "contains", value: "iam.credential_create" }, { field: "status", op: "eq", value: "success" }] }, groupBy: ["principal"], windowMinutes: 60 },
    conditions: {}, severity: "high", confidence: 0.75, enabled: true,
    mitre: [{ tactic: "Persistence", technique: "T1098.001", name: "Additional Cloud Credentials" }, { tactic: "Persistence", technique: "T1136.003", name: "Create Cloud Account" }],
  },
  {
    ruleId: "VGL-AUTH-001", name: "Repeated authentication failures",
    description: "≥10 authentication failures from one source IP within 10 minutes (brute force / credential stuffing).",
    provider: "any", eventSources: [],
    detectionQuery: { kind: "threshold", where: { field: "categories", op: "contains", value: "auth.failure" }, groupBy: ["sourceIp"], windowMinutes: 10, minCount: 10 },
    conditions: {}, severity: "high", confidence: 0.7, enabled: true,
    mitre: [{ tactic: "Credential Access", technique: "T1110", name: "Brute Force" }],
  },
  {
    ruleId: "VGL-HTTP-001", name: "Suspicious administrative endpoint access",
    description: "≥3 requests from one IP within 60 minutes to well-known admin/sensitive paths that this class of app should not expose (.env, .git, wp-admin, phpMyAdmin, actuator, server-status…).",
    provider: "any", eventSources: [],
    detectionQuery: {
      kind: "threshold",
      where: { all: [
        { field: "normalizedEventType", op: "eq", value: "http.request" },
        { field: "urlPath", op: "regex", value: "(?i)(^|/)(\\.env|\\.git|\\.aws|\\.ssh|wp-admin|wp-login\\.php|xmlrpc\\.php|phpmyadmin|pma|actuator|server-status|jmx-console|manager/html|cgi-bin|boaform|HNAP1|\\.DS_Store|config\\.json|web\\.config|admin(/|$)|administrator)" },
      ] },
      groupBy: ["sourceIp"], windowMinutes: 60, minCount: 3,
    },
    conditions: {}, severity: "medium", confidence: 0.7, enabled: true,
    mitre: [{ tactic: "Reconnaissance", technique: "T1595.003", name: "Wordlist Scanning" }, { tactic: "Initial Access", technique: "T1190", name: "Exploit Public-Facing Application" }],
  },
  {
    ruleId: "VGL-HTTP-002", name: "Excessive HTTP 404 responses (possible reconnaissance)",
    description: "≥30 HTTP 404 responses to one source IP within 10 minutes.",
    provider: "any", eventSources: [],
    detectionQuery: { kind: "threshold", where: { field: "httpStatus", op: "eq", value: 404 }, groupBy: ["sourceIp"], windowMinutes: 10, minCount: 30 },
    conditions: {}, severity: "medium", confidence: 0.65, enabled: true,
    mitre: [{ tactic: "Reconnaissance", technique: "T1595", name: "Active Scanning" }],
  },
  {
    ruleId: "VGL-HTTP-003", name: "Unusual HTTP 5xx spike",
    description: "5-minute count of 5xx responses per service ≥3× the trailing 1-hour average (min 20).",
    provider: "any", eventSources: [],
    detectionQuery: { kind: "rate_spike", where: { field: "httpStatus", op: "gte", value: 500 }, groupBy: ["serviceName"], bucketMinutes: 5, baselineBuckets: 12, factor: 3, minCount: 20 },
    conditions: {}, severity: "medium", confidence: 0.5, enabled: true,
    mitre: [{ tactic: "Impact", technique: "T1499", name: "Endpoint Denial of Service" }],
  },
  {
    ruleId: "VGL-NET-001", name: "Suspicious outbound traffic",
    description: "Egress flows to ports commonly used by remote-access tools, IRC or reverse shells.",
    provider: "any", eventSources: [],
    detectionQuery: { kind: "match", where: { all: [{ field: "categories", op: "contains", value: "network.egress" }, { field: "normalized.network.dest_port", op: "in", value: [23, 1337, 4444, 5555, 6667, 6697, 31337, 9001, 3389] }] }, groupBy: ["sourceIp", "destinationIp"], windowMinutes: 60 },
    conditions: {}, severity: "high", confidence: 0.6, enabled: true,
    mitre: [{ tactic: "Command and Control", technique: "T1571", name: "Non-Standard Port" }, { tactic: "Exfiltration", technique: "T1041" }],
  },
  {
    ruleId: "VGL-NET-002", name: "Repeated port scanning",
    description: "One source IP touching ≥20 distinct destination ports within 5 minutes.",
    provider: "any", eventSources: [],
    detectionQuery: { kind: "distinct", where: { field: "categories", op: "contains", value: "network.flow" }, groupBy: ["sourceIp"], field: "normalized.network.dest_port", windowMinutes: 5, minDistinct: 20 },
    conditions: {}, severity: "medium", confidence: 0.7, enabled: true,
    mitre: [{ tactic: "Discovery", technique: "T1046", name: "Network Service Discovery" }],
  },
  {
    ruleId: "VGL-CFG-001", name: "Security policy or firewall modification",
    description: "Firewall rule, security group, WAF/Cloud Armor or detector configuration changed.",
    provider: "any", eventSources: [],
    detectionQuery: { kind: "match", where: { any: [{ field: "categories", op: "contains", value: "firewall.change" }, { field: "categories", op: "contains", value: "security_policy.change" }] }, groupBy: ["principal"], windowMinutes: 60 },
    conditions: {}, severity: "high", confidence: 0.7, enabled: true,
    mitre: [{ tactic: "Defense Evasion", technique: "T1562.007", name: "Disable or Modify Cloud Firewall" }],
  },
  {
    ruleId: "VGL-CFG-002", name: "Security logging disabled or altered",
    description: "Audit/trail/sink/flow-log configuration deleted or modified.",
    provider: "any", eventSources: [],
    detectionQuery: { kind: "match", where: { all: [{ field: "categories", op: "contains", value: "logging.config_change" }, { field: "status", op: "eq", value: "success" }] }, groupBy: ["principal"], windowMinutes: 60 },
    conditions: {}, severity: "critical", confidence: 0.85, enabled: true,
    mitre: [{ tactic: "Defense Evasion", technique: "T1562.008", name: "Disable or Modify Cloud Logs" }],
  },
  // ---- provider-specific ----
  {
    ruleId: "VGL-GCP-001", name: "GCP policy-denied burst",
    description: "≥20 VPC-SC / org-policy denials for one principal or IP in 15 minutes (GCP policy audit log).",
    provider: "gcp", eventSources: ["gcp_audit_policy_denied"],
    detectionQuery: { kind: "threshold", where: { field: "categories", op: "contains", value: "policy.denied" }, groupBy: ["principal"], windowMinutes: 15, minCount: 20 },
    conditions: {}, severity: "medium", confidence: 0.6, enabled: true,
    mitre: [{ tactic: "Discovery", technique: "T1526", name: "Cloud Service Discovery" }],
  },
  {
    ruleId: "VGL-AWS-001", name: "AWS root account activity",
    description: "Any API call made with the AWS account root user.",
    provider: "aws", eventSources: [],
    detectionQuery: { kind: "match", where: { field: "normalized.aws.identity_type", op: "eq", value: "Root" }, groupBy: ["projectOrAccountReference"], windowMinutes: 60 },
    conditions: {}, severity: "high", confidence: 0.8, enabled: true,
    mitre: [{ tactic: "Privilege Escalation", technique: "T1078.004", name: "Cloud Accounts" }],
  },
  {
    ruleId: "VGL-AZ-001", name: "Azure privileged role assigned",
    description: "Owner / User Access Administrator / Contributor / RBAC Administrator granted on Azure RBAC, or a privileged Entra ID directory role (Global Administrator, Privileged Role Administrator, …) assigned.",
    provider: "azure", eventSources: [],
    detectionQuery: {
      kind: "match",
      where: { all: [
        { field: "status", op: "eq", value: "success" },
        { any: [
          { all: [{ field: "normalized.azure.operation", op: "eq", value: "microsoft.authorization/roleassignments/write" }, { field: "normalized.azure.role_name", op: "in", value: ["Owner", "User Access Administrator", "Contributor", "Role Based Access Control Administrator"] }] },
          { all: [{ field: "categories", op: "contains", value: "iam.privilege_grant" }, { field: "normalized.entra.role_name", op: "in", value: ["Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator", "Application Administrator", "Cloud Application Administrator", "User Administrator"] }] },
        ] },
      ] },
      groupBy: ["principal"], windowMinutes: 60,
    },
    conditions: {}, severity: "high", confidence: 0.75, enabled: true,
    mitre: [{ tactic: "Privilege Escalation", technique: "T1098.003", name: "Additional Cloud Roles" }],
  },
  {
    ruleId: "VGL-AZ-002", name: "Entra ID Conditional Access block burst",
    description: "≥20 sign-ins blocked by Conditional Access for one principal in 15 minutes (Entra ID sign-in logs).",
    provider: "azure", eventSources: ["azure_entra_signin"],
    detectionQuery: { kind: "threshold", where: { field: "categories", op: "contains", value: "policy.denied" }, groupBy: ["principal"], windowMinutes: 15, minCount: 20 },
    conditions: {}, severity: "medium", confidence: 0.6, enabled: true,
    mitre: [{ tactic: "Credential Access", technique: "T1110", name: "Brute Force" }, { tactic: "Initial Access", technique: "T1078.004", name: "Cloud Accounts" }],
  },
  {
    ruleId: "VGL-AZ-003", name: "Defender for Cloud high-severity alert",
    description: "Microsoft Defender for Cloud raised a high or critical alert for a monitored resource.",
    provider: "azure", eventSources: ["azure_defender_alerts"],
    detectionQuery: { kind: "match", where: { all: [{ field: "categories", op: "contains", value: "security.finding" }, { field: "severity", op: "in", value: ["high", "critical"] }] }, groupBy: ["resourceId"], windowMinutes: 60 },
    conditions: {}, severity: "high", confidence: 0.8, enabled: true,
    mitre: [],
  },
];
