/**
 * SYNTHETIC Azure / Entra ID records in the vendors' REST shapes — never used on production paths.
 * IPs come from RFC 5737 documentation ranges; GUIDs are fixed test values.
 */
import { randomUUID } from "node:crypto";
import type { ConnectorScenario } from "./scenarios.js";

export const AZ_TENANT = "11111111-2222-3333-4444-555555555555";
export const AZ_SUB = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const OWNER_ROLE = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";

export function azureActivity(o: { ts: Date; operation: string; caller: string; ip: string; status?: "Succeeded" | "Failed" | "Started"; subStatus?: string; resourceId?: string; roleDefinitionId?: string; level?: string }) {
  const rid = o.resourceId ?? `/subscriptions/${AZ_SUB}/resourceGroups/prod-rg`;
  return {
    eventDataId: randomUUID(), correlationId: randomUUID(), eventTimestamp: o.ts.toISOString(), submissionTimestamp: o.ts.toISOString(),
    caller: o.caller, level: o.level ?? "Informational", subscriptionId: AZ_SUB, tenantId: AZ_TENANT,
    operationName: { value: o.operation, localizedValue: o.operation }, category: { value: "Administrative" },
    resourceProviderName: { value: o.operation.split("/")[0] }, resourceId: rid,
    status: { value: o.status ?? "Succeeded" }, subStatus: { value: o.subStatus ?? "" },
    httpRequest: { clientIpAddress: o.ip, method: "PUT", clientRequestId: randomUUID() },
    authorization: { action: o.operation, scope: rid, evidence: { role: "Contributor" } },
    properties: o.roleDefinitionId ? { requestbody: JSON.stringify({ Id: randomUUID(), Properties: { PrincipalId: randomUUID(), PrincipalType: "User", roleDefinitionId: `/subscriptions/${AZ_SUB}/providers/Microsoft.Authorization/roleDefinitions/${o.roleDefinitionId}`, principalId: randomUUID(), principalType: "User" } }), statusCode: "Created" } : { statusCode: o.status === "Failed" ? "Forbidden" : "OK" },
  };
}

export function entraSignIn(o: { ts: Date; upn: string; ip: string; errorCode: number; app?: string; ca?: "success" | "failure" | "notApplied"; failureReason?: string }) {
  return {
    id: randomUUID(), createdDateTime: o.ts.toISOString(), userPrincipalName: o.upn, userId: randomUUID(), appId: randomUUID(), appDisplayName: o.app ?? "Azure Portal",
    ipAddress: o.ip, clientAppUsed: "Browser", correlationId: randomUUID(), conditionalAccessStatus: o.ca ?? "notApplied", isInteractive: true,
    riskLevelDuringSignIn: "none", riskState: "none", resourceDisplayName: "Windows Azure Service Management API",
    status: { errorCode: o.errorCode, failureReason: o.failureReason ?? (o.errorCode === 0 ? null : "Invalid username or password or Invalid on-premise username or password.") },
    location: { city: "Example City", state: "EX", countryOrRegion: "ZZ" },
  };
}

export function entraAudit(o: { ts: Date; activity: string; category: string; initiator: string; ip: string; target?: { type: string; displayName: string; id?: string }; roleName?: string; result?: "success" | "failure" }) {
  return {
    id: `Directory_${randomUUID()}`, activityDateTime: o.ts.toISOString(), activityDisplayName: o.activity, category: o.category, operationType: "Add",
    result: o.result ?? "success", resultReason: "", loggedByService: "Core Directory", correlationId: randomUUID(),
    initiatedBy: { user: { id: randomUUID(), userPrincipalName: o.initiator, ipAddress: o.ip }, app: null },
    targetResources: [{
      id: o.target?.id ?? randomUUID(), displayName: o.target?.displayName ?? "target", type: o.target?.type ?? "User",
      modifiedProperties: o.roleName ? [{ displayName: "Role.DisplayName", oldValue: null, newValue: `"${o.roleName}"` }] : [],
    }],
  };
}

export function defenderAlert(o: { ts: Date; title: string; severity: "High" | "Medium" | "Low" | "Informational"; resourceId: string; ip?: string; account?: string }) {
  const id = randomUUID();
  return {
    id: `/subscriptions/${AZ_SUB}/resourceGroups/prod-rg/providers/Microsoft.Security/locations/westeurope/alerts/${id}`, name: id, type: "Microsoft.Security/Locations/alerts",
    properties: {
      systemAlertId: id, alertType: "VM_SuspiciousActivity", alertDisplayName: o.title, severity: o.severity, status: "Active", intent: "Execution",
      timeGeneratedUtc: o.ts.toISOString(), startTimeUtc: o.ts.toISOString(), compromisedEntity: o.resourceId.split("/").pop(), productName: "Microsoft Defender for Cloud",
      description: "Synthetic alert", resourceIdentifiers: [{ type: "AzureResource", azureResourceId: o.resourceId }],
      entities: [...(o.ip ? [{ type: "ip", address: o.ip }] : []), ...(o.account ? [{ type: "account", name: o.account.split("@")[0], upnSuffix: o.account.split("@")[1] }] : [])],
    },
  };
}

const at = (base: Date, s: number) => new Date(base.getTime() + s * 1000);

export function buildAzureScenarios(base = new Date(Date.now() - 2 * 3600_000)): ConnectorScenario[] {
  const brute = [
    ...Array.from({ length: 12 }, (_, i) => ({ sourceType: "azure_entra_signin", raw: entraSignIn({ ts: at(base, i * 15), upn: "admin@contoso.example", ip: "198.51.100.23", errorCode: 50126 }) })),
    { sourceType: "azure_entra_signin", raw: entraSignIn({ ts: at(base, 200), upn: "admin@contoso.example", ip: "198.51.100.23", errorCode: 0 }) },
  ];
  const vm = `/subscriptions/${AZ_SUB}/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/web-01`;
  const privesc = [
    { sourceType: "azure_activity_log", raw: azureActivity({ ts: at(base, 600), operation: "Microsoft.Authorization/roleAssignments/write", caller: "contractor@contoso.example", ip: "203.0.113.77", roleDefinitionId: OWNER_ROLE, resourceId: `/subscriptions/${AZ_SUB}/providers/Microsoft.Authorization/roleAssignments/${randomUUID()}` }) },
    { sourceType: "azure_activity_log", raw: azureActivity({ ts: at(base, 660), operation: "Microsoft.Insights/diagnosticSettings/delete", caller: "contractor@contoso.example", ip: "203.0.113.77", resourceId: `/subscriptions/${AZ_SUB}/providers/microsoft.insights/diagnosticSettings/to-siem` }) },
    { sourceType: "azure_activity_log", raw: azureActivity({ ts: at(base, 700), operation: "Microsoft.Network/networkSecurityGroups/securityRules/write", caller: "contractor@contoso.example", ip: "203.0.113.77", resourceId: `/subscriptions/${AZ_SUB}/resourceGroups/prod-rg/providers/Microsoft.Network/networkSecurityGroups/web-nsg/securityRules/allow-any-3389` }) },
  ];
  const spCred = [
    { sourceType: "azure_entra_audit", raw: entraAudit({ ts: at(base, 900), activity: "Add service principal credentials", category: "ApplicationManagement", initiator: "contractor@contoso.example", ip: "203.0.113.77", target: { type: "ServicePrincipal", displayName: "ci-deployer" } }) },
    { sourceType: "azure_entra_audit", raw: entraAudit({ ts: at(base, 960), activity: "Add member to role", category: "RoleManagement", initiator: "contractor@contoso.example", ip: "203.0.113.77", target: { type: "User", displayName: "backup-admin" }, roleName: "Global Administrator" }) },
  ];
  const caBlock = Array.from({ length: 25 }, (_, i) => ({ sourceType: "azure_entra_signin", raw: entraSignIn({ ts: at(base, 1200 + i * 20), upn: "travel@contoso.example", ip: "192.0.2.150", errorCode: 53003, ca: "failure", failureReason: "Access has been blocked by Conditional Access policies." }) }));
  const defender = [{ sourceType: "azure_defender_alerts", raw: defenderAlert({ ts: at(base, 1800), title: "Suspicious PowerShell command line", severity: "High", resourceId: vm, ip: "203.0.113.200", account: "svc-web@contoso.example" }) }];
  return [
    { id: "azure-signin-bruteforce", connector: "azure", description: "12 failed Entra sign-ins then a success from one IP", records: brute, expectedRules: ["VGL-AUTH-001"], expectedVerdict: "likely" },
    { id: "azure-privesc-tamper", connector: "azure", description: "Owner role granted, diagnostic setting deleted, NSG rule opened by a contractor", records: privesc, expectedRules: ["VGL-AZ-001", "VGL-IAM-001", "VGL-CFG-002", "VGL-CFG-001"], expectedVerdict: "confirmed" },
    { id: "azure-sp-credential-ga", connector: "azure", description: "Service principal secret added, then Global Administrator assigned", records: spCred, expectedRules: ["VGL-IAM-002", "VGL-IAM-001", "VGL-AZ-001"], expectedVerdict: "confirmed" },
    { id: "azure-ca-block-burst", connector: "azure", description: "25 Conditional Access blocks for one user", records: caBlock, expectedRules: ["VGL-AZ-002"], expectedVerdict: "inconclusive" },
    { id: "azure-defender-high", connector: "azure", description: "High-severity Defender for Cloud alert on a VM", records: defender, expectedRules: ["VGL-AZ-003"], expectedVerdict: "likely" },
  ];
}
