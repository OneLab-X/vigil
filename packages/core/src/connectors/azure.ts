import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import { promisify } from "node:util";
import { z } from "zod";
import type { CanonicalEvent } from "../types.js";
import { normalizeAzureActivity, normalizeDefenderAlert, normalizeEntraAudit, normalizeEntraSignIn } from "../normalize/azure.js";
import { httpError, withRetry } from "./retry.js";
import { assertSameOriginLink, scrubError, scrubSecrets, unverifiedJwtClaims } from "./secrets.js";
import { windowedQuery } from "./window.js";
import { ConnectorError, type CheckpointStore, type CloudConnector, type ConnectionTestResult, type DiscoveredSource, type EventPage, type ListEventsQuery, type PermissionCheck } from "./types.js";
import type { ConnectorDefinition, ConnectorRuntime, KnownSource } from "./registry.js";

const execFileP = promisify(execFile);

const LOGIN = "https://login.microsoftonline.com";
const ARM = "https://management.azure.com";
const GRAPH = "https://graph.microsoft.com";
const LA = "https://api.loganalytics.io";
const RESOURCE = { arm: ARM, graph: GRAPH, la: LA } as const;
/** Azure Instance Metadata Service token endpoint (link-local, fixed; never configurable). */
const IMDS_TOKEN = "http://169.254.169.254/metadata/identity/oauth2/token";
type Resource = keyof typeof RESOURCE;

const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export interface AzureConnectionConfig {
  tenantId: string;
  subscriptionId: string;
  /** app (client) id for workload_identity / client_secret; user-assigned identity client id for managed_identity */
  clientId?: string;
  /**
   * workload_identity: federated token from AZURE_FEDERATED_TOKEN_FILE in the Vigil runtime (keyless, production).
   * managed_identity: token from the Azure VM's Instance Metadata Service (keyless; Vigil runs on an Azure VM with a
   *   system- or user-assigned managed identity; clientId selects a user-assigned identity).
   * client_secret: app secret stored in SecretStore. azure_cli: LOCAL DEV ONLY (`az login`), refused in production.
   */
  authMode: "workload_identity" | "managed_identity" | "client_secret" | "azure_cli";
  /** where Entra ID sign-in/audit logs are read from */
  entraSource: "graph" | "log_analytics" | "none";
  workspaceId?: string;
}

/** Permission probe. Actions are evaluated against the caller's effective permissions on the subscription. */
const REQUIRED_ACTIONS = ["Microsoft.Insights/eventtypes/values/read"];
const OPTIONAL_ACTIONS = ["Microsoft.Security/alerts/read", "Microsoft.OperationalInsights/workspaces/query/read"];
/** Representative write/admin actions held by Owner / Contributor / User Access Administrator / Monitoring Contributor. */
const EXCESSIVE_ACTIONS = [
  "Microsoft.Authorization/roleAssignments/write", "Microsoft.Authorization/roleAssignments/delete",
  "Microsoft.Resources/subscriptions/resourceGroups/write", "Microsoft.Network/networkSecurityGroups/write",
  "Microsoft.Insights/diagnosticSettings/write", "Microsoft.Compute/virtualMachines/write", "Microsoft.KeyVault/vaults/write",
];
const GRAPH_REQUIRED = "AuditLog.Read.All";
/** Graph permissions beyond reading (any ReadWrite / Write / AccessAsUser / FullControl scope). */
const GRAPH_EXCESSIVE = /(ReadWrite|\.Write|AccessAsUser|FullControl|\.Send|Manage)/i;

// Azure action wildcard ("*", "*/read", "Microsoft.Authorization/*/Write") → case-insensitive regex.
const actionRe = (p: string) => new RegExp(`^${p.split("*").map((x) => x.replace(/[.+?^${}()|[\]\\/]/g, "\\$&")).join(".*")}$`, "i");
export function azureActionAllowed(perms: Array<{ actions?: string[]; notActions?: string[] }>, action: string): boolean {
  return perms.some((p) => (p.actions ?? []).some((a) => actionRe(a).test(action)) && !(p.notActions ?? []).some((a) => actionRe(a).test(action)));
}

export function azureKnownSources(cfg: Pick<AzureConnectionConfig, "subscriptionId" | "entraSource">): KnownSource[] {
  const out: KnownSource[] = [
    { sourceType: "azure_activity_log", name: "Activity Log (subscription control plane)", filter: null, description: "Role assignments, NSG / firewall, diagnostic settings and every other ARM write. Reader / Monitoring Reader.", recommended: true },
    { sourceType: "azure_defender_alerts", name: "Defender for Cloud alerts", filter: null, description: "Security alerts → security.finding. Requires Defender plans enabled on the subscription.", recommended: true },
  ];
  if (cfg.entraSource !== "none") {
    const via = cfg.entraSource === "graph" ? "Microsoft Graph (AuditLog.Read.All)" : "Log Analytics workspace (Log Analytics Reader)";
    out.push(
      { sourceType: "azure_entra_signin", name: "Entra ID sign-in logs", filter: null, description: `Interactive user sign-ins via ${via}. Graph sign-in logs need Entra ID P1/P2.`, recommended: true },
      { sourceType: "azure_entra_audit", name: "Entra ID audit logs", filter: null, description: `Directory changes: role / app / user / policy management via ${via}.`, recommended: true },
    );
  }
  return out;
}

const LA_TABLE: Record<string, string> = { azure_entra_signin: "SigninLogs", azure_entra_audit: "AuditLogs" };
const LA_LIMIT = 5000;
const GRAPH_PATH: Record<string, { path: string; ts: string; top: number }> = {
  azure_entra_signin: { path: "/v1.0/auditLogs/signIns", ts: "createdDateTime", top: 1000 },
  azure_entra_audit: { path: "/v1.0/auditLogs/directoryAudits", ts: "activityDateTime", top: 1000 },
};

/** Read-only Azure connector: ARM Activity Log + Defender alerts, Entra ID logs via Graph or Log Analytics. */
export class AzureConnector implements CloudConnector {
  readonly provider = "azure" as const;
  private tokens = new Map<Resource, { value: string; exp: number }>();
  private readonly fetchImpl: typeof fetch;

  constructor(
    private readonly cfg: AzureConnectionConfig,
    private readonly secrets: { clientSecret?: string } | null,
    private readonly checkpoints?: CheckpointStore,
    private readonly rt: ConnectorRuntime = { production: process.env.NODE_ENV === "production", env: process.env },
  ) {
    if (!GUID.test(cfg.tenantId)) throw new Error("invalid Azure tenant id");
    if (!GUID.test(cfg.subscriptionId)) throw new Error("invalid Azure subscription id");
    if (cfg.clientId !== undefined && !GUID.test(cfg.clientId)) throw new Error("invalid clientId");
    if ((cfg.authMode === "workload_identity" || cfg.authMode === "client_secret") && !cfg.clientId) throw new Error("clientId required for this auth mode");
    if (cfg.entraSource === "log_analytics" && !(cfg.workspaceId && GUID.test(cfg.workspaceId))) throw new Error("workspaceId required for entraSource=log_analytics");
    this.fetchImpl = rt.fetch ?? fetch;
  }

  private secretValues() { return [this.secrets?.clientSecret, ...[...this.tokens.values()].map((t) => t.value)]; }

  async connect(): Promise<void> {
    if (this.cfg.authMode === "azure_cli" && this.rt.production) throw new Error("azure_cli auth mode is disabled in production");
  }

  private async token(res: Resource): Promise<string> {
    await this.connect();
    const cached = this.tokens.get(res);
    if (cached && cached.exp - Date.now() > 120_000) return cached.value;
    let value: string;
    let expiresInS: number;
    if (this.cfg.authMode === "azure_cli") {
      const { stdout } = await execFileP("az", ["account", "get-access-token", "--resource", RESOURCE[res], "--tenant", this.cfg.tenantId, "-o", "json"], { timeout: 30_000 });
      const j = JSON.parse(stdout);
      value = j.accessToken;
      expiresInS = j.expires_on ? Number(j.expires_on) - Date.now() / 1000 : 1800;
    } else if (this.cfg.authMode === "managed_identity") {
      // Keyless: the VM's managed identity. IMDS only answers on the host's link-local address and requires the
      // Metadata header, so tokens cannot be obtained from outside the VM.
      const q = new URLSearchParams({ "api-version": "2018-02-01", resource: RESOURCE[res] });
      if (this.cfg.clientId) q.set("client_id", this.cfg.clientId);
      const r = await withRetry(async () => {
        const resp = await this.fetchImpl(`${IMDS_TOKEN}?${q}`, { headers: { Metadata: "true" }, signal: AbortSignal.timeout(10_000) });
        if (!resp.ok) throw httpError(resp.status, await resp.text(), resp.headers.get("retry-after"));
        return (await resp.json()) as { access_token: string; expires_in?: string | number; expires_on?: string | number };
      }).catch((e) => { throw new Error(`managed identity token unavailable (is Vigil running on an Azure VM with a managed identity?): ${(e as Error).message}`); });
      value = r.access_token;
      expiresInS = Number(r.expires_in) || (r.expires_on ? Number(r.expires_on) - Date.now() / 1000 : 3600);
    } else {
      const form = new URLSearchParams({ client_id: this.cfg.clientId!, scope: `${RESOURCE[res]}/.default`, grant_type: "client_credentials" });
      if (this.cfg.authMode === "client_secret") {
        if (!this.secrets?.clientSecret) throw new Error("client secret missing");
        form.set("client_secret", this.secrets.clientSecret);
      } else {
        // Keyless: the runtime platform (AKS workload identity, or any OIDC token projector) writes a short-lived JWT here.
        const file = this.rt.env.AZURE_FEDERATED_TOKEN_FILE;
        if (!file) throw new Error("workload_identity needs AZURE_FEDERATED_TOKEN_FILE in the Vigil runtime environment");
        form.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        form.set("client_assertion", (await fs.readFile(file, "utf8")).trim());
      }
      const r = await withRetry(async () => {
        const resp = await this.fetchImpl(`${LOGIN}/${this.cfg.tenantId}/oauth2/v2.0/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form, signal: AbortSignal.timeout(30_000) });
        if (!resp.ok) throw httpError(resp.status, await resp.text(), resp.headers.get("retry-after"));
        return (await resp.json()) as { access_token: string; expires_in: number };
      }).catch((e) => { throw scrubError(e, [this.secrets?.clientSecret]); });
      value = r.access_token;
      expiresInS = Number(r.expires_in) || 3600;
    }
    this.tokens.set(res, { value, exp: Date.now() + expiresInS * 1000 });
    return value;
  }

  private async request<T>(res: Resource, method: "GET" | "POST", url: string, body?: unknown): Promise<T> {
    try {
      const tok = await this.token(res);
      return await withRetry(async () => {
        const r = await this.fetchImpl(url, { method, headers: { authorization: `Bearer ${tok}`, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(60_000) });
        if (!r.ok) throw httpError(r.status, await r.text(), r.headers.get("retry-after"));
        return (await r.json()) as T;
      });
    } catch (e) { throw scrubError(e, this.secretValues()); }
  }

  private async laQuery(kql: string): Promise<Record<string, unknown>[]> {
    const out = await this.request<{ tables?: Array<{ columns: Array<{ name: string; type: string }>; rows: unknown[][] }> }>("la", "POST", `${LA}/v1/workspaces/${this.cfg.workspaceId}/query`, { query: kql });
    const t = out.tables?.[0];
    if (!t) return [];
    return t.rows.map((row) => Object.fromEntries(t.columns.map((c, i) => [c.name, c.type === "dynamic" && typeof row[i] === "string" ? safeJson(row[i] as string) : row[i]])));
  }

  async testConnection(): Promise<ConnectionTestResult> {
    const res: ConnectionTestResult = {
      ok: false, provider: "azure", accountRef: this.cfg.subscriptionId, principal: null, credentialType: this.cfg.authMode,
      checks: [], readOnly: true, warnings: [], errors: [], sampleReadOk: false, testedAt: new Date().toISOString(),
    };
    const scrub = (m: string) => scrubSecrets(m, this.secretValues());
    try {
      const claims = unverifiedJwtClaims(await this.token("arm"));
      res.principal = String(claims.upn ?? claims.unique_name ?? claims.app_displayname ?? claims.appid ?? claims.oid ?? "") || null;
      res.credentialType = `${this.cfg.authMode}:${claims.idtyp ?? (claims.upn ? "user" : "app")}`;
      if (claims.tid && String(claims.tid).toLowerCase() !== this.cfg.tenantId.toLowerCase()) res.errors.push(`token issued for tenant ${claims.tid}, expected ${this.cfg.tenantId}`);
    } catch (e) {
      res.errors.push(scrub(`credential error: ${(e as Error).message}`));
      return res;
    }
    const sub = `${ARM}/subscriptions/${this.cfg.subscriptionId}`;
    let requiredOk = true;
    try {
      const perms = await this.request<{ value?: Array<{ actions?: string[]; notActions?: string[] }> }>("arm", "GET", `${sub}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01`);
      const p = perms.value ?? [];
      const wanted = [...REQUIRED_ACTIONS, ...OPTIONAL_ACTIONS.filter((a) => this.cfg.entraSource === "log_analytics" || !a.includes("OperationalInsights")), ...EXCESSIVE_ACTIONS];
      res.checks.push(...wanted.map<PermissionCheck>((a) => ({ permission: a, granted: azureActionAllowed(p, a), required: REQUIRED_ACTIONS.includes(a), excessive: EXCESSIVE_ACTIONS.includes(a) || undefined })));
      requiredOk = res.checks.filter((c) => c.required).every((c) => c.granted);
      const excessive = res.checks.filter((c) => c.excessive && c.granted);
      if (excessive.length) {
        res.readOnly = false;
        res.warnings.push(`Credential has write/admin permissions not needed by Vigil (Owner / Contributor / User Access Administrator-level): ${excessive.map((c) => c.permission).join(", ")}. Assign only Reader or Monitoring Reader on the subscription (+ Log Analytics Reader on the workspace).`);
      }
      if (!azureActionAllowed(p, "Microsoft.Security/alerts/read")) res.warnings.push("Defender for Cloud alerts not readable (Microsoft.Security/alerts/read) — optional.");
    } catch (e) {
      res.warnings.push(scrub(`permission listing unavailable (${(e as Error).message.slice(0, 160)}); falling back to read probe.`));
    }
    if (this.cfg.entraSource === "graph") {
      try {
        const g = unverifiedJwtClaims(await this.token("graph"));
        const granted = [...(Array.isArray(g.roles) ? g.roles as string[] : []), ...String(g.scp ?? "").split(" ").filter(Boolean)];
        const has = granted.includes(GRAPH_REQUIRED) || granted.includes("AuditLog.ReadWrite.All");
        res.checks.push({ permission: `graph:${GRAPH_REQUIRED}`, granted: has, required: true });
        const tooMuch = granted.filter((x) => GRAPH_EXCESSIVE.test(x));
        for (const x of tooMuch) res.checks.push({ permission: `graph:${x}`, granted: true, required: false, excessive: true });
        if (tooMuch.length) { res.readOnly = false; res.warnings.push(`Microsoft Graph token carries write-capable permissions not needed by Vigil: ${tooMuch.join(", ")}. Grant only AuditLog.Read.All (application).`); }
        if (!has) { requiredOk = false; res.errors.push("Microsoft Graph: AuditLog.Read.All not granted — Entra ID logs unavailable (grant admin consent)"); }
        else await this.request("graph", "GET", `${GRAPH}/v1.0/auditLogs/directoryAudits?$top=1`);
      } catch (e) {
        requiredOk = false;
        res.errors.push(scrub(`Microsoft Graph probe failed: ${(e as Error).message}`));
      }
    } else if (this.cfg.entraSource === "log_analytics") {
      try {
        await this.laQuery("print ok=1");
        res.checks.push({ permission: "loganalytics:workspace query", granted: true, required: true });
      } catch (e) {
        requiredOk = false;
        res.checks.push({ permission: "loganalytics:workspace query", granted: false, required: true });
        res.errors.push(scrub(`Log Analytics query failed: ${(e as Error).message}`));
      }
    }
    try {
      const f = encodeURIComponent(`eventTimestamp ge '${new Date(Date.now() - 86_400_000).toISOString()}' and eventTimestamp le '${new Date().toISOString()}'`);
      await this.request("arm", "GET", `${sub}/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$filter=${f}`);
      res.sampleReadOk = true;
    } catch (e) {
      res.errors.push(scrub(`Activity Log read probe failed: ${(e as Error).message}`));
    }
    res.ok = res.sampleReadOk && requiredOk && res.errors.length === 0;
    return res;
  }

  async discoverSources(): Promise<DiscoveredSource[]> {
    const probe = async (fn: () => Promise<unknown>) => { try { await fn(); return true; } catch { return false; } };
    const sub = `${ARM}/subscriptions/${this.cfg.subscriptionId}`;
    const out: DiscoveredSource[] = [];
    for (const s of azureKnownSources(this.cfg)) {
      let available = false;
      if (s.sourceType === "azure_activity_log") available = await probe(() => this.request("arm", "GET", `${sub}/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$filter=${encodeURIComponent(`eventTimestamp ge '${new Date(Date.now() - 3_600_000).toISOString()}'`)}`));
      else if (s.sourceType === "azure_defender_alerts") available = await probe(() => this.request("arm", "GET", `${sub}/providers/Microsoft.Security/alerts?api-version=2022-01-01`));
      else if (this.cfg.entraSource === "graph") available = await probe(() => this.request("graph", "GET", `${GRAPH}${GRAPH_PATH[s.sourceType]!.path}?$top=1`));
      else if (this.cfg.entraSource === "log_analytics") available = await probe(() => this.laQuery(`${LA_TABLE[s.sourceType]} | take 1`));
      out.push({ ...s, available, meta: { via: s.sourceType.startsWith("azure_entra") ? this.cfg.entraSource : "arm" } });
    }
    return out;
  }

  async listEvents(q: ListEventsQuery): Promise<EventPage> {
    const sub = `/subscriptions/${this.cfg.subscriptionId}`;
    if (q.sourceType === "azure_activity_log") {
      const pathPrefix = `${sub}/providers/Microsoft.Insights/eventtypes/management/values`;
      let url: string;
      if (q.pageToken) url = assertSameOriginLink(q.pageToken, ARM, pathPrefix);
      else {
        // Activity Log $filter supports ge/le only; end - 1ms keeps windows half-open and contiguous.
        let f = `eventTimestamp ge '${q.start.toISOString()}' and eventTimestamp le '${new Date(q.end.getTime() - 1).toISOString()}'`;
        if (q.filter) f += ` and ${validateOdataFilter(q.filter)}`;
        url = `${ARM}${pathPrefix}?api-version=2015-04-01&$filter=${encodeURIComponent(f)}`;
      }
      const out = await this.request<{ value?: unknown[]; nextLink?: string }>("arm", "GET", url);
      return { raw: out.value ?? [], nextPageToken: out.nextLink ?? null };
    }
    if (q.sourceType === "azure_defender_alerts") {
      const pathPrefix = `${sub}/providers/Microsoft.Security/alerts`;
      const url = q.pageToken ? assertSameOriginLink(q.pageToken, ARM, pathPrefix) : `${ARM}${pathPrefix}?api-version=2022-01-01`;
      const out = await this.request<{ value?: Array<{ properties?: { timeGeneratedUtc?: string } }>; nextLink?: string }>("arm", "GET", url);
      // The alerts API has no time filter: keep alerts generated inside the requested window.
      const raw = (out.value ?? []).filter((a) => { const t = Date.parse(a.properties?.timeGeneratedUtc ?? ""); return t >= q.start.getTime() && t < q.end.getTime(); });
      return { raw, nextPageToken: out.nextLink ?? null };
    }
    if (q.sourceType === "azure_entra_signin" || q.sourceType === "azure_entra_audit") {
      if (this.cfg.entraSource === "graph") {
        const g = GRAPH_PATH[q.sourceType]!;
        let url: string;
        if (q.pageToken) url = assertSameOriginLink(q.pageToken, GRAPH, g.path);
        else {
          let f = `${g.ts} ge ${q.start.toISOString()} and ${g.ts} lt ${q.end.toISOString()}`;
          if (q.filter) f += ` and ${validateOdataFilter(q.filter)}`;
          url = `${GRAPH}${g.path}?$filter=${encodeURIComponent(f)}&$top=${Math.min(q.pageSize ?? g.top, g.top)}`;
        }
        const out = await this.request<{ value?: unknown[]; "@odata.nextLink"?: string }>("graph", "GET", url);
        return { raw: out.value ?? [], nextPageToken: out["@odata.nextLink"] ?? null };
      }
      if (this.cfg.entraSource === "log_analytics") {
        const table = LA_TABLE[q.sourceType]!;
        const where = q.filter ? ` | where ${validateKqlFilter(q.filter)}` : "";
        const r = await windowedQuery({
          start: q.start, end: q.end, pageToken: q.pageToken, limit: LA_LIMIT,
          run: (s, e) => this.laQuery(`${table} | where TimeGenerated >= datetime(${s.toISOString()}) and TimeGenerated < datetime(${e.toISOString()})${where} | order by TimeGenerated asc | take ${LA_LIMIT}`),
        });
        return { raw: r.rows, nextPageToken: r.nextPageToken };
      }
      throw new ConnectorError("Entra ID source disabled for this connection (entraSource=none)");
    }
    throw new Error(`source type ${q.sourceType} not implemented for Azure`);
  }

  normalize(raw: unknown, sourceType: string): CanonicalEvent {
    return normalizeAzure(raw, sourceType, this.cfg);
  }

  async getCheckpoint(sourceId: string) { return this.checkpoints?.get(sourceId) ?? null; }
  async saveCheckpoint(sourceId: string, cp: { watermark: string | null; pageToken: string | null }) { await this.checkpoints?.save(sourceId, cp); }
  async disconnect() { this.tokens.clear(); }
}

const safeJson = (s: string) => { try { return JSON.parse(s); } catch { return s; } };

/** Admin-supplied OData filter fragments: a conservative character set, no nesting tricks. */
function validateOdataFilter(f: string): string {
  if (f.length > 500 || !/^[\w\s'.:/@,()=-]+$/.test(f)) throw new ConnectorError("filter contains unsupported characters");
  return `(${f})`;
}
/** Admin-supplied KQL where-clause: a single predicate — no pipes (no extra operators / unions) and no statements. */
function validateKqlFilter(f: string): string {
  if (f.length > 1000 || /[|;]/.test(f) || /\b(union|externaldata|evaluate|invoke)\b/i.test(f)) throw new ConnectorError("KQL filter must be a single where-predicate (no |, ;, union, externaldata, evaluate)");
  return `(${f})`;
}

export function normalizeAzure(raw: unknown, sourceType: string, cfg: Pick<AzureConnectionConfig, "tenantId" | "subscriptionId">): CanonicalEvent {
  const r = raw as Record<string, any>;
  switch (sourceType) {
    case "azure_entra_signin": return normalizeEntraSignIn(r, { tenantId: cfg.tenantId, sourceType });
    case "azure_entra_audit": return normalizeEntraAudit(r, { tenantId: cfg.tenantId, sourceType });
    case "azure_defender_alerts": return normalizeDefenderAlert(r, { subscriptionId: cfg.subscriptionId, sourceType });
    default: return normalizeAzureActivity(r, { subscriptionId: cfg.subscriptionId, sourceType });
  }
}

// ---------- registry definition ----------

const guid = (title: string, description?: string) => z.string().regex(GUID, "must be a GUID").meta({ title, description, ui: { placeholder: "00000000-0000-0000-0000-000000000000" } });

const AzureConfigSchema = z.object({
  tenantId: guid("Directory (tenant) ID"),
  subscriptionId: guid("Subscription ID"),
  authMode: z.enum(["workload_identity", "managed_identity", "client_secret", "azure_cli"]).default("workload_identity").meta({
    title: "Authentication", description: "Managed identity when Vigil runs on an Azure VM, workload identity federation elsewhere; client secret only if neither is possible",
    ui: { kind: "select", labels: { workload_identity: "Workload identity federation (keyless)", managed_identity: "Managed identity of this Azure VM (keyless)", client_secret: "App registration + client secret", azure_cli: "Azure CLI token (local dev only)" } },
  }),
  clientId: guid("Application (client) ID", "App registration used by Vigil, or the user-assigned managed identity's client ID").optional().meta({ title: "Application (client) ID", ui: { showWhen: { authMode: ["workload_identity", "managed_identity", "client_secret"] } } }),
  entraSource: z.enum(["graph", "log_analytics", "none"]).default("graph").meta({
    title: "Entra ID logs via", ui: { kind: "select", labels: { graph: "Microsoft Graph (AuditLog.Read.All)", log_analytics: "Log Analytics workspace", none: "Don't read Entra ID logs" } },
  }),
  workspaceId: guid("Log Analytics workspace ID").optional().meta({ title: "Log Analytics workspace ID", ui: { showWhen: { entraSource: ["log_analytics"] } } }),
});
type AzureConfig = z.infer<typeof AzureConfigSchema>;

const AzureCredentialSchema = z.object({
  clientSecret: z.string().min(8).max(512).optional().meta({ title: "Client secret", description: "Only for client_secret auth. Stored encrypted; never returned.", ui: { kind: "secret", showWhen: { authMode: ["client_secret"] } } }),
});
type AzureCredentials = z.infer<typeof AzureCredentialSchema>;

export const azureConnectorDefinition: ConnectorDefinition<AzureConfig, AzureCredentials> = {
  id: "azure", kind: "cloud", displayName: "Microsoft Azure", version: "1.0.0",
  description: "Activity Log, Entra ID sign-in & audit logs, Defender for Cloud alerts for one subscription.",
  configSchema: AzureConfigSchema,
  credentialSchema: AzureCredentialSchema,
  authModes: [
    { id: "workload_identity", label: "Workload identity federation", description: "Federated credential on the app registration; token from AZURE_FEDERATED_TOKEN_FILE (keyless)" },
    { id: "managed_identity", label: "Managed identity", description: "System- or user-assigned managed identity of the Azure VM running Vigil (IMDS, keyless)" },
    { id: "client_secret", label: "Client secret", description: "App registration secret stored encrypted in the SecretStore" },
    { id: "azure_cli", label: "Azure CLI token", description: "Developer's `az login`", devOnly: true },
  ],
  authModeOf: (c) => c.authMode,
  accountRefOf: (c) => c.subscriptionId.toLowerCase(),
  validate(c, creds, rt) {
    if (c.authMode === "azure_cli" && rt.production) return "azure_cli auth is for local development only";
    if ((c.authMode === "workload_identity" || c.authMode === "client_secret") && !c.clientId) return "clientId required for workload_identity / client_secret";
    if (c.authMode === "client_secret" && !creds?.clientSecret) return "clientSecret required for authMode=client_secret";
    if (c.authMode !== "client_secret" && creds?.clientSecret) return "clientSecret is only used with authMode=client_secret";
    if (c.entraSource === "log_analytics" && !c.workspaceId) return "workspaceId required for entraSource=log_analytics";
    return null;
  },
  prepareSecrets: (c, creds) => (c.authMode === "client_secret" && creds?.clientSecret ? { clientSecret: creds.clientSecret } : null),
  create: (c, secrets, cps, rt) => new AzureConnector(c, secrets, cps, rt),
  knownSources: (c) => azureKnownSources(c),
  normalizers: { "*": (raw, ctx) => normalizeAzure(raw, ctx.sourceType, ctx.config) },
  onboardingInstructions: (c, _s, rt) => {
    const mi = c.authMode === "managed_identity";
    const app = c.clientId ?? (mi ? "<MANAGED_IDENTITY_PRINCIPAL_ID>" : "<APP_ID>");
    const scope = `/subscriptions/${c.subscriptionId}`;
    return {
      roles: [
        "Reader or Monitoring Reader on the subscription (Activity Log, Defender alerts)",
        ...(c.entraSource === "graph" ? ["Microsoft Graph application permission AuditLog.Read.All (+ admin consent)"] : []),
        ...(c.entraSource === "log_analytics" ? ["Log Analytics Reader on the workspace receiving Entra ID SigninLogs / AuditLogs"] : []),
      ],
      commands: [
        ...(c.authMode === "azure_cli" ? ["# local dev: az login --tenant " + c.tenantId]
          : mi ? ["# the VM's managed identity (deploy/cloud/azure Terraform creates a user-assigned one): az identity show -g <RG> -n vigil --query '{clientId:clientId,principalId:principalId}'"]
          : [`az ad app create --display-name vigil-reader   # note the appId → clientId`, `az ad sp create --id ${app}`]),
        `az role assignment create --assignee ${app} --role "Monitoring Reader" --scope ${scope}`,
        ...(c.entraSource === "graph" && mi ? [`# Graph app role for a managed identity: POST https://graph.microsoft.com/v1.0/servicePrincipals/<MI_PRINCIPAL_ID>/appRoleAssignments {"principalId":"<MI_PRINCIPAL_ID>","resourceId":"<GRAPH_SP_OBJECT_ID>","appRoleId":"b0afded3-3588-46d8-8b3d-9842eff778da"}   # AuditLog.Read.All`] : []),
        ...(c.entraSource === "graph" && !mi ? [`az ad app permission add --id ${app} --api 00000003-0000-0000-c000-000000000000 --api-permissions b0afded3-3588-46d8-8b3d-9842eff778da=Role   # AuditLog.Read.All`, `az ad app permission admin-consent --id ${app}`] : []),
        ...(c.entraSource === "log_analytics" ? [`az role assignment create --assignee ${app} --role "Log Analytics Reader" --scope <WORKSPACE_RESOURCE_ID>`] : []),
        ...(c.authMode === "workload_identity" ? [`az ad app federated-credential create --id ${app} --parameters '{"name":"vigil","issuer":"<VIGIL_RUNTIME_OIDC_ISSUER>","subject":"<VIGIL_RUNTIME_SUBJECT>","audiences":["api://AzureADTokenExchange"]}'`] : []),
      ],
      note: `Never assign Owner, Contributor or User Access Administrator — the connection test flags them as over-privileged. Vigil only reads.${c.authMode === "workload_identity" && !rt.env.AZURE_FEDERATED_TOKEN_FILE ? " This Vigil runtime has no AZURE_FEDERATED_TOKEN_FILE set yet." : ""}`,
    };
  },
  auditSourcePrefixes: ["azure_activity", "azure_entra_audit"],
  formHelp: "Assign Reader / Monitoring Reader on the subscription (+ AuditLog.Read.All for Graph or Log Analytics Reader on the workspace). Owner / Contributor / User Access Administrator are flagged as over-privileged.",
};
