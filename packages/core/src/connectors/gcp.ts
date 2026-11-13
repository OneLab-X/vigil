import { GoogleAuth, type AuthClient } from "google-auth-library";
import { execFile } from "node:child_process";
import { z } from "zod";
import { promisify } from "node:util";
import { createHash } from "node:crypto";

const execFileP = promisify(execFile);

/** Minimal header provider so all auth modes share one request path. */
interface HeaderSource { getRequestHeaders(url?: string): Promise<Record<string, string> | Headers> }

class GcloudCliTokenSource implements HeaderSource {
  private token: { value: string; exp: number } | null = null;
  account: string | null = null;
  async getRequestHeaders(): Promise<Record<string, string>> {
    if (!this.token || this.token.exp < Date.now()) {
      const { stdout } = await execFileP("gcloud", ["auth", "print-access-token"], { timeout: 20_000 });
      this.token = { value: stdout.trim(), exp: Date.now() + 30 * 60_000 };
      const acct = await execFileP("gcloud", ["config", "get-value", "account"], { timeout: 20_000 }).catch(() => ({ stdout: "" }));
      this.account = acct.stdout.trim() || null;
    }
    return { authorization: `Bearer ${this.token.value}` };
  }
}
import type { CanonicalEvent } from "../types.js";
import { normalizeGcpEntry, gcpSourceTypeForLog, type GcpLogEntry } from "../normalize/gcp.js";
import { httpError, withRetry } from "./retry.js";
import type {
  CheckpointStore, CloudConnector, ConnectionTestResult, DiscoveredSource, EventPage, ListEventsQuery, PermissionCheck,
} from "./types.js";
import type { ConnectorDefinition } from "./registry.js";

export interface GcpConnectionConfig {
  projectId: string;
  /**
   * adc: Application Default Credentials. wif: external_account credential config (prod).
   * gcloud_cli: LOCAL DEV ONLY — short-lived token from the developer's `gcloud` login; refused when NODE_ENV=production.
   */
  authMode: "adc" | "wif" | "gcloud_cli";
  /** For wif: the external_account JSON config (contains no secret material — it points at a token source). */
  wifCredentialConfig?: Record<string, unknown>;
  /** Optional quota project for user ADC credentials. */
  quotaProjectId?: string;
}

const LOGGING = "https://logging.googleapis.com/v2";
const CRM = "https://cloudresourcemanager.googleapis.com/v1";
const SCOPES = ["https://www.googleapis.com/auth/logging.read", "https://www.googleapis.com/auth/cloudplatformprojects.readonly"];

const REQUIRED = ["logging.logEntries.list", "logging.logs.list"];
const OPTIONAL = ["logging.privateLogEntries.list"]; // Data Access audit logs
const EXCESSIVE = [
  "logging.sinks.create", "logging.sinks.delete", "logging.sinks.update", "logging.logs.delete",
  "resourcemanager.projects.setIamPolicy", "iam.serviceAccountKeys.create", "compute.firewalls.update",
];

/**
 * Process-wide cache of Google auth clients. google-auth-library re-reads and re-parses the credential on every
 * `new GoogleAuth()` (and 10.x prints a deprecation warning from its own internal loader each time); the client
 * already refreshes tokens itself, so one instance per credential is enough. Entries expire hourly so a changed ADC
 * file (e.g. a new `gcloud auth application-default login`) is picked up without a restart. Keyed by a hash of the
 * credential config — no secret material is used as a key or kept beyond what the client already holds.
 */
const AUTH_TTL_MS = 3_600_000;
const authCache = new Map<string, { at: number; p: Promise<{ auth: GoogleAuth; client: AuthClient }> }>();
export function cachedGoogleAuth(wifConfig: Record<string, unknown> | null): Promise<{ auth: GoogleAuth; client: AuthClient }> {
  const key = wifConfig ? `wif:${createHash("sha256").update(JSON.stringify(wifConfig)).digest("hex")}` : "adc";
  const hit = authCache.get(key);
  if (hit && Date.now() - hit.at < AUTH_TTL_MS) return hit.p;
  const p = (async () => {
    const auth = wifConfig ? new GoogleAuth({ credentials: wifConfig as any, scopes: SCOPES }) : new GoogleAuth({ scopes: SCOPES });
    return { auth, client: await auth.getClient() };
  })();
  p.catch(() => authCache.delete(key)); // never cache a failure (missing ADC, bad config)
  if (authCache.size > 200) authCache.clear();
  authCache.set(key, { at: Date.now(), p });
  return p;
}
export const clearGoogleAuthCache = () => authCache.clear();

/** Well-known sources. Filters are explicit: no implicit console time window. */
export function gcpKnownSources(projectId: string): Omit<DiscoveredSource, "available">[] {
  const p = `projects/${projectId}/logs`;
  return [
    { sourceType: "gcp_gae_app", name: "App Engine · default module", filter: 'resource.type="gae_app" AND resource.labels.module_id="default"', description: "App Engine request logs and application stdout/stderr for module default", recommended: true },
    { sourceType: "gcp_audit_admin_activity", name: "Admin Activity audit logs", filter: `logName="${p}/cloudaudit.googleapis.com%2Factivity"`, description: "Configuration and IAM changes (always on, free)", recommended: true },
    { sourceType: "gcp_audit_system_event", name: "System Event audit logs", filter: `logName="${p}/cloudaudit.googleapis.com%2Fsystem_event"`, description: "Google-initiated resource changes", recommended: true },
    { sourceType: "gcp_audit_policy_denied", name: "Policy Denied audit logs", filter: `logName="${p}/cloudaudit.googleapis.com%2Fpolicy"`, description: "VPC-SC / org policy denials", recommended: true },
    { sourceType: "gcp_audit_data_access", name: "Data Access audit logs", filter: `logName="${p}/cloudaudit.googleapis.com%2Fdata_access"`, description: "Data reads/writes. Requires logging.privateLogEntries.list and must be enabled by the customer.", recommended: false },
    { sourceType: "gcp_load_balancer", name: "HTTP(S) Load Balancer logs", filter: 'resource.type="http_load_balancer"', description: "LB request logs incl. Cloud Armor enforcement", recommended: true },
    { sourceType: "gcp_cloud_armor", name: "Cloud Armor enforcement", filter: 'resource.type="http_load_balancer" AND jsonPayload.enforcedSecurityPolicy.name:*', description: "Requests evaluated by Cloud Armor policies", recommended: false },
    { sourceType: "gcp_vpc_flow", name: "VPC Flow Logs", filter: `logName="${p}/compute.googleapis.com%2Fvpc_flows"`, description: "Sampled network flows (must be enabled per subnet)", recommended: false },
  ];
}

export class GcpConnector implements CloudConnector {
  readonly provider = "gcp" as const;
  private auth: GoogleAuth | null = null;
  private client: (AuthClient | HeaderSource) | null = null;

  constructor(
    private readonly cfg: GcpConnectionConfig,
    private readonly checkpoints?: CheckpointStore,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(cfg.projectId)) throw new Error("invalid GCP project id");
  }

  async connect(): Promise<void> {
    if (this.client) return;
    if (this.cfg.authMode === "gcloud_cli") {
      if (process.env.NODE_ENV === "production") throw new Error("gcloud_cli auth mode is disabled in production");
      this.client = new GcloudCliTokenSource();
      return;
    }
    const cached = await cachedGoogleAuth(this.cfg.authMode === "wif" ? this.cfg.wifCredentialConfig ?? null : null);
    this.auth = cached.auth;
    this.client = cached.client;
  }

  private async request<T>(method: "GET" | "POST", url: string, body?: unknown): Promise<T> {
    await this.connect();
    return withRetry(async () => {
      const headers = new Headers(await this.client!.getRequestHeaders(url) as any);
      headers.set("content-type", "application/json");
      if (this.cfg.quotaProjectId) headers.set("x-goog-user-project", this.cfg.quotaProjectId);
      const res = await this.fetchImpl(url, { method, headers, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(60_000) });
      if (!res.ok) throw httpError(res.status, googleErrorSummary(await res.text()), res.headers.get("retry-after"));
      return (await res.json()) as T;
    });
  }

  async principal(): Promise<{ principal: string | null; credentialType: string }> {
    await this.connect();
    if (this.client instanceof GcloudCliTokenSource) {
      await this.client.getRequestHeaders();
      return { principal: this.client.account, credentialType: "gcloud_cli:dev-user-token" };
    }
    const creds: any = await this.auth!.getCredentials().catch(() => ({}));
    const type = (this.client as any)?.constructor?.name ?? "unknown";
    let principal: string | null = creds?.client_email ?? null;
    if (!principal) {
      // User ADC credentials carry no email; ask the userinfo endpoint (token in a header, never a URL).
      principal = await (async () => {
        const headers = new Headers(await this.client!.getRequestHeaders("https://openidconnect.googleapis.com/v1/userinfo") as any);
        const r = await this.fetchImpl("https://openidconnect.googleapis.com/v1/userinfo", { headers, signal: AbortSignal.timeout(10_000) });
        return r.ok ? ((await r.json()) as { email?: string }).email ?? null : null;
      })().catch(() => null);
    }
    return { principal, credentialType: this.cfg.authMode === "wif" ? `wif:${type}` : `adc:${type}` };
  }

  async testConnection(): Promise<ConnectionTestResult> {
    const res: ConnectionTestResult = {
      ok: false, provider: "gcp", accountRef: this.cfg.projectId, principal: null, credentialType: "unknown",
      checks: [], readOnly: true, warnings: [], errors: [], sampleReadOk: false, testedAt: new Date().toISOString(),
    };
    try {
      const who = await this.principal();
      res.principal = who.principal;
      res.credentialType = who.credentialType;
    } catch (e) {
      res.errors.push(`credential error: ${(e as Error).message}`);
      return res;
    }
    try {
      const perms = [...REQUIRED, ...OPTIONAL, ...EXCESSIVE];
      const out = await this.request<{ permissions?: string[] }>("POST", `${CRM}/projects/${this.cfg.projectId}:testIamPermissions`, { permissions: perms });
      const granted = new Set(out.permissions ?? []);
      res.checks = perms.map<PermissionCheck>((p) => ({ permission: p, granted: granted.has(p), required: REQUIRED.includes(p), excessive: EXCESSIVE.includes(p) || undefined }));
      const excessive = res.checks.filter((c) => c.excessive && c.granted);
      if (excessive.length) {
        res.readOnly = false;
        res.warnings.push(`Credential has write/admin permissions not needed by Vigil: ${excessive.map((c) => c.permission).join(", ")}. Use a dedicated principal with roles/logging.viewer (+ roles/logging.privateLogViewer for Data Access logs).`);
      }
      if (!granted.has("logging.privateLogEntries.list")) res.warnings.push("Data Access audit logs not readable (logging.privateLogEntries.list missing) — optional.");
    } catch (e) {
      const m = (e as Error).message;
      const where = /in project (\S+?)(?: before|[ ,.]|$)/i.exec(m)?.[1]?.replace(/[^\w-]/g, "") ?? null;
      const quotaHint = where && where !== this.cfg.projectId && !/^\d+$/.test(where) ? ` (or make ${this.cfg.projectId} your quota project: gcloud auth application-default set-quota-project ${this.cfg.projectId})` : "";
      res.warnings.push(/Cloud Resource Manager API has not been used|SERVICE_DISABLED|cloudresourcemanager\.googleapis\.com.*disabled/i.test(m)
        ? `Read-only NOT verified: the Cloud Resource Manager API is disabled in ${where ? `project ${where}` : "the project your credentials bill API calls to (with user ADC: the quota project)"}, so Vigil can't check for write permissions. Log reading still works. To enable the check: gcloud services enable cloudresourcemanager.googleapis.com --project=${where ?? this.cfg.projectId}${quotaHint}.`
        : `testIamPermissions unavailable (${m.slice(0, 120)}); falling back to read probe.`);
    }
    try {
      await this.request("POST", `${LOGGING}/entries:list`, {
        resourceNames: [`projects/${this.cfg.projectId}`],
        filter: `timestamp >= "${new Date(Date.now() - 86_400_000).toISOString()}"`,
        pageSize: 1, orderBy: "timestamp desc",
      });
      res.sampleReadOk = true;
    } catch (e) {
      res.errors.push(`read probe failed: ${(e as Error).message}`);
    }
    const requiredOk = res.checks.length === 0 || res.checks.filter((c) => c.required).every((c) => c.granted);
    res.ok = res.sampleReadOk && requiredOk;
    return res;
  }

  async discoverSources(): Promise<DiscoveredSource[]> {
    const logIds: string[] = [];
    let pageToken: string | undefined;
    for (let i = 0; i < 10; i++) {
      const q = new URLSearchParams({ pageSize: "1000" });
      if (pageToken) q.set("pageToken", pageToken);
      const out = await this.request<{ logNames?: string[]; nextPageToken?: string }>("GET", `${LOGGING}/projects/${this.cfg.projectId}/logs?${q}`);
      logIds.push(...(out.logNames ?? []).map((n) => decodeURIComponent(n.split("/logs/")[1] ?? n)));
      pageToken = out.nextPageToken;
      if (!pageToken) break;
    }
    const has = (suffix: string) => logIds.some((l) => l.endsWith(suffix));
    const known = gcpKnownSources(this.cfg.projectId).map((s) => {
      let available: boolean;
      switch (s.sourceType) {
        case "gcp_gae_app": available = logIds.some((l) => l.startsWith("appengine.googleapis.com")); break;
        case "gcp_audit_admin_activity": available = has("cloudaudit.googleapis.com/activity"); break;
        case "gcp_audit_system_event": available = has("cloudaudit.googleapis.com/system_event"); break;
        case "gcp_audit_policy_denied": available = has("cloudaudit.googleapis.com/policy"); break;
        case "gcp_audit_data_access": available = has("cloudaudit.googleapis.com/data_access"); break;
        case "gcp_vpc_flow": available = has("compute.googleapis.com/vpc_flows"); break;
        default: available = logIds.some((l) => l === "requests");
      }
      return { ...s, available, meta: {} };
    });
    return [...known, ...[] as DiscoveredSource[]].map((s) => ({ ...s, meta: { ...s.meta, observedLogIds: logIds.length } }));
  }

  async listEvents(q: ListEventsQuery): Promise<EventPage> {
    // Explicit, absolute time bounds — never rely on a console-style relative window.
    const timeFilter = `timestamp >= "${q.start.toISOString()}" AND timestamp < "${q.end.toISOString()}"`;
    const filter = q.filter ? `(${q.filter}) AND ${timeFilter}` : timeFilter;
    const out = await this.request<{ entries?: GcpLogEntry[]; nextPageToken?: string }>("POST", `${LOGGING}/entries:list`, {
      resourceNames: [`projects/${this.cfg.projectId}`],
      filter, orderBy: "timestamp asc",
      pageSize: Math.min(q.pageSize ?? 1000, 1000),
      pageToken: q.pageToken ?? undefined,
    });
    return { raw: out.entries ?? [], nextPageToken: out.nextPageToken ?? null };
  }

  normalize(raw: unknown, sourceType: string): CanonicalEvent {
    const e = raw as GcpLogEntry;
    const logId = e.logName ? decodeURIComponent(e.logName.split("/logs/")[1] ?? "") : "";
    const st = sourceType === "gcp_log" ? gcpSourceTypeForLog(logId, e.resource?.type) : sourceType;
    return normalizeGcpEntry(e, { projectId: this.cfg.projectId, sourceType: st });
  }

  async getCheckpoint(sourceId: string) { return this.checkpoints?.get(sourceId) ?? null; }
  async saveCheckpoint(sourceId: string, cp: { watermark: string | null; pageToken: string | null }) { await this.checkpoints?.save(sourceId, cp); }

  async disconnect(): Promise<void> {
    this.client = null;
    this.auth = null;
  }

  /**
   * Commands a customer admin runs to enable near-real-time streaming. Vigil never executes these:
   * sink creation is a privileged, customer-approved setup step.
   */
  static streamingSetupInstructions(projectId: string, filter: string, readerPrincipal: string): string[] {
    const topic = "vigil-security-events";
    return [
      `gcloud pubsub topics create ${topic} --project=${projectId}`,
      `gcloud logging sinks create vigil-sink pubsub.googleapis.com/projects/${projectId}/topics/${topic} --project=${projectId} --log-filter='${filter.replace(/'/g, "'\\''")}'`,
      `# grant the sink's writer identity publish rights (printed by the previous command)`,
      `gcloud pubsub topics add-iam-policy-binding ${topic} --project=${projectId} --member=<SINK_WRITER_IDENTITY> --role=roles/pubsub.publisher`,
      `gcloud pubsub subscriptions create vigil-sub --topic=${topic} --project=${projectId}`,
      `gcloud pubsub subscriptions add-iam-policy-binding vigil-sub --project=${projectId} --member=${readerPrincipal} --role=roles/pubsub.subscriber`,
    ];
  }
}

/** Google API errors are verbose JSON; keep status + message (and the disabled-service consumer) within httpError's 300 chars. */
export function googleErrorSummary(body: string): string {
  try {
    const e = JSON.parse(body)?.error;
    if (!e?.message) return body;
    const consumer = (e.details ?? []).map((d: any) => d?.metadata?.consumer).find(Boolean);
    return `${e.status ?? e.code}: ${e.message}${consumer && !String(e.message).includes(consumer) ? ` [${consumer}]` : ""}`;
  } catch { return body; }
}

// ---------- registry definition ----------

export interface OnboardingStep { title: string; detail?: string; commands?: string[] }

/** Only the steps the chosen auth mode needs — a developer login should not be shown the production setup. */
export function gcpOnboardingSteps(c: { projectId: string; authMode: "adc" | "wif" | "gcloud_cli" }): OnboardingStep[] {
  const p = c.projectId;
  const sa = `vigil-reader@${p}.iam.gserviceaccount.com`;
  const finish: OnboardingStep[] = [
    { title: "Click Test on the connection below", detail: "Expect “Connection OK”. “Over-privileged” only means the identity can also write (e.g. a project Owner) — fine for a dev login, avoid it in production." },
    { title: "Open Sources and enable what you need", detail: "Usually “Admin Activity audit logs” (IAM, firewall and logging changes), plus “App Engine · default module” if you use App Engine. Then pick a range and click Ingest history." },
  ];
  if (c.authMode === "gcloud_cli") return [
    { title: "Log in with gcloud on the machine running Vigil", commands: ["gcloud auth login"] },
    { title: "Make sure your account can read logs (skip if you are already Owner, Editor or Logs Viewer)", detail: "A project owner runs this, with your email:", commands: [`gcloud projects add-iam-policy-binding ${p} --member=user:YOUR_EMAIL --role=roles/logging.viewer`] },
    ...finish,
  ];
  if (c.authMode === "adc") return [
    { title: "Give Vigil an identity that can read logs", detail: "Local machine: log in once (your account needs Logs Viewer on the project). Google Cloud VM / GKE: instead attach a service account with roles/logging.viewer to the host — no command needed here.", commands: ["gcloud auth application-default login"] },
    { title: "If that identity can't read logs yet, grant Logs Viewer", detail: "Replace the member with your email (user:…) or the host's service account (serviceAccount:…):", commands: [`gcloud projects add-iam-policy-binding ${p} --member=user:YOUR_EMAIL --role=roles/logging.viewer`] },
    ...finish,
  ];
  return [
    { title: "Create a read-only service account", commands: [
      `gcloud iam service-accounts create vigil-reader --project=${p} --display-name="Vigil read-only"`,
      `gcloud projects add-iam-policy-binding ${p} --member=serviceAccount:${sa} --role=roles/logging.viewer`,
    ] },
    { title: "Let Vigil's runtime identity impersonate it via Workload Identity Federation", detail: "Create a pool and provider for where Vigil runs (AWS, Azure, OIDC), then generate the credential config you pasted into this connection:", commands: [
      `gcloud iam workload-identity-pools create vigil-pool --location=global --project=${p}`,
      `gcloud iam service-accounts add-iam-policy-binding ${sa} --role=roles/iam.workloadIdentityUser --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/vigil-pool/*"`,
    ] },
    ...finish,
  ];
}

const GcpConfigSchema = z.object({
  projectId: z.string().regex(/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/).meta({ title: "Project ID", ui: { placeholder: "my-project-123456" } }),
  authMode: z.enum(["adc", "wif", "gcloud_cli"]).default("adc").meta({
    title: "Authentication", description: "ADC locally, Workload Identity Federation in production",
    ui: { kind: "select", labels: { adc: "Application Default Credentials", wif: "Workload Identity Federation", gcloud_cli: "gcloud CLI user token (local dev only)" } },
  }),
  quotaProjectId: z.string().max(64).optional().meta({ title: "Quota project (optional)", description: "Billing/quota project for user ADC credentials" }),
});
type GcpConfig = z.infer<typeof GcpConfigSchema>;

const GcpCredentialSchema = z.object({
  wifCredentialConfig: z.record(z.string(), z.unknown()).optional().meta({
    title: "WIF credential configuration (JSON)", secret: false,
    description: "external_account credential config from `gcloud iam workload-identity-pools create-cred-config`. Never a service-account key.",
    ui: { kind: "json", showWhen: { authMode: ["wif"] } },
  }),
});
type GcpCredentials = z.infer<typeof GcpCredentialSchema>;

const gcpNormalizer = (raw: unknown, ctx: { config: GcpConfig; sourceType: string }) => {
  const e = raw as GcpLogEntry;
  const logId = e.logName ? decodeURIComponent(e.logName.split("/logs/")[1] ?? "") : "";
  const st = ctx.sourceType === "gcp_log" ? gcpSourceTypeForLog(logId, e.resource?.type) : ctx.sourceType;
  return normalizeGcpEntry(e, { projectId: ctx.config.projectId, sourceType: st });
};

export const gcpConnectorDefinition: ConnectorDefinition<GcpConfig, GcpCredentials> = {
  id: "gcp", kind: "cloud", displayName: "Google Cloud", version: "1.0.0",
  description: "Cloud Logging (audit, App Engine, load balancer, VPC flow) for one GCP project.",
  configSchema: GcpConfigSchema,
  credentialSchema: GcpCredentialSchema,
  authModes: [
    { id: "adc", label: "Application Default Credentials", description: "Runtime service account or local `gcloud auth application-default login`" },
    { id: "wif", label: "Workload Identity Federation", description: "Keyless external_account credential (production)" },
    { id: "gcloud_cli", label: "gcloud CLI user token", description: "Developer's gcloud login", devOnly: true },
  ],
  authModeOf: (c) => c.authMode,
  accountRefOf: (c) => c.projectId,
  validate(c, creds, rt) {
    if (c.authMode === "gcloud_cli" && rt.production) return "gcloud_cli auth is for local development only";
    if (c.authMode === "wif" && !creds?.wifCredentialConfig) return "wifCredentialConfig required for authMode=wif";
    if (creds?.wifCredentialConfig && creds.wifCredentialConfig.type !== "external_account") return "WIF config must be an external_account credential configuration (no service-account keys)";
    return null;
  },
  // Historical format: the raw external_account JSON (not wrapped) — keeps rows created before the registry readable.
  prepareSecrets: (_c, creds) => creds?.wifCredentialConfig ?? null,
  encodeSecrets: (s) => JSON.stringify(s),
  decodeSecrets: (stored) => JSON.parse(stored),
  create(c, secrets, cps) {
    if (c.authMode === "wif" && !secrets) throw new Error("WIF config missing");
    return new GcpConnector({ projectId: c.projectId, authMode: c.authMode, wifCredentialConfig: secrets ?? undefined, quotaProjectId: c.quotaProjectId }, cps);
  },
  knownSources: (c) => gcpKnownSources(c.projectId),
  normalizers: { "*": gcpNormalizer },
  onboardingInstructions: (c) => {
    const steps = gcpOnboardingSteps(c);
    return {
      authMode: c.authMode,
      steps,
      roles: ["roles/logging.viewer", "roles/logging.privateLogViewer (optional, Data Access logs)"],
      /** flat list kept for API consumers of the pre-checklist format */
      commands: steps.flatMap((st) => st.commands ?? []),
      note: "Never create or upload service-account keys. Vigil only reads logs.",
    };
  },
  sourceSetupInstructions: (c, s) => GcpConnector.streamingSetupInstructions(c.projectId, s.filter ?? "", "serviceAccount:vigil-reader@PROJECT.iam.gserviceaccount.com"),
  auditSourcePrefixes: ["gcp_audit"],
  formHelp: "Grant the reading principal roles/logging.viewer (and optionally roles/logging.privateLogViewer). Never upload service-account keys.",
};
