import { z } from "zod";
import type { CanonicalEvent } from "../types.js";
import { normalizeForwardedLog } from "../normalize/logplatform.js";
import { httpError, withRetry } from "./retry.js";
import { scrubError, scrubSecrets } from "./secrets.js";
import { ConnectorError, type CheckpointStore, type CloudConnector, type ConnectionTestResult, type DiscoveredSource, type EventPage, type ListEventsQuery } from "./types.js";
import type { ConnectorDefinition, ConnectorRuntime, KnownSource } from "./registry.js";

export const DATADOG_SITES = ["datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu", "ap1.datadoghq.com", "ap2.datadoghq.com", "ddog-gov.com"] as const;
export type DatadogSite = (typeof DATADOG_SITES)[number];

export interface DatadogConnectionConfig {
  site: DatadogSite;
  /** org label used as the account reference (Datadog has no read-only org-id API under logs_read_data) */
  orgName: string;
  /** log indexes to search; ["*"] = all the key may read */
  indexes: string[];
  /** query ANDed with every source filter, e.g. "env:prod" */
  baseQuery?: string;
}
export interface DatadogSecrets { apiKey: string; appKey: string }

/** Scopes Vigil may hold. Anything else (incl. an unscoped key, which inherits the user's full rights) is excessive. */
export const DATADOG_ALLOWED_SCOPES = ["logs_read_data", "logs_read_index_data", "security_monitoring_signals_read", "audit_logs_read"];
const REQUIRED_SCOPE = "logs_read_data";

const SOURCE_PATH: Record<string, string> = {
  datadog_logs: "/api/v2/logs/events/search",
  datadog_siem_signals: "/api/v2/security_monitoring/signals/search",
  datadog_audit: "/api/v2/audit/events/search",
};

export function datadogKnownSources(): KnownSource[] {
  const logs = (name: string, filter: string, description: string, recommended = true): KnownSource => ({ sourceType: "datadog_logs", name, filter, description, recommended, meta: { editableFilter: true } });
  return [
    { sourceType: "datadog_siem_signals", name: "Cloud SIEM signals", filter: "*", description: "Datadog Cloud SIEM / Security signals → security.finding (scope security_monitoring_signals_read)", recommended: true, meta: { editableFilter: true } },
    { sourceType: "datadog_audit", name: "Datadog Audit Trail", filter: "*", description: "Changes to your Datadog org: API keys, roles, log pipelines/indexes, security rules (scope audit_logs_read)", recommended: true, meta: { editableFilter: true } },
    logs("AWS CloudTrail (forwarded)", "source:cloudtrail", "CloudTrail events forwarded to Datadog — normalized with the AWS CloudTrail normalizer"),
    logs("Google Cloud logs (forwarded)", "source:gcp*", "GCP audit / request logs forwarded via Pub/Sub — normalized with the GCP normalizer"),
    logs("Azure logs (forwarded)", "source:azure*", "Azure Activity / Entra ID logs forwarded via Event Hub — normalized with the Azure normalizer"),
    logs("Web access logs", "source:(nginx OR apache OR haproxy OR traefik)", "HTTP access logs (network.client.ip, http.status_code, http.url_details.path)"),
    logs("Authentication logs", "source:(auth OR sshd OR okta OR auth0) OR @evt.category:authentication", "Login success / failure from OS and identity providers"),
  ];
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Read-only Datadog connector: Logs / Security signals / Audit Trail search APIs with cursor paging. */
export class DatadogConnector implements CloudConnector {
  readonly provider = "datadog" as const;
  private readonly base: string;
  private readonly fetchImpl: typeof fetch;
  private pauseUntil = 0;

  constructor(
    private readonly cfg: DatadogConnectionConfig,
    private readonly secrets: DatadogSecrets,
    private readonly checkpoints?: CheckpointStore,
    rt: Partial<ConnectorRuntime> = {},
    private readonly opts: { sleep?: (ms: number) => Promise<void> } = {},
  ) {
    if (!DATADOG_SITES.includes(cfg.site)) throw new Error("unsupported Datadog site");
    if (!secrets?.apiKey || !secrets?.appKey) throw new Error("Datadog API key and application key required");
    this.base = `https://api.${cfg.site}`;
    this.fetchImpl = rt.fetch ?? fetch;
  }

  private scrub = (m: string) => scrubSecrets(m, [this.secrets.apiKey, this.secrets.appKey]);

  async connect(): Promise<void> {}

  private async request<T>(method: "GET" | "POST", path: string, body?: unknown, opts: { retry?: boolean } = {}): Promise<T> {
    const doSleep = this.opts.sleep ?? sleep;
    try {
      return await withRetry(async () => {
        const wait = this.pauseUntil - Date.now();
        if (wait > 0) await doSleep(Math.min(wait, 60_000));
        const r = await this.fetchImpl(`${this.base}${path}`, {
          method, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(60_000),
          headers: { "DD-API-KEY": this.secrets.apiKey, "DD-APPLICATION-KEY": this.secrets.appKey, "content-type": "application/json", accept: "application/json" },
        });
        // Datadog rate-limit headers: proactively pause when the window is exhausted.
        const remaining = r.headers.get("x-ratelimit-remaining");
        const reset = Number(r.headers.get("x-ratelimit-reset"));
        if (remaining === "0" && Number.isFinite(reset)) this.pauseUntil = Date.now() + Math.min(reset, 60) * 1000;
        if (!r.ok) throw httpError(r.status, await r.text(), r.headers.get("retry-after") ?? (Number.isFinite(reset) && r.status === 429 ? String(Math.min(reset, 60)) : null));
        return (await r.json()) as T;
      }, { retries: opts.retry === false ? 0 : 5, sleep: this.opts.sleep });
    } catch (e) { throw scrubError(e, [this.secrets.apiKey, this.secrets.appKey]); }
  }

  private query(filter: string | null): string {
    const parts = [this.cfg.baseQuery, filter].map((x) => x?.trim()).filter((x): x is string => !!x && x !== "*");
    const q = parts.length ? parts.map((p) => `(${p})`).join(" ") : "*";
    if (q.length > 4000) throw new ConnectorError("Datadog query too long");
    return q;
  }

  private search(sourceType: string, filter: string | null, from: string, to: string, limit: number, cursor?: string | null, retry = true) {
    const path = SOURCE_PATH[sourceType];
    if (!path) throw new Error(`source type ${sourceType} not implemented for Datadog`);
    const body: Record<string, unknown> = { filter: { query: this.query(filter), from, to }, sort: "timestamp", page: { limit, ...(cursor ? { cursor } : {}) } };
    if (sourceType === "datadog_logs") (body.filter as Record<string, unknown>).indexes = this.cfg.indexes.length ? this.cfg.indexes : ["*"];
    return this.request<{ data?: unknown[]; meta?: { page?: { after?: string } } }>("POST", path, body, { retry });
  }

  async testConnection(): Promise<ConnectionTestResult> {
    const res: ConnectionTestResult = {
      ok: false, provider: "datadog", accountRef: `${this.cfg.orgName}@${this.cfg.site}`, principal: null, credentialType: "api_key+application_key",
      checks: [], readOnly: true, warnings: [], errors: [], sampleReadOk: false, testedAt: new Date().toISOString(),
    };
    try {
      const v = await this.request<{ valid?: boolean }>("GET", "/api/v1/validate", undefined, { retry: false });
      if (!v.valid) throw new Error("API key not valid for this site");
    } catch (e) {
      res.errors.push(this.scrub(`API key validation failed: ${(e as Error).message}`));
      return res;
    }
    // Application key scopes. A key scoped to logs_read_data cannot list application keys (403) — that is the
    // expected, least-privilege outcome. If listing succeeds, the key has broader rights; inspect its scopes.
    const last4 = this.secrets.appKey.slice(-4);
    try {
      const keys = await this.request<{ data?: Array<{ id: string; attributes?: { name?: string; last4?: string; scopes?: string[] | null; owner?: unknown } }> }>("GET", "/api/v2/current_user/application_keys?page[size]=100", undefined, { retry: false });
      const mine = (keys.data ?? []).find((k) => k.attributes?.last4 === last4);
      res.principal = mine?.attributes?.name ? `application key "${mine.attributes.name}"` : null;
      if (!mine) {
        res.checks.push({ permission: "application key: user_app_keys (can list keys)", granted: true, required: false, excessive: true });
        res.warnings.push("Application key can list the user's application keys (broader than logs_read_data) and its own scopes could not be matched.");
      } else if (mine.attributes?.scopes == null) {
        res.checks.push({ permission: "application key: unscoped (all user permissions)", granted: true, required: false, excessive: true });
      } else {
        for (const s of mine.attributes.scopes) res.checks.push({ permission: s, granted: true, required: s === REQUIRED_SCOPE, excessive: DATADOG_ALLOWED_SCOPES.includes(s) ? undefined : true });
        if (!mine.attributes.scopes.includes(REQUIRED_SCOPE)) res.errors.push(`application key is missing the ${REQUIRED_SCOPE} scope`);
      }
    } catch (e) {
      const status = (e as ConnectorError).status;
      if (status === 403 || status === 401) {
        res.checks.push({ permission: "application key: user_app_keys (can list keys)", granted: false, required: false });
        res.warnings.push("Application key is scoped (it cannot list application keys). Verify it carries only logs_read_data (+ optional security_monitoring_signals_read, audit_logs_read).");
      } else res.warnings.push(this.scrub(`could not inspect application key scopes: ${(e as Error).message.slice(0, 160)}`));
    }
    const excessive = res.checks.filter((c) => c.excessive && c.granted);
    if (excessive.length) {
      res.readOnly = false;
      res.warnings.push(`Application key is broader than needed: ${excessive.map((c) => c.permission).join(", ")}. Create a scoped application key with only logs_read_data (optionally security_monitoring_signals_read, audit_logs_read).`);
    }
    try {
      await this.search("datadog_logs", null, "now-15m", "now", 1, null, false);
      res.sampleReadOk = true;
      if (!res.checks.some((c) => c.permission === REQUIRED_SCOPE)) res.checks.push({ permission: REQUIRED_SCOPE, granted: true, required: true });
    } catch (e) {
      if (!res.checks.some((c) => c.permission === REQUIRED_SCOPE)) res.checks.push({ permission: REQUIRED_SCOPE, granted: false, required: true });
      res.errors.push(this.scrub(`log search probe failed: ${(e as Error).message}`));
    }
    for (const [st, scope] of [["datadog_siem_signals", "security_monitoring_signals_read"], ["datadog_audit", "audit_logs_read"]] as const) {
      if (res.checks.some((c) => c.permission === scope)) continue;
      const granted = await this.search(st, null, "now-15m", "now", 1, null, false).then(() => true, () => false);
      res.checks.push({ permission: scope, granted, required: false });
    }
    res.ok = res.sampleReadOk && res.errors.length === 0;
    return res;
  }

  async discoverSources(): Promise<DiscoveredSource[]> {
    const out: DiscoveredSource[] = [];
    for (const s of datadogKnownSources()) {
      let available = false;
      let note: string | undefined;
      try { available = ((await this.search(s.sourceType, s.filter, "now-24h", "now", 1, null, false)).data ?? []).length > 0; }
      catch (e) { note = this.scrub((e as Error).message.slice(0, 160)); }
      out.push({ ...s, available, meta: { ...s.meta, ...(note ? { error: note } : {}) } });
    }
    return out;
  }

  async listEvents(q: ListEventsQuery): Promise<EventPage> {
    const out = await this.search(q.sourceType, q.filter, q.start.toISOString(), q.end.toISOString(), Math.min(q.pageSize ?? 1000, 1000), q.pageToken);
    const data = out.data ?? [];
    // Datadog may return a cursor with an empty page at the end of results; stop there.
    return { raw: data, nextPageToken: data.length && out.meta?.page?.after ? out.meta.page.after : null };
  }

  normalize(raw: unknown, sourceType: string): CanonicalEvent {
    return normalizeDatadog(raw, sourceType, `${this.cfg.orgName}@${this.cfg.site}`);
  }

  async getCheckpoint(sourceId: string) { return this.checkpoints?.get(sourceId) ?? null; }
  async saveCheckpoint(sourceId: string, cp: { watermark: string | null; pageToken: string | null }) { await this.checkpoints?.save(sourceId, cp); }
  async disconnect() {}
}

const SIGNAL_SEV: Record<string, "info" | "low" | "medium" | "high" | "critical"> = { info: "info", low: "low", medium: "medium", high: "high", critical: "critical" };

/** Normalize one Datadog search result item (`{ id, type, attributes }`). */
export function normalizeDatadog(raw: unknown, sourceType: string, accountRef: string | null): CanonicalEvent {
  const item = raw as { id?: string; attributes?: Record<string, any> };
  const at = item.attributes ?? {};
  const tags: string[] = Array.isArray(at.tags) ? at.tags.filter((t: unknown) => typeof t === "string") : [];
  const tag = (k: string) => tags.find((t) => t.startsWith(`${k}:`))?.slice(k.length + 1) ?? null;
  const inner: Record<string, any> = at.attributes && typeof at.attributes === "object" ? at.attributes : {};
  if (sourceType === "datadog_siem_signals") {
    const custom: Record<string, any> = at.custom ?? inner ?? {};
    const sev = String(custom.severity ?? inner.severity ?? tag("severity") ?? "").toLowerCase();
    const base = normalizeForwardedLog({ platform: "datadog", id: item.id ?? null, timestamp: at.timestamp ?? null, message: at.message ?? null, host: at.host ?? null, service: at.service ?? null, source: "security_signal", level: null, tags, attributes: inner }, { accountRef, sourceType });
    const title = custom.title ?? inner.title ?? custom.workflow?.rule?.name ?? (typeof at.message === "string" ? at.message.split("\n")[0] : null);
    return {
      ...base, normalizedEventType: "security.finding", categories: ["security.finding"], severity: SIGNAL_SEV[sev] ?? null,
      action: custom.workflow?.rule?.name ?? base.action, status: null,
      normalized: { ...base.normalized, ocsf: { class_uid: 2004, class_name: "Detection Finding" }, finding: { title, rule_id: custom.workflow?.rule?.id ?? null, triage_state: custom.workflow?.triage?.state ?? null } },
    };
  }
  return normalizeForwardedLog({
    platform: "datadog", id: item.id ?? null, timestamp: at.timestamp ?? null, message: at.message ?? null,
    host: at.host ?? null, service: at.service ?? null, source: inner.ddsource ?? at.source ?? tag("source"), level: at.status ?? null, tags, attributes: inner,
  }, { accountRef, sourceType });
}

// ---------- registry definition ----------

const DatadogConfigSchema = z.object({
  site: z.enum(DATADOG_SITES).default("datadoghq.com").meta({ title: "Datadog site", description: "The site your org lives on (US1 = datadoghq.com, EU = datadoghq.eu, US1-FED = ddog-gov.com)", ui: { kind: "select" } }),
  orgName: z.string().regex(/^[A-Za-z0-9._-]{1,64}$/).meta({ title: "Organization name", description: "Label for this Datadog org (used as the account reference)", ui: { placeholder: "acme-prod" } }),
  indexes: z.array(z.string().regex(/^[\w*.-]{1,100}$/)).min(1).max(50).default(["*"]).meta({ title: "Log indexes", ui: { kind: "list" } }),
  baseQuery: z.string().max(1000).optional().meta({ title: "Base query (optional)", description: "Datadog log search syntax ANDed with every source, e.g. env:prod" }),
});
type DatadogConfig = z.infer<typeof DatadogConfigSchema>;

const DatadogCredentialSchema = z.object({
  apiKey: z.string().regex(/^[A-Za-z0-9]{32}$/, "Datadog API keys are 32 alphanumeric characters").meta({ title: "API key", ui: { kind: "secret" } }),
  appKey: z.string().regex(/^[A-Za-z0-9]{40}$/, "Datadog application keys are 40 alphanumeric characters").meta({ title: "Application key (scoped: logs_read_data)", ui: { kind: "secret" } }),
});
type DatadogCredentials = z.infer<typeof DatadogCredentialSchema>;

export const datadogConnectorDefinition: ConnectorDefinition<DatadogConfig, DatadogCredentials> = {
  id: "datadog", kind: "log_platform", displayName: "Datadog", version: "1.0.0",
  description: "Logs, Cloud SIEM signals and Audit Trail via the read-only search APIs.",
  configSchema: DatadogConfigSchema,
  credentialSchema: DatadogCredentialSchema,
  authModes: [{ id: "api_key+application_key", label: "API key + scoped application key", description: "Application key scoped to logs_read_data; stored encrypted" }],
  authModeOf: () => "api_key+application_key",
  accountRefOf: (c) => `${c.orgName}@${c.site}`,
  prepareSecrets: (_c, creds) => (creds ? { apiKey: creds.apiKey, appKey: creds.appKey } : null),
  validate: (_c, creds) => (creds?.apiKey && creds?.appKey ? null : "apiKey and appKey are required"),
  create: (c, secrets, cps, rt) => new DatadogConnector(c, secrets, cps, rt),
  knownSources: () => datadogKnownSources(),
  normalizers: { "*": (raw, ctx) => normalizeDatadog(raw, ctx.sourceType, `${ctx.config.orgName}@${ctx.config.site}`) },
  onboardingInstructions: (c) => ({
    steps: [
      `Organization Settings → Application Keys → New Key → "vigil-reader" → Scopes: logs_read_data (optional: security_monitoring_signals_read, audit_logs_read). Do not leave the key unscoped.`,
      "Organization Settings → API Keys → New Key → \"vigil-reader\" (API keys only identify the org; Vigil never sends data to Datadog).",
      "Prefer creating both keys as a service account with the Datadog Read Only role so the key cannot exceed read access.",
    ],
    api: `https://api.${c.site}`,
    note: "Vigil only calls search endpoints (POST /api/v2/logs/events/search, …/security_monitoring/signals/search, …/audit/events/search). The connection test flags unscoped or broader keys as over-privileged.",
  }),
  auditSourcePrefixes: ["datadog_audit"],
  formHelp: "Use an application key scoped to logs_read_data only (optionally security_monitoring_signals_read and audit_logs_read). Unscoped keys inherit the creating user's full permissions and are flagged as over-privileged.",
};
