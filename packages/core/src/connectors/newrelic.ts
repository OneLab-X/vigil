import { z } from "zod";
import type { CanonicalEvent } from "../types.js";
import { detectEmbeddedCloud, normalizeForwardedLog, unflatten } from "../normalize/logplatform.js";
import { httpError, withRetry } from "./retry.js";
import { scrubError, scrubSecrets } from "./secrets.js";
import { windowedQuery } from "./window.js";
import { ConnectorError, type CheckpointStore, type CloudConnector, type ConnectionTestResult, type DiscoveredSource, type EventPage, type ListEventsQuery } from "./types.js";
import type { ConnectorDefinition, ConnectorRuntime, KnownSource } from "./registry.js";

const ENDPOINT = { US: "https://api.newrelic.com/graphql", EU: "https://api.eu.newrelic.com/graphql" } as const;
/** NRQL `LIMIT MAX` for event queries. Reaching it means the window may be truncated → split. */
export const NRQL_LIMIT = 5000;

export interface NewRelicConnectionConfig {
  region: "US" | "EU";
  accountId: number;
  /** NRQL WHERE predicate ANDed with every source filter */
  nrqlWhere?: string;
}

/**
 * New Relic key types by prefix. Only User keys (NRAK-) can query NerdGraph; admin, license/ingest, insert and
 * browser keys are refused — they either grant write/admin rights or are not meant for reading.
 */
export function newRelicKeyType(key: string): "user" | "admin" | "ingest_license" | "insert" | "browser" | "query" | "unknown" {
  if (/^NRAK-/.test(key)) return "user";
  if (/^NRAA-/.test(key)) return "admin";
  if (/^NRII-/.test(key)) return "insert";
  if (/^NRIQ-/.test(key)) return "query";
  if (/^NRJS-/.test(key)) return "browser";
  if (/^[0-9a-f]{36}NRAL$/i.test(key) || /^[0-9a-f]{40}$/i.test(key)) return "ingest_license";
  return "unknown";
}

const ADMIN_GROUP = /(admin|manager|owner)/i;

/** Admin-supplied NRQL predicate: no clauses that change the query shape, no statement separators. */
export function validateNrqlWhere(f: string): string {
  const unquoted = f.replace(/'(?:[^'\\]|\\.)*'/g, "''");
  if (f.length > 1000 || /;/.test(unquoted) || /\b(SELECT|FROM|SINCE|UNTIL|LIMIT|OFFSET|FACET|TIMESERIES|COMPARE|EXTRAPOLATE|SHOW|WITH)\b/i.test(unquoted)) {
    throw new ConnectorError("NRQL filter must be a WHERE predicate only (no SELECT/FROM/SINCE/UNTIL/LIMIT/FACET/…)");
  }
  return f;
}

export function newRelicKnownSources(): KnownSource[] {
  const p = (name: string, filter: string | null, description: string, recommended = true): KnownSource => ({ sourceType: "newrelic_logs", name, filter, description, recommended, meta: { editableFilter: true } });
  return [
    p("AWS CloudTrail (forwarded)", "eventSource LIKE '%.amazonaws.com' AND eventName IS NOT NULL", "CloudTrail records in New Relic Logs — normalized with the AWS CloudTrail normalizer"),
    p("Google Cloud audit logs (forwarded)", "logName LIKE '%cloudaudit.googleapis.com%'", "GCP audit LogEntries — normalized with the GCP normalizer"),
    p("Azure Activity / Entra ID (forwarded)", "resourceId LIKE '/SUBSCRIPTIONS/%' OR resourceId LIKE '/subscriptions/%' OR category IN ('SignInLogs', 'AuditLogs')", "Azure Activity Log and Entra ID diagnostic exports — normalized with the Azure normalizer"),
    p("Web access logs", "logtype IN ('nginx', 'apache', 'haproxy', 'alb', 'elb')", "HTTP access logs (client IP, status, method, path)"),
    p("Authentication logs", "logtype IN ('auth', 'sshd', 'okta', 'auth0') OR `evt.category` = 'authentication'", "Login success / failure"),
    p("All logs", null, "Every log the key can read — high volume; prefer a narrower filter", false),
  ];
}

interface GqlResponse<T> { data?: T; errors?: Array<{ message?: string; extensions?: { errorClass?: string } }> }

/** Read-only New Relic connector: NerdGraph NRQL over the Log event type, windowed by timestamp. */
export class NewRelicConnector implements CloudConnector {
  readonly provider = "newrelic" as const;
  private readonly fetchImpl: typeof fetch;

  constructor(
    private readonly cfg: NewRelicConnectionConfig,
    private readonly secrets: { userApiKey: string },
    private readonly checkpoints?: CheckpointStore,
    rt: Partial<ConnectorRuntime> = {},
    private readonly opts: { sleep?: (ms: number) => Promise<void> } = {},
  ) {
    if (!Number.isSafeInteger(cfg.accountId) || cfg.accountId <= 0) throw new Error("invalid New Relic account id");
    if (!secrets?.userApiKey) throw new Error("New Relic User API key required");
    this.fetchImpl = rt.fetch ?? fetch;
  }

  private scrub = (m: string) => scrubSecrets(m, [this.secrets.userApiKey]);
  async connect(): Promise<void> {}

  private async gql<T>(query: string, variables: Record<string, unknown>, opts: { retry?: boolean } = {}): Promise<T> {
    try {
      return await withRetry(async () => {
        const r = await this.fetchImpl(ENDPOINT[this.cfg.region], {
          method: "POST", signal: AbortSignal.timeout(120_000), body: JSON.stringify({ query, variables }),
          headers: { "API-Key": this.secrets.userApiKey, "content-type": "application/json", "NewRelic-Requesting-Services": "vigil" },
        });
        if (!r.ok) throw httpError(r.status, await r.text(), r.headers.get("retry-after"));
        const j = (await r.json()) as GqlResponse<T>;
        if (j.errors?.length) {
          const cls = j.errors.map((e) => e.extensions?.errorClass ?? "").join(",");
          const msg = j.errors.map((e) => e.message ?? "error").join("; ").slice(0, 300);
          const throttled = /TOO_MANY_REQUESTS|RATE_LIMIT/i.test(cls) || /rate limit|too many/i.test(msg);
          const timeout = /TIMEOUT/i.test(cls) || /timed? ?out/i.test(msg);
          throw new ConnectorError(`NerdGraph ${cls || "error"}: ${msg}`, throttled ? 429 : timeout ? 504 : 400, throttled || /SERVER_ERROR/i.test(cls));
        }
        return j.data as T;
      }, { retries: opts.retry === false ? 0 : 5, sleep: this.opts.sleep });
    } catch (e) { throw scrubError(e, [this.secrets.userApiKey]); }
  }

  private nrql<T = Record<string, unknown>>(nrql: string, retry = true): Promise<T[]> {
    return this.gql<{ actor?: { account?: { nrql?: { results?: T[] } } | null } }>(
      "query($accountId: Int!, $nrql: Nrql!) { actor { account(id: $accountId) { nrql(query: $nrql, timeout: 90) { results } } } }",
      { accountId: this.cfg.accountId, nrql }, { retry },
    ).then((d) => {
      if (!d?.actor?.account) throw new ConnectorError(`key cannot access account ${this.cfg.accountId}`, 403);
      return d.actor.account.nrql?.results ?? [];
    });
  }

  private where(filter: string | null): string {
    const parts = [this.cfg.nrqlWhere, filter].map((x) => x?.trim()).filter((x): x is string => !!x).map((x) => `(${validateNrqlWhere(x)})`);
    return parts.length ? ` WHERE ${parts.join(" AND ")}` : "";
  }

  async testConnection(): Promise<ConnectionTestResult> {
    const res: ConnectionTestResult = {
      ok: false, provider: "newrelic", accountRef: String(this.cfg.accountId), principal: null, credentialType: `user_api_key:${this.cfg.region}`,
      checks: [], readOnly: true, warnings: [], errors: [], sampleReadOk: false, testedAt: new Date().toISOString(),
    };
    const kind = newRelicKeyType(this.secrets.userApiKey);
    res.checks.push({ permission: "key type: User API key (NRAK-)", granted: kind === "user", required: true });
    if (kind === "admin") { res.readOnly = false; res.checks.push({ permission: "key type: admin key (NRAA-)", granted: true, required: false, excessive: true }); }
    if (kind !== "user") {
      res.errors.push(kind === "admin" ? "Admin API keys (NRAA-) grant write/admin rights — create a User API key for a read-only user instead"
        : `This is a ${kind.replace("_", "/")} key, not a User API key (NRAK-…); ingest/insert/browser keys cannot read via NerdGraph`);
      return res;
    }
    let userId: string | null = null;
    try {
      const d = await this.gql<{ actor?: { user?: { id?: number; email?: string; name?: string }; account?: { id: number; name?: string } | null } }>(
        "query($accountId: Int!) { actor { user { id email name } account(id: $accountId) { id name } } }", { accountId: this.cfg.accountId }, { retry: false });
      res.principal = d?.actor?.user?.email ?? null;
      userId = d?.actor?.user?.id != null ? String(d.actor.user.id) : null;
      const ok = !!d?.actor?.account;
      res.checks.push({ permission: `NerdGraph access to account ${this.cfg.accountId}`, granted: ok, required: true });
      if (!ok) { res.errors.push(`the key's user cannot access account ${this.cfg.accountId}`); return res; }
    } catch (e) {
      res.errors.push(this.scrub(`NerdGraph authentication failed: ${(e as Error).message}`));
      return res;
    }
    // User keys inherit the user's roles. Best effort: if the user can read user management, inspect their groups.
    try {
      const d = await this.gql<any>(
        "query($uid: String!) { actor { organization { userManagement { authenticationDomains { authenticationDomains { users(filter: { id: { eq: $uid } }) { users { groups { groups { displayName } } } } } } } } } }",
        { uid: userId ?? "" }, { retry: false });
      const groups: string[] = (d?.actor?.organization?.userManagement?.authenticationDomains?.authenticationDomains ?? [])
        .flatMap((ad: any) => ad?.users?.users ?? []).flatMap((u: any) => u?.groups?.groups ?? []).map((g: any) => String(g?.displayName ?? "")).filter(Boolean);
      const admin = groups.filter((g) => ADMIN_GROUP.test(g));
      for (const g of admin) res.checks.push({ permission: `user group: ${g}`, granted: true, required: false, excessive: true });
      if (admin.length) {
        res.readOnly = false;
        res.warnings.push(`The key's user is in admin groups (${admin.join(", ")}); User API keys inherit those rights. Create the key for a dedicated user in a read-only group.`);
      } else if (!groups.length) res.warnings.push("User groups not visible to this key — verify the key's user only has read-only access.");
    } catch {
      res.warnings.push("User management not readable with this key (expected for read-only users) — verify the key's user has no admin role.");
    }
    try {
      await this.nrql("SELECT count(*) FROM Log SINCE 15 minutes ago", false);
      res.sampleReadOk = true;
      res.checks.push({ permission: "NRQL: SELECT FROM Log", granted: true, required: true });
    } catch (e) {
      res.checks.push({ permission: "NRQL: SELECT FROM Log", granted: false, required: true });
      res.errors.push(this.scrub(`NRQL probe failed: ${(e as Error).message}`));
    }
    res.ok = res.sampleReadOk && res.errors.length === 0;
    return res;
  }

  async discoverSources(): Promise<DiscoveredSource[]> {
    const out: DiscoveredSource[] = [];
    for (const s of newRelicKnownSources()) {
      let available = false;
      let note: string | undefined;
      try {
        const r = await this.nrql<{ count?: number }>(`SELECT count(*) FROM Log${this.where(s.filter)} SINCE 1 day ago`, false);
        available = Number(r[0]?.count ?? 0) > 0;
      } catch (e) { note = this.scrub((e as Error).message.slice(0, 160)); }
      out.push({ ...s, available, meta: { ...s.meta, ...(note ? { error: note } : {}) } });
    }
    return out;
  }

  async listEvents(q: ListEventsQuery): Promise<EventPage> {
    if (q.sourceType !== "newrelic_logs") throw new Error(`source type ${q.sourceType} not implemented for New Relic`);
    const where = this.where(q.filter);
    const r = await windowedQuery({
      start: q.start, end: q.end, pageToken: q.pageToken, limit: NRQL_LIMIT,
      // SINCE is inclusive, UNTIL exclusive → contiguous windows; overlap from the scheduler is deduped.
      run: (s, e) => this.nrql(`SELECT * FROM Log${where} SINCE ${s.getTime()} UNTIL ${e.getTime()} LIMIT MAX`),
      splitOn: (err) => err instanceof ConnectorError && err.status === 504,
    });
    return { raw: r.rows, nextPageToken: r.nextPageToken };
  }

  normalize(raw: unknown, sourceType: string): CanonicalEvent {
    return normalizeNewRelic(raw, sourceType, String(this.cfg.accountId));
  }

  async getCheckpoint(sourceId: string) { return this.checkpoints?.get(sourceId) ?? null; }
  async saveCheckpoint(sourceId: string, cp: { watermark: string | null; pageToken: string | null }) { await this.checkpoints?.save(sourceId, cp); }
  async disconnect() {}
}

const s = (v: unknown) => (typeof v === "string" && v ? v : typeof v === "number" ? String(v) : null);

/** Normalize one NRQL `SELECT * FROM Log` row (flat, dotted attribute names). */
export function normalizeNewRelic(raw: unknown, sourceType: string, accountRef: string | null): CanonicalEvent {
  const row = (raw ?? {}) as Record<string, unknown>;
  let attrs = unflatten(row);
  // Some forwarders ship JSON as an unparsed message; parse it so cloud payloads can be recognised.
  const msg = typeof row.message === "string" ? row.message : null;
  if (msg && !detectEmbeddedCloud(attrs) && /^\s*\{/.test(msg) && msg.length < 200_000) {
    try { const parsed = JSON.parse(msg); if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) attrs = { ...parsed, ...attrs, message: msg }; } catch { /* plain text */ }
  }
  return normalizeForwardedLog({
    platform: "newrelic",
    id: s(row.messageId) ?? s(row["log.id"]) ?? null,
    timestamp: (row.timestamp as number | string | undefined) ?? null,
    message: msg,
    host: s(row.hostname) ?? s(row["host.name"]) ?? s(row.host),
    service: s(row["service.name"]) ?? s(row["entity.name"]) ?? s(row.service),
    source: s(row.logtype) ?? s(row["plugin.type"]),
    level: s(row.level) ?? s(row["log.level"]) ?? s(row.severity),
    tags: [],
    attributes: attrs,
  }, { accountRef, sourceType });
}

// ---------- registry definition ----------

const NewRelicConfigSchema = z.object({
  region: z.enum(["US", "EU"]).default("US").meta({ title: "Data center region", ui: { kind: "select", labels: { US: "US (api.newrelic.com)", EU: "EU (api.eu.newrelic.com)" } } }),
  accountId: z.coerce.number().int().positive().max(Number.MAX_SAFE_INTEGER).meta({ title: "Account ID", ui: { kind: "number", placeholder: "1234567" } }),
  nrqlWhere: z.string().max(1000).optional().meta({ title: "NRQL WHERE filter (optional)", description: "ANDed with every source, e.g. environment = 'prod'", ui: { placeholder: "environment = 'prod'" } }),
});
type NewRelicConfig = z.infer<typeof NewRelicConfigSchema>;

const NewRelicCredentialSchema = z.object({
  userApiKey: z.string().regex(/^NRAK-[A-Za-z0-9]{20,64}$/, "must be a New Relic User API key (NRAK-…); admin, license/ingest and browser keys are not accepted").meta({ title: "User API key", ui: { kind: "secret", placeholder: "NRAK-…" } }),
});
type NewRelicCredentials = z.infer<typeof NewRelicCredentialSchema>;

export const newRelicConnectorDefinition: ConnectorDefinition<NewRelicConfig, NewRelicCredentials> = {
  id: "newrelic", kind: "log_platform", displayName: "New Relic", version: "1.0.0",
  description: "Logs via NerdGraph NRQL (SELECT * FROM Log), windowed by timestamp.",
  configSchema: NewRelicConfigSchema,
  credentialSchema: NewRelicCredentialSchema,
  authModes: [{ id: "user_api_key", label: "User API key", description: "NRAK- key of a read-only user; stored encrypted" }],
  authModeOf: () => "user_api_key",
  accountRefOf: (c) => String(c.accountId),
  validate(c, creds) {
    if (!creds?.userApiKey) return "userApiKey required";
    if (c.nrqlWhere) try { validateNrqlWhere(c.nrqlWhere); } catch (e) { return (e as Error).message; }
    return null;
  },
  prepareSecrets: (_c, creds) => (creds ? { userApiKey: creds.userApiKey } : null),
  create: (c, secrets, cps, rt) => new NewRelicConnector(c, secrets, cps, rt),
  knownSources: () => newRelicKnownSources(),
  normalizers: { "*": (raw, ctx) => normalizeNewRelic(raw, ctx.sourceType, String(ctx.config.accountId)) },
  onboardingInstructions: (c) => ({
    steps: [
      "Administration → User management → create a dedicated user (e.g. vigil-reader) in a group with a read-only role (e.g. the built-in Read Only role) on this account only.",
      "Log in as / switch to that user → API keys → Create a key → Key type: User. Never use admin (NRAA-), license/ingest (…NRAL) or browser keys.",
    ],
    endpoint: ENDPOINT[c.region],
    note: "Vigil only runs NRQL SELECT queries through NerdGraph. The connection test refuses non-user keys and flags admin group membership as over-privileged when visible.",
  }),
  auditSourcePrefixes: [],
  formHelp: "Use a User API key (NRAK-…) belonging to a read-only user. Admin and ingest keys are rejected.",
};
