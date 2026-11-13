import { z } from "zod";
import type { CanonicalEvent, ConnectorId } from "../types.js";
import type { CheckpointStore, CloudConnector, DiscoveredSource } from "./types.js";

/**
 * Connector SDK: every data source Vigil can read from is described by one `ConnectorDefinition` and registered
 * here. The API, worker, detection DSL and web UI resolve connectors only through this registry, so adding a
 * connector means adding a definition — no provider checks elsewhere.
 *
 * Contract for implementations (enforced by review + tests, not by types):
 *  - read-only: no method may create, modify or delete anything in the customer's environment;
 *  - the permission probe flags write/admin capability as `excessive` (→ "over-privileged");
 *  - secrets come only from `credentialSchema` fields / `prepareSecrets`, are stored via SecretStore, and must be
 *    scrubbed from every error and test result (see ./secrets.ts);
 *  - paging is bounded and honours vendor rate limits (./retry.ts).
 */

export type ConnectorKind = "cloud" | "log_platform";

export interface AuthModeInfo {
  id: string;
  label: string;
  description: string;
  /** local development only — refused when NODE_ENV=production */
  devOnly?: boolean;
}

/** A source preset the connector knows about before discovery talks to the vendor. */
export type KnownSource = Omit<DiscoveredSource, "available">;

export type SourceNormalizer<C> = (raw: unknown, ctx: { config: C; sourceType: string }) => CanonicalEvent;

/** Process-level facts a definition may depend on. Never tenant-controlled. */
export interface ConnectorRuntime {
  production: boolean;
  env: Record<string, string | undefined>;
  /** test seam; defaults to global fetch */
  fetch?: typeof fetch;
}

export interface ConnectorDefinition<C = any, S = any> {
  id: ConnectorId;
  kind: ConnectorKind;
  displayName: string;
  description: string;
  /** bump when config/credential shape or normalization changes in a way operators should notice */
  version: string;
  /** non-secret settings stored in cloud_connections.config. Annotate fields with `.meta({ title, description, ui })`. */
  configSchema: z.ZodType<C>;
  /** user-supplied secret material (stored only via SecretStore). null = connector takes no credentials from the user. */
  credentialSchema: z.ZodType<S> | null;
  authModes: AuthModeInfo[];
  authModeOf(config: C): string;
  /** stable external reference for cloud_accounts.external_id (project id, account id, subscription id, org…) */
  accountRefOf(config: C): string;
  /** cross-field and environment checks at creation time; return a message for HTTP 400 */
  validate?(config: C, credentials: S | undefined, rt: ConnectorRuntime): string | null;
  /** secret material to persist (may be generated, e.g. AWS ExternalId); null → nothing stored */
  prepareSecrets(config: C, credentials: S | undefined): unknown | null;
  /** serialization of the stored secret (default JSON). Lets legacy rows keep their historical format. */
  encodeSecrets?(secrets: unknown): string;
  decodeSecrets?(stored: string): unknown;
  create(config: C, secrets: any, checkpoints: CheckpointStore | undefined, rt: ConnectorRuntime): CloudConnector;
  knownSources(config: C): KnownSource[];
  /** normalizers keyed by sourceType; "*" is the fallback */
  normalizers: Record<string, SourceNormalizer<C>>;
  /** what the customer admin must do to grant read-only access (shown once after creation) */
  onboardingInstructions(config: C, secrets: any, rt: ConnectorRuntime): unknown;
  /** customer-admin steps for a single source (e.g. a streaming sink). Vigil never executes them. */
  sourceSetupInstructions?(config: C, source: { sourceType: string; filter: string | null }): unknown;
  /** sourceType prefixes holding control-plane audit records (used by the agent's search_cloud_audit_logs tool) */
  auditSourcePrefixes: string[];
  /** short guidance rendered under the "Add connection" form */
  formHelp?: string;
  /** reserved for push ingestion (webhooks, Event Hubs, log forwarding) — not implemented yet */
  streaming?: { supported: false };
}

const ID_RE = /^[a-z][a-z0-9_]{1,31}$/;
const registry = new Map<string, ConnectorDefinition>();

export function registerConnector(def: ConnectorDefinition): void {
  if (!ID_RE.test(def.id)) throw new Error(`invalid connector id "${def.id}"`);
  if (def.id === "any") throw new Error(`"any" is reserved`);
  if (registry.has(def.id)) throw new Error(`connector "${def.id}" already registered`);
  registry.set(def.id, def);
}

export const getConnector = (id: string): ConnectorDefinition | undefined => registry.get(id);
export function requireConnector(id: string): ConnectorDefinition {
  const d = registry.get(id);
  if (!d) throw new Error(`unknown connector "${id}"`);
  return d;
}
export const listConnectors = (): ConnectorDefinition[] => [...registry.values()];
export const connectorIds = (): string[] => [...registry.keys()];
export const isConnectorId = (id: string): boolean => registry.has(id);

/** Pick the source normalizer for `sourceType`, falling back to "*". */
export function normalizerFor<C>(def: ConnectorDefinition<C>, sourceType: string): SourceNormalizer<C> {
  const n = def.normalizers[sourceType] ?? def.normalizers["*"];
  if (!n) throw new Error(`${def.id}: no normalizer for source type ${sourceType}`);
  return n;
}

export const encodeStoredSecrets = (def: ConnectorDefinition, s: unknown): string => (def.encodeSecrets ? def.encodeSecrets(s) : JSON.stringify(s));
export const decodeStoredSecrets = (def: ConnectorDefinition, stored: string): unknown => (def.decodeSecrets ? def.decodeSecrets(stored) : JSON.parse(stored));

// ---------- metadata for the API / UI (never contains secret values) ----------

export type FieldKind = "text" | "select" | "secret" | "list" | "json" | "textarea" | "number";

export interface FieldDescriptor {
  name: string;
  scope: "config" | "credentials";
  label: string;
  help: string | null;
  kind: FieldKind;
  required: boolean;
  secret: boolean;
  default?: unknown;
  placeholder?: string;
  pattern?: string;
  options?: Array<{ value: string; label: string }>;
  /** render only when another field has one of these values, e.g. { authMode: ["wif"] }; such fields are required when shown */
  showWhen?: Record<string, string[]>;
}

/** UI hints carried in Zod `.meta({ ui: … })`. */
export interface FieldUi {
  kind?: FieldKind;
  placeholder?: string;
  labels?: Record<string, string>;
  showWhen?: Record<string, string[]>;
  order?: number;
}

type JsonSchema = Record<string, any>;
const toJson = (s: z.ZodType): JsonSchema => z.toJSONSchema(s, { io: "input", unrepresentable: "any" }) as JsonSchema;

function fieldsOf(schema: JsonSchema, scope: FieldDescriptor["scope"]): FieldDescriptor[] {
  const props: Record<string, JsonSchema> = schema.properties ?? {};
  const required = new Set<string>(schema.required ?? []);
  return Object.entries(props).map(([name, p], i) => {
    const ui: FieldUi = p.ui ?? {};
    const secret = scope === "credentials" ? p.secret !== false : p.secret === true;
    const kind: FieldKind = ui.kind ?? (secret ? "secret" : p.enum ? "select" : p.type === "array" ? "list" : p.type === "object" ? "json" : p.type === "integer" || p.type === "number" ? "number" : "text");
    // Conditional fields are optional in the schema (absent for other modes) but required whenever they are shown;
    // definition.validate() enforces the same rule server-side.
    const f: FieldDescriptor = { name, scope, label: p.title ?? name, help: p.description ?? null, kind, required: (required.has(name) || !!ui.showWhen) && p.default === undefined, secret };
    if (p.default !== undefined && !secret) f.default = p.default;
    if (ui.placeholder) f.placeholder = ui.placeholder;
    if (typeof p.pattern === "string") f.pattern = p.pattern;
    if (Array.isArray(p.enum)) f.options = p.enum.map((v: string) => ({ value: v, label: ui.labels?.[v] ?? v }));
    if (ui.showWhen) f.showWhen = ui.showWhen;
    return { f, order: ui.order ?? i };
  }).sort((a, b) => a.order - b.order).map((x) => x.f);
}

export interface ConnectorDescription {
  id: string;
  kind: ConnectorKind;
  displayName: string;
  description: string;
  version: string;
  authModes: Array<AuthModeInfo & { available: boolean }>;
  fields: FieldDescriptor[];
  configSchema: JsonSchema;
  credentialSchema: JsonSchema | null;
  formHelp: string | null;
  streaming: boolean;
}

export function describeConnector(def: ConnectorDefinition, rt: Pick<ConnectorRuntime, "production">): ConnectorDescription {
  const configSchema = toJson(def.configSchema);
  const credentialSchema = def.credentialSchema ? toJson(def.credentialSchema) : null;
  // Drop default values from credential schemas defensively: a default secret would be a bug, never ship it.
  if (credentialSchema?.properties) for (const p of Object.values<JsonSchema>(credentialSchema.properties)) delete p.default;
  const fields = [...fieldsOf(configSchema, "config"), ...(credentialSchema ? fieldsOf(credentialSchema, "credentials") : [])];
  const authField = fields.find((f) => f.name === "authMode" && f.options);
  if (authField && rt.production) authField.options = authField.options!.filter((o) => !def.authModes.find((m) => m.id === o.value)?.devOnly);
  return {
    id: def.id, kind: def.kind, displayName: def.displayName, description: def.description, version: def.version,
    authModes: def.authModes.map((m) => ({ ...m, available: !(m.devOnly && rt.production) })),
    fields, configSchema, credentialSchema, formHelp: def.formHelp ?? null, streaming: false,
  };
}

/** Split a legacy flat request body into config and credential objects using the credential schema's keys. */
export function splitLegacyBody(def: ConnectorDefinition, flat: Record<string, unknown>): { config: Record<string, unknown>; credentials: Record<string, unknown> | undefined } {
  const credKeys = new Set(def.credentialSchema ? Object.keys((toJson(def.credentialSchema).properties ?? {})) : []);
  const config: Record<string, unknown> = {};
  const credentials: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(flat)) (credKeys.has(k) ? credentials : config)[k] = v;
  return { config, credentials: Object.keys(credentials).length ? credentials : undefined };
}
