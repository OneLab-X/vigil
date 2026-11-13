# Vigil — Agentic SOC Platform: Architecture

Status: living document. Last updated 2026-11-11 (Increments 1–4 vertical slice).

## 1. Goals

Multi-tenant security operations platform: cloud signals → ingestion → normalization →
deterministic detection → correlation → AI investigation → evidence-backed verdict →
human decision → organizational learning. GCP first, AWS second, other providers via the
same connector contract.

Non-goals for the initial product: automatic remediation of any kind; agents never hold
cloud credentials or write to customer infrastructure.

## 2. Runtime components

```
                ┌────────────────────────── apps/web (Next.js 15) ─────────────────────────┐
                │ Overview · Incidents · Event Explorer · Connections · Rules · AI · KB ·   │
                │ Governance · Evaluation · Audit · Settings                                │
                └───────────────▲──────────────────────────────────────────────────────────┘
                                │ REST /api/v1 (session cookie, CSRF header, RBAC)
┌───────────────────────────────┴──────── apps/api (Node, Hono, Zod, OpenAPI) ──────────────┐
│ auth · RBAC · tenant context (RLS) · audit log · connections · ingestion · events ·       │
│ detection engine · incidents · approvals · knowledge · agent governance · TOOL BROKER     │
│ worker loop (Postgres SKIP LOCKED job queue): ingest → normalize → detect → correlate     │
└────────┬──────────────────────────────┬───────────────────────────────▲──────────────────┘
         │ read-only APIs               │ HTTP: start investigation     │ HTTP: tool calls
         ▼                              ▼  (scoped run token)           │  (scoped run token)
  GCP Cloud Logging v2           services/agents (Python FastAPI) ───────┘
  AWS STS/CloudTrail/CWL         Detection Analyst · Investigation Analyst
                                 model-provider abstraction (Anthropic/OpenAI/Gemini)
                                 output-contract validation · budgets · timeouts
         │
         ▼
  PostgreSQL 17 (+pgvector) — all tenant data, RLS enforced; raw payload store (local FS
  in dev, S3/GCS adapter interface for prod)
```

Why this split:
- **Control plane in TypeScript** owns all data access and every authorization decision.
- **Agent worker in Python** owns only LLM orchestration. It has no DB credentials, no cloud
  credentials and no network path except the model provider and the control-plane tool broker.
- **Tool broker** is the single choke point: it verifies an HMAC-signed run token (tenant,
  run id, agent role, tool allowlist, expiry), validates arguments with Zod, executes the
  query under the tenant's RLS context, caps result size, wraps log content as untrusted
  data, and persists every call to `investigation_tool_calls`.

## 3. Layers

### A. Connector layer (`packages/core/src/connectors`)

Every data source is a **`ConnectorDefinition`** registered in `connectors/registry.ts`
(built-ins in `connectors/builtin.ts`). The API, worker, detection DSL and web UI resolve
connectors only through the registry — there are no provider `if`s elsewhere:

```ts
interface ConnectorDefinition<Config, Credentials> {
  id: string;                         // "gcp" | "aws" | … — stored as text, validated by the registry
  kind: "cloud" | "log_platform";
  displayName; description; version;
  configSchema: ZodType<Config>;      // non-secret settings (cloud_connections.config); .meta() drives the UI form
  credentialSchema: ZodType<Credentials> | null; // secret fields → SecretStore only, never returned
  authModes: AuthModeInfo[];          // devOnly modes are refused in production
  accountRefOf(config): string;       // cloud_accounts.external_id
  validate?(config, credentials, runtime): string | null;
  prepareSecrets(config, credentials): unknown | null; // e.g. generate AWS ExternalId
  create(config, secrets, checkpointStore, runtime): CloudConnector;
  knownSources(config); normalizers: Record<sourceType | "*", Normalizer>;
  onboardingInstructions(config, secrets, runtime); sourceSetupInstructions?(config, source);
  auditSourcePrefixes: string[];      // control-plane audit sources for the agent's audit-log tool
  streaming?: …                       // reserved: push ingestion (webhooks / Event Hubs / forwarding)
}
```

`GET /api/v1/connectors` serves `describeConnector()` for each definition — id, kind, auth
modes, JSON Schema of config/credential fields and a flattened field list
(`text | select | secret | list | json | number`) — and the web "Add connection" picker
renders its form from it, so a new connector needs no page changes. Connection create
bodies are `{ provider, displayName, config, credentials? }`; the pre-registry flat GCP/AWS
body is still accepted. Provider columns (`cloud_connections.provider`,
`cloud_accounts.provider`, `security_events.cloud_provider`) are `text` with a format CHECK
(migration 0008); membership is validated in the app. SDK helpers: `scrubSecrets` /
`scrubError` (strip credential values from any error or probe result),
`assertSameOriginLink` (pagination links are only followed on the vendor's own origin).

| Connector | Kind | Auth | Sources | Status |
|---|---|---|---|---|
| `gcp` | cloud | ADC · WIF · gcloud CLI (dev) | Cloud Logging: audit (admin/system/policy/data access), App Engine, LB/Cloud Armor, VPC flow | live-tested |
| `aws` | cloud | STS AssumeRole + ExternalId | CloudTrail management events, CloudWatch Logs | adapter, not live-tested |
| `datadog` | log_platform | API key + application key scoped to `logs_read_data` (SecretStore) | Logs search (presets by `source:`), Cloud SIEM signals → `security.finding`, Audit Trail | adapter + fixtures, not live-tested |
| `newrelic` | log_platform | User API key `NRAK-` (SecretStore) | Logs via NerdGraph NRQL, windowed by timestamp | adapter + fixtures, not live-tested |
| `azure` | cloud | workload identity federation · client secret (SecretStore) · Azure CLI (dev) | Activity Log (ARM), Entra ID sign-in + audit (Graph or Log Analytics KQL), Defender for Cloud alerts → `security.finding` | adapter + fixtures, not live-tested |

Each connector implements the runtime contract:

```ts
interface CloudConnector {
  readonly provider: ConnectorId;
  connect(): Promise<void>;                              // obtain short-lived credentials
  testConnection(): Promise<ConnectionTestResult>;       // identity + permission probe, read-only
  discoverSources(): Promise<DiscoveredSource[]>;        // log names / trails / log groups
  listEvents(q: ListEventsQuery): Promise<EventPage>;    // paginated, time-bounded pull
  startStreaming?(h: StreamHandler): Promise<StreamHandle>; // Pub/Sub / CW subscription (later)
  getCheckpoint(sourceId): Promise<Checkpoint | null>;
  saveCheckpoint(sourceId, cp): Promise<void>;
  disconnect(): Promise<void>;                           // drop cached creds
}
```

Common behaviors are implemented once (`withRetry` exponential backoff + jitter honoring
429/`Retry-After`, page loop, checkpoint persistence). Providers only translate.

- **GCP** (implemented, live-tested): Cloud Logging `entries.list` with filter expressions,
  `pageToken`, explicit `timestamp >=/<` bounds (no console 5‑minute window), ADC locally,
  Workload Identity Federation in prod (same ADC code path via external-account config). Permission probe:
  `projects.getIamPolicy` is *not* used (needs more rights); instead we call
  `logs.list` + `entries.list pageSize=1` and `testIamPermissions` for
  `logging.logEntries.list`, `logging.logs.list`, `logging.privateLogEntries.list`
  (data-access), flagging any write permission found as a least-privilege warning.
  Pub/Sub sink streaming is designed as an *admin-approved setup step* (generated gcloud
  commands shown to the customer admin); the reader never creates sinks.
- **Azure** (adapter implemented with recorded fixtures, not live-tested): OAuth2 client-credentials
  (federated assertion from `AZURE_FEDERATED_TOKEN_FILE`, or a client secret), per-resource token cache.
  Probe: `Microsoft.Authorization/permissions` on the subscription evaluated with Azure wildcard /
  `notActions` semantics; Graph token `roles`/`scp` claims. Activity Log uses `$filter` time bounds + `nextLink`;
  Graph uses `$filter` + `@odata.nextLink` (both only followed on their own origin/path); Log Analytics uses
  windowed KQL (`connectors/window.ts`) that halves a window whenever it hits the 5,000-row cap, so nothing is
  silently truncated. Normalizers accept both REST and exported/diagnostic schemas (case-insensitive lookup).
- **Log platforms** (`normalize/logplatform.ts`): a forwarded record that carries a known cloud payload
  (CloudTrail fields, a GCP `LogEntry` under `data`, Azure Activity / Entra diagnostic schema) is normalized by
  that cloud's normalizer — same categories, provider rules and dedup key as direct ingestion, `cloudProvider`
  = origin cloud, `normalized.via` = platform. Everything else maps Datadog standard attributes /
  OpenTelemetry names (`network.client.ip`, `http.status_code`, `http.method`, `http.url_details.path`,
  `usr.id|email`, `evt.name|outcome`, `service`, `host`); unknown shapes become `app.log` with nulls.
- **Datadog** (adapter + fixtures, not live-tested): search APIs with cursor paging and explicit time bounds;
  probe = `/api/v1/validate` + application-key scope introspection (a 403 on listing keys is the expected
  least-privilege result) + 1-record search.
- **New Relic** (adapter + fixtures, not live-tested): NerdGraph `account.nrql` with
  `SELECT * FROM Log … SINCE/UNTIL <epoch ms> LIMIT MAX`; windows from `connectors/window.ts` split on the
  5,000-row cap and on NRQL timeouts. Rows are flat (`a.b.c` keys) and are unflattened before the shared
  log-platform normalizer; a JSON string `message` is parsed so forwarded cloud payloads are still recognised.
  Probe = key-type check (only `NRAK-` user keys) + account access + best-effort admin-group check + `count(*)`.
- **AWS** (adapter implemented, not live-tested — no customer account available): STS
  `AssumeRole` with per-connection `ExternalId`, 1h session creds, CloudTrail
  `LookupEvents` (management events) and CloudWatch Logs `FilterLogEvents`. GuardDuty /
  Security Hub declared as source types, adapters pending (Increment 6).

### B. Normalization (`packages/core/src/normalize`)

Canonical `SecurityEvent` (see ERD) with nullable fields; never fabricated. Mapping keeps an
OCSF `class_uid`/`activity_id` hint in `normalized_payload.ocsf` (e.g. 4002 HTTP Activity,
3005 Account Change / 6003 API Activity) and OTel-style `resource`/`attributes` naming.

- Raw entry stored immutably (`raw_event_references` → content-addressed blob, sha256).
- `deduplication_key = sha256(provider|account|providerEventId)`; GCP uses `insertId`+`logName`,
  AWS uses `EventId`. Unique index `(tenant_id, deduplication_key)` → `ON CONFLICT DO NOTHING`
  makes ingestion idempotent across retries, overlapping windows and duplicate delivery.
- Late events: incremental windows overlap by a configurable lag (default 5 min) and rely
  on dedup; detections run over `event_timestamp`, not ingestion time.
- Trace correlation: GCP `trace`/`spanId`, App Engine `protoPayload.traceId`/`requestId`
  map to `trace_id`/`request_id`, so request logs and app stdout lines join.

### C. Detection & correlation (`packages/core/src/detection`)

Deterministic, LLM-free. Rule schema (`detection_rules`): id, name, provider (`any` or
specific), event_sources, `detection_query` (JSON DSL), conditions, severity, MITRE
mapping, enabled, version, owner, approval status. Rule kinds:
`match` (single event predicate), `threshold` (count by group key within window),
`rate_spike` (window count vs baseline), `distinct` (distinct values of a field per key,
e.g. port scan), `sequence` (A then B by same entity within window). Each run writes
`detection_runs`; hits produce `findings` with `dedup_key = rule|group|window-bucket` so
re-runs don't duplicate. Correlator groups open findings by entity (IP/principal/resource)
within a time window into an `incident`, linking events via `incident_events`.
Sigma: a `sigma` import maps the Sigma `detection` selection subset (field|modifiers,
`condition: selection`) into `match` rules; unsupported constructs are rejected loudly.

### D. AI investigation (`services/agents`)

Two roles, one engine, provider-agnostic input (canonical events only):
- **Detection Analyst** — triage: tools `search_events`, `get_event_details`,
  `get_identity_activity`, `create_investigation_note`. Output: `{should_investigate,
  rationale, enrichment}`. Cannot emit verdicts.
- **Investigation Analyst** — full tool set incl. `get_related_incidents`,
  `search_approved_security_knowledge`, `propose_detection_rule`. Output: the investigation
  contract (verdict ∈ confirmed|likely|benign|inconclusive|needs_more_data, severity,
  confidence, timeline, evidence, contradictory_evidence, impact, recommendations,
  `requires_human_approval: true`).
Sensitive values (IPs, emails, identities, accounts, resources) are pseudonymized per run at the tool broker
before reaching the model and restored before validation ([AI_DATA_HANDLING.md](AI_DATA_HANDLING.md#masking-on-by-default)).
Model selection is per agent version: either a customer-configured provider (Settings → AI models: Gemini,
Anthropic, OpenAI or any OpenAI-compatible endpoint such as Ollama; key encrypted in `vigil_secrets`, passed to the
worker per run) or the worker's own env keys. An organization AI data policy can restrict runs to customer-hosted
models. Default model: Gemini `gemini-4-argon` via the Gemini API (`generateContent`, API key held only by the
agent worker); Anthropic/OpenAI remain selectable per agent version in Agent Governance. Every model
must have a price in `pricing.py` or the run is refused, so the USD budget can't be silently disabled.
Guards: role prompt + task, tool allowlist in signed token, max steps, wall-clock timeout,
token & USD budget, per-call result truncation, structured JSON output validated by
Pydantic **and** re-validated by the control plane, which rejects any evidence whose
`event_id` was not returned by a tool call in that same run (grounding check) and checks
quoted IPs/timestamps against the referenced event. Log content is delivered inside
`<untrusted_log_data>` envelopes with a standing instruction that it is data only.

### E. Knowledge base

`security_knowledge` (kind: trusted_identity | trusted_ip | false_positive | policy |
lesson | incident_conclusion), versioned, owner, status (proposed|approved|rejected|expired),
`expires_at`. Agents may only *propose*; `knowledge_approvals` requires a human with
`analyst+` role who is not the proposer. Approved entries are retrievable by agents via
`search_approved_security_knowledge` (structured filters; pgvector column reserved).

### F. Case management

Incident states: new → investigating → needs_review → confirmed | false_positive →
remediation_pending → resolved → closed (transition table enforced server-side).
`approval_requests` gate verdict acceptance and recommendations; every mutation writes
`audit_logs` (actor, action, target, before/after hash, request id).

## 4. Tenancy & security model (summary — see THREAT_MODEL.md)

- Every customer row has `tenant_id`; RLS policies `USING (tenant_id = current_setting('app.tenant_id')::uuid)`
  with `FORCE ROW LEVEL SECURITY`. The API connects as `vigil_app` (NOBYPASSRLS, not owner);
  migrations run as `vigil_owner`. Each request runs in a transaction with `SET LOCAL app.tenant_id`.
- RBAC roles: owner > admin > analyst > viewer (+ internal `agent` principal for broker).
- Sessions: opaque random token in httpOnly SameSite=Lax cookie, sha256 stored; scrypt
  password hashing; CSRF via required `x-vigil-csrf` header on mutations; rate limiting on
  auth and API.
- Secrets: `SecretStore` interface (env / local encrypted file in dev; GCP Secret Manager /
  AWS Secrets Manager adapters). Connection secrets are references, never values in rows
  readable by agents.

## 5. Dependencies

| Concern | Choice | Notes |
|---|---|---|
| API framework | Hono + @hono/zod-openapi | Zod validation & generated OpenAPI 3.1 at `/api/v1/openapi.json` |
| ORM | Drizzle ORM + drizzle-kit | SQL migrations + hand-written RLS migration |
| DB | PostgreSQL 17, pgvector | local cluster in `.local/pg` for dev |
| Queue | Postgres `jobs` table w/ `FOR UPDATE SKIP LOCKED` behind `JobQueue` interface | Redis/SQS/PubSub adapters later |
| GCP | `@google-cloud/logging` not used; direct REST via `google-auth-library` | thinner, explicit pagination control |
| AWS | `@aws-sdk/client-sts`, `client-cloudtrail`, `client-cloudwatch-logs` | |
| New Relic | none — NerdGraph over `fetch` | one GraphQL query shape; no client library needed |
| Datadog | none — direct REST (`fetch`) to `api.<site>` | avoids a large client; only search endpoints are called |
| Azure | none — direct REST (`fetch`) to login.microsoftonline.com, ARM, Graph, Log Analytics | small surface, explicit paging/retry, same-origin `nextLink` check |
| Agents | FastAPI, Pydantic v2, httpx; anthropic/openai/google-genai SDKs optional | |
| Web | Next.js 15, Tailwind v4, shadcn-style components, lucide, Recharts, TanStack Query | |
| Workflow | in-process durable job queue now; Temporal when multi-step retries need it | |

## 6. Increments (status as of 2026-11-12)

| # | Scope | Status | Evidence |
|---|---|---|---|
| 1 | Monorepo, DB + migrations + RLS, auth, RBAC, audit, web shell | ✅ done | `apps/api/test/security.test.ts` (17 tests incl. cross-tenant) |
| 2 | GCP connector, permission probe, discovery, historical + incremental polling, checkpoints, normalization, Event Explorer | ✅ done, **live-tested** on `example-project` | `scripts/verify-gcp-live.mts`: 1,880 App Engine + 6,761 audit events ingested, raw integrity verified |
| 3 | Rule DSL, 10 common + 2 provider rules, sliding windows, findings, correlation, incidents | ✅ done | core tests + e2e; real finding on `example-project` audit logs |
| 4 | Agent worker, tool broker, contract, grounding validation, workspace | ✅ done; **live-run on Gemini `gemini-4-argon`** 2026-11-12 against CASE-0001 (7 steps, 19 tool calls, grounded verdict `benign` 0.95, $0.34) | e2e acceptance + `services/agents/tests` + live run |
| 5 | Knowledge, four-eyes approval, feedback → suppression, detection replay eval, cost tracking | ◐ mostly done | agent-level eval against a real model not built yet |
| 6 | AWS STS/CloudTrail/CWL adapter, normalization, same investigation engine | ◐ adapter written, **not live-tested**; GuardDuty / Security Hub not implemented | e2e AWS section (fixtures) |
| 7 | Streaming, retention scheduling, notifications, tickets, deploy automation | ◐ deploy automation done (Docker Compose, install/backup/restore/upgrade scripts — [SELF_HOSTING.md](SELF_HOSTING.md)); streaming, retention scheduling, notifications, tickets not started | clean install + backup/restore test |
| + | Customer-controlled AI configuration (spec §17) | ✅ providers incl. OpenAI-compatible/Ollama, encrypted keys, data policy — [AI_DATA_HANDLING.md](AI_DATA_HANDLING.md) | `apps/api/test/selfhosted.test.ts`, `services/agents/tests/test_compat.py` |
