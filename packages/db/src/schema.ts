import { sql } from "drizzle-orm";
import {
  pgTable, uuid, text, timestamp, jsonb, integer, boolean, real, bigint, index, uniqueIndex,
  pgEnum, primaryKey, numeric, vector, doublePrecision,
} from "drizzle-orm/pg-core";

// ---------- enums ----------
export const roleEnum = pgEnum("member_role", ["owner", "admin", "analyst", "viewer"]);
export const severityEnum = pgEnum("severity", ["info", "low", "medium", "high", "critical"]);
export const incidentStatusEnum = pgEnum("incident_status", [
  "new", "investigating", "needs_review", "confirmed", "false_positive",
  "remediation_pending", "resolved", "closed",
]);
export const verdictEnum = pgEnum("verdict", ["confirmed", "likely", "benign", "inconclusive", "needs_more_data"]);
export const runStatusEnum = pgEnum("run_status", ["queued", "running", "succeeded", "failed", "rejected", "timeout"]);
export const approvalStatusEnum = pgEnum("approval_status", ["pending", "approved", "rejected", "expired"]);

const id = () => uuid("id").primaryKey().default(sql`gen_random_uuid()`);
const tenantId = () => uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" });
const createdAt = () => timestamp("created_at", { withTimezone: true }).notNull().defaultNow();
const updatedAt = () => timestamp("updated_at", { withTimezone: true }).notNull().defaultNow();

// ---------- identity & tenancy ----------
export const tenants = pgTable("tenants", {
  id: id(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  retentionDays: integer("retention_days").notNull().default(90),
  settings: jsonb("settings").notNull().default({}),
  createdAt: createdAt(),
});

export const users = pgTable("users", {
  id: id(),
  email: text("email").notNull().unique(),
  displayName: text("display_name").notNull(),
  passwordHash: text("password_hash"),
  /** set for CLI-created accounts: the one-time password must be changed at first login */
  mustChangePassword: boolean("must_change_password").notNull().default(false),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: createdAt(),
});

export const memberships = pgTable("memberships", {
  id: id(),
  tenantId: tenantId(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  role: roleEnum("role").notNull(),
  createdAt: createdAt(),
}, (t) => [uniqueIndex("memberships_tenant_user_uq").on(t.tenantId, t.userId)]);

export const sessions = pgTable("sessions", {
  id: id(),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  tokenHash: text("token_hash").notNull().unique(),
  activeTenantId: uuid("active_tenant_id").references(() => tenants.id, { onDelete: "set null" }),
  csrfToken: text("csrf_token").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
  ip: text("ip"),
  createdAt: createdAt(),
});

// ---------- cloud connectivity ----------
export const cloudConnections = pgTable("cloud_connections", {
  id: id(),
  tenantId: tenantId(),
  /** connector id from the registry (gcp | aws | …); validated by the app, not a DB enum (migration 0008) */
  provider: text("provider").notNull(),
  displayName: text("display_name").notNull(),
  /** connector-specific non-secret config, validated by the registry definition's configSchema */
  config: jsonb("config").notNull(),
  /** reference into SecretStore (never the secret itself). AWS ExternalId lives here. */
  secretRef: text("secret_ref"),
  status: text("status").notNull().default("pending"), // pending|healthy|degraded|error|disconnected
  lastTestedAt: timestamp("last_tested_at", { withTimezone: true }),
  lastTestResult: jsonb("last_test_result"),
  lastSuccessfulIngestAt: timestamp("last_successful_ingest_at", { withTimezone: true }),
  createdBy: uuid("created_by").references(() => users.id),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
}, (t) => [index("cloud_connections_tenant_idx").on(t.tenantId)]);

export const cloudAccounts = pgTable("cloud_accounts", {
  id: id(),
  tenantId: tenantId(),
  connectionId: uuid("connection_id").notNull().references(() => cloudConnections.id, { onDelete: "cascade" }),
  provider: text("provider").notNull(), // connector id, see cloud_connections.provider
  externalId: text("external_id").notNull(), // connector account reference: GCP project id / AWS account id / …
  name: text("name"),
  createdAt: createdAt(),
}, (t) => [uniqueIndex("cloud_accounts_uq").on(t.tenantId, t.provider, t.externalId)]);

export const cloudResources = pgTable("cloud_resources", {
  id: id(),
  tenantId: tenantId(),
  cloudAccountId: uuid("cloud_account_id").notNull().references(() => cloudAccounts.id, { onDelete: "cascade" }),
  resourceType: text("resource_type").notNull(),
  resourceId: text("resource_id").notNull(),
  labels: jsonb("labels").notNull().default({}),
  firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [uniqueIndex("cloud_resources_uq").on(t.tenantId, t.cloudAccountId, t.resourceType, t.resourceId)]);

export const logSources = pgTable("log_sources", {
  id: id(),
  tenantId: tenantId(),
  connectionId: uuid("connection_id").notNull().references(() => cloudConnections.id, { onDelete: "cascade" }),
  cloudAccountId: uuid("cloud_account_id").notNull().references(() => cloudAccounts.id, { onDelete: "cascade" }),
  sourceType: text("source_type").notNull(), // gae_app | audit_admin | cloudtrail_mgmt | ...
  name: text("name").notNull(),
  filter: text("filter"), // provider filter expression
  ingestionMode: text("ingestion_mode").notNull().default("poll"), // poll | stream
  pollIntervalSeconds: integer("poll_interval_seconds").notNull().default(300),
  enabled: boolean("enabled").notNull().default(false),
  meta: jsonb("meta").notNull().default({}),
  createdAt: createdAt(),
}, (t) => [uniqueIndex("log_sources_uq").on(t.tenantId, t.connectionId, t.sourceType, t.name)]);

export const ingestionJobs = pgTable("ingestion_jobs", {
  id: id(),
  tenantId: tenantId(),
  logSourceId: uuid("log_source_id").notNull().references(() => logSources.id, { onDelete: "cascade" }),
  kind: text("kind").notNull(), // historical | incremental
  status: text("status").notNull().default("queued"), // queued|running|succeeded|failed
  rangeStart: timestamp("range_start", { withTimezone: true }).notNull(),
  rangeEnd: timestamp("range_end", { withTimezone: true }).notNull(),
  pagesFetched: integer("pages_fetched").notNull().default(0),
  eventsSeen: integer("events_seen").notNull().default(0),
  eventsInserted: integer("events_inserted").notNull().default(0),
  duplicates: integer("duplicates").notNull().default(0),
  error: text("error"),
  requestedBy: uuid("requested_by").references(() => users.id),
  startedAt: timestamp("started_at", { withTimezone: true }),
  finishedAt: timestamp("finished_at", { withTimezone: true }),
  createdAt: createdAt(),
}, (t) => [index("ingestion_jobs_tenant_idx").on(t.tenantId, t.createdAt), index("ingestion_jobs_source_idx").on(t.tenantId, t.logSourceId, t.createdAt.desc())]);

export const ingestionCheckpoints = pgTable("ingestion_checkpoints", {
  id: id(),
  tenantId: tenantId(),
  logSourceId: uuid("log_source_id").notNull().references(() => logSources.id, { onDelete: "cascade" }),
  /** high-water mark of event_timestamp fully ingested */
  watermark: timestamp("watermark", { withTimezone: true }),
  /** provider page token for resuming an interrupted job */
  pageToken: text("page_token"),
  jobId: uuid("job_id"),
  updatedAt: updatedAt(),
}, (t) => [uniqueIndex("ingestion_checkpoints_uq").on(t.tenantId, t.logSourceId)]);

// ---------- events ----------
export const rawEventReferences = pgTable("raw_event_references", {
  id: id(),
  tenantId: tenantId(),
  storageUri: text("storage_uri").notNull(), // file://... | gs://... | s3://...
  sha256: text("sha256").notNull(),
  sizeBytes: integer("size_bytes").notNull(),
  providerEventId: text("provider_event_id"),
  createdAt: createdAt(),
}, (t) => [uniqueIndex("raw_event_refs_uq").on(t.tenantId, t.sha256)]);

export const securityEvents = pgTable("security_events", {
  id: id(),
  tenantId: tenantId(),
  cloudProvider: text("cloud_provider").notNull(), // connector id of the event's origin (gcp | aws | …)
  cloudAccountId: uuid("cloud_account_id").references(() => cloudAccounts.id, { onDelete: "set null" }),
  projectOrAccountReference: text("project_or_account_reference"),
  logSourceId: uuid("log_source_id").references(() => logSources.id, { onDelete: "set null" }),
  region: text("region"),
  sourceType: text("source_type").notNull(),
  sourceName: text("source_name"),
  eventTimestamp: timestamp("event_timestamp", { withTimezone: true }).notNull(),
  ingestionTimestamp: timestamp("ingestion_timestamp", { withTimezone: true }).notNull().defaultNow(),
  resourceType: text("resource_type"),
  resourceId: text("resource_id"),
  serviceName: text("service_name"),
  severity: severityEnum("severity"),
  principal: text("principal"),
  sourceIp: text("source_ip"),
  destinationIp: text("destination_ip"),
  action: text("action"),
  status: text("status"), // success | failure | blocked | unknown | http status code
  httpStatus: integer("http_status"),
  httpMethod: text("http_method"),
  urlPath: text("url_path"),
  userAgent: text("user_agent"),
  traceId: text("trace_id"),
  requestId: text("request_id"),
  normalizedEventType: text("normalized_event_type").notNull(),
  categories: text("categories").array().notNull().default(sql`'{}'::text[]`),
  originalPayloadReference: uuid("original_payload_reference").references(() => rawEventReferences.id),
  normalizedPayload: jsonb("normalized_payload").notNull(),
  deduplicationKey: text("deduplication_key").notNull(),
}, (t) => [
  uniqueIndex("security_events_dedup_uq").on(t.tenantId, t.deduplicationKey),
  index("security_events_ts_idx").on(t.tenantId, t.eventTimestamp),
  index("security_events_ip_idx").on(t.tenantId, t.sourceIp, t.eventTimestamp),
  index("security_events_principal_idx").on(t.tenantId, t.principal, t.eventTimestamp),
  index("security_events_trace_idx").on(t.tenantId, t.traceId),
  index("security_events_type_idx").on(t.tenantId, t.normalizedEventType, t.eventTimestamp),
  index("security_events_categories_gin").using("gin", t.categories),
]);

// ---------- detection ----------
export const detectionRules = pgTable("detection_rules", {
  id: id(),
  tenantId: tenantId(),
  ruleId: text("rule_id").notNull(), // stable slug, e.g. VGL-HTTP-404-RECON
  name: text("name").notNull(),
  description: text("description").notNull(),
  provider: text("provider").notNull().default("any"), // any | <connector id>
  eventSources: jsonb("event_sources").notNull().default([]),
  detectionQuery: jsonb("detection_query").notNull(), // DSL, see packages/core/detection
  conditions: jsonb("conditions").notNull().default({}),
  severity: severityEnum("severity").notNull(),
  mitre: jsonb("mitre").notNull().default([]),
  enabled: boolean("enabled").notNull().default(true),
  version: integer("version").notNull().default(1),
  owner: text("owner"),
  approvalStatus: approvalStatusEnum("approval_status").notNull().default("approved"),
  proposedByRunId: uuid("proposed_by_run_id"),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  lastUpdated: timestamp("last_updated", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [uniqueIndex("detection_rules_uq").on(t.tenantId, t.ruleId, t.version)]);

export const detectionRuns = pgTable("detection_runs", {
  id: id(),
  tenantId: tenantId(),
  windowStart: timestamp("window_start", { withTimezone: true }).notNull(),
  windowEnd: timestamp("window_end", { withTimezone: true }).notNull(),
  rulesEvaluated: integer("rules_evaluated").notNull().default(0),
  findingsCreated: integer("findings_created").notNull().default(0),
  status: text("status").notNull().default("running"),
  error: text("error"),
  startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
  finishedAt: timestamp("finished_at", { withTimezone: true }),
});

export const findings = pgTable("findings", {
  id: id(),
  tenantId: tenantId(),
  ruleId: uuid("rule_id").notNull().references(() => detectionRules.id),
  detectionRunId: uuid("detection_run_id").references(() => detectionRuns.id),
  title: text("title").notNull(),
  severity: severityEnum("severity").notNull(),
  confidence: real("confidence").notNull(),
  groupKey: jsonb("group_key").notNull(), // {source_ip: "..."} etc
  eventIds: jsonb("event_ids").notNull(), // uuid[] (capped sample)
  eventCount: integer("event_count").notNull(),
  firstSeen: timestamp("first_seen", { withTimezone: true }).notNull(),
  lastSeen: timestamp("last_seen", { withTimezone: true }).notNull(),
  dedupKey: text("dedup_key").notNull(),
  details: jsonb("details").notNull().default({}),
  incidentId: uuid("incident_id"),
  status: text("status").notNull().default("open"),
  createdAt: createdAt(),
}, (t) => [uniqueIndex("findings_dedup_uq").on(t.tenantId, t.dedupKey), index("findings_tenant_idx").on(t.tenantId, t.createdAt)]);

// ---------- incidents ----------
export const incidents = pgTable("incidents", {
  id: id(),
  tenantId: tenantId(),
  caseNumber: integer("case_number").notNull(),
  title: text("title").notNull(),
  status: incidentStatusEnum("status").notNull().default("new"),
  severity: severityEnum("severity").notNull(),
  assigneeId: uuid("assignee_id").references(() => users.id),
  primaryEntity: jsonb("primary_entity").notNull().default({}),
  summary: text("summary"),
  currentVerdictId: uuid("current_verdict_id"),
  correlationKey: text("correlation_key").notNull(),
  firstSeen: timestamp("first_seen", { withTimezone: true }).notNull(),
  lastSeen: timestamp("last_seen", { withTimezone: true }).notNull(),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
}, (t) => [
  uniqueIndex("incidents_case_uq").on(t.tenantId, t.caseNumber),
  index("incidents_corr_idx").on(t.tenantId, t.correlationKey, t.status),
]);

export const incidentEvents = pgTable("incident_events", {
  tenantId: tenantId(),
  incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  eventId: uuid("event_id").notNull().references(() => securityEvents.id, { onDelete: "cascade" }),
  findingId: uuid("finding_id").references(() => findings.id),
  addedBy: text("added_by").notNull().default("correlator"),
  createdAt: createdAt(),
}, (t) => [primaryKey({ columns: [t.incidentId, t.eventId] })]);

export const incidentNotes = pgTable("incident_notes", {
  id: id(),
  tenantId: tenantId(),
  incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  authorUserId: uuid("author_user_id").references(() => users.id),
  authorRunId: uuid("author_run_id"),
  body: text("body").notNull(),
  createdAt: createdAt(),
});

// ---------- investigations ----------
export const agentDefinitions = pgTable("agent_definitions", {
  id: id(),
  tenantId: tenantId(),
  role: text("role").notNull(), // detection_analyst | investigation_analyst
  version: integer("version").notNull(),
  promptVersion: text("prompt_version").notNull(),
  modelProvider: text("model_provider").notNull(),
  modelName: text("model_name").notNull(),
  /** customer-configured provider (endpoint, key, prices); null = worker env-key mode */
  modelProviderId: uuid("model_provider_id").references(() => modelProviders.id, { onDelete: "restrict" }),
  allowedTools: jsonb("allowed_tools").notNull(),
  maxSteps: integer("max_steps").notNull().default(12),
  timeoutSeconds: integer("timeout_seconds").notNull().default(180),
  tokenBudget: integer("token_budget").notNull().default(200000),
  costBudgetUsd: numeric("cost_budget_usd", { precision: 10, scale: 4 }).notNull().default("2.0"),
  enabled: boolean("enabled").notNull().default(true),
  createdAt: createdAt(),
}, (t) => [uniqueIndex("agent_definitions_uq").on(t.tenantId, t.role, t.version)]);

export const investigationRuns = pgTable("investigation_runs", {
  id: id(),
  tenantId: tenantId(),
  incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  agentDefinitionId: uuid("agent_definition_id").notNull().references(() => agentDefinitions.id),
  role: text("role").notNull(),
  status: runStatusEnum("status").notNull().default("queued"),
  task: text("task").notNull(),
  modelProvider: text("model_provider"),
  modelName: text("model_name"),
  promptVersion: text("prompt_version"),
  /** "on": sensitive values were pseudonymized before reaching the model */
  masking: text("masking").notNull().default("off"),
  /** AES-GCM ciphertext of the run's token map (never sent to the model or returned by the API) */
  maskState: text("mask_state"),
  maskStats: jsonb("mask_stats"),
  steps: integer("steps").notNull().default(0),
  inputTokens: integer("input_tokens").notNull().default(0),
  outputTokens: integer("output_tokens").notNull().default(0),
  costUsd: numeric("cost_usd", { precision: 10, scale: 4 }).notNull().default("0"),
  output: jsonb("output"),
  validationErrors: jsonb("validation_errors"),
  error: text("error"),
  triggeredBy: uuid("triggered_by").references(() => users.id),
  startedAt: timestamp("started_at", { withTimezone: true }),
  finishedAt: timestamp("finished_at", { withTimezone: true }),
  createdAt: createdAt(),
}, (t) => [index("investigation_runs_incident_idx").on(t.tenantId, t.incidentId), index("investigation_runs_tenant_created_idx").on(t.tenantId, t.createdAt)]);

export const investigationToolCalls = pgTable("investigation_tool_calls", {
  id: id(),
  tenantId: tenantId(),
  runId: uuid("run_id").notNull().references(() => investigationRuns.id, { onDelete: "cascade" }),
  seq: integer("seq").notNull(),
  tool: text("tool").notNull(),
  arguments: jsonb("arguments").notNull(),
  allowed: boolean("allowed").notNull(),
  denialReason: text("denial_reason"),
  resultSummary: jsonb("result_summary"),
  returnedEventIds: jsonb("returned_event_ids").notNull().default([]),
  durationMs: integer("duration_ms"),
  createdAt: createdAt(),
}, (t) => [uniqueIndex("tool_calls_seq_uq").on(t.runId, t.seq)]);

export const investigationEvidence = pgTable("investigation_evidence", {
  id: id(),
  tenantId: tenantId(),
  runId: uuid("run_id").notNull().references(() => investigationRuns.id, { onDelete: "cascade" }),
  incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  eventId: uuid("event_id").references(() => securityEvents.id),
  kind: text("kind").notNull(), // supporting | contradictory
  claim: text("claim").notNull(),
  verified: boolean("verified").notNull(),
  createdAt: createdAt(),
});

export const investigationVerdicts = pgTable("investigation_verdicts", {
  id: id(),
  tenantId: tenantId(),
  runId: uuid("run_id").notNull().references(() => investigationRuns.id, { onDelete: "cascade" }),
  incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  verdict: verdictEnum("verdict").notNull(),
  severity: severityEnum("severity").notNull(),
  confidence: real("confidence").notNull(),
  summary: text("summary").notNull(),
  contract: jsonb("contract").notNull(), // full validated output contract
  reviewStatus: approvalStatusEnum("review_status").notNull().default("pending"),
  reviewedBy: uuid("reviewed_by").references(() => users.id),
  reviewedAt: timestamp("reviewed_at", { withTimezone: true }),
  reviewComment: text("review_comment"),
  createdAt: createdAt(),
});

export const recommendations = pgTable("recommendations", {
  id: id(),
  tenantId: tenantId(),
  incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  verdictId: uuid("verdict_id").references(() => investigationVerdicts.id, { onDelete: "cascade" }),
  action: text("action").notNull(),
  rationale: text("rationale"),
  priority: text("priority").notNull().default("medium"),
  status: text("status").notNull().default("proposed"), // proposed|approved|rejected|ticketed|done
  ticketRef: text("ticket_ref"),
  finalActionNote: text("final_action_note"),
  createdAt: createdAt(),
});

export const approvalRequests = pgTable("approval_requests", {
  id: id(),
  tenantId: tenantId(),
  subjectType: text("subject_type").notNull(), // verdict | recommendation | knowledge | rule
  subjectId: uuid("subject_id").notNull(),
  requestedByUserId: uuid("requested_by_user_id").references(() => users.id),
  requestedByRunId: uuid("requested_by_run_id"),
  status: approvalStatusEnum("status").notNull().default("pending"),
  decidedBy: uuid("decided_by").references(() => users.id),
  decidedAt: timestamp("decided_at", { withTimezone: true }),
  comment: text("comment"),
  createdAt: createdAt(),
}, (t) => [index("approval_requests_subject_idx").on(t.tenantId, t.subjectType, t.subjectId)]);

// ---------- knowledge ----------
export const securityKnowledge = pgTable("security_knowledge", {
  id: id(),
  tenantId: tenantId(),
  kind: text("kind").notNull(), // trusted_identity|trusted_ip|false_positive|policy|lesson|incident_conclusion
  key: text("key").notNull(), // e.g. ip "45.127.106.164", principal, rule id
  title: text("title").notNull(),
  body: text("body").notNull(),
  attributes: jsonb("attributes").notNull().default({}),
  version: integer("version").notNull().default(1),
  owner: text("owner"),
  status: approvalStatusEnum("status").notNull().default("pending"),
  sourceIncidentId: uuid("source_incident_id").references(() => incidents.id, { onDelete: "set null" }),
  proposedByUserId: uuid("proposed_by_user_id").references(() => users.id),
  proposedByRunId: uuid("proposed_by_run_id"),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  embedding: vector("embedding", { dimensions: 1536 }),
  createdAt: createdAt(),
}, (t) => [index("security_knowledge_lookup_idx").on(t.tenantId, t.kind, t.key, t.status)]);

export const knowledgeApprovals = pgTable("knowledge_approvals", {
  id: id(),
  tenantId: tenantId(),
  knowledgeId: uuid("knowledge_id").notNull().references(() => securityKnowledge.id, { onDelete: "cascade" }),
  decision: approvalStatusEnum("decision").notNull(),
  decidedBy: uuid("decided_by").notNull().references(() => users.id),
  comment: text("comment"),
  createdAt: createdAt(),
});

// ---------- governance ----------
export const agentEvaluations = pgTable("agent_evaluations", {
  id: id(),
  tenantId: tenantId(),
  suite: text("suite").notNull(),
  agentRole: text("agent_role").notNull(),
  modelProvider: text("model_provider").notNull(),
  modelName: text("model_name").notNull(),
  promptVersion: text("prompt_version").notNull(),
  metrics: jsonb("metrics").notNull(),
  cases: jsonb("cases").notNull(),
  createdAt: createdAt(),
});

export const modelUsage = pgTable("model_usage", {
  id: id(),
  tenantId: tenantId(),
  runId: uuid("run_id").references(() => investigationRuns.id, { onDelete: "set null" }),
  provider: text("provider").notNull(),
  model: text("model").notNull(),
  inputTokens: integer("input_tokens").notNull(),
  outputTokens: integer("output_tokens").notNull(),
  costUsd: numeric("cost_usd", { precision: 10, scale: 6 }).notNull(),
  createdAt: createdAt(),
}, (t) => [index("model_usage_tenant_idx").on(t.tenantId, t.createdAt), index("model_usage_run_idx").on(t.tenantId, t.runId)]);

export const auditLogs = pgTable("audit_logs", {
  id: bigint("id", { mode: "number" }).primaryKey().generatedAlwaysAsIdentity(),
  tenantId: uuid("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
  actorType: text("actor_type").notNull(), // user | agent | system
  actorId: text("actor_id"),
  action: text("action").notNull(),
  targetType: text("target_type"),
  targetId: text("target_id"),
  details: jsonb("details").notNull().default({}),
  requestId: text("request_id"),
  ip: text("ip"),
  prevHash: text("prev_hash"),
  hash: text("hash").notNull(),
  createdAt: createdAt(),
}, (t) => [index("audit_logs_tenant_idx").on(t.tenantId, t.createdAt)]);

// ---------- durable job queue ----------
export const jobs = pgTable("jobs", {
  id: id(),
  tenantId: tenantId(),
  type: text("type").notNull(),
  payload: jsonb("payload").notNull(),
  status: text("status").notNull().default("queued"), // queued|running|done|failed
  attempts: integer("attempts").notNull().default(0),
  maxAttempts: integer("max_attempts").notNull().default(5),
  runAfter: timestamp("run_after", { withTimezone: true }).notNull().defaultNow(),
  lockedAt: timestamp("locked_at", { withTimezone: true }),
  lastError: text("last_error"),
  idempotencyKey: text("idempotency_key"),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
}, (t) => [
  index("jobs_poll_idx").on(t.status, t.runAfter),
  index("jobs_tenant_status_idx").on(t.tenantId, t.status, t.updatedAt),
  uniqueIndex("jobs_idem_uq").on(t.tenantId, t.idempotencyKey),
]);

// ---------- customer-controlled configuration ----------
/** Encrypted secret values (AES-256-GCM with VIGIL_SECRET_KEY). Rows hold ciphertext only. */
export const vigilSecrets = pgTable("vigil_secrets", {
  id: id(),
  tenantId: tenantId(),
  ref: text("ref").notNull().unique(),
  ciphertext: text("ciphertext").notNull(),
  createdAt: createdAt(),
});

/** Customer-configured AI model providers. API keys live in vigil_secrets via secretRef. */
export const modelProviders = pgTable("model_providers", {
  id: id(),
  tenantId: tenantId(),
  name: text("name").notNull(),
  kind: text("kind").notNull(), // anthropic | openai | gemini | openai_compatible
  baseUrl: text("base_url"),
  secretRef: text("secret_ref"),
  hosting: text("hosting").notNull(), // external | customer_hosted
  timeoutSeconds: integer("timeout_seconds").notNull().default(120),
  priceInputPerMtok: numeric("price_input_per_mtok", { precision: 10, scale: 4 }).notNull(),
  priceOutputPerMtok: numeric("price_output_per_mtok", { precision: 10, scale: 4 }).notNull(),
  enabled: boolean("enabled").notNull().default(true),
  createdBy: uuid("created_by").references(() => users.id),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
}, (t) => [uniqueIndex("model_providers_tenant_name_uq").on(t.tenantId, t.name)]);

// ---------- notifications ----------
/**
 * Incident alert channels (Slack incoming webhook, SMTP email). `config` holds non-secret settings only;
 * the webhook URL / SMTP password live in vigil_secrets via secretRef.
 */
export const notificationChannels = pgTable("notification_channels", {
  id: id(),
  tenantId: tenantId(),
  kind: text("kind").notNull(), // slack | email
  name: text("name").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  minSeverity: severityEnum("min_severity").notNull().default("high"),
  events: text("events").array().notNull(),
  config: jsonb("config").notNull().default({}),
  secretRef: text("secret_ref"),
  createdBy: uuid("created_by").references(() => users.id),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
}, (t) => [uniqueIndex("notification_channels_tenant_name_uq").on(t.tenantId, t.name)]);

/** One row per (channel, incident, event[, severity step]); also the flood-control ledger. */
export const notificationDeliveries = pgTable("notification_deliveries", {
  id: id(),
  tenantId: tenantId(),
  channelId: uuid("channel_id").notNull().references(() => notificationChannels.id, { onDelete: "cascade" }),
  incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  event: text("event").notNull(),
  dedupeKey: text("dedupe_key").notNull().default(""),
  status: text("status").notNull().default("pending"), // pending | sent | failed | suppressed
  attempts: integer("attempts").notNull().default(0),
  lastError: text("last_error"),
  summarized: boolean("summarized").notNull().default(false),
  sentAt: timestamp("sent_at", { withTimezone: true }),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
}, (t) => [
  uniqueIndex("notification_deliveries_uq").on(t.channelId, t.incidentId, t.event, t.dedupeKey),
  index("notification_deliveries_channel_idx").on(t.tenantId, t.channelId, t.createdAt),
]);

// ---------- operations ----------
/**
 * Per-minute API latency rollups per (tenant, method, route template). Never per-request rows, IPs,
 * query strings or bodies. `hist` = counts per latency bucket (bounds in apps/api/src/lib/latency.ts). Kept ≤ 7 days.
 */
export const apiLatencyRollups = pgTable("api_latency_rollups", {
  tenantId: tenantId(),
  bucket: timestamp("bucket", { withTimezone: true }).notNull(),
  method: text("method").notNull(),
  route: text("route").notNull(),
  count: integer("count").notNull().default(0),
  status4xx: integer("status_4xx").notNull().default(0),
  status5xx: integer("status_5xx").notNull().default(0),
  sumMs: doublePrecision("sum_ms").notNull().default(0),
  maxMs: doublePrecision("max_ms").notNull().default(0),
  hist: integer("hist").array().notNull(),
}, (t) => [primaryKey({ columns: [t.tenantId, t.bucket, t.method, t.route] })]);

/** Worker liveness (system table, no tenant data): one row per worker process. */
export const workerHeartbeats = pgTable("worker_heartbeats", {
  workerId: uuid("worker_id").primaryKey(),
  startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
});
