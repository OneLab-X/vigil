# Vigil — Database ERD

Source of truth: `packages/db/src/schema.ts` + migrations in `packages/db/migrations/`.
Every customer-owned table carries `tenant_id` and is protected by `FORCE ROW LEVEL SECURITY`.

```mermaid
erDiagram
  tenants ||--o{ memberships : has
  users ||--o{ memberships : has
  users ||--o{ sessions : has
  tenants ||--o{ cloud_connections : owns
  cloud_connections ||--o{ cloud_accounts : maps
  cloud_accounts ||--o{ cloud_resources : contains
  cloud_connections ||--o{ log_sources : exposes
  log_sources ||--o{ ingestion_jobs : runs
  log_sources ||--|| ingestion_checkpoints : tracks
  raw_event_references ||--o{ security_events : "original_payload_reference"
  log_sources ||--o{ security_events : produced
  detection_rules ||--o{ findings : fires
  detection_runs ||--o{ findings : created_in
  incidents ||--o{ findings : groups
  incidents ||--o{ incident_events : links
  security_events ||--o{ incident_events : linked
  incidents ||--o{ incident_notes : has
  agent_definitions ||--o{ investigation_runs : configures
  incidents ||--o{ investigation_runs : investigated_by
  investigation_runs ||--o{ investigation_tool_calls : trace
  investigation_runs ||--o{ investigation_verdicts : produces
  investigation_runs ||--o{ investigation_evidence : cites
  security_events ||--o{ investigation_evidence : cited
  investigation_verdicts ||--o{ recommendations : proposes
  approval_requests }o--|| investigation_verdicts : "subject (verdict|rule|knowledge)"
  security_knowledge ||--o{ knowledge_approvals : reviewed_by
  incidents ||--o{ security_knowledge : source
  investigation_runs ||--o{ model_usage : bills
  tenants ||--o{ audit_logs : records
  tenants ||--o{ jobs : queues
  tenants ||--o{ agent_evaluations : scores
  tenants ||--o{ api_latency_rollups : measures
```

## Key constraints & indexes

| Table | Constraint / index | Purpose |
|---|---|---|
| security_events | `UNIQUE (tenant_id, deduplication_key)` | idempotent ingestion, duplicate delivery |
| security_events | `(tenant_id, event_timestamp)`, `(tenant_id, source_ip, ts)`, `(tenant_id, principal, ts)`, `(tenant_id, trace_id)`, GIN `categories` | explorer, detection windows, agent pivots |
| raw_event_references | `UNIQUE (tenant_id, sha256)`; app role has no UPDATE/DELETE | immutable, content-addressed evidence |
| findings | `UNIQUE (tenant_id, dedup_key)` | alert dedup across re-runs (rule + group + window start) |
| incidents | `UNIQUE (tenant_id, case_number)`; `vigil_next_case_number()` advisory-locked | race-free CASE-NNNN |
| detection_rules | `UNIQUE (tenant_id, rule_id, version)` | versioned rules |
| agent_definitions | `UNIQUE (tenant_id, role, version)` | versioned agent configs |
| investigation_tool_calls | `UNIQUE (run_id, seq)` | ordered, complete tool trace |
| ingestion_checkpoints | `UNIQUE (tenant_id, log_source_id)` | one watermark/page token per source |
| jobs | `UNIQUE (tenant_id, idempotency_key)` | at-most-once enqueue per key |
| audit_logs | INSERT/SELECT only for app role; `prev_hash → hash` chain | tamper evidence |
| api_latency_rollups | `PRIMARY KEY (tenant_id, bucket, method, route)`; RLS | per-minute API latency histogram per route template (Operations page). Additive upsert; no per-request rows, IPs, paths or query strings; pruned after 7 days |
| worker_heartbeats | `PRIMARY KEY (worker_id)`; system table, no tenant data | worker liveness (random id per process, no hostnames); rows idle > 1 day are pruned |
| jobs | `(tenant_id, status, updated_at)`; `updated_at` set on claim/complete/fail | Operations queue depth and failure windows |
| ingestion_jobs | `(tenant_id, log_source_id, created_at DESC)` | last success / last error per log source |
| investigation_runs, model_usage | `(tenant_id, created_at)`, `(tenant_id, run_id)` | windowed failure and cost-per-investigation queries |

## Roles

| Role | Rights |
|---|---|
| `vigil_owner` | table owner, migrations, `BYPASSRLS` only for `SECURITY DEFINER` system functions (`vigil_due_log_sources`, `vigil_create_tenant`) |
| `vigil_app` | runtime role, `NOBYPASSRLS`, DML only where granted; every query runs under `app.tenant_id` |
