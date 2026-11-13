-- Operations page: API latency rollups, worker heartbeats, job update time, and indexes for bounded ops queries.
-- Per-minute latency rollups per (tenant, method, route template). No per-request rows, IPs, query strings or bodies.
-- hist holds counts per latency bucket; bounds (ms) are fixed in apps/api/src/lib/latency.ts: 5,10,25,50,100,250,500,1000,2500,5000,10000,+inf.
CREATE TABLE api_latency_rollups (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  bucket timestamptz NOT NULL,
  method text NOT NULL,
  route text NOT NULL,
  count integer NOT NULL DEFAULT 0,
  status_4xx integer NOT NULL DEFAULT 0,
  status_5xx integer NOT NULL DEFAULT 0,
  sum_ms double precision NOT NULL DEFAULT 0,
  max_ms double precision NOT NULL DEFAULT 0,
  hist integer[] NOT NULL,
  PRIMARY KEY (tenant_id, bucket, method, route)
);
--> statement-breakpoint
ALTER TABLE api_latency_rollups ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE api_latency_rollups FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY tenant_isolation ON api_latency_rollups USING (tenant_id = vigil_current_tenant()) WITH CHECK (tenant_id = vigil_current_tenant());
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON api_latency_rollups TO vigil_app;
--> statement-breakpoint
-- Worker liveness. System table (no tenant data): one row per worker process, random id, no hostnames.
CREATE TABLE worker_heartbeats (
  worker_id uuid PRIMARY KEY,
  started_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now()
);
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON worker_heartbeats TO vigil_app;
--> statement-breakpoint
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS jobs_tenant_status_idx ON jobs (tenant_id, status, updated_at);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS ingestion_jobs_source_idx ON ingestion_jobs (tenant_id, log_source_id, created_at DESC);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS investigation_runs_tenant_created_idx ON investigation_runs (tenant_id, created_at);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS model_usage_run_idx ON model_usage (tenant_id, run_id);
