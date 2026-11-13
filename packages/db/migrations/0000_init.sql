CREATE TYPE "public"."approval_status" AS ENUM('pending', 'approved', 'rejected', 'expired');--> statement-breakpoint
CREATE TYPE "public"."incident_status" AS ENUM('new', 'investigating', 'needs_review', 'confirmed', 'false_positive', 'remediation_pending', 'resolved', 'closed');--> statement-breakpoint
CREATE TYPE "public"."cloud_provider" AS ENUM('gcp', 'aws');--> statement-breakpoint
CREATE TYPE "public"."member_role" AS ENUM('owner', 'admin', 'analyst', 'viewer');--> statement-breakpoint
CREATE TYPE "public"."run_status" AS ENUM('queued', 'running', 'succeeded', 'failed', 'rejected', 'timeout');--> statement-breakpoint
CREATE TYPE "public"."severity" AS ENUM('info', 'low', 'medium', 'high', 'critical');--> statement-breakpoint
CREATE TYPE "public"."verdict" AS ENUM('confirmed', 'likely', 'benign', 'inconclusive', 'needs_more_data');--> statement-breakpoint
CREATE TABLE "agent_definitions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"role" text NOT NULL,
	"version" integer NOT NULL,
	"prompt_version" text NOT NULL,
	"model_provider" text NOT NULL,
	"model_name" text NOT NULL,
	"allowed_tools" jsonb NOT NULL,
	"max_steps" integer DEFAULT 12 NOT NULL,
	"timeout_seconds" integer DEFAULT 180 NOT NULL,
	"token_budget" integer DEFAULT 200000 NOT NULL,
	"cost_budget_usd" numeric(10, 4) DEFAULT '2.0' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agent_evaluations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"suite" text NOT NULL,
	"agent_role" text NOT NULL,
	"model_provider" text NOT NULL,
	"model_name" text NOT NULL,
	"prompt_version" text NOT NULL,
	"metrics" jsonb NOT NULL,
	"cases" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "approval_requests" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"subject_type" text NOT NULL,
	"subject_id" uuid NOT NULL,
	"requested_by_user_id" uuid,
	"requested_by_run_id" uuid,
	"status" "approval_status" DEFAULT 'pending' NOT NULL,
	"decided_by" uuid,
	"decided_at" timestamp with time zone,
	"comment" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_logs" (
	"id" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "audit_logs_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"tenant_id" uuid,
	"actor_type" text NOT NULL,
	"actor_id" text,
	"action" text NOT NULL,
	"target_type" text,
	"target_id" text,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"request_id" text,
	"ip" text,
	"prev_hash" text,
	"hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cloud_accounts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"connection_id" uuid NOT NULL,
	"provider" "cloud_provider" NOT NULL,
	"external_id" text NOT NULL,
	"name" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cloud_connections" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider" "cloud_provider" NOT NULL,
	"display_name" text NOT NULL,
	"config" jsonb NOT NULL,
	"secret_ref" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"last_tested_at" timestamp with time zone,
	"last_test_result" jsonb,
	"last_successful_ingest_at" timestamp with time zone,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cloud_resources" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"cloud_account_id" uuid NOT NULL,
	"resource_type" text NOT NULL,
	"resource_id" text NOT NULL,
	"labels" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "detection_rules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"rule_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text NOT NULL,
	"provider" text DEFAULT 'any' NOT NULL,
	"event_sources" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"detection_query" jsonb NOT NULL,
	"conditions" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"severity" "severity" NOT NULL,
	"mitre" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"owner" text,
	"approval_status" "approval_status" DEFAULT 'approved' NOT NULL,
	"proposed_by_run_id" uuid,
	"expires_at" timestamp with time zone,
	"last_updated" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "detection_runs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"window_start" timestamp with time zone NOT NULL,
	"window_end" timestamp with time zone NOT NULL,
	"rules_evaluated" integer DEFAULT 0 NOT NULL,
	"findings_created" integer DEFAULT 0 NOT NULL,
	"status" text DEFAULT 'running' NOT NULL,
	"error" text,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "findings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"rule_id" uuid NOT NULL,
	"detection_run_id" uuid,
	"title" text NOT NULL,
	"severity" "severity" NOT NULL,
	"confidence" real NOT NULL,
	"group_key" jsonb NOT NULL,
	"event_ids" jsonb NOT NULL,
	"event_count" integer NOT NULL,
	"first_seen" timestamp with time zone NOT NULL,
	"last_seen" timestamp with time zone NOT NULL,
	"dedup_key" text NOT NULL,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"incident_id" uuid,
	"status" text DEFAULT 'open' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "incident_events" (
	"tenant_id" uuid NOT NULL,
	"incident_id" uuid NOT NULL,
	"event_id" uuid NOT NULL,
	"finding_id" uuid,
	"added_by" text DEFAULT 'correlator' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "incident_events_incident_id_event_id_pk" PRIMARY KEY("incident_id","event_id")
);
--> statement-breakpoint
CREATE TABLE "incident_notes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"incident_id" uuid NOT NULL,
	"author_user_id" uuid,
	"author_run_id" uuid,
	"body" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "incidents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"case_number" integer NOT NULL,
	"title" text NOT NULL,
	"status" "incident_status" DEFAULT 'new' NOT NULL,
	"severity" "severity" NOT NULL,
	"assignee_id" uuid,
	"primary_entity" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"summary" text,
	"current_verdict_id" uuid,
	"correlation_key" text NOT NULL,
	"first_seen" timestamp with time zone NOT NULL,
	"last_seen" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ingestion_checkpoints" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"log_source_id" uuid NOT NULL,
	"watermark" timestamp with time zone,
	"page_token" text,
	"job_id" uuid,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ingestion_jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"log_source_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"status" text DEFAULT 'queued' NOT NULL,
	"range_start" timestamp with time zone NOT NULL,
	"range_end" timestamp with time zone NOT NULL,
	"pages_fetched" integer DEFAULT 0 NOT NULL,
	"events_seen" integer DEFAULT 0 NOT NULL,
	"events_inserted" integer DEFAULT 0 NOT NULL,
	"duplicates" integer DEFAULT 0 NOT NULL,
	"error" text,
	"requested_by" uuid,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "investigation_evidence" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"run_id" uuid NOT NULL,
	"incident_id" uuid NOT NULL,
	"event_id" uuid,
	"kind" text NOT NULL,
	"claim" text NOT NULL,
	"verified" boolean NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "investigation_runs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"incident_id" uuid NOT NULL,
	"agent_definition_id" uuid NOT NULL,
	"role" text NOT NULL,
	"status" "run_status" DEFAULT 'queued' NOT NULL,
	"task" text NOT NULL,
	"model_provider" text,
	"model_name" text,
	"prompt_version" text,
	"steps" integer DEFAULT 0 NOT NULL,
	"input_tokens" integer DEFAULT 0 NOT NULL,
	"output_tokens" integer DEFAULT 0 NOT NULL,
	"cost_usd" numeric(10, 4) DEFAULT '0' NOT NULL,
	"output" jsonb,
	"validation_errors" jsonb,
	"error" text,
	"triggered_by" uuid,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "investigation_tool_calls" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"run_id" uuid NOT NULL,
	"seq" integer NOT NULL,
	"tool" text NOT NULL,
	"arguments" jsonb NOT NULL,
	"allowed" boolean NOT NULL,
	"denial_reason" text,
	"result_summary" jsonb,
	"returned_event_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"duration_ms" integer,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "investigation_verdicts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"run_id" uuid NOT NULL,
	"incident_id" uuid NOT NULL,
	"verdict" "verdict" NOT NULL,
	"severity" "severity" NOT NULL,
	"confidence" real NOT NULL,
	"summary" text NOT NULL,
	"contract" jsonb NOT NULL,
	"review_status" "approval_status" DEFAULT 'pending' NOT NULL,
	"reviewed_by" uuid,
	"reviewed_at" timestamp with time zone,
	"review_comment" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"type" text NOT NULL,
	"payload" jsonb NOT NULL,
	"status" text DEFAULT 'queued' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"max_attempts" integer DEFAULT 5 NOT NULL,
	"run_after" timestamp with time zone DEFAULT now() NOT NULL,
	"locked_at" timestamp with time zone,
	"last_error" text,
	"idempotency_key" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "knowledge_approvals" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"knowledge_id" uuid NOT NULL,
	"decision" "approval_status" NOT NULL,
	"decided_by" uuid NOT NULL,
	"comment" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "log_sources" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"connection_id" uuid NOT NULL,
	"cloud_account_id" uuid NOT NULL,
	"source_type" text NOT NULL,
	"name" text NOT NULL,
	"filter" text,
	"ingestion_mode" text DEFAULT 'poll' NOT NULL,
	"poll_interval_seconds" integer DEFAULT 300 NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"meta" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "memberships" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"role" "member_role" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "model_usage" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"run_id" uuid,
	"provider" text NOT NULL,
	"model" text NOT NULL,
	"input_tokens" integer NOT NULL,
	"output_tokens" integer NOT NULL,
	"cost_usd" numeric(10, 6) NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "raw_event_references" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"storage_uri" text NOT NULL,
	"sha256" text NOT NULL,
	"size_bytes" integer NOT NULL,
	"provider_event_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "recommendations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"incident_id" uuid NOT NULL,
	"verdict_id" uuid,
	"action" text NOT NULL,
	"rationale" text,
	"priority" text DEFAULT 'medium' NOT NULL,
	"status" text DEFAULT 'proposed' NOT NULL,
	"ticket_ref" text,
	"final_action_note" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "security_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"cloud_provider" "cloud_provider" NOT NULL,
	"cloud_account_id" uuid,
	"project_or_account_reference" text,
	"log_source_id" uuid,
	"region" text,
	"source_type" text NOT NULL,
	"source_name" text,
	"event_timestamp" timestamp with time zone NOT NULL,
	"ingestion_timestamp" timestamp with time zone DEFAULT now() NOT NULL,
	"resource_type" text,
	"resource_id" text,
	"service_name" text,
	"severity" "severity",
	"principal" text,
	"source_ip" text,
	"destination_ip" text,
	"action" text,
	"status" text,
	"http_status" integer,
	"http_method" text,
	"url_path" text,
	"user_agent" text,
	"trace_id" text,
	"request_id" text,
	"normalized_event_type" text NOT NULL,
	"original_payload_reference" uuid,
	"normalized_payload" jsonb NOT NULL,
	"deduplication_key" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "security_knowledge" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"key" text NOT NULL,
	"title" text NOT NULL,
	"body" text NOT NULL,
	"attributes" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"owner" text,
	"status" "approval_status" DEFAULT 'pending' NOT NULL,
	"source_incident_id" uuid,
	"proposed_by_user_id" uuid,
	"proposed_by_run_id" uuid,
	"expires_at" timestamp with time zone,
	"embedding" vector(1536),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"active_tenant_id" uuid,
	"csrf_token" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ip" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sessions_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE TABLE "tenants" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"slug" text NOT NULL,
	"retention_days" integer DEFAULT 90 NOT NULL,
	"settings" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenants_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"display_name" text NOT NULL,
	"password_hash" text,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
ALTER TABLE "agent_definitions" ADD CONSTRAINT "agent_definitions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_evaluations" ADD CONSTRAINT "agent_evaluations_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approval_requests" ADD CONSTRAINT "approval_requests_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approval_requests" ADD CONSTRAINT "approval_requests_requested_by_user_id_users_id_fk" FOREIGN KEY ("requested_by_user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approval_requests" ADD CONSTRAINT "approval_requests_decided_by_users_id_fk" FOREIGN KEY ("decided_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_accounts" ADD CONSTRAINT "cloud_accounts_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_accounts" ADD CONSTRAINT "cloud_accounts_connection_id_cloud_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."cloud_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_connections" ADD CONSTRAINT "cloud_connections_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_connections" ADD CONSTRAINT "cloud_connections_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_resources" ADD CONSTRAINT "cloud_resources_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_resources" ADD CONSTRAINT "cloud_resources_cloud_account_id_cloud_accounts_id_fk" FOREIGN KEY ("cloud_account_id") REFERENCES "public"."cloud_accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detection_rules" ADD CONSTRAINT "detection_rules_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detection_runs" ADD CONSTRAINT "detection_runs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_rule_id_detection_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."detection_rules"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_detection_run_id_detection_runs_id_fk" FOREIGN KEY ("detection_run_id") REFERENCES "public"."detection_runs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_events" ADD CONSTRAINT "incident_events_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_events" ADD CONSTRAINT "incident_events_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_events" ADD CONSTRAINT "incident_events_event_id_security_events_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."security_events"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_events" ADD CONSTRAINT "incident_events_finding_id_findings_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."findings"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_notes" ADD CONSTRAINT "incident_notes_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_notes" ADD CONSTRAINT "incident_notes_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_notes" ADD CONSTRAINT "incident_notes_author_user_id_users_id_fk" FOREIGN KEY ("author_user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_assignee_id_users_id_fk" FOREIGN KEY ("assignee_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingestion_checkpoints" ADD CONSTRAINT "ingestion_checkpoints_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingestion_checkpoints" ADD CONSTRAINT "ingestion_checkpoints_log_source_id_log_sources_id_fk" FOREIGN KEY ("log_source_id") REFERENCES "public"."log_sources"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingestion_jobs" ADD CONSTRAINT "ingestion_jobs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingestion_jobs" ADD CONSTRAINT "ingestion_jobs_log_source_id_log_sources_id_fk" FOREIGN KEY ("log_source_id") REFERENCES "public"."log_sources"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingestion_jobs" ADD CONSTRAINT "ingestion_jobs_requested_by_users_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_evidence" ADD CONSTRAINT "investigation_evidence_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_evidence" ADD CONSTRAINT "investigation_evidence_run_id_investigation_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."investigation_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_evidence" ADD CONSTRAINT "investigation_evidence_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_evidence" ADD CONSTRAINT "investigation_evidence_event_id_security_events_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."security_events"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_runs" ADD CONSTRAINT "investigation_runs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_runs" ADD CONSTRAINT "investigation_runs_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_runs" ADD CONSTRAINT "investigation_runs_agent_definition_id_agent_definitions_id_fk" FOREIGN KEY ("agent_definition_id") REFERENCES "public"."agent_definitions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_runs" ADD CONSTRAINT "investigation_runs_triggered_by_users_id_fk" FOREIGN KEY ("triggered_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_tool_calls" ADD CONSTRAINT "investigation_tool_calls_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_tool_calls" ADD CONSTRAINT "investigation_tool_calls_run_id_investigation_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."investigation_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_verdicts" ADD CONSTRAINT "investigation_verdicts_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_verdicts" ADD CONSTRAINT "investigation_verdicts_run_id_investigation_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."investigation_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_verdicts" ADD CONSTRAINT "investigation_verdicts_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_verdicts" ADD CONSTRAINT "investigation_verdicts_reviewed_by_users_id_fk" FOREIGN KEY ("reviewed_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "jobs" ADD CONSTRAINT "jobs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "knowledge_approvals" ADD CONSTRAINT "knowledge_approvals_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "knowledge_approvals" ADD CONSTRAINT "knowledge_approvals_knowledge_id_security_knowledge_id_fk" FOREIGN KEY ("knowledge_id") REFERENCES "public"."security_knowledge"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "knowledge_approvals" ADD CONSTRAINT "knowledge_approvals_decided_by_users_id_fk" FOREIGN KEY ("decided_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "log_sources" ADD CONSTRAINT "log_sources_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "log_sources" ADD CONSTRAINT "log_sources_connection_id_cloud_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."cloud_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "log_sources" ADD CONSTRAINT "log_sources_cloud_account_id_cloud_accounts_id_fk" FOREIGN KEY ("cloud_account_id") REFERENCES "public"."cloud_accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "model_usage" ADD CONSTRAINT "model_usage_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "model_usage" ADD CONSTRAINT "model_usage_run_id_investigation_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."investigation_runs"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "raw_event_references" ADD CONSTRAINT "raw_event_references_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recommendations" ADD CONSTRAINT "recommendations_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recommendations" ADD CONSTRAINT "recommendations_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recommendations" ADD CONSTRAINT "recommendations_verdict_id_investigation_verdicts_id_fk" FOREIGN KEY ("verdict_id") REFERENCES "public"."investigation_verdicts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_cloud_account_id_cloud_accounts_id_fk" FOREIGN KEY ("cloud_account_id") REFERENCES "public"."cloud_accounts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_log_source_id_log_sources_id_fk" FOREIGN KEY ("log_source_id") REFERENCES "public"."log_sources"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_original_payload_reference_raw_event_references_id_fk" FOREIGN KEY ("original_payload_reference") REFERENCES "public"."raw_event_references"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_knowledge" ADD CONSTRAINT "security_knowledge_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_knowledge" ADD CONSTRAINT "security_knowledge_source_incident_id_incidents_id_fk" FOREIGN KEY ("source_incident_id") REFERENCES "public"."incidents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_knowledge" ADD CONSTRAINT "security_knowledge_proposed_by_user_id_users_id_fk" FOREIGN KEY ("proposed_by_user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_active_tenant_id_tenants_id_fk" FOREIGN KEY ("active_tenant_id") REFERENCES "public"."tenants"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "agent_definitions_uq" ON "agent_definitions" USING btree ("tenant_id","role","version");--> statement-breakpoint
CREATE INDEX "approval_requests_subject_idx" ON "approval_requests" USING btree ("tenant_id","subject_type","subject_id");--> statement-breakpoint
CREATE INDEX "audit_logs_tenant_idx" ON "audit_logs" USING btree ("tenant_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "cloud_accounts_uq" ON "cloud_accounts" USING btree ("tenant_id","provider","external_id");--> statement-breakpoint
CREATE INDEX "cloud_connections_tenant_idx" ON "cloud_connections" USING btree ("tenant_id");--> statement-breakpoint
CREATE UNIQUE INDEX "cloud_resources_uq" ON "cloud_resources" USING btree ("tenant_id","cloud_account_id","resource_type","resource_id");--> statement-breakpoint
CREATE UNIQUE INDEX "detection_rules_uq" ON "detection_rules" USING btree ("tenant_id","rule_id","version");--> statement-breakpoint
CREATE UNIQUE INDEX "findings_dedup_uq" ON "findings" USING btree ("tenant_id","dedup_key");--> statement-breakpoint
CREATE INDEX "findings_tenant_idx" ON "findings" USING btree ("tenant_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "incidents_case_uq" ON "incidents" USING btree ("tenant_id","case_number");--> statement-breakpoint
CREATE INDEX "incidents_corr_idx" ON "incidents" USING btree ("tenant_id","correlation_key","status");--> statement-breakpoint
CREATE UNIQUE INDEX "ingestion_checkpoints_uq" ON "ingestion_checkpoints" USING btree ("tenant_id","log_source_id");--> statement-breakpoint
CREATE INDEX "ingestion_jobs_tenant_idx" ON "ingestion_jobs" USING btree ("tenant_id","created_at");--> statement-breakpoint
CREATE INDEX "investigation_runs_incident_idx" ON "investigation_runs" USING btree ("tenant_id","incident_id");--> statement-breakpoint
CREATE UNIQUE INDEX "tool_calls_seq_uq" ON "investigation_tool_calls" USING btree ("run_id","seq");--> statement-breakpoint
CREATE INDEX "jobs_poll_idx" ON "jobs" USING btree ("status","run_after");--> statement-breakpoint
CREATE UNIQUE INDEX "jobs_idem_uq" ON "jobs" USING btree ("tenant_id","idempotency_key");--> statement-breakpoint
CREATE UNIQUE INDEX "log_sources_uq" ON "log_sources" USING btree ("tenant_id","connection_id","source_type","name");--> statement-breakpoint
CREATE UNIQUE INDEX "memberships_tenant_user_uq" ON "memberships" USING btree ("tenant_id","user_id");--> statement-breakpoint
CREATE INDEX "model_usage_tenant_idx" ON "model_usage" USING btree ("tenant_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "raw_event_refs_uq" ON "raw_event_references" USING btree ("tenant_id","sha256");--> statement-breakpoint
CREATE UNIQUE INDEX "security_events_dedup_uq" ON "security_events" USING btree ("tenant_id","deduplication_key");--> statement-breakpoint
CREATE INDEX "security_events_ts_idx" ON "security_events" USING btree ("tenant_id","event_timestamp");--> statement-breakpoint
CREATE INDEX "security_events_ip_idx" ON "security_events" USING btree ("tenant_id","source_ip","event_timestamp");--> statement-breakpoint
CREATE INDEX "security_events_principal_idx" ON "security_events" USING btree ("tenant_id","principal","event_timestamp");--> statement-breakpoint
CREATE INDEX "security_events_trace_idx" ON "security_events" USING btree ("tenant_id","trace_id");--> statement-breakpoint
CREATE INDEX "security_events_type_idx" ON "security_events" USING btree ("tenant_id","normalized_event_type","event_timestamp");--> statement-breakpoint
CREATE INDEX "security_knowledge_lookup_idx" ON "security_knowledge" USING btree ("tenant_id","kind","key","status");