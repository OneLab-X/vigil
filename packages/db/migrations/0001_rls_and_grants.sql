-- Tenant isolation via Row-Level Security.
-- The API connects as vigil_app (NOBYPASSRLS, not table owner). Every request runs inside a
-- transaction that executes: SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)
CREATE OR REPLACE FUNCTION vigil_current_tenant() RETURNS uuid
  LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('app.tenant_id', true), '')::uuid $$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION vigil_current_user() RETURNS uuid
  LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;
--> statement-breakpoint
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'cloud_connections','cloud_accounts','cloud_resources','log_sources','ingestion_jobs',
    'ingestion_checkpoints','raw_event_references','security_events','detection_rules',
    'detection_runs','findings','incidents','incident_events','incident_notes',
    'agent_definitions','investigation_runs','investigation_tool_calls','investigation_evidence',
    'investigation_verdicts','recommendations','approval_requests','security_knowledge',
    'knowledge_approvals','agent_evaluations','model_usage'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = vigil_current_tenant()) WITH CHECK (tenant_id = vigil_current_tenant())', t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO vigil_app', t);
  END LOOP;
END $$;
--> statement-breakpoint
-- memberships: visible for the active tenant, or the caller's own memberships (tenant switcher)
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY membership_visibility ON memberships
  USING (tenant_id = vigil_current_tenant() OR user_id = vigil_current_user())
  WITH CHECK (tenant_id = vigil_current_tenant());
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON memberships TO vigil_app;
--> statement-breakpoint
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY tenant_visibility ON tenants
  USING (id = vigil_current_tenant() OR id IN (SELECT tenant_id FROM memberships WHERE user_id = vigil_current_user()));
--> statement-breakpoint
GRANT SELECT, UPDATE ON tenants TO vigil_app;
--> statement-breakpoint
-- Global identity tables (no tenant column). Access mediated by the auth service.
GRANT SELECT, INSERT, UPDATE ON users TO vigil_app;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO vigil_app;
--> statement-breakpoint
-- Job queue is a system table polled across tenants by the worker; jobs carry tenant_id and the
-- worker re-establishes tenant context before touching tenant data.
GRANT SELECT, INSERT, UPDATE, DELETE ON jobs TO vigil_app;
--> statement-breakpoint
-- Audit log: append-only for the app role, tenant-scoped reads.
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY audit_read ON audit_logs FOR SELECT USING (tenant_id = vigil_current_tenant());
--> statement-breakpoint
CREATE POLICY audit_insert ON audit_logs FOR INSERT WITH CHECK (tenant_id IS NULL OR tenant_id = vigil_current_tenant());
--> statement-breakpoint
GRANT SELECT, INSERT ON audit_logs TO vigil_app;
--> statement-breakpoint
-- Raw evidence immutability: app role may not update or delete raw references.
REVOKE UPDATE, DELETE ON raw_event_references FROM vigil_app;
--> statement-breakpoint
-- Normalized events: original reference + payload are immutable once written.
REVOKE UPDATE ON security_events FROM vigil_app;
--> statement-breakpoint
GRANT USAGE ON SCHEMA public TO vigil_app;
--> statement-breakpoint
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vigil_app;
--> statement-breakpoint
-- Per-tenant case numbers without a race: advisory-locked counter function.
CREATE OR REPLACE FUNCTION vigil_next_case_number(p_tenant uuid) RETURNS integer
  LANGUAGE plpgsql AS $$
DECLARE n integer;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('case:' || p_tenant::text));
  SELECT coalesce(max(case_number), 0) + 1 INTO n FROM incidents WHERE tenant_id = p_tenant;
  RETURN n;
END $$;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION vigil_next_case_number(uuid) TO vigil_app;
