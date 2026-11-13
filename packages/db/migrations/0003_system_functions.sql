-- Worker scheduling needs to know which sources are due across tenants without granting the app
-- role cross-tenant reads. This SECURITY DEFINER function exposes only (tenant_id, source_id).
CREATE OR REPLACE FUNCTION vigil_due_log_sources() RETURNS TABLE(tenant_id uuid, log_source_id uuid)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT s.tenant_id, s.id
  FROM log_sources s
  JOIN cloud_connections c ON c.id = s.connection_id AND c.status IN ('healthy', 'degraded')
  LEFT JOIN ingestion_checkpoints cp ON cp.log_source_id = s.id
  WHERE s.enabled AND s.ingestion_mode = 'poll'
    AND (cp.watermark IS NULL OR cp.watermark < now() - make_interval(secs => s.poll_interval_seconds))
    AND NOT EXISTS (SELECT 1 FROM ingestion_jobs j WHERE j.log_source_id = s.id AND j.status IN ('queued', 'running'))
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION vigil_due_log_sources() FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION vigil_due_log_sources() TO vigil_app;
--> statement-breakpoint
-- Retention purge per tenant (called by worker inside the tenant context; RLS still applies).
CREATE OR REPLACE FUNCTION vigil_purge_expired_events(p_tenant uuid, p_days integer) RETURNS integer
  LANGUAGE plpgsql AS $$
DECLARE n integer;
BEGIN
  DELETE FROM security_events e WHERE e.tenant_id = p_tenant AND e.event_timestamp < now() - make_interval(days => p_days)
    AND NOT EXISTS (SELECT 1 FROM incident_events ie WHERE ie.event_id = e.id);
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION vigil_purge_expired_events(uuid, integer) TO vigil_app;
--> statement-breakpoint
-- Tenant bootstrap (signup / admin provisioning) without granting INSERT on tenants.
CREATE OR REPLACE FUNCTION vigil_create_tenant(p_name text, p_slug text, p_owner uuid) RETURNS uuid
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE t uuid;
BEGIN
  INSERT INTO tenants(name, slug) VALUES (p_name, p_slug) RETURNING id INTO t;
  INSERT INTO memberships(tenant_id, user_id, role) VALUES (t, p_owner, 'owner');
  RETURN t;
END $$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION vigil_create_tenant(text, text, uuid) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION vigil_create_tenant(text, text, uuid) TO vigil_app;
