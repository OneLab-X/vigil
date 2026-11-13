-- Operator CLI (verify-audit) and readiness checks need the list of tenant ids without granting
-- the app role cross-tenant reads. Exposes ids only.
CREATE OR REPLACE FUNCTION vigil_tenant_ids() RETURNS SETOF uuid
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$ SELECT id FROM tenants ORDER BY created_at $$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION vigil_tenant_ids() FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION vigil_tenant_ids() TO vigil_app;
