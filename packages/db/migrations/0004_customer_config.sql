ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false;
--> statement-breakpoint
CREATE TABLE vigil_secrets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  ref text NOT NULL UNIQUE,
  ciphertext text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE model_providers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('anthropic','openai','gemini','openai_compatible')),
  base_url text,
  secret_ref text,
  hosting text NOT NULL CHECK (hosting IN ('external','customer_hosted')),
  timeout_seconds integer NOT NULL DEFAULT 120 CHECK (timeout_seconds BETWEEN 5 AND 1800),
  price_input_per_mtok numeric(10,4) NOT NULL CHECK (price_input_per_mtok >= 0),
  price_output_per_mtok numeric(10,4) NOT NULL CHECK (price_output_per_mtok >= 0),
  enabled boolean NOT NULL DEFAULT true,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  -- a zero price would silently disable the cost budget; only allowed for models the customer hosts
  CONSTRAINT model_providers_price_ck CHECK (hosting = 'customer_hosted' OR (price_input_per_mtok > 0 AND price_output_per_mtok > 0)),
  CONSTRAINT model_providers_url_ck CHECK (kind <> 'openai_compatible' OR base_url IS NOT NULL)
);
--> statement-breakpoint
CREATE UNIQUE INDEX model_providers_tenant_name_uq ON model_providers (tenant_id, name);
--> statement-breakpoint
ALTER TABLE agent_definitions ADD COLUMN IF NOT EXISTS model_provider_id uuid REFERENCES model_providers(id) ON DELETE RESTRICT;
--> statement-breakpoint
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['vigil_secrets','model_providers'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = vigil_current_tenant()) WITH CHECK (tenant_id = vigil_current_tenant())', t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO vigil_app', t);
  END LOOP;
END $$;
