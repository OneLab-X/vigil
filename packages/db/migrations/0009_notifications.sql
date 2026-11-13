-- Incident alerting: Slack / SMTP channels per tenant and a delivery ledger (idempotency + flood control).
-- Secrets (webhook URL, SMTP password) are never stored here: secret_ref points into vigil_secrets.
CREATE TABLE notification_channels (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('slack', 'email')),
  name text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  min_severity severity NOT NULL DEFAULT 'high',
  events text[] NOT NULL,
  config jsonb NOT NULL DEFAULT '{}'::jsonb,
  secret_ref text,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
--> statement-breakpoint
CREATE UNIQUE INDEX notification_channels_tenant_name_uq ON notification_channels (tenant_id, name);
--> statement-breakpoint
CREATE TABLE notification_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  channel_id uuid NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  event text NOT NULL,
  dedupe_key text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'suppressed')),
  attempts integer NOT NULL DEFAULT 0,
  last_error text,
  summarized boolean NOT NULL DEFAULT false,
  sent_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
--> statement-breakpoint
CREATE UNIQUE INDEX notification_deliveries_uq ON notification_deliveries (channel_id, incident_id, event, dedupe_key);
--> statement-breakpoint
CREATE INDEX notification_deliveries_channel_idx ON notification_deliveries (tenant_id, channel_id, created_at);
--> statement-breakpoint
ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE notification_channels FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY tenant_isolation ON notification_channels USING (tenant_id = vigil_current_tenant()) WITH CHECK (tenant_id = vigil_current_tenant());
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_channels TO vigil_app;
--> statement-breakpoint
ALTER TABLE notification_deliveries ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE notification_deliveries FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY tenant_isolation ON notification_deliveries USING (tenant_id = vigil_current_tenant()) WITH CHECK (tenant_id = vigil_current_tenant());
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_deliveries TO vigil_app;
