-- Connector registry: provider columns become text validated by the application registry
-- (packages/core/src/connectors/registry.ts) so new connectors need no enum migration.
-- Data-preserving: existing 'gcp' / 'aws' values are cast in place. A light CHECK keeps ids well-formed.
ALTER TABLE cloud_connections ALTER COLUMN provider TYPE text USING provider::text;
--> statement-breakpoint
ALTER TABLE cloud_accounts ALTER COLUMN provider TYPE text USING provider::text;
--> statement-breakpoint
ALTER TABLE security_events ALTER COLUMN cloud_provider TYPE text USING cloud_provider::text;
--> statement-breakpoint
DROP TYPE IF EXISTS cloud_provider;
--> statement-breakpoint
ALTER TABLE cloud_connections ADD CONSTRAINT cloud_connections_provider_format CHECK (provider ~ '^[a-z][a-z0-9_]{1,31}$');
--> statement-breakpoint
ALTER TABLE cloud_accounts ADD CONSTRAINT cloud_accounts_provider_format CHECK (provider ~ '^[a-z][a-z0-9_]{1,31}$');
--> statement-breakpoint
ALTER TABLE security_events ADD CONSTRAINT security_events_cloud_provider_format CHECK (cloud_provider ~ '^[a-z][a-z0-9_]{1,31}$');
