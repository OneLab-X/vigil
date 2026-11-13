-- Per-run masking of sensitive values sent to AI models. mask_state is AES-GCM ciphertext (token -> real value map);
-- mask_stats holds counts per kind only.
ALTER TABLE investigation_runs ADD COLUMN IF NOT EXISTS masking text NOT NULL DEFAULT 'off' CHECK (masking IN ('on','off'));
--> statement-breakpoint
ALTER TABLE investigation_runs ADD COLUMN IF NOT EXISTS mask_state text;
--> statement-breakpoint
ALTER TABLE investigation_runs ADD COLUMN IF NOT EXISTS mask_stats jsonb;
