-- Add enrichment columns to known_hosts if they don't exist
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS site_name        TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS brand            TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS model            TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS device_status    TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS lifecycle_status TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS netvault_id      TEXT;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS synced_from_nv   BOOLEAN DEFAULT FALSE;
ALTER TABLE known_hosts ADD COLUMN IF NOT EXISTS last_synced       TIMESTAMPTZ;
