-- Add app_settings table to logvault DB
CREATE TABLE IF NOT EXISTS app_settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Default branding
INSERT INTO app_settings (key, value) VALUES
  ('app_name',      'LogVault')
  ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES
  ('app_subtitle',  'Syslog & Log Analysis')
  ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES
  ('primary_color', '#2563eb')
  ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES
  ('sidebar_color', '#0f1b2d')
  ON CONFLICT (key) DO NOTHING;
INSERT INTO app_settings (key, value) VALUES
  ('logo_url',      '')
  ON CONFLICT (key) DO NOTHING;
