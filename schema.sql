-- DevSec Toolbox — D1 schema (anonymous aggregate stats only; NO user data/content stored).
CREATE TABLE IF NOT EXISTS stats (k TEXT PRIMARY KEY, v INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, kind TEXT, n INTEGER NOT NULL DEFAULT 0, last_seen INTEGER);
INSERT OR IGNORE INTO stats (k, v) VALUES
  ('scans_sca', 0), ('scans_headers', 0), ('scans_dns', 0),
  ('packages_scanned', 0), ('vulns_found', 0), ('sites_scanned', 0);
