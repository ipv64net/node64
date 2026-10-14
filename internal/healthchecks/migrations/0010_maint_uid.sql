-- Lokale Gruppe: Wartungsfenster brauchen eine Kennung, die auf allen Nodes gleich ist (die lokale Nummer ist je
-- Node verschieden), und den Zeitpunkt der letzten Aenderung (die juengere gewinnt).
ALTER TABLE hc_maintenance ADD COLUMN uid TEXT NOT NULL DEFAULT '';
ALTER TABLE hc_maintenance ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
UPDATE hc_maintenance SET uid = lower(hex(randomblob(12))) WHERE uid = '';
UPDATE hc_maintenance SET updated_at = created_at WHERE updated_at = '';
CREATE INDEX IF NOT EXISTS idx_hc_maintenance_uid ON hc_maintenance(uid);
