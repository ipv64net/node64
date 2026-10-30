-- Healthchecks: Der SecNtfy-Kanal heisst jetzt „IPv64 App“ und hat wieder den Typ app (2026-10-30).
-- Geraete-Token (device_key) und „kritischer Alarm“ (critical) bleiben, der Server ist fest im hub
-- (api.secntfy.app; ein gespeichertes server wird nicht mehr gelesen). Der fruehere Firebase-Weg der App ist
-- ersetzt: alte app-Kanaele mit device_token (ohne NTFY-DEVICE-Token) melden beim Senden einen Fehler, bis ein
-- Geraete-Token aus der IPv64 App eingetragen ist.
--
-- Vorher ansehen (nur lesen):
--   SELECT type, COUNT(*) FROM hc2_channels WHERE type IN ('app', 'secntfy') AND deleted_at IS NULL GROUP BY type;
UPDATE hc2_channels SET type = 'app' WHERE type = 'secntfy';
