-- Healthchecks 3.0.0: Proxmox VE und Docker sind ins Modul Monitor64 umgezogen (ohne Uebernahme, auch keine
-- Zugangsdaten; dort neu einrichten). Alles, was die Healthchecks dazu hatten, faellt weg: Checks der Typen docker und
-- proxmox samt Messungen, Ereignissen, Stoerungen, Messstellen, Verdichtung, Statusseiten-Eintraegen, ausstehenden
-- Aenderungen fuer den hub und Konflikten, dazu die Systeme der Ueberwachung (pve_*, Docker-Hosts als Art docker) mit
-- Einstellungen, Regeln und Verlauf. Andere Checks bleiben (Eltern-Verweise auf entfernte Checks werden leer).
-- Eigene Checks (owner self) muessen auch der hub und die anderen Nodes des Clusters loeschen: Loeschvermerk wie beim
-- Loeschen in der Oberflaeche, die Tokens merkt sich hc.removed_tokens, die Meldung schickt das Modul nach dem Start
-- (removed.go). Checks anderer Nodes verschwinden nur hier (ohne Loeschvermerk). Wartungsfenster: removed.go.

-- Hinweis in der Uebersicht, nur wenn es etwas gab (Schliessen loescht ihn)
INSERT OR REPLACE INTO settings (key, value, updated_at)
SELECT 'hc.notice.monitor64', '1', strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
WHERE EXISTS (SELECT 1 FROM hc_checks WHERE type IN ('docker', 'proxmox')) OR EXISTS (SELECT 1 FROM pve_systems);

INSERT OR REPLACE INTO settings (key, value, updated_at)
SELECT 'hc.removed_tokens', group_concat(token, ','), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
FROM hc_checks WHERE type IN ('docker', 'proxmox') AND owner IN ('self', '') HAVING count(*) > 0;

INSERT OR REPLACE INTO hc_tombstones (token, revision, deleted_at)
SELECT token, revision, strftime('%Y-%m-%dT%H:%M:%fZ', 'now') FROM hc_checks WHERE type IN ('docker', 'proxmox') AND owner IN ('self', '');

DELETE FROM hc_measurements WHERE token IN (SELECT token FROM hc_checks WHERE type IN ('docker', 'proxmox'));
DELETE FROM hc_events WHERE token IN (SELECT token FROM hc_checks WHERE type IN ('docker', 'proxmox'));
DELETE FROM hc_incidents WHERE token IN (SELECT token FROM hc_checks WHERE type IN ('docker', 'proxmox'));
DELETE FROM hc_sources WHERE token IN (SELECT token FROM hc_checks WHERE type IN ('docker', 'proxmox'));
DELETE FROM hc_source_points WHERE token IN (SELECT token FROM hc_checks WHERE type IN ('docker', 'proxmox'));
DELETE FROM hc_source_hourly WHERE token IN (SELECT token FROM hc_checks WHERE type IN ('docker', 'proxmox'));
DELETE FROM hc_hourly WHERE token IN (SELECT token FROM hc_checks WHERE type IN ('docker', 'proxmox'));
DELETE FROM hc_daily WHERE token IN (SELECT token FROM hc_checks WHERE type IN ('docker', 'proxmox'));
DELETE FROM hc_status_items WHERE token IN (SELECT token FROM hc_checks WHERE type IN ('docker', 'proxmox'));
DELETE FROM hc_outbox WHERE entity = 'check' AND entity_id IN (SELECT token FROM hc_checks WHERE type IN ('docker', 'proxmox'));
DELETE FROM hc_conflicts WHERE entity = 'check' AND entity_id IN (SELECT token FROM hc_checks WHERE type IN ('docker', 'proxmox'));
UPDATE hc_checks SET parent_token = '' WHERE parent_token IN (SELECT token FROM hc_checks WHERE type IN ('docker', 'proxmox'));
DELETE FROM hc_checks WHERE type IN ('docker', 'proxmox');

-- Systeme der Proxmox-/Docker-Ueberwachung (0015, 0016, 0017, 0020) samt Einstellungen
DROP TABLE IF EXISTS pve_hist_1m;
DROP TABLE IF EXISTS pve_hist_5m;
DROP TABLE IF EXISTS pve_hist_1h;
DROP TABLE IF EXISTS pve_settings;
DROP TABLE IF EXISTS pve_systems;
DELETE FROM settings WHERE key LIKE 'pve.engine.%' OR key IN ('pve.last_incident', 'docker.last_incident', 'docker.monitor');
