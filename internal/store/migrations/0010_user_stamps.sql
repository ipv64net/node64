-- Benutzer im Cluster: Zeitpunkt der letzten Aenderung der Verwaltungsfelder (admin_at: Rolle, Sperre, Herkunft,
-- E-Mail, Gruppen von Hand) und von Passwort samt "Passwort beim naechsten Anmelden setzen" (password_at). Beim
-- Abgleich gewinnt je Feldgruppe der juengere Zeitpunkt; eine eigene Aenderung anderer Felder (Anmeldung mit 2FA,
-- Sprache, Gruppen aus LDAP) nimmt so keine Sperre oder Herabstufung einer anderen Node zurueck. Leer = unbekannt
-- (Bestand); Benutzer mit vergebener Rolle, Sperre oder Gruppen gelten als seit der Anlage so (sonst kaeme eine solche
-- Vergabe nie auf einer Node an, die bis eben noch keine Benutzerverwaltung hatte).
ALTER TABLE users ADD COLUMN admin_at TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN password_at TEXT NOT NULL DEFAULT '';
UPDATE users SET admin_at = created_at WHERE role <> 'admin' OR disabled <> 0 OR group_uids <> '';

-- Geloeschte Benutzer (Kennung, Zeitpunkt; 30 Tage wie die Loeschvermerke im Cluster): ein aelterer Stand einer
-- anderen Node legt einen hier geloeschten Benutzer nicht wieder an.
CREATE TABLE IF NOT EXISTS user_deletions (
	uid        TEXT PRIMARY KEY,
	deleted_at TEXT NOT NULL
);
