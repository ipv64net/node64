-- Benutzerverwaltung: Zeitpunkt der letzten erfolgreichen Pruefung der Gruppen aus LDAP/SSO (ext_group_uids). Die
-- Gruppen zaehlen nur, solange die Pruefung frisch ist (LDAP 24 h, SSO 7 Tage). Bestand: die letzte Anmeldung (dort
-- wurden die Gruppen zuletzt ermittelt).
ALTER TABLE users ADD COLUMN ext_checked_at TEXT NOT NULL DEFAULT '';
UPDATE users SET ext_checked_at = last_login_at WHERE ext_group_uids <> '';
