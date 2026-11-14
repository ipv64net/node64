-- Benutzerverwaltung: Rolle, Sperre, Herkunft, E-Mail und Gruppen je Benutzer; Gruppen mit Rolle und Zuordnungen
-- nach aussen (LDAP-Gruppen-DNs, OIDC-Gruppennamen). Bestehende Benutzer bleiben Administratoren.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';
ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN source TEXT NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN group_uids TEXT NOT NULL DEFAULT '';     -- von Hand zugeordnete Gruppen (Komma-Liste)
ALTER TABLE users ADD COLUMN ext_group_uids TEXT NOT NULL DEFAULT ''; -- beim letzten Anmelden ueber LDAP/SSO ermittelt
ALTER TABLE users ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0;  -- Passwort beim naechsten Anmelden setzen

CREATE TABLE IF NOT EXISTS user_groups (
	uid         TEXT PRIMARY KEY,
	name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
	role        TEXT NOT NULL DEFAULT 'read',
	description TEXT NOT NULL DEFAULT '',
	ldap_groups TEXT NOT NULL DEFAULT '', -- Zeilen: DNs bzw. Namen der Verzeichnisgruppen
	oidc_groups TEXT NOT NULL DEFAULT '', -- Zeilen: Gruppennamen aus dem SSO-Claim
	created_at  TEXT NOT NULL,
	updated_at  TEXT NOT NULL
);
