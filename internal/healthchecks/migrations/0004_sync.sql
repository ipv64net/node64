-- Sync mit ipv64 (Phase 3): Besitz, Outbox, Konflikte, Zuordnung zu Server-IDs.
-- owner: self = dieser Node gehoert der Check (wird hier gemessen), online = nur bei ipv64 gemessen,
-- other = Check einer anderen Node des Accounts (nur Anzeige)
ALTER TABLE hc_checks ADD COLUMN owner TEXT NOT NULL DEFAULT 'self';
ALTER TABLE hc_maintenance ADD COLUMN remote_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hc_maintenance ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;

-- Ausstehende lokale Aenderungen fuer den Server (Sync-Plan 3.4, 3.9); der ungenutzte Platzhalter aus 0001 weicht
DROP TABLE IF EXISTS hc_outbox;
CREATE TABLE hc_outbox (
	id            INTEGER PRIMARY KEY,
	entity        TEXT NOT NULL,              -- check, maintenance, channel
	entity_id     TEXT NOT NULL,              -- Token oder lokale ID
	op            TEXT NOT NULL,              -- upsert, delete
	base_revision INTEGER NOT NULL DEFAULT 0,
	payload       TEXT NOT NULL DEFAULT '',   -- JSON (wire-Format), leer bei delete
	created_at    TEXT NOT NULL,
	status        TEXT NOT NULL DEFAULT 'pending', -- pending, conflict
	error         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_hc_outbox_entity ON hc_outbox(entity, entity_id);

-- Konflikte: lokale und Server-Version nebeneinander, bis der Nutzer entscheidet
CREATE TABLE IF NOT EXISTS hc_conflicts (
	id              INTEGER PRIMARY KEY,
	entity          TEXT NOT NULL,
	entity_id       TEXT NOT NULL,
	local_op        TEXT NOT NULL,
	local_payload   TEXT NOT NULL DEFAULT '',
	server_payload  TEXT NOT NULL DEFAULT '', -- leer = auf dem Server geloescht
	server_revision INTEGER NOT NULL DEFAULT 0,
	created_at      TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_hc_conflicts_entity ON hc_conflicts(entity, entity_id);
