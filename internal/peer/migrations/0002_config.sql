-- Abgleich der Konfiguration: je Node ein Protokoll, welche Eintraege sich geaendert haben (nur der letzte Stand
-- je Eintrag), und je Mitglied der zuletzt abgeholte Stand.
CREATE TABLE IF NOT EXISTS peer_log (
	seq        INTEGER PRIMARY KEY AUTOINCREMENT,
	entity     TEXT NOT NULL,   -- check
	entity_id  TEXT NOT NULL,
	op         TEXT NOT NULL,   -- upsert, delete
	origin     TEXT NOT NULL,   -- Node, auf der die Aenderung entstand ("hub" fuer ipv64)
	changed_at TEXT NOT NULL,
	UNIQUE (entity, entity_id)
);
ALTER TABLE peer_members ADD COLUMN cursor INTEGER NOT NULL DEFAULT 0;
ALTER TABLE peer_members ADD COLUMN linked INTEGER NOT NULL DEFAULT 0;  -- mit dem hub verknuepft (Healthchecks-Sync)
