-- Cluster: eingeschaltete Bereiche je Mitglied (laut Ping, NULL = aeltere Version: nur Healthchecks) und das
-- Protokoll der allgemein abgeglichenen Eintraege (alle Module ausser Healthchecks, sync2.go). Je Eintrag nur der
-- letzte Stand; geloeschte bleiben 30 Tage als Vermerk.
ALTER TABLE peer_members ADD COLUMN sync TEXT;
ALTER TABLE peer_members ADD COLUMN cursor2 INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS cluster_log (
	seq        INTEGER PRIMARY KEY AUTOINCREMENT,
	module     TEXT NOT NULL,
	item       TEXT NOT NULL,
	entity_id  TEXT NOT NULL,
	deleted    INTEGER NOT NULL DEFAULT 0,
	origin     TEXT NOT NULL,   -- Node, auf der die Aenderung entstand
	changed_at TEXT NOT NULL,
	UNIQUE (module, item, entity_id)
);
