-- Lokale Gruppe: Nodes desselben ipv64-Accounts, die Healthchecks direkt untereinander abgleichen.
CREATE TABLE IF NOT EXISTS peer_members (
	node_id    TEXT PRIMARY KEY,
	name       TEXT NOT NULL,
	url        TEXT NOT NULL,              -- Adresse der Oberflaeche, unter der die anderen sie erreichen
	pubkey     TEXT NOT NULL,              -- Ed25519, base64
	account_id INTEGER NOT NULL,
	added_at   TEXT NOT NULL,
	added_by   TEXT NOT NULL DEFAULT '',   -- Node, die sie aufgenommen hat
	last_seen  TEXT NOT NULL DEFAULT '',
	last_error TEXT NOT NULL DEFAULT '',
	version    TEXT NOT NULL DEFAULT ''
);
