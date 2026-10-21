-- MCP-Schnittstelle (KI-Anwendungen): eigene Schluessel, getrennt von den API-Keys. Nur der Hash wird gespeichert,
-- dazu die Rechte je Bereich (z. B. "healthchecks:read,dns64:read").

CREATE TABLE IF NOT EXISTS mcp_keys (
	id           INTEGER PRIMARY KEY,
	user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	name         TEXT NOT NULL,
	key_hash     TEXT NOT NULL UNIQUE,
	key_hint     TEXT NOT NULL DEFAULT '',
	scopes       TEXT NOT NULL DEFAULT '',
	created_at   TEXT NOT NULL,
	last_used_at TEXT NOT NULL DEFAULT '',
	last_ip      TEXT NOT NULL DEFAULT ''
);
