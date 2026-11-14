-- Environment E2: hinzugefuegte Nodes (mit Zugangsschluessel der anderen Node, Geheimnis mit secret.key
-- verschluesselt) und Zugaenge dieser Node fuer andere Nodes (nur Pruefwert des Schluessels).
CREATE TABLE env_nodes (
    uid         TEXT PRIMARY KEY,
    name        TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL,
    browser_url TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    node_id     TEXT NOT NULL DEFAULT '',
    node_pub    TEXT NOT NULL DEFAULT '',
    secret      TEXT NOT NULL DEFAULT '',
    owner_uid   TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE env_access (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL,
    user_uid       TEXT NOT NULL,
    key_pub        TEXT NOT NULL UNIQUE,
    created_by     TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    last_used_at   TEXT NOT NULL DEFAULT '',
    last_from_node TEXT NOT NULL DEFAULT '',
    last_from_name TEXT NOT NULL DEFAULT ''
);
