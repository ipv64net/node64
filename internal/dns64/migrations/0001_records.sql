-- Eigene DNS-Eintraege (Modul DNS64). name klein, ohne Punkt am Ende, "*.example.lan" = alle Unternamen.
CREATE TABLE dns64_records (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    type       TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    ttl        INTEGER NOT NULL DEFAULT 300,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL,
    UNIQUE (name, type, value)
);
