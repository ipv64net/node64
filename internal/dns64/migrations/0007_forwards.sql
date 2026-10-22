-- Weiterleitungen (Domain -> eigene DNS-Server) und Umschreiben (Name antwortet wie ein anderer).
CREATE TABLE dns64_forwards (
    id         INTEGER PRIMARY KEY,
    domain     TEXT    NOT NULL UNIQUE, -- klein, ohne Punkt am Ende, gilt mit allen Unternamen
    servers    TEXT    NOT NULL,        -- eine URL je Zeile: dns://ip:port, tls://, https://, quic://
    comment    TEXT    NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL
);
CREATE TABLE dns64_rewrites (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE, -- "*.example.lan" = alle Unternamen
    target     TEXT    NOT NULL,
    comment    TEXT    NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL
);
