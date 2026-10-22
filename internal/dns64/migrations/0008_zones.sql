-- Lokale Zonen: Namen darunter beantwortet DNS64 selbst (eigene Eintraege, Geraetenamen, SOA).
CREATE TABLE dns64_zones (
    id            INTEGER PRIMARY KEY,
    name          TEXT    NOT NULL UNIQUE, -- z. B. home.lan
    authoritative INTEGER NOT NULL DEFAULT 1, -- 1 = unbekannte Namen NXDOMAIN, 0 = weiter an Weiterleitung/Router
    devices       INTEGER NOT NULL DEFAULT 1, -- 1 = Geraete der Gruppen mit Namen als <name>.<zone>
    comment       TEXT    NOT NULL DEFAULT '',
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL
);
