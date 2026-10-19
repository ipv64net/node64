-- Geraetegruppen (Modul DNS64): Reihenfolge = Vorrang, Mitglieder per MAC, IP oder Netz.
CREATE TABLE dns64_groups (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    position   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL
);
CREATE TABLE dns64_group_members (
    id         INTEGER PRIMARY KEY,
    group_id   INTEGER NOT NULL,
    kind       TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    label      TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL,
    UNIQUE (kind, value)
);
CREATE INDEX dns64_group_members_group ON dns64_group_members(group_id);
