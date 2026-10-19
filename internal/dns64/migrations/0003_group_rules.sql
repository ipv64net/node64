-- Regeln je Geraetegruppe (Phase G2): eigene Blocklisten, Kategorien, Freigaben und Sperren.
ALTER TABLE dns64_groups ADD COLUMN lists_mode TEXT NOT NULL DEFAULT 'global';
ALTER TABLE dns64_groups ADD COLUMN lists TEXT NOT NULL DEFAULT '';
ALTER TABLE dns64_groups ADD COLUMN cats TEXT NOT NULL DEFAULT '';
CREATE TABLE dns64_group_domains (
    id         INTEGER PRIMARY KEY,
    group_id   INTEGER NOT NULL,
    domain     TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    created_at TEXT    NOT NULL,
    UNIQUE (group_id, domain)
);
