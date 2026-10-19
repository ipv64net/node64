-- Zeitplaene und Sofort-Knoepfe je Geraetegruppe (Phase G4).
ALTER TABLE dns64_groups ADD COLUMN hold TEXT NOT NULL DEFAULT '';
ALTER TABLE dns64_groups ADD COLUMN hold_until TEXT NOT NULL DEFAULT '';
CREATE TABLE dns64_group_schedules (
    id         INTEGER PRIMARY KEY,
    group_id   INTEGER NOT NULL,
    label      TEXT    NOT NULL DEFAULT '',
    days       TEXT    NOT NULL,
    start      TEXT    NOT NULL,
    end        TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    cats       TEXT    NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL
);
CREATE INDEX dns64_group_schedules_group ON dns64_group_schedules(group_id);
