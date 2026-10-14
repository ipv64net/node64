-- Weiterreichen der hub-Daten: je Mitglied der zuletzt abgeholte Messpunkt vom hub (node_seq dort) und der
-- Zeitpunkt in hc_source_points (Hybrid-Checks, die das Mitglied selbst misst).
ALTER TABLE peer_members ADD COLUMN rcursor INTEGER NOT NULL DEFAULT 0;
ALTER TABLE peer_members ADD COLUMN rtime TEXT NOT NULL DEFAULT '';
