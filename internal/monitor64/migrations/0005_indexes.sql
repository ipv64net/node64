-- "Zuletzt" (Uebersicht, alle 15 s je offenem Tab) und geschlossene Probleme (Seite Probleme, Dashboard) ohne
-- Durchlauf der ganzen Historie (bis 365 Tage).
CREATE INDEX IF NOT EXISTS m64_events_ts ON m64_events (ts);
CREATE INDEX IF NOT EXISTS m64_problems_closed ON m64_problems (opened_at) WHERE closed_at != '' AND deleted = 0;
