-- Gruppen: frei benannte Zusammenfassung von Checks (Anzeige, Filter)
ALTER TABLE hc_checks ADD COLUMN group_name TEXT NOT NULL DEFAULT '';
