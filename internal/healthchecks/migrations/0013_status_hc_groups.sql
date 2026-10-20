-- Statusseiten: Eintraege nach den Gruppen der Healthchecks anzeigen (statt der Gruppen der Seite); neue Seiten
-- werden standardmaessig auf dem Node-Port veroeffentlicht (Entscheidung Dennis 2026-10-20, Standard im Formular/API).
ALTER TABLE hc_status_pages ADD COLUMN hc_groups INTEGER NOT NULL DEFAULT 0;
