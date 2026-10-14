-- Lokale Gruppe (Schritt 4): Gesamtzustand ueber die messenden Nodes der Gruppe, zuletzt bestimmt (fuer die
-- Benachrichtigung genau einer Node und das Uebernehmen bei Ausfall ohne doppelte Meldung).
ALTER TABLE hc_checks ADD COLUMN group_state TEXT NOT NULL DEFAULT '';
ALTER TABLE hc_checks ADD COLUMN group_since TEXT NOT NULL DEFAULT '';
