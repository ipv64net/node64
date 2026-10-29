-- Cluster: abgelehnte Eintraege (v2) erneut abholen - Nummer vor dem ersten abgelehnten Eintrag je Mitglied
-- (-1 = keiner). Einmal alles neu abholen, damit vor diesem Stand abgelehnte Eintraege noch ankommen (die juengere
-- Aenderung gewinnt, doppelt schadet nicht).
ALTER TABLE peer_members ADD COLUMN retry2 INTEGER NOT NULL DEFAULT -1;
UPDATE peer_members SET cursor2 = 0;
