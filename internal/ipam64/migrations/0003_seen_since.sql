-- IPAM64: Beginn der aktuellen Anwesenheit eines Paars (IP, MAC). first_seen bleibt die erste Sichtung (Anzeige,
-- neue Geraete); since faengt nach einer Luecke neu an und dient den Konfliktregeln (Rueckkehr zu einer frueher
-- gesehenen MAC ist keine Doppelvergabe).
ALTER TABLE ipam_seen ADD COLUMN since INTEGER NOT NULL DEFAULT 0;
UPDATE ipam_seen SET since = first_seen;
