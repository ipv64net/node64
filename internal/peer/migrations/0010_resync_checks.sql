-- #194: Kurz nach dem Beitritt konnte eine Node das Protokoll einer anderen bis zum Ende abholen, ohne die Eintraege zu
-- bekommen (dort galt noch ihr alter Stand der Bereiche). Vorhandene Checks fehlten dann dauerhaft. Einmal von vorn
-- abholen; die juengere Aenderung gewinnt, bereits Bekanntes bleibt unveraendert.
UPDATE peer_members SET cursor = 0;
