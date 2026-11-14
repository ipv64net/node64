-- Statusseiten frei sortierbar, mit Ueberschriften und Trennern als eigene Eintraege (Token "@heading"/"@divider", #131):
-- die Reihenfolge so speichern, wie die Seite sie bisher zeigt - erst die Healthchecks, dann die Eintraege aus
-- Monitor64 (eigener Abschnitt), je in der Reihenfolge der Seite (fruehere eigene Gruppen der Seite nacheinander), alles
-- in der ersten Gruppe der Seite (der Editor kennt seit 3.1.0 nur noch eine Liste). Die Anzeige aendert sich dadurch nicht.
UPDATE hc_status_items SET sort = (CASE WHEN token LIKE 'm64:%' THEN 1000000000 ELSE 0 END)
	+ (SELECT g.sort FROM hc_status_groups g WHERE g.id = hc_status_items.group_id) * 100000 + sort;
UPDATE hc_status_items SET group_id = (SELECT f.id FROM hc_status_groups g JOIN hc_status_groups f ON f.page_id = g.page_id
	WHERE g.id = hc_status_items.group_id ORDER BY f.sort, f.id LIMIT 1);
