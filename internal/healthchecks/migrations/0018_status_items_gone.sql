-- Eintraege geloeschter Checks von den Statusseiten entfernen (seit 2.26.0 passiert das beim Loeschen des Checks).
DELETE FROM hc_status_items WHERE token IN (SELECT token FROM hc_tombstones) AND token NOT IN (SELECT token FROM hc_checks);
