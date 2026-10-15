-- Lokale Gruppe: eine Stoerung der Gruppe ist offen (seit "down"/"flapping", bis "up"), wie die Stoerungen am hub.
-- Danach meldet "up" das Ende auch dann, wenn der Check zwischendurch nur teilweise gestoert war.
ALTER TABLE hc_checks ADD COLUMN group_open INTEGER NOT NULL DEFAULT 0;
