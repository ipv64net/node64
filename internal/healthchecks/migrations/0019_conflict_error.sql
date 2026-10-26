-- Konflikte (Ablehnungen durch den hub): Grund der Ablehnung; leer = vor 2.30.0 entstanden (Server-Stand unbekannt).
ALTER TABLE hc_conflicts ADD COLUMN error TEXT NOT NULL DEFAULT '';
