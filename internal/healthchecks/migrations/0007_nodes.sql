-- Mehrere messende Nodes je Check (Komma-Liste der Node-Kennungen; leer = nur der Besitzer)
ALTER TABLE hc_checks ADD COLUMN nodes TEXT NOT NULL DEFAULT '';
