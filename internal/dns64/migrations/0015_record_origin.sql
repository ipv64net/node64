-- Herkunft eines eigenen Eintrags ('' = von Hand, Import oder Cluster; 'docker' = Abgleich der Docker-Labels). Der
-- Abgleich fasst nur Eintraege mit seiner Herkunft an, die auch nur auf dieser Node gelten; der Cluster und der Export
-- tragen die Spalte nicht weiter.
ALTER TABLE dns64_records ADD COLUMN origin TEXT NOT NULL DEFAULT '';
