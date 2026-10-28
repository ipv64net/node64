-- Statusseiten ueber den Cluster (statuscluster.go): Kennung je Seite, gleich auf allen Nodes des Clusters (die lokale
-- Nummer ist je Node verschieden; PROXY64-Hosts verweisen weiter auf die lokale Nummer).
ALTER TABLE hc_status_pages ADD COLUMN uid TEXT NOT NULL DEFAULT '';
UPDATE hc_status_pages SET uid = lower(hex(randomblob(16))) WHERE uid = '';
CREATE UNIQUE INDEX hc_status_pages_uid ON hc_status_pages (uid) WHERE uid <> '';
