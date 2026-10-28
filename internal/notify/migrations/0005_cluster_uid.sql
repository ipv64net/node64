-- Kanaele ueber den Cluster (cluster.go): Kennung je Kanal, gleich auf allen Nodes des Clusters (die lokale Nummer ist
-- je Node verschieden; Checks verweisen im Cluster ueber die Kennung auf ihre Kanaele).
ALTER TABLE nf_channels ADD COLUMN uid TEXT NOT NULL DEFAULT '';
UPDATE nf_channels SET uid = lower(hex(randomblob(16))) WHERE uid = '';
CREATE UNIQUE INDEX nf_channels_uid ON nf_channels (uid) WHERE uid <> '';
