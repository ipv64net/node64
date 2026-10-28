-- Namen ueber den Cluster (cluster.go): Kennung je Ziel, gleich auf allen Nodes des Clusters (die lokale Nummer ist je
-- Node verschieden).
ALTER TABLE dyn_targets ADD COLUMN uid TEXT NOT NULL DEFAULT '';
UPDATE dyn_targets SET uid = lower(hex(randomblob(16))) WHERE uid = '';
CREATE UNIQUE INDEX dyn_targets_uid ON dyn_targets (uid) WHERE uid <> '';
