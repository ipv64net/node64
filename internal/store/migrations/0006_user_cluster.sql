-- Benutzer ueber den Cluster (internal/usercluster): Kennung je Benutzer, gleich auf allen Nodes des Clusters (die
-- lokale Nummer ist je Node verschieden). Dazu die Wahl bei gleichnamigen, verschiedenen Benutzern: die durch die Wahl
-- abgeloesten Kennungen (kommagetrennt) und der Zeitpunkt der Wahl.
ALTER TABLE users ADD COLUMN uid TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN cluster_replaces TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN cluster_chosen_at TEXT NOT NULL DEFAULT '';
UPDATE users SET uid = lower(hex(randomblob(16))) WHERE uid = '';
CREATE UNIQUE INDEX users_uid ON users (uid) WHERE uid <> '';
