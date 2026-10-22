-- Cluster: "nur diese Node" fuer eigene Eintraege und Weiterleitungen (wird nie abgeglichen); Gruppen heissen auf
-- allen Nodes gleich (uid), damit Umbenennen und Mitglieder je Standort zusammenpassen.
ALTER TABLE dns64_records ADD COLUMN local_only INTEGER NOT NULL DEFAULT 0;
ALTER TABLE dns64_forwards ADD COLUMN local_only INTEGER NOT NULL DEFAULT 0;
ALTER TABLE dns64_groups ADD COLUMN uid TEXT NOT NULL DEFAULT '';
UPDATE dns64_groups SET uid = lower(hex(randomblob(16))) WHERE uid = '';
CREATE UNIQUE INDEX dns64_groups_uid ON dns64_groups(uid) WHERE uid != '';
