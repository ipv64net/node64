-- Proxmox VE und Docker ueber den Cluster (pvecluster.go): Kennung je System (gleich auf allen Nodes des Clusters)
-- und Heim-Node (die das System angelegt hat und die Meldungen der Ueberwachung schickt; '' = diese Node).
ALTER TABLE pve_systems ADD COLUMN uid TEXT NOT NULL DEFAULT '';
ALTER TABLE pve_systems ADD COLUMN home TEXT NOT NULL DEFAULT '';
UPDATE pve_systems SET uid = lower(hex(randomblob(16))) WHERE uid = '';
CREATE UNIQUE INDEX pve_systems_uid ON pve_systems (uid) WHERE uid <> '';
