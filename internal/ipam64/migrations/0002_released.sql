-- IPAM64: Adresse an DNS64 uebergeben (Uebergabe, auch von einer anderen Node im Cluster): IPAM64 schreibt fuer sie
-- nichts mehr nach DNS64, bis DNS oder DHCP an der Adresse wieder eingeschaltet wird.
ALTER TABLE ipam_addresses ADD COLUMN released INTEGER NOT NULL DEFAULT 0;
