-- Lokale Zonen: Standard-TTL und SOA-Werte je Zone.
ALTER TABLE dns64_zones ADD COLUMN ttl INTEGER NOT NULL DEFAULT 300;        -- Standard fuer neue Eintraege der Zone
ALTER TABLE dns64_zones ADD COLUMN refresh INTEGER NOT NULL DEFAULT 3600;
ALTER TABLE dns64_zones ADD COLUMN retry INTEGER NOT NULL DEFAULT 600;
ALTER TABLE dns64_zones ADD COLUMN expire INTEGER NOT NULL DEFAULT 86400;
ALTER TABLE dns64_zones ADD COLUMN minimum INTEGER NOT NULL DEFAULT 60;     -- TTL fuer "nicht vorhanden"
ALTER TABLE dns64_zones ADD COLUMN hostmaster TEXT NOT NULL DEFAULT '';     -- Mail im SOA, leer = hostmaster.<zone>
