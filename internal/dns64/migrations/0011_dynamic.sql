-- Dynamische Updates (RFC 2136) je Zone mit TSIG-Schluessel (bleibt auf der Node, nie im Cluster oder Export);
-- Eintraege, die per Update kamen, sind markiert.
ALTER TABLE dns64_zones ADD COLUMN dynamic INTEGER NOT NULL DEFAULT 0;
ALTER TABLE dns64_zones ADD COLUMN tsig_name TEXT NOT NULL DEFAULT '';
ALTER TABLE dns64_zones ADD COLUMN tsig_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE dns64_records ADD COLUMN dynamic INTEGER NOT NULL DEFAULT 0;
