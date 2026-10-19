-- CDN64 1.15: Laendersperre je Stream (wie advanced.geo_mode/geo_countries bei Hosts)
ALTER TABLE cdn_streams ADD COLUMN geo_mode TEXT NOT NULL DEFAULT '';      -- "" = aus, block, allow
ALTER TABLE cdn_streams ADD COLUMN geo_countries TEXT NOT NULL DEFAULT ''; -- ISO-Codes mit Komma, z. B. DE,AT
