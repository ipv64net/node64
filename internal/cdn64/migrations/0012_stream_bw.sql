-- PROXY64 1.42: Bandbreite je Stream in Mbit/s (0 = unbegrenzt), wie advanced.bw_down_mbit/bw_up_mbit bei Proxy-Hosts
ALTER TABLE cdn_streams ADD COLUMN bw_down_mbit INTEGER NOT NULL DEFAULT 0; -- zum Besucher
ALTER TABLE cdn_streams ADD COLUMN bw_up_mbit INTEGER NOT NULL DEFAULT 0;   -- vom Besucher
