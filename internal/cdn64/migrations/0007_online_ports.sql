-- PROXY64 1.24: Portmapper Modus 1/2 - ein Stream ist ueber einen CDN64-Namen der Node auch aus dem Internet
-- erreichbar (Port der Server -> Tunnel -> Stream).
ALTER TABLE cdn_streams ADD COLUMN online_name TEXT NOT NULL DEFAULT ''; -- CDN64-Name ("" = nur hier)
CREATE TABLE cdn_online_ports (
	stream_id   INTEGER NOT NULL,
	transport   TEXT NOT NULL,    -- tcp, udp
	name        TEXT NOT NULL,    -- CDN64-Name
	remote_id   INTEGER NOT NULL, -- Name bei ipv64
	mapping_id  INTEGER NOT NULL, -- Mapping bei ipv64
	listen_port INTEGER NOT NULL, -- Port der Server
	target_port INTEGER NOT NULL, -- Port des Streams beim Anlegen
	created_at  TEXT NOT NULL,
	PRIMARY KEY (stream_id, transport)
);
