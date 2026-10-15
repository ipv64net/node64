-- CDN64 C3: Weiterleitungen, 404-Hosts, TLS durchreichen (ueber kind) und Streams.
ALTER TABLE cdn_hosts ADD COLUMN redirect_target TEXT NOT NULL DEFAULT '';     -- Domain[:Port][/Pfad]
ALTER TABLE cdn_hosts ADD COLUMN redirect_scheme TEXT NOT NULL DEFAULT 'auto'; -- auto | http | https
ALTER TABLE cdn_hosts ADD COLUMN redirect_code INTEGER NOT NULL DEFAULT 301;
ALTER TABLE cdn_hosts ADD COLUMN preserve_path INTEGER NOT NULL DEFAULT 1;

CREATE TABLE cdn_streams (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL DEFAULT '',
	enabled     INTEGER NOT NULL DEFAULT 1,
	listen_port INTEGER NOT NULL,
	tcp         INTEGER NOT NULL DEFAULT 1,
	udp         INTEGER NOT NULL DEFAULT 0,
	target_host TEXT NOT NULL,
	target_port INTEGER NOT NULL,
	tls_cert_id INTEGER NOT NULL DEFAULT 0, -- TCP: TLS hier beenden mit diesem Zertifikat (0 = nein)
	created_at  TEXT NOT NULL,
	updated_at  TEXT NOT NULL
);
