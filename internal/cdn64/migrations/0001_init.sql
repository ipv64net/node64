-- CDN64: Hosts des Reverse-Proxys (C1: Proxy-Hosts; weitere Arten folgen ueber kind).
CREATE TABLE cdn_hosts (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	kind            TEXT NOT NULL DEFAULT 'proxy',
	names           TEXT NOT NULL,                 -- Komma-Liste, klein, ohne Punkt am Ende
	enabled         INTEGER NOT NULL DEFAULT 1,
	scheme          TEXT NOT NULL DEFAULT 'http',  -- Ziel: http | https
	target_host     TEXT NOT NULL DEFAULT '',      -- Name oder IP (IPv6 ohne Klammern)
	target_port     INTEGER NOT NULL DEFAULT 80,
	websockets      INTEGER NOT NULL DEFAULT 1,
	block_exploits  INTEGER NOT NULL DEFAULT 0,
	cache_assets    INTEGER NOT NULL DEFAULT 0,
	cert_id         INTEGER NOT NULL DEFAULT 0,    -- 0 = passendes nach Namen, -1 = nur HTTP, sonst fest
	force_ssl       INTEGER NOT NULL DEFAULT 0,
	http2           INTEGER NOT NULL DEFAULT 1,
	http3           INTEGER NOT NULL DEFAULT 1,
	hsts            INTEGER NOT NULL DEFAULT 0,
	hsts_subdomains INTEGER NOT NULL DEFAULT 0,
	min_tls         TEXT NOT NULL DEFAULT '1.2',
	verify_target   INTEGER NOT NULL DEFAULT 0,    -- Zertifikat eines https-Ziels pruefen (Heimnetz oft selbstsigniert)
	advanced        TEXT NOT NULL DEFAULT '{}',    -- weitere Optionen (C4), JSON
	created_at      TEXT NOT NULL,
	updated_at      TEXT NOT NULL
);
