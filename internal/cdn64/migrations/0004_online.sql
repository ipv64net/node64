-- CDN64 online (T4): Namen eines Proxy-Hosts, die bei ipv64 eingeschaltet sind (DNS zeigt auf srv07/srv08).
CREATE TABLE cdn_online (
	name       TEXT PRIMARY KEY,           -- eingeschalteter Name (klein)
	host_id    INTEGER NOT NULL,           -- Proxy-Host der Node
	remote_id  INTEGER NOT NULL,           -- ID bei ipv64 (/cdn64o/hosts/{id})
	mode       INTEGER NOT NULL DEFAULT 1, -- 1 = durchreichen
	check_token TEXT NOT NULL DEFAULT '',  -- Healthcheck, der beim Einschalten angelegt wurde
	created_at TEXT NOT NULL
);
CREATE INDEX cdn_online_host ON cdn_online (host_id);
