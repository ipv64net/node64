-- DynDNS-Updater: Ziele, IP-Pruefungen und Update-Aufrufe bei ipv64

-- Ziele: ein Name (Domain + Host), der von dieser Node aus aktuell gehalten wird
CREATE TABLE IF NOT EXISTS dyn_targets (
	id           INTEGER PRIMARY KEY,
	domain       TEXT NOT NULL,
	host         TEXT NOT NULL DEFAULT '',        -- praefix bei ipv64, leer = Domain selbst
	record_id    INTEGER NOT NULL DEFAULT 0,      -- Record bei ipv64 (API v2), 0 = unbekannt/manuell
	token_kind   TEXT NOT NULL DEFAULT 'record',  -- record oder domain
	token        TEXT NOT NULL,                   -- verschluesselt (secrets.Box)
	mode4        TEXT NOT NULL DEFAULT 'auto',    -- auto, fixed, off
	fixed4       TEXT NOT NULL DEFAULT '',
	mode6        TEXT NOT NULL DEFAULT 'off',     -- host, prefix, suffix, iface, fixed, off
	fixed6       TEXT NOT NULL DEFAULT '',
	suffix6      TEXT NOT NULL DEFAULT '',        -- Interface-ID fuer mode6=suffix
	iface        TEXT NOT NULL DEFAULT '',        -- Interface fuer mode6=iface
	enabled      INTEGER NOT NULL DEFAULT 1,
	paused       TEXT NOT NULL DEFAULT '',        -- Grund einer automatischen Pause (badauth, Flattern ...)
	last_ip4     TEXT NOT NULL DEFAULT '',        -- zuletzt erfolgreich gemeldet
	last_ip6     TEXT NOT NULL DEFAULT '',
	last_prefix  TEXT NOT NULL DEFAULT '',
	last_ok_at   TEXT NOT NULL DEFAULT '',
	last_error   TEXT NOT NULL DEFAULT '',
	last_err_at  TEXT NOT NULL DEFAULT '',
	dns_state    INTEGER NOT NULL DEFAULT 0,      -- 0 unbekannt, 1 stimmt, 2 weicht ab
	dns_at       TEXT NOT NULL DEFAULT '',
	created_at   TEXT NOT NULL,
	updated_at   TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dyn_targets_name ON dyn_targets(domain, host);

-- Jede Ermittlung der oeffentlichen Adresse (Aufbewahrung einstellbar)
CREATE TABLE IF NOT EXISTS dyn_checks (
	id          INTEGER PRIMARY KEY,
	time        TEXT NOT NULL,
	family      TEXT NOT NULL,                    -- 4 oder 6
	source      TEXT NOT NULL DEFAULT '',
	ip          TEXT NOT NULL DEFAULT '',
	error       TEXT NOT NULL DEFAULT '',
	duration_ms INTEGER NOT NULL DEFAULT 0,
	changed     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_dyn_checks_time ON dyn_checks(time);

-- Jeder Aufruf bei ipv64
CREATE TABLE IF NOT EXISTS dyn_updates (
	id          INTEGER PRIMARY KEY,
	time        TEXT NOT NULL,
	target_id   INTEGER NOT NULL,
	target      TEXT NOT NULL DEFAULT '',          -- Name zum Zeitpunkt des Aufrufs
	trigger     TEXT NOT NULL DEFAULT 'auto',      -- auto, manual, start
	sent4       TEXT NOT NULL DEFAULT '',
	sent6       TEXT NOT NULL DEFAULT '',
	sent_prefix TEXT NOT NULL DEFAULT '',
	http_status INTEGER NOT NULL DEFAULT 0,
	status      TEXT NOT NULL DEFAULT '',
	info        TEXT NOT NULL DEFAULT '',
	ok          INTEGER NOT NULL DEFAULT 0,
	error       TEXT NOT NULL DEFAULT '',
	duration_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_dyn_updates_time ON dyn_updates(time);
CREATE INDEX IF NOT EXISTS idx_dyn_updates_target ON dyn_updates(target_id, time);
