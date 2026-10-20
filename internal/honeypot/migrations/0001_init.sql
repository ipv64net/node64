-- Modul Honeypot64: Ereignisse der Fallen-Dienste (lokal 7 Tage, feste Obergrenze, siehe store.go).
-- Zeiten als "2006-01-02T15:04:05.000Z" (UTC, feste Breite, damit Zeichenkettenvergleiche der Zeitreihenfolge
-- entsprechen und substr() Stunde bzw. Tag liefert).

CREATE TABLE IF NOT EXISTS hp_events (
	id       INTEGER PRIMARY KEY,
	ts       TEXT NOT NULL,
	service  TEXT NOT NULL,
	port     INTEGER NOT NULL DEFAULT 0,
	kind     TEXT NOT NULL,
	src      TEXT NOT NULL DEFAULT '',
	src_port INTEGER NOT NULL DEFAULT 0,
	login    INTEGER NOT NULL DEFAULT 0, -- 1 = Login-Versuch (SSH, Telnet, HTTP)
	username TEXT NOT NULL DEFAULT '',
	password TEXT NOT NULL DEFAULT '',
	method   TEXT NOT NULL DEFAULT '',
	path     TEXT NOT NULL DEFAULT '',
	host     TEXT NOT NULL DEFAULT '',
	ua       TEXT NOT NULL DEFAULT '',
	client   TEXT NOT NULL DEFAULT '',
	page     TEXT NOT NULL DEFAULT '',
	payload  BLOB,
	detail   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS hp_events_ts ON hp_events (ts);
CREATE INDEX IF NOT EXISTS hp_events_src ON hp_events (src, ts);
