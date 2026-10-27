-- PROXY64: vom Honeypot gemeldete und lokal gesperrte IPs (honeypot.go), ueberstehen einen Neustart.
CREATE TABLE cdn_hp_blocks (
	ip     TEXT PRIMARY KEY,
	reason TEXT NOT NULL DEFAULT '',
	since  TEXT NOT NULL,
	until  TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX cdn_hp_blocks_until ON cdn_hp_blocks (until);
