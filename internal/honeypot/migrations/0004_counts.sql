-- Honeypot64 0.16.0: Zaehler je Minute (Ereignisse, Login-Versuche) und letzte Sichtung je Quell-IP. Kacheln und Verlauf
-- lesen daraus, damit die Zahlen stimmen, auch wenn die Obergrenze einzelne Ereignisse schon geloescht hat. Aufgeraeumt
-- wird nur nach der Aufbewahrung. Bestand aus hp_events uebernehmen.

CREATE TABLE IF NOT EXISTS hp_minutes (
	minute TEXT PRIMARY KEY, -- "2006-01-02T15:04" (UTC)
	events INTEGER NOT NULL DEFAULT 0,
	logins INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS hp_srcs (
	src  TEXT PRIMARY KEY,
	last TEXT NOT NULL -- letzte Sichtung (wie hp_events.ts)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS hp_srcs_last ON hp_srcs (last);

INSERT OR IGNORE INTO hp_minutes (minute, events, logins) SELECT substr(ts, 1, 16), COUNT(*), COALESCE(SUM(login), 0) FROM hp_events GROUP BY 1;
INSERT OR IGNORE INTO hp_srcs (src, last) SELECT src, MAX(ts) FROM hp_events WHERE src <> '' GROUP BY src;
