-- Laufzeit-Luecken des Moduls je Node (uptime.go): Zeiten, in denen Monitor64 auf einer Node nicht lief (Modul aus,
-- Node aus, Neustart). Die Statusseiten zaehlen sie weder als beobachtet noch als Stoerung. Im Cluster ueber den
-- Bereich "status" abgeglichen (Eintrag "gap:<node>:<beginn>"); Aufbewahrung wie die Problem-Historie.
CREATE TABLE IF NOT EXISTS m64_gaps (
	node_id TEXT NOT NULL,
	from_at TEXT NOT NULL,
	to_at   TEXT NOT NULL,
	PRIMARY KEY (node_id, from_at)
) WITHOUT ROWID;
