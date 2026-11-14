-- Environment: Sitzungen, die ueber ein Anmelde-Ticket einer anderen Node entstanden sind (Rolle begrenzt, Rueckweg).
-- Eine Zeile je Sitzung; verwaiste Zeilen (Sitzung abgelaufen oder abgemeldet) raeumt SaveSession auf.
CREATE TABLE IF NOT EXISTS env_sessions (
	session_id TEXT PRIMARY KEY,
	max_role   TEXT NOT NULL,             -- hoechste Rolle in dieser Sitzung (admin, read)
	from_node  TEXT NOT NULL,             -- Kennung der Node, ueber die geoeffnet wurde
	from_name  TEXT NOT NULL DEFAULT '',
	back_url   TEXT NOT NULL DEFAULT '',  -- Rueckweg (Seite Environment der anderen Node)
	created_at TEXT NOT NULL
);
