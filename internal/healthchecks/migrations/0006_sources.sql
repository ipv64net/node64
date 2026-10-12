-- Messstellen je Check (Zustand aus den remote_states des Hubs) und Messpunkte fremder
-- Messstellen fuer Hybrid-Checks (Diagramm mit einer Linie je Messstelle).
CREATE TABLE IF NOT EXISTS hc_sources (
	token         TEXT NOT NULL,
	source        TEXT NOT NULL,
	label         TEXT NOT NULL DEFAULT '',
	state         TEXT NOT NULL DEFAULT '',
	since         TEXT NOT NULL DEFAULT '',
	last_check_at TEXT NOT NULL DEFAULT '',
	last_status   TEXT NOT NULL DEFAULT '',
	latency_ms    REAL NOT NULL DEFAULT 0,
	reason        TEXT NOT NULL DEFAULT '',
	message       TEXT NOT NULL DEFAULT '',
	updated_at    TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (token, source)
);
CREATE TABLE IF NOT EXISTS hc_source_points (
	token      TEXT NOT NULL,
	source     TEXT NOT NULL,
	time       TEXT NOT NULL,
	status     INTEGER NOT NULL,
	latency_ms REAL NOT NULL DEFAULT 0,
	PRIMARY KEY (token, source, time)
);
CREATE INDEX IF NOT EXISTS idx_hc_source_points_time ON hc_source_points(time);
