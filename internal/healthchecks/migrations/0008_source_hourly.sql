-- Stundenwerte fremder Messstellen (ipv64-Standorte, andere Nodes): vom hub nachgeladen oder aus
-- eigenen Live-Punkten verdichtet, bevor diese nach der Aufbewahrungszeit geloescht werden.
CREATE TABLE IF NOT EXISTS hc_source_hourly (
	token    TEXT NOT NULL,
	source   TEXT NOT NULL,
	hour     TEXT NOT NULL,   -- Stundenbeginn UTC wie hc_hourly
	count    INTEGER NOT NULL,
	up_count INTEGER NOT NULL,
	avg_ms   REAL,            -- Mittel der erfolgreichen Messungen
	PRIMARY KEY (token, source, hour)
);
CREATE INDEX IF NOT EXISTS idx_hc_source_hourly_hour ON hc_source_hourly(hour);
