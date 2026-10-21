-- In der Ruhezeit zurueckgehaltene Meldungen (Sammelmeldung danach), damit ein Neustart sie nicht verliert.
CREATE TABLE IF NOT EXISTS nf_held (
	user_id    INTEGER PRIMARY KEY,
	alerts     TEXT NOT NULL DEFAULT '[]', -- JSON, hoechstens 500 je Account (maxHeld)
	updated_at TEXT NOT NULL
);
