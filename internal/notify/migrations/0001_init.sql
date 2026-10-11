-- Benachrichtigungskanaele und Zustellprotokoll (Kern, laeuft immer)

CREATE TABLE IF NOT EXISTS nf_channels (
	id                INTEGER PRIMARY KEY,
	type              TEXT NOT NULL,            -- smtp, webhook, telegram, discord, ntfy, gotify
	name              TEXT NOT NULL,
	config            TEXT NOT NULL DEFAULT '{}', -- JSON, Geheimnisse verschluesselt (enc:v1:...)
	enabled           INTEGER NOT NULL DEFAULT 1,
	is_default        INTEGER NOT NULL DEFAULT 0, -- Standardkanal fuer Checks ohne eigene Auswahl
	lang              TEXT NOT NULL DEFAULT 'de',
	notify_down       INTEGER NOT NULL DEFAULT 1,
	notify_up         INTEGER NOT NULL DEFAULT 1,
	secret_only_local INTEGER NOT NULL DEFAULT 0, -- vorbereitet fuer den Sync
	execution         TEXT NOT NULL DEFAULT 'node',
	revision          INTEGER NOT NULL DEFAULT 1,
	created_at        TEXT NOT NULL,
	updated_at        TEXT NOT NULL,
	last_used_at      TEXT NOT NULL DEFAULT '',
	last_error        TEXT NOT NULL DEFAULT ''
);

-- Zustellprotokoll, append-only
CREATE TABLE IF NOT EXISTS nf_deliveries (
	id          INTEGER PRIMARY KEY,
	time        TEXT NOT NULL,
	event_id    TEXT NOT NULL DEFAULT '',
	channel_id  INTEGER NOT NULL,
	channel     TEXT NOT NULL DEFAULT '',      -- Name zum Zeitpunkt der Zustellung
	kind        TEXT NOT NULL DEFAULT '',      -- down, up, flapping_start, flapping_end, reminder, summary, test
	check_token TEXT NOT NULL DEFAULT '',
	subject     TEXT NOT NULL DEFAULT '',
	ok          INTEGER NOT NULL DEFAULT 0,
	error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_nf_deliveries_time ON nf_deliveries(time);
CREATE INDEX IF NOT EXISTS idx_nf_deliveries_channel ON nf_deliveries(channel_id, time);
