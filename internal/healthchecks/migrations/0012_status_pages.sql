-- Statusseiten (Plan docs/PLAN-NODE64-STATUSSEITE.md): oeffentliche Seiten aus den Healthchecks. Ohne eingeschaltete
-- Seite laeuft nichts (keine Hintergrundarbeit, keine oeffentliche Route).
CREATE TABLE hc_status_pages (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	slug         TEXT NOT NULL UNIQUE,            -- /status/<slug>
	title        TEXT NOT NULL DEFAULT '',
	description  TEXT NOT NULL DEFAULT '',        -- Markdown (einfach)
	footer       TEXT NOT NULL DEFAULT '',        -- Markdown (einfach)
	enabled      INTEGER NOT NULL DEFAULT 0,      -- 0 = aus: nirgends erreichbar (auch nicht ueber PROXY64)
	publish_node INTEGER NOT NULL DEFAULT 0,      -- 1 = auch direkt auf dem Node-Port unter /status/<slug>
	layout       TEXT NOT NULL DEFAULT 'list',    -- list | tiles | compact
	theme        TEXT NOT NULL DEFAULT 'auto',    -- auto | light | dark
	lang         TEXT NOT NULL DEFAULT '',        -- '' = Browser, de, en
	accent       TEXT NOT NULL DEFAULT '',        -- Akzentfarbe #rrggbb, '' = Standard
	days         INTEGER NOT NULL DEFAULT 90,     -- Tagesbalken: 30 | 60 | 90
	show_uptime  INTEGER NOT NULL DEFAULT 1,
	show_history INTEGER NOT NULL DEFAULT 1,      -- Stoerungen/Ankuendigungen der letzten 30 Tage
	refresh_sec  INTEGER NOT NULL DEFAULT 60,     -- Neuladen im Browser (30-3600)
	password     TEXT NOT NULL DEFAULT '',        -- bcrypt-Hash, '' = ohne
	noindex      INTEGER NOT NULL DEFAULT 1,
	powered_by   INTEGER NOT NULL DEFAULT 1,      -- "Bereitgestellt mit Node64"
	created_at   TEXT NOT NULL,
	updated_at   TEXT NOT NULL
);

CREATE TABLE hc_status_groups (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	page_id INTEGER NOT NULL REFERENCES hc_status_pages(id) ON DELETE CASCADE,
	name    TEXT NOT NULL DEFAULT '',
	sort    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX hc_status_groups_page ON hc_status_groups(page_id, sort);

CREATE TABLE hc_status_items (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	group_id INTEGER NOT NULL REFERENCES hc_status_groups(id) ON DELETE CASCADE,
	token    TEXT NOT NULL,                       -- Check; geloeschte Checks fallen beim Anzeigen weg
	label    TEXT NOT NULL DEFAULT '',            -- Anzeigename ('' = Name des Checks)
	sort     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX hc_status_items_group ON hc_status_items(group_id, sort);

-- Ankuendigungen von Hand (mit Updates als Zeitleiste)
CREATE TABLE hc_status_notices (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	page_id     INTEGER NOT NULL REFERENCES hc_status_pages(id) ON DELETE CASCADE,
	title       TEXT NOT NULL,
	level       TEXT NOT NULL DEFAULT 'info',     -- info | warning | danger
	created_at  TEXT NOT NULL,
	updated_at  TEXT NOT NULL,
	resolved_at TEXT NOT NULL DEFAULT ''          -- '' = offen
);
CREATE INDEX hc_status_notices_page ON hc_status_notices(page_id, created_at);

CREATE TABLE hc_status_notice_updates (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	notice_id INTEGER NOT NULL REFERENCES hc_status_notices(id) ON DELETE CASCADE,
	time      TEXT NOT NULL,
	text      TEXT NOT NULL                       -- Markdown (einfach)
);
CREATE INDEX hc_status_notice_updates_notice ON hc_status_notice_updates(notice_id, time);
