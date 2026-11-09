-- Modul Monitor64: Konfiguration und Problem-Historie (Plan docs/PLAN-NODE64-MONITOR64.md, "Speicher und Leistung").
-- Der Verlauf (Messreihen) liegt in einer eigenen Datei monitor64.db (Paket tsdb), nicht hier.
-- Clusterfaehig von Anfang an: jeder Eintrag hat eine clusterweite Kennung (uid), Aenderungszeit und Loeschvermerk.
-- Zeiten als "2006-01-02T15:04:05.000Z" (UTC, feste Breite: Zeichenkettenvergleich = Zeitreihenfolge).
-- Akteure als JSON {"kind":"user|api|system","uid":"","name":"","method":"local|sso|ldap","ip":""}.

CREATE TABLE IF NOT EXISTS m64_hosts (
	id             INTEGER PRIMARY KEY,
	uid            TEXT NOT NULL UNIQUE,
	name           TEXT NOT NULL,
	address        TEXT NOT NULL DEFAULT '',      -- Hostname oder IP (v4/v6)
	kind           TEXT NOT NULL DEFAULT '',      -- linux-agent, windows, ssh, pve, pbs, docker, snmp, nas
	group_name     TEXT NOT NULL DEFAULT '',
	tags           TEXT NOT NULL DEFAULT '[]',    -- JSON-Liste
	interval_sec   INTEGER NOT NULL DEFAULT 60,   -- 30 .. 900
	owner_node     TEXT NOT NULL DEFAULT '',      -- zustaendige Node (leer = diese)
	preferred_node TEXT NOT NULL DEFAULT '',
	backup_nodes   TEXT NOT NULL DEFAULT '[]',    -- JSON-Liste der Ersatz-Nodes
	agent_autoupd  INTEGER NOT NULL DEFAULT 1,
	paused         INTEGER NOT NULL DEFAULT 0,
	notes          TEXT NOT NULL DEFAULT '',
	created_at     TEXT NOT NULL,
	created_by     TEXT NOT NULL DEFAULT '{}',
	updated_at     TEXT NOT NULL,
	updated_by     TEXT NOT NULL DEFAULT '{}',
	deleted        INTEGER NOT NULL DEFAULT 0
);

-- Zugaenge eines Hosts (mehrere je Host). Geheimnisse verschluesselt (internal/secrets) in secret.
CREATE TABLE IF NOT EXISTS m64_access (
	id         INTEGER PRIMARY KEY,
	uid        TEXT NOT NULL UNIQUE,
	host_uid   TEXT NOT NULL,
	type       TEXT NOT NULL,                     -- agent, ssh, snmp, pve, pbs, docker, prom
	config     TEXT NOT NULL DEFAULT '{}',        -- JSON ohne Geheimnisse (Port, Benutzer, Optionen)
	secret     TEXT NOT NULL DEFAULT '',          -- verschluesselt
	hostkey    TEXT NOT NULL DEFAULT '',          -- gemerkter Fingerabdruck (TOFU) bzw. Zertifikats-Pin
	enabled    INTEGER NOT NULL DEFAULT 1,
	updated_at TEXT NOT NULL,
	updated_by TEXT NOT NULL DEFAULT '{}',
	deleted    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS m64_access_host ON m64_access (host_uid);

-- Dienste eines Hosts: uebernommen (1), neu erkannt/Hinweis (0), ignoriert (-1).
CREATE TABLE IF NOT EXISTS m64_services (
	id          INTEGER PRIMARY KEY,
	uid         TEXT NOT NULL UNIQUE,
	host_uid    TEXT NOT NULL,
	key         TEXT NOT NULL,                    -- stabil: fs:/var/lib/vz, if:enp1s0, disk:<serial>, vm:101 ...
	name        TEXT NOT NULL DEFAULT '',         -- Anzeigename (aenderbar)
	kind        TEXT NOT NULL DEFAULT '',         -- Art fuer Regeln (fs, if, disk, cpu ...)
	adopted     INTEGER NOT NULL DEFAULT 0,
	vanished_at TEXT NOT NULL DEFAULT '',         -- verschwunden seit (bleibt bis "Entfernen")
	via         TEXT NOT NULL DEFAULT '',         -- Zugang erzwingen (leer = Rangfolge)
	host_rule   TEXT NOT NULL DEFAULT '',         -- JSON: Schwelle der Stufe "dieser Host" (nur dieser Dienst)
	soll        TEXT NOT NULL DEFAULT '',         -- run, off, '' = automatisch
	report      TEXT NOT NULL DEFAULT '',         -- '', melden, show
	updated_at  TEXT NOT NULL,
	updated_by  TEXT NOT NULL DEFAULT '{}',
	deleted     INTEGER NOT NULL DEFAULT 0,
	UNIQUE (host_uid, key)
);

-- Einstellungen der Stufe "dieser Host" fuer alle Dienste einer Art (z. B. alle Dateisysteme von nas01).
CREATE TABLE IF NOT EXISTS m64_host_rules (
	id         INTEGER PRIMARY KEY,
	uid        TEXT NOT NULL UNIQUE,
	host_uid   TEXT NOT NULL,
	kind       TEXT NOT NULL,
	rule       TEXT NOT NULL DEFAULT '{}',
	updated_at TEXT NOT NULL,
	updated_by TEXT NOT NULL DEFAULT '{}',
	deleted    INTEGER NOT NULL DEFAULT 0,
	UNIQUE (host_uid, kind)
);

-- Abweichungen fuer Gruppe/Tag: Schwellen (scope=rule) und Benachrichtigung (scope=notify). Oben gewinnt (position).
CREATE TABLE IF NOT EXISTS m64_overrides (
	id          INTEGER PRIMARY KEY,
	uid         TEXT NOT NULL UNIQUE,
	scope       TEXT NOT NULL,                    -- rule, notify
	position    INTEGER NOT NULL DEFAULT 0,
	target_type TEXT NOT NULL,                    -- group, tag
	target      TEXT NOT NULL,
	kind        TEXT NOT NULL DEFAULT '',         -- Art (bei rule)
	data        TEXT NOT NULL DEFAULT '{}',       -- JSON: Regel bzw. Benachrichtigungs-Abweichung
	updated_at  TEXT NOT NULL,
	updated_by  TEXT NOT NULL DEFAULT '{}',
	deleted     INTEGER NOT NULL DEFAULT 0
);

-- Wartungsfenster (Hosts, Gruppen, Tags; jetzt, geplant, wiederkehrend).
CREATE TABLE IF NOT EXISTS m64_maint (
	id         INTEGER PRIMARY KEY,
	uid        TEXT NOT NULL UNIQUE,
	title      TEXT NOT NULL DEFAULT '',
	targets    TEXT NOT NULL DEFAULT '{}',        -- JSON {"hosts":[],"groups":[],"tags":[]}
	start_at   TEXT NOT NULL DEFAULT '',
	end_at     TEXT NOT NULL DEFAULT '',          -- leer = bis beendet
	recur      TEXT NOT NULL DEFAULT '',          -- JSON (wiederkehrend) oder leer
	ended_at   TEXT NOT NULL DEFAULT '',
	created_by TEXT NOT NULL DEFAULT '{}',
	updated_at TEXT NOT NULL,
	updated_by TEXT NOT NULL DEFAULT '{}',
	deleted    INTEGER NOT NULL DEFAULT 0
);

-- Probleme (gehoeren der Node, die sie festgestellt hat: node_id). Ablauf in m64_events.
CREATE TABLE IF NOT EXISTS m64_problems (
	id          INTEGER PRIMARY KEY,
	uid         TEXT NOT NULL UNIQUE,
	node_id     TEXT NOT NULL DEFAULT '',
	host_uid    TEXT NOT NULL,
	service_key TEXT NOT NULL DEFAULT '',         -- leer = Host (nicht erreichbar)
	state       TEXT NOT NULL,                    -- warn, crit, unknown, unreachable (aktuell)
	worst       TEXT NOT NULL,                    -- schlimmster Zustand
	opened_at   TEXT NOT NULL,
	closed_at   TEXT NOT NULL DEFAULT '',
	closed_how  TEXT NOT NULL DEFAULT '',         -- auto, user, api, maint, handover
	closed_by   TEXT NOT NULL DEFAULT '{}',
	ack         TEXT NOT NULL DEFAULT '',         -- JSON {"by":{...},"at":"","comment":""}
	notified    TEXT NOT NULL DEFAULT '[]',       -- Kanal-IDs, die das Problem bekommen haben
	updated_at  TEXT NOT NULL,
	deleted     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS m64_problems_open ON m64_problems (closed_at, host_uid);
CREATE INDEX IF NOT EXISTS m64_problems_time ON m64_problems (opened_at);

CREATE TABLE IF NOT EXISTS m64_events (
	id          INTEGER PRIMARY KEY,
	uid         TEXT NOT NULL UNIQUE,
	node_id     TEXT NOT NULL DEFAULT '',
	problem_uid TEXT NOT NULL DEFAULT '',
	host_uid    TEXT NOT NULL DEFAULT '',
	service_key TEXT NOT NULL DEFAULT '',
	ts          TEXT NOT NULL,
	kind        TEXT NOT NULL,                    -- warn, crit, ok, ack, comment, resolved, maint, bell, held, takeover ...
	text        TEXT NOT NULL DEFAULT '',
	actor       TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS m64_events_problem ON m64_events (problem_uid, ts);
CREATE INDEX IF NOT EXISTS m64_events_host ON m64_events (host_uid, ts);

-- Laufzeit je Node (nicht abgeglichen): letzter Zustand und Tracker je Host, damit ein Neustart nichts neu meldet.
CREATE TABLE IF NOT EXISTS m64_runtime (
	host_uid   TEXT PRIMARY KEY,
	state      TEXT NOT NULL DEFAULT '{}',
	updated_at TEXT NOT NULL
);
