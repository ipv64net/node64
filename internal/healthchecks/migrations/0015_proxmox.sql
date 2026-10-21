-- Proxmox-VE-Ueberwachung (Plan docs/PLAN-NODE64-PROXMOX.md, Code internal/proxmox): Systeme, Einstellungen/Regeln je
-- System, Node und Gast sowie der lokale Verlauf. Messdaten bleiben nur auf dem Node.
CREATE TABLE pve_systems (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL DEFAULT '',
	addresses    TEXT NOT NULL DEFAULT '[]',      -- JSON-Liste https://host:port
	token_id     TEXT NOT NULL,                   -- user@realm!tokenid
	secret       TEXT NOT NULL DEFAULT '',        -- Token-Secret, immer verschluesselt (enc:v1:…)
	pin_sha256   TEXT NOT NULL DEFAULT '',        -- Fingerabdruck (64 hex), '' = System-CA
	interval_sec INTEGER NOT NULL DEFAULT 30,     -- 15–300
	enabled      INTEGER NOT NULL DEFAULT 1,
	created_at   TEXT NOT NULL,
	updated_at   TEXT NOT NULL
);

-- Einstellungen je Ebene: key '' = System, node/<name>, qemu/<vmid>, lxc/<vmid>
CREATE TABLE pve_settings (
	system_id      INTEGER NOT NULL REFERENCES pve_systems(id) ON DELETE CASCADE,
	key            TEXT NOT NULL,
	muted          INTEGER NOT NULL DEFAULT 0,
	as_check       INTEGER NOT NULL DEFAULT 0,    -- auch als Healthchecks-Check fuehren
	check_token    TEXT NOT NULL DEFAULT '',      -- zugehoeriger Check ('' = keiner)
	expect_running INTEGER,                       -- NULL = automatisch (lief schon einmal), 0/1 = fest
	seen_running   INTEGER NOT NULL DEFAULT 0,    -- wurde laufend gesehen (fuer automatisch)
	rules          TEXT NOT NULL DEFAULT '',      -- JSON RuleSet, '' = alles erben
	updated_at     TEXT NOT NULL,
	PRIMARY KEY (system_id, key)
) WITHOUT ROWID;

-- Verlauf: Werte als Ganzzahlen (Anteile in 1/10000, Raten in Byte/s), t = Beginn des Intervalls (Unix-Sekunden),
-- n = Anzahl zusammengefasster Abfragen. 1 min fuer 48 h, 5 min so lange wie hc.raw_days, 1 h so lange wie
-- hc.hourly_days (0 = unbegrenzt).
CREATE TABLE pve_hist_1m (
	system_id  INTEGER NOT NULL,
	key        TEXT NOT NULL,
	t          INTEGER NOT NULL,
	n          INTEGER NOT NULL,
	cpu        INTEGER NOT NULL,                  -- Mittel
	cpu_max    INTEGER NOT NULL,
	mem        INTEGER NOT NULL,
	disk       INTEGER,                           -- NULL = unbekannt (QEMU ohne Gast-Agent)
	net_in     INTEGER NOT NULL,
	net_out    INTEGER NOT NULL,
	disk_read  INTEGER NOT NULL,
	disk_write INTEGER NOT NULL,
	PRIMARY KEY (system_id, key, t)
) WITHOUT ROWID;
CREATE INDEX pve_hist_1m_t ON pve_hist_1m(t);

CREATE TABLE pve_hist_5m (
	system_id  INTEGER NOT NULL,
	key        TEXT NOT NULL,
	t          INTEGER NOT NULL,
	n          INTEGER NOT NULL,
	cpu        INTEGER NOT NULL,
	cpu_max    INTEGER NOT NULL,
	mem        INTEGER NOT NULL,
	disk       INTEGER,
	net_in     INTEGER NOT NULL,
	net_out    INTEGER NOT NULL,
	disk_read  INTEGER NOT NULL,
	disk_write INTEGER NOT NULL,
	PRIMARY KEY (system_id, key, t)
) WITHOUT ROWID;
CREATE INDEX pve_hist_5m_t ON pve_hist_5m(t);

CREATE TABLE pve_hist_1h (
	system_id  INTEGER NOT NULL,
	key        TEXT NOT NULL,
	t          INTEGER NOT NULL,
	n          INTEGER NOT NULL,
	cpu        INTEGER NOT NULL,
	cpu_max    INTEGER NOT NULL,
	mem        INTEGER NOT NULL,
	disk       INTEGER,
	net_in     INTEGER NOT NULL,
	net_out    INTEGER NOT NULL,
	disk_read  INTEGER NOT NULL,
	disk_write INTEGER NOT NULL,
	PRIMARY KEY (system_id, key, t)
) WITHOUT ROWID;
CREATE INDEX pve_hist_1h_t ON pve_hist_1h(t);
