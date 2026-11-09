-- Monitor64 im Cluster (Plan "Cluster", cluster*.go). Probleme gehoeren einer Node: hoechstens ein offenes Problem je
-- Node, Host und Dienst (im Split-Brain koennen zwei Nodes dasselbe Problem offen haben; nach der Wiederverbindung
-- schliesst die nicht zustaendige Node ihres mit "durch Uebergabe beendet").
DROP INDEX IF EXISTS m64_problems_one_open;
CREATE UNIQUE INDEX IF NOT EXISTS m64_problems_one_open_node ON m64_problems (node_id, host_uid, service_key) WHERE closed_at = '' AND deleted = 0;

-- Abgleich: zuletzt gemeldeter bzw. uebernommener Stand je Eintrag (Art, Kennung) - so erkennt die Node eigene
-- Aenderungen an allen Schreibstellen, ohne uebernommene Staende erneut zu melden. Nur lokal.
CREATE TABLE IF NOT EXISTS m64_csync (
	kind  TEXT NOT NULL,
	uid   TEXT NOT NULL,
	stamp TEXT NOT NULL,
	PRIMARY KEY (kind, uid)
) WITHOUT ROWID;

-- Zustand der Hosts je Node (eigener Stand und der anderen Nodes, abgeglichen ueber den Bereich "status").
CREATE TABLE IF NOT EXISTS m64_cstate (
	host_uid TEXT NOT NULL,
	node_id  TEXT NOT NULL,
	data     TEXT NOT NULL DEFAULT '{}',          -- JSON: Ansicht, Laufzeitstand, Gedaechtnis der Meldungen
	at       TEXT NOT NULL,
	PRIMARY KEY (host_uid, node_id)
);

-- Agents (bzw. SSH-Hosts), die noch auf den aktuellen Schluessel der Node umgestellt werden muessen. Nur lokal.
CREATE TABLE IF NOT EXISTS m64_keypending (
	access_uid TEXT PRIMARY KEY,
	host_uid   TEXT NOT NULL,
	type       TEXT NOT NULL,                     -- agent, ssh
	target_fp  TEXT NOT NULL,                     -- Fingerabdruck des Schluessels, auf den umgestellt wird
	tries      INTEGER NOT NULL DEFAULT 0,
	last_try   TEXT NOT NULL DEFAULT '',
	error      TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL
);

-- Aenderungen schnell finden (Abgleich alle paar Sekunden).
CREATE INDEX IF NOT EXISTS m64_hosts_upd ON m64_hosts (updated_at);
CREATE INDEX IF NOT EXISTS m64_access_upd ON m64_access (updated_at);
CREATE INDEX IF NOT EXISTS m64_services_upd ON m64_services (updated_at);
CREATE INDEX IF NOT EXISTS m64_host_rules_upd ON m64_host_rules (updated_at);
CREATE INDEX IF NOT EXISTS m64_overrides_upd ON m64_overrides (updated_at);
CREATE INDEX IF NOT EXISTS m64_maint_upd ON m64_maint (updated_at);
CREATE INDEX IF NOT EXISTS m64_problems_upd ON m64_problems (updated_at);
