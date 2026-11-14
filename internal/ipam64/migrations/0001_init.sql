-- IPAM64: Praefixe, Adressbereiche und feste Adressen (IPv4 und IPv6, im Cluster per uid abgeglichen) sowie die
-- Sichtungen aus der Nachbartabelle (je Node). Die Hierarchie der Praefixe und die Zuordnung einer Adresse zu ihrem
-- Praefix werden berechnet, nicht gespeichert. Zeiten in Unix-Sekunden.
CREATE TABLE ipam_prefixes (
	uid         TEXT PRIMARY KEY,
	prefix      TEXT NOT NULL UNIQUE,          -- kanonisch, z. B. 192.168.10.0/24 bzw. 2001:db8::/56
	family      INTEGER NOT NULL,              -- 4 oder 6
	name        TEXT NOT NULL DEFAULT '',
	status      TEXT NOT NULL DEFAULT 'active', -- container | active | reserved | deprecated
	role        TEXT NOT NULL DEFAULT '',
	vlan        INTEGER NOT NULL DEFAULT 0,
	tags        TEXT NOT NULL DEFAULT '',      -- durch Leerzeichen getrennt
	description TEXT NOT NULL DEFAULT '',
	mark_full   INTEGER NOT NULL DEFAULT 0,    -- gilt als voll belegt
	dns_zone    TEXT NOT NULL DEFAULT '',
	scan        TEXT NOT NULL DEFAULT 'passive', -- off | passive | active
	scan_node   TEXT NOT NULL DEFAULT '',      -- Kennung der scannenden Node (leer = jede mit Adresse im Netz)
	dyn_parent  TEXT NOT NULL DEFAULT '',      -- IPv6 dynamisch (Stufe I4): uid des Provider-Praefixes
	dyn_index   TEXT NOT NULL DEFAULT '',      -- IPv6 dynamisch: Praefix-ID (hex)
	dyn_source  TEXT NOT NULL DEFAULT '',      -- IPv6 dynamisch: Quelle des Provider-Praefixes
	updated     INTEGER NOT NULL,
	updated_by  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE ipam_ranges (
	uid         TEXT PRIMARY KEY,
	start_addr  TEXT NOT NULL,
	end_addr    TEXT NOT NULL,
	kind        TEXT NOT NULL DEFAULT 'fixed', -- fixed (feste Adressen) | reserved (frei halten)
	name        TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	updated     INTEGER NOT NULL,
	updated_by  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE ipam_addresses (
	uid         TEXT PRIMARY KEY,
	address     TEXT NOT NULL UNIQUE,          -- kanonisch, IPv4 oder IPv6
	status      TEXT NOT NULL DEFAULT 'active', -- active | reserved | deprecated
	role        TEXT NOT NULL DEFAULT '',      -- gateway | dns | vip | anycast | leer
	name        TEXT NOT NULL DEFAULT '',      -- Rechnername (ohne Zone)
	dns         INTEGER NOT NULL DEFAULT 0,    -- lokalen Eintrag in DNS64 fuehren (Stufe I3)
	dns_zone    TEXT NOT NULL DEFAULT '',
	ptr         INTEGER NOT NULL DEFAULT 1,
	mac         TEXT NOT NULL DEFAULT '',
	dhcp        INTEGER NOT NULL DEFAULT 0,    -- Reservierung im DHCP-Server von DNS64 (Stufe I3)
	description TEXT NOT NULL DEFAULT '',
	tags        TEXT NOT NULL DEFAULT '',
	updated     INTEGER NOT NULL,
	updated_by  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX ipam_addresses_mac ON ipam_addresses (mac);
CREATE INDEX ipam_addresses_name ON ipam_addresses (name);

CREATE TABLE ipam_seen (
	ip         TEXT NOT NULL,
	mac        TEXT NOT NULL,
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	PRIMARY KEY (ip, mac)
) WITHOUT ROWID;
CREATE INDEX ipam_seen_last ON ipam_seen (last_seen);
