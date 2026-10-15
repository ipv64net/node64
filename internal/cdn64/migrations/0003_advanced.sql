-- CDN64 C4: Access Lists, Custom Locations (JSON am Host), Zugriffsliste je Host. Erweitert liegt in advanced (JSON).
ALTER TABLE cdn_hosts ADD COLUMN access_list_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cdn_hosts ADD COLUMN locations TEXT NOT NULL DEFAULT '[]';

CREATE TABLE cdn_access_lists (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL,
	satisfy_any INTEGER NOT NULL DEFAULT 0, -- 1 = eine Bedingung genuegt (IP oder Anmeldung), 0 = beide
	pass_auth   INTEGER NOT NULL DEFAULT 0, -- Anmeldung (Authorization) an das Ziel weiterreichen
	users       TEXT NOT NULL DEFAULT '[]', -- [{username, hash}] (bcrypt)
	rules       TEXT NOT NULL DEFAULT '[]', -- [{action allow|deny, cidr}], in Reihenfolge; ohne Treffer gesperrt
	created_at  TEXT NOT NULL,
	updated_at  TEXT NOT NULL
);
