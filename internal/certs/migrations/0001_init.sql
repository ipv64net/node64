-- Zertifikatsverwaltung des Kerns (CDN64, spaeter DNS64 und Oberflaeche): Let's Encrypt und hochgeladene
-- Zertifikate. Der private Schluessel liegt mit secret.key verschluesselt in key_pem.
CREATE TABLE certs (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	names        TEXT NOT NULL,             -- Komma-Liste, der erste ist der Hauptname
	source       TEXT NOT NULL,             -- ipv64 | alias | http | upload
	alias_zone   TEXT NOT NULL DEFAULT '',  -- alias: ipv64-Domain, bei der der TXT-Record entsteht
	alias_prefix TEXT NOT NULL DEFAULT '',  -- alias: Praefix darunter ("" = Domain selbst)
	staging      INTEGER NOT NULL DEFAULT 0,
	auto_renew   INTEGER NOT NULL DEFAULT 1,
	cert_pem     TEXT NOT NULL DEFAULT '',  -- Zertifikat mit Kette
	key_pem      TEXT NOT NULL DEFAULT '',  -- verschluesselt
	not_before   TEXT NOT NULL DEFAULT '',
	not_after    TEXT NOT NULL DEFAULT '',
	issuer       TEXT NOT NULL DEFAULT '',
	status       TEXT NOT NULL DEFAULT 'pending', -- pending | valid | error
	last_error   TEXT NOT NULL DEFAULT '',
	last_attempt TEXT NOT NULL DEFAULT '',
	warned       TEXT NOT NULL DEFAULT '',  -- zuletzt gemeldete Ablauf-Stufe (14, 3)
	created_at   TEXT NOT NULL,
	updated_at   TEXT NOT NULL
);
