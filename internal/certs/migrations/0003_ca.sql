-- Eigene CAs (erzeugt oder importiert) und weitere ACME-Stellen (ZeroSSL, Google, step-ca …).
CREATE TABLE cert_cas (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL,
	cert_pem    TEXT NOT NULL,             -- CA-Zertifikat, bei einer Zwischen-CA mit den uebergeordneten
	key_pem     TEXT NOT NULL,             -- verschluesselt
	imported    INTEGER NOT NULL DEFAULT 0,
	created_at  TEXT NOT NULL
);
CREATE TABLE cert_acme_cas (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL,
	directory   TEXT NOT NULL UNIQUE,      -- ACME-Verzeichnis
	eab_kid     TEXT NOT NULL DEFAULT '',  -- External Account Binding (ZeroSSL, Google …)
	eab_hmac    TEXT NOT NULL DEFAULT '',  -- verschluesselt
	root_pem    TEXT NOT NULL DEFAULT '',  -- eigene Root fuer die Verbindung (z. B. step-ca im eigenen Netz)
	created_at  TEXT NOT NULL
);
ALTER TABLE certs ADD COLUMN ca_id INTEGER NOT NULL DEFAULT 0;   -- source ca: ausstellende CA
ALTER TABLE certs ADD COLUMN acme_ca INTEGER NOT NULL DEFAULT 0; -- 0 = Let's Encrypt, sonst cert_acme_cas.id
ALTER TABLE certs ADD COLUMN days INTEGER NOT NULL DEFAULT 0;    -- source ca: Laufzeit in Tagen
