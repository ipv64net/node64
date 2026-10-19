-- Cluster: stabile Kennung je Eintrag (die lokalen IDs unterscheiden sich je Node). Verweise zwischen Nodes laufen
-- ueber die Kennung; neue Eintraege bekommen sie per Trigger, ohne dass jedes INSERT sie setzen muss.
ALTER TABLE certs ADD COLUMN uid TEXT NOT NULL DEFAULT '';
ALTER TABLE cert_dns_accounts ADD COLUMN uid TEXT NOT NULL DEFAULT '';
ALTER TABLE cert_cas ADD COLUMN uid TEXT NOT NULL DEFAULT '';
ALTER TABLE cert_acme_cas ADD COLUMN uid TEXT NOT NULL DEFAULT '';
-- Node, die das Zertifikat erneuert ('' = diese Node), und Verweise einer anderen Node, deren Ziel hier fehlt
-- (Bereich hier aus): dann ist die lokale ID 0 und das Zertifikat wird hier nicht erneuert.
ALTER TABLE certs ADD COLUMN renewer TEXT NOT NULL DEFAULT '';
ALTER TABLE certs ADD COLUMN ref_dns_account TEXT NOT NULL DEFAULT '';
ALTER TABLE certs ADD COLUMN ref_ca TEXT NOT NULL DEFAULT '';
ALTER TABLE certs ADD COLUMN ref_acme_ca TEXT NOT NULL DEFAULT '';
UPDATE certs SET uid = lower(hex(randomblob(16))) WHERE uid = '';
UPDATE cert_dns_accounts SET uid = lower(hex(randomblob(16))) WHERE uid = '';
UPDATE cert_cas SET uid = lower(hex(randomblob(16))) WHERE uid = '';
UPDATE cert_acme_cas SET uid = lower(hex(randomblob(16))) WHERE uid = '';
CREATE UNIQUE INDEX certs_uid_idx ON certs(uid) WHERE uid != '';
CREATE UNIQUE INDEX cert_dns_accounts_uid_idx ON cert_dns_accounts(uid) WHERE uid != '';
CREATE UNIQUE INDEX cert_cas_uid_idx ON cert_cas(uid) WHERE uid != '';
CREATE UNIQUE INDEX cert_acme_cas_uid_idx ON cert_acme_cas(uid) WHERE uid != '';
CREATE TRIGGER certs_uid_new AFTER INSERT ON certs WHEN NEW.uid = '' BEGIN
	UPDATE certs SET uid = lower(hex(randomblob(16))) WHERE id = NEW.id;
END;
CREATE TRIGGER cert_dns_accounts_uid_new AFTER INSERT ON cert_dns_accounts WHEN NEW.uid = '' BEGIN
	UPDATE cert_dns_accounts SET uid = lower(hex(randomblob(16))) WHERE id = NEW.id;
END;
CREATE TRIGGER cert_cas_uid_new AFTER INSERT ON cert_cas WHEN NEW.uid = '' BEGIN
	UPDATE cert_cas SET uid = lower(hex(randomblob(16))) WHERE id = NEW.id;
END;
CREATE TRIGGER cert_acme_cas_uid_new AFTER INSERT ON cert_acme_cas WHEN NEW.uid = '' BEGIN
	UPDATE cert_acme_cas SET uid = lower(hex(randomblob(16))) WHERE id = NEW.id;
END;
