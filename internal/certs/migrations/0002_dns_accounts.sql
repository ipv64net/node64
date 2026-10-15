-- Zugangsdaten zu DNS-Anbietern (lego) fuer DNS-01 bei Domains, die nicht bei ipv64 liegen.
CREATE TABLE cert_dns_accounts (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	provider   TEXT NOT NULL,             -- cloudflare, hetzner, netcup …
	config     TEXT NOT NULL DEFAULT '',  -- Felder als JSON, mit secret.key verschluesselt
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
ALTER TABLE certs ADD COLUMN dns_account INTEGER NOT NULL DEFAULT 0; -- source dns: welcher Zugang
