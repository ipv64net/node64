-- Anmeldung ueber SSO (OIDC, z. B. Authelia, Authentik) und Passkeys. Lokale Konten bleiben die Grundlage:
-- eine SSO-Identitaet gehoert immer zu einem lokalen Benutzer, der sie selbst verknuepft hat.

CREATE TABLE IF NOT EXISTS user_identities (
	id           INTEGER PRIMARY KEY,
	user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	provider     TEXT NOT NULL,             -- oidc:<issuer>
	subject      TEXT NOT NULL,             -- sub-Claim des Anbieters
	label        TEXT NOT NULL DEFAULT '',  -- Anzeige, z. B. E-Mail oder Benutzername beim Anbieter
	created_at   TEXT NOT NULL,
	last_used_at TEXT NOT NULL DEFAULT '',
	UNIQUE (provider, subject)
);

CREATE TABLE IF NOT EXISTS passkeys (
	id            INTEGER PRIMARY KEY,
	user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	name          TEXT NOT NULL,
	rp_id         TEXT NOT NULL,            -- Hostname bei der Registrierung (Passkeys gelten nur dafuer)
	credential_id TEXT NOT NULL UNIQUE,     -- base64url
	data          TEXT NOT NULL,            -- webauthn.Credential als JSON
	created_at    TEXT NOT NULL,
	last_used_at  TEXT NOT NULL DEFAULT ''
);
