-- PROXY64: Zugriffslisten mit Anmeldedienst (Forward-Auth wie Traefik), API-Keys und Benutzer ans Ziel
-- (forwardauth.go, access_keys.go; Plan docs/PLAN-PROXY64-FORWARDAUTH.md).
ALTER TABLE cdn_access_lists ADD COLUMN auth TEXT NOT NULL DEFAULT '';        -- "" = Benutzer der Liste, sonst authentik | authelia | oauth2-proxy | custom
ALTER TABLE cdn_access_lists ADD COLUMN forward TEXT NOT NULL DEFAULT '{}';   -- {address, headers, callback}
ALTER TABLE cdn_access_lists ADD COLUMN pass_user INTEGER NOT NULL DEFAULT 0; -- Remote-User/-Email/-Groups/-Name an das Ziel
ALTER TABLE cdn_access_lists ADD COLUMN api_keys TEXT NOT NULL DEFAULT '[]';  -- [{name, hash (SHA-256), hint, created_at}]
