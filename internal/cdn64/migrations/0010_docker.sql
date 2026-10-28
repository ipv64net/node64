-- PROXY64: Proxy-Hosts aus Docker-Labels (docker.go). Leer = von Hand angelegt.
ALTER TABLE cdn_hosts ADD COLUMN docker_container TEXT NOT NULL DEFAULT '';
ALTER TABLE cdn_hosts ADD COLUMN docker_router TEXT NOT NULL DEFAULT '';
