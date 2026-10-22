-- Docker-Ueberwachung im Rahmen der Proxmox-Ueberwachung (internal/proxmox/docker.go): ein Docker-Host ist ein System
-- der Art docker, seine Container sind Gaeste (Key docker/<name>). Einstellungen und Verlauf wie bei Proxmox.
ALTER TABLE pve_systems ADD COLUMN kind TEXT NOT NULL DEFAULT 'pve'; -- pve oder docker
