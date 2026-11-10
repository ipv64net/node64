-- Healthchecks 3.0.0: die Bereiche healthchecks/proxmox und healthchecks/docker gibt es nicht mehr (Proxmox VE und
-- Docker sind nach Monitor64 umgezogen, ohne Uebernahme). Ihre Eintraege im Protokoll des Clusters fallen weg.
DELETE FROM cluster_log WHERE module = 'healthchecks' AND item IN ('proxmox', 'docker');
