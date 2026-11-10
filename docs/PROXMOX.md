# Proxmox VE und Docker überwachen

Seit **Healthchecks 3.0.0** gehört die Überwachung von Proxmox VE, Proxmox Backup Server und Docker-Hosts zum Modul
**Monitor64**. Die frühere Einbindung in die Healthchecks (Seiten *Healthchecks → Proxmox VE* und *Healthchecks →
Docker*, Check-Typen `proxmox` und `docker`, Statusseiten-Einträge, Prometheus-Metriken `node64_pve_*` und
`node64_docker_*`, API unter `/api/healthchecks/proxmox` und `/api/healthchecks/docker`, Cluster-Bereiche
*Proxmox VE* und *Docker*) gibt es nicht mehr.

Beim Update auf 3.0.0 löscht die Node alle Daten dazu: Systeme samt Zugangsdaten, Einstellungen, Regeln und Verlauf,
die Checks dieser Typen mit Messungen, Störungen und Statusseiten-Einträgen. Eigene Checks verschwinden auch bei
ipv64 und auf den anderen Nodes des Clusters. Es gibt keine Übernahme nach Monitor64 – bitte dort neu einrichten.
Die alten Endpunkte antworten mit `410 Gone`, Anlegen eines Checks vom Typ `docker` oder `proxmox` mit `400`.

Plan der früheren Umsetzung: [PLAN-NODE64-PROXMOX.md](PLAN-NODE64-PROXMOX.md).
