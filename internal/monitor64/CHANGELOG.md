# Monitor64 – Änderungen

## 0.1.0 – unveröffentlicht (Vorschau, nur mit Schalter `NODE64_MONITOR64=1`)

- Neues Modul: Systeme überwachen mit Schwellen und Verlauf (Plan `docs/PLAN-NODE64-MONITOR64.md`).
- Zugänge: Monitor64-Agent (Linux), SSH ohne Agent, Proxmox VE, Proxmox Backup Server und Docker per API.
- Dienste werden erkannt, aber nie automatisch übernommen; verschwundene Dienste bleiben bis „Entfernen“.
- Schwellen in drei Stufen (Standard, Abweichungen je Gruppe/Tag – oben gewinnt –, dieser Host), Dauer, Hysterese,
  „GB frei“, Trend „voll in N Tagen“, feste Regeln (SMART, RAID/ZFS, Bonding/LACP, Updates, Gäste/Container).
- Probleme mit Ablauf und Akteur (Benutzer, API-Key, System), Quittieren, Als gelöst markieren, CSV.
- Benachrichtigung über die Kanäle der Node: eine Meldung je Host und Runde, Entwarnung an dieselben Kanäle,
  Erinnerung, Flattern, Ruhezeit mit Sammelmeldung, Abweichungen je Gruppe/Tag.
- Wartung für Hosts, Gruppen und Tags (jetzt, geplant, wiederkehrend).
- Verlauf in eigener Datei `monitor64.db` (1 min / 5 min / 1 h), Diagramme mit Zoom.
- Prometheus-Export unter `/api/metrics`, Konfig-Export/-Import (Geheimnisse nur mit Export-Passwort).
