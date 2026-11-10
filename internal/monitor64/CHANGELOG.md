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
- Phase 2/3: Agent für Windows (Dienst, PowerShell-Einzeiler) und FreeBSD/OPNsense, Prometheus-Exporter abfragen
  (node_exporter, windows_exporter, eigene Metriken), Einträge auf den Statusseiten, Regel „Windows-Dienst gestoppt“.
- Neue Zugänge: NUT (USV), TrueNAS, Unraid, Redfish (Server-BMC); Assistent mit Kacheln für Windows, FreeBSD,
  TrueNAS, Unraid, Server-BMC, USV und Prometheus; neue Regeln für USV, Gerätemeldungen und Unraid-Parität.
- Zugang SNMP (v1/v2c/v3, Geräteprofile, eigene OIDs) mit Kacheln „SNMP-Gerät“ und „NAS“; SNMP-Traps (Port einstellbar,
  sofortige Abfrage bei bekannten Traps, Dienst „Traps“ bis quittiert, unbekannte Absender als Host anlegen); neue
  Regeln für Neustart, Ports, USV-Alarm, Drucker, Hardware und PoE.
- Agent im Push-Betrieb für Hosts hinter NAT bzw. VPS (Agent verbindet sich zur Node, Port 6466/TCP, nur offen
  bei Bedarf); Auswahl „Verbindung“ im Assistenten mit Installationsbefehl.
- Cluster-Oberfläche: „überwacht von“, bevorzugte und Ersatz-Nodes je Host mit Erreichbarkeitsprüfung, Karte
  Cluster mit Schlüsselwechsel, Lücken-Hinweis in Diagrammen.
- Nachbesserungen aus dem Code-Review Phase 2–4: Push-Betrieb robuster (Test zerstört die Anmeldung nicht mehr, keine
  Übernahme durch Token-Inhaber, Port-Wechsel sicher), Cluster (ausgesetzte Nodes, Schlüsselwechsel ohne Aussperren,
  eigene Kanäle bleiben, Altersgrenzen), Traps (Ratenbegrenzung je Absender, v3-Zeitfenster, Traps im Cluster),
  Windows-Installation (vorhandener Ordner, Skript-Ordner, Job-Objekt), USV-Restlaufzeit nur auf Batterie,
  Statusseiten (Unbekannt, Pausen, wiederkehrende Wartung), nicht vorgeschlagene Dienste übernehmbar.
- Nachbesserungen aus dem Code-Review: gewollt fehlende Messwerte (gestoppte VM, schlafende Platte) bleiben OK,
  Erinnerungen gehen nach der Ruhezeit nicht verloren, keine doppelten Meldungen an Standardkanäle,
  ZFS-Gerätefehler an ONLINE-Pools, Proxmox-Cluster-Dienste von einer überwachten Node, hängende VMs auch bei
  „darf aus sein“, Tausendertrenner und Hysterese in der angezeigten Einheit.
- Phase 4 (Backend): Monitor64 im Cluster (Bereiche „Konfiguration“ und „Zustand“): eine zuständige Node je Host
  mit bevorzugter und Ersatz-Nodes, Übernahme nach 2 min und Rückgabe nach 5 min stabil, Mehrheitsregel bei
  getrennten Teilen, gemeinsamer Cluster-Schlüssel (Agents werden automatisch umgestellt, „Schlüssel wechseln“),
  Gesamtübersicht „überwacht von“, Verlauf live von der überwachenden Node, Traps an die zuständige Node.
- Menüpunkt „Agent“: Die Node hält die signierten Agent-Dateien bereit (Download auch für Hosts ohne Internet), zeigt
  Installationsbefehle und Agent-Versionen und aktualisiert Agents automatisch (je Host abschaltbar, „Jetzt
  aktualisieren“).
- Agent unter FreeBSD, OPNsense, pfSense und TrueNAS CORE per `install.sh` installierbar (rc.d-Dienst, Push-Betrieb).
- Dienstnamen, Zustands- und Fehlertexte in Deutsch und Englisch (auch in Meldungen, CSV und auf Statusseiten).
- Cluster: Mini-Verläufe auch für Hosts anderer Nodes; Karte „Hosts ohne überwachende Node“ (zuweisen/entfernen);
  offene Traps bleiben bei einer Übernahme offen; Änderungen gehen nach einem Schreibfehler im Cluster-Protokoll
  nicht verloren. Statusseiten: Zeiten, in denen Monitor64 nicht lief, zählen weder als Störung noch als beobachtet.
- Sicherheit: Bei SSH mit Passwort geht das Passwort erst an den Host, nachdem der Fingerabdruck seines
  Hostschlüssels bestätigt wurde (Verbindungstest und nach „Hostschlüssel verwerfen“).
- Aus dem Klicktest: RAM von Proxmox-VMs hat eine eigene Regel ohne Standardschwelle (der Wert enthält den Cache
  des Gastes); fehlt dem Proxmox-Token das Recht für Updates, steht das am Dienst statt als Teilfehler; neue Hosts
  und Zugänge werden sofort abgefragt, neu auftauchende Dienste sofort angeboten; Pseudo-Dateisysteme (SNMP) und
  Datei-Mounts (node_exporter im Container) entfallen; Host-Kacheln sind echte Links; Texte ohne Plural-Fehler.
- Windows-Agent: Dienste mit Starttyp Automatisch, die seit dem Booten nie gestartet wurden, zählen nicht als gestoppt.
  Die Installation scheitert nicht mehr an einem leeren Ordner `%ProgramData%\monitor64-agent` eines anderen
  Besitzers; ein Start im Vordergrund mit fehlerhaften Optionen legt diesen Ordner nicht mehr an.
