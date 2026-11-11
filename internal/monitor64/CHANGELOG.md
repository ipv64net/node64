# Monitor64 – Änderungen

## 0.1.9 – 2026-11-11

- Neuer Zugang **FRITZ!Box** (eigene Kachel im Assistenten) über die Schnittstelle TR-064: Internetverbindung (verbunden/getrennt, Dauer, externe Adresse, aktueller Durchsatz, Zugangsart und Zustand der Leitung), bei DSL-Anschlüssen Sync-Raten, Störabstand, Dämpfung und CRC-Fehler, Laufzeit und FRITZ!OS-Version der Box sowie „Update verfügbar“.
- Anmeldung mit einem FRITZ!Box-Benutzer (das Kennwort geht dabei nicht über die Leitung). In der FRITZ!Box muss „Zugriff für Anwendungen zulassen“ eingeschaltet sein. Für alle Werte braucht der Benutzer das Recht „FRITZ!Box Einstellungen“ – eine Nur-Lese-Rolle kennt die FRITZ!Box nicht; ohne das Recht kommen Zugangsart, Zustand der Leitung und der Update-Stand.

## 0.1.8 – 2026-11-11

- **Raspberry Pi, Stromversorgung korrigiert (Agent 0.1.2 und SSH):** Die Werte kommen jetzt von `vcgencmd get_throttled` (Unterspannung und Drosselung, jetzt und seit dem Start) und, wo das Programm fehlt oder der Zugriff nicht erlaubt ist, vom Unterspannungs-Alarm des Kernels (nur „jetzt“). Die bisher gelesene Datei `get_throttled` unter `/sys` ist im Pi-Kernel veraltet: Das Lesen schrieb einmal je Start eine Warnung ins Kernel-Log, „seit dem Start“ stimmte damit nicht, und ab Kernel 6.12 (Raspberry Pi OS 13) gibt es sie nicht mehr.
- Für „seit dem Start“ per SSH muss der Abfrage-Benutzer `vcgencmd` ausführen dürfen (Gruppe `video`); der Agent läuft als root und braucht nichts.

## 0.1.7 – 2026-11-11

- **Inodes:** Jedes Dateisystem mit Inode-Grenze (ext4, XFS …) hat jetzt eine eigene Schwelle „Dateisystem: Inodes belegt“ (Warnung ab 80 %, kritisch ab 90 %) – kein eigener Dienst, der Wert gehört zum Dateisystem und steht ab 50 % auch im Text. Dateisysteme ohne feste Grenze (Btrfs, FAT) haben den Wert nicht.
- **Btrfs:** je eingehängtem Dateisystem ein Dienst „Btrfs <Label>“ mit Profil (single, raid1 …), Anzahl der Geräte und Belegung der Metadaten; ein fehlendes Gerät wird wie ein degradiertes RAID gemeldet, Fehlerzähler der Geräte (wie `btrfs device stats`) als Warnung. Subvolumes desselben Dateisystems erscheinen weiterhin nur einmal. Kommt mit dem Agent ab 0.1.1 und per SSH sofort.
- **ZFS:** Die Fragmentierung des Pools steht im Dienst und im Verlauf.
- **Raspberry Pi:** eigene Kachel im Assistenten; neuer Dienst „Stromversorgung“: Unterspannung jetzt = kritisch, seit dem Start aufgetreten = Warnung, Drosselung = Warnung (Stand der Firmware wie `vcgencmd get_throttled`). Kommt mit dem Agent ab 0.1.1 und per SSH sofort.
- **Agent 0.1.1:** Die 32-Bit-ARM-Datei läuft jetzt auch auf Raspberry Pi Zero und Pi 1 (ARMv6); das Installationsskript erkennt `armv6l`.

## 0.1.6 – 2026-11-11

- Neuer Zugang **mailcow** (eigene Kachel im Assistenten) über die mailcow-API mit Nur-Lese-Schlüssel: Container (Postfix, Dovecot, Rspamd, SOGo …; jeder, der nicht läuft, wird gemeldet), Belegung des Mail-Speichers (vmail), Mail-Warteschlange mit den größten Ziel-Domains (nutzt die Schwelle „Mail-Warteschlange: zurückgestellte Mails“) und Quarantäne. In mailcow muss die Adresse der Node unter „API-Zugriff erlauben von“ stehen.

## 0.1.5 – 2026-11-11

- Neuer Zugang **Proxmox Mail Gateway** (eigene Kachel im Assistenten): CPU, Load, RAM, Swap und Root-Dateisystem, Dienste (Postfix, SMTP-Filter, ClamAV, Datenbank …), Mail-Warteschlange mit den größten Ziel-Domains, Durchsatz der letzten Stunde (ein, aus, Spam, Viren, abgewiesen), Quarantäne, Alter der ClamAV-Signaturen, Cluster (Node nicht erreichbar, nicht synchron) und ausstehende Updates.
- Anmeldung am Mail Gateway mit Benutzer und Passwort (Rolle „Auditor“, z. B. `monitor64@pmg`), weil es keine API-Token kennt; das Ticket wird automatisch erneuert. Benutzer mit zweitem Faktor werden mit Hinweis abgelehnt.
- Neue Schwelle „Mail-Warteschlange: zurückgestellte Mails“ (Warnung ab 100, kritisch ab 500, jeweils über 10 Minuten) im neuen Abschnitt „E-Mail“ der Schwellen; die Dienste stehen in der neuen Kategorie „E-Mail“.

## 0.1.4 – 2026-11-11

- Hängt ein Zugang (Docker-Daemon, PVE-API oder BMC antwortet nicht), wird die Runde nicht mehr verworfen: Der Host wird wie erwartet „nicht erreichbar“ und gemeldet, statt auf dem letzten Stand (oft OK) stehen zu bleiben.
- Benachrichtigungen: Ein ausdrücklich gewählter Kanal, der zugleich Standardkanal ist, bekommt Meldungen auch dann, wenn „Standardkanäle“ für diese Stufe nicht gewählt ist (bisher gingen sie verloren, im Verlauf stand trotzdem „gemeldet“).
- Nicht erreichbare Hosts werden wie kritische Dienste erinnert (Standard: täglich), solange das Problem nicht quittiert ist.
- Nach einem Neustart der Node melden Push-Hosts nicht mehr „unbekannt“, solange ihr Agent noch nicht wieder verbunden ist.
- Pausieren zeigt den Host sofort als pausiert, auch in Übersicht, Dashboard und Kennzahlen; seine alten Probleme stehen dort nicht mehr.
- Ein Wert, der bewusst nicht mehr kommt (z. B. CPU einer gestoppten VM), bleibt nicht mehr 7 Tage „unbekannt“, wenn er zuletzt eine Warnung hatte.
- „Alle neu prüfen“ nach dem Speichern bringt die Hosts nicht mehr dauerhaft in den Gleichschritt (Lastspitzen).
- „Dienste erkennen“ zählt einen Abbruch der Seite oder einen langsamen Zugang nicht mehr als Ausfall.
- Prometheus: Das Label `service` trägt den Namen (englisch) statt eines internen Textschlüssels; ebenso die Zeilen im Webhook ohne eigenen Inhalt.
- Cluster: Eine Quittierung, die eine andere Node gerade überschreibt, geht nicht mehr verloren; bei mehr als 500 Einträgen kommen die neuesten bei den anderen Nodes an; Änderungen während einer langen Sicherung werden nicht mehr verpasst; nach einem Wechsel der Zuständigkeit holt eine Node den Host nicht im 30-Sekunden-Takt zurück (getrennte Verbindung nur zwischen zwei Nodes); ein Schlüsselwechsel wird nicht mehr durch eine vorgehende Uhr einer anderen Node zurückgedreht; abgebrochene Anfragen der Oberfläche und Lesefehler stören den Cluster nicht mehr. Einzelne Nodes ohne Cluster fragen die Datenbank nicht mehr alle 2 s ab.
- Verlauf: Ein weit zurückliegender Zeitraum (Jahr) zeigt keine falschen Zeiten mehr.
- Sicherheit: Ändert man Adresse, Art oder Fingerabdruck eines Zugangs, muss das Geheimnis neu eingegeben werden – das gespeicherte geht nicht mehr still an das neue Ziel. Push-Token stehen im Export nicht mehr im Klartext (mit Passwort verschlüsselt, ohne Passwort weggelassen). Ein Push-Agent kann seinen ersten Hostschlüssel nach einem Neuladen des Hosts nicht mehr an einen fremden Token-Inhaber verlieren. Berichte eines Agents sind begrenzt (höchstens 5000 Dienste, 2000 lokale Checks), damit ein manipulierter Host die Datenbank nicht füllt. Fehlversuche am Push-Port zählen auch je IPv6-/48.
- SNMP: Das Zeitfenster der v3-Traps gilt je Absender (ein Host sperrt nicht mehr die Traps eines anderen; nach einer Stunde Ruhe neu); der Schutz gegen Trap-Fluten leert sich nicht mehr komplett. Die gelernte GETBULK-Grenze (RouterOS) gilt nur noch eine Stunde – ein einzelner Paketverlust drosselt nicht mehr für immer. Zu große GET-Antworten werden in kleineren Teilen nachgefragt. Zähler, die zurückgesetzt statt übergelaufen sind, erzeugen keine Spitze mehr. „Langsamer als sonst“ lernt nach einem Link-Verlust neu und gilt nicht für WLAN. Große Tabellen werden schneller sortiert.
- Proxmox VE und PBS mit Link-Local-Adresse samt Zone (`fe80::1%eth0`) funktionieren jetzt wirklich.
- Ein Port in der Adresse des Hosts (SSH, z. B. `nas:2222`) gilt nicht mehr für API-Zugänge ohne eigene URL und für SNMP – wie im Vorschlag der Oberfläche.
- Docker/Podman: Die CPU-Last bei Podman auf Hosts mit 2 Kernen springt nicht mehr zwischen richtigem und doppeltem Wert.
- Agent (mit der nächsten Agent-Version): Fehlversuche vor der Anmeldung zählen auch je IPv6-/48.
- Oberfläche: Im Assistenten gehen Eingaben (Benutzer, Passwort) nicht mehr verloren, wenn die Antwort zur Node-Adresse bzw. zum Push-Token nachkommt. Abweichungen für Gruppen oder Tags mit „|“ im Namen werden richtig gespeichert. Auf der Seite Probleme zeigt ein schnell gewechseltes Problem nicht mehr den Verlauf (und die Knöpfe) eines anderen. Dialoge stapeln keine alten Klick-Handler mehr. Ein kaputter Link `#svc=%` hält das Neuladen der Host-Seite nicht mehr an.
- Schneller: Skript und Stylesheet werden mit ETag ausgeliefert (unverändert 304 statt jedes Mal 230 KB); die Dashboard-Karte rechnet ohne Datenbank-Abfragen; neue Indizes für „Zuletzt“ und geschlossene Probleme; die Kennung der Node wird nicht mehr je Runde gelesen.

- IPv6 durchgängig: Die Adresse eines Hosts nimmt IPv6 jetzt auch mit Port (`[2001:db8::1]:2222`) an; bisher wurde diese Schreibweise beim Speichern verstümmelt. Ungültige Adressen werden gleich abgelehnt.
- IPv6 ohne eckige Klammern funktioniert jetzt auch in der Adresse eines Prometheus-Exporters (`fd00::1`) und bei Docker über `tcp://` bzw. `ssh://`; bei `ssh://user@fd00::1` wurde bisher still der letzte Block als Port gelesen.
- Link-Local-Adressen mit Zone (`fe80::1%eth0`) funktionieren jetzt auch bei den Zugängen über HTTPS (Proxmox VE, Proxmox Backup Server, TrueNAS, Unraid, Server-BMC) und Prometheus.
- Assistent und Zugangs-Dialog: Die vorgeschlagene URL setzt eine IPv6-Adresse in Klammern und lässt einen Port aus der Adresse des Hosts weg; die weiteren Nodes eines Proxmox-Clusters bekommen damit auch bei einer Adresse mit Port die richtige URL.

## 0.1.3 – 2026-11-11

- Dashboard: eigene Karte mit Hosts, Diensten, nicht erreichbaren Hosts, kritischen Diensten und Warnungen, Wartung und letzter Störung. Die Probleme stehen unter „Letzte Störungen“ in derselben Liste wie die Healthchecks (mit Abzeichen „Monitor64“).
- Tablet und Smartphone: Die Dienste-Tabelle der Host-Seite passt auf den Bildschirm – Zusatztexte brechen um, Dienstnamen nicht mehr buchstabenweise; die Listenansicht der Übersicht passt auf schmale Bildschirme, „4 Hosts · 93 Dienste“ wird nicht mehr abgeschnitten.

## 0.1.2 – 2026-11-11

- Eigenes Logo (hell und dunkel) in der Übersicht und bei den Modulen.
- Neue Dienste beim Host: Knöpfe „alle“ und „keine“ über der Auswahl.
- Docker-Zugang funktioniert auch mit Podman (Docker-kompatible API über `podman.socket`, lokal oder per `ssh://…/run/podman/podman.sock`). Die CPU-Last der Container stimmt dabei: Podman meldet die Systemzeit anders als Docker, bisher zeigte ein Container mit einem belegten Kern bis zu 100 %.
- SNMP-Traps ausgeschaltet: Der gemerkte Trap-Stand verschwindet sofort, auch wenn gerade eine Abfrage lief (bisher bis zur nächsten Runde).
- Proxmox Backup Server: Die Befehle im Assistenten geben das Recht `Audit` jetzt auch dem Benutzer – ein PBS-Token darf nur, was auch sein Benutzer darf.
- SNMP mit MikroTik/RouterOS (z. B. CRS305): Die Ports kommen jetzt. RouterOS verwirft zu große Sammelabfragen still statt sie abzulehnen; Monitor64 fragt dann kleiner und merkt sich die Grenze. Fehlende Werte ohne Angabe, welcher fehlt (RouterOS), machen die Runde nicht mehr „teilweise“.

## 0.1.1 – 2026-11-10

- Übersicht, Ansicht „Liste“: Hosts stehen nach Gruppen zusammen (Gruppenzeile mit Anzahl wie bei den Kacheln). Ein
  Klick auf eine Spalte sortiert innerhalb jeder Gruppe, und die gewählte Sortierung bleibt beim automatischen
  Auffrischen erhalten.

## 0.1.0 – 2026-11-10

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
  Hostschlüssels bestätigt wurde (Verbindungstest und nach „Hostschlüssel verwerfen“). Aus dem Security-Review: Das
  gilt jetzt auch im Assistenten „Host hinzufügen“ (ein nur angezeigter, nicht bestätigter Fingerabdruck wird nicht
  mehr übernommen) und wenn ein Zugang erstmals ein Passwort bekommt; SNMP-v3-Traps müssen mindestens die Stufe des
  Benutzers haben; Texte von Geräten können die Anzeige nicht mehr über fremde Text-Schlüssel stören.
- Aus dem Klicktest: RAM von Proxmox-VMs hat eine eigene Regel ohne Standardschwelle (der Wert enthält den Cache
  des Gastes); fehlt dem Proxmox-Token das Recht für Updates, steht das am Dienst statt als Teilfehler; neue Hosts
  und Zugänge werden sofort abgefragt, neu auftauchende Dienste sofort angeboten; Pseudo-Dateisysteme (SNMP) und
  Datei-Mounts (node_exporter im Container) entfallen; Host-Kacheln sind echte Links; Texte ohne Plural-Fehler.
- Windows-Agent: Dienste mit Starttyp Automatisch, die seit dem Booten nie gestartet wurden, zählen nicht als gestoppt.
  Die Installation scheitert nicht mehr an einem leeren Ordner `%ProgramData%\monitor64-agent` eines anderen
  Besitzers; ein Start im Vordergrund mit fehlerhaften Optionen legt diesen Ordner nicht mehr an.
- Windows-Agent: Symbol im Infobereich der Taskleiste für jeden angemeldeten Benutzer – zeigt, dass der Dienst läuft,
  die Version, die letzte Abfrage durch die Node und ob ein Update verfügbar ist (abschaltbar mit `-NoTray` bzw.
  `install --no-tray`).
