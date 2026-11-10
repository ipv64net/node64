# Plan: Monitor64 (Monitoring mit Schwellen und Verlauf)

Stand 2026-11-09 – Planung abgeschlossen, alle Abschnitte mit Dennis entschieden; Umsetzung beginnt mit Phase 0 auf Ansage.

## Entscheidungen

| Thema | Entscheidung |
|---|---|
| Abgrenzung | **Healthchecks** = up/down (läuft es?). **Monitor64** = Zustand und Leistung mit Schwellen und Verlauf (Füllstände, Auslastung, Platten, Netz, RAID, USV …). |
| Keine Schnittmenge | Monitor64 hängt nicht von Healthchecks ab. Ob ein System erreichbar ist, stellt Monitor64 selbst über seinen Zugang fest (Agent, SSH, SNMP, API). Einzige Brücke: ein Klick „Healthcheck anlegen“ (z. B. Ping alle 5 Minuten auf die IP) – danach ohne Verbindung. |
| Proxmox/Docker/PBS | Ziehen **komplett** nach Monitor64: Proxmox VE und Docker verschwinden mit der Freigabe aus Healthchecks (entschieden 2026-11-09, PBS ebenso). **Kein Migrationsweg**, auch keine Übernahme von Zugangsdaten – Verbindungen werden in Monitor64 neu angelegt. |
| Bestand | **Nichts übernehmen.** Alte Schwellen und Verläufe aus Healthchecks werden nicht migriert; Monitor64 startet für alle mit eigenen Standard-Schwellen (angelehnt an CheckMK/Zabbix, siehe unten). |
| ipv64.net | Erster Schritt **ohne** ipv64.net: alles läuft und speichert lokal. Benachrichtigung darf über die ipv64-Kanäle laufen. Später evtl. einfache Infos an ipv64.net – nicht in v1. |
| Standard | Modul **aus**. Ausgeschaltet: kein Menüpunkt, kein Port, keine Goroutine, keine Abfrage, keine Migration; stört kein anderes Modul. |
| Grenzen | Lokal keine Grenzen (Hosts, Dienste, Verlauf nur durch Hardware begrenzt). |
| Agent | Name **Monitor64-Agent** (`monitor64-agent`). **Node fragt ab (Pull)** – wie CheckMK, Zabbix (passiv), NRPE, Prometheus, Beszel. Push später optional (NAT/VPS). Download über GitHub-Releases und node64.de. **Nicht im Image:** die Node lädt die Dateien bei Bedarf nach (Signatur geprüft) und bietet sie dann auch selbst zum Download an (für Hosts ohne Internet). |
| Abhängigkeiten | `github.com/gosnmp/gosnmp`, `golang.org/x/crypto/ssh` (schon da), Chart.js (schon da). |
| Windows-Signatur | Später (Code-Signing-Zertifikat, Kosten offen). |
| Git | Kein Verstecken nötig (Veröffentlichung in 2–3 Tagen). Normal im Repo, Push nur auf Ansage; bis zur Freigabe ist das Modul **nicht einschaltbar** (Schalter `NODE64_MONITOR64=1`, nur auf 8091 gesetzt) und der Agent nicht als Download verlinkt. |

## Kernmodell

Leitlinie: **einfach und übersichtlich** – lieber wenige klare Regeln als viele Schalter.

| Begriff | Bedeutung |
|---|---|
| Host | ein Gerät/System (Name, Adresse, Art, **eine** Gruppe, beliebig viele Tags, optional Beschreibung/Standort) |
| Zugang | ein Weg zu Daten: Agent, SSH, SNMP, API (Proxmox VE/PBS, Docker …), Prometheus – ein Host hat einen oder mehrere |
| Dienst | ein überwachtes Ding auf dem Host (Dateisystem, Platte, Port, Bond, VM, Container …) |
| Messgröße | eine Zahl mit Verlauf; ein Dienst kann mehrere haben (Port: ↓/↑ Mbit/s, Fehler/min, Auslastung) |
| Zustand | OK, Warnung, Kritisch, Unbekannt |

**Host**
- Erreichbar, solange **ein** Zugang antwortet. Fällt nur einer von mehreren aus, wird er zum Dienst „Zugang SSH“
  (Warnung). Antworten alle zwei Runden lang nicht: „nicht erreichbar“ – eine Meldung, Dienste Unbekannt.
- Zustand = schlechtester Dienst; Wartung und „nicht erreichbar“ gehen vor.

**Zugang**
- Art, Verbindungsdaten, Geheimnisse verschlüsselt (`internal/secrets`), Intervall, Timeout; Anzeige letzte Antwort
  und Antwortzeit. Je Runde eine Abfrage (Agent: alles in einer Antwort; SSH: eine Sitzung; SNMP: Bulk).
- Liefern zwei Zugänge denselben Dienst, gibt es ihn nur einmal: Rangfolge Agent > SSH > API > SNMP > Prometheus,
  je Dienst änderbar.
- **Intervall** Standard 1 Minute, je Host 30 Sekunden bis 15 Minuten. SMART alle 30 Min., Updates alle 60 Min.
  (ändern sich kaum, Platten nicht unnötig wecken).

**Dienst**
- Fester Schlüssel, damit Verlauf und Schwellen bleiben: `fs:/var/lib/vz`, `if:enp1s0`, `bond:bond0`, `ctr:nextcloud`,
  `vm:101`; **Platten nach Seriennummer** (nicht `sda`, das wechselt nach Neustart/Tausch).
- Anzeigename frei änderbar. Typen: Zahlenwert mit Schwellen, Zustandsdienst mit festen Regeln, nur Anzeige.
- Zustand = schlechteste Messgröße; 3 Intervalle ohne Daten = Unbekannt.

**Messgrößen**
- Zähler werden auf der Node zu Raten (Byte → Mbit/s, Fehler → je Minute); Überlauf/Neustart des Zählers wird erkannt
  und übersprungen. Einheiten einheitlich (%, Byte, Byte/s, °C, Anzahl), Anzeige rechnet um.

**Zustand ermitteln**
- Zahlenwert: Warnung/Kritisch, Richtung (oben oder unten, z. B. Toner), Dauer, Hysterese (Standard 2 Punkte: Warnung
  ab 80 % wird erst unter 78 % wieder OK). Füllstände zusätzlich Trend aus 7 Tagen („voll in N Tagen“).
- Regeln mit drei Stufen: Standard → Gruppe/Tag → Host/Dienst (inkl. „nur anzeigen“); je Dienst sichtbar, woher die
  Schwelle kommt. Einzelheiten unter „Schwellen und Regeln im Detail“.

**Dienste erkennen** (entschieden 2026-11-09)
- Beim Anlegen (im Assistenten bestätigen) und danach stündlich im Hintergrund.
- **Neue Dienste werden nie automatisch übernommen:** Hinweis „3 neue Dienste auf nas01“ an Host und Übersicht,
  übernehmen oder ignorieren per Klick.
- **Verschwundene Dienste werden immer gemeldet** (Warnung, z. B. „Platte WD-ABC123 nicht mehr da“) und bleiben, bis
  jemand aktiv auf „Entfernen“ klickt (mit Akteur im Verlauf). Keine Ausnahmen.
- Standardmäßig nicht angeboten: tmpfs, overlay, squashfs, /snap, /run, Docker-Overlays; Switch-Ports ohne Link
  (werden erst angeboten, wenn sie einmal verbunden waren).

**Proxmox**
- VMs und LXC sind **Dienste** des Proxmox-Hosts (CPU, RAM, Disk, läuft/gestoppt). Knopf „als eigenen Host anlegen“
  übernimmt Name und IP (für Agent/SSH in der VM).
- **Cluster automatisch erkennen:** Zugang zur Cluster-API schlägt alle Nodes als eigene Hosts vor (übernehmen per
  Klick, wie bei Diensten); neue Nodes im Cluster erscheinen als Hinweis.

## Zugänge und was sie liefern

| Zugang | Gut für | Liefert u. a. |
|---|---|---|
| **Monitor64-Agent** (Linux, Windows, FreeBSD) | alles, wo man installieren darf | CPU, Load, RAM/Swap, Dateisysteme, Platten-I/O, **SMART**, Netz je Port, Bonding/LACP, Temperaturen, ZFS/mdraid, systemd-Dienste, Updates, Neustart nötig; Windows: Dienste, Windows Update, Laufwerke, SMART; eigene Skripte (Format der CheckMK-„local checks“) |
| **SSH agentenlos** | Pi, OMV, Unraid, Synology, Linux | dieselben Linux-Werte aus `/proc`, `/sys`, `df`; SMART nur mit sudo-Freigabe für `smartctl` (eine Zeile in sudoers, wird angezeigt) |
| **SNMP v2c/v3 + Traps** | Switches, NAS, USV, Drucker, Router | IF-MIB (Bandbreite, Fehler, Status), LAG/LACP-MIB, HOST-RESOURCES, UCD; Profile für Synology, QNAP, APC, Drucker, MikroTik, UniFi; „eigene OID“ |
| **API** | Proxmox VE, PBS, Docker, später TrueNAS, Unraid, NUT, Redfish/IPMI | Gäste, Speicher, Datastores, Backups, Container; bei Proxmox auch SMART |
| **Prometheus abfragen** | wer schon `node_exporter`/`windows_exporter` hat | was der Exporter liefert |

**Gemeinsam für alle Zugänge (entschieden 2026-11-09)**
- Jede Node hat **einen eigenen Schlüssel** (ed25519, beim ersten Einschalten erzeugt, in `internal/secrets`). Er gilt
  für Agent und SSH. Der öffentliche Teil ist kein Geheimnis und steht im Installationsbefehl.
- Hostschlüssel bzw. Zertifikat wird beim ersten Kontakt gemerkt (TOFU), im Assistenten mit Fingerabdruck angezeigt;
  ändert er sich, wird nicht abgefragt, sondern der Zugang meldet „Schlüssel geändert“ mit Knopf „neuen übernehmen“.
- Verbindungen bleiben offen (eine je Host, je Runde ein neuer Kanal); spart Handshakes bei vielen Hosts. Höchstzahl
  gleichzeitiger Abfragen in den Einstellungen.
- Jeder Zugang zeigt im Host „Was wird abgefragt?“ – Befehle, OIDs bzw. API-Pfade im Klartext.

### Monitor64-Agent

- Eine statische Go-Datei ohne Abhängigkeiten: Linux amd64/arm64/armv7 (Pi), Windows amd64; FreeBSD (OPNsense,
  TrueNAS Core) später. Ziel unter 15 MB RAM, im Leerlauf keine Arbeit.
- **Protokoll:** SSH (`x/crypto/ssh`) auf Port 6465/TCP (nicht 6556 wegen CheckMK, nicht 6464 wegen Sonar64),
  einstellbar. Nimmt nur Schlüssel aus `/etc/monitor64-agent/keys` (mehrere Nodes möglich, z. B. Cluster).
  Genau vier Anfragen, alles andere wird abgewiesen: `info` (Version, OS, Fähigkeiten), `collect` (Werte),
  `update` (signierte neue Datei), `keys` (Schlüsselliste ersetzen – für Schlüsselwechsel und Cluster). Keine Shell, keine Befehle von außen, kein Port-Forwarding.
- **Antwort:** ein JSON-Dokument mit Version und Abschnitten (`cpu`, `mem`, `fs`, `disk`, `net`, `bond`, `smart`,
  `raid`, `zfs`, `temp`, `svc`, `updates`, `local` …). Zähler roh mit Zeitstempel, Raten rechnet die Node; der Agent
  ist zustandslos. Unbekannte Abschnitte werden ignoriert – alte Agents passen zu neuen Nodes und umgekehrt.
- Langsame Abschnitte (SMART 30 min, Updates 60 min) puffert der Agent und liefert den letzten Stand sofort.
- **Linux:** Werte aus `/proc` und `/sys`; SMART über `smartctl -j` (smartmontools ≥ 7; fehlt es, Hinweis statt
  Fehler); mdraid `/proc/mdstat`, ZFS `zpool`, Bonding `/proc/net/bonding`, Temperaturen `hwmon`/`thermal`,
  systemd fehlgeschlagene Dienste, „Neustart nötig“, Updates (apt, dnf, zypper, pacman, apk).
  Läuft als root unter systemd mit Härtung (`ProtectSystem=strict`, `NoNewPrivileges` …), weil SMART root braucht.
- **Windows:** Dienst über `x/sys/windows/svc` (schon im Modul). Schnelle Werte über die Windows-API, langsame
  (SMART/Zuverlässigkeit über `Get-PhysicalDisk`/`Get-StorageReliabilityCounter`, Windows Update) über PowerShell –
  keine zusätzlichen Bibliotheken. Legt die Firewall-Regel für 6465 an.
- **Eigene Skripte:** Dateien in `/etc/monitor64-agent/local.d/` bzw. `C:\ProgramData\monitor64-agent\local.d\`, Format
  der CheckMK-„local checks“ (vorhandene Skripte laufen weiter). Nur lokal ablegbar, nie von der Node aus.
- **Installation:** Der Assistent zeigt einen Befehl mit dem öffentlichen Schlüssel der Node, z. B.
  `curl -fsSL https://node64.de/agent/install.sh | sh -s -- --key "ssh-ed25519 AAAA… node64@nas"`; Windows als
  PowerShell-Einzeiler. Das Skript legt Datei, Schlüssel und Dienst an und zeigt den Fingerabdruck zum Vergleich.
  Deinstallation `monitor64-agent uninstall`. Alternativ kommt alles von der Node selbst
  (`http(s)://<node>/monitor64/agent/…`): sie lädt die Dateien beim ersten Bedarf von GitHub/node64.de, prüft die
  Signatur und hält sie vor – so geht es auch für Hosts ohne Internet.
- **Verteilung (gebaut 2026-11-10, entschieden 2026-11-09/10):** Die Dateien liegen unter
  `https://ipv64.net/node64/agent/` (Standard-Quelle der Node, Ordner `node64` wie die Selbst-Updates) und
  `https://node64.de/agent/` (Ausweichquelle); für Tests per `NODE64_MONITOR64_AGENT_URL` überschreibbar. Ablage:
  `agents.json` (Version, Dateien je Plattform mit Größe und SHA-256) + `agents.json.sig` (signiert wie das Manifest
  der Selbst-Updates), `<version>/monitor64-agent-<os>-<arch>[.exe]` + `.update.json` (signierte Kopfzeile),
  `install.sh`, `install.ps1`, `SHA256SUMS`; Plattformen Linux amd64/arm64/armv7, Windows amd64, FreeBSD
  amd64/arm64. Der Agent hat eine eigene Version (`cmd/monitor64-agent/VERSION`). Die Node holt das Verzeichnis beim
  ersten Bedarf und alle 6 h, lädt Dateien erst bei Bedarf nach `<data>/monitor64/agent/`, prüft SHA-256 und
  Signatur und bietet sie ohne Anmeldung unter `/monitor64/agent/<datei>` an (`install.sh --base …`,
  `install.ps1 -Base …`). Eigener Menüpunkt **Agent**: verfügbare Version, Downloads, Installationsbefehle für
  Linux/Windows/FreeBSD (Quelle „Internet“ oder „diese Node“ – dieselbe Auswahl im Assistenten), Schlüssel der Node,
  Hosts mit Agent-Version und Update-Stand. Einzelheiten und Release-Ablauf: `MONITOR64-AGENT-RELEASE.md`.
- **Updates automatisch** (Standard an, je Host abschaltbar; entschieden 2026-11-09): Erscheint ein neuer Agent,
  schiebt die Node ihn über die bestehende Verbindung (Host braucht kein Internet), höchstens 2 Hosts
  gleichzeitig, nie während einer Abfragerunde desselben Hosts, im Cluster nur die zuständige Node. Der Agent prüft
  die Signatur (ed25519, Release-Schlüssel eingebaut), tauscht sich aus und startet neu; bei Fehler bleibt die alte
  Datei, die Node zeigt den Fehler am Zugang und versucht es frühestens nach 6 h erneut. Im Verlauf steht
  „Agent 0.3 → 0.4 (System)“; Knopf „jetzt aktualisieren“ (Seite Agent) bleibt für Hosts mit abgeschaltetem
  Automatismus.

### SSH ohne Agent

- Anmeldung mit dem Schlüssel der Node. Passwort nur als echte Ausnahme für Systeme, die keinen Schlüssel annehmen
  (im Assistenten unter „Erweitert“, mit Hinweis; gespeichert in `internal/secrets`). Empfohlen: eigener Benutzer
  `monitor64`, Zeile in `authorized_keys` mit `restrict,from="<IP der Node>"` (zeigt der Assistent).
- Je Runde **ein** festes Skript (in der Node eingebaut, im Host einsehbar) per `sh -s`: nur lesende Befehle
  (`cat /proc/…`, `/sys/…`, `df -PkT`, `zpool list -Hp`, `systemctl --failed`, Updates stündlich), Ausgabe in
  Abschnitten wie beim Agent. Läuft mit BusyBox (Synology, OpenWrt) und Slackware (Unraid).
- SMART nur mit `sudo -n smartctl -j …`; die sudoers-Zeile zeigt der Assistent. Als root (Unraid) ohne sudo.
- Liefert dieselben Dienste wie der Agent unter Linux – nur ohne Windows und ohne eigene Skripte.

### SNMP

- `gosnmp`; v1/v2c (Community) und v3 (authPriv, SHA-2/AES). GETBULK, nur benötigte Tabellen, 64-Bit-Zähler.
- **Immer:** sysUpTime (Neustart erkannt), IF-MIB (Ports: Mbit/s, Auslastung, Fehler, Status – nur Ports, die schon
  einmal verbunden waren), HOST-RESOURCES (Speicher, Platten, CPU), UCD (Linux net-snmp), IEEE8023-LAG (LACP),
  ENTITY-SENSOR (Temperaturen), Printer-MIB (Toner, Papier), UPS-MIB (USV).
- **Profile** wählt die Node selbst über `sysObjectID`: Synology, QNAP, TrueNAS, APC, MikroTik, UniFi, dazu Drucker
  und USV allgemein. Profile sind Datendateien im Repo (`internal/monitor64/snmp/profiles/*.json`: OID → Dienst,
  Einheit, Faktor, Standard-Schwellen) – Community kann neue per Pull-Request beitragen.
- **Eigene OID** am Host: OID, Name, Einheit, Faktor, Zähler oder Wert.
- **Traps:** Empfang auf UDP 162 (einstellbar, z. B. 1162 mit Port-Mapping), nur offen, wenn ein Host Traps nutzt.
  Trap von bekanntem Host → sofortige Abfrage des betroffenen Dienstes (linkDown → Port, onBattery → USV); der
  Zustand kommt weiter aus der Abfrage, nicht aus dem Trap. Übrige Traps landen im Dienst „Traps“ des Hosts
  (Warnung bis quittiert). Traps unbekannter Absender: Liste mit „als Host anlegen“. v3-Traps in Phase 2.

### APIs

- Vorhandene Clients aus `internal/proxmox` (Proxmox VE mit Cluster-Adressen und Zertifikats-Pinning, PBS,
  Docker lokal/entfernt) werden wiederverwendet; Monitor64 hat aber eigene Verbindungen und Einstellungen.
- **Proxmox VE** (Token mit Rolle `PVEAuditor`, Befehl zeigt der Assistent): Node CPU/RAM/Load, Speicher und
  ZFS-Pools, Platten mit SMART und Verschleiß, Gäste als Dienste (`vm:101`: Status, CPU, RAM, Platte, Netz),
  Cluster-Quorum, HA, Ceph-Zustand (falls vorhanden), ausstehende Updates.
- **PBS:** Datastores (Füllstand, „voll in X Tagen“), Alter des letzten Backups je Gruppe, Verify/GC/Prune-Jobs,
  Platten mit SMART.
- **Docker:** Container als Dienste (Zustand, Health, Neustarts, CPU, RAM).
- Später: TrueNAS, Unraid, NUT, Redfish/IPMI.

### Prometheus abfragen (Phase 3)

- Eigener kleiner Parser für das Textformat (keine Bibliothek); `node_exporter` und `windows_exporter` werden auf
  dieselben Dienste abgebildet wie beim Agent.

## Netzwerk (Pflicht in v1)

- Bandbreite je Port in Mbit/s (ein/aus) und Auslastung bezogen auf die Link-Geschwindigkeit.
- Fehler und Verwerfungen je Port (Errors, Drops, CRC) als Rate; Link-Status, Geschwindigkeit/Duplex-Wechsel.
- Bonding/LACP: Zustand je Bond, Mitglieder (up/down), LACP-Partner/Aggregator passt, Modus; Linux aus
  `/proc/net/bonding`, Switches per SNMP.
- Platten-I/O-Fehler (Kernel/SMART) als eigener Dienst.

## Standard-Schwellen (angelehnt an CheckMK/Zabbix, entschieden 2026-11-09)

| Dienst | Warnung | Kritisch | Dauer |
|---|---|---|---|
| Dateisystem belegt | 80 % | 90 % | sofort; Trend „voll in < 7 Tagen“ = Warnung, < 2 Tagen = Kritisch |
| RAM belegt | 80 % | 90 % | 5 min |
| Swap belegt | 50 % | 80 % | 5 min |
| CPU-Auslastung | 90 % | 95 % | 15 min |
| Load je Kern | 2,0 | 4,0 | 15 min |
| SMART | neu umgelegte/ausstehende Sektoren > 0 | Gesamtstatus FAILED, ausstehende Sektoren steigen | sofort |
| Plattentemperatur | 50 °C | 60 °C (NVMe 70/80 °C) | 5 min |
| SSD-Verschleiß | 80 % verbraucht | 90 % | sofort |
| Port-Auslastung | 80 % | 90 % | 5 min |
| Port-Fehlerrate | 0,01 % | 0,1 % | 5 min |
| Bond-Mitglied down / LACP passt nicht | Warnung | – | sofort |
| RAID/ZFS degraded | – | Kritisch | sofort |
| USV auf Batterie / Restlaufzeit | auf Batterie | < 10 min | sofort |
| Updates ausstehend / Neustart nötig | Warnung (Sicherheitsupdates) | – | 1 Tag |

## Schwellen und Regeln im Detail (entschieden 2026-11-09)

Ziel: Man stellt fast nie etwas ein. Standard passt für die meisten; Abweichungen sind wenige, klar sichtbar und immer
erklärt („woher kommt die Schwelle?“).

**Stufen**
1. **Standard** – eine Tabelle je Art (Dateisystem, RAM, CPU, Port …), siehe oben.
2. **Abweichungen für Gruppe oder Tag** – **eine** Liste, **oben gewinnt** (mit Pfeilen sortierbar). Kein
   Rechnen, kein Mischen mehrerer Treffer. Beim Speichern steht da: „betrifft 14 Dienste auf 5 Hosts, danach 2
   Warnungen“ (Vorschau, bevor es gilt).
3. **Dieser Host** – direkt am Dienst: „nur dieser Dienst“ oder „alle Dateisysteme (Ports …) dieses Hosts“.

- Jedes Feld erbt einzeln (Warnung, Kritisch, Dauer): nur was man einträgt, weicht ab; leere Felder zeigen „erbt 80 %“.
- Am Dienst immer sichtbar: die drei Stufen untereinander, die geltende markiert, Knopf „auf Standard zurück“.
- Jede Änderung mit Akteur im Verlauf und im Audit-Log; Neubewertung sofort.
- Bewusst **nicht** in v1: Namensmuster (Regex), zeitabhängige Schwellen (dafür wiederkehrende Wartung), Formeln.

**Ein Dienst, mehrere Werte**
- Ein Dienst kann mehrere Messgrößen haben (Port `if:enp1s0`: ein/aus Mbit/s, Fehler, Verwerfungen; Platte: Temperatur,
  SMART, Verschleiß). Schwellen je Messgröße, Zustand des Dienstes = schlimmste Messgröße; die Meldung nennt die
  auslösende („enp1s0: Fehlerrate 0,3 %“).

**Zahlenwerte**
- Warnung/Kritisch, Richtung kommt aus der Art (Toner, Akku, USV-Restlaufzeit: nach unten).
- **Dauer:** Alle Messungen im Zeitraum müssen über der Schwelle liegen (kurze Spitzen zählen nicht). Der Dienst zeigt
  „seit 7 Min. über 90 % – Warnung ab 15 Min.“
- **Hysterese:** Standard 2 Einheiten (2 Prozentpunkte, 2 °C), nur unter „Erweitert“.
- **Dateisysteme/Datastores:** wahlweise in % belegt **oder** „weniger als X GB frei“ (für große Volumes: 90 % von
  40 TB sind noch 4 TB). Dazu Trend aus 7 Tagen (lineare Ausgleichsgerade, ab 24 h Daten): voll in < 7 Tagen =
  Warnung, < 2 Tagen = Kritisch.

**Zustandsdienste (feste Regeln, ohne Zahl)**
- SMART FAILED, RAID/ZFS degraded, Bond-Mitglied down, USV auf Batterie, Neustart nötig …: je Regel nur wählbar
  **Kritisch / Warnung / nicht melden**.
- **Soll-Zustand von Gästen und Containern** ohne Einstellen: Proxmox-Gast mit „beim Booten starten“ (onboot) soll
  laufen, sonst darf er aus sein; Docker-Container mit Neustart-Richtlinie soll laufen, ohne darf er aus sein. Am
  Dienst änderbar („soll laufen / darf aus sein“).

**Melden oder nur anzeigen**
- Je Stufe: **melden** (Standard) oder **nur anzeigen** (Zustand und Verlauf ja, keine Benachrichtigung, nicht in der
  Problemliste oben, aber im Filter). „Nicht überwachen“ gibt es nicht als Schwelle – dafür Dienst entfernen/ignorieren.

**Unbekannt**
- Ein Dienst ohne Daten (3 Intervalle) wird **Unbekannt** und wie eine Warnung gemeldet – außer der ganze Host ist
  nicht erreichbar, dann nur die eine Host-Meldung.

## Speicher und Leistung (entschieden 2026-11-09)

**Wo liegt was**
- **Konfiguration** (Hosts, Zugänge, Dienste, Regeln, Abweichungen, Benachrichtigung, Wartung, Quittierungen,
  Probleme mit Ablauf und Akteur) in `node64.db`, Tabellen `m64_*`. Die Tabellen entstehen erst beim **ersten
  Einschalten** (keine Migration, solange das Modul aus ist). Damit ist alles automatisch im Konfig-Export und in
  jedem Backup.
- **Verlauf** (Messreihen) in eigener Datei `monitor64.db` – wie `dns64.db`/`cdn64.db`: im Backup „mit Statistik“,
  sonst nicht; eigene Datei, damit Schreiblast die Kern-Datenbank nicht bremst (WAL).
- Zustandswechsel sind keine Messreihe, sondern Ereignisse in der Problem-Historie (Konfiguration).
- Modul aus: `monitor64.db` wird nicht geöffnet, Daten bleiben liegen. Knopf „Monitor64-Daten löschen“ in den
  Einstellungen (mit Akteur im Audit-Log).

**Messreihen**
- Eine Reihe je Messgröße (Dienst + Wert, z. B. `if:enp1s0/in`). Gespeichert wird der fertige Wert (Mbit/s, %, °C),
  Zähler rechnet die Node vorher in Raten um.
- **Blöcke statt Zeilen:** je Reihe und Stunde ein Block (Zeitstempel als Delta-of-Delta, Werte skaliert als
  Ganzzahl-Delta, Varint, danach komprimiert) – grob 2–3 Byte je Messpunkt statt ~40 Byte als SQLite-Zeile.
- Der laufende Block liegt im Speicher und wird **alle 5 Minuten** gesichert (Absturz verliert höchstens 5 Minuten).
- **Verdichtung:** Ist eine Stunde voll, entstehen 5-Minuten- und Stundenwerte jeweils mit **Min/Mittel/Max** – im
  Jahresdiagramm bleiben Spitzen sichtbar.
- **Aufbewahrung** (einstellbar, auch „unbegrenzt“): 1-Minuten-Werte 48 h, 5-Minuten-Werte 30 Tage, Stundenwerte
  1 Jahr. Aufräumen einmal nachts.
- **Größe (Schätzung):** ca. 30 Messgrößen je Host → etwa 5 MB je Host bei Standard-Aufbewahrung (10 Hosts ≈ 50 MB,
  100 Hosts ≈ 500 MB). Die Einstellungen zeigen die aktuelle Größe.

**Abfragen**
- Ein Planer, Hosts gleichmäßig über das Intervall verteilt (fester Versatz je Host, keine Lastspitze zur vollen
  Minute). Arbeiter-Pool mit Obergrenze (Standard 16, einstellbar).
- Zeitlimit je Abfrage höchstens 80 % des Intervalls (max. 30 s). Ein langsamer Host bremst keinen anderen; ist die
  vorige Runde noch nicht fertig, fällt die nächste aus und der Zugang zeigt „verspätet“.
- Verbindungen (Agent, SSH) bleiben offen; SNMP über einen gemeinsamen Socket.

**Oberfläche**
- Diagramme bekommen höchstens ~700 Punkte: der Server wählt die Auflösung nach Zeitraum (6 h → 1 min, 24 h–30 Tage
  → 5 min, darüber Stundenwerte) und verdichtet bei Bedarf mit Min/Max.
- Übersicht und Probleme lesen nur den Zustand aus dem Speicher; Aktualisierung alle 15 s, nur geänderte Daten.
- Prometheus-Export liest nur den Speicher (keine Datenbankabfrage).

**Zielwerte (Testlauf vor der Freigabe)**
- 100 Hosts / 3.000 Messgrößen: unter 50 MB zusätzlicher RAM, CPU im Mittel unter 2 % eines Kerns.
- 1.000 Hosts / 30.000 Messgrößen müssen laufen (500 Messpunkte je Sekunde), ohne die übrigen Module zu bremsen.
- Prüfung mit einem eingebauten Lastgenerator (Schein-Hosts) auf 8091.

## Statusseiten (entschieden 2026-11-09)

- **Die einzige Verbindung zu Healthchecks:** Es gibt die Statusseiten weiterhin nur **einmal** (Healthchecks).
  Bei eingeschaltetem Monitor64 kann man dort zusätzlich Monitor64-**Hosts** (optional einzelne Dienste) als Eintrag
  aufnehmen – gemischt mit Healthchecks oder nur Monitor64, wie jeder mag.
- Zustand auf der Seite: OK → in Betrieb, Warnung → eingeschränkt, Kritisch/nicht erreichbar → gestört,
  Unbekannt → unbekannt, Wartung → Wartung (die vorhandenen Zustände der Statusseite).
- Tagesbalken und Verfügbarkeit aus der Problem-Historie; laufende und geplante Wartungen sowie automatische
  Vorfälle erscheinen wie bei den Checks.
- Öffentlich nur Name (bzw. eigene Bezeichnung) und Zustand – keine Werte, IPs oder Dienstnamen, außer man nimmt
  einen einzelnen Dienst bewusst auf.
- Monitor64 aus: Einträge werden ausgeblendet, die Seite läuft weiter; im Editor ein Hinweis.
- Technisch: Eintrag mit eigener Quelle (`m64:host:<id>` bzw. `m64:svc:<id>/<key>` statt Check-Token), Monitor64
  liefert Zustand und Balken über eine kleine Schnittstelle an die Statusseite.

## Probleme und Verlauf

- Eigene Seite „Probleme“: offen / gelöst / alle, Zeitraum, Suche, CSV. Je Problem der Ablauf: aufgetreten (Wert und
  Schwelle), Verschärfung, an wen gemeldet, in Ruhezeit zurückgehalten, quittiert (wer, Kommentar), gelöst – automatisch
  (Wert wieder unter Schwelle), von Hand („als gelöst markiert“ von wem) oder in Wartung (nicht gemeldet).
- Quittieren mit optionalem Kommentar; stoppt Erinnerungen bis zur nächsten Änderung.
- **Wer war es (Pflicht):** Jede Aktion an einem Problem (quittieren, kommentieren, als gelöst markieren, Wartung
  eintragen/beenden) und jede Änderung an Hosts, Schwellen und Benachrichtigung speichert den Akteur: Benutzer (UID
  clusterweit, Name zum Zeitpunkt der Aktion, Anmeldeart lokal/SSO/LDAP), API-Key (Name) oder „System“ (automatisch
  gelöst, weil der Wert wieder passt), dazu Zeit und IP. Zusätzlich im vorhandenen Audit-Log des Kerns (`g.Audit`).
  Der Name bleibt lesbar, auch wenn der Benutzer später gelöscht wird. Filter „Person“ auf der Seite Probleme.
- Aufbewahrung wie die Stundenwerte.
- Übersicht: Probleme kompakt in halber Breite, daneben „Zuletzt“ (gelöst, Wartung begonnen …), Link zur Seite.

## Benachrichtigung (entschieden 2026-11-09)

Grundsatz: Wenige, eindeutige Meldungen. Lieber eine Meldung mit drei Punkten als drei Meldungen.

**Technik (vorhanden, wird genutzt)**
- Vorhandener Dispatcher (`internal/notify`) und dieselben Kanäle wie Healthchecks. Monitor64 sendet wie DynDNS und
  Proxmox selbst (`Local`), die Kanäle des ipv64-Accounts über die API; Ruhezeit, Sammelmeldung nach der Ruhezeit
  (bleibt über Neustarts erhalten), Bündeln, Kanal-Ratenlimit und Zustellprotokoll kommen von dort.
- Neue Arten: `monitor_problem` (Warnung, Kritisch, Unbekannt – Schwere in den Daten), `monitor_ok` (Entwarnung),
  `monitor_unreachable` / `monitor_reachable` (Host), `monitor_flapping`, `monitor_reminder`. Eigener Text wie
  `composeProxmox` (Platzhalter host, service, state, value, threshold, group, tags, url). Ein Trend ist keine eigene
  Art: Er macht den Dienst Warnung/Kritisch, die Meldung nennt den Grund („voll in ca. 3 Tagen“).

**Wann gemeldet wird**
- Jede Verschlechterung (OK → Warnung → Kritisch) und die Entwarnung zurück auf OK. Kritisch → Warnung wird als
  „besser, aber noch Warnung“ gemeldet (zählt als Entwarnung).
- Nicht gemeldet: Dienste „nur anzeigen“, Hosts/Dienste in Wartung, quittierte Probleme (bis sie sich
  verschlechtern), Unbekannt bei nicht erreichbarem Host (dann nur die Host-Meldung), neue Dienste (nur Hinweis in
  der Oberfläche).
- **Host nicht erreichbar:** eine Meldung; wieder erreichbar: eine Meldung mit allem, was danach noch nicht OK ist.
- **Ende der Wartung:** nur wenn dann noch etwas gestört ist, eine Meldung „nach der Wartung noch offen: …“.
- **Flattern:** mehr als 5 Wechsel in 30 Minuten → eine Meldung „flattert“, danach Ruhe, bis der Dienst 30 Minuten
  stabil ist; dann eine Meldung mit dem aktuellen Zustand.

**Wohin – Kanäle × Schwere**
- Eine Tabelle: je Kanal ankreuzen **Warnung** / **Kritisch** (nicht erreichbar zählt als Kritisch). Beispiel:
  E-Mail bekommt beides, Pushover nur Kritisch.
- **Entwarnung geht genau an die Kanäle, die das Problem bekommen haben** – kein eigener Schalter.
- Ohne Auswahl: die Standardkanäle von Node64, Warnung und Kritisch.

**Bündeln**
- Alles, was in einer Abfragerunde an einem Host passiert, ist **eine** Meldung („nas01: 1 Kritisch, 2 Warnung …“).
- Über Hosts hinweg: die vorhandene Sammelmeldung der Node64-Einstellungen (ab 3 Meldungen im Zeitfenster) – keine
  eigene Einstellung in Monitor64.

**Erinnerung**
- Solange offen und nicht quittiert: Kritisch **täglich**, Warnung **nie** (Standard); wählbar nie / alle 4 Std. /
  täglich. In der Ruhezeit keine Erinnerung – das Offene steht ohnehin in der Sammelmeldung.

**Ruhezeit**
- Aus den Node64-Einstellungen (wie Healthchecks). In der Ruhezeit nichts senden, am Ende **eine Sammelmeldung**
  je Kanal: was passiert ist und was davon noch offen ist (je Dienst der letzte Stand).
- „Kritisch auch in der Ruhezeit sofort melden“ (Standard aus; nicht erreichbar zählt als Kritisch).

**Abweichungen je Gruppe oder Tag** – wie bei den Schwellen **eine Liste, oben gewinnt**. Je Eintrag nur:
andere Kanäle (statt oder zusätzlich), „nur Kritisch“, „Kritisch auch in der Ruhezeit“, Erinnerung.

**Meldungstext**
- Titel: Zustand, Host, Dienst („🔴 Kritisch: nas01 · Platte 2“); Text: Wert, Schwelle, seit wann, Gruppe; Link
  auf den Dienst in der Node. Entwarnung mit Dauer („✅ OK nach 3 Std. 12 Min.“). Sprache je Kanal (vorhanden).
- Webhook/Home Assistant bekommt dieselben Felder als JSON.
- Knopf „Testmeldung senden“ mit einer Beispiel-Meldung.

**Bewusst nicht in v1:** Eskalationsstufen (nach X Min. anderer Kanal), eigene Textvorlagen, Bereitschaftspläne.
**Gar nicht geplant:** Tages-/Wochenbericht (entschieden 2026-11-09).

## Wartung

- Seite „Wartung“: einen oder mehrere Hosts, ganze Gruppen oder Tags; jetzt (für Dauer / bis beendet), geplant
  (von–bis) oder wiederkehrend (z. B. jeden Sonntag 02–04 Uhr); Grund und Person.
- In der Wartung wird weiter aufgezeichnet, aber nicht gemeldet; ist nach dem Ende noch etwas gestört, kommt die Meldung
  dann. Kennzeichnung auf Kachel und Host-Seite. Auch direkt vom Host aus („Wartung eintragen“).

## Prometheus

- Optional unter `/api/metrics` (gleicher Zugriff wie die übrigen Kennzahlen): `node64_monitor_value` (Wert je Dienst
  bzw. Messgröße, Labels host, group, service, unit, optional Tags), `node64_monitor_state` (0–3),
  `node64_monitor_host_up`.

## Oberfläche – leicht, übersichtlich, modern

- Grundsätze: Probleme zuerst; wenig Ebenen (Übersicht → Host → Dienst); Farbe nur für Zustände; selten Gebrauchtes
  unter „Erweitert“ zugeklappt; gute Standards, damit ein Host nach zwei Klicks läuft; Begriffe ohne Fachjargon;
  Dark Mode und Handy von Anfang an. Kein Regelwerk-Labyrinth wie CheckMK/Zabbix.
- Übersicht: Zähler (Kritisch/Warnung/Unbekannt/OK), Problemliste, darunter Host-Kacheln nach Gruppe mit Mini-Verläufen,
  Filter/Suche/Tags.
- Host-Seite: Kopf mit Zustand und Zugängen, Dienste mit Zustand, Wert, Mini-Verlauf; Diagramme 6 h / 24 h / 7 / 30
  Tage / 1 Jahr, Bereich aufziehen zum Zoomen, nach links scrollen.
- Host anlegen: Assistent – Art/Zugang wählen, Installationsbefehle zum Kopieren, Verbindung testen, Dienste erkennen.
- Regeln auf einer Seite mit den drei Stufen. Lokale API für alles, MCP lesend.
- Menü: Monitor64 mit Übersicht, Probleme (Zähler offener Probleme), Wartung, Schwellen, Benachrichtigung,
  Einstellungen; „Host hinzufügen“ als Knopf.
- Klickbarer Entwurf (Beispieldaten) im Scratchpad der Sitzung, Stand 2026-11-09; Dennis: Übersicht und Kacheln sehr gut,
  Zähler-Karten etwas groß (bleiben), Diagramme und Dienste-Ansicht gut.

## Export und Backup

Monitor64 komplett in Konfig-Export/-Import und Backup: Hosts, Zugänge (Geheimnisse wie die übrigen Module),
Gruppen, Tags, Regeln, ignorierte Dienste, Quittierungen, Wartungsfenster, Problem-Historie (alles in `node64.db`);
Verlauf (`monitor64.db`) im Backup „mit Statistik“.

## Sicherheit (entschieden 2026-11-09)

Grundsatz: Alles, was von Hosts kommt (Agent, SSH-Ausgabe, SNMP, Traps, APIs), ist **nicht vertrauenswürdig**.
Monitor64 liest nur, führt nichts aus und gibt keine Geheimnisse heraus.

**Geheimnisse**
- SSH-Passwörter, SNMP-Communities/v3-Schlüssel, API-Tokens und der private Schlüssel der Node liegen verschlüsselt in
  `internal/secrets`; nie im Log, nie in API-Antworten (nur „gesetzt“), nie über MCP. Im Konfig-Export wie die
  übrigen Geheimnisse (verschlüsselt). Der Node-Schlüssel ist im Backup, sonst müsste man nach einer
  Wiederherstellung alle Agents neu koppeln.
- Webhook-/Meldungs-Inhalte enthalten nie Geheimnisse.

**Agent**
- SSH-Server nur mit Schlüssel (kein Passwort, kein keyboard-interactive), nur Schlüssel aus `keys`; Fehlversuche
  je IP gebremst. Keine Shell, kein `exec` beliebiger Befehle, keine Weiterleitungen, keine Subsysteme – nur `info`,
  `collect`, `update`, `keys`. `keys` muss den Schlüssel der anfragenden Verbindung nicht enthalten, lehnt aber eine
  leere Liste ab (sonst sperrt man sich aus).
- Bremse vor der Anmeldung: Fehlversuche je exakter IP und je IPv6-/64; gesperrt wird eine unbekannte IP, deren
  Adresse oder /64 gesperrt ist – eine IP, die sich schon angemeldet hat, nie (Nachbar im selben /64 bzw. hinter
  derselben NAT-IP sperrt die Node nicht aus). Offene Handshakes: je IP, je /48 (4) und gesamt (8); bekannte IPs
  haben einen eigenen Topf (8 je IP, 32 gesamt). Abweisen wegen voller Plätze zählt nicht als Fehlversuch.
- `from=` in `authorized_keys`: IPv4/IPv6/CIDR, `::ffff:a.b.c.d/n` ab /96, Joker `*` nur für IPv4; Zone nur bei
  Link-Local (`fe80::1%eth0`), sonst wird die Zeile abgelehnt.
- **Eigene Skripte** (`local.d`): nur root-eigene Dateien, nicht für andere schreibbar (sonst ignoriert und als
  Warnung gemeldet), Zeitlimit und Größengrenze je Skript. Der Interpreter aus der `#!`-Zeile wird genauso geprüft
  (absoluter Pfad, root-eigen samt Ordnern, bis 4 Ebenen); `#!/usr/bin/env name` nur mit einem Namen ohne Optionen
  im festen PATH der Skripte.
- Update-Rückfall: Die neue Version zählt ihren Start, bevor sie irgendetwas prüft (scheitert sie an Flags oder
  Schlüsseln, startet beim nächsten Mal die alte); Versionen mit/ohne „v“ gelten als gleich.
- **Updates:** ed25519-Signatur über Datei, Version und Plattform; Release-Schlüssel im Agent eingebaut, privater
  Schlüssel nur im Release-Prozess (GitHub-Actions-Secret); **kein Downgrade** (Version muss steigen); bei Fehler
  bleibt die alte Datei. **Schlüssel (entschieden 2026-11-09):** derselbe Release-Schlüssel wie für die
  Selbst-Updates von Node64 (`internal/selfupdate/keys.go`, Secret `NODE64_SIGNING_KEY`); signiert wird mit
  `node64-release agent-sign` (Kopfzeile `<datei>.update.json`), das Verzeichnis `agents.json` mit
  `node64-release sign`. Die Node prüft beides, bevor sie eine Datei ablegt, ausliefert oder verteilt (Signatur des
  Verzeichnisses, SHA-256 und Signatur der Kopfzeile; nur HTTPS, Größengrenzen, keine Weiterleitung auf fremde
  Hosts, kein älteres Verzeichnis als das gespeicherte). Release-Ablauf: `MONITOR64-AGENT-RELEASE.md`.
- systemd-Härtung (`ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, `PrivateTmp`, nur nötige
  Schreibpfade). Windows: Dienst als LocalSystem (für Speicher-/Update-Abfragen nötig), Datei nur für Admins
  schreibbar.
- Installationsweg: Standard über HTTPS (GitHub, node64.de). Von der Node nur über HTTPS empfohlen; über HTTP mit
  deutlichem Hinweis. Download-Pfad `/monitor64/agent/` liefert nur signierte Dateien und das Skript, nur bei
  eingeschaltetem Modul, mit Ratenbegrenzung (je IP durch den Kern, dazu höchstens 8 Downloads gleichzeitig); nur
  feste Dateinamen aus dem signierten Verzeichnis. **Grenze:** Die Prüfsumme im Skript schützt nur vor defekten
  Downloads – über HTTP kann jemand zwischen Host und Node Skript, Datei und `SHA256SUMS` gemeinsam austauschen.
  Über HTTPS muss der Host dem Zertifikat der Node vertrauen (selbst signiert: Download bricht ab). Die Oberfläche
  sagt das beim Befehl.

**Node als Empfänger**
- Größengrenzen: Agent-Antwort max. 4 MB, SSH-Ausgabe max. 4 MB, Trap max. 64 KB; Zeitlimits je Abfrage.
- Hostschlüssel/Zertifikat fest (TOFU); Änderung = keine Abfrage mehr, Meldung „Schlüssel geändert“.
- SSH agentenlos: festes Skript, **keine Werte von Hosts oder Benutzern in Befehlen**; Gerätenamen für `smartctl`
  nur nach Prüfung (`^/dev/[a-z0-9/]+$`).
- **Traps** nur von IPs bekannter Hosts mit passender Community bzw. v3-Benutzer; Ratenbegrenzung je Absender;
  Liste unbekannter Absender begrenzt (z. B. 100 Einträge), nie automatisch angelegt.
- SNMP v2c: Hinweis „Community unverschlüsselt – v3 empfohlen“.
- Alle Texte von Hosts (Dienstnamen, Modelle, Meldungen) werden überall escaped: Oberfläche (`html/template`),
  Meldungen (Telegram-HTML, Markdown), **CSV-Export gegen Formel-Einschleusung** (`= + - @` am Anfang).
- Prometheus-Abfrage (Phase 3) und API-Ziele: nur http(s), Größengrenze, keine Weiterleitung auf andere Hosts.

**Zugriff**
- Wie im übrigen Node64: jeder angemeldete Benutzer und jeder API-Key hat volle Rechte (es gibt im Kern keine
  Rollen). Jede Änderung mit Akteur im Verlauf und im Audit-Log. MCP nur lesend und ohne Geheimnisse.
- Statusseiten zeigen nur Bezeichnung und Zustand; `/api/metrics` mit dem vorhandenen Schutz.

**Lieferkette**
- Neue Abhängigkeit nur `gosnmp` (Version fest, `govulncheck` und Trivy wie bisher). Der Lastgenerator ist nur mit
  Entwickler-Schalter aktiv, nie in der Oberfläche.

## Beim Durchsehen aufgefallen (entschieden 2026-11-09)

1. **Umzug aus Healthchecks:** Wer heute Proxmox-/Docker-Checks hat, verliert sie mit der Freigabe. Vorschlag:
   Hinweis in Healthchecks („nach Monitor64 umgezogen – Monitor64 einschalten“), Changelog und Doku; die alten
   Checks werden entfernt (kein Migrationsweg). **Entschieden:** so umsetzen.
2. **hubs und Portal:** Die Check-Typen Proxmox/Docker gibt es auch auf hubs und in ipv64.net (Check-Sync). Der
   Abbau muss dort mitgehen (Node, hubs, Portal gemeinsam) – Ausrollen nur auf Dennis' Ansage, Portal-Teil über
   `deploy/upload/`, Doku in `ipv64_docs`. **Entschieden:** wird auf hubs und Portal entfernt; vereinfachte
   Monitor64-Statistiken an ipv64.net vielleicht später, derzeit nicht geplant.
3. **Rollen:** Node64 kennt keine Rechte je Benutzer (z. B. „nur quittieren“). Für Monitor64 v1 nicht nötig; wäre
   eine Kern-Funktion für später. **Entschieden:** eigenes Thema im Kern (mehrere lokale Benutzer, SSO/Authentik,
   auch im Cluster); Monitor64 speichert Akteure schon mit clusterweiter UID.
4. **Host entfernen:** fragt, ob der Verlauf gelöscht oder behalten wird (Problem-Historie bleibt), mit Akteur.
5. **Adressen:** Hostname oder IP, IPv4 und IPv6; Hostnamen werden je Runde neu aufgelöst.
6. **Zeit:** Wartung, Ruhezeit und Diagramme in der Zeitzone der Node (Sommerzeit beachtet); Messzeit ist immer die
   Empfangszeit der Node, Zeitstempel des Agents nur für Raten.
7. **Texte zweisprachig** (de/en) von Anfang an; Doku auf node64.de über die Sitzung „Node64 Webseite“.

## Cluster (Konzept für Phase 4, entschieden 2026-11-09)

Passt zu den vorhandenen Cluster-Regeln (`docs/CLUSTER.md`): kein Anführer, keine Mehrheit, jüngere Änderung gewinnt,
Zuständigkeit mit Übernahme wie bei DynDNS. Bereich „Monitor64“ je Cluster schaltbar.

**Wer überwacht – eine zuständige Node je Host**
- Jeder Host hat **genau eine zuständige Node**, die ihn abfragt, speichert und meldet. Alle Nodes überwachen
  nicht doppelt (Messwerte wie CPU sind von jeder Node gleich; doppelte Last und doppelte Meldungen bringen nichts).
- Je Host: **bevorzugte Node** (Standard: die Node, auf der er angelegt wurde) und optional **Ersatz-Nodes**.
  Standard: keine Ersatz-Node – denn eine Node an einem anderen Standort erreicht das Heimnetz oft gar nicht und
  würde fälschlich „nicht erreichbar“ melden.
- Der Assistent hilft: „Verbindung testen“ prüft auch von den anderen Nodes aus und schlägt die erreichbaren als
  Ersatz vor („von node02 auch erreichbar ✓“).
- **Übernahme** wie bei DynDNS: zuständige Node 2 min nicht erreichbar (Karenz des Clusters), ausgesetzt oder
  Monitor64 dort aus → die nächste Ersatz-Node übernimmt. **Rückgabe** erst, wenn die bevorzugte Node 5 min stabil
  erreichbar ist (kein Hin und Her). Jede Übernahme steht im Verlauf des Hosts (Akteur „System“). Eigene Meldung
  gibt es nicht – „Cluster: Node … nicht erreichbar“ kommt schon vom Cluster.
- Offene Probleme, Quittierungen und „wohin gemeldet“ sind abgeglichen: die übernehmende Node meldet nichts doppelt,
  sondern macht mit dem Stand weiter.
- Ohne Ersatz-Node: Host wird auf den anderen Nodes als „zuständige Node nicht erreichbar“ (Unbekannt) angezeigt,
  nicht gemeldet.

**Was abgeglichen wird**
| Art | Was |
|---|---|
| gemeinsam | Hosts (mit bevorzugter/Ersatz-Node), Zugänge (Geheimnisse über die Cluster-Verbindung, auf der Empfängerin mit ihrem Schlüssel gespeichert – wie DynDNS-Tokens), übernommene/ignorierte Dienste, Schwellen und Abweichungen, Benachrichtigung, Wartung, Quittierungen und Kommentare, Gruppen/Tags, Einstellungen (außer unten) |
| gehört einer Node (kein Konflikt) | Problem-Ereignisse und Übernahmen (mit Node-Kennung), aktueller Zustand und letzter Wert ihrer Hosts |
| nur lokal | Messreihen (`monitor64.db`), Arbeiter-Zahl, Agent-Download-Zwischenspeicher, Trap-Port |

- **Verlauf wird nicht kopiert:** Diagramme fragen live bei den Nodes ab, die den Host im Zeitraum überwacht haben,
  und setzen die Stücke zusammen (Überschneidung: Daten der bevorzugten Node). Ist eine davon offline: Lücke mit
  Hinweis „Daten auf node01 (nicht erreichbar)“.
- **Aktueller Zustand** fremder Hosts kommt über die Cluster-Verbindung (nur Änderungen) – jede Node zeigt die
  gesamte Übersicht mit „überwacht von node01“.
- **Ein gemeinsamer Cluster-Schlüssel** (entschieden 2026-11-09): Mit dem Bereich Monitor64 haben alle Nodes
  denselben privaten Schlüssel (über die Cluster-Verbindung verschlüsselt verteilt, wie das ACME-Konto). Ein Agent
  wird einmal installiert und jede Node darf ihn abfragen. Hostschlüssel (TOFU) werden mit abgeglichen.
  - Beitritt einer Node mit eigenem Schlüssel: sie übernimmt den Cluster-Schlüssel, behält ihren alten nur, bis
    ihre Agents umgestellt sind. Umstellen macht die Node selbst: neue Agent-Anfrage `keys` (Schlüsselliste setzen,
    nur für eine bereits angemeldete Node), danach alter Schlüssel weg.
  - **Schlüssel wechseln** (Knopf; vorgeschlagen, wenn eine Node aus dem Cluster genommen wird): neuer Schlüssel an
    alle Agents per `keys`, dann der alte ungültig. Agents, die gerade nicht erreichbar sind, stehen als
    „Schlüssel veraltet“ in der Liste.
  - SSH ohne Agent: der öffentliche Cluster-Schlüssel steht einmal in `authorized_keys`; beim Wechsel zeigt die
    Node die neue Zeile (SSH-Hosts kann sie nicht selbst umstellen).
- **Traps** an eine nicht zuständige Node werden als Anstoß an die zuständige weitergereicht (Trap löst ohnehin
  nur eine Abfrage aus; ginge er verloren, fängt die nächste Runde es auf).

**Split-Brain (Teile des Clusters getrennt)** (entschieden 2026-11-09)

Ziel: Nach der Wiederverbindung läuft alles sauber zusammen; die Mehrheit arbeitet normal weiter, eine abgehängte
Node stimmt sich danach mit ihr ab.

- **Mehrheit entscheidet, wer übernimmt:** Eine Node darf einen fremden Host nur übernehmen, wenn sie mit mehr als
  der Hälfte aller Cluster-Mitglieder (sich eingeschlossen) verbunden ist. Bei 3 Nodes, C abgetrennt: A+B (2 von 3)
  übernehmen C's Hosts, sofern sie als Ersatz eingetragen sind; **C übernimmt nichts** und meldet nur noch für
  Hosts, für die es ohnehin zuständig ist. → keine doppelten Meldungen.
- **Eigene Hosts laufen immer weiter:** Die zuständige Node überwacht ihre Hosts auch ohne Mehrheit (C am anderen
  Standort sieht sein Heimnetz weiter). Hat die Mehrheit C's Hosts übernommen, misst C sie trotzdem weiter
  (Verlauf ohne Lücke), **meldet aber nicht mehr**, sobald es keine Mehrheit hat und eine Ersatz-Node existiert.
- **Zwei Nodes** haben bei einer Trennung keine Mehrheit. Damit Ausfallsicherheit trotzdem geht: Übernahme
  erlaubt, doppelte Meldungen im Split-Brain möglich (wie Healthchecks heute). Häufigster Fall ist ohnehin eine
  kurz abgeschaltete oder ausgefallene Node, keine echte Trennung.
- **Wiederverbindung:** Die abgehängte Node holt alles ab ihrem letzten Stand nach, die anderen ebenso von ihr.
  Problem-Ereignisse beider Seiten bleiben (gehören je einer Node, kein Konflikt); doppelt offene Probleme schließt
  die nicht zuständige Node mit „durch Übergabe beendet“. Zuständigkeit: der Eintrag der Mehrheit gilt, danach die
  Rückgabe-Regel (bevorzugte Node nach 5 min).
- **Konfiguration:** wie im übrigen Cluster je Eintrag die jüngere Änderung – im typischen Fall (eine Node kurz
  weg) haben die verbliebenen Nodes die jüngeren Stände, die zurückkehrende Node übernimmt sie (nichts geht verloren, was nur auf
  einer Seite geändert wurde). Nur wenn derselbe Eintrag auf beiden Seiten geändert wurde, gewinnt die jüngere als
  Ganzes. NTP auf allen Hosts nötig.

**Schon ab Phase 0/1 vorsehen** (damit Phase 4 kein Umbau wird)
- Jeder Eintrag (Host, Zugang, Regel, Wartung, Quittierung …) mit clusterweiter Kennung (`uid`), Änderungszeit und
  Löschvermerk – wie die vorhandenen Bereiche.
- Host mit Feld „zuständige Node“ (ohne Cluster: diese Node); Problem-Ereignisse mit Node-Kennung.
- Akteur mit clusterweiter Benutzer-UID (passt zu den späteren Benutzerrollen im Kern).
- Verlaufs-Abfrage über eine Schnittstelle, die später auch eine andere Node beantworten kann.

## Phasen (entschieden 2026-11-09)

Jede Phase endet mit demselben **Abschluss** – erst danach beginnt die nächste:
1. Tests grün auf der Box (`go test ./...` in golang:1.27), `gofmt`, `go vet`, `govulncheck`, `node --check` für JS,
   Render-Tests der Templates.
2. **Code-Review `/code-review max`** über alle Änderungen der Phase. Jeder bestätigte Fund wird behoben oder
   bewusst als offener Punkt in diesen Plan geschrieben – nichts bleibt stillschweigend liegen.
3. Bei Agent, Transport, Parsern, Traps, Download und Geheimnissen zusätzlich **`/security-review`**.
4. Test auf 8091 gegen echte Ziele (siehe Testziele), Ergebnis hier vermerkt.
5. Modul-Version, beide Changelogs, Commit (nur eigene Dateien, kein Push).

**Stand der Umsetzung**
- 2026-11-09: Phase 0 begonnen (Dennis: „starte die Phasen, gerne parallel“). Modul `internal/monitor64` (Schalter,
  Tabellen beim Einschalten, Planer, Lastgenerator, Statusseite), Protokoll `internal/m64proto`, Zuordnung
  Bericht → Dienste (`mapper.go`); parallel: Verlauf `tsdb`, Linux-Werte `m64linux`, Agent `m64agent` +
  `transport`, Bewertung `eval`. Auf node64-test als 1.5.0-dev.m64.1 mit 100 Schein-Hosts.
- 2026-11-09: Teilpakete fertig und getestet (`-race` auf der Box): `tsdb` (1,5 B/Punkt, >250.000 Punkte/s),
  `eval` (98 % Abdeckung), `m64linux` (Debian/BusyBox echt, Proxmox/Synology/Unraid/Pi nachgebaut), Agent
  (6 MB, 13 MB RAM) + `transport`. Kern verdrahtet: Abfragerunde, Erkennen, Bewerten, Verlauf, Probleme mit Akteur,
  Meldungen über den Dispatcher (neue Arten `monitor_*`, Texte de/en), Prometheus-Export, Konfig-Export/-Import.
  Ende-zu-Ende-Test (Agent im Prozess) grün. Agent auf agentbox installiert, Host „agentbox“ auf node64-test
  (1.5.0-dev.m64.2). Oberfläche/API und API-Sammler (Proxmox/PBS/Docker) laufen parallel.
- 2026-11-09: Phase 0/1 lokal committet (d9ddf033, kein Push), auf node64-test ausgerollt (Agent und SSH ohne Agent
  gegen agentbox, Docker-API). **Code-Review `/code-review max`** über den Commit: 11 Prüfer nach Bereichen, rund 85
  Kandidaten, die 15 schwersten bestätigt (u. a. Pool schloss Verbindungen nach 30 min, Zeitlimit griff bei totem Host
  nicht, Fehlalarm „verschwunden“ bei Teilausfall, Standardkanäle schluckten gewählte Kanäle, geteilte Zeiger in der
  Standard-Tabelle, Host-Schwelle für alle Messgrößen eines Dienstes, NaN von Hosts brach die Oberfläche). Behebung aller
  Funde parallel nach Bereichen; Liste: Review-Kandidaten im Scratchpad der Sitzung.
- 2026-11-09: Alle Funde behoben (06f42134, 2366c849); zweite Runde Prüfung („Sweep“) nach Bereichen fand weitere
  21 Stellen (Agent-Sperren bei NAT/IPv6, `from=`, Update-Rückfall, `#!`-Interpreter, gewollt fehlende Messwerte,
  Erinnerung nach der Ruhezeit, doppelte Meldungen, ZFS-Gerätefehler, Proxmox-Cluster-Zuständigkeit u. a.) – behoben
  in 4b5dbd0e und dem folgenden Agent-Commit, Tests mit `-race` auf der Box grün.
- 2026-11-09: Phasen 2–4 gebaut (Windows-/FreeBSD-Agent, SNMP+Traps, NUT, TrueNAS, Unraid, Redfish, Prometheus,
  Statusseiten, Push-Betrieb, Cluster samt Oberfläche), `/code-review max` über 16ce32ac..c751761a (11 Prüfer, rund 85
  Kandidaten, unabhängig geprüft) – alle bestätigten Funde behoben (8fde73c0). **Echter Test mit drei Nodes** auf
  agentbox (8091/8092/8093, gekoppelt): Abgleich, gemeinsamer Schlüssel mit Umstellung der Agents, Übernahme nach
  2 min 9 s, Rückgabe nach 5 min, Problem-Übergang ohne Doppel, Split-Brain (abgetrennte Node ohne Mehrheit, Mehrheit
  übernimmt nach 2 min 11 s), Wiederverbindung ohne doppelte Probleme. Funde daraus behoben: Zeiten ohne
  Millisekunden, Push-Fehlalarm nach Neustart, fehlende Entwarnung im Ablauf, abgetrennte Node meldete vor Klärung
  der Mehrheit, Node-Name im Verlauf, Hinweis bei lokalen Zugängen. Nicht echt getestet (nur Tests im Prozess): Trap
  an nicht zuständige Node, „Schlüssel wechseln“.
- 2026-11-10 (Runde 3): Agent-Verteilung über die Node (Menüpunkt „Agent“, signiertes Verzeichnis `agents.json`,
  Download ohne Anmeldung, automatische Updates; Ablauf in `docs/MONITOR64-AGENT-RELEASE.md`), Installation unter
  FreeBSD/OPNsense/pfSense/TrueNAS CORE (echt getestet auf FreeBSD 14.5 in einer VM), Dienstnamen und Texte
  übersetzbar (de/en, `model.T`), bekannte Lücken im Cluster und auf den Statusseiten geschlossen. Klicktest in
  Chrome auf 8091 (Funde F1–F16 behoben), Fund der Sicherheitsprüfung behoben (SSH-Passwort erst nach bestätigtem
  Hostschlüssel). **Lasttest** auf agentbox: 100 echte Agents (800 Dienste) kosten rund 26 MB RAM und unter 0,5 %
  eines Kerns; mit zusätzlich 1.000 Schein-Hosts 90–112 MB RAM (stabil über 20 min) und rund 1 % eines Kerns.
  **Windows-Agent echt** auf Windows 11 im Vordergrund (Push-Betrieb): Werte stimmen; Funde behoben (nie gestartete
  Automatik-Dienste, „Updates“ erst nach der stündlichen Erkennung).
- 2026-11-10 (Nachmittag): **Windows-Agent als Dienst echt getestet** (Windows 11, `install.ps1` von einer Testnode
  mit Testschlüssel, Push-Betrieb): Installation, Abfrage mit Systemrechten (Plattentemperatur, Verschleiß),
  automatisches Update samt Signaturprüfung, Gegenprobe mit fremder Signatur (abgelehnt). Funde behoben: leerer
  Datenordner eines anderen Besitzers blockierte die Installation. Neu auf Wunsch: **Symbol im Infobereich der
  Taskleiste** (der Dienst startet es je angemeldeter Sitzung; zeigt läuft/Version/letzte Abfrage/Update verfügbar –
  die Node nennt dem Agent die verfügbare Version mit `info latest=<version>`), echt getestet inklusive Update.
  Englische Oberfläche durchgeklickt, Funde behoben.
- Offene Punkte: OPNsense, pfSense und TrueNAS CORE nur nachgestellt (Test durch die Community); Ruhezeit-Prüfung für Erinnerungen (Dispatcher
  exportieren); vor der Umstellung auf übersetzbare Namen erkannte Dienste behalten ihren deutschen Namen (der
  gespeicherte Name geht vor); Synology md0/md1 mit leeren Plätzen erscheint als degraded; Aufbewahrung zur Laufzeit
  ändern (`tsdb.SetRetention`). Rollout: Node vor den Agents aktualisieren (neue Agents senden Hinweis-Codes, die
  eine ältere Node roh zeigt).

**Phase 0 – Gerüst**
Modul `internal/monitor64` mit Schalter `NODE64_MONITOR64`, aus = nichts läuft; Tabellen beim ersten Einschalten;
Speicher für Messreihen (Blöcke, Verdichtung, Aufräumen) mit Tests; Planer und Arbeiter-Pool; Lastgenerator.
Ziel: Messwerte von Schein-Hosts landen im Verlauf, Zielwerte für 100 und 1.000 Hosts gemessen.
Datenmodell schon clusterfähig (siehe „Cluster – schon ab Phase 0/1 vorsehen“).

**Phase 1 – Kern und Linux/Proxmox**
Hosts, Zugänge, Dienste erkennen (übernehmen/ignorieren, verschwunden), Regeln mit drei Stufen, Zustand und
Problem-Historie mit Akteur, Benachrichtigung, Wartung, Übersicht/Host/Dienst/Probleme/Schwellen/Einstellungen,
Export/Backup, Prometheus-Export, lokale API und MCP lesend. Zugänge: **Monitor64-Agent Linux** (inkl. SMART,
Netz, Bonding, Updates, eigene Skripte, automatische Updates), **SSH agentenlos**, **Proxmox VE / PBS / Docker per
API** (inkl. Cluster-Erkennung, Gäste als Dienste, „als eigenen Host“).

**Phase 2 – Windows, SNMP, Statusseiten**
**Monitor64-Agent Windows**, **SNMP v1/v2c/v3** mit Profilen und eigener OID, **Traps**, NUT/USV,
Monitor64-Einträge auf den **Statusseiten**.

**Freigabe (nach Phase 2)** – nur auf Dennis' Ansage:
- Gesamt-Review des Moduls (`/code-review max` und `/security-review` über alles), offene Punkte leer oder bewusst
  verschoben.
- Proxmox/Docker aus Healthchecks abbauen (Node, hubs, Portal; siehe „Beim Durchsehen aufgefallen“).
- Agent-Release signiert (GitHub, node64.de), Schalter entfernen, Doku DE/EN (node64.de, `ipv64_docs` für den
  Portal-Teil), öffentlicher Changelog, parallele Sitzungen vorher informieren.

**Phase 3 – Mehr Quellen**
TrueNAS, Unraid, Redfish/IPMI, Prometheus abfragen, Push-Betrieb des Agents für Hosts hinter NAT/VPS,
FreeBSD-Agent (OPNsense).

**Phase 4 – Cluster**
Nach dem Konzept unter „Cluster“: zuständige Node je Host mit Ersatz, Abgleich, Split-Brain, Statusseiten im
Cluster. Abschluss wie jede Phase (Review max, Security-Review, Test mit zwei Nodes inkl. Trennung).

## Veröffentlichung

- Bis zur Freigabe: Schalter `NODE64_MONITOR64=1` nur auf 8091, Agent nicht verlinkt.
- Freigabe nach Phase 2 – Schritte unter „Phasen“ (Gesamt-Review, Abbau in Healthchecks, Agent-Release, Doku).

## Testziele

Linux-Host, Windows-VM, Proxmox (von Dennis), SNMP-Gerät (organisiert Dennis), danach Community-Test.
