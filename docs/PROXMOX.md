# Proxmox VE überwachen (Healthchecks → Proxmox VE)

Node64 überwacht Proxmox-VE-Systeme – einen einzelnen Node oder einen ganzen Cluster – **nur lesend** über die
Proxmox-API: Nodes, VMs (QEMU) und Container (LXC), Abstürze, Neustarts und Schwellen für CPU, RAM und Disk. Node64
startet, stoppt oder ändert in Proxmox nichts. Die Seite liegt unter **Healthchecks → Proxmox VE**
(`/healthchecks/proxmox`) und läuft nur, solange das Modul Healthchecks eingeschaltet ist. Plan und Entscheidungen:
[PLAN-NODE64-PROXMOX.md](PLAN-NODE64-PROXMOX.md).

Messdaten (Verlauf, Graphen, Prometheus) bleiben **auf der Node**. An ipv64 geht nur der Zustand der Gäste, die du
„als Check“ führst (normale Healthchecks-Checks).

## Einrichtung

### 1. Leser-Token in Proxmox anlegen

Auf einem Node als root (Shell, z. B. Datacenter → Node → Shell):

```bash
pveum user add node64@pve
pveum aclmod / -user node64@pve -role PVEAuditor
pveum user token add node64@pve monitor --privsep 0
```

Proxmox zeigt das **Secret nur einmal** an – gleich kopieren. Die Token-ID ist dann `node64@pve!monitor`.

Mit **Privilege Separation** (`--privsep 1`, Standard in der Oberfläche) hat das Token keine eigenen Rechte, auch
wenn der Benutzer welche hat. Dann braucht das Token selbst die Rolle:

```bash
pveum user token add node64@pve monitor --privsep 1
pveum aclmod / -token 'node64@pve!monitor' -role PVEAuditor
```

(In neueren Versionen gleichwertig: `pveum acl modify / --tokens 'node64@pve!monitor' --roles PVEAuditor`.)
`PVEAuditor` auf `/` reicht für alles, was Node64 liest (cluster/resources, cluster/status, qmpstatus,
Zertifikate der Nodes). Sieht das Token keine Gäste, warnt „Verbindung testen“.

### 2. System hinzufügen (Assistent)

1. **Adresse(n):** `https://<node>:8006` – eine reicht. Im Cluster lernt Node64 die anderen Nodes aus
   `cluster/status` und weicht bei Ausfall auf sie aus; weitere Adressen (eine je Zeile) sind feste Ausweichziele.
2. **Token-ID und Secret** eintragen. Das Secret wird mit dem Schlüssel der Node (`secret.key`) verschlüsselt
   gespeichert und nie wieder angezeigt; beim Bearbeiten bleibt ein leeres Feld beim gespeicherten Secret.
3. **Verbindung testen:** zeigt Version, Cluster, Nodes, Anzahl Gäste und den **SHA-256-Fingerabdruck** des
   Zertifikats. Bei selbstsignierten Zertifikaten (Proxmox-Standard) mit dem Fingerabdruck in Proxmox vergleichen
   (Node → System → Zertifikate) und **„Fingerabdruck stimmt – festpinnen“** bestätigen. Bei Zertifikaten einer
   bekannten CA (z. B. Let's Encrypt über ACME) ist Pinning optional. Eine „Prüfung aus“ gibt es nicht.
4. **Intervall** (15–300 s, Standard 30 s) für `cluster/resources`; `cluster/status` läuft jede Minute, der
   `qmpstatus` laufender VMs alle 2 Minuten.

Ändert sich das Zertifikat (neu ausgestellt), meldet die Abfrage `certificate mismatch` – dann im Bearbeiten
„Verbindung testen“ und den neuen Fingerabdruck bestätigen.

## Übersicht und Seiten

- **Proxmox VE:** alle Systeme mit Zustand (in Ordnung, Hinweis, nicht erreichbar, Fehler, aus), Version,
  Cluster/Quorum, Nodes online, Gäste laufend/gestört, letzte Abfrage; Bearbeiten, Ein-/Ausschalten, Löschen.
- **System:** Nodes und Gäste als Tabelle mit Name, ID, Typ (VM/Container), Node, Zustand (inkl. Backup, Lock,
  Absturz mit qmpstatus), CPU, RAM, Disk, Netz, Laufzeit, CPU-Verlauf der letzten Stunde und Schalter „als Check“.
  Filter nach Zustand (u. a. „gestört“), Node, Typ und Suche (Name, ID, Tags). Darunter die Regeln des Systems.
- **Gast bzw. Node**: aktuelle Werte, Graphen für 1 h, 24 h, 7 Tage und 30 Tage (CPU mit Spitze, RAM und
  Disk, Netz rein/raus, Disk lesen/schreiben) und die Regeln dieser Ebene.

Zustände: läuft · Backup (läuft, Hinweis) · gesperrt (Migration, Snapshot …, läuft) · angehalten · suspendiert ·
gestoppt · **abgestürzt** (qmpstatus `internal-error`, `guest-panicked`, `io-error`) · unbekannt (Node offline).
Vorlagen und Gäste mit dem Proxmox-Tag `nomonitor` werden nicht überwacht.

Fehlt der Schlüssel für das Secret (anderer `secret.key`, Import ohne Passwort), zeigt das System **„Fehler: token
secret cannot be decrypted …“** bzw. „token secret missing“ und wird nicht abgefragt – Secret neu eintragen.

## Benachrichtigung und Regeln

Regeln gelten mit Vererbung **System → Node → Gast** (unten überschreibt oben). Jede Zeile zeigt, was ohne eigenen
Wert gilt und woher es kommt („Standard“, „vom System geerbt“, „vom Node geerbt“).

| Regel | Standard | Bedeutung |
|---|---|---|
| Absturz | an | qmpstatus internal-error/guest-panicked/io-error – sofort, ohne Verzögerung |
| Gestoppt | an | nur wenn „erwartet läuft“: automatisch, sobald der Gast einmal lief; je Gast fest einstellbar |
| Angehalten / Suspendiert | an | qmpstatus paused bzw. Lock/qmpstatus suspended |
| Node offline | an | Node laut cluster/status offline; seine Gäste melden dann nichts einzeln |
| System nicht erreichbar | an | API antwortet nicht (alle Adressen) |
| Neustart | an | Laufzeit springt zurück, obwohl der Gast weiterläuft (Hinweis) |
| CPU / RAM / Disk über | 90 % 10 min / 95 % 10 min / 90 % | mindestens so lange über der Grenze; 0 % = aus. Disk nur bei Containern bzw. VMs mit Gast-Agent |
| Verzögerung | 2 Abfragen | erst melden, wenn der Zustand so viele Abfragen anhält (Entwarnung ebenso) |

„Stumm“ schaltet Meldungen eines Systems, Nodes oder Gasts ab. Ruhezeiten gelten für alle Proxmox-Meldungen, auch für Abstürze. In einem Wartungsfenster für alle Checks kommen keine Proxmox-Meldungen; ein Fenster für bestimmte Checks gilt für Gäste, die als Check geführt werden. Versand über die vorhandenen Kanäle und Ruhezeiten
der Benachrichtigungen mit eigenen Arten:

| Art | Wann |
|---|---|
| `proxmox_down` | System nicht erreichbar, Node offline, Gast gestoppt/angehalten/suspendiert/abgestürzt |
| `proxmox_up` | Entwarnung (mit Dauer) |
| `proxmox_threshold` / `proxmox_threshold_ok` | Schwelle überschritten / wieder darunter |
| `proxmox_restarted` | Neustart erkannt |

Gemeldete Störungen überstehen einen Neustart der Node: Nach dem Start kommt keine zweite Meldung, nur die
Entwarnung, sobald es wieder passt.

## Als Check führen

Der Schalter „als Check“ (je Gast und Node) legt einen normalen Healthchecks-Check vom Typ **`proxmox`** an
(Name „System – Gast“, Gruppe „Proxmox VE“, Intervall wie das System). Damit greifen Statusseiten, Uptime-Balken,
der Sync mit ipv64 und die Einstellungen des Checks (Kanäle, Erinnerungen, kritisch). Der Check fragt Proxmox nicht
selbst, sondern liest den letzten Stand der Abfrage:

- **up:** läuft, Backup, gesperrt (Gast) bzw. online (Node)
- **down:** `pve_stopped`, `pve_paused`, `pve_suspended`, `pve_crashed`, `pve_offline`, `pve_unknown`,
  `pve_missing` (Gast nicht mehr vorhanden), `pve_unreachable` (System nicht erreichbar, aus oder Stand zu alt)

Zustandsmeldungen (Ausfall/Entwarnung) kommen dann **nur über den Check**, Neustart und Schwellen weiter über
Proxmox VE. Wie Docker-Checks laufen `proxmox`-Checks nur lokal auf der Node, die das System abfragt (nicht online,
nicht auf andere Nodes verschiebbar). Ausschalten des Systems pausiert seine Checks, Löschen entfernt sie.

## Verlauf

1-Minuten-Werte 48 Stunden, 5-Minuten-Werte so lange wie „Einzelmessungen aufbewahren“ (`hc.raw_days`),
Stundenwerte so lange wie „Stundenwerte aufbewahren“ (`hc.hourly_days`, 0 = unbegrenzt) – dieselben lokalen
Einstellungen wie die Healthchecks.

## API

Unter `/api/healthchecks/proxmox` (Anmeldung wie die übrige API, siehe `/api/docs`):

| Methode | Pfad | |
|---|---|---|
| GET / POST | `/systems` | Liste (mit Zustand, ohne Secret) / anlegen |
| GET / PUT / DELETE | `/systems/{id}` | lesen / Teiländerung (leeres `secret` behält es) / löschen |
| POST | `/probe` | Verbindung testen (Fingerabdruck, Version, Nodes, Gäste) |
| GET | `/systems/{id}/resources` | Nodes und Gäste der letzten Abfrage |
| GET | `/systems/{id}/series?key=qemu/101&range=24h` | Verlauf (`1h`, `24h`, `7d`, `30d`) |
| GET / PUT / DELETE | `/systems/{id}/settings[?key=…]` | Einstellungen und wirksame Regeln / Ebene setzen (`as_check` legt den Check an) / zurücksetzen |

## Prometheus

| Metrik | Bedeutung |
|---|---|
| `node64_pve_up{system}` | API erreichbar (1/0) |
| `node64_pve_error{system}`, `node64_pve_poll_failures_total{system}` | letzte Abfrage fehlgeschlagen bzw. nicht abfragbar; Fehler seit dem Start |
| `node64_pve_enabled`, `node64_pve_last_poll_seconds`, `node64_pve_quorate` | eingeschaltet, Zeit der letzten Abfrage, Quorum |
| `node64_pve_guests_running`, `node64_pve_guests_bad` | Anzahl je System |
| `node64_pve_node_up{system,node}`, `node64_pve_node_{cpu,memory,disk}_ratio`, `node64_pve_node_uptime_seconds` | je Node |
| `node64_pve_guest_state{system,node,type,vmid,name,state}` | immer 1, Zustand im Label |
| `node64_pve_guest_up`, `node64_pve_guest_{cpu,memory,disk}_ratio`, `node64_pve_guest_uptime_seconds` `{system,type,vmid}` | je Gast (Anteile 0..1) |

Gäste insgesamt höchstens 1000 (Labels begrenzt), Namen höchstens 64 Zeichen, Vorlagen nicht.

## Export und Import

Der Export der Konfiguration enthält die Systeme mit Einstellungen und Regeln. Das Token-Secret ist nur beim Export
**mit Passwort** dabei (verschlüsselt). Ohne Passwort wird ein System beim Import abgeschaltet angelegt und zeigt
„Secret fehlt“, bis du es einträgst. Checks „als Check“ werden auf das System der neuen Node umgestellt.
