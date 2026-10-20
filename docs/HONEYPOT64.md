# Honeypot64 ohne Oberfläche (`NODE64_MODE=honeypot`)

Node64 kann als reiner Sensor laufen: nur die Fallen-Dienste von Honeypot64, **keine Weboberfläche, keine anderen
Module, kein Anmelden**. So sind 22, 80 und 443 frei für die Fallen, und es gibt keine Admin-Seite als
Angriffsfläche. Eingestellt wird alles über Umgebungsvariablen; den Zustand zeigen das Log, eine kleine Info-Seite
und Prometheus auf einem eigenen Port. Plan und Hintergrund: [PLAN-NODE64-HONEYPOT64.md](PLAN-NODE64-HONEYPOT64.md).

Die Fallen sind Low Interaction: Logins werden angenommen und immer abgelehnt, es gibt keine Shell, es wird nichts
ausgeführt oder geladen, und der Sensor baut keine ausgehenden Verbindungen auf.

## Start

```bash
docker run -d --name honeypot64 --network host --restart unless-stopped \
  -e NODE64_MODE=honeypot -e NODE64_HONEYPOT_PROFILE=standard \
  -e NODE64_IPV64_KEY=<api-key> \
  -v honeypot64:/data ghcr.io/ipv64net/node64
```

Ohne `NODE64_IPV64_KEY` bleiben alle Ereignisse lokal (siehe [Meldung an ipv64](#meldung-an-ipv64)).

Das Image gibt es für `linux/amd64`, `linux/arm64` und `linux/arm/v7` (ältere Raspberry Pi, viele NAS).

**Host-Netzwerk empfohlen:** Nur so sieht der Sensor die echten Quell-Adressen. Mit Port-Weiterleitung (`-p`) im
Bridge-Netz sehen manche Docker-Versionen statt der Angreifer die Adresse des Docker-Gateways.

## Umgebungsvariablen

| Variable | Standard | Bedeutung |
|---|---|---|
| `NODE64_MODE` | – | `honeypot` schaltet den Modus ohne Oberfläche ein; andere Werte sind ein Fehler |
| `NODE64_HONEYPOT_PROFILE` | `standard` | `minimal`, `standard` oder `full` (Tabelle unten) |
| `NODE64_HONEYPOT_SERVICES` | – | eigene Dienste statt des Profils, z. B. `ssh:22,ssh:2222,http:80,https:443,tcp:3389`; Dienste `ssh`, `telnet`, `http`, `https`, `tcp`; bei `http`/`https` optional ein Köder als dritter Teil (`http:80:wp-login`, möglich: `generic`, `wp-login`, `phpmyadmin`, `admin`). Unbekannte Dienste, doppelte Ports oder ungültige Ports verhindern den Start |
| `NODE64_HONEYPOT_SCAN` | `1` | Port-Scan-Erkennung (`1`/`0`) |
| `NODE64_HONEYPOT_RETENTION` | `7d` | lokale Aufbewahrung, z. B. `3d`, `48h` (1 Stunde bis 365 Tage); zusätzlich gilt eine feste Obergrenze von 200 000 Ereignissen |
| `NODE64_HONEYPOT_INFO_PORT` | `9064` | Port der Info-Seite, `0` = aus; darf kein Fallen-Port sein |
| `NODE64_HONEYPOT_INFO_TOKEN` | – | erlaubt die Info-Seite auch von außerhalb privater Netze (mindestens 16 Zeichen) |
| `NODE64_IPV64_KEY` | – | API-Key des ipv64-Accounts (16 bis 64 Buchstaben und Ziffern). Gesetzt = Meldung an ipv64 alle 10 Minuten; ein ungültiges Format verhindert den Start |
| `NODE64_HONEYPOT_REPORT` | `1` | `0` schaltet die Meldung an ipv64 trotz Key ab; ohne Key ist sie immer aus |
| `NODE64_DATA_DIR` | `/data` | Datenverzeichnis: Datenbank `node64.db`, Sensor-Dateien (SSH-Host-Schlüssel, TLS-Zertifikat, Sensor-Kennung `sensor_id`, Stand der Meldung `report_state.json`) unter `honeypot/` |
| `NODE64_BIND_ADDR` | – | Adresse der Info-Seite (leer = alle) |
| `NODE64_LOG_LEVEL`, `NODE64_LOG_FORMAT` | `info`, `text` | wie im normalen Betrieb |

Die übrigen Variablen der Node (Weboberfläche, Admin, TLS) werden in diesem Modus nicht benutzt.

## Ports

| Profil | Dienste |
|---|---|
| `minimal` | SSH 22, HTTP 80 (für kleine Geräte) |
| `standard` | SSH 22 und 2222, Telnet 23, HTTP 80 und 8080, HTTPS 443, TCP 3389 (RDP) und 5900 (VNC) |
| `full` | wie `standard`, dazu Telnet 2323, HTTPS 8443 und TCP 21, 25, 445, 1433, 1883, 2375, 3306, 5432, 6379, 9200, 27017 |

Dazu die Info-Seite auf `NODE64_HONEYPOT_INFO_PORT` (Standard 9064).

**Ports unter 1024** (22, 23, 80, 443 …) öffnet Node64 ohne Root über die Fähigkeit `cap_net_bind_service`, die das
Image dem Binary als „erlaubt“ mitgibt (`+p`) und die Node64 beim Start selbst einschaltet. Nimmt der Container die
Fähigkeit weg (`--cap-drop`, manche Podman-Einstellungen), bleiben diese Ports zu, die übrigen laufen weiter.

**Belegte Ports:** Läuft auf dem Rechner schon ein echter Dienst (z. B. der eigene SSH-Server auf 22), kann die Falle
den Port nicht öffnen. Das ist kein Fehler für die anderen Dienste. Entweder den echten Dienst auf einen anderen Port
legen oder den Port mit `NODE64_HONEYPOT_SERVICES` weglassen.

Beim Start steht im Log für jeden Dienst, ob er offen ist und, wenn nicht, warum (z. B. „address already in use“,
„permission denied“).

### Portfreigabe

Damit Angreifer die Fallen erreichen, müssen die Ports aus dem Internet ankommen: am Router die gewünschten Ports
(z. B. 22, 23, 80, 443, 2222, 3389) an den Rechner mit dem Sensor weiterleiten, am besten an ein eigenes Gerät oder
eine eigene VM in einem abgetrennten Netz (DMZ/VLAN). **Den Port der Info-Seite (9064) nicht freigeben.** Ein
Sensor nur im Heimnetz sieht fast nichts.

## Info-Seite, `/metrics`, `/health`

Auf dem Info-Port (getrennt von den Fallen) antwortet ein kleiner Server, nur `GET` und `HEAD`:

| Pfad | Inhalt |
|---|---|
| `/` | Info-Seite, nur lesend (kein Formular, kein JavaScript, hell/dunkel nach System, Deutsch oder Englisch nach Browser): Zustand der Dienste, Treffer 24 h und 7 Tage, Quell-IPs, Login-Versuche, Top-IPs, Arten, Ports, Zugangsdaten, Pfade, User-Agents, Meldung an ipv64 (an/aus, letzte Meldung, nächster Versuch, gemeldete Quell-IPs, letzter Fehler, Sensor-Kennung), Version, Laufzeit. Aktualisiert sich jede Minute |
| `/metrics` | Prometheus-Textformat |
| `/health` | `200 ok`, wenn die Datenbank antwortet und mindestens ein Fallen-Dienst offen ist, sonst `503` |

**Zugriff:** ohne Token nur aus privaten Netzen (10/8, 172.16/12, 192.168/16, fc00::/7), CGNAT (100.64/10, z. B.
Tailscale), Loopback und Link-Local. Maßgeblich ist allein die Absender-Adresse der Verbindung; Kopfzeilen wie
`X-Forwarded-For` werden nicht beachtet. Mit `NODE64_HONEYPOT_INFO_TOKEN` ist sie zusätzlich von überall erreichbar,
mit `?token=<Token>` oder `Authorization: Bearer <Token>`; alles andere bekommt `403`. Die Seite schickt strenge
Kopfzeilen (Content-Security-Policy ohne Skripte, `nosniff`, `no-referrer`, `X-Frame-Options: DENY`, `no-store`).

Die Inhalte der Seite stammen von Angreifern (Benutzernamen, Pfade, User-Agents). Sie werden maskiert und gekürzt
angezeigt; trotzdem gilt: nichts davon anklicken oder kopieren und ausführen.

### Prometheus

```yaml
scrape_configs:
  - job_name: honeypot64
    static_configs:
      - targets: ["192.168.1.20:9064"]
    # von außerhalb privater Netze: authorization: { credentials: "<Token>" }
```

Kennzahlen (dieselben wie beim Modul unter `/api/metrics`, Zähler seit dem Start):
`node64_honeypot_connections_total{service,port}`, `node64_honeypot_logins_total{service}`,
`node64_honeypot_events_total{kind,source}`, `node64_honeypot_unique_sources` (24 h),
`node64_honeypot_services`, `node64_honeypot_services_listening`, `node64_honeypot_listen_errors{port}`,
`node64_honeypot_buffer_events`, `node64_honeypot_dropped_total`; dazu im Modus ohne Oberfläche
`node64_honeypot_up`, `node64_honeypot_info{version,profile}`, `node64_honeypot_uptime_seconds`. Zur Meldung an
ipv64 (Modul und Modus ohne Oberfläche): `node64_honeypot_report_last_success_timestamp` (Unix-Zeit, 0 = noch
keine), `node64_honeypot_report_errors_total`, `node64_honeypot_report_sources_total`. Beispiel-Alarm:
`time() - node64_honeypot_report_last_success_timestamp > 3600`. Die übrigen Kennzahlen der Node siehe
[PROMETHEUS.md](PROMETHEUS.md).

### Docker-Healthcheck

Der `HEALTHCHECK` des Images (`/node64 healthcheck`) fragt in diesem Modus `/health` auf dem Info-Port über
`127.0.0.1`/`::1` (bzw. `NODE64_BIND_ADDR`) ab, mit Token, falls gesetzt. Mit `NODE64_HONEYPOT_INFO_PORT=0` gibt es
keine Prüfung über das Netz; der Container gilt dann als gesund, solange der Prozess läuft.

## Meldung an ipv64

Mit `NODE64_IPV64_KEY` meldet der Sensor alle 10 Minuten (mit kleinem Zufallsversatz) an ipv64
(`POST /api/v2/honeypot/reports`, Format `schema: 1`, gzip). Beim Modul mit Oberfläche ist es der Schalter
„An ipv64 melden“ unter Honeypot64 → Einstellungen (Standard aus, braucht den zentralen API-Key der Node).

**Übertragen werden:** je Quell-IP Art, Dienst, Port, Anzahl, erster und letzter Zeitpunkt; dazu Proben mit Anzahl:
Zugangsdaten aus dem Honeypot (Benutzername und Passwort im Klartext, nur SSH, Telnet, HTTP/HTTPS), Pfade,
User-Agents und der Anfang von Payloads (SHA-256 und höchstens 256 Bytes). Außerdem eine feste Sensor-Kennung
(UUID, `honeypot/sensor_id`), Version, Profil und Modus. Die Daten fließen in die v64 Blocklist ein, sobald die
Auswertung bei ipv64 läuft.

**Nie übertragen:** die eigene öffentliche IP (ipv64 kennt sie aus der Verbindung) und Quellen aus privaten oder
reservierten Netzen – RFC 1918, CGNAT (100.64/10), Loopback, Link-Local, ULA (fc00::/7), Doku-Netze (192.0.2/24,
198.51.100/24, 203.0.113/24, 2001:db8::/32) u. a. So landen lokale Tests und interne Scanner nicht bei ipv64; lokal
bleiben sie sichtbar.

**Ablauf:** Gemeldet wird jeweils der Zeitraum seit der letzten erfolgreichen Meldung (`honeypot/report_state.json`),
höchstens 7 Tage zurück und in Stücken zu höchstens einer Stunde (beim Nachholen von mehr als einem Tag zu sechs
Stunden). War ipv64 nicht erreichbar, holt der Sensor danach nach; ipv64 nimmt je Sensor höchstens eine Meldung in
2 Minuten an, entsprechend verteilt sich das Nachholen. Antworten: `202`/`200` (schon bekannt) = Erfolg; `400`/`413`/`422` = Meldung ungültig, wird verworfen und
gezählt; `401`/`403`/`429`/`5xx` oder Netzfehler = später erneut (Backoff ab 1 Minute bis 1 Stunde, `Retry-After`
wird beachtet). Einzelne Quellen, die ipv64 nicht übernimmt (z. B. eigene oder nicht öffentliche IPs, außerhalb des
Zeitraums), stehen mit Grund auf der Info-Seite bzw. in der Oberfläche („zuletzt abgelehnt“); die Meldung selbst gilt
trotzdem als angenommen. Gibt es im Zeitraum keine Ereignisse, geht trotzdem eine kurze Meldung ohne Quellen – so kann ipv64
aktive Sensoren zählen. Wird die Meldung eingeschaltet (auch nach `NODE64_HONEYPOT_REPORT=0`), beginnt der Zeitraum
neu; nichts aus der Zeit ohne Meldung wird nachgeholt.

## Beenden

`docker stop` (SIGTERM) schließt erst die Info-Seite, dann alle Fallen, und schreibt die noch gepufferten
Ereignisse in die Datenbank.

## Ressourcen

Geschätzt 30–50 MB RAM. Die Ereignisse liegen in SQLite (`/data/node64.db`, Tabelle `hp_events`), standardmäßig
7 Tage und höchstens 200 000 Stück; Älteres wird stündlich gelöscht. Limits je Quell-IP und insgesamt verhindern,
dass ein Angreifer den Sensor überlastet; was darüber hinausgeht, wird verworfen und in
`node64_honeypot_dropped_total` gezählt.

## MikroTik RouterOS (Container)

Der Sensor kann direkt auf dem Router laufen: dasselbe Image, Modus ohne Oberfläche, Profil `minimal` (SSH 22,
HTTP 80). **Nicht live getestet.** Die Schritte folgen der Container-Doku von MikroTik
([manual.mikrotik.com/docs/containers](https://manual.mikrotik.com/docs/containers/), Stand RouterOS 7.21); auf einem
echten Gerät ist die Anleitung noch nicht durchgespielt. Was offen ist, steht unter [Ungeprüft](#ungeprüft).

### Voraussetzungen

- RouterOS 7; die Befehle unten gelten für **7.21 oder neuer** (ältere Versionen siehe [Ungeprüft](#ungeprüft)).
- Paket `container` installiert (aus den „Extra packages“ der eigenen RouterOS-Version).
- Container-Modus freigeschaltet. Das geht nur mit Zugang zum Gerät: nach dem Befehl die Reset-Taste drücken
  (x86: Kaltstart).

  ```
  /system/device-mode/update container=yes
  ```

- Architektur arm64, arm 32 Bit (Image `linux/arm/v7`) oder x86 (`linux/amd64`). Geräte mit EN7562CT (z. B. hEX
  Refresh) führen laut MikroTik nur arm32v5-Images aus; dafür gibt es kein Image.
- Mindestens 256 MB RAM; der Sensor braucht geschätzt 30–50 MB.
- Externer Datenträger (USB, SATA oder NVMe) mit einem Dateisystem, das RouterOS unterstützt; MikroTik rät für
  Container vom internen Speicher ab. Den Namen zeigt `/disk print` (unten `disk1`).

### 1. Netz für den Container

```
/interface/veth/add name=veth-hp64 address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/add name=containers
/ip/address/add address=172.17.0.1/24 interface=containers
/interface/bridge/port/add bridge=containers interface=veth-hp64
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.0.0/24 comment="Honeypot64 ausgehend"
```

Nach außen braucht der Sensor nur HTTPS zu ipv64 (Meldung). Damit niemand über den Sensor ins Heimnetz kommt, neue
Verbindungen vom Container ins LAN sperren (LAN-Netz anpassen; die Regel muss vor Regeln stehen, die solchen
Verkehr erlauben):

```
/ip/firewall/filter/add chain=forward src-address=172.17.0.0/24 dst-address=192.168.88.0/24 connection-state=new action=drop comment="Honeypot64 nicht ins LAN"
```

### 2. Fallen-Ports weiterleiten

```
/ip/firewall/nat/add chain=dstnat in-interface-list=WAN protocol=tcp dst-port=22 action=dst-nat to-addresses=172.17.0.2 to-ports=22 comment="Honeypot64 SSH"
/ip/firewall/nat/add chain=dstnat in-interface-list=WAN protocol=tcp dst-port=80 action=dst-nat to-addresses=172.17.0.2 to-ports=80 comment="Honeypot64 HTTP"
```

- dst-nat ändert nur das Ziel; der Sensor sieht die echten Quell-Adressen.
- Port 22 und 80 aus dem Internet landen danach beim Sensor, nicht mehr beim Router. Den Router nur aus dem LAN oder
  per VPN verwalten. Im LAN ändert sich nichts, die Regeln greifen nur auf der Interface-Liste `WAN` (aus der
  Standardkonfiguration; ohne sie `in-interface=<WAN-Interface>`).
- **Die Info-Seite (9064) nicht weiterleiten.** Aus dem LAN ist sie unter `http://172.17.0.2:9064/` erreichbar
  (private Absender-Adresse), Prometheus fragt dort `/metrics` ab.
- `minimal` öffnet nur 22 und 80. Weitere Fallen (z. B. 23, 443) über `NODE64_HONEYPOT_SERVICES` und je Port eine
  dst-nat-Regel; jede Falle braucht etwas RAM.

### 3. Image

**Das Image ist noch privat.** Bis zur Veröffentlichung geht nur der Import als Datei. Auf einem PC mit Docker
(Plattform passend zum Router: `linux/arm64`, `linux/arm/v7` oder `linux/amd64`):

```bash
docker pull --platform linux/arm64 ghcr.io/ipv64net/node64:latest
docker save ghcr.io/ipv64net/node64:latest > node64.tar
```

`node64.tar` auf den Datenträger des Routers kopieren (WinBox › Files, SFTP oder SCP), z. B. nach `disk1/node64.tar`.

Nach der Veröffentlichung kann RouterOS das Image selbst laden:

```
/container/config/set registry-url=https://ghcr.io tmpdir=disk1/tmp
```

MikroTik nennt Docker Hub als Beispiel und erlaubt andere Registries über `registry-url`; ob `ghcr.io` so
funktioniert, ist nicht getestet. Das Laden aus einer Registry braucht viel freien RAM; auf kleinen Geräten ist
die Datei der sicherere Weg.

### 4. Umgebungsvariablen und Datenordner

```
/container/envs/add list=hp64-env key=NODE64_MODE value=honeypot
/container/envs/add list=hp64-env key=NODE64_HONEYPOT_PROFILE value=minimal
/container/envs/add list=hp64-env key=NODE64_IPV64_KEY value=<api-key>
/container/envs/add list=hp64-env key=NODE64_HONEYPOT_RETENTION value=3d
/container/mounts/add list=hp64-data src=disk1/honeypot64/data dst=/data
```

- Ohne `NODE64_IPV64_KEY` bleiben die Ereignisse lokal. Exporte der Router-Konfiguration können den Key
  enthalten; solche Exporte nicht weitergeben.
- `NODE64_HONEYPOT_RETENTION=3d` ist optional und schont den Datenträger (Standard 7 Tage).
- Der Datenordner hält Datenbank, SSH-Host-Schlüssel und Sensor-Kennung. Liegt er im Mount, bleiben sie beim
  Neuanlegen des Containers (Update) erhalten.

### 5. Container anlegen und starten

Aus der Datei:

```
/container/add name=honeypot64 file=disk1/node64.tar interface=veth-hp64 root-dir=disk1/honeypot64/root envlists=hp64-env mountlists=hp64-data logging=yes start-on-boot=yes memory-max=128M
```

Nach der Veröffentlichung statt `file=…` aus der Registry: `remote-image=ipv64net/node64:latest`.

Der Container startet nach dem Anlegen nicht von selbst. Warten, bis `/container/print` ihn nicht mehr beim
Entpacken zeigt, dann:

```
/container/start honeypot64
/log/print where topics~"container"
```

Im Log (`logging=yes`) steht für jeden Fallen-Dienst, ob er offen ist. Danach aus dem LAN
`http://172.17.0.2:9064/` öffnen.

**Ressourcen:** `memory-max=128M` begrenzt den RAM des Containers (je Container ab RouterOS 7.20). Braucht er mehr,
beendet RouterOS den Prozess. Das Image ist klein (nur das Binary); den meisten Platz brauchen die Ereignisse in
`/data` (höchstens 200 000, siehe [Ressourcen](#ressourcen)).

### Ungeprüft

- **Ports 22 und 80:** Das Image läuft als Benutzer 65532 und öffnet Ports unter 1024 über die Datei-Fähigkeit
  `cap_net_bind_service` (siehe [Ports](#ports)). Ob RouterOS das im Container zulässt, ist nicht getestet. Meldet
  das Log für 22/80 „permission denied“, hohe Ports nehmen und per dst-nat umsetzen (der Sensor meldet dann Port
  2222 bzw. 8080):

  ```
  /container/stop honeypot64
  /container/envs/add list=hp64-env key=NODE64_HONEYPOT_SERVICES value="ssh:2222,http:8080"
  /ip/firewall/nat/set [find comment="Honeypot64 SSH"] to-ports=2222
  /ip/firewall/nat/set [find comment="Honeypot64 HTTP"] to-ports=8080
  /container/start honeypot64
  ```

- **Schreibrechte in `/data`:** Ob der Benutzer 65532 im gemounteten Ordner schreiben darf, ist nicht getestet.
  Falls nicht: den gestoppten Container mit `/container/set [find name=honeypot64] user=0:0` als root laufen lassen
  (so empfiehlt es MikroTik für Container, die mehr Rechte brauchen) oder ohne Mount betreiben – dann liegen die
  Daten im `root-dir`, und ein neu angelegter Container meldet mit neuer Sensor-Kennung.
- **Registry `ghcr.io`** und der **Import per `docker save`** sind nicht auf einem Router ausprobiert.
- **Aktualisieren:** Container stoppen, entfernen und neu anlegen (Daten im Mount bleiben). RouterOS hat seit 7.20
  auch den Befehl `repull`; nicht getestet.
- **Ältere RouterOS-Versionen:** Vor 7.21 heißt der Parameter `mounts=` statt `mountlists=`; mehrere `envlists` und
  `memory-max` je Container gibt es erst ab 7.20 (vorher RAM-Grenze nur global unter `/container/config`). Welche
  Parameter die eigene Version kennt, zeigt `/container/add ?` im Terminal.
- **IPv6** ist hier nicht beschrieben; die Weiterleitung oben gilt nur für IPv4.
