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
| `NODE64_HONEYPOT_SERVICES` | – | eigene Dienste statt des Profils, z. B. `ssh:22,ssh:2222,http:80,https:443,tcp:3389`; Dienste `ssh`, `telnet`, `http`, `https`, `tcp`, `ftp`, `smtp`, `pop3`, `imap`, `smtps`, `pop3s`, `imaps` (Mail mit TLS), `mqtt`, `mysql`, `postgres`, `mssql`, `redis`, `rdp`, `vnc`, `mikrotik-api`, `snmp` (UDP), `sip` (UDP); bei `http`/`https` optional ein Köder als dritter Teil (`http:80:wp-login`, möglich: `generic`, `wp-login`, `phpmyadmin`, `admin`). Unbekannte Dienste, doppelte Ports oder ungültige Ports verhindern den Start |
| `NODE64_HONEYPOT_SCAN` | `1` | Port-Scan-Erkennung (`1`/`0`) |
| `NODE64_HONEYPOT_PERSONAS` | – | Dienst-Profile je Port, Komma-Liste `dienst:port=profil`, z. B. `ssh:22=dropbear,http:8080=apache` (Profile siehe [Ports](#ports)); nur für aktive Fallen, Fehler verhindern den Start |
| `NODE64_HONEYPOT_HOSTNAME` | – | Hostname der Fallen (Banner, Zertifikate), leer = aus der Sensor-Kennung erzeugt |
| `NODE64_NAME` | `Honeypot64` | Name des Sensors in der Node-Übersicht auf ipv64.net (höchstens 64 Zeichen) |
| `NODE64_HONEYPOT_RETENTION` | `7d` | lokale Aufbewahrung, z. B. `3d`, `48h` (1 Stunde bis 365 Tage); zusätzlich gilt eine feste Obergrenze von 200 000 Ereignissen |
| `NODE64_HONEYPOT_INFO_PORT` | `9064` | Port der Info-Seite, `0` = aus; darf kein Fallen-Port sein |
| `NODE64_HONEYPOT_INFO_TOKEN` | – | erlaubt die Info-Seite auch von außerhalb privater Netze (mindestens 16 Zeichen) |
| `NODE64_IPV64_KEY` | – | API-Key des ipv64-Accounts (16 bis 64 Buchstaben und Ziffern). Gesetzt = Meldung an ipv64 alle 10 Minuten; ein ungültiges Format verhindert den Start |
| `NODE64_HONEYPOT_REPORT` | `1` | `0` schaltet die Meldung an ipv64 trotz Key ab; ohne Key ist sie immer aus |
| `NODE64_HONEYPOT_COUNTRY` | – | Standort des Sensors als Ländercode (z. B. `SG`) für die Live-Karte auf ipv64.net; leer = automatisch aus der öffentlichen IPv4. Nur Anzeige, nicht für die Bewertung |
| `NODE64_HONEYPOT_LOGS` | – | Log-Sensor: Komma-Liste, je Eintrag `pfad` oder `pfad=format`, z. B. `/host/log/auth.log=syslog,/host/log/nginx/*access.log=nginx`; Pfade absolut unterhalb von `/host/log`, `/var/log` oder `/data/logs`, Muster erlaubt, höchstens 32. Formate: `syslog`, `nginx`, `apache`, `caddy`, `nextcloud`, `vaultwarden`, `gitea`, `proxmox`, `homeassistant` (ohne = automatisch). Leer = aus; kein Profil schaltet ihn ein (siehe [Log-Sensor und Syslog](#log-sensor-und-syslog)) |
| `NODE64_HONEYPOT_SYSLOG_PORT` | – | Syslog-Empfänger auf UDP und TCP, z. B. `514`; leer oder `0` = aus. Darf kein Fallen-Port und nicht der Info-Port sein |
| `NODE64_HONEYPOT_SYSLOG_ALLOW` | private Netze | erlaubte Absender, Komma-Liste von IPs oder Netzen (CIDR), z. B. `192.168.1.1,10.0.0.0/8`; leer = private Netze und localhost |
| `NODE64_FIREWALL` | – | `nftables` schaltet den [Firewall-Helfer](#firewall-helfer) ein (braucht `--cap-add NET_ADMIN` und `--network host`); leer oder `0` = aus |
| `NODE64_FIREWALL_LISTS` | `v64` | Listen für die Firewall, Komma-Liste von IDs aus `index.json`, z. B. `v64_ssh,v64_web` |
| `NODE64_FIREWALL_ALLOW` | – | eigene Netze, die nie gesperrt werden, Komma-Liste von IPs oder Netzen (CIDR) |
| `NODE64_FIREWALL_KEEP` | `0` | `1` lässt die Tabelle `inet node64` beim Beenden stehen |
| `NODE64_IPV64_LIST_TOKEN` | – | Listen-Token aus dem ipv64-Account (32 Zeichen): v64-Listen live statt im Tagesstand |
| `NODE64_DATA_DIR` | `/data` | Datenverzeichnis: Datenbank `node64.db`, Sensor-Dateien (SSH-Host-Schlüssel, TLS-Zertifikat, Sensor-Kennung `sensor_id`, Stand der Meldung `report_state.json`) unter `honeypot/` |
| `NODE64_BIND_ADDR` | – | Adresse der Info-Seite (leer = alle) |
| `NODE64_LOG_LEVEL`, `NODE64_LOG_FORMAT` | `info`, `text` | wie im normalen Betrieb |

Die übrigen Variablen der Node (Weboberfläche, Admin, TLS) werden in diesem Modus nicht benutzt.

## Ports

| Profil | Dienste |
|---|---|
| `minimal` | SSH 22, HTTP 80 (für kleine Geräte) |
| `standard` | SSH 22 und 2222, Telnet 23, HTTP 80, 8080 und 8123, HTTPS 443 und 8006, FTP 21, SMTP 25, IMAP 143, MQTT 1883, MySQL 3306, Redis 6379, RDP 3389, VNC 5900, MikroTik-API 8728, TCP 8291 (Winbox) |
| `full` | wie `standard`, dazu Telnet 2323, SMTP 587, POP3 110, MSSQL 1433, PostgreSQL 5432, MikroTik-API mit TLS 8729, SNMP UDP 161, SIP UDP 5060, HTTP 2375, 3000, 5000, 9200, HTTPS 4444, 5001, 8007, 8443, 9443, 10000, 10250, 10443 und TCP 445, 27017 |

**Login-Fallen:** FTP, SMTP (AUTH PLAIN/LOGIN, kein Relay), POP3, IMAP (auch mit TLS: SMTPS 465, POP3S 995, IMAPS 993 –
in keinem Profil, nur eigene Auswahl), MQTT, PostgreSQL, MySQL, MSSQL, Redis, MikroTik-API, RDP (nur Benutzername), VNC (nur Versuch), SNMP (Community) und SIP (Benutzername) nehmen Anmeldungen an, lehnen jede
ab und erfassen Benutzername und Passwort – wie SSH und Telnet. Reine TCP-Ports erfassen Verbindung und erste Bytes.

**UDP:** SNMP und SIP laufen über UDP – bei Docker ohne `--network host` die Ports mit `/udp` veröffentlichen (`-p 161:161/udp -p 5060:5060/udp`). SNMP antwortet nie, SIP nur kurz und nie größer als die Anfrage (kein Missbrauch als Verstärker).

**Fingerabdrücke:** Bei HTTPS (und TLS an TCP-Ports) entsteht ein JA4-, bei SSH ein HASSH-Fingerabdruck des Werkzeugs; er steht an jedem Ereignis, in der Rangliste und geht mit der Meldung an ipv64.

**Geräte-Logins:** Die Web-Köder beantworten die Login-Aufrufe verbreiteter Geräte und Oberflächen (Router wie
FRITZ!Box, Speedport, OpenWrt; Firewalls und SSL-VPN; NAS; UniFi; Home Assistant; Proxmox; Grafana; Jenkins; Webmin;
Portainer) mit einer schlichten Ablehnung und erfassen die Zugangsdaten (Gerät im Detail `device=…`). Es gibt keine
Logos oder Nachbauten der Herstellerseiten – Bots greifen die Adressen an, nicht die Optik. Proxmox, Home Assistant,
NAS, Webmin und Grafana antworten nur auf Ports mit diesem Profil (siehe unten), die übrigen auf den Webserver-Ports.

**Dienst-Profile:** Jede Falle gibt sich als ein bestimmter Dienst aus, damit Scanner sie richtig einordnen. Geändert
wird nur, was die Falle sendet; erfasst wird bei jedem Profil dasselbe.

| Dienst | Profile (Standard fett) | Was die Falle sendet |
|---|---|---|
| SSH | **`openssh`** (Debian 12 oder Ubuntu 24.04 je Sensor), `openssh-debian`, `openssh-ubuntu`, `dropbear` | Banner wie `OpenSSH_9.2p1 Debian-2+deb12u…` bzw. `dropbear_2024.8…`, Schlüsseltausch, Verfahren und Host-Schlüssel (RSA, ECDSA, Ed25519) in der Reihenfolge des Originals, soweit Go sie kennt |
| Telnet | **`busybox`**, `linux` | `<host> login: ` (BusyBox) bzw. `Debian GNU/Linux 12` / `Ubuntu 24.04.x LTS` und dann `<host> login: `, Telnet-Optionen wie das Original |
| MySQL | **`mysql`** (8.0, `caching_sha2_password`), `mariadb` (10.11 der Distribution), `mariadb11` (11.4) | Version, Fähigkeiten, Zeichensatz und Auth-Plugin passend zur Version (ohne TLS) |
| HTTP/HTTPS | **`nginx`**, `apache`, `pve`, `webmin`, `homeassistant`, `grafana`, `nas`, `elasticsearch` | Server-Kopf, Fehlerseiten, Status und API-Format wie das Original ohne Anmeldung, schlichte Seiten mit Titel, Zertifikat passend (z. B. Proxmox: `OU=PVE Cluster Node, O=Proxmox Virtual Environment, CN=<host>.<domain>`, von einer „PVE Cluster Manager CA“) |

Standard bei HTTP/HTTPS je Port (bzw. Köder): 8006 `pve`, 10000 `webmin`, 8123 `homeassistant`, 3000 `grafana`,
5000/5001 `nas`, 9200 `elasticsearch`, alle anderen `nginx`. Webserver-Profile (`nginx`, `apache`) zeigen die Köder
je Pfad wie bisher; Anwendungen antworten wie das Original ohne Anmeldung (z. B. Proxmox `/api2/json/*` → 401
`{"data":null}`, Home Assistant `/api/` → 401, Grafana `/api/health` mit Version, Elasticsearch `/` mit Knotenname
und Version 7.17.x). Hostname, Domain, Distribution, Patch-Stände und Zertifikatsdaten (Seriennummer, Ausstellung)
leitet jeder Sensor aus seiner Sensor-Kennung ab: über Neustarts gleich, von Sensor zu Sensor verschieden. Ohne
Oberfläche gelten die Standards je Port, abweichende Profile und Hostname mit `NODE64_HONEYPOT_PERSONAS` und
`NODE64_HONEYPOT_HOSTNAME`. Zertifikate und Host-Schlüssel liegen im Datenordner (`tls-<art>.crt/.key`,
`ssh_host_rsa`, `ssh_host_ecdsa`, `ssh_host_ed25519`).

Dazu die Info-Seite auf `NODE64_HONEYPOT_INFO_PORT` (Standard 9064).

**Ports unter 1024** (22, 23, 80, 443 …) öffnet Node64 ohne Root über die Fähigkeit `cap_net_bind_service`, die das
Image dem Binary als „erlaubt“ mitgibt (`+p`) und die Node64 beim Start selbst einschaltet. Nimmt der Container die
Fähigkeit weg (`--cap-drop`, manche Podman-Einstellungen), bleiben diese Ports zu, die übrigen laufen weiter.

**Belegte Ports:** Läuft auf dem Rechner schon ein echter Dienst (z. B. der eigene SSH-Server auf 22), kann die Falle
den Port nicht öffnen. Das ist kein Fehler für die anderen Dienste. Entweder den echten Dienst auf einen anderen Port
legen oder den Port mit `NODE64_HONEYPOT_SERVICES` weglassen.

Beim Start steht im Log für jeden Dienst, ob er offen ist und, wenn nicht, warum (z. B. „address already in use“,
„permission denied“).

### Auswahl im Modul (mit Oberfläche)

Als Modul wählt man die Dienste unter Honeypot64 › Einstellungen in einer Tabelle aller Fallen-Dienste (nach
Gruppen: Fernzugriff, Web, Mail, Datenbanken, Router/IoT, Sonstiges): je Zeile ein Schalter, der Port (änderbar),
bei http/https der Köder und der Zustand des Ports – frei, offen, Fehler oder „belegt von …“ (PROXY64, DNS64, die
Oberfläche; TCP und UDP getrennt, `udp 161` und `tcp 161` vertragen sich). Die Knöpfe „Minimal“, „Standard“, „Voll“
füllen die Tabelle wie das Profil, „Alle freien einschalten“ nimmt jeden freien Port dazu, „Alle aus“ leert sie;
gespeichert wird erst mit „Speichern“. Unter „Weitere Einträge“ läuft ein Dienst mehrfach (z. B. `ssh` auf 22 und
2200). Entspricht die Auswahl genau einem Profil, wird sie als dieses Profil gespeichert (neue Dienste späterer
Versionen kommen dann dazu), sonst als eigene Liste. Die Textliste „dienst port [köder]“ gibt es weiter unter
„Erweitert“. Die Spalte „Profil“ wählt je Zeile das Dienst-Profil (Standard für Port und Köder vorausgewählt;
gespeichert werden nur Abweichungen, als `personas` mit Schlüssel `dienst:port`, z. B. `{"ssh:22":"dropbear"}`), das
Feld „Hostname der Fallen“ setzt den Hostnamen (leer = aus der Sensor-Kennung erzeugt). Per API:
`GET /api/honeypot/catalog` (Katalog mit Zustand, Profil, Standardprofil und Auswahl je Zeile, `hostname`),
gespeichert wird mit `PUT /api/honeypot/config` (`personas`, `hostname`; ältere Einstellungen ohne diese Felder
gelten unverändert mit den Standards je Port).

Auf einer Node mit weiteren Modulen sind manche Ports vergeben (80/443 PROXY64, 53/853 DNS64, die Oberfläche auf
`NODE64_HTTP_PORT`, Standard 8080). Für alle Ports: Node64 nur mit Honeypot64 und der Oberfläche auf einem
ungewöhnlichen Port – oder dieser Modus ohne Oberfläche.

### Portfreigabe

Damit Angreifer die Fallen erreichen, müssen die Ports aus dem Internet ankommen: am Router die gewünschten Ports
(z. B. 22, 23, 80, 443, 2222, 3389) an den Rechner mit dem Sensor weiterleiten, am besten an ein eigenes Gerät oder
eine eigene VM in einem abgetrennten Netz (DMZ/VLAN). **Den Port der Info-Seite (9064) nicht freigeben.** Ein
Sensor nur im Heimnetz sieht fast nichts.

## Zertifikat für Köder-Namen

Nur im Modul (mit Oberfläche): Unter Honeypot64 › Einstellungen › „Zertifikat für Köder-Namen“ zeigen die HTTPS-Fallen
mit Webserver-Profil (`nginx`, `apache`) und die Mail-Fallen mit TLS (SMTPS, IMAPS, POP3S) ein gültiges Zertifikat aus
der zentralen Zertifikatsverwaltung der Node statt des selbst signierten. Ein Scanner sieht dann z. B. auf 443 und 993
einen „echten“ Server `mail.<domain>`. Profile, die in echt selbst signiert sind – Proxmox (8006, 8007), Webmin
(10000), NAS (5000/5001), UniFi, Router/MikroTik (8729), Grafana, Home Assistant, Elasticsearch, Kubelet, Portainer –
bleiben selbst signiert; unter „Auch auf diesen Ports zeigen“ lassen sich einzelne Ports trotzdem zuweisen. Port 80
bleibt eine Falle (kein HTTP-01 nötig). STARTTLS auf 25/587/110/143 bieten die Fallen weiter nicht an.

- **Vorhandenes Zertifikat wählen** oder **neu anlegen**: einzelne, glaubwürdige Namen (Standard `mail, vpn, cloud,
  portal`, kein Wildcard, höchstens 20) unter einer Domain des ipv64-Accounts. Angelegt wird über den normalen Weg der
  Zertifikatsverwaltung (Let's Encrypt, DNS-01 über ipv64 mit dem zentralen API-Key; Nutzungsbedingungen unter
  *Zertifikate* angenommen). Das Zertifikat erscheint dort mit „benutzt von Honeypot64“ und wird automatisch erneuert;
  bis es ausgestellt ist, bleiben die Fallen selbst signiert.
- **DNS-Records** (optional): Mit einer öffentlichen IPv4/IPv6 der Node legt das Modul A/AAAA-Records an, mit einem
  Namen (z. B. der DynDNS-Domain) einen CNAME – über den zentralen API-Key. Namen, die schon A, AAAA oder CNAME haben,
  bleiben unberührt. Ohne Angabe die Records selbst bei ipv64 anlegen.
- **Eine eigene Domain bzw. Subdomain nur für die Köder nehmen**, nie die Hauptdomain oder Namen echter Dienste: Jedes
  Zertifikat steht mit allen Namen öffentlich in den Certificate-Transparency-Logs (crt.sh), und Scanner lesen dort mit.
- **Angefragter Name (SNI):** Bei HTTPS steht der Name aus dem TLS-Handshake im Detail (`sni=…`), bei Mail mit TLS als
  Host; die Ereignisliste zeigt ihn als „Angefragter Name“. So wird sichtbar, welche Bots die Namen aus den CT-Logs
  kennen.

Im Modus ohne Oberfläche gibt es keine Zertifikatsverwaltung: dort bleiben alle Fallen selbst signiert.

## Anmeldung von Node64 überwachen

Nur im Modul: Solange Honeypot64 läuft, zählt es die Fehlversuche an der eigenen Anmeldung von Node64 (Passwort, TOTP,
Passkey, SSO ohne verknüpftes Konto, ungültige API- und MCP-Keys) je Quell-IP. Ab der Schwelle (Standard 5 Fehlversuche
in 10 Minuten, einstellbar 2–100 bzw. 1–1440 Minuten) entsteht genau ein Ereignis je IP und Zeitfenster: Quelle `log`,
Regel `node64/login@1`, Art `http:bruteforce`, Dienst `http`/`https` mit dem Port der Oberfläche – **ohne
Benutzernamen oder Passwörter**. Dazu:

- Benachrichtigung „Angriff auf die Anmeldung“ über die Kanäle der Node (höchstens eine alle 10 Minuten, weitere
  werden mitgezählt; abschaltbar),
- Sofort-Sperre über PROXY64, wenn dort die Sofort-Sperre von Honeypot64 eingeschaltet ist (siehe [Zusammenarbeit mit PROXY64](#zusammenarbeit-mit-proxy64)),
- Meldung an ipv64 mit den übrigen Ereignissen, wenn die Meldung eingeschaltet ist.

Private, Loopback- und andere nicht öffentliche Adressen werden nur gezählt (Übersicht), nie gemeldet oder gesperrt –
auch ein Reverse-Proxy vor der Oberfläche ohne `NODE64_TRUST_PROXY` erscheint so. Die Übersicht zeigt die Zeile
„Angriffe auf die Node64-Anmeldung“ (24 Stunden, 7 Tage, Fehlversuche seit dem Start).

**Die Oberfläche von Node64 nie offen ins Internet stellen** (keine Portfreigabe für `NODE64_HTTP_PORT`/
`NODE64_HTTPS_PORT`). Von unterwegs nur über VPN oder über PROXY64 mit Anmeldung und Zugriffsliste. Die Überwachung
ist ein Frühwarnsystem, kein Schutz für eine offene Oberfläche.

## Info-Seite, `/metrics`, `/health`

Auf dem Info-Port (getrennt von den Fallen) antwortet ein kleiner Server, nur `GET` und `HEAD`:

| Pfad | Inhalt |
|---|---|
| `/` | Info-Seite, nur lesend (kein Formular, kein JavaScript, hell/dunkel nach System, Deutsch oder Englisch nach Browser): Zustand der Dienste, Treffer 24 h und 7 Tage, Quell-IPs, Login-Versuche, Länderkarte und Herkunft nach Land, Top-IPs, Arten, Quellen (Honeypot, Log, Syslog), Ports, Zugangsdaten, Pfade, User-Agents, Meldung an ipv64 (an/aus, letzte Meldung, nächster Versuch, gemeldete Quell-IPs, letzter Fehler, Sensor-Kennung), Log-Sensor und Syslog (Zustand je Datei, Syslog-Port, Nachrichten, abgewiesene Absender), Version, Laufzeit. Aktualisiert sich jede Minute |
| `/metrics` | Prometheus-Textformat |
| `/health` | `200 ok`, wenn die Datenbank antwortet und mindestens ein Fallen-Dienst offen ist, sonst `503` |

**Zugriff:** ohne Token nur aus privaten Netzen (10/8, 172.16/12, 192.168/16, fc00::/7), CGNAT (100.64/10, z. B.
Tailscale), Loopback und Link-Local. Maßgeblich ist allein die Absender-Adresse der Verbindung; Kopfzeilen wie
`X-Forwarded-For` werden nicht beachtet. Mit `NODE64_HONEYPOT_INFO_TOKEN` ist sie zusätzlich von überall erreichbar,
mit `?token=<Token>` oder `Authorization: Bearer <Token>`; alles andere bekommt `403`. Die Seite schickt strenge
Kopfzeilen (Content-Security-Policy ohne Skripte, `nosniff`, `no-referrer`, `X-Frame-Options: DENY`, `no-store`).

Top-IPs zeigen Flagge und Ländercode, dazu gibt es die Länderkarte und die Rangliste „Herkunft nach Land“ (7 Tage,
siehe [Herkunft](#herkunft)).

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
keine), `node64_honeypot_report_errors_total`, `node64_honeypot_report_sources_total`. Log-Sensor und Syslog:
`node64_honeypot_log_lines_total` (gelesene Zeilen aus Dateien), `node64_honeypot_log_file_ok{path}` (1 = wird
gelesen, 0 = Fehler), `node64_honeypot_syslog_messages_total`, `node64_honeypot_syslog_denied_total`; in
`node64_honeypot_events_total{kind,source}` steht `source` für `honeypot`, `log` oder `syslog`. Firewall-Helfer (nur
wenn eingeschaltet): `node64_firewall_active`, `node64_firewall_entries{family}` (Bereiche je Set, `ipv4`/`ipv6`),
`node64_firewall_last_update_timestamp`, `node64_firewall_errors_total`, `node64_firewall_list_entries{list,edition}`. Zusammenarbeit mit
PROXY64: `node64_honeypot_proxy_decoy_total`, `node64_honeypot_proxy_access_total`, `node64_honeypot_proxy_access_dropped_total`,
`node64_honeypot_proxy_blocks_total`. Herkunft: `node64_honeypot_events_by_country_total{country}` (nur Länder mit
Ereignissen, höchstens 250 Werte, nur mit Länderdaten). Beispiel-Alarm:
`time() - node64_honeypot_report_last_success_timestamp > 3600`. Die übrigen Kennzahlen der Node siehe
[PROMETHEUS.md](PROMETHEUS.md).

### Docker-Healthcheck

Der `HEALTHCHECK` des Images (`/node64 healthcheck`) fragt in diesem Modus `/health` auf dem Info-Port über
`127.0.0.1`/`::1` (bzw. `NODE64_BIND_ADDR`) ab, mit Token, falls gesetzt. Mit `NODE64_HONEYPOT_INFO_PORT=0` gibt es
keine Prüfung über das Netz; der Container gilt dann als gesund, solange der Prozess läuft.

## Herkunft

Honeypot64 zeigt zu jeder Quell-IP das Land: Flagge (Emoji), Ländercode und Name im Tooltip – in der Ereignisliste,
bei den Top-Quellen, in der Benachrichtigung über neue Angreifer und auf der Info-Seite. Die Rangliste „Herkunft nach
Land“ zählt Ereignisse und verschiedene Quell-IPs je Land; die Übersicht im Modul zeigt außerdem farbig, was angegriffen
wurde (je Dienst, Port und Art, nach Gruppe Login/Bruteforce, Exploit, Scan, Sondierung, Log/Syslog) und welche Köder
und erkannten Geräte (`device=…`) getroffen wurden.

Die Länderdaten kommen von ipv64.net (`blocklists/country_ranges.txt.gz`, täglich aufbereitet nach dem Standort der
Adressen aus DB-IP „IP to Country Lite“, Lücken aus den Daten der Registrierungsstellen, eingetragen in
`blocklists/index.json` als `geo`; Lizenz CC BY 4.0, Hinweis „IP-Länderdaten: DB-IP.com“ an Karte und Länderliste).
Node64 fragt dafür keinen fremden Dienst ab. Geladen wird
nur, solange Honeypot64 läuft: beim Start sofort aus dem Zwischenspeicher `/data/geoip/`, danach von ipv64.net und
täglich nur bei Änderung (ETag). Im Speicher belegen die Bereiche etwa 10 Byte je IPv4- und 18 Byte je IPv6-Bereich
(einige MB). Das Land wird beim Auswerten nachgeschlagen, nicht gespeichert; neue Daten gelten sofort auch für ältere
Ereignisse. Private und reservierte Adressen haben kein Land. Fehlt die Datei bei ipv64 oder ist ipv64 nicht
erreichbar, läuft alles ohne Länder weiter (nur ein Eintrag im Log). Ohne Flaggen-Schrift (z. B. Windows) zeigt der
Browser statt der Flagge zwei Buchstaben; der Ländercode steht immer daneben.

API: `country` an Ereignissen (`GET /api/honeypot/events`) und an `top_sources`, `by_country` und `country_unknown`
in `GET /api/honeypot/stats`, dazu `by_decoy` (Köder und Geräte). Ereignisse eines Landes:
`GET /api/honeypot/events?country=DE` (ISO 3166 alpha-2, groß oder klein; ungültig = `400`, ohne Länderdaten leer).

### Karte

Die Übersicht zeigt über der Rangliste eine Weltkarte für den gewählten Zeitraum (24 Std. oder 7 Tage): Länder mit
Angriffen sind in fünf Stufen eingefärbt (logarithmisch bis zum stärksten Land, das immer in der obersten Stufe liegt;
Legende oben rechts), Länder ohne Angriffe grau. Der Tooltip nennt Flagge, Name, Ereignisse und Quell-IPs. Ein Klick
auf ein Land (oder seinen Namen in der Rangliste) filtert die Ereignisliste unten nach diesem Land
(`/honeypot?country=DE`, funktioniert ohne JavaScript; Zeitraum und Sensor-Filter bleiben erhalten, das Kreuz am
Länder-Abzeichen hebt den Filter auf). Ohne Länderdaten erscheint statt der Karte nur der Hinweis, dass sie geladen
werden. Die Info-Seite des Modus ohne Oberfläche zeigt dieselbe Karte für 7 Tage (ohne Links).

Kartendaten: Natural Earth 1:110m Admin-0 Countries (public domain), Projektion Natural Earth, vereinfacht und mit
ganzzahligen Koordinaten in Node64 eingebettet (`internal/honeypot/worldmap/world.txt`, rund 30 KB, ohne Antarktis);
es wird nichts aus dem Netz nachgeladen. Sehr kleine Inselstaaten fehlen in diesem Maßstab; sie stehen weiter in der
Rangliste (Hinweis unter der Karte). Neu erzeugen: GeoJSON `ne_110m_admin_0_countries.geojson` aus
github.com/nvkelso/natural-earth-vector laden und `go run ./internal/honeypot/worldmap/gen -in <Datei> -out
internal/honeypot/worldmap/world.txt`.

## Startseite

Die Karte von Honeypot64 auf der Startseite zeigt für die letzten 24 Stunden: Ereignisse mit Trend gegenüber den
24 Stunden davor (▲/▼ in Prozent, mehr = rot, weniger = grün), verschiedene Quell-IPs, Login-Versuche, die drei
häufigsten Herkunftsländer als Flaggen (Tooltip mit Code und Anzahl), den meistangegriffenen Dienst mit Anteil, offene
Fallen-Dienste und – rot mit Fehlertext – Dienste, die nicht geöffnet werden konnten, die Meldung an ipv64 (aus, kein
API-Key, wartet, ok bzw. Fehler mit Zeitpunkt) und, sobald PROXY64 etwas übergeben hat, die Zahl der Anfragen über
PROXY64 seit dem Start.

## Meldung an ipv64

Mit `NODE64_IPV64_KEY` meldet der Sensor alle 10 Minuten (mit kleinem Zufallsversatz) an ipv64
(`POST /api/v2/honeypot/reports`, Format `schema: 1`, gzip). Beim Modul mit Oberfläche ist es der Schalter
„An ipv64 melden“ unter Honeypot64 → Einstellungen (Standard aus, braucht den zentralen API-Key der Node).

**Übertragen werden:** je Quell-IP Art, Dienst, Port, Anzahl, erster und letzter Zeitpunkt; dazu Proben mit Anzahl:
Zugangsdaten aus dem Honeypot (Benutzername und Passwort im Klartext, nur SSH, Telnet, HTTP/HTTPS), Pfade,
User-Agents und der Anfang von Payloads (SHA-256 und höchstens 256 Bytes). Außerdem eine feste Sensor-Kennung
(UUID, `honeypot/sensor_id`), Version, Profil und Modus, und – nur wenn eingestellt – der Standort des Sensors als
Ländercode (`sensor.country`, Ziel der Bögen auf der öffentlichen Live-Karte). Die Daten fließen in die v64 Blocklist ein, sobald die
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

## Log-Sensor und Syslog

Neben den Fallen kann der Sensor **Logs echter Dienste** lesen und **Syslog von Routern und Firewalls** annehmen.
So kommen die Angriffe dazu, die wirklich bei den eigenen Diensten ankommen. Mitgelieferte, versionierte Regeln
(z. B. `sshd/bruteforce@1`) erkennen Angriffe erst ab einer Schwelle (z. B. mehrere fehlgeschlagene Logins in wenigen
Minuten), weil echte Logs auch Vertipper legitimer Nutzer enthalten; eine erfolgreiche Anmeldung derselben IP setzt
den Zähler zurück. Der Log-Sensor liest nur, schreibt nichts und baut keine Verbindungen auf.

Beim Modul mit Oberfläche: Honeypot64 → Einstellungen → „Log-Sensor und Syslog“ (Dateien mit Format, Vorschläge für
gängige Pfade, Syslog-Port, erlaubte Absender); der Zustand je Datei und des Syslog-Empfängers steht daneben. Im
Modus ohne Oberfläche die Variablen `NODE64_HONEYPOT_LOGS`, `NODE64_HONEYPOT_SYSLOG_PORT` und
`NODE64_HONEYPOT_SYSLOG_ALLOW` ([Umgebungsvariablen](#umgebungsvariablen)). **Kein Profil schaltet den Log-Sensor
ein** – ohne eingebundene Logs gäbe es nur Fehler. Wie bei den Fallen öffnet das Modul nichts, bevor die
Einstellungen einmal gespeichert sind; ein Syslog-Port, den inzwischen ein anderer Teil der Node belegt, bleibt zu
(Fehler im Zustand).

### Was gemeldet wird

Aus echten Logs werden **nur IP, Art, Dienst, Port, Anzahl, Zeitraum und Regel** gespeichert und (mit „An ipv64
melden“) gemeldet. **Nie** Benutzernamen, Passwörter, Pfade, User-Agents oder andere Inhalte – das wären Mitarbeitende
oder Kunden des Betreibers. Der Speicher leert solche Felder bei Log- und Syslog-Ereignissen zusätzlich, auch wenn eine
Regel sie fälschlich setzen würde; Proben (Zugangsdaten, Pfade, User-Agents, Payloads) stammen ausschließlich aus dem
Honeypot. In der Meldung steht je Quelle `source` (`honeypot`, `log`, `syslog`) und die Regel mit Version; ipv64
gewichtet Honeypot höher als Log und Syslog. Private und reservierte Absender bleiben wie beim Honeypot lokal.

### Logs einbinden

Dateien werden über ihren Pfad im Container gelesen, erlaubt sind nur Pfade unterhalb von `/host/log` (empfohlener
Mount der Host-Logs), `/var/log` (Binary ohne Docker, dort die echten Logs) und `/data/logs` (Logs anderer Container in
einem gemeinsamen Volume). Muster wie `/host/log/nginx/*access.log` sind erlaubt, höchstens 32 Dateien. Rotation und
Kürzen der Dateien werden erkannt.

- **Mount:** `-v /var/log:/host/log:ro` – nur lesend.
- **Rechte:** `auth.log`, `secure` und `mail.log` gehören meist der Gruppe `adm` (Debian/Ubuntu: GID 4) und sind nicht
  für alle lesbar. Das Image läuft nicht als root, also `--group-add 4` mitgeben. Fehlt das, steht an der Datei
  „permission denied“ mit dem Hinweis auf `--group-add 4`.
- **journald:** Das Binärformat liest der Sensor (noch) nicht. Entweder `rsyslog` auf dem Host installieren (schreibt
  wieder `/var/log/auth.log` usw.) oder journald per Syslog an den Empfänger weiterleiten.

| Dienst | Datei (Host) | Format |
|---|---|---|
| sshd, sudo (Debian, Ubuntu) | `/var/log/auth.log` | `syslog` |
| sshd (RHEL, Rocky, Alma) | `/var/log/secure` | `syslog` |
| Postfix, Dovecot | `/var/log/mail.log` | `syslog` |
| nginx | `/var/log/nginx/access.log` | `nginx` |
| Apache | `/var/log/apache2/access.log` | `apache` |
| Caddy (JSON-Log) | z. B. `/var/log/caddy/access.log` | `caddy` |
| Proxmox VE | `/var/log/daemon.log` bzw. Syslog | `proxmox` |
| Nextcloud | `nextcloud.log` (Datenordner) | `nextcloud` |
| Vaultwarden (`LOG_FILE`) | z. B. `/var/log/vaultwarden.log` | `vaultwarden` |
| Gitea/Forgejo | `gitea.log` | `gitea` |
| Home Assistant | `home-assistant.log` | `homeassistant` |

Logs, die nicht unter `/var/log` liegen (Nextcloud, Gitea, Home Assistant), einzeln nach `/host/log/…` oder
`/data/logs/…` einbinden, z. B. `-v /srv/nextcloud/data/nextcloud.log:/data/logs/nextcloud.log:ro`.

```bash
docker run -d --name honeypot64 --network host --restart unless-stopped --group-add 4 \
  -e NODE64_MODE=honeypot -e NODE64_HONEYPOT_PROFILE=standard -e NODE64_IPV64_KEY=<api-key> \
  -e NODE64_HONEYPOT_LOGS=/host/log/auth.log=syslog,/host/log/nginx/*access.log=nginx \
  -e NODE64_HONEYPOT_SYSLOG_PORT=514 -e NODE64_HONEYPOT_SYSLOG_ALLOW=192.168.1.1,10.0.0.0/8 \
  -v /var/log:/host/log:ro -v honeypot64:/data ghcr.io/ipv64net/node64
```

```yaml
services:
  honeypot64:
    image: ghcr.io/ipv64net/node64
    network_mode: host
    restart: unless-stopped
    group_add: ["4"]          # Gruppe adm: auth.log lesen
    environment:
      NODE64_MODE: honeypot
      NODE64_HONEYPOT_PROFILE: standard
      NODE64_IPV64_KEY: <api-key>
      NODE64_HONEYPOT_LOGS: /host/log/auth.log=syslog,/host/log/mail.log=syslog
      NODE64_HONEYPOT_SYSLOG_PORT: "514"
    volumes:
      - /var/log:/host/log:ro
      - honeypot64:/data
volumes:
  honeypot64:
```

Beim normalen Node64-Container (Modul mit Oberfläche) gilt dasselbe: Mount und `--group-add 4` beim Container, die
Dateien dann in der Oberfläche eintragen.

### Syslog

Der Empfänger hört auf **UDP und TCP** auf demselben Port (üblich 514; RFC 3164 und RFC 5424, über TCP mit
Zeilenende oder Octet-Counting). Unter 1024 öffnet Node64 den Port wie die Fallen über `cap_net_bind_service`; beim
Modul prüft die Port-Verwaltung, dass kein anderer Teil (z. B. DNS64, Streams) den Port für UDP oder TCP nutzt.

**Absender:** Standard sind nur private Netze und localhost; mit „Erlaubte Absender“ bzw.
`NODE64_HONEYPOT_SYSLOG_ALLOW` genau festlegen (IP oder CIDR). Andere Absender werden verworfen und gezählt
(`node64_honeypot_syslog_denied_total`). UDP-Absender lassen sich fälschen – den Syslog-Port **nie** ins Internet
freigeben.

**Zeitzone:** Klassisches Syslog (RFC 3164) schickt die Uhrzeit ohne Zone. Der Empfänger liest sie in der Zeitzone
des Containers – für richtige Zeiten in der Ereignisliste `-e TZ=Europe/Berlin` setzen (Schwellen und Fenster hängen
nicht davon ab).

Beispiele (Sensor `192.168.1.20`; Menünamen können je nach Version abweichen, nicht auf jedem Gerät live getestet):

- **MikroTik RouterOS:**

  ```
  /system/logging/action/add name=hp64 target=remote remote=192.168.1.20 remote-port=514 bsd-syslog=yes
  /system/logging/add topics=system action=hp64
  /system/logging/add topics=account action=hp64
  ```

- **OPNsense:** System › Einstellungen › Protokollierung › Ziele: neues Ziel, Transport UDP(4) oder TCP(4),
  Host `192.168.1.20`, Port 514; Anwendungen z. B. Anmeldungen/Audit, Firewall (filter), OpenVPN/IPsec.
- **pfSense:** Status › System Logs › Settings › Remote Logging: „Send log messages to remote syslog server“,
  Remote log servers `192.168.1.20:514`, Inhalte System Events, Firewall Events, VPN Events.
- **FortiGate:**

  ```
  config log syslogd setting
      set status enable
      set server "192.168.1.20"
      set port 514
  end
  ```

- **Sophos Firewall:** System services › Log settings › Syslog-Server hinzufügen (IP, Port 514, UDP oder TCP,
  Format „Standard syslog protocol“), dann Authentifizierung, Firewall und VPN an diesen Server senden.
- **UniFi (Network-App):** Einstellungen › Control Plane › Integrations › Activity Logging (Syslog) bzw. „SIEM
  Server“: IP `192.168.1.20`, Port 514.

## Zusammenarbeit mit PROXY64

Nur Opt-in, eingeschaltet in PROXY64 (Zugriff › Honeypot64, je Punkt ein Schalter, Standard aus); Honeypot64 muss als
Modul laufen (gespeicherte Fallen-Dienste sind dafür nicht nötig):

- **Köder für unbekannte Anfragen:** Anfragen auf 80/443 ohne eingerichteten Host (nur IP, fremde Domain) beantwortet
  der Web-Köder des Honeypots statt der Standardseite; Logins, Pfade, User-Agents und Fingerabdrücke werden erfasst
  (Detail `via=proxy64`).
- **Zugriffe auswerten:** PROXY64 gibt je Anfrage nur Eckdaten (IP, Host, Pfad ohne Abfrage, Status, abgelehnte
  Anmeldung) an den Log-Sensor; Regeln `proxy64/exploit`, `proxy64/scan`, `proxy64/bad-useragent`, `proxy64/auth`,
  `proxy64/unknown-host`. Gemeldet wird wie bei echten Logs nur IP, Art und Anzahl.
- **Sofort-Sperre:** Fällt eine IP auf (Login-/Exploit-Versuch, Port-Scan, Regel aus PROXY64), sperrt PROXY64 sie
  lokal für die eingestellte Dauer (Standard 24 h) – ohne auf die v64 Blocklist zu warten. Private Adressen, Trusted
  Proxies und Ausnahmen werden nie gesperrt.

## Frühwarnung

Reiter „Frühwarnung“ im Modul: eigene Netze (IPv4 ab /16, IPv6 ab /32) bei ipv64 hinterlegen; die aktuellen
DynDNS-IPs des Accounts werden automatisch überwacht. ipv64 prüft nach jeder Bewertung, ob eine dieser Adressen als
Angreifer aufgefallen ist; die Node holt Treffer alle 30 Minuten ab und meldet sie gebündelt (Benachrichtigung
„Honeypot64 Frühwarnung“), dazu eine Mail von ipv64.

- Netze ohne Nachweis melden nur IPs, die auf der v64 Blocklist stehen (ohnehin öffentlich); DynDNS-IPs des Accounts
  gelten als nachgewiesen und melden schon jede Sichtung.
- Braucht den zentralen API-Key, nicht die Meldung an ipv64 und keinen eigenen Sensor. Der automatische Abruf läuft,
  solange das Modul an ist; sonst „Jetzt abrufen“.
- Grenzen je Account-Klasse: Standard 3 Netze, sonst 50.

## Firewall-Helfer

Mit `NODE64_FIREWALL=nftables` trägt Node64 die v64 Blocklist in die Firewall des Hosts ein – wie ein
Firewall-Bouncer. Was andere Sensoren gesehen haben, kommt dann gar nicht erst bei den eigenen Diensten an.

```bash
docker run -d --name honeypot64 --network host --cap-add NET_ADMIN --restart unless-stopped \
  -e NODE64_MODE=honeypot -e NODE64_IPV64_KEY=<api-key> \
  -e NODE64_FIREWALL=nftables -e NODE64_FIREWALL_ALLOW=<büro-ip>,<vpn-netz>/24 \
  -e NODE64_IPV64_LIST_TOKEN=<listen-token> \
  -v honeypot64:/data ghcr.io/ipv64net/node64
```

- **Eigene Tabelle:** Node64 legt `table inet node64` an, mit den Sets `blocklist_v4` (`ipv4_addr`) und
  `blocklist_v6` (`ipv6_addr`, beide `flags interval`) und den Ketten `input` und `forward` (`priority filter - 10`,
  vor den üblichen Filterregeln, `policy accept`). Sie verwerfen nur Pakete, deren Absender im Set steht; alles
  andere geht unverändert an die vorhandene Firewall (ufw, firewalld, Docker). Anschauen: `nft list table inet node64`.
- **Listen:** Standard ist die Gesamtliste `v64`; mit `NODE64_FIREWALL_LISTS` andere Listen aus `index.json`
  (`v64_ssh`, `v64_web`, `v64_mail`, `v64_rdp`, `v64_scanner`, `v64_research`, auch fremde wie `spamhaus_drop`).
  Ohne Listen-Token gilt der Tagesstand, mit `NODE64_IPV64_LIST_TOKEN` die Live-Fassung (alle Klassen außer
  Standard, siehe Plan Abschnitt 8); hat das Token keine Berechtigung, nimmt Node64 den Tagesstand.
- **Aktualisierung:** alle 30 Minuten, nur bei Änderung (ETag/If-Modified-Since). Die Sets werden in einer
  Transaktion geleert und neu gefüllt; es gibt keinen Moment ohne Schutz. Fehlt die Tabelle (z. B. nach
  `nft flush ruleset`), legt Node64 sie beim nächsten Abruf neu an. Die letzte Fassung liegt unter
  `/data/honeypot/firewall/`, damit der Schutz nach einem Neustart ohne Netz sofort steht.
- **Nie gesperrt:** private und reservierte Netze (RFC 1918, CGNAT, Loopback, Link-Local, ULA, Multicast,
  Dokumentation), bei IPv6 alles außerhalb von 2000::/3, die Adressen des Hosts selbst und `NODE64_FIREWALL_ALLOW`.
  Netze größer als /8 (IPv4) bzw. /16 (IPv6) aus einer Liste werden verworfen.
- **Beenden:** `docker stop` löscht die Tabelle; mit `NODE64_FIREWALL_KEEP=1` bleibt sie stehen (dann gilt der letzte
  Stand weiter, bis Node64 wieder läuft oder man sie mit `nft delete table inet node64` entfernt).
- **Zustand:** Info-Seite (Abschnitt „Firewall-Helfer“: Einträge, Fassung je Liste, letzte Prüfung, Fehler) und
  `/metrics` (siehe [Prometheus](#prometheus)).

**Rechte:** `--cap-add NET_ADMIN` erlaubt dem Container, die Firewall zu ändern; `--network host` ist nötig, sonst
landet die Tabelle im eigenen Netz des Containers und schützt den Host nicht. Das Image gibt dem Binary
`cap_net_admin` nur als „erlaubt“ mit; ohne `--cap-add NET_ADMIN` hat Node64 das Recht nicht und startet mit
`NODE64_FIREWALL=nftables` gar nicht (Meldung „operation not permitted … needs --cap-add NET_ADMIN“). Nur Linux mit
nftables im Kernel (auch Hosts, deren iptables über nftables läuft).

**Risiken:**

- Gesperrt wird nur **eingehend** nach Absender (`input`, `forward`). Antworten von gelisteten Adressen auf eigene
  Verbindungen werden ebenfalls verworfen; ausgehende Verbindungen zu ihnen selbst bleiben möglich.
- **Eigene Netze vorher in `NODE64_FIREWALL_ALLOW`** eintragen: feste öffentliche IPs von Büro, VPN-Gegenstelle,
  Monitoring, Backup-Ziel. Steht eine davon (z. B. durch eine gemeinsam genutzte IP) in der Liste, sperrt der Helfer
  sonst den eigenen Zugang – bei einem entfernten Server auch SSH. Wer gelistet ist, kann bei ipv64 eine Freigabe
  beantragen.
- `forward` betrifft auch Container und VMs hinter dem Host. Docker-Regeln selbst ändert Node64 nicht.
- Andere Firewall-Werkzeuge, die mit `nft flush ruleset` alles neu schreiben, löschen auch diese Tabelle; Node64 legt
  sie spätestens nach 30 Minuten wieder an.

## Beenden

`docker stop` (SIGTERM) schließt erst die Info-Seite, dann Log-Sensor, Syslog-Empfänger und alle Fallen, und
schreibt die noch gepufferten Ereignisse in die Datenbank. Der Firewall-Helfer löscht seine Tabelle (außer mit
`NODE64_FIREWALL_KEEP=1`).

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
