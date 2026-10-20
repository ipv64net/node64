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
  -v honeypot64:/data ghcr.io/ipv64net/node64
```

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
| `NODE64_IPV64_KEY` | – | API-Key für die Meldung an ipv64. **Wird bisher nur eingelesen**: die Meldung folgt in einer späteren Version (Phase H2), bis dahin bleiben alle Ereignisse lokal |
| `NODE64_DATA_DIR` | `/data` | Datenverzeichnis: Datenbank `node64.db`, Sensor-Dateien (SSH-Host-Schlüssel, TLS-Zertifikat) unter `honeypot/` |
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
| `/` | Info-Seite, nur lesend (kein Formular, kein JavaScript, hell/dunkel nach System, Deutsch oder Englisch nach Browser): Zustand der Dienste, Treffer 24 h und 7 Tage, Quell-IPs, Login-Versuche, Top-IPs, Arten, Ports, Zugangsdaten, Pfade, User-Agents, Version, Laufzeit. Aktualisiert sich jede Minute |
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
`node64_honeypot_up`, `node64_honeypot_info{version,profile}`, `node64_honeypot_uptime_seconds` sowie
`node64_honeypot_report_last_success_timestamp` und `node64_honeypot_report_errors_total` (bis zur Meldung an ipv64
immer 0). Die übrigen Kennzahlen der Node siehe [PROMETHEUS.md](PROMETHEUS.md).

### Docker-Healthcheck

Der `HEALTHCHECK` des Images (`/node64 healthcheck`) fragt in diesem Modus `/health` auf dem Info-Port über
`127.0.0.1`/`::1` (bzw. `NODE64_BIND_ADDR`) ab, mit Token, falls gesetzt. Mit `NODE64_HONEYPOT_INFO_PORT=0` gibt es
keine Prüfung über das Netz; der Container gilt dann als gesund, solange der Prozess läuft.

## Beenden

`docker stop` (SIGTERM) schließt erst die Info-Seite, dann alle Fallen, und schreibt die noch gepufferten
Ereignisse in die Datenbank.

## Ressourcen

Geschätzt 30–50 MB RAM. Die Ereignisse liegen in SQLite (`/data/node64.db`, Tabelle `hp_events`), standardmäßig
7 Tage und höchstens 200 000 Stück; Älteres wird stündlich gelöscht. Limits je Quell-IP und insgesamt verhindern,
dass ein Angreifer den Sensor überlastet; was darüber hinausgeht, wird verworfen und in
`node64_honeypot_dropped_total` gezählt.

## MikroTik RouterOS (geplant)

Geplant ist eine Anleitung für das Container-Paket von RouterOS: dasselbe Image (arm64 bzw. arm/v7), Profil
`minimal`, Speicher auf USB oder Platte, ab 256 MB RAM. Sie folgt mit dem Leitfaden (Phase H4).
