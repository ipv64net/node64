# Node64

Ein leichtgewichtiger Docker-Container für das Heimnetz: Healthchecks (als Uptime-Kuma-Alternative), DynDNS-Updater für ipv64, DNS64 als lokaler DNS-Resolver mit Blocklisten, Reverse-Proxy PROXY64 und CDN64 über die ipv64-Server, standalone oder verknüpft mit einem [ipv64.net](https://ipv64.net)-Account.

Ein einziges Go-Binary, SQLite, eingebettete Weboberfläche, keine externen Abhängigkeiten zur Laufzeit. Läuft auf amd64 und arm64, auch auf einem Raspberry Pi.

**Stand: Phase 5 (Betrieb).** Der erste Entwurf ist vollständig: Kern mit Setup, Login, Zwei-Faktor-Anmeldung (TOTP mit Wiederherstellungscodes), API-Keys, Modulsystem, Datenbank mit Migrationen, Backup und Wiederherstellung, Export und Import der Konfiguration, Audit-Log, Logs mit Log-Level je Bereich, Versionsprüfung per Opt-in. Healthchecks mit allen Typen, Scheduler, Oberfläche, Wartungsfenstern und JSON-API. Benachrichtigungen über E-Mail, Telegram, Discord, ntfy, Gotify, Pushover und Webhook. Was ipv64.net für die Verknüpfung bauen muss, steht in [docs/SYNC.md](docs/SYNC.md).

## Benachrichtigungen

Kanäle werden unter *Benachrichtigungen* angelegt und getestet. Standardkanäle bekommen alle Checks, die keine eigene Auswahl haben. Texte gehen in der Sprache des Kanals raus (Deutsch oder Englisch). Geheimnisse wie Bot-Tokens oder SMTP-Passwörter liegen verschlüsselt in der Datenbank, der Schlüssel in `/data/secret.key`.

Webhooks bekommen standardmäßig ein JSON mit `event_id`, `kind` (down, up, flapping_start, flapping_end, reminder, summary, test, dyndns_ip, dyndns_fail, dyndns_limit, dns64_upstream, dns64_upstream_ok, dns64_lists, dns64_cert), `status`, `check` (token, name, type, target), `reason`, `message`, `duration_seconds`, `node` und `url`. Ein eigener Body mit Platzhaltern wie `{{name}}` oder `{{status}}` ist möglich.

Gegen Alarmrauschen wirken Wiederholungen vor Alarm, Stabilisierung, Flatter-Erkennung, Sammelmeldungen ab drei gleichzeitigen Störungen, Ruhezeiten (nur kritische Checks alarmieren) und höchstens 60 Nachrichten je Kanal und Stunde. Links in Nachrichten brauchen die externe Adresse des Nodes in den Einstellungen der Benachrichtigungen.

### iGotify (iPhone)

[iGotify](https://github.com/androidseb25/iGotify-Notification-Assistent) bringt Nachrichten eines Gotify-Servers als
Push aufs iPhone (iGotify-Assistent neben Gotify, App „iGotify“ auf dem iPhone). Node64 sendet dafür an den
Gotify-Server – wie beim Kanal Gotify: Adresse des Gotify-Servers und App-Token einer Gotify-App, Priorität wie gewohnt;
ein Link zur Störung kommt als Klick-Ziel (`client::notification`) mit.

### Home Assistant

Der Kanal *Home Assistant* ruft den Webhook-Auslöser einer Automation auf: `POST <URL>/api/webhook/<Webhook-ID>` mit JSON. Einzutragen sind die Adresse von Home Assistant ohne Pfad (z. B. `http://homeassistant.local:8123`), die Webhook-ID (wie ein Passwort, verschlüsselt gespeichert, erscheint nicht in Fehlertexten) und optional *Zertifikat prüfen* (bei selbst signiertem Zertifikat im LAN abschalten). Gesendet wird nur von der Node, nicht vom ipv64-Server; *Nur lokal* in Home Assistant kann daher eingeschaltet bleiben. Home Assistant antwortet auf jede Webhook-ID mit 200 – ob die Automation lief, zeigt ihr Verlauf in Home Assistant. Netzwerkfehler und HTTP 5xx werden nach 1, 5 und 15 Minuten erneut versucht.

Felder unter `trigger.json`: `source` (immer `node64`), `kind` (wie beim Webhook, z. B. `down`, `up`, `test`, `dyndns_fail`), `state` (`down`, `up`, `degraded`, `unchecked`, `test` oder `info`), `title`, `message`, `url`, `time` (RFC 3339, UTC), `priority` (1–5), `event_id`, `check` (`name`, `token`, `type`, `target`, `critical`; beim Test leer) und `node` (Name der Node).

```yaml
alias: Node64-Meldung
triggers:
  - trigger: webhook
    webhook_id: node64-xyz   # eigene ID
    allowed_methods: [POST]
    local_only: true
actions:
  - action: notify.mobile_app_dein_handy
    data:
      title: "{{ trigger.json.title }}"
      message: "{{ trigger.json.message }}"
```

Bei einer Störung eine Lampe rot schalten:

```yaml
alias: Node64-Störung rot
triggers:
  - trigger: webhook
    webhook_id: node64-xyz
    allowed_methods: [POST]
    local_only: true
conditions:
  - condition: template
    value_template: "{{ trigger.json.state == 'down' }}"
actions:
  - action: light.turn_on
    target:
      entity_id: light.flur
    data:
      color_name: red
```

## Schnellstart

```bash
docker run -d --name node64 \
  -p 8080:8080 \
  -v node64-data:/data \
  --restart unless-stopped \
  ghcr.io/ipv64net/node64:latest
```

Danach `http://<host>:8080` öffnen. Beim ersten Start führt ein Assistent durch Sprache und Admin-Konto. Es gibt kein Standardpasswort.

### docker compose

```yaml
services:
  node:
    image: ghcr.io/ipv64net/node64:latest
    container_name: node64
    restart: unless-stopped
    ports:
      - "8080:8080"
      # - "8443:8443"   # optional HTTPS, dazu NODE64_HTTPS_PORT=8443 setzen
    volumes:
      - node64-data:/data
      # Optional: Docker-Container überwachen (siehe "Docker-Container prüfen")
      # - /var/run/docker.sock:/var/run/docker.sock:ro
    # group_add:
    #   - "996"   # Gruppe des Sockets: stat -c %g /var/run/docker.sock
    environment:
      NODE64_LOG_LEVEL: info
      # NODE64_HTTPS_PORT: 8443
      # NODE64_ADMIN_USER: admin            # nur beim allerersten Start
      # NODE64_ADMIN_PASSWORD: change-me    # nur beim allerersten Start
    read_only: true
    tmpfs:
      - /tmp
    # Für ICMP-Checks ohne Root: unprivilegiertes Ping erlauben
    sysctls:
      - net.ipv4.ping_group_range=0 65535
volumes:
  node64-data:
```

### Docker-Container prüfen

Der Check-Typ **Docker-Container** fragt die Docker-Engine-API nach dem Zustand eines Containers auf demselben Host (nur lesende Anfragen). Dazu braucht die Node Zugriff auf den Socket:

```yaml
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    group_add:
      - "996"   # stat -c %g /var/run/docker.sock
```

**Docker-Überwachung** (Menüpunkt **Healthchecks → Docker**, `/healthchecks/docker`): Ist der Socket erreichbar, richtet Node64 den Host automatisch ein und überwacht alle Container wie Proxmox-Gäste: alle 30 s Zustand, Health, Neustarts, Exit-Code/OOM, CPU (bezogen auf das CPU-Limit bzw. alle Kerne), RAM (ohne Page-Cache wie `docker stats`, bezogen auf das Limit bzw. den RAM des Hosts), Netz und Block-I/O mit Verlauf (1 h bis 30 Tage), Regeln mit Vererbung Host → Container (Störung, gestoppt, pausiert, Neustart, CPU/RAM-Schwellen, Verzögerung), Kanälen, Ruhezeiten und Wartungsfenstern. Störung sofort: unhealthy, Neustart-Schleife (3 Neustarts in 10 min bzw. Status restarting), beendet mit Fehler, OOM, dead – beendete Container nur, wenn sie laufen sollen (liefen schon einmal oder fest eingestellt). Label `node64.nomonitor=true` schließt einen Container aus. Ein Klick auf einen Container zeigt Werte, Graphen, Labels und seine Regeln. „Als Check führen“ legt zusätzlich einen Check vom Typ Docker an (Statusseiten, Sync, Uptime); vorhandene Docker-Checks werden automatisch zugeordnet. Ausschalten auf der Seite, Entfernen per API (dann keine automatische Einrichtung mehr; Docker-Checks bleiben). Checks ohne Container erscheinen als „Container fehlt“, ohne Socket zeigt die Seite die Docker-Checks und wie der Socket eingebunden wird. API: `GET /api/healthchecks/docker/containers` und `/api/healthchecks/docker/systems/{id}/…` (wie Proxmox), Prometheus `node64_docker_*`.

Bewertung des Check-Typs (angelehnt an Uptime Kuma): läuft = OK, läuft mit Healthcheck „healthy“ oder „starting“ = OK, Healthcheck „unhealthy“, gestoppt (mit Exit-Code, OOM), pausiert oder in einer Neustart-Schleife = gestört, nicht vorhanden = gestört. Docker-Checks stehen als normale Zeilen in der Healthchecks-Liste.

Docker-Checks laufen nur lokal auf der Node; sie lassen sich nicht online prüfen oder umhängen. Mit ipv64 verknüpft wird ihr Zustand trotzdem gemeldet und ist im Portal sichtbar.

**Sicherheit:** Wer den Docker-Socket hat, kann den Host steuern – auch mit `:ro` (das schützt nur die Datei, nicht die API). Die Node sendet ausschließlich GET-Anfragen. Wer das Risiko begrenzen will, setzt einen [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) mit `CONTAINERS=1` davor und trägt in der Node `NODE64_DOCKER_HOST=tcp://socket-proxy:2375` ein (oder je Check unter „Docker-Host“).

## Lokale API

Der Node stellt alles, was die Oberfläche kann, auch als JSON-API im eigenen Netz bereit: Status, Module, Einstellungen, Audit-Log, Logs, Backup, Benachrichtigungskanäle und das komplette Healthchecks-Modul. Die Referenz liegt im Node unter `/api/docs`, die maschinenlesbare Beschreibung (OpenAPI 3.1) unter `/api/openapi.json`.

Anmeldung mit einem API-Key aus den Einstellungen (`Authorization: Bearer node64_…`) oder mit der Browser-Sitzung. Ohne Anmeldung erreichbar sind nur `/api/health` (für Docker) und `/api/push/{token}` (Heartbeats).

![Healthchecks](internal/web/static/img/healthcheck_service_monitoring_ipv64.png)

### Healthchecks per API

Das Modul wird in den Einstellungen aktiviert. Check-Typen: `http`, `keyword`, `json` (Bedingungen auf eine JSON-Antwort, z. B. `status == ok`, `queue < 100`), `dns` (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, PTR, SOA; Erwartung z. B. enthält Wert, Regex, NXDOMAIN oder „zeigt auf meine öffentliche IP“), `icmp`, `tcp`, `port`, `cert`, `push`, `docker`.

Mit ipv64.net verknüpft bilden alle Nodes eines Accounts ein System: `nodes` legt fest, welche Nodes einen Check messen, `owner` zeigt, ob er dieser Node (`self`), einer anderen (`other`) oder nur ipv64 (`online`) gehört. Jede Node darf jeden Check ändern, pausieren, löschen und mit `run` sofort messen lassen. Misst sie ihn nicht selbst, geht der Auftrag über ipv64 an die messenden Nodes. Nur die Messstelle eines Docker-Checks bleibt bei der Node mit dem Container. Ohne Verbindung werden Änderungen gepuffert und nachgeliefert, bei gleichzeitigen Änderungen gewinnt die jüngere.

```bash
# Check anlegen
curl -X POST http://localhost:8080/api/checks -H "Authorization: Bearer node64_…" -H "Content-Type: application/json" -d '{
  "name": "Webseite", "type": "http", "target": "https://example.com/",
  "interval_seconds": 60, "retries": 1, "stabilize": 3,
  "params": {"accept_status": "200-299"}
}'
# Liste, Details, Messpunkte, Ereignisse, Statistik
curl -H "Authorization: Bearer node64_…" http://localhost:8080/api/checks
curl -H "Authorization: Bearer node64_…" "http://localhost:8080/api/checks/<token>/measurements?limit=50"
curl -H "Authorization: Bearer node64_…" "http://localhost:8080/api/checks/<token>/stats?range=24h"
# Diagrammdaten je Messstelle (diese Node, andere Nodes, ipv64-Standorte)
curl -H "Authorization: Bearer node64_…" "http://localhost:8080/api/checks/<token>/chart?range=24h"
# Heartbeat (Push-Check): der Dienst meldet sich selbst
curl http://localhost:8080/api/push/<token>
curl "http://localhost:8080/api/push/<token>?status=down&msg=backup+failed"
curl -X POST --data '{"files": 1200}' http://localhost:8080/api/push/<token>
```

Push-Checks lassen sich an jeder Node und bei ipv64 auslösen. Misst diese Node den Check nicht allein, gibt sie den Push über ipv64 an die anderen messenden Nodes weiter; ist das ohne Verbindung nicht möglich, antwortet sie mit 503.

Weitere Endpunkte: `PUT`/`DELETE /api/checks/{token}`, `POST .../pause|resume|run|clone`, `GET .../events|incidents|chart`, `GET /api/events`, `GET /api/incidents`, `GET|POST /api/maintenance`, `PUT|DELETE /api/maintenance/{id}`, `GET|POST /api/channels`, `POST /api/channels/{id}/test`, `GET /api/status`, `GET|PUT /api/settings`, `GET /api/backup`. Alles mit Parametern und Antworten unter `/api/docs`.

ICMP-Checks brauchen im Container entweder unprivilegiertes Ping (`sysctls: net.ipv4.ping_group_range=0 65535`, siehe compose oben) oder `cap_add: NET_RAW`.

## DynDNS-Updater

Das Modul *DynDNS* (in den Einstellungen einschalten) hält ausgewählte Domains und Records bei ipv64 mit der öffentlichen Adresse des Anschlusses aktuell. Ausgeschaltet läuft nichts.

- **ipv64-API-Key:** einmal unter *Einstellungen → ipv64-API-Key* eintragen (verschlüsselt gespeichert, mit Ablaufdatum). Damit wählst du unter *DynDNS → Ziel hinzufügen* die Namen aus deinem Account und je Name, was aktualisiert wird. Ohne Key lassen sich Ziele von Hand mit Token anlegen.
- **Sicherster Token:** Die Updates laufen nie mit dem API-Key, sondern mit dem Record-Token des Namens (sonst Domain-Token), im HTTP-Header.
- **Nur bei Änderung:** Die Node ermittelt ihre öffentliche IPv4/IPv6 über `ipv4.ipv64.net` bzw. `ipv6.ipv64.net` (alle 5 min, einstellbar) und fragt die ipv64-Nameserver direkt, was sie ausliefern. `update.php` wird nur bei einer Abweichung aufgerufen, denn auch `nochg` zählt auf das Tageslimit. Zwischen zwei Aufrufen liegen mindestens 5 s; Cooldown, Tageslimit, ungültiger Token, Konflikte und Records, die woanders ständig anders gesetzt werden, pausieren statt Limit zu verbrauchen.
- **IPv6-Modi:** Adresse dieses Hosts, nur Präfix (zonenweit, für Records mit Interface-ID wie `::1:2:3:4`), Präfix + eigene Interface-ID (nur dieser Record, stabil trotz Privacy-Adressen), Interface (stabile Adresse, nur mit `network_mode: host`), fest oder aus.
- **Router-IP:** Bei IPv4 sieht ipv64 automatisch die Adresse des Routers, nie die interne Container-Adresse. Bei IPv6 gibt es kein NAT: ohne IPv6 im Docker-Netz zeigt die Seite einen Hinweis (siehe [IPv4 und IPv6](#ipv4-und-ipv6)). Deuten die ersten Stationen ins Internet auf CGNAT (100.64.0.0/10) oder DS-Lite (192.0.0.1) hin, erscheint ein Hinweis mit Links zu ipv64.
- **Verlauf und Limit:** Jede Prüfung und jeder Aufruf steht im Verlauf (Aufbewahrung einstellbar). Mit API-Key zeigt die Seite das Update-Limit des Accounts. Benachrichtigungen (Adresswechsel, Fehler, Limit) gehen an die Standardkanäle, auch bei verknüpfter Node, nicht in der Ruhezeit. ipv64-Mail und -SMS laufen für Modul-Meldungen mit dem API-Key direkt über die ipv64-API (`POST /hc2/channels/{id}/send`), nicht über die hubs; ohne Verknüpfung liest die Node die Kanäle des Accounts über die API.
- **API und Export:** `GET /api/dyndns/status`, `GET|POST /api/dyndns/targets`, `GET|PUT|DELETE /api/dyndns/targets/{id}`, `POST /api/dyndns/targets/{id}/update`, `POST /api/dyndns/check`, `GET /api/dyndns/history`. Der Export enthält Ziele und Einstellungen ohne Tokens; der Import holt sie mit dem API-Key neu.

## DNS64 (lokaler DNS-Resolver)

Das Modul *DNS64* (in den Einstellungen einschalten) ist ein cachender DNS-Server fürs Heimnetz, der Werbung, Tracker und Malware über Blocklisten filtert. Ausgeschaltet läuft nichts und kein Port ist offen.

- **Einrichten:** Im Router (DHCP bzw. bei IPv6 per RDNSS/DHCPv6) die IPv4- und/oder IPv6-Adresse des Hosts als DNS-Server eintragen. DNS64 lauscht auf Port 53 (UDP und TCP, einstellbar unter *DNS64 → Einstellungen*) und antwortet nur privaten und direkt angeschlossenen Netzen, nie als offener Resolver im Internet.
- **IPv4 und IPv6 überall:** Ohne feste Adresse lauschen DNS, DoT, DoQ und DoH auf IPv4 und IPv6 gleichzeitig; erlaubt sind private IPv4-Netze, ULA (fd00::/8), Link-local und das eigene IPv6-/64. Zu den Upstream-Servern verbindet DNS64 nach Happy Eyeballs (IPv6 und IPv4 abwechselnd, der nächste Versuch nach 250 ms, die zuletzt erfolgreiche Familie zuerst); alle Vorlagen haben IPv4- und IPv6-Bootstrap-Adressen. Den Router für lokale Namen findet DNS64 über das IPv4- oder, ohne IPv4, das IPv6-Gateway (auch Link-local wie `fe80::1%eth0`). Ohne IPv6 im Container läuft alles nur über IPv4. Die Heimnetz-CA bestätigt nur private Adressen: Geräte, die DNS64 über eine öffentliche IPv6-Adresse ansprechen, nutzen für DoT/DoH einen Namen.
- **Docker:** Mit Host-Netzwerk sieht DNS64 die echten IPs der Geräte und findet den Router für lokale Namen selbst. Das Image erlaubt dem Binary Ports unter 1024, der Prozess läuft weiter ohne Root.

  ```yaml
  services:
    node:
      image: ghcr.io/ipv64net/node64:latest
      network_mode: host        # statt ports:, Oberfläche dann auf NODE64_HTTP_PORT (8080)
      volumes:
        - node64-data:/data
  ```

  Ohne Host-Netzwerk (Bridge) die Ports unter derselben Nummer freigeben (DNS64 prüft das über das Docker-Gateway und warnt, wenn ein Port fehlt), den Router für lokale Namen unter *Einstellungen* eintragen. Docker leitet per NAT weiter; je nach Docker-Einstellung (Userland-Proxy, IPv6 ohne ip6tables, manche NAS) erscheinen Geräte aber mit der Adresse des Docker-Gateways, und Geräte mit öffentlicher IPv6-Adresse gelten als fremdes Netz – echte Client-IPs nur mit Host-Netzwerk:

  ```yaml
      ports:
        - "8080:8080"
        - "53:53/udp"
        - "53:53/tcp"
        - "443:443/tcp"     # DoH (nur wenn eingeschaltet)
        - "853:853/tcp"     # DoT
        - "853:853/udp"     # DoQ
  ```

  Ist Port 53 auf dem Host schon belegt (z. B. `systemd-resolved` mit `DNSStubListener=yes`), meldet die Seite den Fehler, das Modul versucht es jede Minute erneut, und der Port lässt sich ändern.
- **Blocklisten:** Standard sind StevenBlack, AdGuard DNS, OISD Small, HaGeZi Multi, EasyPrivacy und URLhaus; dazu wählbar OISD Big, HaGeZi Pro/Pro++/Ultimate, HaGeZi Threat Intelligence, HaGeZi Pop-up Ads, Peter Lowe, HaGeZi Fake, HaGeZi Badware Hoster, Phishing Filter (malware-filter), HaGeZi DoH/VPN/Proxy Bypass, HaGeZi Native Tracker (Samsung, LG, Amazon, Apple, Windows/Office, Xiaomi, Huawei, TikTok, Roku), Kinderschutz (HaGeZi Gambling, HaGeZi NSFW, OISD NSFW; gelten für alle Geräte) und eigene Listen (hosts, Domain je Zeile, Adblock-Syntax). Aktualisierung alle 6–48 Stunden. Tracker hinter CNAMEs werden erkannt. Blockiert wird mit `0.0.0.0` bzw. `::` oder wahlweise NXDOMAIN. Freigaben gelten für die Domain samt Subdomains und gehen per Klick im Abfrage-Log. Internationalisierte Domains (IDN, z. B. `bücher.example`) auf Listen, in Freigaben und eigenen Einträgen werden automatisch als Punycode (`xn--bcher-kva.example`) übernommen.
- **Upstream:** verschlüsselt per DNS-over-HTTPS (`https://…`), DNS-over-TLS (`tls://name`, Port 853) oder DNS-over-QUIC (`quic://name`, Port 853), wählbar Cloudflare, Quad9, Google, AdGuard, Mullvad, die europäischen DNS4EU, dnsforge, Freifunk München, Digitalcourage oder eigene Server (mit Bootstrap-IPs, damit DNS64 sie ohne DNS erreicht; das Zertifikat wird auf den Namen geprüft). Betriebsart „Schnellste (automatisch)“ (Standard für neue Installationen): misst die angehakten Server laufend und fragt nur die schnellsten 1–3 gleichzeitig, die übrigen werden alle 30 s kurz nachgemessen und springen ein, wenn einer hängt oder ausfällt; daneben „Parallel“ (jede Anfrage an alle, schnellste gültige Antwort gewinnt) oder „Der Reihe nach“. Optimistischer Cache, Größe einstellbar (Standard 20.000).
- **Verschlüsselt im Heimnetz:** Geräte können DNS64 selbst per DNS-over-HTTPS (`https://<node>/dns-query`, Port 443; läuft über den gemeinsamen Eingang und teilt sich den Port mit PROXY64, nur Geräte aus den erlaubten Netzen bekommen eine Antwort, alle anderen ein neutrales 404), DNS-over-TLS und DNS-over-QUIC (Port 853) fragen; einzeln einschaltbar unter *DNS64 → Verschlüsselung*. Das Zertifikat stellt eine eigene Heimnetz-CA aus (enthält alle privaten IPs und eingestellten Namen; die CA darf nur private Adressen bestätigen; sie liegt in der zentralen Zertifikatsverwaltung, die das Zertifikat bei geänderten Namen oder IPs neu ausstellt), es kommt ein beliebiges Zertifikat aus der Zertifikatsverwaltung (z. B. Let's Encrypt, erneuert wird dort, DNS64 übernimmt es ohne Neustart) oder es wird das Zertifikat der Weboberfläche genutzt (`NODE64_TLS_CERT`). Zum Herunterladen: CA-Zertifikat und Profil für iPhone/iPad/Mac (DoH oder DoT). Android „Privates DNS“ braucht ein öffentlich gültiges Zertifikat: dafür in der Zertifikatsverwaltung ein Let's-Encrypt-Zertifikat für einen Namen unter deiner ipv64-Domain anlegen (DNS-01 über den ipv64-API-Key, der Name muss im Internet nicht erreichbar sein) und unter *DNS64 → Verschlüsselung* auswählen. Beim Update von DNS64 1.10 ziehen die Heimnetz-CA (gleicher Schlüssel, Geräte vertrauen ihr weiter) und ein vorhandenes Let's-Encrypt-Zertifikat von DNS64 einmal automatisch in die Zertifikatsverwaltung um.
- **Eigene Einträge:** A, AAAA, CNAME, TXT, MX, SRV, PTR und CAA, auch Wildcards (`*.home.lan`); zu A/AAAA gibt es die Rückwärtssuche (PTR) dazu (je Eintrag abschaltbar). Bearbeiten, Kommentar, Import/Export als Hosts-Datei, CSV oder JSON. Sie gelten sofort, kommen vor den Blocklisten und gehen nie ins Internet.
- **Weiterleitungen und Umschreiben:** Domain → eigene DNS-Server (IP, IP:Port, DoT, DoH, DoQ; z. B. `firma.local` an den VPN-DNS, ein Netz wie `192.168.0.0/16` als Rückwärtszone), Blocklisten gelten weiter (außer lokale Namen), bei Ausfall SERVFAIL statt Internet. Umschreiben: Name A antwortet wie Name B (auch `*.domain`).
- **Lokaler DNS (eigener Menüpunkt):** Zonen mit ihren Einträgen, SOA/TTL je Zone, Zonendatei (BIND) importieren/exportieren, dynamische Updates nach RFC 2136 mit TSIG (pfSense, OPNsense, Kea tragen DHCP-Namen selbst ein).
- **Lokale Zonen und Gerätenamen:** Zone wie `home.lan` beantwortet DNS64 selbst (SOA, unbekannte Namen NXDOMAIN oder weiter an den Router); Geräte der Gerätegruppen mit Bezeichnung erscheinen als `tablet-lea.home.lan` mit aktueller IP und Rückwärtssuche.
- **Cluster:** DNS64 gleicht Einstellungen, Blocklisten, Freigaben, eigene Einträge/Zonen, Weiterleitungen, Gruppen und Gruppen-Mitglieder ab – jeden Bereich einzeln unter „Cluster“ (Standard aus); Einträge und Weiterleitungen mit „nur diese Node“ bleiben lokal.
- **Datenschutz:** Client-Adressen im Abfrage-Log vollständig, gekürzt (IPv4 /24, IPv6 /48) oder gar nicht speichern. Weitere Client-Netze (z. B. ein öffentliches IPv6-Präfix) lassen sich erlauben, offen fürs Internet wird DNS64 nie.
- **Gerätegruppen:** Geräte lassen sich unter *DNS64 → Gruppen* zu Gruppen zusammenfassen (z. B. Kinder, Gäste), erkannt zuerst per MAC-Adresse aus der Nachbartabelle des Hosts (IPv4 und IPv6, nur im selben Netz und im Host-Netzwerk), sonst per IP oder Netz. Das Abfrage-Log zeigt und filtert die Gruppe. Je Gruppe: Blocklisten wie für alle oder eigene Auswahl, Kategorien sperren (Soziale Netzwerke, Spiele, Streaming, Glücksspiel, Erwachseneninhalte), eigene Freigaben und Sperren, SafeSearch (Google, Bing, DuckDuckGo, YouTube streng/mittel) und Schutz gegen Umgehen (fremde DoH/VPN/Proxys, iCloud Private Relay, Firefox-DoH). Firefox nutzt DNS64 auch global (use-application-dns.net, abschaltbar). Zeitpläne je Gruppe („Internet aus“ oder Kategorien, z. B. Mo–Fr 21–7 Uhr) und Knöpfe „Sperren“/„Frei“; gesperrte Geräte sehen bei http:// eine Hinweisseite der Node. Gruppen ziehen mit Export/Import um, Prometheus zählt je Gruppe, die API liefert den Zustand jeder Gruppe.
- **Lokale Namen:** `*.fritz.box`, `*.lan`, `*.home.arpa`, einzelne Hostnamen und Reverse-Lookups privater IPs gehen nur an den Router (IPv4- oder IPv6-Default-Gateway oder eingestellt), nie ins Internet. Gerätenamen der Clients kommen per PTR vom Router.
- **Blockieren pausieren:** oben rechts auf den DNS64-Seiten für 10 Minuten oder bis zum Wiedereinschalten; der DNS läuft weiter, nur die Blocklisten greifen nicht (API `POST /api/dns64/pause`, `POST /api/dns64/resume`).
- **Benachrichtigungen:** an die Standardkanäle, wenn ein Upstream-Server länger als 3 Minuten gestört ist (und wenn er wieder antwortet) und wenn eine Blockliste dreimal hintereinander nicht geladen werden kann; abschaltbar unter *DNS64 → Einstellungen*.
- **Daten:** unter `/data/dns64/` (Abfrage-Log `dns64.db`, Aufbewahrung 1–90 Tage, Abgelaufenes wird stündlich in Stücken gelöscht, Freigaben `allowlist.txt`, Blocklisten `lists/`); Einstellungen und eigene Einträge in der Datenbank der Node. Export/Import enthält Einstellungen, Freigaben und eigene Einträge.
- **API:** `GET /api/dns64/status|summary|timeline|top|log|lists|upstreams|cache`, `POST /api/dns64/cache/flush`, `GET|POST|DELETE /api/dns64/allowlist`, `GET|PUT /api/dns64/settings`, `GET|POST /api/dns64/records`, `PUT|DELETE /api/dns64/records/{id}`, `POST /api/dns64/records/{id}/enable|disable`, `POST /api/dns64/records/import`, `GET /api/dns64/records/export`, `GET|POST /api/dns64/forwards|rewrites`, `PUT|DELETE /api/dns64/forwards|rewrites/{id}`, `POST /api/dns64/forwards/{id}/enable|disable|test`, `POST /api/dns64/rewrites/{id}/enable|disable`, `GET|POST /api/dns64/zones`, `PUT|DELETE /api/dns64/zones/{id}`, `POST /api/dns64/zones/{id}/enable|disable`, `GET /api/dns64/device-names`, `GET /api/dns64/zones/{id}/zonefile`, `POST /api/dns64/allowlist/import`, `GET|POST /api/dns64/groups`, `PUT|DELETE /api/dns64/groups/{id}`, `POST /api/dns64/groups/{id}/move|members`, `DELETE /api/dns64/groups/members/{id}`, `PUT /api/dns64/groups/{id}/rules`, `POST /api/dns64/groups/{id}/domains`, `DELETE /api/dns64/groups/domains/{id}`, `POST /api/dns64/groups/{id}/hold|schedules`, `POST /api/dns64/groups/schedules/{id}/enable|disable`, `DELETE /api/dns64/groups/schedules/{id}`, `GET /api/dns64/devices`, `POST|DELETE /api/dns64/upstreams`, `POST|DELETE /api/dns64/lists`, `GET /api/dns64/ca.crt`, `GET /api/dns64/mobileconfig`.

## Ports, gemeinsamer Eingang und Zertifikate

Diese Teile gehören zum Kern und werden von Modulen genutzt, zuerst vom Reverse-Proxy PROXY64.

- **Ports:** *Einstellungen → Ports* zeigt in einer Tabelle alle Ports der Node (Oberfläche, Eingang/PROXY64 mit Streams, DNS64, Honeypot64 mit Syslog, was über den Web-Port oder den Eingang mitläuft, ausgehend der Tunnel von CDN64 online): eingestellt/offen, ob unter Linux wirklich ein Listener lauscht (`/proc/net`, im Container dessen Netz-Namensraum), Überschneidungen und Fehler der Module, Hinweise zu Ports unter 1024 und zur Docker-Weiterleitung. `GET /api/ports/probe?proto=tcp&port=443` prüft, ob ein Port auf dem Host frei ist.
- **Gemeinsamer Eingang:** HTTP (80) und HTTPS (443, auch HTTP/3 über 443/UDP) öffnet nur der Kern, und nur solange ein Modul sie braucht. Module melden dort ihre Namen an; verteilt wird nach dem Namen der TLS-Verbindung (SNI) und dem Host-Kopf, unbekannte Namen bekommen eine neutrale 404 (oder die Verbindung wird geschlossen). So teilen sich mehrere Module die Ports 80/443 in einem Container. Die Ports sind einstellbar, z. B. wenn der Router 443 auf 8443 weiterleitet (dann „HTTPS-Port von außen“ = 443).
- **Zertifikate (eigener Menüpunkt *Zertifikate*):** zentrale Verwaltung für PROXY64, DNS64, die Oberfläche und andere Geräte.
  - **Let's Encrypt:** für Namen im ipv64-Account per DNS-01 über den API-Key (auch Wildcards, Port 80 muss nicht offen sein); für fremde Domains per CNAME `_acme-challenge.<name>` → `_acme-challenge.<präfix>.<ipv64-domain>`, über einen von 26 DNS-Anbietern oder per HTTP-01.
  - **Weitere ACME-Stellen:** ZeroSSL, Google, SSL.com oder step-ca.
  - **Eigene CA:** auch für IP-Adressen, mit iOS-Profil.
  - **Hochladen** eigener Zertifikate.
  - **Herunterladen** als PEM, ZIP oder PKCS#12 und Abruf per API mit ETag.
  - **Schlüssel** liegen verschlüsselt in der Datenbank (im Backup enthalten).
  - **Erneuerung:** automatisch 30 Tage vor Ablauf; bei Fehlern und 14 bzw. 3 Tage vor Ablauf gibt es eine Meldung an die Standardkanäle.
  - Details und Beispiel-Skripte: [docs/ZERTIFIKATE.md](docs/ZERTIFIKATE.md).
- **Oberfläche unter eigenem Namen:** Optional ist die Node64-Oberfläche auch unter `https://<name>` über den Eingang erreichbar, standardmäßig nur aus dem eigenen Netz.
- **API:** `GET /api/ports`, `GET|PUT /api/edge`, `GET|PUT /api/edge/ui`, `GET|POST /api/certs`, `POST /api/certs/upload`, `GET|PUT /api/certs/account`, `GET /api/certs/domains`, `GET|PUT|DELETE /api/certs/{id}`, `POST /api/certs/{id}/renew`, `GET /api/certs/{id}/chain`, `GET /api/certs/{id}/meta`, `GET /api/certs/{id}/bundle`, `POST /api/certs/{id}/p12`, `GET|POST /api/cas`, `GET|POST /api/acme-cas` (vollständig in `/api/openapi.json`).

## PROXY64 (Reverse-Proxy)

Ausführlich: [docs/CDN64.md](docs/CDN64.md).

Das Modul *PROXY64* (in den Einstellungen einschalten; technisch `cdn64`, daher Pfade und API unter `/cdn64`) ersetzt den Nginx Proxy Manager: Proxy-Hosts leiten Anfragen für eine Domain an einen Dienst im Heimnetz weiter. Es braucht kein nginx, Node64 macht das selbst (HTTP/1.1, HTTP/2, HTTP/3). Ausgeschaltet läuft nichts und der gemeinsame Eingang schließt seine Ports.

- **Einrichten:** Im Router 80 und 443 (TCP, für HTTP/3 auch 443/UDP) auf die Node weiterleiten; die Domain per DNS auf den Anschluss zeigen lassen (z. B. CNAME auf die DynDNS-Domain). Die Ports teilt sich PROXY64 über den gemeinsamen Eingang mit anderen Modulen (siehe oben).
- **Proxy-Hosts:**
  - mehrere Domains je Host, auch Wildcards;
  - Ziel per http oder https, als Name oder IP mit Port;
  - das Ziel bekommt den ursprünglichen Host-Namen sowie `X-Forwarded-For/-Proto/-Host` und `X-Real-IP`, und zwar nur von der echten Gegenstelle;
  - das Zertifikat eines https-Ziels wird wie beim NPM nicht geprüft (je Host einschaltbar).
- **Optionen:**
  - WebSockets;
  - Block Common Exploits: Regeln wie beim NPM, dazu `.git`/`.env`, Antwort 403;
  - Cache Assets: Bilder, CSS, JS und Schriften im Speicher, zusammen höchstens 64 MB.
- **SSL:**
  - Zertifikat aus der Zertifikatsverwaltung, passend nach Namen oder fest gewählt, oder nur HTTP;
  - HTTPS erzwingen, HSTS (auch für Subdomains), HTTP/2, HTTP/3, mindestens TLS 1.2 oder 1.3.
- **Andere DNS-Anbieter:** Für Domains bei 26 Anbietern (u. a. Cloudflare, Hetzner, netcup, INWX, IONOS, ALL-INKL, deSEC, Namecheap, OVHcloud, dazu eigene Server mit PowerDNS, Technitium oder RFC 2136) lässt sich ein DNS-Zugang hinterlegen (verschlüsselt gespeichert). Damit geht DNS-01 dort auch, Wildcards inklusive. API: `GET /api/certs/dns-providers`, `GET|POST /api/certs/dns-accounts`, `PUT|DELETE /api/certs/dns-accounts/{id}`.
- **DNS-Eintrag bei ipv64:** Beim Anlegen eines Hosts optional für jede Domain im ipv64-Account einen CNAME (z. B. auf die DynDNS-Domain) oder A/AAAA anlegen. Vorhandene Einträge bleiben unverändert.
- **SSL-Zertifikate (eigener Menüpunkt *Zertifikate* im Kern, auch ohne PROXY64):** Liste mit Ablauf, „benutzt von“ und automatischer Erneuerung; anfordern bei Let's Encrypt automatisch, per ipv64 DNS-01, Alias über ipv64 (die Seite zeigt die nötigen CNAMEs) oder HTTP-01; eigene Zertifikate hochladen; Mail und Nutzungsbedingungen von Let's Encrypt. Im Host-Formular lässt sich ein Zertifikat gleich mit anfordern (API: `request_certificate`).
  Herunterladen als PEM, ZIP oder PKCS#12 und Abruf per API für andere Geräte (`/api/certs/{id}/bundle`), 26 DNS-Anbieter, eigene CA (auch für IP-Adressen, mit iOS-Profil) und weitere ACME-Stellen wie ZeroSSL oder step-ca. Die Oberfläche selbst nimmt ihr HTTPS-Zertifikat auf Wunsch ebenfalls aus der Zentrale (*Einstellungen → Allgemein → Erreichbarkeit dieser Node*): [docs/ZERTIFIKATE.md](docs/ZERTIFIKATE.md).
- **Erreichbarkeit:** Jedes Ziel wird jede Minute geprüft (TCP und eine kurze HEAD-Anfrage), die Liste zeigt die Antwortzeit bzw. „nicht erreichbar seit …“. Besucher eines nicht erreichbaren Ziels bekommen eine neutrale Seite 502. Ein Ziel, das auf den Proxy selbst zeigt, beantwortet er mit 508. Überwacht ein Healthcheck genau dieses Ziel (auch von Hand angelegt), steht er mit Zustand in der Tabelle („Healthcheck (lokal)“).
- **ipv64-Blocklisten:** Unter *Zugriffslisten* per Schalter die Listen von ipv64.net einschalten (u. a. Gesamtliste mit und ohne Tor, Spamhaus DROP, FireHOL Level 1, blocklist.de, DShield, Feodo Tracker, Tor, Netze von AWS und Google Cloud; IPv4 und IPv6). Die Auswahl kommt aus `index.json` von ipv64.net, neue Listen erscheinen ohne Update. Gesperrte IPs werden an erster Stelle abgewiesen, schon beim Verbindungsaufbau und vor TLS, für Hosts und Streams. Aktualisierung alle 30 Minuten, Ausnahmen möglich. API: `/api/cdn64/blocklists`.
- **Ländersperre:** je Host (Proxy, Weiterleitung, TLS durchreichen) und je Stream Länder sperren oder nur bestimmte zulassen, z. B. `DE, AT, CH`. Länderlisten täglich von ipv64.net, nur für genutzte Länder; private Netze und die Ausnahmen der Blocklisten werden nie gesperrt. API: `advanced.geo_mode`, `advanced.geo_countries` am Host, `geo_mode`, `geo_countries` am Stream.
- **Schutz vor Überlastung:** Wie beim HAProxy begrenzt PROXY64 Verbindungen und Anfragen je IP (IPv6 je /64), die Verbindungen insgesamt und die gleichzeitigen Anfragen je Ziel; wer dauernd abprallt, wird einige Minuten schon beim Verbindungsaufbau gesperrt. Ab Werk eingeschaltet mit Standardwerten für Browser, Apps und Sync-Clients, das Heimnetz ist ausgenommen. Einstellbar unter *Zugriffslisten*, je Host abschaltbar. API: `/api/cdn64/limits`.
- **CDN64:** Ein Klick in der Host-Liste macht einen Host über srv07/srv08.cdn64.de aus dem Internet erreichbar, per IPv4 und IPv6, auch an Anschlüssen nur mit IPv6 und ohne offene Ports. Die Node öffnet dazu einen Tunnel nach außen (QUIC, sonst TCP), meldet die Namen bei ipv64 an (DNS zeigt danach auf die Server) und prüft den Weg mit einem Selbsttest. TLS endet weiter in der Node (Modus 1). Im Heimnetz beantwortet DNS64 die Namen mit der Node selbst. Voraussetzung: verbundener ipv64-Account mit CDN-Domains. API: `/api/cdn64/online`, `/api/cdn64/hosts/{id}/online`. Details: [docs/CDN64.md](docs/CDN64.md#cdn64-srv07srv08).
- **Verkehr:** Die Übersicht der Proxy-Hosts zeigt ein Diagramm mit Anfragen (2xx–5xx) und Datenmenge für 24 Stunden, 7 oder 30 Tage, gesamt oder je Host.
- **Weiterleitungen und 404-Hosts:** Weiterleitungen gehen auf eine andere Domain (Code 301/302/303/307/308, Pfad mitnehmen, Schema wie die Anfrage oder fest). 404-Hosts antworten bewusst mit „nicht gefunden“. Beide mit denselben SSL-Optionen.
- **Streams:** Ein Port (TCP und/oder UDP) wird roh an ein Ziel weitergereicht, z. B. für Spiele-Server, MQTT oder WireGuard. Bei TCP geht optional ein TLS-Abschluss mit einem Zertifikat der Verwaltung. Belegte Ports werden erkannt und am Stream angezeigt. Im Bridge-Modus muss der Port zusätzlich am Container freigegeben sein.
- **TLS durchreichen:** Ein Name auf Port 443 geht ohne Entschlüsselung an einen Dienst mit eigenem Zertifikat. Die übrigen Namen auf 443 bleiben bei Node64.
- **Custom Locations:** Pfade eines Proxy-Hosts mit eigenem Ziel (z. B. `/api` auf einen anderen Dienst, optional mit anderem Pfad beim Ziel), eigener Zugriffsliste und eigenem WebSocket-Schalter.
- **Zugriffslisten:** Benutzer mit Passwort (bcrypt) und IP-Regeln (allow/deny, erster Treffer gilt). Dazu „beides nötig“ oder „eine Bedingung genügt“, auf Wunsch wird die Anmeldung an das Ziel weitergereicht. Nach 10 Fehlversuchen in 5 Minuten ist die IP 15 Minuten gesperrt.
- **Erweitert (statt freier nginx-Konfiguration):**
  - Kopfzeilen setzen bzw. entfernen;
  - Host-Kopf, Timeout zum Ziel, Upload-Grenze, nicht puffern, gzip;
  - vertrauenswürdige Proxys davor (Cloudflare-Vorlage), damit die echte Client-IP beim Ziel, in den Zugriffslisten und im Log ankommt.
- **Statistik und Zugriffs-Log:** Anfragen je Host und Stunde (90 Tage) immer; das Einzel-Log ist je Host einschaltbar (1–90 Tage, IPs auf Wunsch gekürzt). Beides liegt in `/data/cdn64/cdn64.db`, im Backup nur mit *Statistik mitsichern*.
- **Healthcheck dafür anlegen:** Ein Klick legt im Modul Healthchecks einen Check auf das Ziel an (HTTP oder TCP).
- **Standardseite:** Für unbekannte Namen oder den Aufruf per IP antwortet Node64 mit 404, schließt die Verbindung, leitet weiter oder zeigt eine eigene HTML-Seite.
- **API:** `GET /api/cdn64/status`, `POST /api/cdn64/check`, `GET|POST /api/cdn64/hosts` (`kind`: proxy, redirect, dead, passthrough), `GET|PUT|DELETE /api/cdn64/hosts/{id}`, `POST /api/cdn64/hosts/{id}/enable|disable`, `GET|POST /api/cdn64/streams`, `GET|PUT|DELETE /api/cdn64/streams/{id}`, `POST /api/cdn64/streams/{id}/enable|disable`, `GET|PUT /api/cdn64/default`, `GET|POST /api/cdn64/access-lists`, `GET|PUT|DELETE /api/cdn64/access-lists/{id}`, `GET /api/cdn64/log`, `GET /api/cdn64/stats`, `GET|PUT /api/cdn64/settings`, `POST /api/cdn64/hosts/{id}/healthcheck`, `POST /api/cdn64/streams/{id}/healthcheck`, `GET /api/cdn64/docker`.

### Proxy-Hosts aus Docker-Labels

Unter *PROXY64 → Docker* einschalten (standardmäßig aus). Dann legt PROXY64 für jeden Container mit Labels selbst einen
Proxy-Host an, wie Traefik. Namen, Schema und Ziel kommen aus den Labels und sind im Formular gesperrt (Abzeichen
**Docker**). Alles andere bleibt einstellbar und erhalten, auch CDN64 online – das wird nie per Label eingeschaltet.

```yaml
services:
  node64:
    # ... wie oben, dazu der Docker-Socket (siehe „Docker-Container prüfen“)
    networks: [proxy]
  whoami:
    image: traefik/whoami
    labels:
      - node64.proxy.host=app.example.de,www.example.de
      - node64.proxy.port=80        # optional, sonst der einzige freigegebene Port
      # - node64.proxy.scheme=https
      # - node64.proxy.network=proxy
    networks: [proxy]
networks:
  proxy: {}
```

- **Netz:** PROXY64 spricht den Container direkt an. Node64 und Container brauchen ein gemeinsames Docker-Netz, oder
  Node64 läuft mit `network_mode: host`; bei mehreren Netzen `node64.proxy.network` setzen.
- **Socket:** wie bei der [Docker-Überwachung](#docker-container-prüfen) (`docker.sock` lesend und `group_add`); die
  dortigen Sicherheitshinweise gelten auch hier. Mit [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)
  braucht PROXY64 `CONTAINERS=1` und `EVENTS=1`; die Adresse (z. B. `tcp://socket-proxy:2375`) unter *PROXY64 → Docker*
  eintragen.
- **Traefik-Labels** werden mitgelesen (abschaltbar): `Host(...)`-Regeln, Port und Schema des Service,
  `traefik.docker.network`. Middlewares und Pfad-Regeln nicht.
- **Container entfernt:** Der Host wird nach 2 Minuten gelöscht und bei CDN64 online abgemeldet; ein gestoppter
  Container behält seinen Host. Details: [docs/CDN64.md](docs/CDN64.md#docker-labels).

## Honeypot64 (Fallen-Dienste)

Das Modul *Honeypot64* (in den Einstellungen einschalten, standardmäßig aus) stellt Fallen-Dienste auf, die Angreifer anlocken: SSH und Telnet (Logins werden immer abgelehnt und mit Benutzername und Passwort erfasst), HTTP/HTTPS mit neutralen Login-Ködern und Einordnung der Web-Angriffe nach OWASP (SQL-Injection, Log4Shell, Path Traversal …), beliebige TCP-Ports (erste Bytes, z. B. RDP-Benutzername) und Port-Scan-Erkennung. Je Port wählbare Dienst-Profile (z. B. OpenSSH Debian/Ubuntu oder Dropbear, BusyBox- oder Linux-Telnet, MySQL oder MariaDB, nginx, Apache, Proxmox VE, Webmin, Home Assistant, Grafana, NAS, Elasticsearch) bestimmen Banner, Kopfzeilen, Antworten und Zertifikat; Hostname und Versionen variieren stabil je Sensor. Low Interaction: nichts wird ausgeführt, keine ausgehenden Verbindungen, Limits je IP. Profile `minimal`, `standard`, `full` oder eigene Auswahl; belegte Ports (PROXY64, DNS64, Streams) werden erkannt. Auswertung unter *Honeypot64*: Dienste, Verlauf, Top-IPs, Zugangsdaten, Pfade, User-Agents, letzte Ereignisse; Prometheus (`node64_honeypot_*`), optional Meldung bei neuen Angreifern. Daten lokal 7 Tage. API: `/api/honeypot/*`.

Optional zeigen die HTTPS-Fallen mit Webserver-Profil und SMTPS/IMAPS/POP3S ein gültiges Zertifikat aus der Zertifikatsverwaltung für glaubwürdige Köder-Namen (z. B. `mail.`, `vpn.` unter einer eigenen ipv64-Domain; die Namen stehen öffentlich in den CT-Logs); der angefragte Name (SNI) steht an jedem Ereignis. Außerdem überwacht das Modul die eigene Anmeldung von Node64 (Regel `node64/login@1`: ab 5 Fehlversuchen in 10 Minuten je öffentlicher IP ein Ereignis mit Benachrichtigung, ohne Benutzernamen oder Passwörter). Die Oberfläche von Node64 trotzdem nie offen ins Internet stellen.

Ohne Oberfläche als reiner Sensor (z. B. auf einem kleinen Raspberry Pi, auch armv7): `NODE64_MODE=honeypot`, Einstellung über Umgebungsvariablen, Info-Seite mit `/metrics` und `/health` auf Port 9064 (nur aus privaten Netzen oder mit Token). Einzelheiten: [docs/HONEYPOT64.md](docs/HONEYPOT64.md). Optional (Opt-in, braucht den ipv64-API-Key) meldet der Sensor alle 10 Minuten an ipv64 (Quell-IPs, Arten, Ports, Proben; nie private oder eigene IPs); ohne Oberfläche mit `NODE64_IPV64_KEY`, abschaltbar mit `NODE64_HONEYPOT_REPORT=0`. Die v64 Blocklist daraus folgt in einer späteren Version ([Plan](docs/PLAN-NODE64-HONEYPOT64.md)).

**Achtung:** Fallen-Dienste sind nur nützlich, wenn sie von außen erreichbar sind (Portfreigabe). Auf diesen Ports dürfen keine echten Dienste laufen.

## Betrieb

- **Backup:** Unter *Einstellungen → Daten & Sicherung* gibt es ein vollständiges Backup als Archiv (`.n64backup`, mit Passwort verschlüsselt): Datenbank (alle Tabellen aller Module, auch Honeypot-Ereignisse und Proxmox-/Docker-Verlauf), Schlüssel der Node (`secret.key`), die Dateien der Module unter `/data` (z. B. DNS64-Freigaben und -Zertifikate, Honeypot-Hostschlüssel, -Zertifikat und Sensor-Kennung, TLS der Oberfläche), auf Wunsch auch die Statistik von DNS64 und PROXY64. Nicht enthalten sind Zwischenspeicher, die die Node neu lädt (Blocklisten, Länderdaten `geoip/`), und alte Sicherungen unter `/data/backups`. Damit lässt sich die Node auch auf einer neuen Maschine wiederherstellen (`POST /api/backup`). Die reine Datenbank (`GET /api/backup`) ist nur auf derselben Node vollständig nutzbar. Nach der Wiederherstellung startet der Node neu (Docker startet ihn mit `restart: unless-stopped` automatisch); was ersetzt wird, bleibt unter `/data/backups` (die letzten fünf Stände je Art). Vor jeder Migration entsteht dort ebenfalls ein Backup (die letzten drei).
- **Zurücksetzen:** Unter *Einstellungen → Daten & Sicherung* setzt *Node zurücksetzen* (Passwort und Rückfrage) den Node auf den Auslieferungszustand: vorher meldet sich der Node online ab (Verknüpfung mit ipv64 trennen, CDN64-Namen und Tunnel bei ipv64 austragen, lokale Gruppe verlassen; Fehler dabei halten den Reset nicht auf), nach dem Neustart ist `/data` leer (Datenbank mit allen Tabellen, Schlüssel, Zertifikate, Dateien der Module wie Honeypot-Schlüssel und Sensor-Kennung, Zwischenspeicher, Backups) und die Einrichtung beginnt neu. Ein eigenes Zertifikat (`NODE64_TLS_CERT`/`NODE64_TLS_KEY`) unter `/data` bleibt erhalten; eigene Mounts unter `/data` werden geleert, nicht entfernt. Per API (`POST /api/reset`) nur mit dem Passwort des Benutzers, auch mit API-Key.
- **Export und Import:** Die Konfiguration als JSON, wahlweise ohne Geheimnisse oder mit Passwort verschlüsselt: Einstellungen der Node (Name, Ort, Zeitzone, Ruhezeiten, Datenhaltung, Schalter der MCP-Schnittstelle), Kanäle, Zertifikate (nur mit Passwort) und je eingeschaltetem Modul dessen Konfiguration – Healthchecks mit Wartungsfenstern, Proxmox-Systemen, Docker-Hosts und Statusseiten (mit Logo; Passwort-Hash nur mit Passwort), DynDNS-Ziele (Tokens holt der Import mit dem API-Key), DNS64 mit Gruppen, PROXY64 mit Hosts, Streams, Zugriffslisten und Honeypot-Schaltern, Honeypot64 mit Diensten, Log-Sensor und Syslog. Nicht enthalten: Messdaten, Verläufe und Logs, Benutzer, Sitzungen, API- und MCP-Schlüssel, Passkeys, SSO und Eingang (80/443), die Netze der Frühwarnung (liegen bei ipv64) und CDN64 online (gehört zur Node). Der Import gleicht Checks über den Token, Kanäle und Wartungsfenster über den Namen, Statusseiten über den Slug ab und löscht nichts.
- **Datenhaltung** (*Einstellungen → Daten & Sicherung*)**:** Einzelmessungen und Proxmox-/Docker-Verlauf (5 min) folgen *Einzelmessungen aufbewahren*, Stundenwerte, Ereignisse, abgeschlossene Störungen und Proxmox-Stundenwerte *Stundenwerte aufbewahren* (Proxmox-Minutenwerte 48 Stunden, Tageswerte der Checks unbegrenzt). Das Audit-Log hält 365 Tage (`audit.keep_days`: 90, 180, 365, 730 oder 0 = unbegrenzt, API `PUT /api/retention` mit `audit_days`), Zustellungen der Benachrichtigungen 90 Tage. Honeypot64 (Aufbewahrung und Obergrenze der Ereignisse), DNS64 (Abfrage-Log), PROXY64 (Zugriffs-Log; Stundenstatistik 90 Tage) und DynDNS (Verlauf) haben eigene Einstellungen.
- **Zwei-Faktor-Anmeldung:** TOTP mit jeder Authenticator-App, acht Wiederherstellungscodes.
- **Passwort vergessen:** `docker exec node64 /node64 reset-password` setzt im laufenden Container ein neues (zufälliges) Passwort und beendet alle Sitzungen; `-disable-2fa` schaltet zusätzlich die Zwei-Faktor-Anmeldung ab, `-user NAME` wählt den Benutzer (siehe [docs/ANMELDUNG.md](docs/ANMELDUNG.md)).
- **API-Keys:** Für Skripte gegen die lokale API, `Authorization: Bearer node64_...`. Keys werden nur einmal angezeigt und gehasht gespeichert.
- **KI-Schnittstelle (MCP):** Claude Code, Cursor, VS Code oder Claude Desktop fragen über `/mcp` den Zustand der Node ab (nur lesen, nur aus dem Heimnetz, eigene Schlüssel mit Rechten je Bereich, Standard aus). Einrichtung unter *Einstellungen → KI-Schnittstelle (MCP)*, Details: [docs/MCP.md](docs/MCP.md).
- **Schutz:** Login-Ratelimit, Ratelimit je IP für alle Anfragen, Push-URLs mit Mindestabstand, höchstens 60 Nachrichten je Kanal und Stunde.
- **Updates:** Optional prüft der Node täglich eine Versionsdatei bei ipv64.net. Es werden keine Daten gesendet.

## IPv4 und IPv6

Der Node ist durchgehend Dual-Stack: die Oberfläche lauscht auf IPv4 und IPv6, jeder Check hat einen Modus (`auto`, `ipv4`, `ipv6`, `both` = zwei getrennte Ergebnisse), ICMP pingt v4 und v6, Benachrichtigungen und die spätere ipv64-Verknüpfung nutzen beides. Vor jedem Check prüft der Node, ob die jeweilige Adressfamilie im Container überhaupt erreichbar ist, damit ein fehlendes IPv6 im Docker-Netz nicht als Störung des Ziels gemeldet wird.

Dasselbe gilt für die übrigen Teile:
- **Gemeinsamer Eingang:** 80/443 inklusive HTTP/3.
- **PROXY64:** Proxy-Hosts, TLS durchreichen und Streams (TCP/UDP), jeweils auch mit IPv6-Ziel wie `[fd00::5]:8080`. Zugriffslisten nehmen auch IPv6-Netze. Die echte Client-IP wird erkannt, auch bei IPv4-Clients über Dual-Stack-Sockets.
- **DNS64:** DNS, DoH, DoT und DoQ.
- **Zertifikate:** Die eigene CA stellt auch für IPv6-Adressen aus. Die Let's-Encrypt-Prüfung erreicht die Nameserver über IPv4 oder IPv6.

Live geprüft über `::1` und `127.0.0.1`.

Docker gibt Containern standardmäßig **kein IPv6**. Damit Checks per IPv6 laufen, dem Netz IPv6 geben (Docker 27+, compose):

```yaml
networks:
  default:
    enable_ipv6: true
    ipam:
      config:
        - subnet: fd00:64::/64   # ULA, Docker übernimmt NAT66
```

Alternativ `network_mode: host`. `net.ipv4.ping_group_range` gilt trotz des Namens auch für ICMPv6.

## Umgebungsvariablen

| Variable | Standard | Bedeutung |
| --- | --- | --- |
| `NODE64_DATA_DIR` | `/data` | Einziges beschreibbares Verzeichnis: Datenbank, Backups, Schlüssel, Zertifikat |
| `NODE64_HTTP_PORT` | `8080` | Port der Oberfläche, `0` = aus |
| `NODE64_HTTPS_PORT` | `0` | Port für HTTPS mit selbstsigniertem Zertifikat, `0` = aus |
| `NODE64_BIND_ADDR` | leer (alle) | Bind-Adresse |
| `NODE64_TLS_CERT` / `NODE64_TLS_KEY` | leer | Eigenes Zertifikat statt des selbstsignierten |
| `NODE64_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`; zur Laufzeit im UI änderbar |
| `NODE64_LOG_FORMAT` | `text` | `text` oder `json` |
| `NODE64_ADMIN_USER` / `NODE64_ADMIN_PASSWORD` | leer | Admin beim allerersten Start anlegen; danach ignoriert |
| `NODE64_TRUST_PROXY` | `false` | `X-Forwarded-For` auswerten, nur hinter eigenem Reverse Proxy |

## Sicherheit

- Laufzeit-Image `FROM scratch`: kein OS, keine Shell, nur das Binary. Nicht-Root (UID 65532), Root-FS read-only, nur `/data` beschreibbar.
- Passwörter mit argon2id, Sitzungen in der Datenbank, CSRF-Schutz, Login-Ratelimit, Security-Header, Content-Security-Policy ohne externe Quellen.
- Geheimnisse (später Kanal-Tokens, SMTP-Passwörter) werden mit einem Schlüssel aus `/data/secret.key` verschlüsselt. Im Log werden sie maskiert.
- Vor jeder Datenbank-Migration wird automatisch ein Backup nach `/data/backups` geschrieben.
- Keine Telemetrie. Versionsprüfung gegen ipv64 nur nach Opt-in (folgt).

## Entwicklung

Voraussetzung: Go 1.27 oder neuer. Kein CGO nötig.

```bash
make build          # Binary nach bin/node64
make test           # Tests
make run            # lokal mit ./data und Debug-Log
make docker         # Image für die eigene Architektur
make docker-multiarch PUSH=--push   # amd64 + arm64 über buildx
```

Projektstruktur:

```
cmd/node64/         main, Subcommands (healthcheck, version)
internal/checks/    Check-Bot (Phase 2), ohne Abhängigkeit zu web/store/scheduler/notify
internal/scheduler/ Intervalle, Retry, Worker-Pool, Zustandsautomat (Phase 2)
internal/store/     SQLite, Migrationen je Scope, Backups
internal/notify/    Benachrichtigungskanäle (Phase 4)
internal/web/       Handler, Templates, Sessions, Static (alles eingebettet)
internal/module/    Modulsystem mit Start/Stop zur Laufzeit
internal/i18n/      Sprachdateien de und en
internal/sync/      Stub für die spätere ipv64-Anbindung
internal/config/    Umgebungsvariablen
internal/logging/   slog mit Laufzeit-Level, Ringpuffer und Maskierung
```

## Lizenz

Apache-2.0, siehe [LICENSE](LICENSE).
