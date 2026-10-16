# CDN64 – Reverse-Proxy in Node64

Stand 2026-10-15 (CDN64 1.4.0). CDN64 ersetzt den Nginx Proxy Manager (NPM) und kommt ohne nginx aus: Node64 macht
HTTP/1.1, HTTP/2 und HTTP/3 selbst. Code: `internal/cdn64` (Modul), `internal/edge` (gemeinsamer Eingang 80/443),
`internal/certs` (Zertifikate), `internal/ports` (Port-Verwaltung). Plan und Entscheidungen:
[PLAN-NODE64-CDN64.md](PLAN-NODE64-CDN64.md).

## Einschalten und einrichten

1. **Modul einschalten:** *Einstellungen → Module → CDN64*.
   - Ist es aus, läuft nichts: keine Routen, keine Prüfungen, kein Cache, keine Erneuerung, die Ports sind zu.
2. **Router:**
   - Port 80 und 443 (TCP) auf die Node weiterleiten, für HTTP/3 zusätzlich 443/UDP.
   - Leitet der Router einen anderen Port weiter (z. B. 443 → 8443), unter *Einstellungen → Ports* den HTTPS-Port
     auf 8443 und „HTTPS-Port von außen“ auf 443 stellen.
3. **DNS:**
   - Die Domain muss auf den Anschluss zeigen, am besten als CNAME auf die DynDNS-Domain.
   - Für Domains bei ipv64 legt CDN64 den Eintrag beim Anlegen des Hosts auf Wunsch selbst an.
4. **Zertifikat:**
   - Menüpunkt *Zertifikate* (Kern, auch über den Reiter *SSL-Zertifikate*): Nutzungsbedingungen von Let's
     Encrypt annehmen, dann anfordern. Oder im
     Host-Formular „Neues Zertifikat gleich mit anfordern“.
5. **Docker:**
   - Empfohlen ist das Host-Netzwerk (`network_mode: host`), weil Streams beliebige Ports öffnen.
   - Im Bridge-Modus `-p 80:80 -p 443:443 -p 443:443/udp` und je Stream eine weitere Freigabe.
   - Ports unter 1024 gehen ohne Root (`cap_net_bind_service` im Image).

## Ports: Wie sich Module 443 teilen

Ein Port lässt sich je Adresse nur einmal öffnen. Deshalb gehören 80 und 443 dem **gemeinsamen Eingang** im Kern
und keinem Modul:

- **Verteilung:** Bei TLS wählt der Eingang nach dem Namen in der ersten Nachricht des Browsers (SNI) Zertifikat
  und Ziel. Bei HTTP entscheidet der Host-Kopf.
- **Abnehmer:**
  - CDN64 (Proxy-Hosts, Weiterleitungen, 404-Hosts, TLS durchreichen);
  - DNS64 (DoH unter `/dns-query`, auch per IP, ab DNS64 1.8.0);
  - Let's Encrypt (HTTP-01);
  - die Oberfläche von Node64 unter einem eigenen Namen.
- **Offen** sind die Ports nur, solange ein Abnehmer sie braucht. Besteht DoH allein, bleibt Port 80 zu.
- **Port-Verwaltung:** Die Übersicht unter *Einstellungen → Ports* zeigt, wer welchen Port belegt, und meldet
  Überschneidungen.
  - Streams prüfen ihren Port vor dem Öffnen; die Ports des Eingangs sind für Streams gesperrt.
  - Ein Port, den ein anderes Programm auf dem Host belegt, wird erkannt und mit Grund angezeigt.
- **Zwei Container oder IPs** braucht es nur, wenn ein anderes Programm auf demselben Host 443 will, etwa ein
  alter NPM.

## Host-Arten

| Art | Was | Besonderheiten |
|---|---|---|
| Proxy-Host | Domain(s) → Ziel `http(s)://host:port` | WebSockets, Block Common Exploits, Cache Assets, Locations, Zugriffsliste, Erweitert |
| Weiterleitung | Domain(s) → andere Domain | 301/302/303/307/308, Pfad mitnehmen, Schema wie Anfrage oder fest |
| 404-Host | Domain(s) → „nicht gefunden“ | z. B. für stillgelegte Namen |
| TLS durchreichen | Name auf 443 → Dienst mit eigenem Zertifikat | Node64 entschlüsselt nicht; Port 80 leitet auf HTTPS |
| Stream | Port (TCP/UDP) → Ziel | optional TLS-Abschluss (TCP); UDP-Sitzungen enden nach 60 s ohne Pakete |

**Das Ziel bekommt:**
- den Namen, unter dem der Besucher kam (einstellbar);
- `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` und `X-Real-IP`, und zwar nur mit der echten
  Gegenstelle. Kopfzeilen, die der Besucher mitschickt, werden verworfen, außer er kommt von einem eingetragenen
  vertrauenswürdigen Proxy (Cloudflare-Vorlage).

**Erreichbarkeit:**
- Ziele von Proxy-Hosts, Durchreich-Hosts und TCP-Streams werden jede Minute geprüft: TCP, bei HTTP dazu `HEAD /`.
- „Healthcheck dafür anlegen“ übernimmt das in das Modul Healthchecks, mit Benachrichtigungen.
- Überwacht ein Healthcheck genau dieses Ziel (gleicher Host und Port, Ping nur Host), zeigt die Tabelle ihn
  mit Zustand und Link an: „Healthcheck (lokal)“ für Checks dieser Node, sonst „ipv64/andere Node“. Das gilt
  auch für Checks, die von Hand angelegt wurden. API: Feld `healthchecks` am Host.

## Zertifikate

| Weg | Wann | Port offen? |
|---|---|---|
| ipv64 DNS-01 | Domain liegt im ipv64-Account (API-Key in den Einstellungen) | nein; auch Wildcards |
| Alias über ipv64 | fremde Domain; einmal CNAME `_acme-challenge.<name>` → `_acme-challenge.<präfix>.<ipv64-domain>` | nein; keine Zugangsdaten des Anbieters |
| Anderer DNS-Anbieter | 26 Anbieter, Liste in [ZERTIFIKATE.md](ZERTIFIKATE.md) | nein; DNS-Zugang hinterlegen |
| HTTP-01 | jede Domain, die per DNS auf den Anschluss zeigt | Port 80 |
| Eigenes Zertifikat | PEM hochladen | – |

- **Speicherung:** Schlüssel und Zugangsdaten liegen mit `secret.key` verschlüsselt in der Datenbank und sind
  damit im Backup.
- **Erneuerung:**
  - automatisch 30 Tage vor Ablauf, auch wenn CDN64 aus ist;
  - nach einem Fehler erst wieder nach 6 Stunden;
  - Meldungen an die Standardkanäle bei Fehlschlag (einmal je Störung), bei Entwarnung und 14 bzw. 3 Tage vor
    Ablauf.
- **Testumgebung (Staging)** gegen die Rate-Limits von Let's Encrypt.

## Zugriffslisten und Sicherheit

- **Zugriffslisten:**
  - Benutzer (bcrypt) und IP-Regeln (erster Treffer gilt, ohne Treffer gesperrt).
  - „Beides nötig“ oder „eine Bedingung genügt“.
  - Nach 10 Fehlversuchen in 5 Minuten ist die IP 15 Minuten gesperrt; die Sperre steht im Audit.
- **ipv64-Blocklisten (Reiter *Zugriffslisten*):**
  - Listen schadhafter IPs von ipv64.net per Schalter: Gesamtliste (empfohlen), Spamhaus DROP, FireHOL Level 1,
    blocklist.de, DShield und Tor-Exits; IPv4 und IPv6.
  - Gilt für alle Proxy-Hosts, Durchreich-Hosts und Streams. Abgewiesen wird an erster Stelle: beim
    Verbindungsaufbau, vor TLS und vor jeder Zugriffsliste. HTTP/3 bekommt 403. Hinter einem vertrauenswürdigen
    Proxy (Cloudflare) zählt zusätzlich die echte Client-IP.
  - Aktualisierung alle 30 Minuten (ETag), Zwischenspeicher in `/data/cdn64/blocklists`; ist ipv64.net nicht
    erreichbar, gilt der letzte Stand weiter.
  - Ausnahmen (IPs oder Netze) werden nie gesperrt. Der Zähler „abgewiesen“ steht auf der Karte und in der
    Statistik.
- **Block Common Exploits:** Regeln wie im NPM, dazu `.git`, `.env` und `wp-config.php`.
- **Fehlerseiten:** Neutrale Seiten (404, 403, 502, 508) verraten nichts über Node64 oder das Ziel. Unbekannte
  Namen bekommen die Standardseite: 404, Verbindung schließen, Weiterleitung oder eigenes HTML.
- **DNS bleibt im LAN:** DoH über 443 beantwortet DNS64 nur für Clients aus seiner Freigabeliste. Dabei zählt
  immer die echte Gegenstelle, nie ein Kopf. Andere bekommen eine neutrale 404. Port 53 und 853 nie im Router
  freigeben.
- **Oberfläche über den Eingang:** standardmäßig nur aus dem eigenen Netz; „aus dem Internet“ muss ausdrücklich
  eingeschaltet werden.

## Statistik und Protokoll

- **Anfragen je Host und Stunde** (2xx–5xx, Datenmenge) werden 90 Tage gehalten. Die Liste zeigt die letzten
  24 Stunden.
- **Verkehr in der Übersicht** (Reiter *Proxy-Hosts*): Diagramm mit Anfragen nach 2xx–5xx und Datenmenge
  für 24 Stunden, 7 Tage oder 30 Tage (dann je Tag), für alle Hosts oder einen. Dazu die Kennzahlen Anfragen,
  Datenmenge, Fehler und „abgewiesen“ (Exploits, Zugriffslisten, Blocklisten).
- **Zugriffs-Log** je Host einschaltbar (Reiter *Zugriffe*), 1–90 Tage, Client-IPs auf Wunsch gekürzt.
- **Ablage:** `/data/cdn64/cdn64.db`, nicht im Node-Backup.
- **Audit:** Alle Änderungen aus Oberfläche und API.

## Leistung (Lasttest auf der Testbox, 4 Kerne)

Client, Proxy und Ziel liefen auf derselben Maschine.

| Test | Ergebnis |
|---|---|
| 1.000 gleichzeitige HTTPS-Clients × 20 Anfragen | 14.400 Anfragen/s, p50 53 ms, p99 342 ms, 0 Fehler |
| 500 WebSockets gleichzeitig, je 10 Echos | 0,2 s, 0 Fehler |
| 10 Uploads à 100 MB gleichzeitig | 820 MB/s, Speicherspitze 73 MB (gestreamt) |
| Speicher | Modul aus: kein Zusatz; an mit 100 Hosts: ca. 2 MB |

Wiederholen: `go test -tags loadtest -run TestLoad -v ./internal/cdn64/`

## Umstieg vom Nginx Proxy Manager

| NPM | CDN64 |
|---|---|
| Proxy Hosts (Details, Custom Locations, SSL) | Proxy-Hosts mit Reitern Details, Locations, SSL, Erweitert |
| Advanced (nginx-Konfiguration) | Erweitert: Kopfzeilen, Host-Kopf, Timeout, Upload-Grenze, Puffern, gzip, vertrauenswürdige Proxys |
| Redirection Hosts / Streams / 404 Hosts | Weiterleitungen / Streams / 404-Hosts |
| Access Lists | Zugriffslisten |
| SSL Certificates (certbot-Plugins) | Zertifikate im Kern (ipv64, Alias, DNS-Anbieter, HTTP-01, eigene) |
| Default Site | Standardseite |
| – | TLS durchreichen, Erreichbarkeit, Healthcheck anlegen, DNS-Eintrag bei ipv64, HTTP/3 |

Einen Import gibt es nicht (Entscheidung). Hosts werden neu angelegt; Zertifikate holt CDN64 neu.

## Grenzen

- **Keine freie nginx-Konfiguration** (dafür die festen Felder unter „Erweitert“).
- **Keine Lastverteilung** auf mehrere Ziele, keine Rate-Limits je Host, keine GeoIP-Sperren (vorgemerkt).
- **TLS durchreichen** geht nur über TCP, nicht über HTTP/3.
- **Erreichbarkeit und Zähler „seit Start“** liegen im Speicher. Die Statistik in `cdn64.db` bleibt erhalten.
- **Anbindung an die ipv64-CDN-Server** (mit und ohne TLS-Terminierung, Tunnel): eigener Plan,
  [PLAN-NODE64-CDN64-ONLINE.md](PLAN-NODE64-CDN64-ONLINE.md).

## API (Auszug)

| Bereich | Endpunkte |
|---|---|
| Hosts, Streams, Standardseite | `/api/cdn64/hosts`, `/api/cdn64/streams`, `/api/cdn64/default` |
| Zugriffslisten, Log, Statistik, Einstellungen | `/api/cdn64/access-lists`, `/api/cdn64/log`, `/api/cdn64/stats`, `/api/cdn64/settings` |
| ipv64-Blocklisten | `GET\|PUT /api/cdn64/blocklists`, `POST /api/cdn64/blocklists/refresh` |
| Zertifikate (Kern) | `/api/certs`, `/api/certs/account`, `/api/certs/dns-accounts`, `/api/certs/dns-providers` |
| Ports und Eingang (Kern) | `/api/ports`, `/api/edge`, `/api/edge/ui` |

Alles mit Schemas in `/api/openapi.json` (Seite *API*).
