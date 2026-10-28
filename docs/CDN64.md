# PROXY64 – Reverse-Proxy in Node64

Stand 2026-10-15 (PROXY64 1.4.0). PROXY64 ersetzt den Nginx Proxy Manager (NPM) und kommt ohne nginx aus: Node64 macht
HTTP/1.1, HTTP/2 und HTTP/3 selbst. Code: `internal/cdn64` (Modul), `internal/edge` (gemeinsamer Eingang 80/443),
`internal/certs` (Zertifikate), `internal/ports` (Port-Verwaltung). Plan und Entscheidungen:
[PLAN-NODE64-CDN64.md](PLAN-NODE64-CDN64.md).

**Namen:** PROXY64 ist der lokale Reverse-Proxy der Node. CDN64 heißt nur das Veröffentlichen über die Server
srv07/srv08 (Abschnitt [CDN64](#cdn64-srv07srv08)). Technisch heißt das Modul weiter `cdn64`: Pfade `/cdn64/...`,
API `/api/cdn64/...`, Einstellungen `cdn64.*`, Metriken `node64_cdn64_*` und Ablage `/data/cdn64` bleiben gleich.

## Einschalten und einrichten

1. **Modul einschalten:** *Einstellungen → Module → PROXY64*.
   - Ist es aus, läuft nichts: keine Routen, keine Prüfungen, kein Cache, keine Erneuerung, die Ports sind zu.
2. **Router:**
   - Port 80 und 443 (TCP) auf die Node weiterleiten, für HTTP/3 zusätzlich 443/UDP.
   - Leitet der Router einen anderen Port weiter (z. B. 443 → 8443), unter *Einstellungen → Ports* den HTTPS-Port
     auf 8443 und „HTTPS-Port von außen“ auf 443 stellen.
3. **DNS:**
   - Die Domain muss auf den Anschluss zeigen, am besten als CNAME auf die DynDNS-Domain.
   - Für Domains bei ipv64 legt PROXY64 den Eintrag beim Anlegen des Hosts auf Wunsch selbst an.
4. **Zertifikat:**
   - Menüpunkt *Zertifikate* (Kern, auch über den Reiter *SSL-Zertifikate*): Nutzungsbedingungen von Let's
     Encrypt annehmen, dann anfordern. Oder im
     Host-Formular „Neues Zertifikat gleich mit anfordern“.
5. **Docker:**
   - Empfohlen ist das Host-Netzwerk (`network_mode: host`), weil Streams beliebige Ports öffnen.
   - Im Bridge-Modus `-p 80:80 -p 443:443 -p 443:443/udp` und je Stream eine weitere Freigabe.
   - Im Bridge-Modus prüft Node64, ob 80 und 443 auf dem Docker-Host wirklich veröffentlicht sind: eine Prüfanfrage
     geht über das Gateway (den Docker-Host) an denselben Port und muss bei PROXY64 ankommen. Fehlt ein Port, warnen
     die Host-Liste und *Einstellungen → Ports* („nicht veröffentlicht“) mit fertigen Angaben für `docker run` und
     `docker compose`. Ist der Port auf dem Host unter einer anderen Nummer veröffentlicht (z. B. `-p 8443:443`), diese
     Nummer unter „Port nach außen“ eintragen. HTTP/3 (UDP) lässt sich so nicht prüfen.
   - Ports unter 1024 gehen ohne Root (`cap_net_bind_service` im Image).

## Ports: Wie sich Module 443 teilen

Ein Port lässt sich je Adresse nur einmal öffnen. Deshalb gehören 80 und 443 dem **gemeinsamen Eingang** im Kern
und keinem Modul:

- **Verteilung:** Bei TLS wählt der Eingang nach dem Namen in der ersten Nachricht des Browsers (SNI) Zertifikat
  und Ziel. Bei HTTP entscheidet der Host-Kopf.
- **Abnehmer:**
  - PROXY64 (Proxy-Hosts, Weiterleitungen, 404-Hosts, TLS durchreichen);
  - DNS64 (DoH unter `/dns-query`, auch per IP, ab DNS64 1.8.0);
  - Let's Encrypt (HTTP-01);
  - die Oberfläche von Node64 unter einem eigenen Namen.
- **Offen** sind die Ports nur, solange ein Abnehmer sie braucht. Besteht DoH allein, bleibt Port 80 zu.
- **Port-Verwaltung:** Die Seite *Einstellungen → Ports* zeigt, wer welchen Port belegt, und meldet
  Überschneidungen. Dort stehen auch die Ports des Eingangs (HTTP, HTTPS, Port von außen, HTTP/3, unbekannte Namen).
  - Je Port: Modul, Zweck, Protokoll, Bind-Adresse, eingestellt/offen, ob wirklich ein Listener lauscht (Linux,
    `/proc/net/tcp|udp`, im Container dessen Netz-Namensraum) und der Fehler des Teils (z. B. „address already in
    use“, „permission denied“). Was über den Eingang läuft (Proxy-Hosts, DoH, Oberfläche unter eigenem Namen,
    Honeypot-Köder) und über den Web-Port (Cluster, MCP, Prometheus), steht als „mitgenutzt“ darunter; der Tunnel
    von CDN64 online als ausgehende Verbindung. Filter nach Modul und Zustand.
  - Name und Zertifikat der Oberfläche am Eingang stehen unter *Einstellungen → Allgemein → Erreichbarkeit dieser
    Node*; `POST /settings/edge` übernimmt sie nur noch, wenn das Formular die Felder enthält.
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

## Komprimierung

Schalter „Antworten komprimieren“ unter Erweitert (JSON-Feld `advanced.gzip`, Name aus der ersten Fassung); für neue
Proxy-Hosts **standardmäßig an**, bestehende Hosts behalten ihre Einstellung. Gewählt wird nach `Accept-Encoding`
des Browsers (`internal/httpcompress`):

| Antwort | Reihenfolge | Stufe |
|---|---|---|
| dynamisch | zstd → Brotli → gzip | zstd Standard, Brotli 4, gzip 5 |
| statische Datei mit „Cache Assets“ | Brotli → zstd → gzip | Brotli 9, zstd hoch, gzip 9 – einmal, dann aus dem Cache |

Komprimiert wird nur Status 200, Text/JSON/JS/XML/SVG/WASM/Schriften außer woff/woff2, ab 512 Byte, nicht bei Range,
HEAD, WebSocket, `Cache-Control: no-transform` oder wenn das Ziel schon komprimiert. Starke ETags werden dabei schwach
(`W/`). Der Cache liegt hinter der Komprimierung und hält je Verfahren eine Fassung. Gilt auch für CDN64 Modus 1 und
2 (die Antwort kommt von der Node; in Modus 2 spart es zusätzlich Verkehr im Tunnel).

Hinweis BREACH: Seiten, die ein Geheimnis (z. B. CSRF-Token) zusammen mit Eingaben eines Angreifers in derselben
Antwort ausliefern, können über die Größe der komprimierten Antwort angreifbar sein – dann den Schalter für diesen
Host ausschalten.

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
  - automatisch 30 Tage vor Ablauf, auch wenn PROXY64 aus ist;
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
- **Schutz vor Überlastung (Reiter *Zugriffslisten*):** wie Stick-Tables und `maxconn` beim HAProxy, ab Werk
  eingeschaltet. Gezählt wird je IPv4-Adresse bzw. je IPv6-/64.

  | Limit | Standard | Wirkung |
  |---|---|---|
  | Verbindungen je IP | 200 gleichzeitig | weitere werden vor TLS getrennt |
  | Neue Verbindungen je IP | 20/s, kurzzeitig 200 | weitere werden vor TLS getrennt |
  | Anfragen je IP | 50/s, kurzzeitig 500 | Antwort 429 mit `Retry-After` |
  | Gleichzeitig je Ziel | 200 je Proxy-Host | weitere warten bis 10 s, dann 503; WebSockets zählen nicht |
  | Verbindungen insgesamt | 10.000 | schützt die Node selbst |
  | Sperre | nach 300 Abweisungen in 1 Minute | 10 Minuten schon beim Verbindungsaufbau abgewiesen |

  - Ausgenommen: das Heimnetz (private Adressen, abschaltbar), die vertrauenswürdigen Proxys aller Hosts (dort
    zählt die echte Client-IP) und die Ausnahmen der Blocklisten. Je Host unter *Erweitert* „Ohne Limits je IP“
    (Anfrage-Limit und Grenze je Ziel entfallen, Verbindungs-Limits und Sperren bleiben).
  - Gilt für Proxy-Hosts, Weiterleitungen, 404-Hosts, durchgereichtes TLS (nur Verbindungen) und TCP-Streams.
  - 0 schaltet ein einzelnes Limit ab. Gesperrte Adressen stehen in der Karte und lassen sich freigeben; jede
    Sperre steht im Log. Der Zähler „abgewiesen“ geht in die Statistik ein.
- **Block Common Exploits:** Regeln wie im NPM, dazu `.git`, `.env` und `wp-config.php`.
- **KI-Bots (je Host, Reiter *Details*):**
  - „KI-Bots abweisen (User-Agent)“: Anfragen, deren User-Agent eine Kennung der Liste „v64 KI-Bots (User-Agent)“
    enthält, bekommen eine neutrale 403 (Grund „KI-Bot“ in Statistik und Zugriffs-Log). Die Liste ist ein
    täglicher Spiegel von [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) auf ipv64.net
    (`ipv64_ai_useragents.json`, rund 190 Kennungen); Node64 lädt nichts von GitHub. Groß/klein egal; die Kennung
    muss als eigenes Wort stehen („Spider“ trifft nicht „Baiduspider“).
  - „Nutzer-Abrufe auch sperren“ (Standard an): Abrufe auf Anfrage eines Nutzers (ChatGPT-User, Perplexity-User,
    Claude-User, Assistenten, Agenten). Aus = nur Crawler sperren.
  - `/robots.txt` wird nie gesperrt. „robots.txt mit KI-Sperre ausliefern“ (nur Proxy-Hosts): Hat das Ziel keine
    (404), liefert PROXY64 eine mit `Disallow: /` für alle Kennungen; eine eigene robots.txt bleibt unberührt.
  - Für Proxy-Hosts, Weiterleitungen und Statusseiten. Die Liste wird nur geladen, solange ein Host sie nutzt
    (alle 30 Minuten nur bei Änderung, Zwischenspeicher `/data/cdn64/blocklists/ai_useragents.json`; ohne
    ipv64.net gilt der letzte Stand). Stand und Zähler stehen auf der Karte der Blocklisten.
  - Zusätzlich gibt es die Blockliste „v64 KI-Bots (IP)“ (Kategorie KI-Bots): die offiziellen Netze von OpenAI,
    Perplexity, Common Crawl, Mistral und Google-Agent; sie sperrt wie jede Blockliste für alle Hosts schon beim
    Verbindungsaufbau.
  - Achtung: ai.robots.txt enthält auch `Applebot` (Siri/Spotlight) und `facebookexternalhit` (Link-Vorschau);
    wer das braucht, lässt die Sperre am betroffenen Host aus.
- **Fehlerseiten:** Neutrale Seiten (404, 403, 502, 508) verraten nichts über Node64 oder das Ziel. Unbekannte
  Namen bekommen die Standardseite: 404, Verbindung schließen, Weiterleitung oder eigenes HTML.
- **DNS bleibt im LAN:** DoH über 443 beantwortet DNS64 nur für Clients aus seiner Freigabeliste. Dabei zählt
  immer die echte Gegenstelle, nie ein Kopf. Andere bekommen eine neutrale 404. Port 53 und 853 nie im Router
  freigeben.
- **Oberfläche über den Eingang:** standardmäßig nur aus dem eigenen Netz; „aus dem Internet“ muss ausdrücklich
  eingeschaltet werden.

## Honeypot64 (Opt-in)

Karte **Honeypot64** auf dem Reiter Zugriffslisten (`/cdn64/access#honeypot`, API `GET/PUT /api/cdn64/honeypot`).
Drei Schalter, alle standardmäßig aus; wirken nur, wenn das Modul Honeypot64 auf derselben Node läuft (Verbindung über
`internal/hpbridge`, keiner der beiden Teile kennt den anderen):

| Schalter | Wirkung |
|---|---|
| Unbekannte Anfragen an den Honeypot | Anfragen ohne passenden Host (nur IP, fremde Domain, unbekannter Name, Port 80 und 443) bekommt der Web-Köder statt der Standardseite. Für unbekannte Namen gilt das Ersatz-Zertifikat – auch wenn als Standard „schließen“ eingestellt ist, solange der Köder da ist. |
| Zugriffe an den Honeypot geben | Je Anfrage (bekannte Hosts und unbekannte) gehen nur Metadaten an den Log-Sensor: Client-IP (nach den vertrauenswürdigen Proxys des Hosts), Host, bekannt ja/nein, Methode, Pfad ohne Abfrage, Status, TLS, fehlgeschlagene Anmeldung an der Zugriffsliste, User-Agent (nur zur Einordnung). Nie Inhalte. |
| Angreifer aus dem Honeypot sofort sperren | IPs, die der Honeypot meldet, sperrt PROXY64 für alle Hosts und Streams (Dauer einstellbar, 1–720 h, Standard 24 h), ohne auf die v64 Blocklist zu warten. Nie gesperrt: private Adressen, CGNAT, Ausnahmen der Blocklisten, vertrauenswürdige Proxys der Hosts. Liste im Speicher, höchstens 50 000 Einträge (voll: die am frühesten ablaufende weicht), nach einem Neustart leer. In der Karte mit Grund und Ende, einzeln aufhebbar (`DELETE /api/cdn64/honeypot/blocks/{ip}`). Ausschalten leert die Liste. |

Abweisungen erscheinen in Statistik und Protokoll mit dem Grund „vom Honeypot gemeldet“. Prometheus:
`node64_cdn64_honeypot_blocks`, `…_rejected_total`, `…_blocks_total`, `…_decoy_total`, `…_reported_total` (nur, wenn
ein Schalter an ist).

## CDN64 (srv07/srv08)

Ein Klick macht einen Host über **srv07.cdn64.de** (Nürnberg) und **srv08.cdn64.de** (Falkenstein) aus dem
Internet erreichbar, per IPv4 und IPv6, auch an Anschlüssen nur mit IPv6 (DS-Lite) und ohne offene Ports zu Hause.
Die Node baut dazu einen Tunnel nach außen auf (QUIC über UDP 7844, sonst TCP 7844). Planung und Betrieb:
[CDN64-ONLINE.md](CDN64-ONLINE.md).

- **Voraussetzung:** ipv64-Account verbunden (*Einstellungen › ipv64*) mit einer Account-Klasse, die CDN-Domains
  enthält. Das Kontingent (Domains, Traffic im Monat) teilen sich altes CDN und CDN64.
- **Einschalten:** In der Host-Liste in der Spalte *CDN64* auf *Einschalten*. Das Fenster zeigt vier
  Schritte:
  1. ipv64-Account prüfen; ohne Account geht es von dort zu *Account verbinden*.
  2. Tunnel zu srv07/srv08 anmelden und aufbauen. Der Token liegt verschlüsselt in der Node. Ist UDP gesperrt,
     läuft der Tunnel über TCP; ein zu kleiner UDP-Puffer des Docker-Hosts wird mit Befehl angezeigt.
  3. Namen bei ipv64 einschalten: Jeder Name des Hosts einzeln. Ab dann zeigt DNS mit TTL 10 auf beide Server;
     die bisherigen A/AAAA ruhen bei ipv64. Platzhalter-Namen (`*.`) werden übersprungen. Fehler kommen mit
     Abhilfe, z. B. Name nicht im Account, CNAME vorhanden, Kontingent voll. Auf Wunsch legt die Node gleich
     einen Online-Healthcheck auf den ersten Namen an.
  4. Selbsttest über das Internet: Jeder Name über jeden Server und jede Adresse (IPv4, IPv6). Ok heißt: Die
     Probe kam durch den Tunnel genau dieser Node an. Dazu der Hinweis, ob das Zertifikat für Besucher
     vertrauenswürdig ist und ob DNS schon umgestellt ist.
- **Modus 1 (Standard):** Die Server reichen TLS nur durch. Zertifikat und Schlüssel bleiben in der Node, die
  Server sehen keine Inhalte. Die echte Besucher-IP kommt in der Node an (Zugriffslisten, Limits und Log wirken
  wie gewohnt).
- **Modus 2:** TLS endet auf den Servern (HTTP/1.1, HTTP/2, HTTP/3). Dort greifen schon Blocklisten, Verbindungs-
  und Anfrage-Limits; jede Anfrage geht mit der echten Besucher-IP durch den Tunnel und gilt in der Node als HTTPS
  (keine Umleitung, Zugriffslisten und Log wie gewohnt). Das Zertifikat (Name und `*.Name`) holen die Server selbst
  bei Let's Encrypt; bis es da ist, reichen sie wie in Modus 1 durch. Port 80 leitet auf HTTPS um, ist die Node
  nicht erreichbar, zeigen die Server eine verständliche Seite. Geht nicht für *TLS durchreichen*. Wechsel 1 ↔ 2
  über den Knopf *Modus wechseln* in der Liste, ohne DNS-Änderung.
- **Modus 3:** ohne Tunnel – die Server gehen direkt zum Ziel des Proxy-Hosts. Nur, wenn das Ziel öffentlich
  erreichbar ist (öffentliche IP oder Name); für Ziele im Heimnetz Modus 1 oder 2. Ohne Node64 lässt sich Modus 3
  auf ipv64.net unter *CDN64* einrichten (Ziel aus den DNS-Einträgen oder fest, Frontend-Stufe, Cache, Liste).
- **Liste:** Je Server ein Abzeichen: grün = Tunnel verbunden, blau = über den anderen Server erreichbar,
  rot = kein Tunnel. Dazu „gesperrt“ (z. B. Traffic aufgebraucht), *Selbsttest*, *+n einschalten* (neue Namen am
  Host) und *Ausschalten*.
- **Ausschalten** schaltet die Namen bei ipv64 aus (DNS zeigt wieder auf die alte Adresse); mit dem letzten Namen
  wird auch der Tunnel abgemeldet. Wird ein Host gelöscht oder verliert er einen Namen, trägt der Abgleich (jede
  Minute) ihn bei ipv64 aus. Ein angelegter Healthcheck bleibt bestehen.
- **Im Heimnetz:** DNS64 dieser Node beantwortet eingeschaltete Namen mit ihrer eigenen Adresse im Netz des
  Fragenden (geteilter DNS). Aufrufe von zu Hause gehen so nicht über srv07/srv08. Läuft die Node im
  Docker-Bridge-Netz, bleibt es bei der normalen Antwort.

## Statistik und Protokoll

- **Anfragen je Host und Stunde** (2xx–5xx, Datenmenge, abgewiesen) werden 90 Tage gehalten. Die Liste zeigt
  die letzten 24 Stunden.
- **Verkehr in der Übersicht** (Reiter *Proxy-Hosts*): dasselbe Diagramm wie auf dem Dashboard (gemeinsames
  Skript `cdn64-chart.js`): Anfragen (blau) und Abgewiesene (rot) gestapelt, Datenverkehr als Linie; 24 Stunden,
  7 oder 30 Tage (dann je Tag), alle Hosts oder einer. Dazu die Kennzahlen Anfragen, Datenverkehr, Fehler und
  Abgewiesen im Zeitraum.
- **Abweisungen** werden immer erfasst und protokolliert, auch ohne Zugriffs-Log am Host:
  - Gründe: ipv64-Blockliste, Sperre (Überlastung), zu viele Verbindungen, zu viele neue Verbindungen,
    Verbindungen insgesamt voll, zu viele Anfragen (429), Ziel ausgelastet (503), Exploit-Sperre, KI-Bot,
    Zugriffsliste (403/429; die normale Passwortabfrage 401 zählt nicht).
  - Verbindungen, die schon vor der ersten Anfrage getrennt werden (am Eingang oder bei Streams), stehen als
    „Verbindung abgewiesen“ ohne Host; im Diagramm nur bei „alle Hosts“.
  - Im Log je Adresse, Grund und Host höchstens ein Eintrag alle 10 Sekunden und höchstens 600 je Minute; gezählt
    wird jede Abweisung. Filter „Abgewiesen“ auf dem Reiter *Zugriffe*.
  - Sperren, „Verbindungen insgesamt voll“ und „Ziel ausgelastet“ stehen zusätzlich als Warnung im Log der Node
    (*Logs*, je Art höchstens einmal pro Minute).
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

## Docker-Labels

Seit PROXY64 1.36.0 legt PROXY64 Proxy-Hosts auf Wunsch selbst aus den Labels der Container an – wie Traefik, ohne
Formular. Einschalten unter *PROXY64 → Docker* (Schalter „Docker-Labels auswerten“, **standardmäßig aus**). Der Host ist
danach ein ganz normaler Proxy-Host: Blocklisten, Zugriffslisten, WAF/JA4, Länder- und Ratensperren, Honeypot64,
Zertifikate, CDN64 online und die Statistik greifen unverändert.

| Label | Pflicht | Bedeutung |
|---|---|---|
| `node64.proxy.host` | ja | Namen, durch Komma getrennt (`app.example.de,www.example.de`) |
| `node64.proxy.port` | nein | Port im Container; fehlt er, gilt der einzige freigegebene (`EXPOSE`) Port, sonst Hinweis „Port fehlt“ |
| `node64.proxy.scheme` | nein | `http` (Standard) oder `https` |
| `node64.proxy.network` | nein | Docker-Netz, über das PROXY64 den Container erreicht (bei mehreren Netzen) |
| `node64.proxy.access` | nein | Name einer Zugriffsliste (seit 1.37.0); fehlt das Label, wird die Liste in der Oberfläche gewählt |

```yaml
services:
  node64:
    image: ghcr.io/ipv64net/node64:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    group_add:
      - "996"   # stat -c %g /var/run/docker.sock
    networks: [proxy]
  whoami:
    image: traefik/whoami
    labels:
      - node64.proxy.host=app.example.de
      - node64.proxy.port=80
    networks: [proxy]
networks:
  proxy: {}
```

- **Ein Container = ein Proxy-Host** (mehrere Namen möglich). Kennung ist der Container-Name, er bleibt bei
  `docker compose up` gleich.
- **Aus den Labels, im Formular gesperrt:** Namen, Schema, Ziel. Die Host-Liste zeigt das Abzeichen **Docker** (Tooltip:
  Container), das Formular den Hinweis „Kommt aus den Docker-Labels von Container …“.
- **In der Oberfläche einstellbar und bleibt erhalten** (Neustart, Neuanlegen): CDN64 online samt Modus,
  Zugriffsliste (außer sie kommt per Label, dann ist das Feld gesperrt), Schutz/WAF, Länder, Locations, Erweitert,
  Zertifikat, HTTP/2/3, HSTS. Ausschalten geht, Löschen nur bei ausgeschaltetem Schalter „Docker-Labels auswerten“
  (sonst Label bzw. Container entfernen).
- **Schutz fehlt → Host aus** (seit 1.38.2): Verlangt ein Label eine Zugriffsliste, die es nicht gibt, oder eine
  Traefik-Middleware, die PROXY64 nicht abbilden kann, wird ein neuer Host **ausgeschaltet** angelegt (Hinweis unter
  *Docker*), damit ein Dienst nie ungeschützt erreichbar wird. Ein vorhandener Host behält seine bisherige Liste.
- **CDN64 online** wird nur in der Oberfläche eingeschaltet, nie per Label.
- **Zertifikat:** Unter *Docker* lässt sich ein Weg wählen (automatisch, ipv64 DNS-01, HTTP-01, DNS-Zugang), auf dem für
  neue Docker-Hosts ein Zertifikat angefordert wird; die Nutzungsbedingungen von Let's Encrypt werden dort einmal
  angenommen. Ohne Weg nimmt der Host ein passendes vorhandenes Zertifikat (z. B. Wildcard), sonst nur HTTP.

**Ziel-Adresse.** PROXY64 verbindet sich direkt mit dem Container, nicht über freigegebene Ports. Reihenfolge:
`node64.proxy.network` → gemeinsames Docker-Netz mit dem Node64-Container → bei Node64 mit `network_mode: host` die IP
im (ersten) Bridge-Netz des Containers → freigegebener Port auf dem Docker-Host (über das Gateway). Geht nichts davon,
wird der Host angelegt, zeigt aber „nicht erreichbar“ mit Hinweis. Die IP wird bei jedem Start neu gelesen.

**Abgleich.** Beim Start und alle 5 Minuten die volle Liste, dazwischen lösen Docker-Ereignisse (`start`, `die`,
`destroy`, `rename`) einen Abgleich aus. Die Seite *Docker* zeigt Verbindung, letzten Abgleich und alle Container mit
Labels: übernommen (Link zum Host) oder der Grund, warum nicht.

**Stopp, Entfernen, Update.**
- Container gestoppt: Der Host bleibt, Besucher sehen 502 („Dienst nicht erreichbar“).
- Container entfernt oder `node64.proxy.host` entfernt: Der Host wird nach **2 Minuten** Wartezeit gelöscht und bei
  CDN64 online abgemeldet. Die Wartezeit fängt `docker compose up` ab (Container wird gelöscht und gleich mit gleichem
  Namen neu angelegt) – Einstellungen und CDN64-Anmeldung bleiben so erhalten.
- Docker nicht erreichbar oder Liste fehlerhaft: Es wird nichts gelöscht, nur der Fehler angezeigt.
- War Node64 aus, als ein Container entfernt wurde, holt der nächste Abgleich das Löschen nach.

**Konflikte.** Gehört ein Name schon zu einem von Hand angelegten Host, gewinnt dieser; der Container wird nicht
übernommen (Hinweis). Zwei Container mit demselben Namen: der zuerst gesehene gewinnt. Stehen eigene und
Traefik-Labels am selben Container, gelten nur die eigenen.

**Traefik-Labels** (Schalter „Traefik-Labels mitlesen“, an, solange Docker-Labels an sind). Ausgewertet werden nur:
- `traefik.enable` (`false` → ignorieren),
- `traefik.http.routers.<r>.rule` mit `Host(...)`, auch mehrere mit `||` oder `` Host(`a`, `b`) ``; andere Regeln
  (`PathPrefix`, `Headers` …) → Router übersprungen, Hinweis „Regel nicht unterstützt“,
- `traefik.http.routers.<r>.service` bzw. der einzige Service,
- `traefik.http.services.<s>.loadbalancer.server.port` und `.scheme`,
- `traefik.docker.network`,
- `traefik.http.routers.<r>.middlewares` (seit 1.37.0/1.38.2):
  - Middleware mit `forwardAuth` in den Labels → Zugriffsliste „Traefik: <name> (<Adresse>)“ mit Anmeldedienst
    (Forward-Auth), Antwort-Header werden übernommen;
  - Arten ohne Zugriffsschutz (`headers`, `redirectScheme`, `redirectRegex`, `compress`, `stripPrefix`, `addPrefix`,
    `replacePath`, `rateLimit`, `inFlightReq`, `retry`, `buffering`, `circuitBreaker`, `errors`, `contentType`) werden
    übergangen;
  - alle anderen (`name@file`, `basicAuth`, `ipAllowList`, `chain`, nicht definierte) brauchen eine Zugriffsliste
    gleichen Namens, sonst kommt der Host ausgeschaltet.

Entrypoints, `tls.certresolver` (Zertifikate macht PROXY64) sowie TCP/UDP-Router werden ignoriert. Router für
`/outpost.goauthentik.io/` übergeht PROXY64 (das macht die Zugriffsliste selbst). Je Router entsteht ein Host; zwei
Router mit denselben Namen und demselben Dienst (z. B. `web` mit Umleitung auf HTTPS und `websecure`) ergeben einen
Host, maßgeblich ist der mit den wenigsten nicht übernommenen Middlewares.

**Cluster.** Docker-Hosts gehören zu dem Docker-Host, auf dem die Node läuft, und werden nicht an andere Nodes verteilt.

**Export/Import.** Ein Import übernimmt Docker-Hosts als normale, von Hand angelegte Hosts (ohne Docker-Kennung).
Laufen auf der neuen Box dieselben Container mit Labels, meldet *Docker* dann „Name gehört einem von Hand angelegten
Host“ – den importierten Host löschen, beim nächsten Abgleich übernimmt ihn Docker wieder (Einstellungen neu setzen).

**Sicherheit.**
- Wer den Docker-Socket hat, kann den Host steuern – auch mit `:ro`. PROXY64 sendet nur GET-Anfragen
  (`/containers/json`, `/containers/{id}/json`, `/events`). Sicherer ist ein
  [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) mit `CONTAINERS=1` und `EVENTS=1` (alles
  andere aus); unter *Docker* dann z. B. `tcp://socket-proxy:2375` eintragen. Entfernte Docker-Hosts (SSH) gehen hier
  nicht.
- Wer Container starten darf, kann damit nur **lokale** Proxy-Hosts anlegen: nichts ins Internet stellen (CDN64 online
  nur über die Oberfläche) und keine von Hand angelegten Hosts überschreiben.
- Ziele sind nur Container auf diesem Docker-Host (Container-IP bzw. Gateway), nie beliebige Adressen aus einem Label.

## Umstieg vom Nginx Proxy Manager

| NPM | PROXY64 |
|---|---|
| Proxy Hosts (Details, Custom Locations, SSL) | Proxy-Hosts mit Reitern Details, Locations, SSL, Erweitert |
| Advanced (nginx-Konfiguration) | Erweitert: Kopfzeilen, Host-Kopf, Timeout, Upload-Grenze, Puffern, Komprimierung (zstd/Brotli/gzip), vertrauenswürdige Proxys |
| Redirection Hosts / Streams / 404 Hosts | Weiterleitungen / Streams / 404-Hosts |
| Access Lists | Zugriffslisten |
| SSL Certificates (certbot-Plugins) | Zertifikate im Kern (ipv64, Alias, DNS-Anbieter, HTTP-01, eigene) |
| Default Site | Standardseite |
| – | TLS durchreichen, Erreichbarkeit, Healthcheck anlegen, DNS-Eintrag bei ipv64, HTTP/3 |

Einen Import gibt es nicht (Entscheidung). Hosts werden neu angelegt; Zertifikate holt PROXY64 neu.

## Grenzen

- **Keine freie nginx-Konfiguration** (dafür die festen Felder unter „Erweitert“).
- **Keine Lastverteilung** auf mehrere Ziele, keine Rate-Limits je Host, keine GeoIP-Sperren (vorgemerkt).
- **TLS durchreichen** geht nur über TCP, nicht über HTTP/3.
- **Erreichbarkeit und Zähler „seit Start“** liegen im Speicher. Die Statistik in `cdn64.db` bleibt erhalten.
- **CDN64** kann bisher nur Modus 1 (durchreichen) und nur Namen in Domains des ipv64-Accounts; Modus 2
  und 3 folgen ([CDN64-ONLINE.md](CDN64-ONLINE.md)).

## API (Auszug)

| Bereich | Endpunkte |
|---|---|
| Hosts, Streams, Standardseite | `/api/cdn64/hosts`, `/api/cdn64/streams`, `/api/cdn64/default` |
| Docker-Labels | `GET /api/cdn64/docker` (Einstellungen, Verbindung, Container) |
| Zugriffslisten, Log, Statistik, Einstellungen | `/api/cdn64/access-lists`, `/api/cdn64/log`, `/api/cdn64/stats`, `/api/cdn64/settings` |
| ipv64-Blocklisten | `GET\|PUT /api/cdn64/blocklists`, `POST /api/cdn64/blocklists/refresh` |
| Schutz vor Überlastung | `GET\|PUT /api/cdn64/limits`, `DELETE /api/cdn64/limits/bans/{ip}` |
| CDN64 | `GET /api/cdn64/online`, `POST /api/cdn64/online/tunnel`, `POST\|DELETE /api/cdn64/hosts/{id}/online`, `POST /api/cdn64/hosts/{id}/online/test` |
| Zertifikate (Kern) | `/api/certs`, `/api/certs/account`, `/api/certs/dns-accounts`, `/api/certs/dns-providers` |
| Ports und Eingang (Kern) | `/api/ports`, `/api/edge`, `/api/edge/ui` |

Alles mit Schemas in `/api/openapi.json` (Seite *API*).
