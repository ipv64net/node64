# Plan: Modul CDN64 (Reverse-Proxy) in Node64

Stand 2026-10-15, Grundsatzfragen entschieden (siehe „Entscheidungen“) – noch nichts umgesetzt. Ziel: ein Reverse-Proxy-Manager im Funktionsumfang
des Nginx Proxy Manager (NPM), als Modul von Node64, leichter und mit ipv64 als bevorzugtem Weg zu Zertifikaten.
Ist das Modul aus, laufen keine Goroutinen, kein Port ist offen und es wird nichts erneuert.

Im Menü steht schon der Platzhalter `proxy` (Logo `cdn64.webp`, Pfad `/proxy`, `cmd/node64/main.go`). Er wird durch
das Modul ersetzt.

## Was der NPM kann und was CDN64 daraus macht

| NPM | CDN64 | Bemerkung |
|---|---|---|
| Proxy-Hosts: Domains, Schema, Ziel-Host/IP, Port | ✔ | mehrere Domains je Host, Ziel http/https |
| Cache Assets | ✔ | eigener kleiner Cache für statische Dateien (Bilder, CSS, JS, Fonts), Größe begrenzt |
| Block Common Exploits | ✔ | Regelsatz wie NPM (SQL-Injection, Datei-Injection, bekannte Angriffs-Muster, Spam-Agenten) |
| Websockets Support | ✔ | in Go eingebaut, je Host abschaltbar |
| Access Lists (Basic Auth, IP erlauben/sperren) | ✔ | Passwörter als bcrypt, „eine Regel genügt“ / „beide nötig“ |
| SSL: Force SSL, HTTP/2, HSTS, HSTS-Subdomains | ✔ | dazu **HTTP/3 (QUIC)** und TLS 1.2/1.3 wählbar |
| Custom Locations | ✔ | Pfad → eigenes Ziel mit eigenen Optionen |
| Advanced (freie nginx-Konfiguration) | ✘ → **Erweitert** | es gibt kein nginx. Stattdessen feste Felder: Kopfzeilen setzen/entfernen, Body-Limit, Timeouts, Ziel-Zertifikat nicht prüfen, Host-Kopf, echte Client-IP hinter Cloudflare usw. |
| Redirection Hosts | ✔ | 301/302/307/308, Pfad mitnehmen |
| Streams (TCP/UDP) | ✔ | optional mit TLS-Abschluss bei TCP |
| 404 Hosts | ✔ | |
| SSL-Zertifikate: Let's Encrypt (HTTP oder DNS über certbot-Plugins), eigene | ✔ | ipv64 bevorzugt, siehe unten |
| Standardseite (unbekannte Domain) | ✔ | 404, Verbindung schließen, Weiterleitung, eigene Seite |
| Benutzer/Rechte | – | Node64 hat schon Anmeldung, 2FA, API-Keys |
| Audit-Log | ✔ | über den Audit des Kerns (`g.Audit`), auch für die API |
| Zugriffs-Logs je Host | ✔ | Zähler immer; Einzel-Log abschaltbar, 7 Tage |
| – | **neu: Erreichbarkeit der Ziele** | Prüfung je Ziel, Anzeige in der Liste |
| – | **neu: DNS-Eintrag bei ipv64** | beim Anlegen eines Hosts auf Wunsch A/AAAA bzw. CNAME bei ipv64 setzen |

## Grundsätze

- **Reines Go, kein nginx.** Das Image bleibt `scratch` mit einem Binary. Der Proxy baut auf `net/http`,
  `httputil.ReverseProxy` (WebSocket, Streaming, HTTP/2) und `quic-go/http3` (HTTP/3). `quic-go` ist schon dabei
  (DNS64 nutzt es für DoQ), es kommt also für HTTP/3 keine neue Abhängigkeit dazu.
- **Modul wie DNS64:** Paket `internal/cdn64` mit `module.Module` (Info, Migrationen, Routen, Start/Stop). Ist es
  aus, antworten die Seiten mit 404 (`g.Enabled`). Eigene `CHANGELOG.md`, Startversion 1.0.0
  (`docs/MODUL-VERSIONEN.md`).
- **Daten:**
  - Konfiguration (Hosts, Locations, Access Lists, Streams, Einstellungen) liegt in `node64.db` im Modul-Scope.
    Damit ist sie in Backup und Export/Import enthalten; Passwörter und Schlüssel sind mit `secrets` verschlüsselt.
  - Zugriffszähler und Zugriffs-Log liegen in einer eigenen Datei `cdn64.db` (viele Schreibvorgänge, wie
    `dns64.db`).
  - Zertifikate liegen unter `/data/certs/`.
- **Leerlauf:** Erreichbarkeitsprüfung, Erneuerung und Log-Schreiber laufen nur, solange das Modul an ist. Die
  gemeinsamen Ports (siehe unten) sind nur offen, solange jemand sie braucht.
- **Sicherheit:**
  - Die Oberfläche von Node64 ist über den Proxy nie erreichbar, außer man legt sie ausdrücklich als Host an.
  - Die Standardseite verrät nichts über die Node.
  - Basic Auth ist gegen Raten begrenzt, wie der Login.
  - Ziele „nur LAN / beliebig“ wählbar.
  - Die Rechte für Ports unter 1024 sind schon im Image (`cap_net_bind_service`).
- **Oberfläche:** im Stil von Node64 (Bootstrap 5, Deutsch/Englisch). Lokale API unter `/api/cdn64/…`, dokumentiert
  in OpenAPI, README und Hilfe.

## Das Port-Problem: gemeinsamer Eingang im Kern („Edge“)

Heute öffnet DNS64 für DoH einen eigenen Listener auf 443. Ein Reverse-Proxy braucht 80 und 443 (TCP), für
HTTP/3 auch 443/UDP. Zwei Listener auf demselben Port gehen nicht.

**Entschieden:** Die Ports 80 und 443 gehören dem **Kern**, keinem Modul. Ein neues Kern-Paket `internal/edge` hält
einen gemeinsamen Eingang. Module melden sich dort an:

```
                 :80 TCP ─┐
 Internet/LAN →  :443 TCP ┼─► Edge (Kern) ── SNI / Host ──► CDN64: Proxy-, Redirect-, 404-Hosts
                 :443 UDP ┘   (TLS, HTTP/1.1, HTTP/2, HTTP/3)  ├─► DNS64: /dns-query (DoH) auf seinen Namen
                                                              ├─► ACME: HTTP-01 / TLS-ALPN-01 Antworten
                                                              ├─► Node64-Oberfläche unter eigener Domain (optional)
                                                              └─► Standardseite für Unbekannte
```

- **Ein Listener je Port:**
  - Bei TLS wählt Edge das Zertifikat nach dem Namen (SNI) aus dem Zertifikatsspeicher.
  - Bei HTTP routet Edge nach dem `Host`-Kopf.
  - HTTP/3 läuft auf derselben Nummer über UDP; angekündigt wird es per `Alt-Svc`.
- **Edge läuft nur, solange es Abnehmer gibt.** Meldet sich der letzte ab (CDN64 aus, DoH aus), schließt Edge die
  Ports. Das hält die Leerlauf-Regel ein.
- **DNS64 bleibt unabhängig:**
  - Ist CDN64 aus, nutzt DoH Edge allein. Für Nutzer ändert sich nichts.
  - Ist CDN64 an, teilen sich beide den Port 443. DoH antwortet auf den DNS64-Namen bzw. auf `/dns-query` beim
    Standard-Host.
  - DoT/DoQ (853) und DNS (53) bleiben, wo sie sind.
- **Port-Verwaltung im Kern:**
  - Jeder belegte Port wird mit Modul, Protokoll und Zweck eingetragen: Oberfläche, DNS 53, DoT/DoQ 853, Edge
    80/443, jeder Stream.
  - Beim Speichern einer Einstellung oder eines Streams prüft der Kern auf Überschneidung und lehnt mit klarer
    Meldung ab. Er versucht zusätzlich einen Probe-Bind, ob ein anderes Programm auf dem Host den Port hat.
  - Neu in den Einstellungen: eine Übersicht „Ports“, auch per API.
- **Ports einstellbar:** HTTP/HTTPS von Edge (Standard 80/443) lassen sich verlegen, z. B. hinter einer Fritzbox
  mit Portweiterleitung 443 → 8443.
- **Docker:** Empfohlen ist das Host-Netzwerk, weil Streams beliebige Ports öffnen. Im Bridge-Modus gilt
  `-p 80:80 -p 443:443 -p 443:443/udp` plus eine Freigabe je Stream; die README erklärt beides.

Damit funktionieren DNS64 mit DoH, CDN64 und die Oberfläche in **einem** Container ohne Konflikt.

**Warum das geht:**

- Ein Port ist je IP-Adresse und Protokoll nur von **einem Programm** zu öffnen. In Node64 sind alle Module ein
  einziges Programm. Edge öffnet 443 genau einmal und verteilt intern.
- Bei TLS steht der gewünschte Name unverschlüsselt in der ersten Nachricht des Browsers (SNI). Edge entscheidet
  also vor dem Entschlüsseln:
  - mit welchem Zertifikat terminiert wird und an welchen Abnehmer es geht (Proxy-Host, DoH, Oberfläche), oder
  - ob die Verbindung roh durchgereicht wird (TLS-Durchreichen, siehe unten).
- Bei HTTP auf Port 80 entscheidet der `Host`-Kopf.
- Bei HTTP/3 auf 443/UDP trägt QUIC den Namen ebenso.
- DoH ist damit nur ein weiterer Name bzw. Pfad, wie jeder Proxy-Host.

**Was nicht geteilt werden kann:**

- Dienste ohne Namen in der Verbindung: reine TCP/UDP-Streams (z. B. Minecraft 25565, WireGuard 51820/udp) und
  DNS auf 53. Sie brauchen je einen eigenen Port. Die Port-Verwaltung verhindert Doppelbelegungen und zeigt sie an.
- TLS-Streams mit Namen dagegen können sich 443 teilen, als „TLS durchreichen“ nach SNI.

**Wann trotzdem zwei IP-Adressen nötig sind:**

- Nur wenn ein **anderes Programm außerhalb von Node64** auf demselben Host und derselben IP 443 will (z. B. ein
  alter NPM, UniFi, die Weboberfläche eines Pi-hole).
- Oder wenn jemand zwei Node64-Container mit denselben Modulen im Host-Netzwerk betreibt.
- Lösung in diesen Fällen: anderen Port wählen, zweite IP bzw. macvlan, oder den Dienst als Proxy-Host hinter
  Node64 legen. Node64 erkennt die Belegung per Probe-Bind und sagt das in der Oberfläche, statt still zu
  scheitern.
- Für den Normalfall gilt: **ein Container, eine Portweiterleitung im Router (80/443 → Node64), alles dahinter.**

**Vorbereitet für das ipv64-CDN** (siehe unten), schon ab C0 im Edge:

- **PROXY-Protokoll v2:** Wird eine Verbindung roh durchgereicht, liefert das CDN die echte Client-IP im
  PROXY-Kopf. Edge akzeptiert diesen Kopf nur von vertrauenswürdigen Quellen (Liste der ipv64-CDN-Server, per API).
- **Vertrauenswürdige Proxys:** `X-Forwarded-For`/`X-Real-IP` gelten nur von diesen Quellen. Für Nutzer hinter
  Cloudflare kann die Liste erweitert werden.
- **SNI-Durchreichen:** Ein Name kann statt Terminierung roh an ein Ziel gehen, lokal (eigener Host-Typ in C3) wie
  vom CDN.
- **Herkunftsschutz:** Je Host lässt sich „nur über das ipv64-CDN“ einstellen. Direkte Zugriffe auf den Namen
  werden dann abgewiesen.

## SSL-Zertifikate (eigener Reiter)

### Zertifikatsspeicher im Kern

Zertifikate braucht nicht nur CDN64. DNS64 hat heute einen eigenen Let's-Encrypt-Weg (`internal/dns64/acme.go`),
und die Oberfläche könnte auch eines nutzen. **Entschieden:**

- Neues Kern-Paket `internal/certs` mit Speicher, ACME-Client und Erneuerung.
- Den ACME-Teil aus DNS64 dorthin herauslösen. Der Client ist `golang.org/x/crypto/acme`, wie heute.
- Die Seite „SSL-Zertifikate“ ist ein Reiter von CDN64.
- DNS64 bekommt später den Zertifikatsmodus „aus der Zertifikatsverwaltung“. Sein heutiger Weg bleibt bis dahin
  unverändert, weil das Heimnetz-DNS produktiv läuft.

### Wege zum Zertifikat (Reihenfolge wie in der Oberfläche)

1. **ipv64 DNS-01 (bevorzugt):** Die Domain liegt im ipv64-Account. Der TXT-Record wird über API v2 mit dem
   zentralen API-Key gesetzt und wieder gelöscht, wie heute in DNS64.
   - CDN64 erkennt per API, welche Domains im Account sind, und schlägt diesen Weg automatisch vor.
   - Wildcards (`*.name.ipv64.de`) sind möglich.
   - Port 80/443 muss dafür nicht von außen erreichbar sein.
2. **ipv64 Alias (für fremde Domains):** Für `example.com` bei einem beliebigen Anbieter legt der
   Nutzer einmal den CNAME `_acme-challenge.example.com` → `_acme-challenge.<seine-ipv64-domain>` an. Danach
   setzt Node64 den TXT-Record immer bei ipv64.
   - Let's Encrypt folgt dem CNAME; dasselbe Verfahren nennt acme.sh „DNS alias mode“.
   - Vorteile: Es braucht keine Zugangsdaten des fremden Anbieters, es funktioniert bei jedem Anbieter, und
     Wildcards gehen auch.
   - Die Oberfläche zeigt den nötigen CNAME und prüft ihn vor dem Abruf.
3. **HTTP-01:** Der klassische NPM-Weg. Port 80 muss von außen auf die Node zeigen; Edge beantwortet die
   Challenge selbst.
4. **Andere DNS-Anbieter mit API-Zugang:** acme.sh und certbot sind Shell- bzw. Python-Programme und laufen im
   `scratch`-Image nicht.
   - Daher: die DNS-Anbieter der Go-Bibliothek **lego** (dieselben wie bei Traefik und Caddy), aber nur eine
     Auswahl. Damit bleibt das Binary klein; jeder Anbieter bringt eigene Abhängigkeiten mit.
   - Startliste, gängig in Deutschland: Cloudflare, Hetzner, netcup, INWX, IONOS, deSEC, DuckDNS, OVH,
     Porkbun, GoDaddy, DigitalOcean, Gandi.
   - Dazu der generische Anbieter „RFC 2136“ (eigener DNS-Server).
   - Zugangsdaten werden verschlüsselt gespeichert.
5. **Eigenes Zertifikat hochladen:** PEM mit Zertifikat, Kette und Schlüssel. Node64 prüft die Passung und zeigt
   Namen und Ablauf an.

### Verwaltung

- **Liste:**
  - Namen, Aussteller, Weg, gültig bis, Ablauf-Pille (grün > 30 Tage, gelb < 30, rot < 7 bzw. abgelaufen),
    benutzt von (Hosts, DNS64).
  - Aktionen: Erneuern, Herunterladen (ohne Schlüssel), Löschen. Löschen nur, wenn das Zertifikat unbenutzt ist,
    sonst mit Hinweis.
- **Automatik:**
  - Die Erneuerung läuft täglich und greift 30 Tage vor Ablauf, mit Rückzug bei Fehlern.
  - Ein neues Zertifikat gilt sofort, ohne Neustart.
  - Bei einem fehlgeschlagenen Abruf und 14 Tage vor Ablauf ohne Erfolg geht eine Benachrichtigung über die
    vorhandenen Kanäle.
  - Optional „Zertifikat beim Anlegen des Hosts gleich mit anfordern“, wie im NPM.
- **ACME-Konto:**
  - Ein Konto je Node, der Schlüssel liegt verschlüsselt; die Mail ist optional.
  - Die Nutzungsbedingungen von Let's Encrypt werden einmal per Häkchen angenommen, wie in DNS64.
  - Es gibt eine Testumgebung (Staging) gegen Rate-Limits.
  - Andere ACME-Anbieter wie ZeroSSL (mit EAB) sind als spätere Option vorgesehen.

## Proxy-Hosts im Detail

**Formular** (Reiter wie beim NPM):

- **Details:**
  - Domains (mehrere), Ziel-Schema, Ziel-Host/IP, Port.
  - Schalter: Cache Assets, Block Common Exploits, WebSockets, Access List.
- **Custom Locations:**
  - Pfad (Präfix), Ziel, optional neuer Pfad.
  - Optionen je Location wie beim Host.
- **SSL:**
  - Zertifikat (vorhandenes oder „neu anfordern“).
  - Force SSL, HTTP/2, HTTP/3, HSTS, HSTS-Subdomains.
  - Minimale TLS-Version (1.2/1.3). Eine TLS 1.4 gibt es nicht; 1.3 ist aktuell.
- **Erweitert:**
  - Kopfzeilen zur Anfrage und zur Antwort setzen bzw. entfernen.
  - Host-Kopf durchreichen oder ersetzen.
  - Ziel-Zertifikat nicht prüfen (für Proxmox, UniFi u. a. mit selbstsignierten Zertifikaten).
  - Timeouts, maximale Upload-Größe.
  - Puffern aus (für Streaming und SSE).
  - Echte Client-IP aus vertrauenswürdigen Proxys (z. B. Cloudflare-Netze).
  - Komprimierung (gzip).
- **ipv64:** Auf Wunsch DNS-Eintrag(e) für die Domains im Account anlegen: A/AAAA auf die aktuelle IP aus DynDNS
  oder CNAME auf eine DynDNS-Domain.

**Liste:**

- Spalten: Domains, Ziel, SSL (Pille mit Ablauf), Optionen als kleine Symbole, Zugriff (Access List), Status,
  **Erreichbarkeit**, Anfragen der letzten 24 h.
- Aktionen: an/aus, bearbeiten, löschen, Sammelaktionen.

**Erreichbarkeit der Ziele:**

- Jedes Ziel (Host und Locations) wird alle 60 s geprüft: TCP-Verbindung, bei http/https zusätzlich eine kurze
  `HEAD`-Anfrage. Die Prüfung läuft gebündelt in einer Goroutine, je Ziel höchstens eine gleichzeitig.
- Anzeige als Pille: erreichbar (mit Antwortzeit), langsam, nicht erreichbar seit …; außerdem ein Tooltip mit dem
  letzten Fehler.
- Optional: „Healthcheck dafür anlegen“. Es entsteht ein normaler Healthchecks-Check, mit Benachrichtigungen und
  Sync, falls gewünscht. CDN64 selbst meldet nicht noch einmal, damit nichts doppelt kommt.
- Ein Proxy-Host mit nicht erreichbarem Ziel zeigt Besuchern eine neutrale Seite „Dienst nicht erreichbar“ (502),
  keine Go-Fehlermeldung.

## Weitere Host-Typen

- **Redirection Hosts:**
  - Domains → Ziel-Domain mit Schema und Code 301/302/307/308.
  - Pfad und Query mitnehmen (an/aus).
  - SSL wie oben.
- **404 Hosts:** Domains, die bewusst mit 404 antworten (optional eigene Seite); SSL wie oben.
- **Streams:**
  - Eingangsport TCP und/oder UDP → Ziel-Host:Port.
  - Bei TCP optional TLS-Abschluss mit einem Zertifikat aus dem Speicher.
  - UDP mit Sitzungstabelle und Leerlauf-Timeout.
  - Jeder Stream belegt seinen Port in der Port-Verwaltung; Überschneidungen werden abgelehnt.
  - Zähler: Verbindungen und Bytes.
- **Standardseite:** Was passiert bei unbekannter Domain oder direktem Aufruf per IP: 404-Seite, Verbindung
  schließen (wie nginx 444), Weiterleitung oder eigene HTML-Seite.

## Access Lists

- **Inhalt:**
  - Name.
  - Benutzer (Basic Auth, bcrypt).
  - IP-Regeln (erlauben/sperren, IPv4/IPv6, CIDR, in Reihenfolge, Rest gesperrt).
  - „Eine Bedingung genügt“ oder „beide nötig“.
  - „Anmeldung an das Ziel weiterreichen“.
- Gilt für Hosts und Locations.
- Fehlversuche werden je IP begrenzt und landen im Audit (nur Zähler, kein Passwort).

## Zugriffs-Log und Statistik

- **Zähler je Host und Stunde** (Anfragen, 2xx/3xx/4xx/5xx, Bytes): immer, sehr günstig, in `cdn64.db`,
  90 Tage. Sie speisen eine Dashboard-Kachel (Hosts, Ziele offline, Zertifikate bald fällig, Anfragen 24 h).
- **Einzel-Log:**
  - Zeit, Host, Client-IP, Methode, Pfad, Status, Bytes, Dauer, User-Agent.
  - Je Host abschaltbar, 7 Tage, gebündelt geschrieben.
  - Anonymisierung der IP wie bei DNS64.
  - Seite mit Filter und Suche.

## Audit, API, Doku

- **Audit:** Jede Änderung geht in den Audit des Kerns: Host, Location, Access List, Stream, Zertifikat
  (anfordern, erneuern, hochladen, löschen), Einstellungen. Gilt für Oberfläche und API; der Kern setzt die
  Herkunft.
- **Lokale API (`/api/cdn64/…`):**
  - Objekte: Proxy-, Redirect- und 404-Hosts, Streams, Access Lists, Zertifikate.
  - Dazu Erreichbarkeit, Statistik, Log, Einstellungen, Ports.
  - Gleichstand mit der Oberfläche: Alles, was die Oberfläche kann, kann auch die API. Alles steht in OpenAPI mit
    Schemas.
- **Doku:**
  - `docs/CDN64.md` (Betrieb, Ports, Zertifikatswege, Umstieg vom NPM).
  - README-Abschnitt.
  - `CHANGELOG.md` des Moduls.

## ipv64-CDN: vorgelagerte Server (spätere Phase, Architektur jetzt)

ipv64 betreibt schon CDN-Server: nginx mit IPv4 und IPv6, gesteuert über `bots/cdn_bot.php` und API v2 `/cdn`
(Proxy, Portmapper, Zugriffsliste, Caching, Let's Encrypt). Zielgruppe sind Anschlüsse **ohne eigene öffentliche
IPv4**, z. B. DS-Lite oder CGNAT. Besucher kommen über IPv4 oder IPv6 zum CDN-Server, und der CDN-Server erreicht
die Node über IPv6.

CDN64 soll diese Server später aus der Oberfläche heraus verknüpfen, **je Host wählbar**:

| Veröffentlichung | Weg | TLS | Was das CDN sieht |
|---|---|---|---|
| **Direkt** (Standard) | Besucher → Router → Node64 | auf der Node | – |
| **ipv64-CDN mit TLS-Terminierung** (wie Cloudflare) | Besucher → CDN-Server (TLS endet dort) → neu verschlüsselt → Node64 | zweimal: am CDN mit eigenem Zertifikat, zur Node mit dem Zertifikat der Node | Inhalte; dafür Caching, Zugriffsliste, Schutz vor Angriffen am CDN |
| **ipv64-CDN ohne TLS-Terminierung** (Durchreichen) | Besucher → CDN-Server (liest nur den Namen, SNI) → rohe TCP-Verbindung → Node64 | Ende-zu-Ende nur auf der Node | nur Name, IPs, Datenmenge; kein Caching am CDN |

**Was die Node dafür mitbringt:**

- **Verknüpfen über API v2** mit dem zentralen API-Key, wie bei allen Diensten (Entscheidung „API zuerst“).
  - CDN64 legt die CDN-Domain bzw. den Eintrag an, wählt den Modus und setzt die DNS-Einträge.
  - Es zeigt den Zustand an (zugewiesener Server, Zertifikat am CDN, Datenmenge, Limit der Klasse).
- **Ein Herkunfts-Port für alle Hosts:** Das CDN verbindet sich immer mit Edge auf 443, und Edge verteilt nach dem
  Namen. Mit TLS-Terminierung muss das CDN dafür den Namen weitergeben (nginx `proxy_ssl_server_name on`). Die Node
  braucht so keine zweite Freigabe im Router.
- **Echte Client-IP:**
  - Mit TLS-Terminierung über `X-Forwarded-For`.
  - Beim Durchreichen über das PROXY-Protokoll.
  - Beides gilt nur, wenn die Verbindung von einem ipv64-CDN-Server kommt; die Liste kommt per API.
- **Herkunftsschutz:**
  - Option „nur über das CDN“.
  - Später gegenseitige Zertifikatsprüfung (mTLS) zwischen CDN und Node. Im cdn_bot ist `ssl_verify_client`
    dafür schon angedacht.
- **Zertifikate:**
  - Mit TLS-Terminierung: am CDN das Zertifikat von ipv64 (wie heute) und auf der Node ein eigenes. Das CDN prüft
    das Zertifikat der Node; sie bekommt es per ipv64 DNS-01, ohne dass Port 80 offen sein muss.
  - Beim Durchreichen gibt es nur das Zertifikat auf der Node.
- **HTTP/3:**
  - Mit TLS-Terminierung spricht das CDN mit dem Besucher, was nginx dort kann.
  - Beim Durchreichen läuft zunächst HTTP/1.1 und HTTP/2 über TCP. QUIC durchzureichen braucht am CDN ein Programm,
    das den Namen aus dem QUIC-Paket liest; nginx kann das nicht. Edge kündigt HTTP/3 (`Alt-Svc`) daher nur an, wo
    es auch ankommt.
- **Erreichbarkeit:** In der Liste steht zusätzlich „CDN → Node erreichbar“, geprüft vom CDN-Server, per API
  abgefragt.

**Was auf der ipv64-Seite dazukommt (nicht in diesem Repo, eigene Abstimmung):**

- **Für das Durchreichen:**
  - Auf den CDN-Servern kommt vor 443 ein nginx-`stream` mit `ssl_preread`. Namen im Durchreich-Modus gehen roh
    (mit `proxy_protocol`) zur Node, alle anderen an den bestehenden HTTP-Teil auf dem Server selbst.
  - Port 80 leitet für diese Namen nur auf HTTPS um.
- API v2 `/cdn`:
  - Modus je Eintrag (terminieren/durchreichen);
  - Herkunfts-Port und -Schema, mehrere Namen je Domain;
  - Liste der CDN-Server-IPs;
  - Prüfung „CDN → Node“.
- Später, falls gewünscht: mTLS zur Node.

**Merkposten Tunnel (Idee, nicht entschieden):** Wer auch per IPv6 nicht von außen erreichbar ist (doppeltes
CGNAT, Mobilfunk, strenge Firewall), dem hilft nur eine ausgehende Verbindung von der Node zum CDN-Server (wie
Cloudflare Tunnel). Beide Modi könnten darüber laufen. Das Datenmodell sieht dafür einen dritten Transportweg vor.

**Datenmodell schon ab C1:**

- Jeder Host hat `publish` = `direct` | `ipv64_cdn_tls` | `ipv64_cdn_passthrough` (später ggf. `…_tunnel`) und
  `origin_only_cdn`.
- Bis Phase C7 ist nur `direct` wählbar. So muss später nichts umgebaut werden.

## Was nicht dazugehört (vorerst)

- Die freie nginx-Konfiguration: Die festen Felder unter „Erweitert“ decken die üblichen Fälle ab.
- Abgleich der Proxy-Konfiguration über die lokale Gruppe oder ipv64: Jede Node proxyt ihr eigenes Netz. Ein
  späterer Abgleich ist möglich, da die Daten sauber getrennt liegen.
- Lastverteilung auf mehrere Ziele, Rate-Limits je Host, GeoIP-Sperren: als spätere Erweiterung vorgemerkt,
  passend zum Namen „CDN“.

## Phasen

Jede Phase endet mit Build, Tests (`go test -race`), Version und CHANGELOG, kurzer Zusammenfassung und erst dann
der nächsten Phase. Ausgerollt auf der Box wird nur mit Dennis' Go.

### C0 Kern: Ports, Edge, Zertifikatsspeicher
- `internal/edge`:
  - gemeinsamer Eingang 80/443 (TCP) und 443/UDP (HTTP/3);
  - An- und Abmelden von Abnehmern, Routing nach SNI und Host;
  - Standardseite;
  - Start nur bei Bedarf;
  - PROXY-Protokoll v2 und vertrauenswürdige Proxys (nur von Quellen aus einer Liste).
- **Port-Verwaltung** mit Konfliktprüfung, Probe-Bind und Übersicht „Ports“ (Einstellungen und API).
- `internal/certs`:
  - Speicher (Laden, Ablauf, Zuordnung nach Namen), ACME-Konto;
  - ipv64 DNS-01 (aus DNS64 herausgelöst; DNS64 selbst bleibt unverändert), Hochladen, Erneuerung;
  - Benachrichtigung.
- Tests:
  - Routing (SNI/Host), HTTP/2 und HTTP/3 gegen echte Listener;
  - Konflikte;
  - Erneuerung mit ACME-Testserver (Pebble-artiger Fake).

### C1 Modul-Gerüst und Proxy-Hosts
- Modul `cdn64` ersetzt den Platzhalter. Dazu Menü, Dashboard-Kachel, Migrationen und Version 1.0.0.
- **Proxy-Hosts:**
  - Anlegen, Bearbeiten, Löschen, an/aus;
  - Ziel http/https, WebSockets, Block Common Exploits, Cache Assets;
  - Force SSL, HTTP/2, HTTP/3, HSTS.
- Erreichbarkeit der Ziele in der Liste.
- Datenmodell mit `publish` (vorerst nur `direct`) und `origin_only_cdn`.
- Audit und API für alles Obige.

### C2 Reiter SSL-Zertifikate
- **Seite:**
  - Liste mit Ablauf-Pillen und „benutzt von“;
  - Anfordern (ipv64 DNS-01 mit automatischer Erkennung, ipv64 Alias mit CNAME-Prüfung, HTTP-01), Hochladen,
    Erneuern, Löschen;
  - Wildcards;
  - ToS-Häkchen, Staging.
- „Zertifikat gleich mit anfordern“ im Host-Formular.
- Benachrichtigungen bei Fehlschlag und nahendem Ablauf.

### C3 Redirection Hosts, 404 Hosts, Streams, Standardseite
- Die drei Host-Typen mit SSL.
- Streams TCP/UDP mit Port-Verwaltung und optionalem TLS.
- **TLS durchreichen:** Host-Typ, der einen Namen auf 443 roh (nach SNI) an ein Ziel im LAN weitergibt.
- Standardseite einstellbar.

### C4 Erweitert
- Custom Locations.
- Access Lists.
- Reiter „Erweitert“: Kopfzeilen, Timeouts, Body-Limit, Ziel-Zertifikat, echte Client-IP, gzip.
- Statistik und Zugriffs-Log (`cdn64.db`).
- Option „Healthcheck dafür anlegen“.

### C5 Fremde DNS-Anbieter und ipv64-Einträge
- DNS-Anbieter über lego (Auswahl siehe oben, verschlüsselte Zugangsdaten).
- DNS-Eintrag bei ipv64 beim Anlegen eines Hosts.

### C6 Zusammenführung und Abschluss
- **DNS64:**
  - DoH über Edge statt eigenem Listener (DNS64 1.8.0);
  - Zertifikatsmodus „aus der Zertifikatsverwaltung“;
  - abgestimmt mit der DNS64-Sitzung, Ausrollen nur mit Dennis' Go, weil das Heimnetz-DNS dranhängt.
- Node64-Oberfläche optional unter eigener Domain über Edge.
- Lasttest (z. B. 1.000 gleichzeitige Verbindungen, WebSocket-Dauerverbindungen, große Uploads), Speicherverbrauch
  im Leerlauf mit und ohne Modul.
- Doku, OpenAPI, README.

### C7 ipv64-CDN (nach Abstimmung der Server-Seite)
- **Node:**
  - CDN verknüpfen über API v2;
  - je Host Veröffentlichung „ipv64-CDN mit TLS-Terminierung“ bzw. „ohne TLS-Terminierung“;
  - DNS-Einträge über das CDN;
  - Herkunftsschutz;
  - Anzeige: Server, Zustand, Datenmenge, „CDN → Node erreichbar“.
- **ipv64-Seite (eigene Abstimmung):**
  - `ssl_preread`-Vorstufe mit `proxy_protocol` auf den CDN-Servern;
  - Erweiterungen in API v2 `/cdn`;
  - Liste der CDN-Server-IPs.
  - Website-Code nur als Vorher/Nachher zur Prüfung.
- Später optional: mTLS zur Node, Tunnel.

## Testumgebung

- **Lokal:**
  - Dev-Node (Port 8089) mit Edge auf hohen Ports (z. B. 18080/18443).
  - Testziele: ein kleiner Go-Echo-Server mit HTTP, WebSocket, SSE und großem Upload.
- **Box:**
  - Ein eigener Container `node64-cdn` (Host-Netzwerk, Oberfläche 8094, Edge 18080/18443 TCP+UDP). Er stört das
    Heimnetz-DNS auf node64-test (443/853/53) nicht.
  - Testziele: z. B. ein `whoami`-Container und ein WebSocket-Echo.
  - Den echten Port 443 auf der Box bekommt CDN64 erst in C6 zusammen mit DoH, nach Absprache.
- **Echte Zertifikate:** zuerst Staging. Ein echter Abruf mit Dennis' Domain (TXT-Records im Account, Annahme der
  Nutzungsbedingungen) geschieht erst nach seinem OK.

## Entscheidungen (Dennis, 2026-10-15)

- **Fremde DNS-Anbieter:** ipv64-Alias (CNAME) + HTTP-01 + eine Auswahl DNS-Anbieter über lego in Go. Kein
  acme.sh/certbot; das Image bleibt `scratch`.
- **Zertifikate zentral im Kern** (`internal/certs`) für CDN64, DNS64 und die Oberfläche; die Seite ist ein Reiter
  von CDN64.
- **Port 443 gemeinsam über Edge** im Kern, mit Port-Übersicht und Konfliktprüfung.
- **Kein Import aus dem NPM.**
- **ipv64-CDN** (Ergänzung Dennis): Der lokale Reverse-Proxy ist der Grundbestandteil. Später kommen zwei Wege über
  die bestehenden ipv64-CDN-Server dazu, je Host wählbar: mit TLS-Terminierung am CDN (wie Cloudflare) und ohne
  (Durchreichen, TLS endet erst auf der Node). Zweck: Erreichbarkeit über IPv4 für Anschlüsse ohne eigene IPv4.
  Die Architektur (Edge, Datenmodell) berücksichtigt das ab C0/C1.

## Offene Fragen (für C7, nicht blockierend)

- **Tunnel** für Anschlüsse, die auch per IPv6 nicht erreichbar sind: gewünscht?
- **Durchreichen und HTTP/3:** reicht HTTP/2 über TCP, oder soll QUIC später auch durchgereicht werden (eigenes
  Programm statt nginx vor 443 auf den CDN-Servern)?
