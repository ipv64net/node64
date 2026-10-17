# CDN64 online – Planung (Tunnel zu srv07/srv08)

Stand: 2026-10-17 · Status: **Planung, nichts umgesetzt** · Phasen T0–T6

Der lokale Reverse-Proxy CDN64 in Node64 wird mit einem neuen Online-CDN verbunden – so wie Cloudflare Tunnel:
die Node baut von zu Hause eine dauerhafte, verschlüsselte QUIC-Verbindung zu den CDN-Servern **srv07.cdn64.de**
(Nürnberg) und **srv08.cdn64.de** (Falkenstein) auf. Besucher kommen über IPv4 und IPv6 an diesen Servern an und
werden durch die offene Verbindung zur Node durchgereicht. Zu Hause muss kein Port offen sein.

Inhalt: [1 Ziel](#1-ziel) · [2 Entscheidungen](#2-entscheidungen) · [3 Architektur](#3-architektur) ·
[4 Tunnel](#4-tunnel) · [5 Modus 1](#5-modus-1-durchreichen) · [6 Modus 2](#6-modus-2-terminieren) ·
[7 Steuerung bei ipv64](#7-steuerung-bei-ipv64) · [8 Node64](#8-node64) · [9 Edge-Dienst](#9-edge-dienst-auf-srv07srv08) ·
[10 Sicherheit](#10-sicherheit) · [11 Phasen](#11-phasen) · [12 Risiken und offene Punkte](#12-risiken-und-offene-punkte)

---

## 1. Ziel

- **Erreichbarkeit:** Kunden hinter Glasfaser nur mit IPv6, DS-Lite oder CGNAT sind per IPv4 **und** IPv6 erreichbar.
- **Privatsphäre:** Die Heim-IP bleibt verborgen; im DNS stehen nur srv07/srv08.
- **Ein Klick:** In der Node je Proxy-Host „CDN64 online“ einschalten; DNS, Server, Zertifikat und Tunnel richten
  sich im Hintergrund ein. Der Nutzer sieht den Fortschritt.
- **Zwei Modi:**
  - **Modus 1 – durchreichen:** Die Server entschlüsseln nichts. TLS und Zertifikat bleiben zu Hause.
  - **Modus 2 – terminieren:** TLS endet auf den Servern. Dort greifen schon Schutz (Blocklisten, Limits, Sperren)
    und HTTP/3; danach geht es über denselben Tunnel zur Node.
- **Abgrenzung:** Das bestehende CDN (srv01–srv06, nginx, `cdn_domains`) bleibt unverändert in Betrieb. Es kann ohne
  Tunnel auf frei definierte IP-Adressen zeigen. Beide Systeme werden in der Datenbank strikt getrennt.

## 2. Entscheidungen

| Thema | Entscheidung (Dennis, 2026-10-17) |
|---|---|
| Wer darf es nutzen | Jede Klasse mit `user_class.cdn_domains > 0`, rein dynamisch (Free raus = Standard auf 0 setzen) |
| Limits | Bestehende Spalten `user_class.cdn_domains` und `user_class.cdn_traffic`, bei jeder Prüfung frisch gelesen, keine neue Spalte |
| Kontingent | **Gemeinsam** mit dem alten CDN: Domains und Traffic von alt + neu zählen zusammen (alte Tabellen nur lesen) |
| Tabellen | **Eigene neue Tabellen**, nichts mit dem alten CDN vermischen, nie in alte CDN-Tabellen schreiben |
| Konfiguration auf den Servern | ipv64-DB + API v2 sind die Wahrheit; srv07/srv08 holen ihre Konfiguration selbst per HTTPS (kein SSH-Push, kein MySQL auf den Servern) |
| DNS | A/AAAA beider Server mit TTL 10, wie beim alten CDN; der ursprüngliche Eintrag bleibt deaktiviert erhalten |
| Domains | v1 nur Domains im ipv64-Account (DNS automatisch). Fremde Domains später mit TXT-Nachweis |
| Zertifikate Modus 2 | **DNS-01 mit Wildcard** (`domain` + `*.domain`) bevorzugt, HTTP-01 nur als Ausweg |
| Zertifikate Modus 1 | Bleiben in der Node (zentrale Zertifikatsverwaltung, ipv64 DNS-01, auch Wildcard) |
| Altes CDN | Bleibt bestehen (Dennis' Satz „man sollte dann das CDN irgendwann mal …“ war abgeschnitten – nachfragen) |

## 3. Architektur

```
                     DNS: domain.de  A/AAAA → srv07 + srv08 (TTL 10)
Besucher ───────────────────────────────────────────────────────────┐
 (IPv4/IPv6)                                                         ▼
                ┌──────────────── srv07.cdn64.de ────────────────┐  ┌── srv08.cdn64.de ──┐
                │ cdn64-edge (Go)                                │  │ cdn64-edge (Go)    │
                │  :80  tcp   HTTP (Host lesen)                  │  │ gleich             │
                │  :443 tcp   TLS (SNI lesen / terminieren)      │  │                    │
                │  :443 udp   HTTP/3 (nur Modus 2)               │  │                    │
                │  :7844 udp  Tunnel (QUIC)  ◄──────────────┐    │  │ :7844 ◄────────┐   │
                │  :7844 tcp  Tunnel-Ausweichweg (TLS)      │    │  │                │   │
                └───────────────▲───────────────────────────┼────┘  └────────▲───────┼───┘
                                │ Konfiguration (HTTPS,     │                │       │
                                │ Polling mit ETag)         │ dauerhaft,     │       │
                     ┌──────────┴─────────┐                 │ von der Node   │       │
                     │ ipv64.net          │                 │ geöffnet       │       │
                     │ API v2 + MySQL     │                 │                │       │
                     │ + PowerDNS         │◄── API-Key ──┐  │                │       │
                     └────────────────────┘              │  │                │       │
                                                     ┌───┴──┴────────────────┴───────┴──┐
                                                     │ Node64 zu Hause (CDN64)          │
                                                     │ Tunnel-Client → Eingang → Proxy  │
                                                     │ → Dienst im Heimnetz             │
                                                     └──────────────────────────────────┘
```

Drei Bausteine:

1. **cdn64-edge** – neuer Go-Dienst auf srv07 und srv08 (Quelle im Repo `ipv64_container`, `cmd/cdn64-edge`).
2. **Tunnel-Client in Node64** – Teil des Moduls CDN64; speist Tunnel-Verbindungen direkt in den gemeinsamen Eingang.
3. **Steuerung bei ipv64** – neue Tabellen, API-v2-Endpunkte für Nodes, eigene Endpunkte für die Server (PHP von mir,
   eingespielt von Dennis).

Gemeinsamer Code (SNI lesen, Blocklisten, Limits, Tunnel-Protokoll) wird in Pakete ausgelagert, die Node und Server
beide nutzen (`internal/tunnel`, Teile aus `internal/edge` und `internal/cdn64`).

## 4. Tunnel

### 4.1 Verbindung aufbauen

- Die Node öffnet je Server **eine QUIC-Verbindung** (UDP, TLS 1.3) zu `srvXX.cdn64.de:7844`, ALPN `cdn64-tunnel/1`.
  Ausgehend – funktioniert hinter NAT, DS-Lite, CGNAT, nur IPv6 oder nur IPv4 (die Node nimmt, was sie hat;
  Happy Eyeballs zwischen v6 und v4).
- Die Node prüft das Zertifikat des Servers (Let's Encrypt für `srv07.cdn64.de` bzw. `srv08.cdn64.de`).
- **Anmeldung** auf einem Steuer-Stream: `HELLO {tunnel_id, token, node_version, fähigkeiten}`. Der Server prüft den
  Token gegen seine Konfiguration (dort nur als SHA-256-Hash) und antwortet mit `WELCOME {edge, hosts}` oder trennt.
  Nicht angemeldete Verbindungen werden nach 5 s geschlossen.
- **Immer beide Server:** Die Node hält zu srv07 und srv08 je eine Verbindung. Status je Server sichtbar (verbunden,
  Latenz, seit wann).
- **Wach halten:** QUIC-Keepalive alle 15 s (Router-Zeitlimits für UDP liegen oft bei 30 s), Idle-Timeout 60 s.
- **Wiederverbinden:** sofort, dann mit wachsender Pause 1 s → 60 s plus Zufall. Neue Heim-IP oder Router-Neustart →
  neue Verbindung, laufende Besucher-Verbindungen dieses Servers brechen ab, neue gehen sofort wieder.
- **UDP gesperrt:** Nach 2 gescheiterten QUIC-Versuchen nimmt die Node TCP+TLS auf Port 7844 mit einem Multiplexer
  (Kandidat: yamux; Entscheidung in T1) – wie der HTTP/2-Ausweichweg von Cloudflare. Gleiche Anmeldung, gleiche
  Stream-Semantik.

### 4.2 Besucher-Verbindungen

- Für jede Besucher-Verbindung öffnet der **Server** einen neuen bidirektionalen Stream auf der bestehenden QUIC-
  Verbindung (QUIC erlaubt vom Server geöffnete Streams; tausende parallel, ohne gegenseitiges Ausbremsen).
- **Stream-Kopf** (Version, Art, Länge, dann JSON):
  `{kind: "tls"|"http80"|"http", client: "203.0.113.7:51234", host: "domain.de", port: 443, edge: "srv07"}`.
  Danach fließen die Daten roh in beide Richtungen.
- **Flusskontrolle:** Fenster je Stream ca. 6 MB, je Verbindung ca. 15 MB (Werte in T1 messen und festlegen).
- Die Node verpackt jeden Stream als `net.Conn` mit `RemoteAddr` = echte Besucher-IP und übergibt ihn dem
  gemeinsamen Eingang – derselbe Weg wie eine Verbindung auf Port 443/80 heute. Damit gelten unverändert:
  Zertifikat, Blocklisten, Schutz vor Überlastung (je echter Besucher-IP), Zugriffslisten, Statistik, Log.

### 4.3 Ausweichweg über den Nachbarserver

Ist die Node gerade nur mit einem Server verbunden, nimmt der andere Besucher trotzdem an und reicht sie an den
Nachbarn weiter (eigener Server-zu-Server-Port mit gegenseitigem TLS, Besucher-IP im Kopf). Der DNS muss dafür nicht
umgestellt werden.

## 5. Modus 1: durchreichen

- **Port 443:** Der Server liest nur den Namen aus dem TLS-ClientHello (SNI; Code aus `internal/edge/sni.go`),
  sucht den Tunnel zu diesem Namen und reicht die Verbindung **ohne Entschlüsselung** durch (`kind: "tls"`).
- **Port 80:** Der Server liest die erste Anfragezeile und den Host-Kopf und reicht roh durch (`kind: "http80"`).
  Damit funktionieren die Weiterleitung auf HTTPS und Let's Encrypt HTTP-01 in der Node.
- **Zertifikat:** aus der Zertifikatsverwaltung der Node (ipv64 DNS-01, Wildcard möglich). Der Server sieht nie
  einen Schlüssel.
- **Unbekannter Name:** Verbindung schließen (Port 443) bzw. neutrale 404 (Port 80).
- **Grenzen v1:** HTTP/3 zu den Besuchern nicht in Modus 1 (QUIC durchzureichen braucht SNI aus verschlüsselten
  Initial-Paketen – später). TCP-Streams (z. B. Spiele-Server) und UDP nicht über den Tunnel in v1.
- **Schutz auf dem Server in Modus 1:** nur grob, weil nichts entschlüsselt wird: ipv64-Blocklisten und
  Verbindungs-Limits je IP vor der Weitergabe. Alles Feinere macht die Node.

## 6. Modus 2: terminieren

- Der Server beendet TLS (TLS 1.2/1.3, HTTP/1.1, HTTP/2, **HTTP/3**), prüft und filtert, dann geht die Anfrage über
  den Tunnel zur Node.
- **Weiterleiten:** Der Server nutzt einen normalen Reverse-Proxy, dessen „Verbindungen“ Tunnel-Streams sind
  (`kind: "http"`, HTTP/1.1 über den Stream, Wiederverwendung wie ein Verbindungspool). WebSockets über HTTP/1.1-Upgrade.
- **Echte Client-IP:** je Anfrage im Kopf `CDN64-Connecting-IP`. Die Node vertraut diesem Kopf **nur** auf
  Tunnel-Streams vom Typ `http` (nie von außen).
- **Schutz auf dem Server:** ipv64-Blocklisten, Verbindungs- und Anfrage-Limits je IP, Sperren, Größen- und
  Zeitgrenzen; Abweisungen werden gezählt und an ipv64 gemeldet. Gleicher Code wie in der Node (Pakete teilen).
- **Zertifikate – DNS-01 mit Wildcard (bevorzugt):**
  1. Ein Server bestellt bei Let's Encrypt `domain.de` + `*.domain.de`.
  2. Den TXT-Eintrag `_acme-challenge.domain.de` setzt er **nicht selbst**, sondern bittet ipv64 über den
     Server-Endpunkt (Server-Geheimnis). ipv64 prüft: Domain ist als CDN64 online im Modus 2 eingetragen →
     setzt den TXT über `do_zone_update`/PowerDNS und löscht ihn danach.
  3. Auf den Servern liegt **kein** PowerDNS-Key und **kein** API-Key eines Nutzers.
- **Ausweg HTTP-01:** wenn DNS-01 scheitert; der Server, der die Prüfung bekommt, aber die Bestellung nicht hält,
  fragt den Nachbarn nach dem Token.
- **Ein Zertifikat für beide Server:** Ein Server bestellt (Standard srv07, bei Ausfall srv08), legt Zertifikat und
  Schlüssel **verschlüsselt** (AES-GCM mit einem Schlüssel, den nur die beiden Server kennen) bei ipv64 ab; der andere
  holt es dort. ipv64 speichert nur Chiffretext. Erneuerung 30 Tage vor Ablauf.
- **Weitere Namen:** Mit dem Wildcard-Zertifikat lassen sich weitere Namen unter der Domain hinter derselben Node
  aufschalten (einzeln oder `*.domain.de`), DNS zeigt ebenfalls auf die Server.

## 7. Steuerung bei ipv64

### 7.1 Neue Tabellen (Präfix `cdn64o_`, getrennt vom alten CDN)

| Tabelle | Inhalt |
|---|---|
| `cdn64o_tunnels` | je Node: `id`, `userid`, `node_id`, `name`, `token_hash`, `created`, `last_seen_srv07/08`, `node_version`, `status` (aktiv/gesperrt) |
| `cdn64o_hosts` | je Name: `id`, `userid`, `tunnel_id`, `fqdn`, `subdomain_id` (→ `subdomains.id`), `wildcard`, `mode` (1/2), `status` (pending, dns, edge, cert, active, error, disabling, blocked), `error`, `created`, `updated` |
| `cdn64o_records` | DNS-Umstellung: `host_id`, `record_id` (→ `subdomain_records.id`), `role` (angelegt für Server / Original deaktiviert) – statt der Spalten `cdn_tmp`/`cdn_token` des alten CDN |
| `cdn64o_edges` | `id`, `name`, `hostname`, `ipv4`, `ipv6`, `secret_hash`, `last_seen`, `version`, `disabled` |
| `cdn64o_certs` | `fqdn`, `blob` (verschlüsselt durch die Server), `not_after`, `issued_by`, `updated` |
| `cdn64o_traffic` | `host_id`, `day`, `bytes_in`, `bytes_out`, `requests`, `rejected` (gemeldet von den Servern) |
| `cdn64o_events` | Verlauf je Host für Anzeige und Support (Schritte, Fehler) |

`subdomain_records` ist die DNS-Tabelle selbst und wird zwangsläufig genutzt (neue A/AAAA-Zeilen, Original
deaktivieren) – die Zuordnung steht aber nur in `cdn64o_records`, nie in den Spalten des alten CDN.

### 7.2 Limits und Kontingent

- **Domains:** `aktive Domains im alten CDN (cdn_domains)` + `Einträge in cdn64o_hosts` ≤ `user_class.cdn_domains`
  der aktuellen Klasse des Accounts. Frisch gelesen bei jeder Prüfung.
- **Traffic:** Verbrauch altes CDN (bestehende Zähler, nur lesen) + Summe `cdn64o_traffic` im gleichen Zeitraum ≤
  `user_class.cdn_traffic` (GB). Zeitraum/Rücksetzung wie beim alten CDN – in T3 im Code des alten CDN genau
  nachlesen (`cdn_traffic_gate`).
- **Klasse abgelaufen / Limit überschritten:** Host geht auf `blocked`; Server weisen ab (neutrale Seite), DNS bleibt
  bis zum Ausschalten. Nutzer sieht den Grund in der Node.

### 7.3 API v2 für Nodes (API-Key des Containers)

| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/cdn64o` | Kontingent (Domains, Traffic, Klasse), Tunnel und Hosts des Accounts |
| POST | `/cdn64o/tunnels` | Node anmelden → `tunnel_id` + Token (nur einmal sichtbar), Server-Liste |
| DELETE | `/cdn64o/tunnels/{id}` | Tunnel entfernen (Hosts werden ausgeschaltet) |
| POST | `/cdn64o/hosts` | `{fqdn, mode, wildcard, tunnel_id}` einschalten: Klasse/Kontingent prüfen, Domain gehört dem Account, nicht im alten CDN, DNS umstellen |
| GET | `/cdn64o/hosts/{id}` | Status mit Schritten |
| PATCH | `/cdn64o/hosts/{id}` | Modus wechseln |
| DELETE | `/cdn64o/hosts/{id}` | ausschalten: DNS zurück, Zertifikat auf den Servern löschen |

Umsetzung als eigene Datei `deploy/web/api_v2_cdn64o.php`, eingebunden wie `api_v2_hc2.php`; OpenAPI ergänzen.

### 7.4 Endpunkte für die Server (Server-Geheimnis, eigene Datei)

| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/cdn64o/edge/config` | Tunnels (Token-Hashes) und Hosts (Name, Modus, Tunnel, gesperrt); ETag, Long-Poll bis 25 s |
| POST | `/cdn64o/edge/report` | verbundene Tunnels, Traffic-Deltas je Host, Abweisungen, Version |
| POST/DELETE | `/cdn64o/edge/acme-txt` | TXT für DNS-01 setzen/löschen (nur für eingetragene Modus-2-Hosts) |
| GET/PUT | `/cdn64o/edge/certs/{fqdn}` | verschlüsseltes Zertifikat ablegen/holen |

Die Server speichern die letzte Konfiguration lokal: **fällt ipv64 aus, laufen alle Tunnels weiter**, nur Änderungen
warten.

### 7.5 DNS-Umstellung

- Einschalten: für `fqdn` (und bei Wildcard `*.fqdn`) A = IPv4 von srv07 und srv08, AAAA = IPv6 von beiden, TTL 10;
  vorhandene A/AAAA des Namens deaktivieren; `do_zone_update`. Gleiches Verfahren wie das alte CDN, eigene Zuordnung.
- Ausschalten: angelegte Zeilen löschen, Originale wieder aktivieren, `do_zone_update`.
- DynDNS: Updates landen weiter auf dem deaktivierten Original (Verhalten des Update-Skripts in T3 prüfen) und
  greifen erst nach dem Ausschalten wieder.
- Konflikt: Name schon im alten CDN oder bei einem anderen Account → ablehnen.

## 8. Node64

- **Voraussetzung:** ipv64-API verbunden (zentraler API-Key). Ohne Key oder ohne Kontingent ist der Schalter
  ausgegraut mit Begründung und Link zu `/plans`.
- **Proxy-Host-Formular / Liste:** Schalter **„CDN64 online“** mit Auswahl Modus 1 / Modus 2 und „Wildcard“.
- **Ein Klick – Fortschritt** (live auf der Seite):
  1. Klasse und Kontingent geprüft
  2. Tunnel angemeldet (einmalig je Node)
  3. DNS umgestellt
  4. Server haben die Konfiguration
  5. Tunnel zu srv07 ✓ / srv08 ✓
  6. Zertifikat bereit (Modus 1: lokal; Modus 2: auf den Servern)
  7. **Selbsttest übers Internet:** Die Node ruft `https://domain/.well-known/cdn64-check/<zufall>` über die Server
     auf und beantwortet ihn selbst durch den Tunnel – beweist den ganzen Weg.
- **Anzeige:** Badge „CDN64 online (srv07 ✓ srv08 ✓)“ in der Host-Tabelle, Modus, Traffic über CDN64,
  Abweisungen auf den Servern (Modus 2) im Verkehr-Diagramm.
- **Ohne Portfreigabe:** Hosts, die nur über CDN64 online laufen, brauchen keine offenen Ports 80/443 im Router. Im
  Heimnetz bleibt der direkte Zugriff wie bisher.
- **Code:** `internal/tunnel` (Protokoll, Client), `internal/cdn64/online.go` (API, Fortschritt, UI), Eingang:
  neue Methode, die eine fertige Verbindung annimmt (`ServeConn(conn, port)`).

## 9. Edge-Dienst auf srv07/srv08

- **Server:** Debian 13, 2 vCPU, 3,8 GB RAM, 38 GB (Hetzner Cloud).
  srv07 = 91.99.98.96 / 2a01:4f8:1c18:5887::1, srv08 = 2.28.6.30 / 2a01:4f8:c015:bca8::1.
- **Dienst:** `/usr/local/bin/cdn64-edge`, systemd-Unit, eigener Benutzer `cdn64`,
  `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `ProtectSystem=strict`, `NoNewPrivileges`, Zustand in
  `/var/lib/cdn64-edge` (Konfigurations-Cache, Zertifikate verschlüsselt), Einstellungen in `/etc/cdn64-edge/config.yaml`
  (Server-Name, Server-Geheimnis, API-URL, gemeinsamer Zertifikatsschlüssel).
- **Ports:** 22 (SSH), 80/tcp, 443/tcp, 443/udp, 7844/udp, 7844/tcp, Server-zu-Server-Port nur für den Nachbarn.
  nftables mit festen Regeln, alles andere zu.
- **System:** unattended-upgrades, UDP-Puffer für QUIC (`net.core.rmem_max`/`wmem_max` ca. 7,5 MB), Dateilimits,
  Zeit über NTP.
- **Eigenes Zertifikat** für `srvXX.cdn64.de` (Tunnel-Port) per Let's Encrypt – braucht Dennis' OK zu den
  Let's-Encrypt-Bedingungen.
- **Deploy:** `deploy/server/edge-deploy.sh <version> cdn7 cdn8` – nacheinander, Gesundheitsprüfung, bei Fehler
  zurück auf die vorige Version (wie beim hub).
- **Überwachung:** `/health` (Version, verbundene Tunnels, Hosts, letzte Konfiguration), Healthchecks auf beide
  Server, Warnung bei Konfiguration älter als 5 Minuten.

## 10. Sicherheit

- Tunnel-Token zufällig (32 Byte), bei ipv64 und auf den Servern nur als Hash; je Node widerrufbar und erneuerbar.
- API-Key bleibt in der Node; die Server bekommen ihn nie. Server-Geheimnis je Server, bei ipv64 als Hash.
- Ein Tunnel bekommt nur Verkehr für Namen, die ipv64 ihm zugeordnet hat – die Node kann keine fremden Namen
  beanspruchen.
- Modus 1: Server sehen keine Inhalte. Modus 2: Inhalte auf den Servern nur im Speicher; Zertifikatsschlüssel
  verschlüsselt abgelegt.
- Schutz der Server: nicht angemeldete Tunnel-Verbindungen nach 5 s zu, Limits je IP, ipv64-Blocklisten, Sperre
  je Account/Host von ipv64 aus (Missbrauch).
- Logs auf den Servern ohne Inhalte, IPs nur für Limits/Statistik, kurze Aufbewahrung.

## 11. Phasen

Jede Phase endet mit Tests und einem Commit; Server-Änderungen nur nach Freigabe, PHP/SQL spielt Dennis ein.

### T0 – Grundlage auf srv07/srv08
- Grundeinrichtung (Benutzer, nftables, unattended-upgrades, sysctl), Dienst-Gerüst `cmd/cdn64-edge` mit `/health`,
  systemd-Unit, Deploy-Skript mit Rollback.
- Zertifikat für `srv07.cdn64.de`/`srv08.cdn64.de` (nach OK).
- **Fertig, wenn:** beide Server liefern `/health` per IPv4 und IPv6, Deploy und Rollback getestet.
- Betrifft nur srv07/srv08; Node, ipv64.net und altes CDN bleiben unberührt.

### T1 – Tunnel
- Protokoll (`internal/tunnel`): QUIC-Verbindung, Anmeldung, Steuer-Stream, Keepalive, Wiederverbinden, beide Server,
  TCP-Ausweichweg.
- Node-Seite: Tunnel-Client, Übergabe in den Eingang (`ServeConn`).
- Feste Testkonfiguration auf den Servern (noch ohne ipv64).
- **Messen:** Durchsatz, Latenz, Verhalten hinter NAT (node64-cdn auf der Box: NAT, ohne globales IPv6),
  Wiederverbinden bei Unterbrechung, UDP gesperrt → TCP.
- **Fertig, wenn:** Tunnel steht stabil > 24 h, Wiederverbinden < 5 s, Messwerte dokumentiert.

### T2 – Modus 1 durchreichen
- SNI-Router (443) und Host-Router (80) auf den Servern, Stream-Kopf mit Besucher-IP, Ausweichweg über den Nachbarn,
  grober Schutz (Blocklisten, Verbindungs-Limits).
- **Fertig, wenn:** ein Test-Host auf node64-cdn ist per IPv4 und IPv6 über srv07 und srv08 erreichbar, die Node
  sieht die echte Besucher-IP, Ausfall eines Servers ohne Unterbrechung neuer Verbindungen, Lasttest dokumentiert.

### T3 – Steuerung bei ipv64
- SQL `deploy/sql/cdn64_online.sql` (Tabellen aus 7.1; in MariaDB auf der Box geprüft).
- PHP: API v2 für Nodes (7.3), Server-Endpunkte (7.4), Limits/Kontingent (7.2), DNS-Umstellung (7.5).
- Server holen ihre Konfiguration von ipv64 statt aus der Testdatei.
- **Fertig, wenn:** Ein-/Ausschalten per API mit Testaccount 522 inklusive DNS hin und zurück, Kontingent mit altem
  CDN zusammen gezählt, Server übernehmen Änderungen in < 30 s, ipv64-Ausfall unterbricht keine Tunnels.

### T4 – Ein Klick in der Node
- Schalter, Fortschritt, Selbsttest, Badges, Fehlertexte, Doku (`docs/CDN64.md`, README), OpenAPI der Node.
- **Fertig, wenn:** Ein Klick bis „aktiv“ ohne Handarbeit, Ausschalten stellt alles zurück, Rauchtest grün.

### T5 – Modus 2 terminieren
- TLS/HTTP/1–3 auf den Servern, Weiterleitung als HTTP über den Tunnel, `CDN64-Connecting-IP`.
- Zertifikate per DNS-01 Wildcard über ipv64, HTTP-01-Ausweg, verschlüsselte Ablage, Erneuerung.
- Schutz auf den Servern (Blocklisten, Limits, Sperren) mit Meldung an ipv64.
- **Fertig, wenn:** Wildcard-Zertifikat ausgestellt (nach OK), WebSockets und große Uploads gehen, Modus-Wechsel
  1 ↔ 2 ohne DNS-Änderung, Schutz greift auf dem Server.

### T6 – Betrieb und Start
- Traffic je Host an ipv64 (`cdn64o_traffic`), Kontingent-Sperre, Statistik „über CDN64“ in der Node.
- Last- und Ausfalltests, Sicherheitsprüfung (Code-Review), Überwachung, Doku für Kunden, Beta mit wenigen Accounts,
  dann Freigabe.

## 12. Risiken und offene Punkte

- **Let's-Encrypt-Limits:** 50 Zertifikate je registrierter Domain und Woche. Viele Kunden-Namen liegen unter
  ipv64-Domains (DynDNS) – prüfen, ob diese auf der Public Suffix List stehen; sonst Wildcards bündeln/Staffeln
  oder ZeroSSL als zweite Stelle. Gilt vor allem für Modus 2.
- **Traffic-Zählung des alten CDN:** genauen Zeitraum und Rücksetzung in T3 nachlesen, damit das gemeinsame
  Kontingent stimmt.
- **DynDNS und deaktivierte Einträge:** prüfen, dass das Update-Skript deaktivierte Originale nicht wieder aktiviert.
- **Durchsatz:** 2 vCPU je Server; Modus 2 (TLS + HTTP/3) kostet mehr CPU – in T2/T5 messen, ggf. größere Server.
- **Hetzner-Traffic:** inklusiver Traffic der Cloud-Server im Blick behalten (Kontingente der Klassen).
- **HTTP/3 in Modus 1, TCP-/UDP-Streams, fremde Domains:** bewusst später.
- **Offene Frage an Dennis:** Satz „man sollte dann das CDN irgendwann mal …“ war abgeschnitten.
