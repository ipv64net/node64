# CDN64 – Planung (Tunnel zu srv07/srv08)

Stand: 2026-10-17 · Status: **Planung, nichts umgesetzt** · Phasen T0–T8

Der lokale Reverse-Proxy PROXY64 in Node64 wird mit einem neuen Online-CDN verbunden – so wie Cloudflare Tunnel:
die Node baut von zu Hause eine dauerhafte, verschlüsselte QUIC-Verbindung zu den CDN-Servern **srv07.cdn64.de**
(Nürnberg) und **srv08.cdn64.de** (Falkenstein) auf. Besucher kommen über IPv4 und IPv6 an diesen Servern an und
werden durch die offene Verbindung zur Node durchgereicht. Zu Hause muss kein Port offen sein.

**Namen (seit 2026-10-19):** CDN64 heißt nur das Veröffentlichen über srv07/srv08 (früher „CDN64 online“), der
lokale Reverse-Proxy heißt PROXY64. Technische Kennungen bleiben: Modul-ID `cdn64`, API `/api/cdn64/...` und
`/cdn64o/...`, Tabellen `cdn64o_*`, Programm `cdn64-edge`. Die Phasen-Protokolle unten nennen die alten Namen.

Inhalt: [1 Ziel](#1-ziel) · [2 Entscheidungen](#2-entscheidungen) · [3 Architektur](#3-architektur) ·
[4 Tunnel](#4-tunnel) · [5 Modus 1](#5-modus-1-durchreichen) · [6 Modus 2](#6-modus-2-terminieren) ·
[7 Modus 3](#7-modus-3-direkt-zum-ziel-ohne-tunnel) · [8 Steuerung bei ipv64](#8-steuerung-bei-ipv64) · [9 Node64](#9-node64) ·
[10 Edge-Dienst](#10-edge-dienst-auf-srv07srv08) · [11 Sicherheit](#11-sicherheit) · [12 Phasen](#12-phasen) ·
[13 Risiken und offene Punkte](#13-risiken-und-offene-punkte) ·
[14 Grundlagen-Check](#14-grundlagen-check-cloudflare-in-klein)

---

## 1. Ziel

- **Erreichbarkeit:** Kunden hinter Glasfaser nur mit IPv6, DS-Lite oder CGNAT sind per IPv4 **und** IPv6 erreichbar.
- **Privatsphäre:** Die Heim-IP bleibt verborgen; im DNS stehen nur srv07/srv08.
- **Ein Klick:** In der Node je Proxy-Host „CDN64“ einschalten; DNS, Server, Zertifikat und Tunnel richten
  sich im Hintergrund ein. Der Nutzer sieht den Fortschritt.
- **Drei Modi:**
  - **Modus 1 – durchreichen (Tunnel):** Die Server entschlüsseln nichts. TLS und Zertifikat bleiben zu Hause.
  - **Modus 2 – terminieren (Tunnel):** TLS endet auf den Servern. Dort greifen schon Schutz (Blocklisten, Limits,
    Sperren) und HTTP/3; danach geht es über denselben Tunnel zur Node.
  - **Modus 3 – direkt zum Ziel (ohne Tunnel):** wie das heutige CDN. Der Nutzer gibt ein Ziel an (z. B. die per
    DynDNS gepflegte IPv6 seines Anschlusses, Port, HTTP oder HTTPS); die Server terminieren TLS und verbinden sich
    selbst mit dem Ziel. Keine Node nötig – einrichtbar auf der **ipv64-Webseite** und auch aus der Node.
- **Modus 1 und 2** sind die besseren und werden auf der Webseite so beworben (keine offenen Ports, Heim-IP verborgen,
  Ende-zu-Ende verschlüsselt); sie gehen nur mit einer Node64. **Modus 3** ist der einfache Weg ohne Node.
- **Abgrenzung und Ziel:** Das bestehende CDN (srv01–srv06, nginx, `cdn_domains`) läuft vorerst unverändert weiter.
  Ziel ist **kein dauerhafter Parallelbetrieb**: Modus 3 bietet alles, was das alte CDN kann. **Es gibt keine
  Migration** – Dennis kündigt die Abschaltung an, die Kunden richten ihre Domains auf dem neuen CDN selbst neu ein,
  danach werden srv01–srv06 abgeschaltet. Beide Systeme bleiben in der Datenbank strikt getrennt.

## 2. Entscheidungen

| Thema | Entscheidung (Dennis, 2026-10-17) |
|---|---|
| Wer darf es nutzen | Jede Klasse mit `user_class.cdn_domains > 0`, rein dynamisch (Free raus = Standard auf 0 setzen) |
| Limits | Bestehende Spalten `user_class.cdn_domains` und `user_class.cdn_traffic`, bei jeder Prüfung frisch gelesen, keine neue Spalte |
| Kontingent | **Gemeinsam** mit dem alten CDN: Domains und Traffic von alt + neu zählen zusammen (alte Tabellen nur lesen) |
| Traffic | Wird in **allen drei Modi** gezählt und fließt in den Account; `cdn_traffic` ist das harte Limit – darüber wird gesperrt |
| Bandbreite | Limit je Account aus einer neuen Spalte `user_class.cdn_bandwidth` (Mbit/s, 0 = frei): Supporter begrenzt, Business und Company frei – Werte setzt Dennis, dynamisch gelesen |
| Tabellen | **Eigene neue Tabellen**, nichts mit dem alten CDN vermischen, nie in alte CDN-Tabellen schreiben |
| Konfiguration auf den Servern | ipv64-DB + API v2 sind die Wahrheit; srv07/srv08 holen ihre Konfiguration selbst per HTTPS (kein SSH-Push, kein MySQL auf den Servern) |
| DNS | A/AAAA beider Server mit TTL 10, wie beim alten CDN; der ursprüngliche Eintrag bleibt deaktiviert erhalten |
| Domains | v1 nur Domains im ipv64-Account (DNS automatisch). Fremde Domains später mit TXT-Nachweis |
| Zertifikate Modus 2 | **DNS-01 mit Wildcard** (`domain` + `*.domain`) bevorzugt, HTTP-01 nur als Ausweg |
| Zertifikate Modus 1 | Bleiben in der Node (zentrale Zertifikatsverwaltung, ipv64 DNS-01, auch Wildcard) |
| Modus 3 | Wie das alte CDN: Ziel (IP/Name aus DynDNS oder fest, Port, HTTP/HTTPS) ohne Tunnel; über die Webseite und die Node einrichtbar |
| Altes CDN | Läuft vorerst weiter; kein Dauer-Parallelbetrieb. **Keine Migration:** Abschaltung wird angekündigt, Kunden richten neu ein |

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
                                                     │ Node64 zu Hause (PROXY64)        │
                                                     │ Tunnel-Client → Eingang → Proxy  │
                                                     │ → Dienst im Heimnetz             │
                                                     └──────────────────────────────────┘
```

Drei Bausteine:

1. **cdn64-edge** – neuer Go-Dienst auf srv07 und srv08 (Quelle im Repo `ipv64_container`, `cmd/cdn64-edge`).
   In Modus 3 verbindet er sich selbst mit dem Ziel des Nutzers (statt durch den Tunnel).
2. **Tunnel-Client in Node64** – Teil des Moduls PROXY64 (`cdn64`); speist Tunnel-Verbindungen direkt in den gemeinsamen Eingang.
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
     Server-Endpunkt (Server-Geheimnis). ipv64 prüft: Domain ist als CDN64 im Modus 2 eingetragen →
     setzt den TXT über `do_zone_update`/PowerDNS und löscht ihn danach.
  3. Auf den Servern liegt **kein** PowerDNS-Key und **kein** API-Key eines Nutzers.
- **Ausweg HTTP-01:** wenn DNS-01 scheitert; der Server, der die Prüfung bekommt, aber die Bestellung nicht hält,
  fragt den Nachbarn nach dem Token.
- **Ein Zertifikat für beide Server:** Ein Server bestellt (Standard srv07, bei Ausfall srv08), legt Zertifikat und
  Schlüssel **verschlüsselt** (AES-GCM mit einem Schlüssel, den nur die beiden Server kennen) bei ipv64 ab; der andere
  holt es dort. ipv64 speichert nur Chiffretext. Erneuerung 30 Tage vor Ablauf.
- **Weitere Namen:** Mit dem Wildcard-Zertifikat lassen sich weitere Namen unter der Domain hinter derselben Node
  aufschalten (einzeln oder `*.domain.de`), DNS zeigt ebenfalls auf die Server.

## 7. Modus 3: direkt zum Ziel (ohne Tunnel)

So wie das heutige CDN, nur auf srv07/srv08 mit dem neuen Dienst:

```
Besucher ──► srv07/srv08 (TLS endet hier, Schutz) ──► Ziel des Nutzers (IPv6/IPv4, Port, http/https)
```

- **Ziel angeben:**
  - **aus dem DNS-Eintrag** (Standard, wie heute): die bisherigen A/AAAA des Namens, die beim Einschalten
    deaktiviert werden und per DynDNS weiter aktualisiert werden. ipv64 gibt den Servern bei jeder Änderung die
    aktuelle Adresse mit (Konfiguration per Long-Poll, wirkt in Sekunden);
  - **fest:** eine IP-Adresse oder ein Hostname, den die Server selbst auflösen.
  - Dazu **Port** (Standard 443 bzw. 80), **Schema** HTTP oder HTTPS, Zertifikat des Ziels prüfen ja/nein
    (Standard nein, wie beim alten CDN und beim NPM), **IPv6 bevorzugt** (dann IPv4).
- **Vorne:** TLS auf den Servern mit Wildcard-Zertifikat per DNS-01 (wie Modus 2), HTTP/1–3; optional „nur HTTP“
  wie beim alten CDN (`frontend`).
- **Funktionen wie beim alten CDN** (damit Kunden alles auf dem neuen CDN neu einrichten können):
  - WebSockets;
  - Erlauben-/Sperrliste je Domain (`cdn_block_ips` heute) – jetzt zusätzlich ipv64-Blocklisten, Limits je IP, Sperren;
  - Cache für statische Dateien mit Größen-Limit der Klasse (`cdn_cache_size`);
  - **Portmapper** (TCP/UDP-Ports roh an das Ziel, Limits `cdn_portmapper`/`cdn_mappings`) – eigene Phase, weil je
    Mapping ein Port auf den Servern belegt wird;
  - Traffic-Zählung gegen `cdn_traffic`.
- **Echte Client-IP** an das Ziel per `X-Forwarded-For`/`X-Real-IP` (wie heute).
- **Schutz gegen Missbrauch:** Ziele nur mit öffentlicher Adresse – keine privaten, Loopback-, Link-Local- oder
  eigenen Server-Adressen, auch nicht nach Auflösung eines Hostnamens (sonst könnte man über die Server interne
  Netze erreichen). Prüfung bei jeder Verbindung.
- **Einrichtung:** auf der ipv64-Webseite (neue Seite, siehe 8.6) und in der Node (Proxy-Host oder eigener Eintrag
  „nur online“). Beide nutzen dieselben PHP-Funktionen.
- **Hinweis im Formular:** Modus 1/2 werden angeboten und empfohlen; ohne Node ist Modus 3 der Weg.

## 8. Steuerung bei ipv64

### 8.1 Neue Tabellen (Präfix `cdn64o_`, getrennt vom alten CDN)

| Tabelle | Inhalt |
|---|---|
| `cdn64o_tunnels` | je Node: `id`, `userid`, `node_id`, `name`, `token_hash`, `created`, `last_seen_srv07/08`, `node_version`, `status` (aktiv/gesperrt) |
| `cdn64o_hosts` | je Name: `id`, `userid`, `fqdn`, `subdomain_id` (→ `subdomains.id`), `wildcard`, `mode` (1/2/3), `status` (pending, dns, edge, cert, active, error, disabling, blocked), `error`, `created`, `updated`, `created_via` (node/web) |
| `cdn64o_host_tunnels` | Modus 1/2: welche Tunnels einen Host bedienen (`host_id`, `tunnel_id`, `priority`) – mehrere Nodes je Host möglich (G3) |
| `cdn64o_targets` | nur Modus 3: `host_id`, `source` (records/fest), `target` (IP oder Hostname), `port`, `scheme` (http/https), `verify_tls`, `prefer_ipv6`, `frontend` (https/nur http), `websocket`, `cache_mb` |
| `cdn64o_acl` | Erlauben-/Sperrliste je Host (alle Modi auf den Servern; Modus 1 nur IP-basiert) |
| `cdn64o_mappings` | Portmapper (Modus 3): `host_id`, `listen_port`, `transport` (tcp/udp), `target_port`, Server-Zuteilung |
| `cdn64o_records` | DNS-Umstellung: `host_id`, `record_id` (→ `subdomain_records.id`), `role` (angelegt für Server / Original deaktiviert) – statt der Spalten `cdn_tmp`/`cdn_token` des alten CDN |
| `cdn64o_edges` | `id`, `name`, `hostname`, `ipv4`, `ipv6`, `secret_hash`, `last_seen`, `version`, `disabled` |
| `cdn64o_certs` | `fqdn`, `blob` (verschlüsselt durch die Server), `not_after`, `issued_by`, `updated` |
| `cdn64o_traffic` | `host_id`, `userid`, `day`, `bytes_in`, `bytes_out`, `requests`, `rejected` – alle Modi, gemeldet von den Servern |
| `cdn64o_events` | Verlauf je Host für Anzeige und Support (Schritte, Fehler) |

`subdomain_records` ist die DNS-Tabelle selbst und wird zwangsläufig genutzt (neue A/AAAA-Zeilen, Original
deaktivieren) – die Zuordnung steht aber nur in `cdn64o_records`, nie in den Spalten des alten CDN.

### 8.2 Limits und Kontingent

- **Domains:** `aktive Domains im alten CDN (cdn_domains)` + `Einträge in cdn64o_hosts` ≤ `user_class.cdn_domains`
  der aktuellen Klasse des Accounts. Frisch gelesen bei jeder Prüfung.
- **Traffic:** Verbrauch altes CDN (bestehende Zähler, nur lesen) + Summe `cdn64o_traffic` im gleichen Zeitraum ≤
  `user_class.cdn_traffic` (GB). Zeitraum/Rücksetzung wie beim alten CDN – in T3 im Code des alten CDN genau
  nachlesen (`cdn_traffic_gate`).
- **Gezählt wird überall:** Modus 1 (rohe Bytes durch den Server, in beide Richtungen), Modus 2 und 3 (Anfragen und
  Antworten). Die Server zählen je Host und melden alle 60 s an ipv64 (`/cdn64o/edge/report`); ipv64 summiert je
  Account. Fällt die Meldung aus, puffern die Server und melden nach.
- **Hartes Limit:** Ist `cdn_traffic` des Accounts erreicht, setzt ipv64 alle Hosts des Accounts auf `blocked`
  (Server weisen mit neutraler Seite ab bzw. trennen in Modus 1), die Node und die Webseite zeigen den Grund.
  Warnung vorher bei 80 % und 95 % (Mail/Benachrichtigung). Neuer Zeitraum oder höhere Klasse → automatisch frei.
- **Bandbreite:** neue Spalte `user_class.cdn_bandwidth` (Mbit/s, 0 = unbegrenzt), frisch gelesen wie die anderen
  Limits. Supporter bekommt einen Wert, Business und Company 0. Die Server begrenzen je **Account** (alle Hosts
  zusammen, beide Richtungen, Token-Bucket); die beiden Server gleichen ihren Verbrauch über die Nachbar-Verbindung
  ab, damit das Limit insgesamt gilt und nicht je Server.
- **Klasse abgelaufen / Limit überschritten:** Host geht auf `blocked`; Server weisen ab (neutrale Seite), DNS bleibt
  bis zum Ausschalten. Nutzer sieht den Grund in der Node.

### 8.3 API v2 für Nodes (API-Key des Containers)

| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/cdn64o` | Kontingent (Domains, Traffic, Klasse), Tunnel und Hosts des Accounts |
| POST | `/cdn64o/tunnels` | Node anmelden → `tunnel_id` + Token (nur einmal sichtbar), Server-Liste |
| DELETE | `/cdn64o/tunnels/{id}` | Tunnel entfernen (Hosts werden ausgeschaltet) |
| POST | `/cdn64o/hosts` | `{fqdn, mode, wildcard, tunnel_id}` bzw. bei Modus 3 `{fqdn, mode: 3, target…}` einschalten: Klasse/Kontingent prüfen, Domain gehört dem Account, nicht im alten CDN, DNS umstellen |
| PUT | `/cdn64o/hosts/{id}/target` | Modus 3: Ziel, Port, Schema, Optionen ändern |
| GET/PUT | `/cdn64o/hosts/{id}/acl` | Erlauben-/Sperrliste |
| GET | `/cdn64o/hosts/{id}` | Status mit Schritten |
| PATCH | `/cdn64o/hosts/{id}` | Modus wechseln; `{paused: true\|false}` pausiert bzw. setzt fort (alle Modi) |
| DELETE | `/cdn64o/hosts/{id}` | ausschalten: DNS zurück, Zertifikat auf den Servern löschen |

Umsetzung als eigene Datei `deploy/web/api_v2_cdn64o.php`, eingebunden wie `api_v2_hc2.php`; OpenAPI ergänzen.

**Pause (alle Modi, 2026-10-21):** `cdn64o_hosts.paused` (mit `paused_at`), getrennt von der Traffic-Sperre
(`status`/`blocked_reason`). Die Server bekommen den Namen mit `blocked: "paused"`. Damit greift dieselbe Sperre wie
beim Traffic-Limit: Modus 1 trennt die Verbindung, Modus 2/3 antworten mit 503, Portmapper und QUIC nehmen nichts an,
offene Verbindungen trennt `recheckLive` nach dem nächsten Abruf der Konfiguration. DNS bleibt auf den Servern, die
Adresse des Ziels bzw. der Node bleibt also verborgen. Einstellungen, Liste, Portmapper und Statistik bleiben erhalten.
Pausieren und Fortsetzen geht auf der Webseite (`cdn64.php`, alle Namen) und in PROXY64: am eigenen Host und in der
Karte „Weitere Namen in CDN64“. Namen, die die Node nicht verwaltet (Modus 3, andere Nodes), stehen nur lesend in der
Zeile ihres Hosts, wenn es hier einen Host mit dem Namen gibt (kein Einschalten dort), sonst in dieser Karte: Ziel,
Cache, Liste, Portmapper, Status, Traffic. Einträge `paused`/`resumed` in `cdn64o_events` und im Log.

**Portmapper Modus 1/2 (2026-10-21):** `cdn64o_mappings` gilt für alle Modi. In Modus 1/2 ist `target_port` der Port
eines Streams in PROXY64. Die Server öffnen den Port wie in Modus 3, wählen aber nicht das Ziel an, sondern öffnen einen
Stream `tcp` bzw. `udp` durch den Tunnel (Kopf: Name, Ziel-Port, echte Besucher-Adresse; UDP als Datagramme mit
Länge). Ohne Tunnel auf diesem Server geht es über den Nachbarn (der zählt und begrenzt). Die Node meldet dafür die
Fähigkeit `ports`; ältere Nodes bekommen keine solchen Streams. In der Node wählt man am Stream den CDN64-Namen
(`cdn_streams.online_name`); die Node meldet je Protokoll ein Mapping an (`cdn_online_ports`), trägt es beim
Ausschalten, Löschen oder Portwechsel wieder aus und meldet es neu an, wenn es bei ipv64 fehlt. Eingehende Streams
landen nur bei angemeldeten Streams (Name + Protokoll + Port), mit Blocklisten, Grenzen je IP und Ländersperre.
TCP-Verbindungen über den Portmapper (alle Modi) trennen die Server nach 1 Stunde ohne Daten in beide Richtungen
(cdn64-edge 0.15.1).

**Entfernte Namen auf den Servern (2026-10-26, cdn64-edge 0.18.1):** Verschwindet ein Name aus `edge/config` (gelöscht,
Konto gelöscht, verwaister Tunnel von `bots/cdn64_orphans.php` aufgeräumt), lassen srv07/srv08 ihn beim nächsten
Abruf fallen: Route weg, laufende Verbindungen (auch Portmapper) getrennt, Portmapper-Listener geschlossen, Tunnel
ohne Eintrag getrennt (Token gilt nicht mehr), Cache-Einträge beim nächsten Durchlauf (jede Minute) gelöscht, Zähler
je Name (`/health`, Metriken) und Zertifikats-Plan vergessen. Lokal gespeicherte Zertifikate (Modus 2) bleiben noch
7 Tage (Schutz bei kurzzeitig fehlender Konfiguration), dann werden sie gelöscht; die verschlüsselte Ablage bei
ipv64 entfernt ipv64 selbst.

**Parallele Tunnel-Verbindungen (2026-10-23, PROXY64 1.26.0, cdn64-edge 0.18.0):** `user_class.cdn_tunnel_sessions`
(Business/Company 4, sonst 1) geht als `sessions` an die Node (Tunnel in `GET /cdn64o`) und an die Server (Tunnels in
`edge/config`). Die Node baut je Server so viele Verbindungen auf (Hello `slot` 0..n-1, jede mit eigenem Rückfall
QUIC → QUIC 443 → TLS); der Server lehnt höhere Slots ab (Welcome `sessions` = Grenze, die Node lässt den Slot dann
aus) und gibt neue Besucher-Streams an die Verbindung mit den wenigsten offenen Streams (bei Gleichstand reihum),
bei einem Fehler an die nächste. Grund: Lasttest 2026-10-23 – eine QUIC-Verbindung je Server deckelte Modus 1/2 bei
etwa 650–830 Mbit/s (ein CPU-Kern). Nebenbei begrenzt das die Zahl der Verbindungen je Tunnel (vorher unbegrenzt).

**Schutz-Zähler, Muster-WAF und JA4 (2026-10-27, cdn64-edge 0.19.0, Plan `docs/PLAN-CDN64-SCHUTZ.md`):** `edge/report`
meldet je Host zusätzlich `blocked_list`, `blocked_acl`, `blocked_flood`, `blocked_waf`, `blocked_ja4`, `ja4_hits`,
`conns_v4` (Differenzen), `blocked_ips` (verschiedene gesperrte IPs im Intervall, IPv6 je /64, höchstens 1000) und
`ja4_top` (höchstens 20). Zuordnung zum Host: Blocklisten-Treffer lesen vor dem Schließen noch SNI bzw. Host-Kopf
(≤ 1 s, ≤ 4 KB, höchstens 256 gleichzeitig), Überlast (Verbindungen je IP, Rate, insgesamt) zählt ohne weiteres Lesen
beim zuletzt angefragten Host der IP, ohne Host nur gesamt; Zugriffsliste überall dort, wo sie geprüft wird (zählt
nicht mehr als `rejected`, das bleibt das Anfrage-Limit). Muster-WAF nur Modus 2/3 vor der Weitergabe: einfache
Textvergleiche auf Pfad (dekodiert, nicht bereinigt) und User-Agent, Treffer → 403 mit der Fehlerseite; je Host
`waf` in `edge/config` (fehlt = an). JA4: in `handle443` einmal je Verbindung aus dem ohnehin gelesenen ClientHello
(`internal/fingerprint`, gemeinsam mit Honeypot64), alle Modi auf TCP 443 (nicht QUIC); Liste `ipv64_ja4.txt` von
`blocklist_base` (nur mit `api_url`, alle 30 min mit ETag, Zwischenspeicher `data_dir/blocklists/`), je Host `ja4` =
`off` | `count` (Standard) | `block` (Verbindung zu).

**Review-Korrekturen (2026-10-28, cdn64-edge 0.20.0, PROXY64 1.39.0; Commits b25d3e8, 931f2bc):**
- **Port 80 in Modus 1:** Die Verbindung geht nach dem Host der ersten Anfrage in den Tunnel. Jede weitere Anfrage
  derselben Verbindung (Keep-Alive, absolute URL) wird mitgelesen (`hostgate.go`, gleicher Parser wie die Node) und
  muss an denselben Namen gehen, sonst wird getrennt. Nach einem Upgrade (WebSocket) geht es roh weiter.
- **QUIC auf 443 (HTTP/3 Modus 2/3, Tunnel):** Absender ohne nachgewiesene Adresse (vor dem Handschlag, also
  fälschbar) belegen keinen Platz bei „Verbindungen je IP/insgesamt“, sondern ein eigenes UDP-Budget (¼ von
  `max_conns`). Warten mehr als 64 Handschläge ohne Nachweis, verlangt der Server ein Retry (Adresse belegen, eine
  Rundreise mehr). Nach dem Handschlag zählt die Verbindung wie TCP bis zu ihrem Ende.
- **QUIC durchreichen (Modus 1, HTTP/3):** Bis der Besucher die Verbindungs-ID der Node zurückschickt (Nachweis, höchstens
  10 s), darf die Node ihm höchstens 1500 B + 3 × Eingang schicken (keine Reflexion über gefälschte Absender);
  Datagramme über 1500 B werden verworfen.
- **Modus 2/3 auf Port 80:** Die Frontend-Stufe (bedienen, umleiten, ablehnen) gilt je Anfrage, nicht nur für die erste
  Anfrage der Verbindung. Unternamen eines Wildcard-Namens nur mit Zertifikat, das sie abdeckt (HTTP-01-Ausweg ohne
  `*.name`); DNS-01-Fehler werden nach 6–24 h erneut versucht.
- **Tunnel:** Je Tunnel und Slot höchstens eine Verbindung – eine neue (Neuverbindung, alte noch nicht als tot
  erkannt) ersetzt die alte. Öffnet eine Node selbst einen weiteren Stream (sie öffnet nur den Steuer-Stream), endet die
  Verbindung; Rückstau vor der Anmeldung (TCP/yamux) 256. Ein vom Server abgelehnter Slot (Klasse abgesenkt) versucht
  es nach 2–5 Minuten erneut, statt bis zum Neustart aus zu bleiben.
- Außerdem: Platz im Schutz bis zum Ende der Verbindung (auch wenn sie an den Nachbarn bzw. die Terminierung
  weitergereicht wurde), Cache-Zwischendatei bei Abbruch entfernt, QUIC-Einstellungen je Verbindung wieder wirksam.

### 8.4 Endpunkte für die Server (Server-Geheimnis, eigene Datei)

| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/cdn64o/edge/config` | Tunnels (Token-Hashes) und Hosts (Name, Modus, Tunnel, gesperrt; bei Modus 3 Ziel mit aktueller DynDNS-Adresse, Liste, Mappings); ETag, Long-Poll bis 25 s |
| POST | `/cdn64o/edge/report` | verbundene Tunnels, Traffic-Deltas je Host, Abweisungen, Version |
| POST/DELETE | `/cdn64o/edge/acme-txt` | TXT für DNS-01 setzen/löschen (nur für eingetragene Modus-2-Hosts) |
| GET/PUT | `/cdn64o/edge/certs/{fqdn}` | verschlüsseltes Zertifikat ablegen/holen |

Die Server speichern die letzte Konfiguration lokal: **fällt ipv64 aus, laufen alle Tunnels weiter**, nur Änderungen
warten.

### 8.5 DNS-Umstellung

- Einschalten: für `fqdn` (und bei Wildcard `*.fqdn`) A = IPv4 von srv07 und srv08, AAAA = IPv6 von beiden, TTL 10;
  vorhandene A/AAAA des Namens deaktivieren; `do_zone_update`. Gleiches Verfahren wie das alte CDN, eigene Zuordnung.
- Ausschalten: angelegte Zeilen löschen, Originale wieder aktivieren, `do_zone_update`.
- DynDNS: Updates landen weiter auf dem deaktivierten Original (Verhalten des Update-Skripts in T3 prüfen) und
  greifen erst nach dem Ausschalten wieder.
- Konflikt: Name schon im alten CDN oder bei einem anderen Account → ablehnen.
- Modus 3 mit Ziel „aus dem DNS-Eintrag“: Ändert DynDNS das deaktivierte Original, schreibt ipv64 die neue Adresse in
  die Server-Konfiguration (Hook im DynDNS-Update oder Abgleich im Config-Endpunkt).

### 8.6 Webseite ipv64.net

- **Neue Seite** (z. B. `cdn64.php`, Menü „CDN64“), getrennt von `cdn.php`:
  - Kontingent (gemeinsam mit dem alten CDN), alle Hosts des Accounts mit Modus, Status, Traffic, Servern;
  - **Modus 3 anlegen und verwalten** (Ziel, Port, HTTP/HTTPS, WebSockets, Liste, Cache, Portmapper);
  - **Modus 1/2** werden angezeigt (Status, Traffic, Ausschalten, Tunnel der Nodes) und beworben, eingerichtet aber in
    der Node – mit Erklärung und Link zu Node64;
- Gleiche PHP-Funktionen wie API v2 (`cdn64o_lib.php`), damit Webseite, API und Node nie auseinanderlaufen.
- Werbeseite (`reverse_proxy.php`) später auf die drei Modi umschreiben.

## 9. Node64

- **Voraussetzung:** ipv64-API verbunden (zentraler API-Key). Ohne Key oder ohne Kontingent ist der Schalter
  ausgegraut mit Begründung und Link zu `/plans`.
- **Proxy-Host-Formular / Liste:** Schalter **„CDN64“** mit Auswahl Modus 1 / Modus 2 und „Wildcard“.
- **Ein Klick – Fortschritt** (live auf der Seite):
  1. Klasse und Kontingent geprüft
  2. Tunnel angemeldet (einmalig je Node)
  3. DNS umgestellt
  4. Server haben die Konfiguration
  5. Tunnel zu srv07 ✓ / srv08 ✓
  6. Zertifikat bereit (Modus 1: lokal; Modus 2: auf den Servern)
  7. **Selbsttest übers Internet:** Die Node ruft `https://domain/.well-known/cdn64-check/<zufall>` über die Server
     auf und beantwortet ihn selbst durch den Tunnel – beweist den ganzen Weg.
- **Anzeige:** Badge „CDN64 (srv07 ✓ srv08 ✓)“ in der Host-Tabelle, Modus, Traffic über CDN64,
  Abweisungen auf den Servern (Modus 2) im Verkehr-Diagramm.
- **Ohne Portfreigabe:** Hosts, die nur über CDN64 laufen, brauchen keine offenen Ports 80/443 im Router. Im
  Heimnetz bleibt der direkte Zugriff wie bisher.
- **Modus 3 aus der Node:** zusätzlich wählbar, wenn jemand bewusst ohne Tunnel arbeiten will (z. B. Ziel ist ein
  anderes Gerät mit eigener öffentlicher IPv6). Die Node legt es per API an; Modus 1/2 werden im Formular empfohlen.
- **Code:** `internal/tunnel` (Protokoll, Client), `internal/cdn64/online.go` (API, Fortschritt, UI), Eingang:
  neue Methode, die eine fertige Verbindung annimmt (`ServeConn(conn, port)`).

## 10. Edge-Dienst auf srv07/srv08

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
- **Traffic und Bandbreite:** Zähler je Host im Speicher, alle 60 s an ipv64, bei Ausfall lokal gepuffert
  (`/var/lib/cdn64-edge/traffic`). Bandbreiten-Limit je Account mit Abgleich zum Nachbarserver.

## 11. Sicherheit

- Tunnel-Token zufällig (32 Byte), bei ipv64 und auf den Servern nur als Hash; je Node widerrufbar und erneuerbar.
- API-Key bleibt in der Node; die Server bekommen ihn nie. Server-Geheimnis je Server, bei ipv64 als Hash.
- Ein Tunnel bekommt nur Verkehr für Namen, die ipv64 ihm zugeordnet hat – die Node kann keine fremden Namen
  beanspruchen.
- Modus 1: Server sehen keine Inhalte. Modus 2: Inhalte auf den Servern nur im Speicher; Zertifikatsschlüssel
  verschlüsselt abgelegt.
- Schutz der Server: nicht angemeldete Tunnel-Verbindungen nach 5 s zu, Limits je IP, ipv64-Blocklisten, Sperre
  je Account/Host von ipv64 aus (Missbrauch).
- Logs auf den Servern ohne Inhalte, IPs nur für Limits/Statistik, kurze Aufbewahrung.
- Modus 3: Ziele nur öffentlich erreichbare Adressen (Prüfung nach jeder Namensauflösung), keine Server-eigenen
  Adressen und Ports; Portmapper nur auf freigegebenen Port-Bereichen.

## 12. Phasen

Jede Phase endet mit Tests und einem Commit; Server-Änderungen nur nach Freigabe, PHP/SQL spielt Dennis ein.

### T0 – Grundlage auf srv07/srv08
- Grundeinrichtung (Benutzer, nftables, unattended-upgrades, sysctl), Dienst-Gerüst `cmd/cdn64-edge` mit `/health`,
  systemd-Unit, Deploy-Skript mit Rollback.
- Zertifikat für `srv07.cdn64.de`/`srv08.cdn64.de` (nach OK).
- **Fertig, wenn:** beide Server liefern `/health` per IPv4 und IPv6, Deploy und Rollback getestet.
- Betrifft nur srv07/srv08; Node, ipv64.net und altes CDN bleiben unberührt.
- **Stand 2026-10-17:** erledigt bis auf Zertifikat und Überwachung (warten auf Dennis).
  - Einrichtung: `deploy/server/setup-edge.sh` auf beiden Servern (Benutzer `cdn64-edge`, nftables, Sicherheitsupdates,
    sysctl, systemd-Unit mit Härtung, `systemd-analyze security` 3.2).
  - Dienst: `cdn64-edge` 0.1.0 mit `/health` auf Port 80 (von außen nur Status/Name/Version).
  - Geprüft: von außen per IPv4 und IPv6, Rollback mit kaputtem Binary (srv08 kehrt zu 0.1.0 zurück), Neustart beider
    Server (Dienst, Firewall, sysctl wieder aktiv).
  - Deploy: `bash deploy/server/edge-deploy.sh <version> [cdn7 cdn8]`.

### T1 – Tunnel
- Protokoll (`internal/tunnel`): QUIC-Verbindung, Anmeldung, Steuer-Stream, Keepalive, Wiederverbinden, beide Server,
  TCP-Ausweichweg.
- Node-Seite: Tunnel-Client, Übergabe in den Eingang (`ServeConn`).
- Feste Testkonfiguration auf den Servern (noch ohne ipv64).
- **Messen:** Durchsatz, Latenz, Verhalten hinter NAT (node64-cdn auf der Box: NAT, ohne globales IPv6),
  Wiederverbinden bei Unterbrechung, UDP gesperrt → TCP.
- **Fertig, wenn:** Tunnel steht stabil > 24 h, Wiederverbinden < 5 s, Messwerte dokumentiert.
- **Stand 2026-10-17 (Commits 0254843 ff.):** umgesetzt und live gemessen; offen nur der 24-h-Lauf (läuft seit
  2026-10-17 ~18:00 mit node64-cdn auf der Box).

  | Messung | Ergebnis |
  |---|---|
  | Box (NAT, kein IPv6) → srv07/srv08 | beide per QUIC über IPv4 verbunden, kein offener Port |
  | PC mit nativem IPv6 → srv07/srv08 | beide per QUIC **über IPv6** verbunden |
  | Kleine Anfrage Server → Tunnel → Node → Dienst | ca. 28 ms (RTT 26–35 ms) |
  | 200 MB durch den Tunnel (QUIC, IPv4) | 6,1 MB/s ≈ 49 Mbit/s = voller Upload des Anschlusses (SSH-Vergleich ohne Tunnel: 37 Mbit/s) |
  | 100 MB durch den Tunnel (QUIC, IPv6) | 5,8–6,1 MB/s ≈ 47 Mbit/s |
  | UDP gesperrt | nach ca. 20 s von selbst auf TCP (beide Server), 200 MB mit 5,4 MB/s ≈ 43 Mbit/s |
  | Neustart eines Servers (GOAWAY) | Node nach 1,3 s wieder verbunden, Anfrage danach sofort ok |
  | Let's Encrypt für srv07/srv08.cdn64.de | per HTTP-01 beim Start geholt |

  Erkenntnis G4: Auf Docker-Hosts mit Standard-`rmem_max` (208 KiB) meldet quic-go zu kleine UDP-Puffer; bei 50 Mbit/s
  ohne Folgen, bei schnelleren Anschlüssen bremst es → Hinweis mit Befehl in der Node (T4).
  Gefunden und behoben: Anmeldung nach langem Handschlag lief in die 5-s-Frist des Verbindungsaufbaus (eigene Frist 10 s).

### T2 – Modus 1 durchreichen
- SNI-Router (443) und Host-Router (80) auf den Servern, Stream-Kopf mit Besucher-IP, Ausweichweg über den Nachbarn,
  grober Schutz (Blocklisten, Verbindungs-Limits).
- Traffic-Zählung je Host auf den Servern ab hier (zuerst nur lokal und in `/health`).
- **Fertig, wenn:** ein Test-Host auf node64-cdn ist per IPv4 und IPv6 über srv07 und srv08 erreichbar, die Node
  sieht die echte Besucher-IP, Ausfall eines Servers ohne Unterbrechung neuer Verbindungen, Lasttest dokumentiert,
  gezählte Bytes stimmen mit einer Messung auf der Node überein.
- **Stand 2026-10-17:** umgesetzt (cdn64-edge 0.3.1), live gemessen mit dem Test-Host `t2.node64.test` auf node64-cdn
  (Box: NAT, kein IPv6, kein offener Port); Aufruf per `curl --resolve` (für einen Namen im DNS fehlt noch T3).

  | Messung | Ergebnis |
  |---|---|
  | Besucher über srv07/srv08 × IPv4/IPv6, Port 443 und 80 | alle 8 Wege ok; beim Ziel kommt die echte Besucher-IP an (IPv6-Besucher bei einer Box ganz ohne IPv6) |
  | Aus fremdem Netz (hub1), komplette TLS-Anfrage bis zum Dienst | 65–75 ms |
  | Unbekannter Name | Verbindung getrennt |
  | Tunnel zu srv08 gekappt | Besucher an srv08 laufen über srv07 (Nachbar-Port 7845, + ca. 20 ms); srv08 merkt den Wegfall nach 25 s (vorher 68 s; Wachhalten 10 s, Zeitlimit 30 s) |
  | 2.000 Anfragen, 50 gleichzeitig, je eigener TLS-Handshake bis zur Node | 2.000 × 200 in 29,5 s; srv07 Load 0,5 |
  | 100 MB über srv07 | 6,0 MB/s = Upload des Anschlusses; srv07 zählt 105 MB (Nutzdaten + TLS + Anfragen) |
  | Schutz | ohne Ausnahme greifen srv07 (Rate je IP) **und** die Node (sieht die echte IP von hub1, begrenzt und sperrt) |

  Umsetzung: `internal/cdnedge/route.go` (SNI/Host-Routing inkl. `*.domain`, Nachbar-Port mit gemeinsamem
  Geheimnis, Zähler je Name in `/health`), `guard.go` (Verbindungen je IP/64, Rate, insgesamt, ipv64-Blocklisten –
  auf den Servern vorerst nur `spamhaus_drop`), gemeinsamer Blocklisten-Kern `internal/shield` (Node und Server).
  Port 80: Verteilung je Verbindung nach dem Host der ersten Anfrage; die eigene Seite (/health, ACME) ohne Keep-Alive.
  Offen für später: Tunnel-Ausfall noch schneller erkennen (eigene Pings, Retry über den Nachbarn beim Öffnen).

### T3 – Steuerung bei ipv64
- SQL `deploy/sql/cdn64_online.sql` (Tabellen aus 8.1; in MariaDB auf der Box geprüft).
- PHP: API v2 für Nodes (8.3), Server-Endpunkte (8.4), Limits/Kontingent (8.2), DNS-Umstellung (8.5).
- Server holen ihre Konfiguration von ipv64 statt aus der Testdatei.
- Traffic-Meldung an ipv64, Summe je Account, hartes Limit (`blocked`) und Warnungen; Spalte
  `user_class.cdn_bandwidth` (SQL für Dennis) und Bandbreiten-Limit auf den Servern.
- **Fertig, wenn:** Ein-/Ausschalten per API mit Testaccount 522 inklusive DNS hin und zurück, Kontingent mit altem
  CDN zusammen gezählt, Server übernehmen Änderungen in < 30 s, ipv64-Ausfall unterbricht keine Tunnels, ein
  künstlich kleines Traffic-Limit sperrt den Test-Host, ein Bandbreiten-Limit greift über beide Server.
- **Stand 2026-10-17:** umgesetzt, wartet auf das Einspielen bei ipv64 (Anleitung
  `deploy/web/T3-CDN64-ONLINE-VORHER-NACHHER.md`).
  - SQL `deploy/sql/cdn64_online.sql` (Tabellen `cdn64o_*`, `user_class.cdn_bandwidth`, srv07/srv08 mit dem SHA-256
    ihres Server-Geheimnisses), PHP `deploy/web/api_v2_cdn64o.php`.
  - DNS-Einträge der Server mit `cdn_tmp = 3` in `subdomain_records`: `update.php` (nimmt bei gleichem Namen den
    Eintrag mit kleinstem `cdn_tmp`) überspringt sie, API v2 schützt sie vor Änderungen; ohne diese Markierung könnte
    ein DynDNS-Update bei Namen ohne eigenen A-Eintrag den Server-Eintrag überschreiben.
  - Server: `api.go` (Konfiguration alle 10 s mit ETag, Zwischenspeicher `config.json`, Meldung jede Minute mit
    laufend gezählten Bytes), `bandwidth.go` (Limit je Account, Raten jede Sekunde mit dem Nachbarn abgeglichen),
    gesperrte Hosts: Port 80 → 503, 443 → getrennt; Tunnels, die bei ipv64 fehlen oder gesperrt sind, werden getrennt.
  - Getestet: PHP in einer Testumgebung (MariaDB 10.5 + PHP 8.3, 37 Prüfungen: Kontingent mit altem CDN, Klasse,
    DNS hin und zurück, Konflikte, PowerDNS-Fehler mit Rücknahme, ETag, Server-Anmeldung, Traffic-Sperre und Freigabe
    im neuen Monat), Go-Tests (Fake-ipv64, Bandbreite) und Durchstich echter cdn64-edge + Test-Node gegen das PHP
    (Weiterleitung inkl. Wildcard und Port 80, Meldung landet in `cdn64o_traffic`, Sperre → 503, Ausschalten wirkt
    in 10 s). srv07/srv08 laufen mit 0.4.0 und warten auf die Endpunkte (bis dahin feste Konfiguration).

### T4 – Ein Klick in der Node
- Schalter, Fortschritt, Selbsttest, Badges, Fehlertexte, Doku (`docs/CDN64.md`, README), OpenAPI der Node.
- **Fertig, wenn:** Ein Klick bis „aktiv“ ohne Handarbeit, Ausschalten stellt alles zurück, Rauchtest grün.
- **Stand 2026-10-18 (CDN64 1.7.0, Node 0.11.96): fertig.** Rauchtest gegen das echte ipv64 grün (node64-test,
  pfsense.ipv64.de, Ziel ein Echo-Dienst): ein Klick bis „aktiv“, DNS sofort auf srv07/srv08, Selbsttest ok,
  Besucher von außen (hub1) erreichen das Ziel über alle vier Server-Adressen und über DNS, mit echter IPv4- bzw.
  IPv6-Adresse am Ziel (die Box selbst hat kein IPv6); Ausschalten stellt den DNS zurück und meldet den Tunnel ab.
  Gefunden und eingebaut: Selbsttest wiederholt direkt nach dem Einschalten (Server holen die Einstellung bis
  10 s später) und meldet Namen, die in der Node ein anderes Modul belegt (dort war es DNS64/DoH).
  - Node: Spalte *CDN64 online* in den Host-Listen, Fenster mit vier Schritten (Account mit Kontingent, Tunnel,
    Namen, Selbsttest), Fehlertexte mit Abhilfe je Code von ipv64 (E2/E3), Hinweis bei TCP statt UDP und zu
    kleinem UDP-Puffer (G4), Online-Healthcheck auf Wunsch (E4), geteilter DNS über DNS64 (E5: Antwort mit der
    Adresse der Node auf der Schnittstelle des Fragenden; Node im Bridge-Netz bleibt bei der normalen Antwort).
  - Ablauf: `POST /api/cdn64/online/tunnel` (Tunnel bei ipv64 anlegen bzw. prüfen, Server-Liste übernehmen,
    Token verschlüsselt), `POST /api/cdn64/hosts/{id}/online` (jeder Name einzeln; scheitern alle, wird der
    Tunnel wieder abgemeldet), `POST …/online/test`, `DELETE …/online` (mit dem letzten Namen geht der Tunnel).
    Abgleich jede Minute und nach Änderungen an Hosts: gelöschte Hosts und entfernte Namen werden bei ipv64
    ausgeschaltet, auf der Webseite ausgeschaltete Namen hier ausgetragen, neue Server-Liste übernommen.
  - Selbsttest: je Name über jeden Server und jede Adresse (IPv4/IPv6) TLS-Handschlag bzw. HTTP auf Port 80;
    ok nur, wenn die Probe durch den Tunnel genau dieser Node ankam (Zähler je Name im Tunnel-Eingang). Meldet
    auch „über eine andere Node“, fehlende Adressfamilie der Node, nicht vertrauenswürdiges Zertifikat und ob ein
    öffentlicher Resolver schon die Server nennt.
  - Getestet: Go-Ende-zu-Ende-Test mit echtem cdn64-edge und nachgebautem ipv64 (Einschalten, Fehlercodes,
    Selbsttest durch den Tunnel, Ausschalten, Abgleich nach Löschen); Selbsttest live über srv07/srv08 von
    node64-cdn (IPv4 ok in 75–81 ms, IPv6 dort nicht vorhanden → übersprungen); Oberfläche im Browser mit
    lokaler Node, nachgebautem ipv64 und echtem Tunnel zu srv07/srv08 (alle Schritte, Fehler je Name, Selbsttest
    aus der Liste, Ausschalten).
  - 24-Stunden-Lauf des Tunnels (T1) ausgewertet: seit dem letzten Deploy (17.10. 18:18) 12 h ohne Abbruch und
    ohne Fehlversuch auf beiden Servern (QUIC, 22–45 ms je Anfrage); die Wechsel davor waren eigene Deploys.

### T5 – Modus 2 terminieren
- **Stand 2026-10-18 (cdn64-edge 0.5.0, CDN64 1.8.0):** eingespielt (ipv64, srv07/srv08, node64-test 0.11.97) und
  live getestet, erst mit dem Staging, dann (OK von Dennis) mit **echtem Let's Encrypt**: Wildcard-Zertifikat
  pfsense.ipv64.de + *.pfsense.ipv64.de (Aussteller YE2) nach rund 50 s auf srv07, srv08 aus der Ablage; von hub1
  ohne eigene Root: HTTP/2 über alle vier Adressen und DNS, HTTP/3, echte IP; danach DNS zurück, keine TXT-Reste,
  Ablage gelöscht. **T5 fertig.** Offen für T6: HTTP-01-Ausweg, Aufräumen lokaler Zertifikate ausgeschalteter Namen
  (bleiben bis dahin und werden beim erneuten Einschalten wiederverwendet), Anfragen/Abweisungen an ipv64 melden.
  - Live (pfsense.ipv64.de, Ziel Echo-Dienst): Einschalten im Modus 2 per Klick, srv07 hatte das Zertifikat
    (Name + Wildcard) nach rund 40 s, srv08 übernahm es aus der Ablage, TXT danach wieder weg. Von hub1: HTTPS über
    alle vier Adressen mit HTTP/2 und gültiger Kette (Staging-Root), HTTP/3 über QUIC, `Alt-Svc`, Wildcard-Name,
    Port 80 → 301, fremder Host → 421, echte IPv4/IPv6 am Ziel. Ausschalten: DNS zurück, Ablage bei ipv64 gelöscht.
  - Server: TLS endet für Modus-2-Namen mit Zertifikat (sonst Durchreichen wie Modus 1), HTTP/1.1/2, HTTP/3 mit
    `http3: true`; je Anfrage ein Tunnel-Stream `http` mit der Besucher-Adresse im Kopf (statt
    `CDN64-Connecting-IP`: so gilt die Adresse je Anfrage und die Node braucht keinem Kopf zu trauen), auch über den
    Nachbarn; X-Forwarded-* der Besucher werden entfernt; Host muss zum SNI passen (421); Anfrage-Limit je IP/64
    (`shield.req_rate`, Standard 50/s, kurz 500, 429); Port 80 → 301 HTTPS; Node nicht erreichbar → Seite 502,
    gesperrt → 503; WebSockets und große Uploads gestreamt; Traffic und Bandbreite wie Modus 1.
  - Zertifikate: `certs.go`/`acme.go`, je Name `name` + `*.name` per DNS-01, TXT über
    `POST /cdn64o/edge/acme-txt` (nur Modus-2-Namen, im Account des Hosts), Warten bis alle Nameserver liefern;
    `acme_primary` bestellt, der andere erst nach 10 Minuten ohne Zertifikat; Ablage AES-256-GCM (`cert_key`, an
    den Namen gebunden) über `PUT/GET /cdn64o/edge/certs`, älteres ersetzt nie neueres; lokal `data_dir/certs`;
    Erneuerung 30 Tage vorher, Fehlversuche mit Pause 5 min bis 6 h. HTTP-01-Ausweg noch nicht.
  - Node: Streams `http` laufen über einen eigenen internen Eingang und gelten als HTTPS; Modus wählbar, Wechsel
    ohne DNS-Änderung (`PATCH /cdn64o/hosts/{id}`), nicht für *TLS durchreichen*.
  - Getestet: Go-Test mit zwei Servern (TLS-Ende, HTTP/2, echte IP, 6 MB Upload über den Nachbarn, WebSocket,
    301, 421, 429, Seite 502, Durchreichen ohne Zertifikat, Ablage verschlüsselt und namensgebunden, Primär/Sekundär),
    Node-Test (Stream `http` als HTTPS, Moduswechsel), PHP-Testumgebung 53/53.
- TLS/HTTP/1–3 auf den Servern, Weiterleitung als HTTP über den Tunnel, `CDN64-Connecting-IP`.
- Zertifikate per DNS-01 Wildcard über ipv64, HTTP-01-Ausweg, verschlüsselte Ablage, Erneuerung.
- Schutz auf den Servern (Blocklisten, Limits, Sperren) mit Meldung an ipv64.
- **Fertig, wenn:** Wildcard-Zertifikat ausgestellt (nach OK), WebSockets und große Uploads gehen, Modus-Wechsel
  1 ↔ 2 ohne DNS-Änderung, Schutz greift auf dem Server.

### T6 – Betrieb und Start (Modus 1/2)
- **Stand 2026-10-18 (cdn64-edge 0.6.0, CDN64 1.9.0):** eingespielt (ipv64, srv07/srv08 ohne die feste
  Testkonfiguration aus T1/T2, node64-test 0.11.98) und live getestet. Offen nur noch: Datenschutz-Hinweis (G12),
  Beta und Freigabe (Dennis).
  - Last (von hub1, pfsense.ipv64.de, Ziel ein einfacher Python-Echo-Dienst hinter der Node, `cmd/cdn64-load`):

    | Test | Ergebnis |
    |---|---|
    | Modus 1, HTTP/2, 40/s, 30 s | 1.200 × 200, p50 26 ms, p99 42 ms |
    | Modus 1, je Anfrage neue TLS-Verbindung (IPv6), 15/s | p50 66 ms, p99 84 ms |
    | Modus 1, Vollgas 600 Anfragen | 179/s, 573 × 200, 27 × 429 (Limit der Node) |
    | Modus 2, HTTP/2, 40/s, 30 s | 1.200 × 200, p50 30 ms, p99 42 ms |
    | Modus 2, HTTP/3, 40/s, 20 s | 800 × 200, p50 30 ms, p99 38 ms |
    | Modus 2, je Anfrage neue TLS-Verbindung (IPv6), 15/s | p50 45 ms, p99 64 ms (TLS endet näher) |
    | Modus 2, Vollgas 700 Anfragen | 280/s, 561 × 200, 139 × 429 (Anfrage-Limit des Servers) |

    Die Grenze setzt der Heimanschluss bzw. der Echo-Dienst; die Server waren nicht ausgelastet.
  - Ausfall: cdn64-edge auf srv07 gestoppt (16:01:39) → nach rund 55 s nicht mehr im DNS; Abrufe über den Namen
    durchgehend 200 (srv08); srv07 wieder gestartet (16:04:10) → Node nach < 5 s wieder verbunden, nach rund 40 s
    wieder im DNS. Keine Meldung in der Node (Tunnel zu srv08 stand durchgehend).
  - Statistik: Server melden Anfragen/Abweisungen, `GET /cdn64o/stats`, Monatszeile je Host und Kontingent in der Node.
  - G6: Lebenszeichen je Konfigurationsabruf (10 s), Austragen nach 45 s (nur wenn der rufende Server selbst ohne
    Pause da war und `/health` des anderen nicht antwortet), Wiedereintrag nach 30 s.
  - G1: Tunnel auch über 443 (TCP nach SNI = `public_host`, UDP mit HTTP/3 in einem QUIC-Listener nach ALPN);
    Node probiert nach 7844 auch 443, der zuletzt erfolgreiche Port zuerst.
  - Zertifikate: HTTP-01-Ausweg (nur der Name, Token auch beim Nachbarn), Aufräumen nach 7 Tagen.
  - Meldungen in der Node (Tunnel weg/wieder da, Sperre).
  - Sicherheitsprüfung (Code-Review) mit Korrekturen: Modus-2-Anfragen nicht als Verbindungen zählen, UDP 443 mit
    Schutz vor dem Handschlag und eigenen Grenzen, G6 robust gegen ipv64-Ausfälle, Wildcard über mehrere Ebenen,
    Modus 2 bei „TLS durchreichen“ zurücksetzen. Offen: feste Testkonfiguration (T1/T2) auf den Servern entfernen.
  - Doku für Kunden: [CDN64-ONLINE-KUNDEN.md](CDN64-ONLINE-KUNDEN.md). Datenschutz-Hinweis (G12) und Freigabe: Dennis.
- Statistik „über CDN64“ in der Node (Traffic, Anfragen, Abweisungen auf den Servern) aus den Zahlen bei ipv64.
- Last- und Ausfalltests, Sicherheitsprüfung (Code-Review), Überwachung, Doku für Kunden, Beta mit wenigen Accounts,
  dann Freigabe.

### T7 – Modus 3 direkt zum Ziel + Webseite
- **Stand 2026-10-18 (cdn64-edge 0.7.0, CDN64 1.10.0):** eingespielt und live getestet (fertig bis auf den
  Menüeintrag im Header, den Dennis später setzt).
  - Live mit `m3test.pfsense.ipv64.de` → hub1 (nur IPv6, Port 18080): Besucher per IPv4 über srv07 mit HTTP/2 erreicht
    das Ziel; privates Ziel (192.168.10.30) auf der Seite abgelehnt; Sperrliste (nur hub2 erlaubt) greift; DynDNS-
    Änderung des Originals war nach ≤ 10 s auf beiden Servern aktiv (Abruf alle 10 s).
  - Nachgezogen: `acme-txt`/`certs` auch für Modus 3 (23161c6); SSH-Bremse der Server je Absender statt global;
    DynDNS-Seite schützt CDN64-Einträge und zeigt „CDN64“ (`deploy/web/T7-DYNDNS-CDN64-VORHER-NACHHER.md`).
  - Server (`direct.go`, `cache.go`): Ziel aus `addrs` (DNS-Einträge, von ipv64 je Abruf aktuell) oder `host` (selbst
    aufgelöst), http/https mit wählbarer Prüfung, IPv6 bevorzugt, Frontend-Stufen 1–3, WebSockets, `X-Forwarded-For`/
    `X-Real-IP`; SSRF-Schutz bei jeder Verbindung (öffentlich, nicht die Server); eigener Verbindungspool je Stand
    des Ziels (eine DynDNS-Änderung greift sofort); Cache nach den Köpfen des Ziels, Grenze je Name und gesamt
    (`cache_total_mb`, Standard 4 GB); Erlauben-/Sperrliste für alle Modi (Modus 1 beim Verbindungsaufbau).
  - ipv64: `cdn64o_targets`, `cdn64o_acl`, `acl_default`; Modus 3 anlegen/ändern, Liste; Ziele nur öffentlich.
  - Node: Modus 3 für Proxy-Hosts mit öffentlichem Ziel.
  - Webseite `cdn64.php`: Kontingent, alle Namen mit Modus/Ziel/Status/Traffic, Modus 3 anlegen und bearbeiten,
    Liste, Ausschalten, Tunnels der Nodes, Werbung für Modus 1/2 mit Docker-Befehl (E6). Ruft die API v2 auf.
  - Getestet: Go (Modus 3, SSRF, Frontend-Stufen, Zertifikatsprüfung, Cache, Listen, Zielwechsel), PHP 86/86,
    Seite 10/10.
- Server: Weiterleitung an das Ziel (http/https, Port, IPv6 bevorzugt), Ziel aus DNS-Eintrag oder fest, SSRF-Schutz,
  WebSockets, Erlauben-/Sperrliste, Cache.
- ipv64: Tabellen `cdn64o_targets`/`cdn64o_acl`, DynDNS-Änderungen an die Server, neue Seite `cdn64.php`,
  API-Endpunkte für Modus 3; Node: Modus 3 im Formular.
- **Fertig, wenn:** ein Host mit Ziel = DynDNS-IPv6 eines Testanschlusses über IPv4 erreichbar ist, eine
  Adressänderung per DynDNS in < 30 s greift, private Ziele abgelehnt werden.

### T8 – Portmapper und Abschaltung des alten CDN
- **Stand 2026-10-18 (cdn64-edge 0.8.0):** Portmapper eingespielt, ausgerollt und live getestet. Hinweise im alten CDN
  (Teil B) erst nach 1–2 Wochen Testbetrieb, danach Frist und Abschaltung (Teil C).
  - Live mit `pm8.pfsense.ipv64.de` (Stufe 0, festes Ziel hub1 nur IPv6): TCP 50393 → 18081 und UDP 51999 → 51999
    über alle vier Server-Adressen von hub2 (v4/v6, 9–18 ms) und vom Heimanschluss (nur IPv4, 40–64 ms); Port 80/443
    zu; Liste „nur hub2“: Box abgewiesen (TCP getrennt, UDP verworfen); Traffic gemeldet; Ausschalten schließt die
    Ports auf beiden Servern und stellt die DNS zurück.
  - Server (`portmap.go`): je Mapping ein TCP- bzw. UDP-Port (`port_range`, Standard 50000–62000, nur dort), auf- und
    abgebaut nach jedem Abruf; Ziel, Sperre und Liste bei jeder Verbindung aus dem aktuellen Stand des Namens,
    SSRF-Schutz wie HTTP, Schutz je IP (Blocklisten, Grenzen) auch für UDP-Sitzungen, Bandbreite und Traffic des
    Accounts. UDP: eine Sitzung je Besucher, 2 Minuten ohne Verkehr = Ende, neue Sitzung bei Zielwechsel (DynDNS);
    UDP nimmt immer IPv6 zuerst (0.8.1, ausgerollt), weil ein toter A-Eintrag (DS-Lite) bei UDP nicht auffällt.
  - Frontend-Stufe 0 = keine Webseite, nur Portmapper (kein Zertifikat, Port 80/443 zu).
  - ipv64: `cdn64o_mappings`, API `.../mappings`, Limit `cdn_mappings` (altes CDN zählt mit), Port-Vergabe wie beim
    alten CDN; Seite `cdn64.php` mit Karte „Port mappings“.
  - Altes CDN: Hinweis und Stopp neuer Domains in `cdn.php`, Abschalt-Skript `bots/cdn_alt_abschalten.php` (setzt
    die DNS je Domain zurück, bevor `cdn_bot` löscht), Umleitung und Abgleich der Funktionen in
    `deploy/web/T8-CDN64-ONLINE-VORHER-NACHHER.md`.
  - Getestet: Go (TCP, UDP mit zwei Besuchern, Liste, SSRF, Zielwechsel, Bereich, Schließen, Stufe 0; Race auf
    Linux), PHP 105/105, Seite 19/19, Abschalt-Skript in der Testumgebung.
- Portmapper (TCP/UDP) auf den Servern mit Limits der Klasse (`cdn_portmapper`, `cdn_mappings`), Traffic zählt mit.
- **Keine Migration:** Dennis kündigt die Abschaltung an; Kunden richten auf `cdn64.php` bzw. in der Node neu ein.
  Hinweis auf `cdn.php`, Frist nach Dennis, danach `cdn.php` auf die neue Seite umleiten und srv01–srv06 abschalten;
  das gemeinsame Kontingent zählt dann nur noch das neue CDN.
- **Fertig, wenn:** jede Funktion des alten CDN ist in Modus 3 vorhanden und dokumentiert, Dennis gibt die
  Abschaltung frei.

## 13. Risiken und offene Punkte

- **Let's-Encrypt-Limits:** 50 Zertifikate je registrierter Domain und Woche. Nur ipv64.net, ipv64.de und home64.de
  stehen auf der Public Suffix List (für die übrigen 15 DynDNS-Domains geht das noch nicht). Gelöst in cdn64-edge
  0.9.0: die Server zählen neue Zertifikate je Domain (`/health`: `acme` ok/warn/error, Einzelheiten lokal unter `ca`),
  ab 40 je Woche oder nach „rateLimited“ geht es zu ZeroSSL (Konto info@ipv64.net, EAB automatisch abgerufen);
  `acme_le_week_limit: -1` = nur ZeroSSL. Konto bei ZeroSSL angelegt und gültig; Ausstellung über ZeroSSL live noch
  nicht getestet (ZeroSSL war beim Test gestört).
- **Traffic-Zählung des alten CDN:** genauen Zeitraum und Rücksetzung in T3 nachlesen, damit das gemeinsame
  Kontingent stimmt.
- **DynDNS und deaktivierte Einträge:** geprüft (T7): `update.php` ändert das deaktivierte Original (Ziel in Modus 3),
  nicht die Server-Einträge; die DynDNS-Seite darf Original und Server-Einträge nicht löschen (siehe T7).
- **Durchsatz:** 2 vCPU je Server; Modus 2 (TLS + HTTP/3) kostet mehr CPU – in T2/T5 messen, ggf. größere Server.
- **Hetzner-Traffic:** inklusiver Traffic der Cloud-Server im Blick behalten (Kontingente der Klassen).
- **HTTP/3 in Modus 1:** gebaut (467b117): die Server lesen den Namen aus dem QUIC-Initial (`internal/quicsni`) und
  reichen Modus-1-QUIC roh durch den Tunnel (Stream `quic`), TLS endet in der Node; Alt-Svc nur, wenn alle
  verbundenen Server die Fähigkeit `quic` melden. Live seit 2026-10-18 (cdn64-edge 0.10.x, node64-test 0.11.100-h3):
  pfsense.ipv64.de über alle vier Server-Adressen per HTTP/3 von hub2 (~90 ms), Zertifikat der Node (TLS endet dort).
- **TCP-/UDP-Streams (Portmapper Modus 1/2):** gebaut 2026-10-21 (PROXY64 1.24.0, cdn64-edge 0.15.0), siehe 8.3.
- **Fremde Domains:** bewusst später.
- **Modus 3 und Missbrauch:** offene Weiterleitung ins Internet ist anfällig (Angriffe über unsere IPs); SSRF-Schutz,
  Limits und Sperre je Account sind Pflicht, Abuse-Kontakt klären.
- **Portmapper:** Port-Bereiche und Kollisionen zwischen Kunden auf zwei Servern planen (T8).
- **Bandbreite über zwei Server:** Der Abgleich zwischen srv07 und srv08 erlaubt kurz höhere Spitzen; Genauigkeit in
  T3 messen. In Modus 1/2 begrenzt ohnehin auch der Upload zu Hause.
- **Werte für `cdn_bandwidth`:** Supporter-Wert legt Dennis fest (Business/Company 0 = frei).

## 14. Grundlagen-Check („Cloudflare in klein“)

Prüfung vor dem Start (2026-10-17): Verbindungsaufbau, Sicherheit, Einfachheit. Funktionen kommen später; hier steht,
was in die **Grundlage** gehört, weil es sich später nur schwer nachrüsten lässt.

### 14.1 Zielgruppe nur IPv6 – funktioniert Modus 1?

Ja. Der Besucher kommt per IPv4 an srv07/srv08 (dort IPv4 und IPv6), der Server reicht die Verbindung roh in den
Tunnel, den die Node **über IPv6** geöffnet hat. Die Node braucht nur ausgehendes IPv6 (oder IPv4 über DS-Lite/CGNAT)
und keinen offenen Port. Der Besucher sieht nur die Server-Adressen; TLS endet trotzdem erst zu Hause.

### 14.2 In die Grundlage aufnehmen

| # | Punkt | Warum | Phase |
|---|---|---|---|
| G1 | **Tunnel auch über Port 443** (UDP mit ALPN `cdn64-tunnel/1` neben HTTP/3, TCP+TLS mit eigener ALPN) zusätzlich zu 7844 | Manche Netze lassen nur 443 raus; QUIC trennt Tunnel und HTTP/3 sauber über ALPN auf demselben Port | T1 |
| G2 | **Server-Liste aus der API** statt fest srv07/srv08, mit IPs als Rückfall und Schlüssel-Pin je Server | Später weitere Server ohne Node-Update; Tunnel geht auch, wenn der DNS der Node klemmt; Schutz gegen falsche Zertifikate | T1/T3 |
| G3 | **Host an mehrere Tunnels** im Datenmodell (`cdn64o_host_tunnels` statt einer `tunnel_id`) | Zwei Nodes für denselben Dienst (Ausfallsicherheit, lokale Gruppe) später ohne Umbau | T3 |
| G4 | **MTU und UDP-Puffer:** QUIC mit Path-MTU-Discovery und kleinem Start (DS-Lite, PPPoE, IPv6-Tunnel); Hinweis in der Node, wenn die UDP-Puffer des Docker-Hosts zu klein sind (`net.core.rmem_max` lässt sich nur auf dem Host setzen) | Sonst hängen Verbindungen oder der Durchsatz bricht ein | T1 |
| G5 | **Sanftes Umschalten:** Server kündigt Neustart an (GOAWAY), Node baut zuerst zum anderen Server auf; Deploy immer ein Server nach dem anderen | Updates ohne Ausfall für Besucher | T1 |
| G6 | **Ausgefallenen Server aus dem DNS nehmen:** ipv64 überwacht beide; ist einer > 60 s weg, entfernt ipv64 seine A/AAAA aus allen CDN64-Hosts und trägt sie danach wieder ein | Browser probieren nicht zuverlässig die zweite Adresse | T3/T6 |
| G7 | **Schutz der Server selbst:** SYN-Cookies, QUIC-Adressprüfung (Retry) unter Last, Zeitlimit für nicht angemeldete Tunnels, Limits je IP vor TLS | Die Server sind ab Tag 1 öffentlich angreifbar | T0/T1 |
| G8 | **Protokoll-Version** im HELLO, Server können Version N und N−1 | Node und Server lassen sich getrennt aktualisieren | T1 |
| G9 | **Anfrage-ID** (`CDN64-Ray`) je Verbindung/Anfrage in den Logs von Server und Node | Support: eine ID zeigt den ganzen Weg | T2 |
| G10 | **Host-Bindung:** Tunnel nur für Hosts desselben Accounts; in Modus 2/3 muss der Host-Kopf zum SNI-Namen passen (kein Domain-Fronting); HTTP über Go `net/http` normalisiert (kein Request-Smuggling) | Mandantentrennung zwischen Kunden | T2/T5 |
| G11 | **Not-Aus und Missbrauch:** Sperre je Host und je Account von ipv64 aus (wirkt in Sekunden), Abuse-Kontakt, Nutzungsbedingungen | In Modus 1 sehen wir keine Inhalte, unsere IPs stehen aber im DNS | T3 (Technik), Dennis (Texte) |
| G12 | **Datenschutz:** Besucher-IPs laufen über unsere Server – Hinweis in Datenschutzerklärung/AV, Logs kurz und ohne Inhalte | Pflicht bei „Cloudflare in klein“ | T6, Dennis |

### 14.3 Einfacher für die Nutzer

| # | Punkt | Phase |
|---|---|---|
| E1 | **Standard Modus 1** (Ende-zu-Ende, kein Zertifikat auf unseren Servern, wenig Fehlerquellen); Modus 2 als „mehr Schutz + HTTP/3“ wählbar | T4 |
| E2 | **Kein API-Key verbunden?** Der Schalter führt direkt durch „Account verbinden“ und kommt danach zurück | T4 |
| E3 | **Klare Fehlertexte** mit Abhilfe: „UDP gesperrt – TCP wird genutzt“, „Domain nicht im Account“, „Kontingent voll“, „Node offline“ | T4 |
| E4 | **Node offline:** Server zeigen in Modus 2/3 eine verständliche Seite (in Modus 1 auf Port 80); auf Wunsch legt die Node beim Einschalten gleich einen **Healthcheck** für den CDN-Host an und meldet Ausfälle | T4/T5 |
| E5 | **Im Heimnetz nicht über das Internet:** DNS64 der Node beantwortet CDN64-Hosts im LAN mit der lokalen Adresse (geteilter DNS), sonst ginge jeder Aufruf aus dem Heimnetz über srv07/srv08 und zurück | T4 |
| E6 | **Webseite ohne Node:** Hinweis mit Docker-Befehl „Node64 installieren“, damit Modus 1/2 erreichbar sind | T7 |

### 14.4 Entschieden (Dennis, 2026-10-17)

- **Keine eigene IPv6 je Host:** Die Adressen der Server bleiben für alle Hosts geteilt (IPv4 ohnehin).
- **Standard-Modus in der Node: Modus 1** (durchreichen); Modus 2 und 3 wählbar.
