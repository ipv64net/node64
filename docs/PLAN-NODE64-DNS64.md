# Plan: Modul DNS64 in Node64

Stand 2026-10-14. Grundlage ist der eigenständige Container im Ordner `dns64/` (Go, `miekg/dns`, ca. 3.700 Zeilen).
Ziel: derselbe Dienst als Modul von Node64, im Aussehen von Node64, einzeln ein- und ausschaltbar. Ist das Modul
aus, laufen keine Prozesse und kein Port ist offen.

## Was der bestehende Container kann

| Bereich | Stand |
|---|---|
| DNS-Server | UDP + TCP auf Port 53, nur private und direkt angeschlossene Netze (kein offener Resolver) |
| Blockieren | 6 Listen (StevenBlack, AdGuard DNS, OISD Small, HaGeZi Multi, EasyPrivacy, URLhaus), alle 24 h aktualisiert; hosts-, Domain- und Adblock-Syntax; Antwort 0.0.0.0 bzw. :: |
| CNAME-Cloaking | Tracker hinter Subdomains der besuchten Seite werden erkannt |
| Upstream | nur DNS-over-HTTPS (Cloudflare, Quad9) parallel, schnellste gültige Antwort gewinnt; feste Bootstrap-IPs |
| Cache | TTL-Cache, 20.000 Einträge, optimistisch (abgelaufene Einträge bis 1 h sofort, Erneuerung im Hintergrund) |
| Lokale Namen | `*.fritz.box`, `*.lan`, `*.home.arpa`, einzelne Hostnamen, Reverse privater IPs gehen nur an den Router (Default-Gateway automatisch) |
| Gerätenamen | Client-IP → Name per PTR beim Router |
| Freigaben | Domains (inkl. Subdomains) per Klick freigeben, Datei `allowlist.txt` |
| Abfrage-Log | SQLite, 7 Tage, gebündelt geschrieben |
| Dashboard | Kennzahlen, Zeitverlauf (eigenes SVG), Upstreams, Cache, Top-Domains/-Clients, Log mit Suche und Seiten, Freigaben, Blocklisten |

**Fehlt** gegenüber dem Ziel: DNS-over-TLS und DNS-over-QUIC (Upstream), verschlüsselte Anfragen der Clients
(DoH/DoT/DoQ als Server), einstellbare Upstreams und Listen, eigene DNS-Einträge, echtes DNS64 (RFC 6147).

## Grundsätze

- **Modul wie DynDNS**: Paket `internal/dns64`, `module.Module` (Info, Migrationen, Routen, Start/Stop). Aus = keine
  Goroutinen, keine Sockets, Seiten antworten 404 (`g.Enabled`).
- **Eigene Datenbank-Datei** `dns64.db` für das Abfrage-Log (sehr viele Schreibvorgänge; `node64.db` bleibt klein,
  Backups bleiben schnell). Einstellungen, Freigaben und eigene Einträge in `node64.db` (Modul-Scope), damit sie in
  Export/Import und Backup sind.
- **Ports in Docker (entschieden: Host-Netzwerk)**: Node64 läuft mit `network_mode: host`, der DNS-Dienst lauscht
  direkt auf 53 (UDP/TCP), DoT/DoQ auf 853; DoH für Clients über den vorhandenen HTTPS-Port der Oberfläche
  (`/dns-query`), kein weiterer Port. Node64 läuft ohne Root: das Binary bekommt im Image die Fähigkeit
  `cap_net_bind_service` (setcap im Build), damit Ports unter 1024 gehen. Router-Erkennung (Default-Gateway) bleibt
  automatisch, Eintrag in den Einstellungen als Ausweichweg. Ports (DNS, DoT/DoQ) sind einstellbar, falls 53 auf dem
  Host belegt ist.
- **Box**: der eigenständige DNS64-Container wird ersetzt (gestoppt, Freigaben aus `allowlist.txt` übernommen).
- **Router für lokale Namen**: Default-Gateway automatisch; in den Einstellungen überschreibbar.
- **Oberfläche** im Stil von Node64 (Bootstrap, Chart.js wie Healthchecks), deutsch/englisch, lokale API unter
  `/api/dns64/…`, in OpenAPI und README dokumentiert.

## Phasen

### P0 Modul-Versionen (alle Module)
Jedes Modul bekommt eine eigene Version und ein Änderungsprotokoll (eingebettete `CHANGELOG.md` je Modul,
SemVer). Anzeige in Einstellungen → Module (Version, Datum der letzten Änderung, Protokoll aufklappbar), in
`/api/modules` und im Dashboard. Regeln in `docs/MODUL-VERSIONEN.md`: neue Funktion = Minor, Fehlerbehebung = Patch,
inkompatible Änderung (Daten, API) = Major. Startwerte: Kern = Node64-Version, Healthchecks 1.x, DynDNS 1.x, DNS64 1.0.

### P1 Übernahme als Modul (Funktionsgleichheit)
- Pakete `internal/dns64/{server,cache,filter,upstream,localnet,querylog}` aus dem Container übernommen, auf
  Node64 umgestellt (Logger, Start/Stop, Datenverzeichnis `/data/dns64/`).
- Seiten: **Übersicht** (Kennzahlen, Zeitverlauf, Upstreams, Cache mit „Cache leeren“, Top blockiert/erlaubt/Clients),
  **Abfrage-Log** (Filter, Suche, Seiten, Live, Freigeben per Klick), **Freigaben & Blocklisten**.
- Dashboard-Kachel, Menüpunkt mit Logo (`dns64.webp`, bisher „demnächst“).
- Lokale API (Kennzahlen, Zeitverlauf, Tops, Log, Listen, Upstreams, Cache, Freigaben).
- Docker: Ports im Image/Compose, README-Abschnitt.

### P2 Einstellungen
Upstreams wählbar (Vorlagen Cloudflare, Quad9, Google, AdGuard, Mullvad, eigene) und Modus (parallel/schnellster,
der Reihe nach); Blocklisten an/aus, eigene Listen-URLs, Aktualisierungsintervall; erlaubte Client-Netze;
Antwort bei Blockierung (0.0.0.0/:: oder NXDOMAIN); Cache-Größe; Log-Aufbewahrung und Anonymisierung der
Client-IPs; **eigene DNS-Einträge** (A/AAAA/CNAME, Wildcards); Router für lokale Namen.

### P3 Verschlüsselt ins Internet (Upstream)
Zusätzlich zu DoH: **DNS-over-TLS** (Port 853) und **DNS-over-QUIC** (RFC 9250, `quic-go`), je Server wählbar,
Bootstrap-IPs, Zertifikatsprüfung, Wiederverwendung der Verbindungen, Statistik je Server und Protokoll.

### P4 Verschlüsselt im Heimnetz (Clients)
Node64 beantwortet selbst verschlüsselte Anfragen: **DoH** (`https://<node>/dns-query`, RFC 8484, GET/POST),
**DoT** (853/TCP) und **DoQ** (853/UDP) mit dem TLS-Zertifikat von Node64 (selbstsigniert oder eigenes). Anzeige
der Verbindungsdaten für Geräte (Android „Privates DNS“, iOS-Profil, Browser).

### P5 entfällt
Echtes DNS64 (RFC 6147) ist nicht gewünscht; „DNS64“ bleibt der Name des Moduls.

### P6 Abschluss
Benachrichtigungen (Upstream ausgefallen, Listen-Aktualisierung fehlgeschlagen) über die vorhandenen Kanäle,
Übernahme aus dem eigenständigen Container (Freigaben, optional Log), Tests (Pipeline, Cache, Filter,
Verschlüsselung), Last- und Langzeittest auf der Box.

## Stand

- P0 und P1 fertig (Commits 32cfb94, 032aca2, 71d9c3d, 79d912b), Box 0.11.67-dev.
- P2 fertig (cce58b4, Modul 1.1.0), Box 0.11.68-dev. P3 fertig (a3ad584, Modul 1.2.0, Box 0.11.69-dev): DoT und DoQ zu
  den Upstreams.
- P4 fertig (Modul 1.3.0): DoH (eigener Port statt Web-Port, damit 443 ohne Port in der URL geht und der Web-Kern
  unberuehrt bleibt), DoT, DoQ fuer Geraete; eigene Heimnetz-CA mit Name Constraints; iOS-/macOS-Profil.
- P6 fertig (2294531, Modul 1.4.0): Benachrichtigungen (Upstream gestoert/wieder da, Blockliste nicht ladbar),
  Freigaben uebernehmen per Liste; Lasttest lokal ca. 38.000 Anfragen/s ohne Verluste (p99 < 6 ms, ~106 MB RAM);
  Box im Dauerbetrieb seit 2026-10-14 15:31 (Heimnetz, ~22 Geraete, 47 MB RAM, 0,1 % CPU).
- Idee fuer spaeter: oeffentlich gueltiges Zertifikat per ACME (Let's Encrypt, DNS-01 ueber die ipv64-API mit dem
  zentralen API-Key) fuer eine ipv64-Domain, damit auch Android „Privates DNS“ ohne Weiteres geht.
- Box seit 2026-10-14 15:31: node64 im Host-Netzwerk mit DNS64 auf Port 53, alter Container `dns64` gestoppt
  (restart=no, Rollback: `/opt/ipv64-agent/dns64_switch.sh rollback`). Freigaben, Blocklisten und Abfrage-Log
  übernommen.

## Entscheidungen (2026-10-14)

1. Ports/Docker: Host-Netzwerk.
2. Eigenständiger DNS64-Container auf der Box: wird ersetzt, Freigaben werden übernommen.
3. Echtes DNS64: nein, nur der Name (P5 entfällt).
