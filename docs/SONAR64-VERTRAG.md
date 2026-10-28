# Sonar64 – Schnittstellen-Vertrag (verbindlich für die parallelen Teile)

Stand 2026-10-28. Plan: [PLAN-NODE64-SONAR64.md](PLAN-NODE64-SONAR64.md). Go-Typen: `internal/sonar/wire.go`,
`api.go`, `probe.go`, `keys.go` (Gerüst, kompiliert). Wer etwas am Vertrag ändern muss, ändert ihn hier **und** in
allen betroffenen Teilen, sonst nicht.

## 0. Regeln für alle Teile

- Nur eigene Dateien (Tabelle 1) anlegen/ändern; neue Dateien `git add <pfad>`, Commit nur mit
  `git commit -- <pfade>` (nie `-a`/`-A`); bei `index.lock` kurz warten und erneut versuchen. Nicht pushen, nicht
  ausrollen, nichts auf hubs/Edges/ipv64.net. `deploy/upload/` und `node64-src.tar` nie anfassen.
- Keine Geheimnisse in Dateien oder Ausgaben. `ipv64net_webseite/dbconnect.php` nie komplett öffnen.
- Sicherheit vor Bequemlichkeit: Eingaben streng prüfen (PHP: Prepared Statements, Längen, Muster), Ausgaben
  escapen, keine privaten/reservierten Ziele, Antworten nie größer als Anfragen (UDP), harte Grenzen im Kern.
- Leichtgewicht: Kern und `cmd/sonar64` nur Standardbibliothek + `golang.org/x/net` (schon im go.mod), keine neuen
  Abhängigkeiten. Kein Speicher auf Platte außer ein paar KB im DataDir.
- Go: `gofmt`, deutsche Kommentare ohne Umlaute, Tests unter Linux auf der Box
  (`ssh agentbox`, Quellbaum per `git archive`/tar nach `/tmp/s64-<teil>-<zufall>` kopieren,
  `docker run --rm -v <dir>:/src -w /src golang:1.27 go test ./internal/sonar/...`), danach aufräumen.
- PHP: `php -l` in `c64o-php` auf der Box; Funktionstests gegen die Test-Datenbank `c64o-db` (eigene Tabellen
  `sonar_*` anlegen ist erlaubt, fremde Tabellen nicht ändern). Vorbild für Testharness:
  `deploy/web/honeypot/tests/`. PHP 8.x, Stil wie `deploy/web/api_v2_honeypot.php` (Präfix `s64_` für Funktionen).
- Texte in der Node64-Oberfläche zweisprachig (i18n), öffentliche Seiten DE/EN wie `deploy/web/honeypot/`.

## 1. Teile und Dateien

| Teil | Dateien (Besitz) |
|---|---|
| **K Kern** | `internal/sonar/api.go`, `runner*.go`, `plan*.go`, `client*.go`, `limits*.go`, `state*.go`, `keys.go` + Tests (`*_test.go` dazu) |
| **M Messung** | `internal/sonar/probe.go`, `icmp*.go`, `udp*.go`, `trace*.go`, `responder*.go` + Tests |
| **P Programm** | `cmd/sonar64/**`, `Dockerfile.sonar64`, `deploy/sonar64/install.sh`, `deploy/sonar64/sonar64.service`, `.github/workflows/sonar64.yml`, `docs/SONAR64.md` |
| **N Node64-Modul** | `internal/sonar64/**` (Modul, Templates, CHANGELOG), eine Verdrahtung in `cmd/node64/main.go`, i18n-Block `sonar64` + `nav.sonar64` in `internal/i18n/locales/{de,en}.json`, Pfade `/api/sonar64/*` in `internal/web/static/openapi.json`, README-Abschnitt Sonar64, je ein Stichpunkt in `CHANGELOG.md`/`CHANGELOG.en.md` (Repo-Wurzel, „Unveröffentlicht“) |
| **A API ipv64** | `deploy/web/api_v2_sonar.php`, `deploy/web/sonar/s64_lib.php`, `deploy/sql/sonar64.sql`, eine Zeile am Ende von `deploy/web/api_v2_honeypot.php` (`if(is_file(__DIR__ . '/api_v2_sonar.php')) { require __DIR__ . '/api_v2_sonar.php'; }`), `deploy/web/bots/sonar_keygen.php`, `deploy/web/bots/sonar_anchor_token.php`, Tests `deploy/web/sonar/tests/api/**` |
| **J Jobs ipv64** | `deploy/web/bots/sonar_plan.php`, `sonar_rollup.php`, `sonar_trust.php`, `sonar_outages.php`, `sonar_cleanup.php`, Einträge in `HPC_JOBS` (`deploy/web/bots/honeypot_cron.php`), Tests `deploy/web/sonar/tests/jobs/**` |
| **W Webseiten** | `deploy/web/sonar/index.php` (Karte), `nodes.php`, `node.php`, `top.php`, `me.php`, `s64_web.php` (gemeinsame Seitenteile), `sonar.js`, `sonar.css`, `de_map.json`, Tests `deploy/web/sonar/tests/web/**` |

Teil A stellt in `s64_lib.php` die gemeinsamen Funktionen (Abschnitt 6); J und W benutzen nur diese plus eigene.

## 2. Anmeldung und Schlüssel

- **Sonar-Token:** `s64_` + 40 Zeichen `[A-Za-z0-9]` (Knoten), `s64a_` + 40 (Anker). In der DB nur
  `SHA-256` hex. Knoten-Token per `POST /sonar/tokens` (API-Key des Accounts), höchstens 10 je Account;
  Anker-Token nur per CLI `php bots/sonar_anchor_token.php --name=<anker>` (Dennis).
- **Header:** `Authorization: Bearer <token>`. Die Routen `/sonar/register|me|plan|results|inbound` sind in
  `route(..., true)` (öffentlich) eingetragen und prüfen das Token selbst; `/sonar/tokens` nutzt die normale
  API-Key-Anmeldung. Ein Token gehört zu genau einem Knoten (nach `register`).
- **Knoten-Schlüssel:** Ed25519, erzeugt im Kern beim ersten Start, im DataDir `sonar64.key` (0600). Public Key
  wird bei `register` gespeichert (einmalig je Token; neues Register mit anderem Key nur nach Token-Wechsel).
- **Plan-Schlüssel:** Ed25519 bei ipv64, Datei `dirname(<webroot>)/private/sonar64/plan_ed25519.key` (außerhalb
  des Webroots), erzeugt von `bots/sonar_keygen.php` (gibt nur den Public Key aus). Plan-Signatur mit
  `sodium_crypto_sign_detached` über die exakten Bytes von `plan`. Go pinnt die Public Keys in `keys.go`
  (`PlanKeys`); solange leer, nimmt der Kern `SONAR64_PLAN_KEY` (Warnung im Log). `GET /sonar/public/keys` liefert
  die aktuellen Public Keys.
- **Meldungs-Signatur:** Knoten signiert die exakten Bytes von `report` (Ed25519), ipv64 prüft mit dem gespeicherten
  Key. `seq` muss größer als die letzte angenommene sein (Wiederholschutz).
- Die IP eines Knotens nimmt ipv64 nur aus der Verbindung (`REMOTE_ADDR`), nie aus Angaben des Knotens. ipv64 läuft
  hinter einem internen Reverse Proxy: ist `REMOTE_ADDR` nicht öffentlich, zählt nur die vom Proxy angehängte letzte
  `X-Forwarded-For`-Adresse (`client_ip()` der API v2). Wechselt die IP einer Familie, wird `reach4/6` auf `none`
  gesetzt (die alte Adresse darf in keinen Plan mehr).

## 3. API v2 (`/api/v2/sonar/...`)

Antworten wie API v2 üblich `{ "data": … }`, Fehler RFC 9457. Zeiten ISO 8601 UTC. Größen: Body ≤ 256 KiB.

| Methode | Pfad | Anmeldung | Body / Antwort |
|---|---|---|---|
| POST | `/sonar/tokens` | API-Key | `{name}` → `{id, token}` (Token nur hier im Klartext) |
| GET | `/sonar/tokens` | API-Key | Liste `{id, name, node_id, created_at, last_used_at}` |
| DELETE | `/sonar/tokens/{id}` | API-Key | Token und Knoten deaktivieren |
| POST | `/sonar/register` | Sonar-Token | `Register` → `Me` (legt Knoten an, `node_id` = `n` + 11 `[a-z0-9]`, Anker `a_<name>`); 201 neu, 200 Wiederholung mit gleichem Key, 409 `already_registered` mit anderem |
| GET | `/sonar/me` | Sonar-Token | `Me` |
| PUT | `/sonar/me` | Sonar-Token | `Me` (nur schreibbare Felder; fehlend oder leerer Text = unverändert) → `Me` |
| GET | `/sonar/plan` | Sonar-Token | `SignedPlan`; `ETag`/`If-None-Match` → 304; 204 = kein Plan (pausieren erlaubt) |
| POST | `/sonar/results` | Sonar-Token | `SignedReport` (genau die Schlüssel `report`, `sig`; gzip erlaubt) → 200 `{accepted, rejected, reasons:{…}}`; höchstens 1 Meldung je 60 s (429 + `Retry-After`), `seq` ≤ letzter → 409 `replay`, Nachreichen erlaubt (Puffer 6 h) |
| GET | `/sonar/inbound?since=` | Sonar-Token | Liste `InboundRow` (höchstens 500, `since` ≤ 24 h zurück) |
| GET | `/sonar/public/keys` | – | `{keys:[{kid, pubkey}]}` |
| GET | `/sonar/public/map` | – | Abschnitt 5 |
| GET | `/sonar/public/nodes?trust=&asn=&q=` | – | Liste öffentlicher Knoten `{id, slug, name, role, trust, lat, lon, asn, asname, asn6, access, device, place, measured, reach4, reach6, ipv4, ipv6, since, last_seen, online, uptime30}` (lat/lon verschleiert, `ipv4/ipv6` nur bool) |
| GET | `/sonar/public/node/{slug}` | – | Knoten wie in `nodes` + `anchor_ms:{a_…: ms}` + `history:{a_…: [{hour, fam, ms, loss, n}]}` (7 Tage je Stunde, `ms` = p50) |
| GET | `/sonar/public/stats` | – | `{nodes_active, nodes_total, anchors, measurements_today, providers, regions, by_trust:{…}}` |
| GET | `/sonar/public/top` | – | `{reliable:[…], longest:[…]` (je `{slug, name, trust, asname, uptime30, since}`, höchstens 20), `providers:[{asn, asname, nodes, online, best}]}` |
| GET | `/sonar/public/matrix` | – | `{asns:[{asn,name}], cells:[{a,b,avg,n}]}` (Provider × Provider, Median der letzten 24 h) |
| GET | `/sonar/public/outages?active=1` | – | Liste `{id, kind:"asn"|"region", key, label, started, ended, affected, total}` |

Öffentliche Antworten: `Cache-Control: public, max-age=60`; nie IPs, nie genaue Koordinaten, nie Account-Daten.

Plausibilität beim Annehmen (Teil A, je Ergebnis; verworfen + Grund gezählt):
`not_in_plan` (Ziel/Runde nicht im zuletzt ausgelieferten Plan ± eine Runde), `too_many` (mehr als im Plan),
`bad_time` (At außerhalb Runde−1 min … Runde+6 min), `bad_values` (recv>sent, min>avg>max, negative),
`below_light` (Antwortzeit < 2 × Entfernung / 200 km/ms anhand der genauen Koordinaten, Toleranz 0,3 ms),
`too_smooth` (≥ 5 Pakete, Jitter 0 und min = max über die letzten 12 Meldungen zum selben Ziel). Statistische
Prüfungen (Median, Hin/Zurück, Anker-Wahrheit, Stichproben) macht Teil J.
Umsetzung: „± eine Runde“ nur, wenn das Ziel in der gemeldeten Runde nicht im Plan steht; geprüft gegen die zwei
zuletzt ausgelieferten Pläne; Anker sind per icmp/udp immer erlaubt (je Runde einmal). Weitere Gründe ohne
`plaus_bad`: `not_measured` (sent = 0), `duplicate` (schon gespeichert). Mit `valid=0` gespeichert werden `bad_time`,
`below_light`, `too_smooth`. Sofortige Abstufung um eine Stufe (pillar→trusted→stable→new, Eintrag in
`sonar_trust_log`, Grund `plaus_report`), wenn in einer Meldung ≥ 3 und mehr als die Hälfte der geprüften Werte
`bad_values`/`below_light`/`too_smooth` sind; Quarantäne setzt nur Teil J.

## 4. UDP 6464

- Anfrage 64 Byte: `"S64?"` (4) | Version 1 (1) | Typ 1=Echo (1) | Nonce (8) | Sender-Kurz-ID (4, erste 4 Byte von
  SHA-256(NodeID)) | Füllung 0 (46).
- Antwort 64 Byte: `"S64!"` | Version | Typ | gleiche Nonce | Antwortender-Kurz-ID (4) | Füllung 0.
- Antwort nur auf exakt dieses Format und exakt 64 Byte; nie größer als die Anfrage. Grenzen im Antworter: je
  Quell-IP höchstens 5 Pakete/s, gesamt höchstens 50 Pakete/s, Rest still verwerfen. Keine Antwort an private/
  reservierte Quellen, außer Loopback in Tests.

## 5. Öffentliche Karte (`/sonar/public/map`)

```json
{ "generated": "…Z",
  "nodes": [ {"id":"n…","slug":"…","name":"…","lat":50.12,"lon":8.68,"trust":"stable","role":"node",
              "asn":3320,"asname":"Deutsche Telekom","access":"fiber","device":"pi","online":true,
              "anchor_ms":{"a_fsn":12.3,"a_nbg":9.8}} ],
  "links": [ {"a":"n…","b":"n…","fam":4,"ms":14.2,"loss":0,"n":24} ],
  "outages": [ … wie /sonar/public/outages … ] }
```

`lat/lon` sind die verschleierten Werte (fester Versatz ≤ 1 km je Knoten, `s64_pub_coords()`), `links` die Mediane
der letzten 60 min (höchstens 2.000, die mit den meisten Messungen). Nur Knoten mit Vertrauen ≠ `quarantine` und
online in den letzten 30 min; Anker immer.

## 6. Datenbank (`deploy/sql/sonar64.sql`, Teil A legt an, alle nutzen)

Alle Zeiten `DATETIME(3)` UTC, `utf8mb4`.

- `sonar_tokens` (id PK, userid, kind ENUM('node','anchor'), name, token_hash CHAR(64) UNIQUE, node_id NULL,
  created_at, last_used_at NULL, revoked_at NULL)
- `sonar_nodes` (id PK, node_id VARCHAR(16) UNIQUE, userid, token_id, role ENUM('node','anchor'), pubkey,
  name VARCHAR(32) UNIQUE, slug VARCHAR(40) UNIQUE, lat DOUBLE NULL, lon DOUBLE NULL, pub_lat DOUBLE NULL,
  pub_lon DOUBLE NULL, jitter_seed INT, access VARCHAR(12), device VARCHAR(16), measured TINYINT, budget VARCHAR(12),
  mode VARCHAR(10), version VARCHAR(32), ip4 VARCHAR(45) NULL, ip6 VARCHAR(45) NULL, asn4 INT NULL,
  asname4 VARCHAR(100) NULL, asn6 INT NULL, asname6 VARCHAR(100) NULL, asn_at DATETIME(3) NULL (ASN-Cache),
  place VARCHAR(80) NULL,
  reach4 ENUM('none','icmp','udp') DEFAULT 'none', reach6 …, trust ENUM('new','stable','trusted','pillar','anchor',
  'quarantine') DEFAULT 'new', score DOUBLE DEFAULT 0, uptime30 DOUBLE DEFAULT 0, plaus_ok INT, plaus_bad INT,
  last_seq BIGINT DEFAULT 0, first_seen, last_seen NULL, last_report NULL, last_plan NULL, health JSON NULL,
  active TINYINT DEFAULT 1)
- `sonar_plans` (node_id PK, issued, expires, body MEDIUMTEXT (Plan-JSON ohne Signatur), etag CHAR(16),
  controls TEXT (Ziel-IDs der Kontrollziele, nie ausgeliefert als solche), sent_etag, sent_body, prev_body, sent_at
  (setzt nur `GET /sonar/plan`: zuletzt/davor ausgelieferter Plan); Teil J schreibt per `INSERT … ON DUPLICATE KEY
  UPDATE` nur seine Spalten, nie `REPLACE`)
- `sonar_results` (id PK, round DATETIME, src VARCHAR(16), dst VARCHAR(16), fam TINYINT, method VARCHAR(6),
  sent TINYINT, recv TINYINT, min_ms FLOAT, avg_ms FLOAT, max_ms FLOAT, jitter_ms FLOAT, at DATETIME(3),
  valid TINYINT, reason VARCHAR(16) NULL, UNIQUE(src, round, dst, fam, method), INDEX(dst, at), INDEX(src, at),
  INDEX(at)) – 7 Tage; Spalten `round`, `count`, `old`, `new` in SQL mit Backticks
- `sonar_traces` (id PK, round, src, dst, fam, at, hops JSON, UNIQUE(src, round, dst, fam)) – 7 Tage
- `sonar_inbound` (id PK, node_id, from_short CHAR(8), fam, at, count) – 24 h (Live über UDP)
- `sonar_pair_1h` (src, dst, fam, hour, n, avg_ms, p50_ms, loss, PRIMARY(src,dst,fam,hour)) – 90 Tage
- `sonar_asn_1d` (day, asn_a, asn_b, fam, n, p50_ms, loss, PRIMARY(day,asn_a,asn_b,fam)) – dauerhaft
- `sonar_outages` (id PK, kind ENUM('asn','region'), keyval VARCHAR(32), label VARCHAR(120), started, ended NULL,
  affected INT, total INT)
- `sonar_trust_log` (id PK, node_id, at, old, new, reason VARCHAR(64))

Gemeinsame Funktionen in `deploy/web/sonar/s64_lib.php` (Teil A): `s64_pdo()` (PDO wie die anderen Bots),
`s64_pub_coords(float $lat, float $lon, int $seed): array` (fester Versatz ≤ 1 km), `s64_distance_km(...)`,
`s64_light_min_ms(float $km): float` (= 2·km/200), `s64_asn_lookup(string $ip): array` (ASN + Name über
Team-Cymru-DNS `origin(6).asn.cymru.com` / `asn.cymru.com`, Cache 24 h in der Knotenzeile, Fehler = null),
`s64_is_public_ip(string $ip): bool`, `s64_plan_sign(string $planJson): array` (`kid`, `sig`), `s64_trust_label()`.
`s64_pub_coords` liefert `[0 => lat, 1 => lon, 'lat' => …, 'lon' => …]`, `s64_asn_lookup` immer
`{asn, name, prefix, cc}` (Fehler: `asn` = null). Dazu: `s64_dt()`/`s64_ts()`/`s64_iso()` (UTC, DATETIME(3)),
`s64_median()`, `s64_short_id()`, `s64_plan_keys()`, `s64_trust_color()`, `s64_trust_weight()`, `s64_cache()`.

## 7. Planer und Vertrauen (Teil J)

- **Planer** (`sonar_plan.php`, alle 5 min): je aktivem Knoten (online ≤ 15 min) einen Plan mit 6 Runden (30 min),
  je Runde ≤ Budget-Ziele (sparsam 8, normal 15, großzügig 20; Anker immer zusätzlich zu allen Knoten mit
  `measured=1`, Anker-Budget 2.000 Ziele/Runde). Paarauswahl: beide Anker; 3 geografische Nachbarn; gleicher und
  fremder ASN; rotierende Stichprobe (deterministisch über Knotenpaar + Stunde). Je Ziel und Runde höchstens 10
  Messende. Ziel nur mit `measured=1`, erreichbarem Weg (`reach4/6`) und Vertrauen ≠ quarantine. Methode: `udp`,
  wenn erreichbar, sonst `icmp`. Kontrollziele: in ~5 % der Pläne ein Anker zusätzlich, Werte gegen die Messung
  des Ankers prüfen. Traceroute: je Knoten höchstens 2 Ziele je Stunde (Anker oder Nachbar).
- **Erreichbarkeit:** aus den Anker-Messungen der letzten Stunde (`reach4/6`).
- **Verdichtung** (`sonar_rollup.php`, stündlich): `sonar_pair_1h`, `sonar_asn_1d`; Median über gültige Ergebnisse,
  gewichtet nach Vertrauen (new 0,2 · stable 1 · trusted 2 · pillar 3 · anchor 3).
- **Vertrauen** (`sonar_trust.php`, täglich + sofortige Abstufung aus Teil A über `plaus_bad`): Stufen laut Plan
  Abschnitt 6; Abweichung vom gewichteten Median > max(5 ms, 50 %) in > 20 % der Messungen → Abstufung; Anker-Wahrheit
  (Knoten→Anker vs. Anker→Knoten > max(5 ms, 50 %)) → plaus_bad; Quarantäne bei > 30 % unplausibel über 24 h.
- **Störungen** (`sonar_outages.php`, alle 5 min): je ASN und je Region (Raster 0,5° bzw. Bundesland über
  Koordinaten) mit ≥ 5 Knoten: ≥ 50 % in 10 min nicht erreichbar (für die Anker) oder Median-Latenz > 3× Wochenmittel
  → Störung offen; Ende, wenn < 20 % betroffen.
- **Aufräumen** (`sonar_cleanup.php`, täglich): Aufbewahrung laut Abschnitt 6.

## 8. Go-Schnittstelle (Teil K/M liefern, P/N nutzen)

Siehe `api.go` und `probe.go`. Zusätzlich gilt:

- **Harte Grenzen im Kern** (Konstanten, nicht vom Server änderbar): Ziele je Runde sparsam 8 / normal 15 /
  großzügig 20 (Anker 2.000); höchstens 2 Pakete/s (Anker 50/s); Count ≤ 5; Traceroute ≤ 2/h, MaxTTL ≤ 30;
  Tagesgrenze sparsam 20.000 / normal 40.000 / großzügig 60.000 Pakete; private/reservierte Ziele nie.
- **Ablauf:** Plan alle 15 min (ETag); Plan gilt höchstens 30 min; danach nur `Plan.Anchors` (zuletzt gültiger
  Plan) bis 2 h, dann Pause; Meldung alle 5 min, Puffer 6 h (älteres verwerfen), höchstens 1.000 Ergebnisse je
  Meldung (Rest nach ≥ 61 s), `seq` = max(letzte + 1, Unix-Millisekunden); Selbstbremse: in einer Runde zu
  allen Ankern ≥ 80 % Verlust → nächste Runde Pause (`paused=uplink`).
- **Zustand im DataDir:** `sonar64.key`, `sonar64.json` (node_id, seq, letzter Plan + ETag). Ohne DataDir nur im
  Speicher.
- **Kurz-ID:** erste 4 Byte von SHA-256(NodeID), hex klein.
- **Mini-Status (Teil P):** `SONAR64_STATUS=:8064` → `GET /status` (JSON `Status` + `Recent(50)`), `GET /` schlichte
  HTML-Seite, `GET /health`. Ohne Variable kein Port.
- **Umgebung (Teil P):** `SONAR64_TOKEN` (Pflicht), `SONAR64_MODE` (`headless`|`anchor`, Standard headless),
  `SONAR64_MEASURED` (0/1, Standard 0), `SONAR64_BUDGET` (Standard sparsam), `SONAR64_QUIET` (`23-6`),
  `SONAR64_DATA` (Standard `/data`), `SONAR64_STATUS`, `SONAR64_API` (nur Tests), `SONAR64_PLAN_KEY` (nur solange
  `PlanKeys` leer), `SONAR64_LOG_LEVEL`.

## 9. Node64-Modul (Teil N)

- Name `sonar64`, Version `0.1.0`, Standard **aus**; aus = kein Menüpunkt, kein Port, kein Verkehr.
- Einschalten: braucht die ipv64-Verknüpfung (zentraler API-Key); legt per `sonar.CreateToken` ein Token an
  (verschlüsselt in den Einstellungen wie andere Geheimnisse), startet `sonar.Runner` (Mode `module`).
- Seite `/sonar64`: Teilnahme, Rolle (nur ausgehend / auch gemessen), Budget, Ruhezeit, Name, Standort (Punkt auf
  einer kleinen Karte oder Eingabe Breite/Länge), Anschlussart, Gerät; Vertrauensstufe mit Fortschritt; Tabellen
  **Pings von mir** (`Recent`, live alle 5 s) und **Pings gegen mich** (UDP live aus `Recent`, sonst `Inbound`);
  Link auf die öffentliche Knotenseite. API `/api/sonar64/status|recent|inbound|settings`.
- Ports: UDP 6464 nur bei „auch gemessen“, über die Port-Verwaltung (`ports.Claim`) angemeldet.
