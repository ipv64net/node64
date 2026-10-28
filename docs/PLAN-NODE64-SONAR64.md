# Plan: Sonar64 – verteiltes Community-Messnetz (RIPE-Atlas-Idee)

Stand 2026-10-28 (4. Fassung), Wunsch und Entscheidungen Dennis. **Nur Planung**, noch nichts umgesetzt.

Knoten bei den Leuten zu Hause messen sich gegenseitig (Ping, später Traceroute), geordnet und sparsam nach einem
zentralen Plan von ipv64.net. Ziel ist eine **lebendige Karte**: farbige Badges mit Millisekunden, Verbindungslinien,
sichtbare Teilnehmer und Vertrauensstufen – ein Community-Projekt, bei dem man sieht, dass das eigene Gerät mitarbeitet
und was die anderen tun. **Kein Guthaben, keine Messungen auf Abruf, keine Fremdziele** – nur das automatische Netz.

## Vorgeschichte

Im alten Portal gab es „Node64.io – Distributed Internet Measurement“ (`ipv64net_webseite/nodes.php`, `dims/`,
eigene DB `$node64pdo`, Stand 2023, aufgegeben): zufällige Ziele ohne Plan und Grenzen, nur Koordinaten, keine Karte,
kaum geprüfte Ergebnisse, manipulierbare Belohnungen, IP aus fälschbarem Header. Sonar64 wird neu gebaut; vom alten
Code wird nichts übernommen.

## Entscheidungen

| Thema | Entscheidung |
|---|---|
| Ansatz | **Community**: Karte, öffentliche Knoten, öffentliche Vertrauensstufen, sichtbarer Mehrwert für jeden Teilnehmer |
| Bauweise | **eigenständig und leichtgewichtig**: ein Programm `sonar64`, das allein läuft (bis hinunter zum **Raspberry Pi Zero**, auch MikroTik-Container) |
| Node64 | Sonar64 ist ein **optionales Modul** im Node64-Repo, aus und unsichtbar, bis man es einschaltet |
| Ohne Dashboard | dasselbe Programm läuft auch **allein ohne Oberfläche** („headless“): nur API-Code angeben, es meldet sich als Knoten mit eigener Node-ID an und misst. Als kleiner Einzelcontainer oder als einzelne Datei (Pi Zero) |
| Anker | **dasselbe Programm im Anker-Modus**, völlig losgelöst von den hubs; neuer Anker an beliebigem Standort = Container starten. Start mit `hc-srv01` (Falkenstein) und `hc-srv02` (Nürnberg), nicht auf den CDN64-Servern |
| Schnittstelle | nur die ipv64-API (v2) |
| Teilnahme | Opt-in; wer nicht gemessen werden will, misst **nur ausgehend** und erscheint nie als Ziel |
| Standort | Breiten-/Längengrad, öffentlich **im Umkreis von 1 km verschleiert** (Testwert): fester zufälliger Versatz je Knoten |
| Sonar-Port | **UDP 6464** (Echo-Antwort des Knotens, optional freigeben) |
| Vertrauen | Stufen wie die Flags im Tor-Netz, **öffentlich sichtbar** |
| Nicht dabei | Guthaben, Messungen auf Abruf (Globalping-Art), beliebige Ziele |

## 1. Bausteine

```
Node64-Repo (github.com/ipv64net/node64)
  internal/sonar      Kern: Plan holen, messen (ICMP, UDP 6464), Grenzen, Ergebnisse senden, Antworter auf 6464
  internal/sonar64    optionales Node64-Modul: bindet den Kern ein, Oberfläche (Menüpunkt, Live-Tabellen)
  cmd/sonar64         eigenständiges Programm ohne Dashboard (Knoten- oder Anker-Modus): nur der Kern + Mini-Status
ipv64.net             API v2 /sonar/*, Planer, Auswertung, öffentliche Seiten
```

- **Ein Kern, drei Einsätze:** als Modul in Node64, allein ohne Dashboard (Pi Zero, MikroTik, beliebiger
  Linux-Rechner), als Anker. Der Kern hängt von keinem anderen Node64-Modul ab; `cmd/sonar64` baut nur ihn ein,
  deshalb bleibt die Datei klein.
- **In Node64 optional:** Standard aus, ohne Einschalten kein Menüpunkt, kein Port, kein Verkehr.
- **Ohne Dashboard:** `sonar64` startet mit einem API-Code (Sonar-Token), legt beim ersten Start seine **Node-ID**
  und seinen Schlüssel an (ein paar KB in einem Datenordner) und läuft danach als dieser Knoten weiter, auch nach
  Neustarts und Updates.
- **Leichtgewichtig:** statisches Go-Binary ohne Fremdabhängigkeiten, Ziel < 10 MB und < 20 MB RAM, kein Speicher
  auf Platte nötig (nur Schlüssel und Zustand, ein paar KB), kaum CPU (wenige Pakete pro Sekunde).
- **Raspberry Pi Zero:** der erste Pi Zero (W) ist ARMv6 mit 512 MB – Docker ist dort zu schwer. Deshalb gibt es
  `sonar64` **auch als einzelne Datei** mit systemd-Dienst und Installationsskript (ein Befehl), nicht nur als
  Container. Plattformen: `linux/arm/v6` (Pi Zero/1), `arm/v7` (Pi 2/3, MikroTik), `arm64` (Pi Zero 2, Pi 4/5),
  `amd64`. Container-Image `ghcr.io/ipv64net/sonar64` für alle außer `arm/v6`.
- **ICMP ohne root:** über `cap_net_raw` am Binary bzw. Linux-„ping sockets“ (`net.ipv4.ping_group_range`), wie bei
  Node64.
- **Eigenständig ohne Oberfläche:** Einstellung über Umgebungsvariablen (`SONAR64_TOKEN`, `SONAR64_ROLE=node|anchor`,
  `SONAR64_MEASURED=1`, `SONAR64_BUDGET=sparsam|normal|grosszuegig`); Standort und Anschlussart setzt man auf
  ipv64.net. Ein Mini-Status auf Wunsch (`SONAR64_STATUS=:8064`, JSON und eine schlichte Seite: letzte Pings raus und
  rein). Die volle Ansicht hat jeder Teilnehmer auf ipv64.net unter „Mein Knoten“.
- **Anmeldung:** eigenes **Sonar-Token** mit nur diesem Zweck (im Portal oder per API erzeugt), nicht der volle
  API-Key – wichtig für Router wie MikroTik. Node64 legt sich das Token beim Opt-in selbst über den API-Key an.
- **Anker-Modus:** Antworter auf ICMP und UDP 6464 immer an, fester Standort, misst alle Knoten in einem eigenen,
  größeren Budget, prüft deren Erreichbarkeit. Ein Anker-Token stellt nur ipv64 aus. Neuer Anker:
  `docker run -d --network host -e SONAR64_ROLE=anchor -e SONAR64_TOKEN=… ghcr.io/ipv64net/sonar64` – fertig.

## 2. Was über einen Knoten bekannt ist

| Angabe | Woher | Öffentlich |
|---|---|---|
| Name | Teilnehmer wählt einen Anzeigenamen (Standard: zufällig, z. B. „Sonar-Falke-42“) | ja |
| Standort | Teilnehmer setzt einen Punkt auf der Karte | verschleiert (1 km) |
| Provider, ASN, Präfix | ipv64 aus der öffentlichen IP der Verbindung (BGP-/RIR-Daten), nicht vom Knoten behauptet | ja |
| Anschlussart (Glasfaser, DSL, Kabel, LTE/5G, Starlink, Rechenzentrum …), Gerät (Node64, MikroTik, Pi …) | Teilnehmer / Knoten | ja |
| IPv4, IPv6, DS-Lite/CGNAT | Selbsttest | ja |
| Vertrauensstufe, dabei seit, Verfügbarkeit | Abschnitt 6 | ja |
| Erreichbarkeit (ICMP am Router, UDP 6464, nur ausgehend) | Prüfung durch die Anker | Art ja, Adresse nein |
| Öffentliche IP | Verbindung zu ipv64 (kein Header) | **nie**; nur Knoten, die ihn messen sollen, bekommen sie im Plan |

## 3. Ziele und Erreichbarkeit

Ein Ping endet meist am Router/Modem des anderen – gewollt, gemessen wird dessen Leitung. Je Ziel der beste Weg:

1. **ICMP an die öffentliche IP** (antwortet der Router).
2. **UDP 6464:** der Knoten antwortet selbst, wenn der Port freigegeben ist; misst bis zum Knoten.
3. **Nur ausgehend:** misst andere und die Anker, wird selbst nicht gemessen.

Die Anker prüfen regelmäßig, welcher Weg je Knoten und Adressfamilie funktioniert; Ziele, die nie antworten, kommen
in keinen Messplan.

## 4. Gesittetes Messen

Der Plan kommt zentral, die **Grenzen sitzen im Kern** – auch ein fehlerhafter Plan kann keinen Knoten ausrasten
lassen.

- **Runden:** alle 5 min, zufälliger Versatz je Knoten.
- **Budget je Knoten (fest im Code):** höchstens 20 Ziele je Runde, höchstens 2 Pakete/s, Tagesgrenze; Stufen
  „sparsam / normal / großzügig“ (MikroTik-Standard: sparsam).
- **Budget je Ziel (Zentrale):** ein Knoten wird je Runde von höchstens 10 anderen gemessen.
- **Nur Ziele aus dem signierten Plan**, nie private Netze.
- **Paarauswahl:** immer die Anker; geografische Nachbarn; gleicher und fremder Provider; rotierende Stichprobe,
  damit über den Tag jedes Paar vorkommt.
- **Selbstbremse:** eigene Leitung gestört (kein Uplink, hoher Verlust zu den Ankern) → Pause.

## 5. Messarten

| Phase | Messung |
|---|---|
| S1 | Ping IPv4/IPv6 (ICMP oder UDP 6464): Min, Mittel, Max, Jitter, Verlust – zu Ankern und Knoten |
| S5 | Traceroute (Paris-Traceroute) zu Ankern und ausgewählten Knoten, Hops → ASN → Verbindungswege |
| später | DNS-Antwortzeit, Path-MTU (nur zu Ankern) |

## 6. Vertrauen (öffentlich, wie im Tor-Netz)

| Stufe | Badge | Bedingung (Startwerte, einstellbar) | Wirkung |
|---|---|---|---|
| Neu | grau | < 7 Tage dabei | misst und wird gemessen, zählt in Auswertungen kaum |
| Stabil | blau | ≥ 7 Tage, Verfügbarkeit ≥ 90 % (30 Tage), Werte plausibel | zählt normal |
| Vertraut | grün | ≥ 60 Tage, Verfügbarkeit ≥ 97 %, kaum Abweichungen | zählt doppelt, Bezugspunkt für Nachbarn |
| Säule | gold | ≥ 180 Tage, sehr stabil, wird gemessen | Referenzziel für neue Knoten, hohes Gewicht in der Störungserkennung |
| Anker | violett | von ipv64 betrieben oder freigegeben | feste Messpunkte |

- Grundlagen: Dauer, Verfügbarkeit, Stabilität von IP/Provider, Plausibilität (Abschnitt 6a).
- Aufstieg langsam, **Abstufung sofort** bei unplausiblen Werten oder Manipulationsverdacht.
- Ergebnisse mit dem Schlüssel des Knotens signiert, der Plan mit dem von ipv64.

## 6a. Plausibilitätsprüfung

Jede Meldung wird bei ipv64 geprüft, bevor sie zählt. Ein Knoten kann nur über sich selbst und seine Messungen
lügen – und genau das fällt auf, weil jede Leitung von mehreren Seiten gemessen wird.

| Prüfung | Was sie erkennt |
|---|---|
| **Signatur und Absender** | Meldungen nur mit dem Schlüssel des Knotens; die IP stammt aus der Verbindung, nicht aus einer Angabe |
| **Nur geplante Messungen** | Ergebnisse nur für Ziele und Runden aus dem eigenen Plan; erfundene Ziele, zu viele Messungen, falsche Zeiten → verworfen |
| **Physikalische Untergrenze** | Licht in der Faser schafft ~200 km je ms: Eine Antwortzeit unter 2 × Entfernung / 200 km/ms ist unmöglich (erkennt geschönte Werte und einen falschen Standort) |
| **Anker als Wahrheit** | Beide Anker messen jeden Knoten selbst; was ein Knoten über die Anker meldet, muss zu dem passen, was die Anker über ihn messen |
| **Standort gegen Laufzeit** | Antwortzeiten zu beiden Ankern müssen zum angegebenen Standort passen (grobe Ortung); ein Knoten „in München“ mit 1 ms nach Nürnberg fällt auf |
| **Hin und zurück** | A→B und B→A sollten ähnlich sein; große, dauerhafte Unterschiede sprechen gegen eine Seite |
| **Mehrheit der Messenden** | Jedes Ziel wird von mehreren gemessen; Werte weit weg vom Median der vertrauten Knoten zählen nicht |
| **Erreichbarkeit** | Meldet ein Knoten Ziele als tot, die alle anderen erreichen, liegt es an ihm (Selbstbremse) oder an der Meldung |
| **Zu glatte Werte** | Immer gleiche Zeiten, kein Jitter, nie Verlust → erzeugte statt gemessene Werte |
| **Stichproben** | ipv64 mischt unauffällig Kontrollziele mit bekannten Werten (Anker) in Pläne; wer dort falsch meldet, meldet überall falsch |

**Folgen:** Unplausible Meldungen werden verworfen und gezählt. Häufen sie sich, sinkt das Vertrauen, bis hin zu
**Quarantäne** (misst weiter, zählt aber nicht und taucht nicht in Statistiken auf) und Ausschluss. Öffentliche Werte
und die Störungserkennung rechnen ohnehin mit dem gewichteten Median, nie mit dem Wert eines einzelnen Knotens.

## 7. Community und Mehrwert

**Für alle sichtbar (ipv64.net/sonar):**
- **Die Karte** (Deutschland, eigene schlichte Karte ohne fremde Kacheln): Knoten als Punkte im Badge-Stil
  (Farbe = Latenz bzw. Vertrauensstufe), Verbindungslinien mit kleinen Badges in ms, die aktuellen Messungen laufen
  sichtbar über die Karte. Klick auf einen Knoten: Name, Provider, Anschlussart, Stufe, dabei seit, Latenz zu den Ankern.
- **Teilnehmerliste:** alle Knoten mit Stufe, Provider, Region, Gerät, Verfügbarkeit; filterbar.
- **Bestenliste / Säulen:** die zuverlässigsten Knoten, längste Teilnahme, je Provider und Region.
- **Zahlen live:** aktive Knoten, Messungen heute, abgedeckte Provider und Regionen.
- **Provider-Matrix** (Latenz Provider A ↔ B) und Vergleich je Anschlussart.
- **Störungen:** laufende und vergangene Ausfälle nach Region und Provider auf der Karte.
- **Öffentliche Knotenseite** (`/sonar/node/<name>`), teilbar, mit Stufe und Verlauf (ohne IP, Standort verschleiert).

**Für den Teilnehmer:**
- **In Node64** (Menüpunkt Sonar64): Teilnahme, Rolle, Budget, Stufe, Fortschritt zur nächsten Stufe;
  **live als Tabellen**: abgesetzte Pings (Ziel, Provider, Ort, Weg, ms, Verlust, Zeit) und Pings gegen mich
  (über UDP 6464 sofort, über ICMP am Router aus den Ergebnissen bei ipv64, bis 5 min verzögert).
- **Auf ipv64.net „Mein Knoten“** (auch für eigenständige Knoten ohne Oberfläche): dieselben Tabellen, Verlauf.
- **Mehrwert:** eigene Leitung im Vergleich zu Nachbarn mit gleichem Provider; Meldung, wenn beim eigenen Provider in
  der Region eine Störung erkannt wird; Verlauf der eigenen Latenz zu den Ankern (Beleg gegenüber dem Provider).

## 8. Auswertung bei ipv64

- Knoten schicken alle 5 min eine **Zusammenfassung je Ziel** (keine Rohpakete).
- Aufbewahrung: 5-min-Werte 7 Tage, Stundenwerte je Paar 90 Tage, Tageswerte je Provider/Region dauerhaft.
- **Störungen nach Sektoren:** viele Knoten einer Region oder eines Providers gleichzeitig nicht erreichbar oder stark
  langsamer → Störung, gewichtet nach Vertrauen.
- Jobs (Planer alle 5 min, Verdichtung stündlich, Störungserkennung alle 5 min, Vertrauen täglich) in
  `bots/honeypot_cron.php` (HPC_JOBS), kein neuer Cron. Wächst es stark, wandern Annahme und Planer in ein eigenes
  Go-Programm.

## 9. API v2

| Methode | Pfad | Zweck |
|---|---|---|
| POST | `/sonar/tokens` | Sonar-Token anlegen (mit API-Key; Node64 macht das beim Opt-in) |
| GET/PUT | `/sonar/me` | eigener Knoten: Name, Standort, Anschlussart, Rolle |
| GET | `/sonar/plan` | Messplan (ETag, alle 15 min, signiert) |
| POST | `/sonar/results` | Ergebnisse (alle 5 min, signiert) |
| GET | `/sonar/inbound` | wer hat mich gemessen |
| GET | `/sonar/public/*` | Karte, Knoten, Statistik, Störungen (ohne Anmeldung, für die öffentlichen Seiten) |

## 10. Datenschutz

Standort verschleiert, IPs nie öffentlich und nur an die Knoten, die messen sollen; Anzeigename statt Account; Opt-in
mit klarem Hinweis; Eintrag in der Datenschutzerklärung.

## 11. Phasen

| Phase | Inhalt |
|---|---|
| S0 | Kern `internal/sonar`, Programm `cmd/sonar64` (Knoten + Anker, ohne Dashboard), Binaries und Image, Installationsskript, API `/sonar/me` und Tokens, Anker auf hc-srv01/02, Provider-Erkennung, Selbsttest |
| S1 | Messpläne, Ping-Netz mit Grenzen und Plausibilitätsprüfung, optionales Node64-Modul mit Live-Tabellen, Mini-Status, „Mein Knoten“ auf ipv64.net; Test auf Pi Zero |
| S2 | Öffentliche Karte mit Badges, Teilnehmerliste, Zahlen live |
| S3 | Vertrauensstufen (öffentlich), Bestenliste, Provider-Matrix |
| S4 | Störungserkennung nach Region und Provider, Meldungen an Teilnehmer |
| S5 | Traceroute und Verbindungswege auf der Karte |

## Offen

- Startwerte für Budget und Stufen nach den ersten Wochen nachjustieren.
- MikroTik: kleinstes sinnvolles Gerät testen (RAM, Container-Paket, ICMP-Rechte im Container).
- Pi Zero (ARMv6) als Referenz für „leichtgewichtig“: RAM, CPU und Laufzeit im Dauerbetrieb messen.
- Karte später ggf. Europa.
