# Plan: Sonar64 – verteiltes Messnetz (RIPE-Atlas-Idee)

Stand 2026-10-28, Wunsch und Entscheidungen Dennis. **Nur Planung**, noch nichts umgesetzt.

Node64-Installationen bei den Leuten zu Hause messen sich gegenseitig (Ping, später Traceroute), geordnet und
sparsam nach einem zentralen Plan von ipv64.net. Daraus entsteht ein Gesamtbild: wer wie erreichbar ist, welche
Latenzen zwischen Providern und Regionen bestehen und wo ganze Bereiche ausfallen. **Kein Guthaben, keine Messungen
auf Abruf, keine Fremdziele** – nur das automatische Netz der Teilnehmer und der Anker.

## Vorgeschichte

Im alten Portal gab es „Node64.io – Distributed Internet Measurement“ (`ipv64net_webseite/nodes.php`, `dims/`,
eigene DB `$node64pdo`, Stand 2023, aufgegeben). Lehren daraus:

- Ziele waren zufällige andere Nodes (`ORDER BY RAND()`), ohne Paarplanung und ohne Grenzen je Ziel.
- Nur Koordinaten, kein Provider/ASN, keine Karte.
- Ergebnisse kaum geprüft, Belohnungs-/Blockchain-Teil manipulierbar, IP aus fälschbarem Header.

Sonar64 wird neu gebaut; vom alten Code wird nichts übernommen.

## Entscheidungen

| Thema | Entscheidung |
|---|---|
| Teilnahme | Opt-in in Node64 (eigener Menüpunkt **Sonar64**), nur mit ipv64-Verknüpfung (API-Key) |
| Gemessen werden | freiwillig: wer nicht gemessen werden will, misst **nur ausgehend** und erscheint nie als Ziel |
| Standort | Breiten-/Längengrad, öffentlich **im Umkreis von 1 km verschleiert** (Testwert): fester zufälliger Versatz je Node, damit der Punkt nicht springt; genauer Wert nur bei ipv64 |
| Anker | die hubs `hc-srv01` (Falkenstein) und `hc-srv02` (Nürnberg), **nicht** die CDN64-Server |
| Anker-Software | **eigenes Programm**, nicht im hub: eigenes Binary, eigener Dienst, eigene Konfiguration, kein Zugriff auf die hub-Datenbank. Ein Anker meldet sich wie ein Knoten über die API an und lässt sich jederzeit auf andere Server verschieben |
| Vertrauen | Knoten bauen über die Zeit Vertrauen auf (wie die Flags im Tor-Netz), siehe Abschnitt 6 |
| Karte | Deutschlandkarte mit Knoten, Verbindungslinien und kleinen Badges (ms), Infos je Knoten |
| Node64 | live und tabellarisch: abgesetzte Pings und Pings gegen mich (wenn gemessen werden aktiv ist) |
| Nicht dabei | Guthaben, Messungen auf Abruf (Globalping-Art), beliebige Ziele |

## 1. Was über einen Knoten bekannt ist

| Angabe | Woher | Öffentlich |
|---|---|---|
| Standort | Nutzer setzt einen Punkt auf der Karte (Node64) | verschleiert (1 km) |
| Provider, ASN, Präfix | ipv64 aus der öffentlichen IP der Verbindung (BGP-/RIR-Daten), nicht vom Knoten behauptet | ja |
| Anschlussart (Glasfaser, DSL, Kabel, LTE/5G, Starlink, Rechenzentrum …) | Nutzer | ja |
| IPv4, IPv6, DS-Lite/CGNAT, MTU | Selbsttest | ja |
| Erreichbarkeit (ICMP am Router, Sonar-Port, nur ausgehend) | Prüfung durch die Anker | nein |
| Öffentliche IP | Verbindung zu ipv64 (kein Header) | **nie**; nur Knoten, die ihn messen sollen, bekommen sie im Plan |
| Vertrauensstufe | Abschnitt 6 | ja (Badge) |

## 2. Ziele und Erreichbarkeit

Ein Ping endet meist am Router/Modem des anderen – gewollt, gemessen wird dessen Leitung. Viele Router antworten
nicht (besonders IPv6 hinter der Firewall), daher je Ziel der beste Weg:

1. **ICMP an die öffentliche IP** (antwortet der Router).
2. **Sonar-Port (UDP-Echo, optional):** Node64 antwortet selbst, wenn der Nutzer den Port freigibt; misst bis zur Node.
3. **Nur ausgehend:** misst andere und die Anker, wird selbst nicht gemessen.

Die Anker prüfen regelmäßig, welcher Weg je Knoten und Adressfamilie funktioniert. Ziele, die nie antworten, kommen
in keinen Messplan.

## 3. Gesittetes Messen

Der Plan kommt zentral, die **Grenzen sitzen in der Node** – auch ein fehlerhafter Plan kann keine Node ausrasten
lassen.

- **Runden:** alle 5 min, zufälliger Versatz je Node.
- **Budget je Node (fest im Code, vom Server nicht änderbar):** höchstens 20 Ziele je Runde, höchstens 2 Pakete/s,
  Tagesgrenze; Stufen „sparsam / normal / großzügig“; Ruhezeiten.
- **Budget je Ziel (Zentrale):** ein Knoten wird je Runde von höchstens 10 anderen gemessen.
- **Nur Ziele aus dem signierten Plan**, nie private Netze.
- **Paarauswahl** statt Zufall: immer die Anker; geografische Nachbarn; gleicher und fremder Provider; rotierende
  Stichprobe, damit über den Tag jedes Paar vorkommt.
- **Selbstbremse:** eigene Leitung gestört (kein Uplink, hoher Verlust zu den Ankern) → Pause, damit kaputte
  Anschlüsse das Bild nicht verfälschen.

## 4. Messarten

| Phase | Messung |
|---|---|
| S1 | Ping IPv4/IPv6: Min, Mittel, Max, Jitter, Verlust – zu Ankern und Knoten |
| S4 | Traceroute (Paris-Traceroute) zu Ankern und ausgewählten Knoten, Hops → ASN → Pfade und Übergänge zwischen Providern |
| später | DNS-Antwortzeit, HTTPS-Zeit, Path-MTU (nur zu Ankern/eigenen Zielen von ipv64) |

## 5. Auswertung bei ipv64

- Knoten schicken alle 5 min eine **Zusammenfassung je Ziel** (keine Rohpakete).
- Aufbewahrung: 5-min-Werte 7 Tage, Stundenwerte je Paar 90 Tage, Tageswerte je Provider/Region dauerhaft.
- **Störungen nach Sektoren:** Viele Knoten einer Region oder eines Providers gleichzeitig nicht erreichbar oder stark
  langsamer → Störung („Vodafone Kabel, Raum Köln: 23 von 40 nicht erreichbar seit 14:05“). Gewichtet nach Vertrauen.
- **Plausibilität:** Ergebnisse gegen den Median der anderen Messenden; Abweichler verlieren Vertrauen.

## 6. Vertrauen (Ranking wie im Tor-Netz)

Neue Knoten zählen wenig; wer lange zuverlässig mitmacht, gewinnt Gewicht.

| Stufe | Bedingung (Startwerte, einstellbar) | Wirkung |
|---|---|---|
| Neu | < 7 Tage dabei | misst, wird gemessen, zählt in Auswertungen kaum |
| Stabil | ≥ 7 Tage, Verfügbarkeit ≥ 90 % (30 Tage), Werte plausibel | zählt normal |
| Vertraut | ≥ 60 Tage, Verfügbarkeit ≥ 97 %, kaum Abweichungen | zählt doppelt, Bezugspunkt für Nachbarn |
| Säule | ≥ 180 Tage, sehr stabil, gemessen werden aktiv | Referenzziel für neue Knoten, besonders hohes Gewicht in der Störungserkennung |

- Grundlagen: Dauer der Teilnahme, Verfügbarkeit, Stabilität der IP/des Providers, Plausibilität der Ergebnisse.
- **Abwertung** bei unplausiblen Werten, auffälligen Mustern oder Manipulationsverdacht; Herabstufung sofort, Aufstieg
  langsam. Ein Providerwechsel setzt das Alter nicht zurück, die Plausibilität wird neu aufgebaut.
- Ergebnisse sind mit dem Schlüssel der Node signiert; der Plan mit dem von ipv64.

## 7. Darstellung

**ipv64.net/sonar (öffentlich):**
- Deutschlandkarte (eigene, schlichte Karte ohne fremde Kartenkacheln): Knoten als Punkte (verschleiert), eingefärbt
  nach Latenz/Erreichbarkeit, Verbindungslinien mit kleinen Badges (ms), Klick zeigt Knoten-Infos (Provider,
  Anschlussart, Vertrauensstufe, Latenz zu den Ankern).
- Provider-Matrix (Latenz Provider A ↔ B), Rangliste je Anschlussart.
- Laufende und vergangene Störungen auf der Karte; später Pfade aus Traceroutes.

**Node64 (Menüpunkt Sonar64):**
- Teilnahme, Rolle (messen / auch gemessen werden), Sonar-Port, Budget-Stufe, Standort setzen, Vertrauensstufe.
- **Abgesetzte Pings live** als Tabelle (Ziel-Knoten, Provider, Ort, Weg, ms, Verlust, Zeit).
- **Pings gegen mich:** über den Sonar-Port live (die Node sieht sie selbst); über ICMP am Router sieht die Node
  sie nicht – dann aus den Ergebnissen bei ipv64 (Verzögerung bis 5 min).
- Eigene Leitung im Vergleich zu Nachbarn mit gleichem Provider; Verlauf zu den Ankern.

## 8. Technik

- **Node ↔ ipv64:** API v2 (Muster Honeypot64): `PUT /sonar/me` (Standort, Anschlussart, Rolle),
  `GET /sonar/plan` (ETag, alle 15 min), `POST /sonar/results` (alle 5 min), `GET /sonar/inbound` (wer hat mich
  gemessen).
- **Anker:** eigenes Go-Programm `cmd/sonar-anchor` (eigener Dienst `ipv64-sonar-anchor`, eigene Konfiguration,
  eigener Anker-Schlüssel). Gemeinsam mit Node64 nur ein kleines Paket für Protokoll und Messung (`internal/sonar`),
  keine Abhängigkeit vom hub. Umzug = Binary auf anderen Server, Schlüssel mitnehmen.
- **Zentrale Jobs** (Planer alle 5 min, Verdichtung stündlich, Störungserkennung alle 5 min, Vertrauen täglich) in
  `bots/honeypot_cron.php` (HPC_JOBS), kein neuer Cron.
- **Last:** 1.000 Knoten ≈ 3 Anfragen/s – PHP/MySQL reicht; wächst es stark, wandern Annahme und Planer in ein
  eigenes Go-Programm.
- **Rechte:** ICMP braucht `cap_net_raw` (hat Node64 schon für Healthchecks).
- **Datenschutz:** Standort verschleiert, IPs nie öffentlich und nur an die Knoten, die messen sollen; Opt-in mit
  klarem Hinweis; Eintrag in der Datenschutzerklärung.

## 9. Phasen

| Phase | Inhalt |
|---|---|
| S0 | Opt-in, Standort, ASN-Zuordnung, Anker-Programm auf hc-srv01/02, Selbsttest der Erreichbarkeit |
| S1 | Messpläne, Ping-Netz mit Grenzen, Seite in Node64 mit Live-Tabellen |
| S2 | Öffentliche Deutschlandkarte, Provider-Matrix |
| S3 | Vertrauensstufen, Störungserkennung nach Region und Provider, Meldungen |
| S4 | Traceroute und Pfade |

## Offen

- Startwerte für Budget und Vertrauensstufen nach den ersten Wochen nachjustieren.
- Sonar-Port: feste Nummer festlegen (Vorschlag UDP 6464).
- Karte später ggf. Europa.
