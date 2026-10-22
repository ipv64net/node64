# Plan: DNS64 als lokaler DNS-Server, Weiterleitungen und Cluster

Stand 2026-10-22. Anlass: Rückmeldungen an Dennis – eigene Einträge reichen für einen echten lokalen DNS-Server noch
nicht, gewünscht sind Weiterleitungen „Domain → DNS-Server“, und DNS64 soll in den Cluster (Schalter je Bereich).
Grundlagen: [PLAN-NODE64-DNS64.md](PLAN-NODE64-DNS64.md), [CLUSTER.md](CLUSTER.md),
[PLAN-NODE64-CLUSTER-MODULE.md](PLAN-NODE64-CLUSTER-MODULE.md) (DNS64-Teil wird hiermit umgesetzt).

## Ausgangslage

- Eigene Einträge (`dns64_records`): A, AAAA, CNAME, Platzhalter `*.name`, PTR automatisch aus A/AAAA. Nur anlegen,
  löschen, an/aus – kein Bearbeiten, kein Kommentar, kein Import.
- Lokale Namen (`.lan`, `.home.arpa`, `.fritz.box`, ein Wort, private Reverse-Zonen …) gehen fest an den Router
  (automatisch erkannt oder Einstellung `dns64.router`), nie ins Internet.
- Eine Weiterleitung einzelner Domains an andere DNS-Server gibt es nicht.
- Cluster: Provider-Schnittstelle `/peer/v2/sync` vorhanden (erstes Modul: Zertifikate); die Cluster-Seite zeigt
  Module und Bereiche mit Schaltern automatisch, sobald sich ein Provider anmeldet.

## Teil A – Lokaler DNS (Phase L1, L2)

**L1 Eigene Einträge ausbauen**
- Weitere Typen: TXT, MX, SRV, PTR (von Hand, z. B. für Geräte ohne A-Eintrag hier), CAA. NS/SOA nur über Zonen (L2).
- Bearbeiten (heute nur löschen und neu anlegen), Kommentar je Eintrag, eigene TTL bleibt.
- PTR automatisch je Eintrag abschaltbar (mehrere Namen auf derselben IP: einer ist der „richtige“).
- Import/Export: Hosts-Datei (`192.168.1.10 nas nas.home.lan`), CSV und JSON; Export als Hosts-Datei und CSV.
- Liste: Suche, Gruppierung nach Domain, Zähler.
- Geräte aus den Gerätegruppen mit Namen automatisch als `<name>.<lokale Domain>`.

**L2 Lokale Zonen**
- Eine Zone (z. B. `home.lan`) ist „hier zu Hause“: Namen darin kommen aus den eigenen Einträgen, unbekannte Namen
  bekommen NXDOMAIN mit SOA – statt an den Router zu gehen. Wahlweise „Rest an den Router/Weiterleitung“.
- SOA/NS der Zone automatisch (Node als Nameserver), damit sich Clients und `nslookup` sauber verhalten.
- Ohne Zone bleibt alles wie heute (Router für lokale Namen).

## Teil B – Weiterleitungen (Phase L3)

Tabelle „Domain → DNS-Server“ (links Domain, rechts ein oder mehrere Server):
- Domain gilt mit allen Unternamen (`firma.local`, `corp.example.de`, `10.in-addr.arpa`); die längste passende gewinnt.
- Server: `192.168.1.1`, `[fd00::1]:5353`, `tls://dns.firma.de`, `https://…/dns-query`, `quic://…` (derselbe Parser wie
  die Upstreams, inkl. Happy Eyeballs). Mehrere Server: der Reihe nach, Ausfall → nächster.
- Reihenfolge im Resolver: eigene Einträge → lokale Zonen → **Weiterleitung** → lokale Namen an den Router → Filter →
  Cache → Upstreams. Der eingebaute Router-Weg erscheint in der Tabelle als feste Zeile („lokale Namen → Router“).
- Schlägt eine Weiterleitung fehl: SERVFAIL, nie an die öffentlichen Upstreams (keine internen Namen nach draußen).
- Abfrage-Log zeigt „Weiterleitung: <Domain> → <Server>“; Prometheus je Weiterleitung (Anfragen, Fehler, Zeit);
  „Testen“-Knopf je Zeile; Hinweis bei Ausfall über die Benachrichtigungen (wie Upstream gestört).
- „Umschreiben“: Domain A antwortet wie Domain B (CNAME mit Auflösung durch DNS64, Platzhalter erlaubt).

## Teil C – DNS64 im Cluster (Phase L4)

Neues Provider-Modul `dns64` (über ein kleines Paket wie `certs/certcluster`, damit dns64 nicht von peer abhängt).
Auf der Cluster-Seite erscheint DNS64 mit Schiebereglern je Bereich:

| Bereich | Standard | Inhalt | nicht dabei |
|---|---|---|---|
| Einstellungen | aus | Upstreams, Modus, Blockier-Art, Cache, Listen-Intervall, Firefox-Schalter, Anonymisierung, Aufbewahrung | Ports, Bind, Router, DoH/DoT/DoQ, Namen, Zertifikat, Client-Netze, Pause |
| Blocklisten | aus | Auswahl und eigene Listen-URLs (jede Node lädt selbst) | |
| Freigaben | aus | Freigabeliste | |
| Eigene Einträge | aus | alle Typen, Zonen | Einträge mit „nur diese Node“ |
| Weiterleitungen | aus | Domain → Server | Einträge mit „nur diese Node“ |
| Gruppen | aus | Regeln, Kategorien, Kinderschutz, Domains, Zeitpläne, Sperren/Frei | |
| Gruppen-Mitglieder | aus | MAC/IP/Netz je Gruppe (gehören zum Standort) | |

Technik:
- Jeder Eintrag bekommt eine Cluster-Kennung (`uid`); Verweise laufen darüber (Mitglied → Gruppe).
- Natürliche Schlüssel für das erste Zusammenführen: Eintrag = Name+Typ+Wert, Weiterleitung = Domain, Freigabe =
  Domain, Gruppe = Name, Einstellung = Schlüssel. Gleiche Einträge auf zwei Nodes werden so nicht doppelt.
- „Nur diese Node“ je Eintrag/Weiterleitung (z. B. `nas.home.lan` je Standort, `firma.local` nur am Büro-Node): wird
  nie abgeglichen.
- Änderungen über Hooks in den bestehenden Funktionen (Anlegen, Ändern, Löschen) → `ClusterChange`; Übernahmen bauen
  Momentaufnahme/Filter neu, ohne Neustart, wo es heute schon ohne geht.
- Die jüngere Änderung gewinnt (wie im Cluster üblich); „Internet aus“ wirkt dadurch sofort auf allen Nodes.
- Abfrage-Log und Statistik werden nicht kopiert (später live über alle Nodes, eigener Schritt).

## Phase L5 – Doku, API, Webseite

README, Changelog, OpenAPI, i18n (de/en), Hilfe-Anker (`dns64#eigene-eintraege`, `dns64#zonen`,
`dns64#weiterleitungen`, `dns64#cluster`), Meldung an die Webseiten-Sitzung je Commit.

## Reihenfolge

L1 → L3 → L2 → L4 → L5 (Weiterleitungen vor Zonen, weil gefragter; Cluster zuletzt, damit alle neuen Tabellen von
Anfang an eine `uid` haben). Jede Phase eigene DNS64-Version mit Tests, Rollout nur auf Dennis' Ansage.

## Entscheidungen (Dennis, 2026-10-22)

1. Weiterleitungen: Blocklisten und Gruppenregeln gelten weiter, außer für lokale Namen und Reverse-Zonen.
2. Cluster: alle DNS64-Bereiche ohne Einstellung **aus**, jeder Bereich wird einzeln eingeschaltet.
3. Geräte mit Namen automatisch als DNS-Namen: wird in L1 mitgebaut (Schalter je lokaler Zone, siehe L2).
4. „Umschreiben“ Domain A → Domain B: wird mitgebaut (in L3).
