# Plan: IPAM64 (IP-Adressverwaltung)

Stand 2026-11-14, **Plan v2, von Dennis freigegeben (E1–E5 wie empfohlen, 2026-11-14). I1 umgesetzt (IPAM64 0.1.0, Zweig `claude/zen-goldberg-805131`, auf 1.7.0), noch nicht in `main`; Ziel 1.8.0.**

Anlass: Das Community-Mitglied UlrichSchwarz hat ein Modul IPAM64 gebaut (Repo `UlrichSchwarz/node64-redesign`, Zweig
`claude/inspiring-hamilton-dpu6g9`, Basis 1.5.9). Vorbild ist der IP-Teil von Netbox, ohne Räume, Racks und
Geräteinventar. Klickbare Vorschau mit Beispieldaten: https://claude.ai/artifact/8DJdoWH7ioX463yxdJpq4g

Grundlagen: [PLAN-NODE64-DNS64-DHCP.md](PLAN-NODE64-DNS64-DHCP.md), [PLAN-NODE64-DNS64-LOKAL.md](PLAN-NODE64-DNS64-LOKAL.md),
[PLAN-NODE64-CLUSTER-MODULE.md](PLAN-NODE64-CLUSTER-MODULE.md), [PLAN-NODE64-BENUTZER.md](PLAN-NODE64-BENUTZER.md).

## Entschieden (Dennis, 2026-11-14)

- Community-Code **als Grundlage übernehmen und umbauen**, auf dem aktuellen Stand (`main`, wird 1.7.0), nicht auf 1.5.9.
- **Eigenes Modul** nach DNS64 im Menü, Standard aus.
- **IPv4 und IPv6 von Anfang an** (nicht erst in einer späteren Stufe).
- **Cluster** von Anfang an.
- **DHCP-Server und DNS beziehen ihre festen Einträge aus IPAM64** und vergeben bzw. beantworten sie.
- DNS64 bekommt **Ausnahmen im DHCP-Adressbereich**.
- **Aktiver Scan erlaubt, aber begrenzt** (nur private Netze, IPv4 höchstens /22, im Hintergrund).
- Ziel: sicher, übersichtlich für Anfänger, trägt aber auch größere Umgebungen.

## Ziel in einem Satz

IPAM64 ist **die eine Stelle**, an der man Netze und feste Adressen (IPv4 und IPv6) plant. DHCP-Server und lokaler
DNS von DNS64 setzen das sofort um: Eine Adresse mit MAC wird zur DHCP-Reservierung, eine Adresse mit Namen zu A/AAAA
und PTR. Leases, Scan und die anderen Module zeigen, was wirklich im Netz ist; Abweichungen erscheinen als Konflikte.

## Leitlinien

1. **IPAM64 ist führend für feste Einträge, DNS64 bleibt der Dienst.** Planen (Präfixe, Adressbereiche, feste
   Adressen, Status, DNS-Name, Reservierung) geschieht in IPAM64. Ausliefern (DHCP-Vergabe, DNS-Antworten, Leases,
   Optionen, CNAME/TXT/MX, Weiterleitungen, Filter) bleibt in DNS64.
2. **Keine Drift.** Jeder feste Eintrag hat genau einen Besitzer. Einträge, die IPAM64 besitzt, sind in DNS64 als
   „verwaltet von IPAM64“ gekennzeichnet und dort nur über IPAM64 änderbar (Oberfläche, API, MCP). Ein Abgleich prüft
   regelmäßig, ob beide Seiten übereinstimmen, und repariert bzw. meldet.
3. **Ausfallsicher.** DHCP und DNS laufen weiter, wenn IPAM64 abgeschaltet ist, eine Cluster-Node IPAM64 nicht hat
   oder die Reserve-Node übernimmt (siehe E1).
4. **Eine Sprache.** „Netz“ = DHCP-Netz in DNS64, „Präfix“ = Netz in IPAM64, „Adressbereich“ statt „Bereich“ (das Wort
   gehört dem Cluster). IPv4 und IPv6 erscheinen in denselben Listen.
5. **Einfach zuerst.** Beim Einschalten richtet ein Assistent alles aus dem Vorhandenen ein (Schnittstellen der Node,
   DHCP-Netze, feste Adressen, lokale A/AAAA-Einträge). VLAN, Rolle, Tags und Adressbereiche stehen unter „Erweitert“,
   bis man sie nutzt.
6. **Skalierbar.** Listen werden auf dem Server gefiltert und seitenweise geladen, das Raster gibt es nur bis /22 (in
   /24-Blöcken), IPv6 wird in /64 gezählt. Die API kann alles, was die Oberfläche kann (Import, Export, „nächste freie
   Adresse“ atomar).
7. **Sicher.** Rechte über die vorhandenen Rollen (Administrator ändert, „Nur lesen“ sieht), jede Änderung im
   Audit-Log mit ihren Folgen in DNS64, strenge Eingabeprüfung, ein Scan nie außerhalb eigener privater Netze.

## Bestand, auf dem wir aufbauen

### Node64 heute (`main`, DNS64 1.40.x)

| Baustein | Stelle im Code | Bedeutung für IPAM64 |
|---|---|---|
| DHCP-Konfiguration | `dns64.(*Module).dhcpConfig` liest Netze, Reservierungen, Leases → `dhcp.Config` | einzige Stelle, an der Reservierungen in den Server gehen |
| Reservierungen | `dns64_dhcp_reservations`, `AddDHCPReservation` …, Cluster `r:<Netz>\|<MAC>` | bekommen `origin`/`ref` für IPAM64 |
| Pool | `dhcp.Scope{Start, End}`; `pick()` überspringt reservierte IPs (`resIP`) | Ausnahmen = reservierte IPs ohne MAC (kleine Erweiterung) |
| ARP-Prüfung | `probeWait` vor der Vergabe | bleibt, schützt zusätzlich |
| Lokale Einträge | `dns64_records` mit `origin` (heute `''`/`docker`), PTR automatisch aus A/AAAA | IPAM64-Einträge mit `origin = 'ipam64'` |
| DNS-Antwort | `Lookup`: eigene Einträge → DHCP-Namen (Speicher) → Platzhalter → PTR | unverändert; IPAM-Einträge sind eigene Einträge |
| Nachbartabelle | `dns64/groups` (Netlink `RTM_GETNEIGH`, `AF_UNSPEC`, **IPv4 und IPv6**) | ersetzt den IPv4-Parser des Community-Zweigs |
| Geräte/Client-Namen | `groups.Resolver`, Abfrage-Log, `NetDevices` | Name und „zuletzt gesehen“ |
| IPv6-Präfix | `dyndns/detect.go` (globale Adresse, `prefix64`) und Schnittstellen der Node | Quelle für dynamische Präfixe |
| Cluster | `peer.Provider` (`ClusterIDs/Get/Apply`), `ClusterChange` | eigene Bereiche für IPAM64 |
| Modul-Schnittstellen | `module.Module`, `Exporter`, `CardProvider`, `Templater`, Audit, Metriken, MCP-Bereiche | wie bei den anderen Modulen |
| Rollen | `Guards.Auth` sperrt schreibende Methoden für „Nur lesen“ zentral | nichts Eigenes nötig |
| Weitere Adressen | `m64_hosts.address`, `cdn64.Host/Stream.TargetHost`, `healthchecks.Check.Target` | Zuordnung und IPv6-Nachführung |

Lücken heute: kein DHCPv6 (nur RA), ein Pool je Netz ohne Ausnahmen, keine Lease-Historie, keine Herstellerliste,
Lese-Funktionen für Leases und DHCP-Namen sind privat.

### Community-Zweig: was wir übernehmen

| Datei | Umgang |
|---|---|
| `merge.go` (Quellen zusammenführen, Rang, Zuordnung über Namen, Konflikte, Belegung) | **übernehmen, erweitern** auf IPv6, neue Quellen, Konfliktdämpfung |
| `store.go` (Prüfung/Normalisierung, Überschneidung) | **übernehmen**, Datenmodell v2 (unten) |
| `scan.go` (UDP-Sweep ohne Rechte) | **übernehmen, härten**: private Netze, /22, asynchron, je Node |
| `neigh*.go` | **übernommen und um IPv6 erweitert** (`AF_UNSPEC`, 16-Byte-Adressen, ohne Link-Local); `dns64/groups` liefert kein Alter der Sichtung, darum nicht ersetzt |
| `cmd/node64/ipam.go` (Verdrahtung) | **übernehmen**, um Schreibwege erweitern |
| `DHCPLeases()` in `dns64/netdevices.go`, `ProxyTargets()` in `cdn64/hosts.go` | **übernehmen** (in die neue DNS64-Schnittstelle) |
| `ui.go`, `overview.html`, Adresskarte, CSS, CSV-Export (`csvSafe`) | **Grundlage**, Oberfläche nach der Vorschau neu gliedern |
| i18n, OpenAPI, Changelogs, Tests | **übernehmen und anpassen** |

Autor nennen: `Co-Authored-By: UlrichSchwarz` in den Übernahme-Commits und im Modul-Changelog. Lizenz des Repos vor
der Übernahme prüfen. Übertragen von Hand, kein Merge des fremden Repos.

## Architektur

### Wer besitzt was

| Objekt | Besitzer | Gespeichert in | Sichtbar in |
|---|---|---|---|
| Präfix (IPv4/IPv6), Status, VLAN, Rolle, Tags | IPAM64 | `ipam_prefixes` | IPAM64 |
| Adressbereich (fest, reserviert) | IPAM64 | `ipam_ranges` | IPAM64 |
| DHCP-Pool eines Präfixes | DNS64 (Netz) | `dns64_dhcp_scopes` | beide; IPAM64 ändert über `UpdateDHCPScope` |
| DHCP-Optionen, Schnittstelle, Rolle | DNS64 | `dns64_dhcp_scopes` | DNS64 |
| Feste Adresse (Status, Name, Beschreibung) | IPAM64 | `ipam_addresses` | beide |
| DHCP-Reservierung einer festen Adresse | IPAM64 | `dns64_dhcp_reservations` mit `origin='ipam64'`, `ref=<uid>` | beide, in DNS64 nur lesend |
| Ausnahme im Pool (feste Adresse ohne MAC) | IPAM64 | `dns64_dhcp_reservations` mit leerer MAC, `origin='ipam64'` | beide |
| A/AAAA (+ PTR) einer festen Adresse | IPAM64 | `dns64_records` mit `origin='ipam64'`, `ref=<uid>` | beide, in DNS64 nur lesend |
| Lease, DHCP-Name | DNS64 | `dns64_dhcp_leases`, Speicher | beide |
| CNAME, TXT, MX, SRV, Platzhalter, Zonen, Weiterleitungen | DNS64 | wie heute | DNS64 |
| Sichtungen (MAC, zuletzt gesehen) | je Node | `ipam_seen` (nicht im Cluster) | IPAM64 |

### E1: Wie kommen die IPAM-Einträge in DHCP und DNS? (Entscheidung)

**Empfehlung: IPAM64 schreibt durch.** Speichert man eine Adresse, legt IPAM64 über die öffentlichen Funktionen von
DNS64 die Reservierung und die A/AAAA-Einträge an (gekennzeichnet). DHCP-Server und DNS lesen wie bisher aus ihren
Tabellen und vergeben bzw. beantworten damit alles, was in IPAM64 steht. Vorteile:
- Die Reserve-Node im DHCP-Cluster und jede Node ohne IPAM64 (ältere Version, Modul aus) haben die Einträge über den
  vorhandenen DNS64-Abgleich. DHCP-Failover und die Antworten beider DNS-Server bleiben gleich.
- IPAM64 abschalten nimmt nichts weg. Beim Abschalten fragt die Node, ob die Einträge an DNS64 übergeben werden
  (Kennzeichen weg, normal bearbeitbar) oder gekennzeichnet bleiben.
- Prüfung, Neustart des DHCP-Servers, PTR-Automatik und Audit von DNS64 laufen unverändert.

Alternative „DNS64 fragt live bei IPAM64 nach“ (ohne Kopie in DNS64): nur ein Datensatz, aber jede Node braucht dann
IPAM64 in derselben Version. Sonst fehlen der Reserve-Node die Reservierungen, und zwei DNS-Server antworten
unterschiedlich. Dagegen spricht die Ausfallsicherheit, deshalb nicht empfohlen.

Schutz vor Drift: Einträge mit `origin='ipam64'` lehnt DNS64 beim Ändern ab (Hinweis mit Link zu IPAM64). Der
Cluster-Abgleich wendet IPAM- und DNS64-Bereiche getrennt an. `ClusterApply` in IPAM64 schreibt **nicht** erneut
durch (die DNS64-Zeilen kommen über den DNS64-Abgleich). Ein Abgleich-Job (alle 10 Min. und nach dem Start) vergleicht
`ipam_addresses` mit den gekennzeichneten DNS64-Zeilen und repariert bzw. meldet Abweichungen.

### Datenmodell v2 (Migration `internal/ipam64/migrations/0001_init.sql`, neu statt Community-Schema)

- **`ipam_prefixes`**: `uid` (Cluster-Kennung), `prefix` (kanonisch; bei dynamischem IPv6 der aktuelle Wert), `family`
  4/6, `name`, `status` (container/active/reserved/deprecated), `vlan`, `role`, `tags`, `description`, `mark_full`,
  `dns_zone`, `scan` (off/passive/active), `scan_node` (welche Node scannt, leer = jede mit Adresse im Netz),
  `dyn_parent` (uid des Provider-Präfixes) + `dyn_index` (Präfix-ID, z. B. `10`), `dyn_source` (Schnittstelle oder
  DynDNS), `created`/`updated`/`updated_by`. Die Hierarchie wird aus den Präfixen berechnet, nicht gespeichert.
  Vorgesehen, aber in v1 ohne Oberfläche: `space` (Namensraum für überlappende Netze, Standard leer).
- **`ipam_ranges`**: `uid`, `start`, `end`, `kind` (fixed/reserved), `name`, `description`. DHCP-Pools
  sind keine Zeilen hier, sondern kommen aus DNS64.
- **`ipam_addresses`**: `uid`, `address` (IPv4 oder IPv6; bei dynamischem Präfix zusätzlich `iid`, die
  Interface-ID), `status` (active/reserved/deprecated), `role` (VIP, Anycast, Gateway …), `name`, `dns` (an/aus),
  `dns_zone`, `ptr`, `mac`, `dhcp` (Reservierung an/aus), `description`, `tags`, `created`/`updated`/`updated_by`.
  Eindeutig: `address`. Index auf `mac`, `name`. Umgesetzt in I1: Das Präfix einer Adresse bzw. eines Bereichs wird berechnet (kleinstes umfassendes Präfix), nicht gespeichert – so bleibt nichts hängen, wenn Präfixe sich ändern. `space` und `iid` kommen erst mit ihrer Stufe (eigene Migration).
- **`ipam_seen`** (je Node, nicht im Cluster): `ip`, `mac`, `iface`, `source` (neigh/scan/lease), `first`, `last`;
  30 Tage. Index auf `last`.
- VLANs sind in v1 ein Feld am Präfix; die VLAN-Liste entsteht daraus.
- **DNS64-Migrationen** (neu): `origin` und `ref` an `dns64_dhcp_reservations`, `ref` an `dns64_records`; Reservierung
  ohne MAC erlaubt (Ausnahme), nur mit `origin='ipam64'`.

### Schnittstelle DNS64 ↔ IPAM64

Neue öffentliche Funktionen in DNS64 (eine Datei `ipam_bridge.go`), verdrahtet in `cmd/node64/ipam.go` wie
`cdnModule.SetLocalDNS`, nur wenn DNS64 läuft:
- Lesen: `DHCPScopes`, `DHCPLeases()` (aus dem Community-Zweig), `DHCPUsage()`, `DeviceNames()`, `Records(origin)`.
- Schreiben mit Kennzeichen: `PutIPAMReservation(ref, scopeID, mac, ip, name)` / `DeleteIPAMReservation(ref)`,
  `PutIPAMRecords(ref, name, zone, addrs, ptr)` / `DeleteIPAMRecords(ref)`, `UpdateDHCPScope` (Pool),
  `AddDHCPScope` („DHCP für dieses Präfix einrichten“).
- Übergabe: `ReleaseIPAM(ref)` entfernt das Kennzeichen (beim Abschalten von IPAM64).
- `dhcp`-Paket: Reservierung ohne MAC = Adresse wird nie vergeben (`resIP` mit leerer MAC), zählt in `Reserved`.

### IPv4 und IPv6

- **IPv4:** Präfixe /8 bis /32, Raster bis /22, Scan bis /22, Reservierung über DHCP.
- **IPv6:** Präfixe /16 bis /128. Statische Präfixe (ULA `fd…`, eigenes Netz) und **dynamische** (vom Provider
  delegiert): Ein Provider-Präfix (z. B. /56) bekommt eine Quelle (Schnittstelle der Node oder DynDNS64). Kinder
  speichern nur ihre Präfix-ID, Adressen nur ihre Interface-ID. Wechselt das Präfix, rechnet IPAM64 alle Adressen neu
  und schreibt die AAAA-Einträge durch. PTR folgt automatisch. Im Verlauf steht „IPv6-Präfix gewechselt“.
- Adressen erkennen: Nachbartabelle (NDP) und Leases; kein Sweep in /64 (unmöglich). Aktiv nur gezielt (bekannte
  Adressen anpingen).
- Feste IPv6-Adresse vergeben: Es gibt kein DHCPv6. IPAM64 plant die Adresse (Token bzw. EUI-64, statische
  Konfiguration) und legt AAAA/PTR an; das Gerät setzt sie selbst. **DHCPv6 (stateful) wäre ein eigener DNS64-Plan
  (E3).**
- PROXY64-Ziele, Monitor64-Hosts und Healthchecks mit einer IPv6 aus einem dynamischen Präfix: IPAM64 zeigt sie an
  und zieht sie beim Präfixwechsel auf Wunsch nach (Schalter je Präfix, Standard: Vorschlag, nicht automatisch).
  Empfehlung in der Oberfläche: Ziele per DNS-Name statt IP.

### Cluster

- Eigene Bereiche im Cluster-Abgleich (Standard an): `ipam_prefixes` (`p:<uid>`), `ipam_ranges` (`g:<uid>`),
  `ipam_addresses` (`a:<uid>`). Wie die anderen Module: letzte Änderung gewinnt, Herkunft im Audit.
- Sichtungen bleiben je Node. Die Übersicht zeigt, welche Node was gesehen hat. Scan je Präfix auf der Node mit
  Adresse in diesem Netz (`scan_node` überschreibt das).
- Nodes ohne IPAM64 bekommen Reservierungen und DNS-Einträge über DNS64 (E1). Environment zeigt je Node die
  IPAM64-Version.

### Oberfläche (nach der Vorschau)

- **Übersicht** (`/ipam64`): Präfix-Baum IPv4/IPv6 mit Auslastung, freien Blöcken, DHCP-Netz, Zone, Konflikten; Suche
  nach IP, MAC, Name, Präfix.
- **Präfix** (`/ipam64/p/<uid>`): Raster (IPv4 bis /22), Liste mit Zeilen für freie Blöcke (seitenweise),
  Adressbereiche, Kinder-Präfixe.
- **Adresse** (`/ipam64/a/<uid>`): Grunddaten, DNS, DHCP; Karte „Beim Speichern passiert“; Gesehen; Zuordnungen;
  Verlauf der Adresse.
- **Adresse vergeben**: nächste freie Adresse im gewählten Adressbereich, Gerät aus Lease/Scan übernehmen.
- **Scan & Konflikte**, **Verlauf** (aus dem Audit-Log).
- **Assistent** beim ersten Öffnen: Vorschläge aus Schnittstellen und DHCP-Netzen, Übernahme der festen Adressen und
  A/AAAA-Einträge (bestehende Zeilen werden gekennzeichnet, nicht kopiert), Vorschau vor dem Übernehmen.
- **In DNS64:** Kennzeichen „IPAM64“ an Reservierungen und Einträgen mit Link; „feste Adresse geben“ an Leases legt bei
  laufendem IPAM64 eine IPAM-Adresse an.
- Dashboard-Karte (Präfixe, Belegung, Konflikte, neue Geräte). Beide Designs (Klassisch/Neu), hell und dunkel.

### Konflikte und Hinweise

Doppelte Adresse (zwei MACs), Lease gegen feste Adresse, statische Adresse im Pool ohne Lease, DNS-Eintrag ohne Gerät,
Reservierung mit fremder MAC gesehen, fremder DHCP-Server (aus DNS64), Pool fast voll (aus DNS64), IPv6-Präfix
gewechselt, Abgleich IPAM64 ↔ DNS64 abweichend. Dämpfung gegen Fehlalarme: Ein Konflikt gilt erst nach zwei
Sichtungen in mindestens 5 Minuten. DHCP-Wechsel und bekannte Repeater (MAC-NAT, Liste je Präfix) zählen nicht.
Benachrichtigung über das vorhandene System (neues Gerät, neuer Konflikt), je Art abschaltbar.

### Sicherheit

- Scan nur in Präfixen, die IPAM64 kennt, **und** an denen die Node selbst eine Adresse hat, **und** die privat sind
  (RFC 1918, 100.64/10, fd00::/8, fe80::/10). IPv4 höchstens /22, höchstens ein Scan je Node gleichzeitig,
  Paketrate begrenzt, Abbruch möglich.
- Eingaben über `netip`/`net.ParseMAC`, Längen, keine Steuerzeichen; DNS-Namen nach RFC 1123; Zone muss es in DNS64
  geben.
- Rollen zentral über `Guards.Auth`; CSV-Export für alle (keine Geheimnisse), Import nur Administrator.
- CSV mit Schutz gegen Formel-Injektion (`csvSafe` aus dem Community-Zweig). Import mit Vorschau, Fehlerliste,
  höchstens 10.000 Zeilen je Datei.
- Audit: `ipam64.prefix_*`, `ipam64.range_*`, `ipam64.address_*`, `ipam64.scan`, `ipam64.import`, `ipam64.handover`;
  die Folgen in DNS64 stehen in den Details.
- MCP: lesend (Präfixe, Adressen, freie Adressen, Konflikte).

### Größere Umgebungen

Listen seitenweise und gefiltert auf dem Server; Belegung pro Präfix zwischengespeichert (15 s) und bei Änderungen neu
berechnet; Raster nur bis /22; Baum klappt ab 50 Kindern zu; API mit Seiten (`limit`, `cursor`); Import und Export in
Stapeln; Indizes wie oben. Richtwert für Tests: 500 Präfixe, 20.000 Adressen, 3 Nodes; Übersicht unter 300 ms.

## Stufen

Jede Stufe endet mit Tests, `gofmt`, Review, eigenen Commits, Modul-Changelogs und Root-Changelog-Stichpunkt.

| Stufe | Inhalt | Versionen |
|---|---|---|
| **I1 Grundlage** | Community-Code auf `main` übertragen, Datenmodell v2 (IPv4+IPv6), Modul, Migration, i18n, Audit-Bereich, `Exporter`, Cluster-Provider, Lesesicht mit Zusammenführung (DHCP, A/AAAA, Leases, Monitor64, Healthchecks, PROXY64, Nachbartabelle IPv4/IPv6), Übersicht, Präfix, Adresse (noch ohne Schreiben nach DNS64), CSV-Export | IPAM64 0.1.0 |
| **I2 DNS64-Schnittstelle** | `ipam_bridge.go`, Migrationen `origin`/`ref`, Ausnahmen im Pool (`dhcp`-Paket), Sperre für gekennzeichnete Einträge, Kennzeichen in den DNS64-Seiten, Cluster-Abgleich der neuen Felder, Tests | DNS64 1.41.0 |
| **I3 Schreiben** | Adresse anlegen/ändern mit Reservierung und A/AAAA/PTR, „Beim Speichern passiert“, nächste freie Adresse (UI und `POST /api/ipam64/prefixes/{uid}/available`), Lease → feste Adresse, Adressbereiche, Abgleich-Job, Übergabe beim Abschalten | IPAM64 0.2.0 |
| **I4 Assistent und IPv6 dynamisch** | Einrichtung aus dem Bestand, dynamische IPv6-Präfixe mit Präfix-ID/Interface-ID, Nachführen von AAAA (und auf Wunsch PROXY64/Monitor64/Healthchecks) | IPAM64 0.3.0 |
| **I5 Scan und Konflikte** | Scan gehärtet und asynchron, Sichtungen je Node, Konfliktregeln mit Dämpfung, Benachrichtigungen, Herstellerliste (OUI, E4) | IPAM64 0.4.0 |
| **I6 Abrunden** | CSV-Import, Dashboard-Karte, Prometheus, MCP, OpenAPI vollständig, README und Doku (Hinweis an die Sitzung „Node64 Webseite“) | IPAM64 0.5.0 |
| **I7 Praxistest** | agentbox im Host-Netz und Cluster mit Testnode: echtes Netz, DHCP-Failover, Präfixwechsel simuliert, 20.000 Adressen, Rolle „Nur lesen“, beide Designs | – |

## Entscheidungen E1–E5 (freigegeben wie empfohlen, Dennis 2026-11-14)

Gilt jeweils die Empfehlung: E1 IPAM64 schreibt gekennzeichnet durch; E2 nach dem Tag 1.7.0 (I1–I3 für 1.8.0);
E3 kein DHCPv6 jetzt; E4 Herstellerliste ins Image; E5 Assistent kennzeichnet den Bestand.

- **E1 Weg nach DHCP/DNS:** IPAM64 schreibt gekennzeichnet in DNS64 (Empfehlung) oder DNS64 fragt live nach.
- **E2 Release:** IPAM64 kommt **nach** dem Tag 1.7.0 (Empfehlung: 1.7.0 nicht aufhalten; I1–I3 für 1.8.0) oder
  soll schon in 1.7.0 (dann mindestens I1–I3, Standard aus)?
- **E3 DHCPv6:** Feste IPv6-Adressen nur planen und per AAAA veröffentlichen (Empfehlung für jetzt) oder eigener Plan
  für stateful DHCPv6 in DNS64?
- **E4 Herstellerliste (OUI):** rund 1–2 MB im Image (IEEE-Liste, öffentlich) ja oder nein?
- **E5 Assistent:** bestehende DNS64-Reservierungen und A/AAAA-Einträge beim Einrichten **kennzeichnen** (IPAM64 wird
  Besitzer, Empfehlung) oder nur anzeigen und einzeln übernehmen?
- Wer sich bei UlrichSchwarz meldet (nicht diese Sitzung).

## Stand I1 (2026-11-14)

Umgesetzt im Zweig `claude/zen-goldberg-805131` (auf `main` mit 1.7.0), Modul `internal/ipam64` 0.1.0:
- Datenmodell v2 (Präfixe, Adressbereiche, feste Adressen, Sichtungen; IPv4 und IPv6), Prüfung der Eingaben, Migration.
- Zusammenführung mit Präfix-Baum, Auslastung (Container: Anteil der Kinder), 15 s Zwischenspeicher; Quellen wie im
  Community-Zweig plus AAAA-Einträge und Nachbartabelle IPv6.
- Freie Adressen (ohne DHCP-Pool, ohne Bereiche zum Freihalten, ohne IPv6-Subnet-Router-Anycast), Vergabe am Stück über
  die API.
- Scan gehärtet: nur private IPv4-Netze bis /22, an denen die Node hängt, im Hintergrund, je Präfix abschaltbar.
- Cluster (`ipam64/ipamcluster`, Bereiche prefixes/ranges/addresses, Doppel per kleinerer uid), Export/Import.
- Oberfläche: Übersicht (Baum, Vorschläge aus DHCP-Netzen und Schnittstellen), Präfix (Raster, Liste mit Lücken,
  Adressbereiche), Adresse; CSV; Dashboard-Karte; API `/api/ipam64/…` samt OpenAPI; i18n DE/EN; Audit-Bereich.
- In DNS64/PROXY64 nur lesende Ergänzungen (`DHCPLeases`, `ProxyTargets`).
- Tests: Store, Zusammenführung (IPv4/IPv6), freie Adressen, Scan-Grenzen, Netlink-Parser, Cluster, Export, Seiten und
  API über den Webserver.
- Offen für I2/I3: Schreiben nach DNS64 (Reservierung, A/AAAA/PTR mit Kennzeichen), Ausnahmen im Pool, DNS- und
  DHCP-Schalter an der Adresse. MCP-Routen stehen bis I6 als Ausnahme im MCP-Test.
